//! Passive scanning: run the checks in `pm-scan` over recorded traffic and
//! group duplicates. Sends nothing, so it is a read action.

use std::collections::BTreeMap;

use pm_policy::{Actor, ActorKind, Tier};
use pm_scan::Severity;
use pm_store::HistoryFilter;
use serde::{Deserialize, Serialize};

use crate::{Result, Service};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanFilter {
    /// Only exchanges whose host contains this.
    pub host: Option<String>,
    /// How many recent exchanges to look at (default 2000, max 20000).
    pub limit: Option<usize>,
    /// Only issues at least this severe: info, low, medium or high.
    pub min_severity: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanIssue {
    /// A built-in check id, or `<plugin>/<check>` for a plugin's.
    pub check: String,
    pub title: String,
    pub severity: Severity,
    /// scheme://host[:port]
    pub origin: String,
    /// Path template, or "*" for host-wide issues such as missing headers.
    pub path: String,
    /// What was seen (from the target: untrusted; wrapped for agents).
    pub evidence: String,
    pub count: usize,
    /// First few exchanges showing it.
    pub exchange_ids: Vec<i64>,
}

fn severity(s: &str) -> Option<Severity> {
    Some(match s {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        _ => return None,
    })
}

impl Service {
    /// Passive issues in recorded traffic, most severe first. These are
    /// leads to test, not findings.
    pub fn scan_passive(&self, actor: &Actor, filter: &ScanFilter) -> Result<Vec<ScanIssue>> {
        let min = match filter.min_severity.as_deref() {
            Some(s) => severity(s)
                .ok_or_else(|| crate::ServiceError::Invalid("min_severity: info, low, medium or high".into()))?,
            None => Severity::Info,
        };
        let limit = filter.limit.unwrap_or(2000).clamp(1, 20_000);
        let summaries = self.store.read(|db| {
            db.search_exchanges(&HistoryFilter { host: filter.host.clone(), limit: Some(limit), ..Default::default() })
        })?;
        let mut groups: BTreeMap<(String, String, String, String), ScanIssue> = BTreeMap::new();
        let mut lines: Vec<pm_plugin::ExchangeLine> = Vec::new();
        let mut where_of: std::collections::HashMap<i64, (String, String)> = std::collections::HashMap::new();
        let plugins = self.enabled_plugins();
        for s in summaries {
            let Some(ex) = self.store.read(|db| db.get_exchange(s.id))? else { continue };
            let Some(resp) = ex.response.as_deref() else { continue };
            let converted;
            let resp = if pm_http::h2text::is_http2_response(resp) {
                match pm_http::h2text::to_http1_response(resp) {
                    Some(r) => {
                        converted = r;
                        &converted[..]
                    }
                    None => continue,
                }
            } else {
                resp
            };
            let (head, body) = pm_http::split_message(resp);
            let Ok(head) = pm_http::parse_response_head(head) else { continue };
            let decoded = pm_ai::body::decode(&head.headers, body);
            let issues = pm_scan::check(&pm_scan::Exchange {
                scheme: &s.scheme,
                request: &ex.request,
                status: head.status,
                headers: &head.headers,
                body: &decoded.bytes,
            });
            let origin = pm_core::authority(&s.scheme, &s.host, s.port);
            let origin = format!("{}://{origin}", s.scheme);
            if !plugins.is_empty() {
                where_of.insert(s.id, (origin.clone(), pm_model::template_path(&s.path).0));
                lines.push(pm_plugin::ExchangeLine {
                    exchange_id: s.id,
                    scheme: s.scheme.clone(),
                    host: s.host.clone(),
                    port: s.port,
                    method: s.method.clone(),
                    path: s.path.clone(),
                    status: s.status,
                    request: pm_core::base64(&ex.request),
                    response: ex.response.as_deref().map(pm_core::base64),
                });
            }
            for i in issues.into_iter().filter(|i| i.severity >= min) {
                let path = if i.host_wide { "*".to_string() } else { pm_model::template_path(&s.path).0 };
                let key_evidence = if i.host_wide { String::new() } else { i.evidence.clone() };
                let g = groups.entry((i.check.to_string(), origin.clone(), path.clone(), key_evidence)).or_insert_with(
                    || ScanIssue {
                        check: i.check.to_string(),
                        title: i.title.to_string(),
                        severity: i.severity,
                        origin: origin.clone(),
                        path,
                        evidence: i.evidence.clone(),
                        count: 0,
                        exchange_ids: Vec::new(),
                    },
                );
                g.count += 1;
                if g.exchange_ids.len() < 5 {
                    g.exchange_ids.push(s.id);
                }
            }
        }
        // Plugins see the same exchanges; their issues are grouped the same way.
        for p in &plugins {
            let name = p.manifest.name.clone();
            let found = match pm_plugin::run_passive(p, &lines) {
                Ok((found, _rejected)) => found,
                Err(e) => {
                    groups.insert(
                        (format!("{name}/plugin_error"), String::new(), String::new(), String::new()),
                        ScanIssue {
                            check: format!("{name}/plugin_error"),
                            title: format!("Plugin {name} failed"),
                            severity: Severity::Info,
                            origin: String::new(),
                            path: String::new(),
                            evidence: e.to_string(),
                            count: 1,
                            exchange_ids: vec![],
                        },
                    );
                    continue;
                }
            };
            for i in found {
                let Some(sev) = severity(&i.severity).filter(|s| *s >= min) else { continue };
                let Some((origin, path)) = where_of.get(&i.exchange_id).cloned() else { continue };
                let check = format!("{name}/{}", i.check);
                let g = groups.entry((check.clone(), origin.clone(), path.clone(), i.evidence.clone())).or_insert_with(
                    || ScanIssue {
                        check,
                        title: i.title.clone(),
                        severity: sev,
                        origin,
                        path,
                        evidence: i.evidence.clone(),
                        count: 0,
                        exchange_ids: Vec::new(),
                    },
                );
                g.count += 1;
                if g.exchange_ids.len() < 5 {
                    g.exchange_ids.push(i.exchange_id);
                }
            }
        }
        let mut out: Vec<ScanIssue> = groups.into_values().collect();
        out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.check.cmp(&b.check)).then(a.origin.cmp(&b.origin)));
        if let Some(r) = self.redactor_for(actor) {
            for i in &mut out {
                i.evidence = r.redact(&i.evidence);
            }
        }
        if actor.kind == ActorKind::Agent {
            for i in &mut out {
                i.evidence = pm_ai::wrap_untrusted(&i.evidence);
            }
        }
        Ok(out)
    }
}

// ------------------------------------------------------------ active --

/// Seconds a delay probe asks for, and the longer delay that confirms it.
const DELAY: u64 = 3;
const DELAY_CONFIRM: u64 = 5;

/// A multi-step check planned for one insertion point.
enum Plan {
    Bool(pm_scan::active::Point, Vec<pm_scan::active::BoolPair>),
    Time(&'static str, pm_scan::active::Point, Vec<pm_scan::active::TimeProbe>),
    NoSql(pm_scan::active::Point, pm_scan::active::NoSqlProbes),
    /// (trick, request, control on a missing path)
    AuthBypass(Vec<(String, Vec<u8>, Vec<u8>)>),
    /// The request with every guessed parameter added.
    Params(Vec<u8>),
    /// (point, request storing the `i`-th value, i), then the pages that may
    /// show it: (path, request).
    StoredXss(Vec<(pm_scan::active::Point, Vec<u8>, usize)>, Vec<(String, Vec<u8>)>),
    /// (point, request, URL fragment to add), and the page's same-origin
    /// scripts to fetch and serve to the browser: (URL, request).
    DomXss(Vec<(pm_scan::active::Point, Vec<u8>, String)>, Vec<(String, Vec<u8>)>),
    /// (what changed, cross-site version of the request), and the request
    /// without cookies (a control: an action that needs no session can't be forged).
    Csrf(Vec<(String, Vec<u8>)>, Vec<u8>),
    /// Tokens found in the (unredacted) request, and that request.
    Jwt(Vec<pm_scan::advanced::Jwt>, String),
    GraphQl(Vec<(&'static str, Vec<u8>)>),
    /// (header, poisoned request, same URL without it), each with its own cache buster.
    CachePoison(Vec<(&'static str, Vec<u8>, Vec<u8>)>),
    /// (trick, request), and the original without credentials.
    CacheDeception(Vec<(&'static str, Vec<u8>)>, Vec<u8>),
    MassAssignment(Vec<u8>),
    Proto(Vec<(&'static str, Vec<u8>)>),
    /// (trick, request), and the request without `state`.
    OAuth(Vec<(&'static str, Vec<u8>)>, Option<Vec<u8>>),
    /// (point, format, request with a corrupted object)
    Deser(Vec<(pm_scan::active::Point, &'static str, Vec<u8>)>),
    Smuggling(pm_scan::advanced::SmugglingProbes),
    Upload(Vec<(pm_scan::advanced::UploadKind, Vec<u8>)>),
    /// Copies sent at once (run before the baseline, which would use up a one-time action).
    Race(usize),
    /// A login with a wrong password (twice) and an unknown account.
    UserEnum(pm_scan::advanced::EnumProbes),
    /// A password change without the current password (request, field removed).
    PasswordChange(Vec<u8>, String),
}

impl Plan {
    /// Most requests it can send (with confirmations).
    fn max_requests(&self) -> usize {
        match self {
            Plan::Bool(_, pairs) => pairs.len() * 2 + 3,
            Plan::Time(_, _, list) => list.len() + 2,
            Plan::NoSql(..) => 5,
            Plan::AuthBypass(v) => v.len() * 2,
            Plan::Params(_) => 16,
            Plan::StoredXss(stores, pages) => stores.len() + pages.len(),
            Plan::DomXss(v, scripts) => v.len() + scripts.len(),
            Plan::Csrf(v, _) => v.len() + 1,
            Plan::Jwt(tokens, _) => tokens.len() * 6,
            Plan::GraphQl(v) => v.len(),
            Plan::CachePoison(v) => v.len() * 2,
            Plan::CacheDeception(v, _) => v.len() * 2 + 1,
            // The probe, then up to three read-backs.
            Plan::MassAssignment(_) => 4,
            Plan::Proto(v) => v.len(),
            Plan::OAuth(v, s) => v.len() + usize::from(s.is_some()),
            Plan::Deser(v) => v.len(),
            Plan::Smuggling(_) => 5,
            Plan::Upload(v) => v.len() * 5,
            Plan::Race(n) => *n,
            Plan::UserEnum(_) => 3,
            Plan::PasswordChange(..) => 1,
        }
    }

    /// One request per payload, to classify the tier.
    fn samples(&self, raw: &str) -> Vec<Vec<u8>> {
        use pm_scan::active::inject;
        match self {
            Plan::Bool(pt, pairs) => pairs.iter().filter_map(|p| inject(raw, pt, &p.falsy)).collect(),
            Plan::Time(_, pt, list) => list.iter().filter_map(|t| inject(raw, pt, &t.with_delay(DELAY))).collect(),
            Plan::NoSql(_, n) => vec![n.ne.clone()],
            Plan::AuthBypass(v) => v.iter().map(|(_, t, _)| t.clone()).collect(),
            Plan::Params(r) => vec![r.clone()],
            Plan::StoredXss(stores, _) => stores.iter().map(|(_, r, _)| r.clone()).collect(),
            Plan::DomXss(v, _) => v.iter().map(|(_, r, _)| r.clone()).collect(),
            Plan::Csrf(v, _) => v.iter().map(|(_, r)| r.clone()).collect(),
            Plan::Jwt(tokens, real) => tokens
                .iter()
                .flat_map(|t| t.forgeries().into_iter().map(|(_, f)| real.replace(&t.token, &f).into_bytes()))
                .collect(),
            Plan::GraphQl(v) | Plan::Proto(v) | Plan::CacheDeception(v, _) => {
                v.iter().map(|(_, r)| r.clone()).collect()
            }
            Plan::CachePoison(v) => v.iter().map(|(_, r, _)| r.clone()).collect(),
            Plan::MassAssignment(r) => vec![r.clone()],
            Plan::OAuth(v, _) => v.iter().map(|(_, r)| r.clone()).collect(),
            Plan::Deser(v) => v.iter().map(|(_, _, r)| r.clone()).collect(),
            Plan::Smuggling(p) => vec![p.te_cl.clone(), p.cl_te.clone()],
            Plan::Upload(v) => v.iter().map(|(_, r)| r.clone()).collect(),
            Plan::Race(_) => vec![raw.as_bytes().to_vec()],
            Plan::UserEnum(p) => vec![p.wrong_password.clone(), p.unknown_user.clone()],
            Plan::PasswordChange(r, _) => vec![r.clone()],
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActiveScanRequest {
    /// The recorded request to scan (its target is used).
    pub exchange_id: i64,
    /// Checks to run (default: all but request_smuggling, file_upload and
    /// race_condition, which need approval and run only when named). See
    /// `pm_scan::active::CHECKS` and `pm_scan::oob::CHECKS`.
    pub checks: Vec<String>,
    /// Most probe requests (default 300, max 2000).
    pub max_requests: Option<usize>,
    /// How long to wait for out-of-band callbacks after the last such
    /// probe (default 10 s, max 60).
    pub oob_wait_seconds: Option<u64>,
    pub identity: Option<String>,
    pub approval_id: Option<String>,
    pub hypothesis_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveFinding {
    #[serde(flatten)]
    pub issue: pm_scan::active::ActiveIssue,
    pub exchange_id: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ActiveScanResult {
    Done {
        baseline_exchange_id: i64,
        insertion_points: Vec<pm_scan::active::Point>,
        requests: usize,
        /// Leads to prove (see prove_with), not findings.
        issues: Vec<ActiveFinding>,
        /// Checks skipped or cut short, and why.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        notes: Vec<String>,
    },
    PendingApproval {
        approval_id: String,
        summary: String,
        reasons: Vec<String>,
    },
    Denied {
        reasons: Vec<String>,
    },
}

/// An issue from the step 4 checks (titles and severities vary per finding).
fn adv_issue(
    check: &'static str,
    title: &'static str,
    severity: &'static str,
    point: &str,
    payload: &str,
    evidence: String,
) -> pm_scan::active::ActiveIssue {
    pm_scan::active::ActiveIssue {
        check,
        title,
        severity,
        point: point.to_string(),
        payload: payload.to_string(),
        evidence,
        prove_with: None,
    }
}

fn seen_of(resp: Option<&[u8]>) -> pm_scan::active::Seen {
    let Some(r) = resp else { return Default::default() };
    let converted;
    let r = if pm_http::h2text::is_http2_response(r) {
        match pm_http::h2text::to_http1_response(r) {
            Some(c) => {
                converted = c;
                &converted[..]
            }
            None => r,
        }
    } else {
        r
    };
    let (head, body) = pm_http::split_message(r);
    let Ok(h) = pm_http::parse_response_head(head) else { return Default::default() };
    let d = pm_ai::body::decode(&h.headers, body);
    pm_scan::active::Seen {
        status: Some(h.status),
        location: pm_http::header(&h.headers, "location").map(|v| String::from_utf8_lossy(v).into_owned()),
        content_type: d.content_type.clone(),
        body: String::from_utf8_lossy(&d.bytes).into_owned(),
        headers: h
            .headers
            .iter()
            .map(|x| (x.name.to_ascii_lowercase(), String::from_utf8_lossy(&x.value).into_owned()))
            .collect(),
    }
}

impl Service {
    /// Active checks on one recorded request: one gate decision (at least
    /// intrusive) covers every probe; probes go through rate limits and
    /// into history like any send.
    /// Indices of path segments that the app model's template for this
    /// exchange marks as parameters.
    fn id_segments(&self, exchange_id: i64, path: &str) -> Vec<usize> {
        let Ok(model) = self.model() else { return Vec::new() };
        let Some(op) = model.operations.iter().find(|o| o.examples.contains(&exchange_id)) else { return Vec::new() };
        let segs: Vec<&str> = path.split(['?', '#']).next().unwrap_or("/").split('/').collect();
        let tpl: Vec<&str> = op.template.split('/').collect();
        if segs.len() != tpl.len() {
            return Vec::new();
        }
        tpl.iter().enumerate().filter(|(_, t)| t.starts_with('{')).map(|(i, _)| i).collect()
    }

    /// Pages that may show stored input: recent HTML GETs to the same
    /// origin from history (not the scanner's own probes), one per path.
    fn stored_xss_pages(&self, s: &pm_store::ExchangeSummary) -> Result<Vec<(String, Vec<u8>)>> {
        // By source: the scanner's own probes would crowd out the pages.
        let mut rows = Vec::new();
        for source in ["proxy", "crawl", "replay"] {
            let f = pm_store::HistoryFilter {
                host: Some(s.host.clone()),
                method: Some("GET".into()),
                status_class: Some("2".into()),
                source: Some(source.into()),
                limit: Some(200),
                ..Default::default()
            };
            rows.extend(self.store.read(|db| db.search_exchanges(&f))?);
        }
        rows.sort_by_key(|r| std::cmp::Reverse(r.id));
        let mut out: Vec<(String, Vec<u8>)> = Vec::new();
        let mut paths = std::collections::HashSet::new();
        for r in rows {
            if r.source == "scan" || r.host != s.host || r.port != s.port || r.scheme != s.scheme {
                continue;
            }
            if !paths.insert(r.path.split('?').next().unwrap_or("").to_string()) {
                continue;
            }
            let Some(e) = self.store.read(|db| db.get_exchange(r.id))? else { continue };
            let html = seen_of(e.response.as_deref()).content_type.is_some_and(|c| c.contains("html"));
            if html {
                out.push((r.path.clone(), self.redactor.redact(&String::from_utf8_lossy(&e.request)).into_bytes()));
            }
            if out.len() >= 8 {
                break;
            }
        }
        Ok(out)
    }

    pub async fn scan_active(&self, actor: &Actor, req: ActiveScanRequest) -> Result<ActiveScanResult> {
        use crate::Authorization;
        use pm_scan::active::{self as act, PointKind};
        let known = |c: &str| act::CHECKS.contains(&c) || pm_scan::oob::CHECKS.contains(&c);
        if let Some(bad) = req.checks.iter().find(|c| !known(c)) {
            return Err(crate::ServiceError::Invalid(format!(
                "unknown check {bad}; use {}, {}",
                act::CHECKS.join(", "),
                pm_scan::oob::CHECKS.join(", ")
            )));
        }
        // By default every check but the ones that need approval: those run when named.
        let want = |c: &str| {
            if req.checks.is_empty() { !act::APPROVAL_CHECKS.contains(&c) } else { req.checks.iter().any(|x| x == c) }
        };
        let ex = self
            .store
            .read(|db| db.get_exchange(req.exchange_id))?
            .ok_or_else(|| crate::ServiceError::NotFound(format!("exchange {}", req.exchange_id)))?;
        let endpoint = pm_replay::Endpoint::new(&ex.summary.scheme, &ex.summary.host, ex.summary.port);
        // Work on what the actor may see: secrets stay placeholders until sent.
        let raw = self.redactor.redact(&String::from_utf8_lossy(&ex.request));
        let marker = format!("pm{}", &pm_oast::new_token()[..10]);
        let limit = req.max_requests.unwrap_or(300).clamp(1, 2000);
        // Path segments the app model knows are identifiers (`/users/{username}`) are tested too.
        let id_segments = self.id_segments(req.exchange_id, &ex.summary.path);
        let mut probes = act::probes_with(&raw, &req.checks, &marker, limit, &id_segments);
        probes.extend(act::request_probes(&raw, &req.checks, &marker));
        let points = act::points_with(&raw, &id_segments);

        // Multi-step plans: (check, point, payloads to try), most likely first.
        let mut plans: Vec<Plan> = Vec::new();
        let mut notes = Vec::new();
        for pt in &points {
            let header = pt.kind == PointKind::Header;
            if want("sql_boolean") && !header {
                plans.push(Plan::Bool(pt.clone(), act::sql_bool_pairs(&pt.original)));
            }
            if want("sql_time") {
                plans.push(Plan::Time("sql_time", pt.clone(), act::sql_time_probes(&pt.original)));
            }
            if want("cmd_time") && pt.kind != PointKind::Path {
                plans.push(Plan::Time("cmd_time", pt.clone(), act::cmd_time_probes(&pt.original)));
            }
            if want("nosql_operator")
                && let Some(n) = act::nosql_probes(&raw, pt, &marker)
            {
                plans.push(Plan::NoSql(pt.clone(), n));
            }
        }
        if want("auth_bypass") {
            let v = act::auth_bypass_variants(&raw, &marker);
            if !v.is_empty() {
                plans.push(Plan::AuthBypass(v));
            }
        }
        if want("hidden_params")
            && let Some(r) = act::with_params(&raw, act::HIDDEN_PARAMS, &marker)
        {
            plans.push(Plan::Params(r));
        }
        let stores: Vec<(act::Point, Vec<u8>, usize)> = points
            .iter()
            .filter(|p| matches!(p.kind, PointKind::Query | PointKind::Form | PointKind::Json))
            .take(10)
            .enumerate()
            .filter_map(|(i, pt)| Some((pt.clone(), act::inject(&raw, pt, &act::stored_payload(&marker, i))?, i)))
            .collect();
        if want("stored_xss") && !ex.summary.method.eq_ignore_ascii_case("GET") && !stores.is_empty() {
            let pages = self.stored_xss_pages(&ex.summary)?;
            if pages.is_empty() {
                if !req.checks.is_empty() {
                    notes.push(
                        "stored XSS skipped: no HTML pages for this host in history (browse or crawl first)".into(),
                    );
                }
            } else {
                plans.push(Plan::StoredXss(stores, pages));
            }
        }
        if want("dom_xss") && ex.summary.method.eq_ignore_ascii_case("GET") {
            let recorded = seen_of(ex.response.as_deref());
            if recorded.content_type.as_deref().is_some_and(|c| c.contains("html")) {
                if pm_browser::find_chromium().is_none() {
                    notes.push(format!("DOM XSS skipped: no Chromium found (set {})", pm_browser::ENV_CHROMIUM));
                } else {
                    let page_url = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?.url();
                    let scripts: Vec<(String, Vec<u8>)> = act::script_srcs(&recorded.body, &page_url)
                        .into_iter()
                        .filter_map(|u| {
                            let t = url::Url::parse(&u).ok()?;
                            let target =
                                format!("{}{}", t.path(), t.query().map(|q| format!("?{q}")).unwrap_or_default());
                            Some((u, act::get_request(&raw, &target)?))
                        })
                        .collect();
                    let value = format!("{marker}<pmx>'\"");
                    let mut v: Vec<(act::Point, Vec<u8>, String)> = points
                        .iter()
                        .filter(|p| p.kind == PointKind::Query)
                        .take(5)
                        .filter_map(|pt| Some((pt.clone(), act::inject(&raw, pt, &value)?, String::new())))
                        .collect();
                    v.push((act::Point::request("URL fragment"), raw.clone().into_bytes(), format!("#{value}")));
                    plans.push(Plan::DomXss(v, scripts));
                }
            }
        }
        if want("csrf") {
            let v = act::csrf_variants(&raw, &marker);
            if !v.is_empty()
                && let Some(anon) = act::without_header(&raw, "cookie")
            {
                plans.push(Plan::Csrf(v, anon));
            }
        }
        // Step 4: tokens, GraphQL, caches, mass assignment, prototypes.
        {
            use pm_scan::advanced as adv;
            let get = ex.summary.method.eq_ignore_ascii_case("GET");
            // Tokens and serialized cookies are redacted in `raw`: look at the real request.
            let real = String::from_utf8_lossy(&self.redactor.unredact(raw.as_bytes())).into_owned();
            if want("jwt") {
                let tokens = adv::find_jwts(&real);
                if !tokens.is_empty() {
                    plans.push(Plan::Jwt(tokens, real.clone()));
                }
            }
            if want("graphql") {
                let v = adv::graphql_probes(&raw);
                if !v.is_empty() {
                    plans.push(Plan::GraphQl(v));
                }
            }
            if want("cache_poisoning") && get {
                plans.push(Plan::CachePoison(adv::cache_poison_probes(&raw, &marker)));
            }
            if want("cache_deception")
                && get
                && adv::has_credentials(&raw)
                && let Some(anon) = adv::anonymous(&raw)
            {
                plans.push(Plan::CacheDeception(adv::cache_deception_probes(&raw, &marker), anon));
            }
            if want("mass_assignment")
                && !get
                && let Some(r) = adv::with_privileged_fields(&raw, &marker)
            {
                plans.push(Plan::MassAssignment(r));
            }
            if want("user_enumeration")
                && !get
                && let Some(p) = adv::enum_probes(&raw, &marker)
            {
                plans.push(Plan::UserEnum(p));
            }
            if want("password_change")
                && let Some((r, field)) = adv::without_current_password(&raw)
            {
                plans.push(Plan::PasswordChange(r, field));
            }
            if want("oauth") {
                let v = adv::oauth_probes(&raw, &marker);
                if !v.is_empty() {
                    plans.push(Plan::OAuth(v, adv::without_query_param(&raw, "state")));
                }
            }
            if want("deserialization") {
                let v: Vec<_> = act::points_with(&real, &id_segments)
                    .iter()
                    .filter(|p| !matches!(p.kind, PointKind::Nested | PointKind::Header))
                    .filter_map(|p| {
                        let (kind, bad) = adv::deser_probe(&p.original)?;
                        Some((p.clone(), kind, act::inject(&real, p, &bad)?))
                    })
                    .collect();
                if !v.is_empty() {
                    plans.push(Plan::Deser(v));
                }
            }
            if want("request_smuggling")
                && let Some(p) = adv::smuggling_probes(&raw)
            {
                plans.push(Plan::Smuggling(p));
            }
            if want("file_upload") && !get {
                let v = adv::upload_probes(&raw, &marker);
                if !v.is_empty() {
                    plans.push(Plan::Upload(v));
                }
            }
            if want("race_condition") && !get {
                plans.push(Plan::Race(10));
            }
            if want("proto_pollution") && !get {
                let v = adv::proto_probes(&raw, &marker);
                if !v.is_empty() {
                    plans.push(Plan::Proto(v));
                }
            }
        }
        // Out-of-band probes, when an OAST listener is configured.
        // One lock at a time: in one struct literal both guards would live
        // to the end of the statement and deadlock.
        let url = self.store.read(|db| db.get_setting(crate::proof::OAST_SETTING))?;
        let domain = self.store.read(|db| db.get_setting(crate::proof::OAST_DNS_SETTING))?;
        let callback = pm_scan::oob::Callback { url, domain };
        let oob = pm_scan::oob::probes(&raw, &req.checks, &callback, &id_segments, limit, pm_oast::new_token);
        if !callback.is_set() && pm_scan::oob::CHECKS.iter().any(|c| want(c)) {
            notes.push(
                "out-of-band checks skipped: no OAST listener (run `proxymind oast-server`, or mcp with --oast-listen)"
                    .to_string(),
            );
        } else if callback.domain.is_none() && pm_scan::oob::CHECKS.iter().any(|c| want(c)) {
            notes.push("DNS-only payloads (nslookup, UNC paths, JNDI) skipped: no OAST DNS zone".to_string());
        }
        if probes.is_empty() && plans.is_empty() && oob.is_empty() && !points.is_empty() {
            // The requested checks don't apply here (see notes): nothing to send.
            notes.push("none of the requested checks apply to this request".into());
            return Ok(ActiveScanResult::Done {
                baseline_exchange_id: req.exchange_id,
                insertion_points: points,
                requests: 0,
                issues: Vec::new(),
                notes,
            });
        }
        if probes.is_empty() && plans.is_empty() && oob.is_empty() {
            return Err(crate::ServiceError::Invalid(
                "no insertion points in this request (no query, form, JSON, numeric path values, cookies or headers)"
                    .into(),
            ));
        }

        // One gate decision covers every request the scan may send: the tier
        // of the most intrusive payload, and the number as an upper bound.
        let mut base = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
        base.hypothesis_id = req.hypothesis_id;
        let mut tier = Tier::ActiveIntrusive;
        let mut planned = probes.len() + oob.len() + if plans.is_empty() { 1 } else { 3 };
        for raw in probes
            .iter()
            .map(|p| p.raw.clone())
            .chain(oob.iter().map(|p| p.probe.raw.clone()))
            .chain(plans.iter().flat_map(|p| p.samples(&raw)))
        {
            tier = tier.max(Tier::for_http_request(&raw).0);
        }
        planned += plans.iter().map(Plan::max_requests).sum::<usize>();
        let planned = planned.min(limit + 3);
        // Smuggling, uploads and races can reach other users or stay on the
        // target: a person approves them.
        let risky: Vec<&str> = plans
            .iter()
            .filter_map(|p| match p {
                Plan::Smuggling(_) => Some("request_smuggling"),
                Plan::Upload(_) => Some("file_upload"),
                Plan::Race(_) => Some("race_condition"),
                _ => None,
            })
            .collect();
        if !risky.is_empty() {
            tier = Tier::Destructive;
        }
        let extra = serde_json::json!({ "active_scan": { "checks": req.checks, "max_requests": planned, "needs_approval_for": risky } });
        match self.gate_send_with(
            actor,
            "scan_active",
            &base,
            req.identity.as_deref(),
            true,
            req.approval_id.as_deref(),
            Some(tier),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(ActiveScanResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(ActiveScanResult::PendingApproval {
                    approval_id,
                    summary: format!("active scan (up to {planned} requests): {summary}"),
                    reasons,
                });
            }
        }

        let identity = req.identity.as_deref();
        let mut sent_count = 0usize;
        let send = |raw: Vec<u8>| {
            let endpoint = endpoint.clone();
            async move {
                let mut o = self.outgoing(endpoint, &raw, true)?;
                o.hypothesis_id = req.hypothesis_id;
                let (sent, _) = self.send_as(actor, &o, identity, true, "scan").await?;
                Ok::<_, crate::ServiceError>(sent)
            }
        };
        // A race goes first: the baseline request would use up a one-time action.
        let mut raced: Option<(usize, usize, Option<u16>, Vec<i64>)> = None;
        if let Some(Plan::Race(n)) = plans.iter().find(|p| matches!(p, Plan::Race(_))) {
            let out = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
            if let crate::RaceResult::Done { exchange_ids, .. } =
                self.race_execute(actor, &out, identity, true, *n, crate::RaceModeChoice::Auto).await?
            {
                let recorded = seen_of(ex.response.as_deref());
                let mut ok = 0;
                let mut status = None;
                for id in &exchange_ids {
                    let got = seen_of(self.store.read(|db| db.get_exchange(*id))?.and_then(|e| e.response).as_deref());
                    // Same 2xx status as the recorded success (bodies carry counters and times).
                    if got.status.is_some_and(|x| (200..300).contains(&x)) && got.status == recorded.status {
                        ok += 1;
                        status = got.status;
                    }
                }
                sent_count += exchange_ids.len();
                raced = Some((ok, exchange_ids.len(), status, exchange_ids));
            }
        }
        let b = send(raw.clone().into_bytes()).await?;
        let base_seen = seen_of(b.response.as_deref());
        let mut issues: Vec<ActiveFinding> = Vec::new();
        if let Some((ok, n, status, ids)) = &raced {
            let recorded = seen_of(ex.response.as_deref());
            if *ok >= 2 && base_seen.status != recorded.status {
                let evidence = format!(
                    "{ok} of {n} copies sent at once succeeded ({}), but sent alone afterwards it is refused ({}): \
                     a one-time action ran {ok} times",
                    pm_proof::status_text(*status),
                    pm_proof::status_text(base_seen.status)
                );
                issues.push(ActiveFinding {
                    issue: adv_issue(
                        "race_condition",
                        "Race condition: a one-time action succeeds several times when requests arrive together",
                        "high",
                        "request as a whole",
                        &format!("{n} copies at once"),
                        evidence,
                    ),
                    exchange_id: ids.first().copied().unwrap_or(b.exchange_id),
                });
            } else if *ok == 0 {
                notes.push(
                    "race_condition: no copy succeeded; the action may already be used up for this account (scan a \
                     recorded request that wasn't sent yet, or pass another identity)"
                        .into(),
                );
            }
        }
        let found = |issues: &[ActiveFinding], family: &str, pt: &str| {
            issues.iter().any(|f| f.issue.check.starts_with(family) && f.issue.point.ends_with(&pt.to_lowercase()))
        };

        // On an OAuth authorization request, redirect_uri belongs to the oauth check.
        if plans.iter().any(|p| matches!(p, Plan::OAuth(..))) {
            probes.retain(|p| !(p.check == "open_redirect" && p.point.name == "redirect_uri"));
        }
        // Keep budget for the targeted checks (a few requests each), so the
        // broad one-shot probes can't use it all up.
        let reserve: usize = plans
            .iter()
            .filter(|p| !matches!(p, Plan::Bool(..) | Plan::Time(..) | Plan::NoSql(..) | Plan::Params(_)))
            .map(Plan::max_requests)
            .sum::<usize>()
            .min(limit / 2);
        let broad_limit = limit.saturating_sub(reserve);
        // 1. One-shot probes (fast).
        for p in &probes {
            // One issue per check and parameter is enough.
            if issues.iter().any(|f| f.issue.check == p.check && f.issue.point.ends_with(&p.point.name.to_lowercase()))
            {
                continue;
            }
            if sent_count >= broad_limit {
                notes.push(format!("stopped at the request limit ({limit})"));
                break;
            }
            sent_count += 1;
            let sent = send(p.raw.clone()).await?;
            let Some(issue) = act::analyze(p, &base_seen, &seen_of(sent.response.as_deref()), &marker) else {
                continue;
            };
            // A database error must come back with the payload, and not
            // without it (an app that fails by itself isn't injectable).
            if p.check == "sql_error" {
                sent_count += 2;
                let again = seen_of(send(p.raw.clone()).await?.response.as_deref());
                let clean = seen_of(send(raw.clone().into_bytes()).await?.response.as_deref());
                if act::analyze(p, &clean, &again, &marker).is_none() {
                    notes.push(format!(
                        "{} on {}: an error that didn't repeat or also comes without the payload",
                        p.check, issue.point
                    ));
                    continue;
                }
            }
            issues.push(ActiveFinding { issue, exchange_id: sent.exchange_id });
        }

        // 2. Out-of-band probes; their callbacks are collected at the end,
        // while the slower checks below run.
        let mut oob_sent: Vec<(&pm_scan::oob::OobProbe, i64)> = Vec::new();
        for p in &oob {
            let family = p.probe.check.split('_').next().unwrap_or_default();
            // Already shown in-band; and where a shell already runs our input,
            // template or code payloads that call curl would be ambiguous.
            let shell = matches!(p.probe.check, "ssti_oob" | "code_oob") && found(&issues, "cmd", &p.probe.point.name);
            if found(&issues, family, &p.probe.point.name) || shell {
                continue;
            }
            if sent_count >= broad_limit {
                notes.push(format!("stopped at the request limit ({limit})"));
                break;
            }
            sent_count += 1;
            oob_sent.push((p, send(p.probe.raw.clone()).await?.exchange_id));
        }
        let wait = std::time::Duration::from_secs(req.oob_wait_seconds.unwrap_or(10).clamp(1, 60));
        // One moment for both clocks: the wall-clock deadline stored with the
        // probes is the same instant the scan stops waiting.
        let deadline_ms = pm_core::now_ms() + wait.as_millis() as i64;
        let oob_deadline = std::time::Instant::now() + wait;
        // Remembered, so a callback after the wait still becomes a finding.
        if !oob_sent.is_empty() {
            let s = &ex.summary;
            let url = pm_core::url(&s.scheme, &s.host, s.port, &s.path);
            self.remember_oob_probes(actor, &url, deadline_ms, &oob_sent)?;
        }

        // 3 and 4. Multi-step checks: boolean pairs, then delays (slowest last).
        if !plans.is_empty() {
            let b2 = send(raw.clone().into_bytes()).await?;
            let b3 = send(raw.clone().into_bytes()).await?;
            let base2 = seen_of(b2.response.as_deref());
            let base_ms = vec![b.elapsed_ms, b2.elapsed_ms, b3.elapsed_ms];
            let timing_ok = act::timing_usable(&base_ms);
            if !timing_ok && plans.iter().any(|p| matches!(p, Plan::Time(..))) {
                notes.push(format!("time-based checks skipped: the baseline is slow ({base_ms:?} ms)"));
            }
            // The broad hidden-parameter guess goes after the targeted checks
            // (it can use many requests), and delays go last.
            plans.sort_by_key(|p| match p {
                Plan::Time(..) => 2,
                Plan::Params(_) => 1,
                _ => 0,
            });
            let denied = base_seen.status.is_some_and(|s| s == 401 || s == 403);
            'plans: for plan in &plans {
                match plan {
                    Plan::Bool(pt, pairs) => {
                        if found(&issues, "sql", &pt.name) {
                            continue;
                        }
                        for pair in pairs {
                            if sent_count + 2 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            let inj = |v: &str| act::inject(&raw, pt, v);
                            let (Some(t), Some(f)) = (inj(&pair.truthy), inj(&pair.falsy)) else { continue };
                            sent_count += 2;
                            let ts = send(t).await?;
                            let fs = send(f.clone()).await?;
                            let (tv, fv) = (seen_of(ts.response.as_deref()), seen_of(fs.response.as_deref()));
                            if !act::bool_differs(&base_seen, &base2, &tv, &fv) {
                                continue;
                            }
                            // Confirm: the other formulation agrees, and false is false again.
                            let (Some(t2), Some(f2)) = (inj(&pair.truthy2), inj(&pair.falsy2)) else { continue };
                            sent_count += 3;
                            let t2v = seen_of(send(t2).await?.response.as_deref());
                            let f2v = seen_of(send(f2).await?.response.as_deref());
                            let fagain = seen_of(send(f).await?.response.as_deref());
                            if act::bool_differs(&base_seen, &base2, &t2v, &f2v)
                                && act::bool_differs(&base_seen, &base2, &tv, &fagain)
                            {
                                let evidence = format!(
                                    "true {:?} → {} ({} bytes, like the baseline's {}); false {:?} → {} ({} bytes); \
                                     confirmed with {:?} / {:?}",
                                    pair.truthy,
                                    pm_proof::status_text(tv.status),
                                    tv.body.len(),
                                    base_seen.body.len(),
                                    pair.falsy,
                                    pm_proof::status_text(fv.status),
                                    fv.body.len(),
                                    pair.truthy2,
                                    pair.falsy2,
                                );
                                let issue = act::multi_step_issue("sql_boolean", pt, &pair.falsy, evidence);
                                issues.push(ActiveFinding { issue, exchange_id: fs.exchange_id });
                                break;
                            }
                        }
                    }
                    Plan::NoSql(pt, n) => {
                        if found(&issues, "nosql", &pt.name) || found(&issues, "sql", &pt.name) {
                            continue;
                        }
                        if sent_count + 3 > limit {
                            notes.push(format!("stopped at the request limit ({limit})"));
                            break 'plans;
                        }
                        sent_count += 3;
                        let plain = seen_of(send(n.plain.clone()).await?.response.as_deref());
                        let eq = seen_of(send(n.eq.clone()).await?.response.as_deref());
                        let ne_sent = send(n.ne.clone()).await?;
                        let ne = seen_of(ne_sent.response.as_deref());
                        if !act::nosql_differs(&plain, &eq, &ne) {
                            continue;
                        }
                        // Confirm: a regex matching anything acts like $ne, one matching nothing like $eq.
                        sent_count += 2;
                        let all = seen_of(send(n.all.clone()).await?.response.as_deref());
                        let none = seen_of(send(n.none.clone()).await?.response.as_deref());
                        if act::nosql_differs(&none, &plain, &all) || act::nosql_differs(&plain, &none, &all) {
                            let evidence = format!(
                                "plain value → {} ({} bytes); {{\"$eq\"}} → {} (same); {{\"$ne\"}} → {} ({} bytes); \
                                 confirmed with $regex",
                                pm_proof::status_text(plain.status),
                                plain.body.len(),
                                pm_proof::status_text(eq.status),
                                pm_proof::status_text(ne.status),
                                ne.body.len()
                            );
                            let issue = act::multi_step_issue("nosql_operator", pt, "$ne operator", evidence);
                            issues.push(ActiveFinding { issue, exchange_id: ne_sent.exchange_id });
                        }
                    }
                    Plan::AuthBypass(variants) => {
                        if !denied {
                            continue; // nothing to bypass
                        }
                        for (trick, t, c) in variants {
                            if sent_count + 2 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let got_sent = send(t.clone()).await?;
                            let got = seen_of(got_sent.response.as_deref());
                            if !got.status.is_some_and(|s| (200..300).contains(&s)) {
                                continue;
                            }
                            sent_count += 1;
                            let control = seen_of(send(c.clone()).await?.response.as_deref());
                            if act::bypassed(&base_seen, &got, &control) {
                                let evidence = format!(
                                    "{} → {} ({} bytes) instead of {}; the same trick on a missing path → {}",
                                    trick,
                                    pm_proof::status_text(got.status),
                                    got.body.len(),
                                    pm_proof::status_text(base_seen.status),
                                    pm_proof::status_text(control.status)
                                );
                                let pt = act::Point::request("path and headers");
                                let issue = act::multi_step_issue("auth_bypass", &pt, trick, evidence);
                                issues.push(ActiveFinding { issue, exchange_id: got_sent.exchange_id });
                                break;
                            }
                        }
                    }
                    Plan::Params(all) => {
                        if sent_count + 1 > limit {
                            continue;
                        }
                        sent_count += 1;
                        let names: Vec<&str> = act::HIDDEN_PARAMS.to_vec();
                        let g_sent = send(all.clone()).await?;
                        let g = seen_of(g_sent.response.as_deref());
                        let reflected = act::reflected_params(&names, &marker, &g);
                        let pt = act::Point::request("parameters");
                        if !reflected.is_empty() {
                            let evidence = format!("values of {} come back in the response", reflected.join(", "));
                            let issue = act::multi_step_issue("hidden_params", &pt, &reflected.join(", "), evidence);
                            issues.push(ActiveFinding { issue, exchange_id: g_sent.exchange_id });
                            continue;
                        }
                        if !act::differs(&base_seen, &base2, &g) {
                            continue;
                        }
                        // Halve the list until one name explains the difference.
                        let mut cands = names.clone();
                        while cands.len() > 1 && sent_count < limit {
                            let (a, b) = cands.split_at(cands.len() / 2);
                            let Some(r) = act::with_params(&raw, a, &marker) else { break };
                            sent_count += 1;
                            let seen = seen_of(send(r).await?.response.as_deref());
                            cands = if act::differs(&base_seen, &base2, &seen) { a.to_vec() } else { b.to_vec() };
                        }
                        if cands.len() == 1
                            && sent_count < limit
                            && let Some(r) = act::with_params(&raw, &cands, &marker)
                        {
                            sent_count += 1;
                            let one_sent = send(r).await?;
                            let one = seen_of(one_sent.response.as_deref());
                            if act::differs(&base_seen, &base2, &one) {
                                let evidence = format!(
                                    "adding {}= changes the response: {} ({} bytes) instead of {} ({} bytes)",
                                    cands[0],
                                    pm_proof::status_text(one.status),
                                    one.body.len(),
                                    pm_proof::status_text(base_seen.status),
                                    base_seen.body.len()
                                );
                                let issue = act::multi_step_issue("hidden_params", &pt, cands[0], evidence);
                                issues.push(ActiveFinding { issue, exchange_id: one_sent.exchange_id });
                            }
                        }
                    }
                    Plan::StoredXss(stores, pages) => {
                        let mut stored: Vec<&(act::Point, Vec<u8>, usize)> = Vec::new();
                        for st in stores {
                            if sent_count + 1 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            send(st.1.clone()).await?;
                            stored.push(st);
                        }
                        for (path, r) in pages {
                            if stored.is_empty() {
                                break;
                            }
                            if sent_count + 1 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let page_sent = send(r.clone()).await?;
                            let page = seen_of(page_sent.response.as_deref());
                            stored.retain(|(pt, _, i)| {
                                if act::stored_seen(&page.body, &marker, *i) != Some(true) {
                                    return true;
                                }
                                let payload = act::stored_payload(&marker, *i);
                                let at = page.body.find(&payload).unwrap_or(0);
                                let evidence = format!(
                                    "a value sent in {} shows unencoded on GET {path}: {}",
                                    pt.name,
                                    act::snippet(&page.body, at, 120)
                                );
                                let issue = act::multi_step_issue("stored_xss", pt, &payload, evidence);
                                issues.push(ActiveFinding { issue, exchange_id: page_sent.exchange_id });
                                false
                            });
                        }
                    }
                    Plan::DomXss(variants, scripts) => {
                        let Some(chromium) = pm_browser::find_chromium() else { continue };
                        // The page's own scripts, fetched once like any probe.
                        let mut resources = Vec::new();
                        for (u, r) in scripts {
                            if sent_count + 1 > limit {
                                break;
                            }
                            sent_count += 1;
                            let s = send(r.clone()).await?;
                            if let Some(d) = s.response.as_deref().and_then(|x| crate::proof::recorded_document(u, x)) {
                                resources.push(pm_browser::Resource {
                                    url: u.clone(),
                                    status: d.status,
                                    headers: d.headers,
                                    body: d.body,
                                });
                            }
                        }
                        for (pt, r, fragment) in variants {
                            if sent_count + 1 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let page_sent = send(r.clone()).await?;
                            let url = format!("{}{fragment}", self.outgoing(endpoint.clone(), r, true)?.url());
                            let Some(mut doc) =
                                page_sent.response.as_deref().and_then(|x| crate::proof::recorded_document(&url, x))
                            else {
                                continue;
                            };
                            doc.resources = resources.clone();
                            let opts = pm_browser::RenderOptions {
                                init_script: Some(act::dom_hooks(&marker, "pmProof")),
                                ..Default::default()
                            };
                            match pm_browser::render(&chromium, &doc, &opts).await {
                                Ok(rep) => {
                                    let hit = act::dom_reports(&rep.binding_calls, &marker)
                                        .into_iter()
                                        .find(|(sink, v)| act::dom_dangerous(sink, v, &marker));
                                    if let Some((sink, value)) = hit {
                                        let evidence = format!(
                                            "a value in the {} reached {sink} in the page's scripts: {}",
                                            if fragment.is_empty() {
                                                format!("parameter {}", pt.name)
                                            } else {
                                                "URL fragment".into()
                                            },
                                            value.chars().take(200).collect::<String>()
                                        );
                                        let payload = if fragment.is_empty() {
                                            format!("{marker}<pmx>'\"")
                                        } else {
                                            fragment.clone()
                                        };
                                        let issue = act::multi_step_issue("dom_xss", pt, &payload, evidence);
                                        issues.push(ActiveFinding { issue, exchange_id: page_sent.exchange_id });
                                    }
                                }
                                Err(e) => notes.push(format!("DOM XSS: browser error: {e}")),
                            }
                        }
                    }
                    Plan::Csrf(variants, anonymous) => {
                        if !base_seen.status.is_some_and(|s| (200..400).contains(&s)) || sent_count + 1 > limit {
                            continue;
                        }
                        // Only a request that needs the session can be forged with it.
                        sent_count += 1;
                        let anon = seen_of(send(anonymous.clone()).await?.response.as_deref());
                        if act::csrf_accepted(&base_seen, &anon) {
                            continue;
                        }
                        for (what, r) in variants {
                            if sent_count + 1 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let got_sent = send(r.clone()).await?;
                            let got = seen_of(got_sent.response.as_deref());
                            if act::csrf_accepted(&base_seen, &got) {
                                let evidence = format!(
                                    "sent with {what} and the session cookie: {} ({} bytes) like the original; \
                                     no CSRF token in the request and the origin isn't checked. Browsers still \
                                     block it if the session cookie is SameSite=Lax or Strict",
                                    pm_proof::status_text(got.status),
                                    got.body.len()
                                );
                                let pt = act::Point::request("Origin header");
                                let issue = act::multi_step_issue("csrf", &pt, what, evidence);
                                issues.push(ActiveFinding { issue, exchange_id: got_sent.exchange_id });
                                break;
                            }
                        }
                    }
                    Plan::Jwt(tokens, real) => {
                        use pm_scan::advanced as adv;
                        for t in tokens {
                            let where_ = real
                                .lines()
                                .find(|l| l.contains(&t.token))
                                .and_then(|l| l.split_once(':').map(|(k, _)| k.trim().to_ascii_lowercase()))
                                .filter(|k| !k.contains(' ') && k.len() < 40)
                                .unwrap_or_else(|| "body".into());
                            let point = format!("request jwt ({where_})");
                            if let Some(secret) = t.weak_secret() {
                                let evidence = format!(
                                    "the {} signature verifies with the secret {secret:?}: anyone can sign tokens \
                                     with any claims",
                                    t.alg
                                );
                                issues.push(ActiveFinding {
                                    issue: adv_issue(
                                        "jwt",
                                        "JWT signed with a guessable secret",
                                        "high",
                                        &point,
                                        &t.alg,
                                        evidence,
                                    ),
                                    exchange_id: b.exchange_id,
                                });
                            }
                            if !adv::accepted(&base_seen, &base_seen) || sent_count + 2 > limit {
                                continue;
                            }
                            let with = |tok: &str| real.replace(&t.token, tok).into_bytes();
                            // A request that works without the token says nothing about it.
                            sent_count += 2;
                            let anon = seen_of(send(with("")).await?.response.as_deref());
                            if adv::accepted(&base_seen, &anon) {
                                continue;
                            }
                            let tampered_sent = send(with(&t.tampered())).await?;
                            if adv::accepted(&base_seen, &seen_of(tampered_sent.response.as_deref())) {
                                let evidence = "a token with a changed signature got the same answer as the real one, \
                                                and no token was refused"
                                    .to_string();
                                issues.push(ActiveFinding {
                                    issue: adv_issue(
                                        "jwt",
                                        "JWT signature is not verified",
                                        "high",
                                        &point,
                                        "changed signature",
                                        evidence,
                                    ),
                                    exchange_id: tampered_sent.exchange_id,
                                });
                                continue;
                            }
                            for (how, forged) in t.forgeries() {
                                if sent_count + 1 > limit {
                                    notes.push(format!("stopped at the request limit ({limit})"));
                                    break 'plans;
                                }
                                sent_count += 1;
                                let f_sent = send(with(&forged)).await?;
                                if adv::accepted(&base_seen, &seen_of(f_sent.response.as_deref())) {
                                    let evidence = format!(
                                        "a forged token ({how}) got the same answer as the real one, while a changed \
                                         signature and no token were refused"
                                    );
                                    issues.push(ActiveFinding {
                                        issue: adv_issue(
                                            "jwt",
                                            "JWT forgery accepted (alg none or no signature)",
                                            "high",
                                            &point,
                                            &how,
                                            evidence,
                                        ),
                                        exchange_id: f_sent.exchange_id,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    Plan::GraphQl(probes) => {
                        for (what, r) in probes {
                            if sent_count + 1 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let g_sent = send(r.clone()).await?;
                            let got = seen_of(g_sent.response.as_deref());
                            if let Some((severity, title, evidence)) =
                                pm_scan::advanced::graphql_verdict(what, &base_seen, &got)
                            {
                                issues.push(ActiveFinding {
                                    issue: adv_issue("graphql", title, severity, "request graphql", what, evidence),
                                    exchange_id: g_sent.exchange_id,
                                });
                            }
                        }
                    }
                    Plan::CachePoison(probes) => {
                        use pm_scan::advanced as adv;
                        for (header, poisoned, clean) in probes {
                            if sent_count + 2 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let p_seen = seen_of(send(poisoned.clone()).await?.response.as_deref());
                            if !adv::shows_injection(header, &base_seen, &p_seen, &marker) {
                                continue;
                            }
                            // The same URL without the header: served from the cache?
                            sent_count += 1;
                            let c_sent = send(clean.clone()).await?;
                            let c_seen = seen_of(c_sent.response.as_deref());
                            if adv::shows_injection(header, &base_seen, &c_seen, &marker) {
                                let evidence = format!(
                                    "{header} changed the response, and the same URL requested without it got the \
                                     changed response back from the cache (age: {}, x-cache: {}); probes used a \
                                     cache buster, so other users were not affected",
                                    c_seen.header("age").unwrap_or("-"),
                                    c_seen.header("x-cache").unwrap_or("-")
                                );
                                let point = format!("request {} header", header.to_ascii_lowercase());
                                issues.push(ActiveFinding {
                                    issue: adv_issue(
                                        "cache_poisoning",
                                        "Web cache poisoning through an unkeyed header",
                                        "high",
                                        &point,
                                        header,
                                        evidence,
                                    ),
                                    exchange_id: c_sent.exchange_id,
                                });
                                break;
                            }
                        }
                    }
                    Plan::CacheDeception(probes, anon) => {
                        use pm_scan::advanced as adv;
                        if !base_seen.status.is_some_and(|s| (200..300).contains(&s))
                            || base_seen.body.trim().is_empty()
                            || sent_count + 1 > limit
                        {
                            continue;
                        }
                        // Only private content matters: without credentials the page must differ.
                        sent_count += 1;
                        let anon_seen = seen_of(send(anon.clone()).await?.response.as_deref());
                        if act::similarity(&anon_seen.body, &base_seen.body) >= 0.9
                            && anon_seen.status == base_seen.status
                        {
                            continue;
                        }
                        for (trick, r) in probes {
                            if sent_count + 2 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let authed = seen_of(send(r.clone()).await?.response.as_deref());
                            if !adv::accepted(&base_seen, &authed) {
                                continue;
                            }
                            let Some(anon_r) = adv::anonymous(&String::from_utf8_lossy(r)) else { continue };
                            sent_count += 1;
                            let a_sent = send(anon_r).await?;
                            let leaked = seen_of(a_sent.response.as_deref());
                            if adv::accepted(&base_seen, &leaked) {
                                let evidence = format!(
                                    "the private page with a {trick} suffix was cached: requested again without \
                                     credentials it came back with the logged-in content ({} bytes), while the \
                                     original URL without credentials gets {}",
                                    leaked.body.len(),
                                    pm_proof::status_text(anon_seen.status)
                                );
                                issues.push(ActiveFinding {
                                    issue: adv_issue(
                                        "cache_deception",
                                        "Web cache deception: a private page is cached under a static-looking URL",
                                        "high",
                                        "request path",
                                        trick,
                                        evidence,
                                    ),
                                    exchange_id: a_sent.exchange_id,
                                });
                                break;
                            }
                        }
                    }
                    Plan::MassAssignment(r) => {
                        // A sign-up re-sent as is fails ("already taken"): compare
                        // with the recorded success instead.
                        let ok = |s: &pm_scan::active::Seen| s.status.is_some_and(|x| (200..300).contains(&x));
                        let recorded = seen_of(ex.response.as_deref());
                        let base = if ok(&base_seen) { &base_seen } else { &recorded };
                        if !ok(base) || sent_count + 1 > limit {
                            continue;
                        }
                        sent_count += 1;
                        let m_sent = send(r.clone()).await?;
                        let got = seen_of(m_sent.response.as_deref());
                        let mut fields = pm_scan::advanced::mass_assigned(base, &got, &marker);
                        let mut where_seen = "came back set";
                        let mut finding_exchange = m_sent.exchange_id;
                        // Not echoed: look for the new account where accounts are listed
                        // with their privileges (recorded GETs on the same origin).
                        if fields.is_empty() && ok(&got) {
                            let account = pm_scan::advanced::probe_account_values(r, &marker);
                            let reads: Vec<Vec<u8>> = if account.is_empty() {
                                Vec::new()
                            } else {
                                let rows = self.store.read(|db| {
                                    db.search_exchanges(&HistoryFilter {
                                        host: Some(ex.summary.host.clone()),
                                        method: Some("GET".into()),
                                        limit: Some(500),
                                        ..Default::default()
                                    })
                                })?;
                                let mut out = Vec::new();
                                for row in rows.iter().filter(|x| {
                                    x.port == ex.summary.port
                                        && x.scheme == ex.summary.scheme
                                        && x.status.is_some_and(|c| (200..300).contains(&c))
                                }) {
                                    if out.len() >= 3 {
                                        break;
                                    }
                                    let Some(e) = self.store.read(|db| db.get_exchange(row.id))? else { continue };
                                    if pm_scan::advanced::lists_privileges(&seen_of(e.response.as_deref()).body) {
                                        out.push(
                                            self.redactor.redact(&String::from_utf8_lossy(&e.request)).into_bytes(),
                                        );
                                    }
                                }
                                out
                            };
                            for read in reads {
                                if sent_count + 1 > limit {
                                    break;
                                }
                                sent_count += 1;
                                let back = send(read).await?;
                                let found = pm_scan::advanced::assigned_in_listing(
                                    &seen_of(back.response.as_deref()).body,
                                    &account,
                                );
                                if !found.is_empty() {
                                    fields = found;
                                    where_seen = "are set on the new account in a later response";
                                    finding_exchange = back.exchange_id;
                                    break;
                                }
                            }
                        }
                        if !fields.is_empty() {
                            let evidence = format!(
                                "privileged fields added to the submission {where_seen}: {}",
                                fields.join(", ")
                            );
                            issues.push(ActiveFinding {
                                issue: adv_issue(
                                    "mass_assignment",
                                    "Mass assignment: privileged fields in the request are accepted",
                                    "high",
                                    "request body fields",
                                    &fields.join(", "),
                                    evidence,
                                ),
                                exchange_id: finding_exchange,
                            });
                        }
                    }
                    Plan::Race(_) => {} // ran before the baseline
                    Plan::UserEnum(p) => {
                        if sent_count + 3 > limit {
                            continue;
                        }
                        sent_count += 3;
                        let w = send(p.wrong_password.clone()).await?;
                        let a = send(p.wrong_password.clone()).await?;
                        let u = send(p.unknown_user.clone()).await?;
                        let (ws, as_, us) = (
                            seen_of(w.response.as_deref()),
                            seen_of(a.response.as_deref()),
                            seen_of(u.response.as_deref()),
                        );
                        if let Some(evidence) = pm_scan::advanced::enumerates(p, &ws, &as_, &us) {
                            issues.push(ActiveFinding {
                                issue: adv_issue(
                                    "user_enumeration",
                                    "Login reveals which accounts exist",
                                    "medium",
                                    "login",
                                    "unknown account vs wrong password",
                                    evidence,
                                ),
                                exchange_id: u.exchange_id,
                            });
                        }
                    }
                    Plan::PasswordChange(r, field) => {
                        let recorded = seen_of(ex.response.as_deref());
                        let ok = |s: &pm_scan::active::Seen| s.status.is_some_and(|x| (200..300).contains(&x));
                        if !ok(&recorded) || sent_count + 1 > limit {
                            continue;
                        }
                        sent_count += 1;
                        let p_sent = send(r.clone()).await?;
                        let got = seen_of(p_sent.response.as_deref());
                        let refused = ["incorrect", "wrong", "invalid", "required", "missing", "not match"]
                            .iter()
                            .any(|w| got.body.to_ascii_lowercase().contains(w));
                        if ok(&got) && got.status == recorded.status && !refused {
                            issues.push(ActiveFinding {
                                issue: adv_issue(
                                    "password_change",
                                    "Password change doesn't check the current password",
                                    "high",
                                    &format!("parameter {field}"),
                                    &format!("{field} removed"),
                                    format!(
                                        "without {field} the password change still succeeds (status {}): a stolen \
                                         session or a CSRF can take over the account",
                                        got.status.unwrap_or(0)
                                    ),
                                ),
                                exchange_id: p_sent.exchange_id,
                            });
                        }
                    }
                    Plan::OAuth(tricks, no_state) => {
                        use pm_scan::advanced as adv;
                        for (trick, r) in tricks {
                            if sent_count + 1 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let o_sent = send(r.clone()).await?;
                            let got = seen_of(o_sent.response.as_deref());
                            if adv::oauth_leaks(&got, &marker) {
                                let evidence = format!(
                                    "with redirect_uri set to {trick}, the server redirects there: Location: {}",
                                    got.location.clone().unwrap_or_default().chars().take(200).collect::<String>()
                                );
                                issues.push(ActiveFinding {
                                    issue: adv_issue(
                                        "oauth",
                                        "OAuth redirect_uri is not checked: codes and tokens go to another site",
                                        "high",
                                        "query redirect_uri",
                                        trick,
                                        evidence,
                                    ),
                                    exchange_id: o_sent.exchange_id,
                                });
                                break;
                            }
                        }
                        if let Some(r) = no_state
                            && sent_count < limit
                        {
                            sent_count += 1;
                            let n_sent = send(r.clone()).await?;
                            let got = seen_of(n_sent.response.as_deref());
                            if adv::oauth_without_state(&String::from_utf8_lossy(r), &got) {
                                let evidence = "without the state parameter the server still issues a code or token \
                                                (login CSRF: an attacker can log a victim into the attacker's account)"
                                    .to_string();
                                issues.push(ActiveFinding {
                                    issue: adv_issue(
                                        "oauth",
                                        "OAuth works without state",
                                        "medium",
                                        "query state",
                                        "state removed",
                                        evidence,
                                    ),
                                    exchange_id: n_sent.exchange_id,
                                });
                            }
                        }
                    }
                    Plan::Deser(probes) => {
                        for (pt, kind, r) in probes {
                            if sent_count + 1 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let d_sent = send(r.clone()).await?;
                            let got = seen_of(d_sent.response.as_deref());
                            if let Some(err) = pm_scan::advanced::deser_error(&base_seen, &got) {
                                let evidence = format!(
                                    "{} holds a serialized {kind} object; a corrupted copy made the server fail with \
                                     {err:?}: it deserializes what the client sends (gadget chains may run code)",
                                    pt.name
                                );
                                let point = format!("{:?} {}", pt.kind, pt.name).to_lowercase();
                                issues.push(ActiveFinding {
                                    issue: adv_issue(
                                        "deserialization",
                                        "Insecure deserialization of client-supplied objects",
                                        "high",
                                        &point,
                                        kind,
                                        evidence,
                                    ),
                                    exchange_id: d_sent.exchange_id,
                                });
                            }
                        }
                    }
                    Plan::Smuggling(probes) => {
                        use pm_scan::advanced as adv;
                        if sent_count + 3 > limit {
                            continue;
                        }
                        // Exact bytes: no Content-Length fix-up.
                        let send_exact = |raw: Vec<u8>| {
                            let endpoint = endpoint.clone();
                            async move {
                                let mut o = self.outgoing(endpoint, &raw, false)?;
                                o.hypothesis_id = req.hypothesis_id;
                                let (sent, _) = self.send_as(actor, &o, identity, false, "scan").await?;
                                Ok::<_, crate::ServiceError>(sent)
                            }
                        };
                        sent_count += 1;
                        let control = send_exact(probes.control.clone()).await?;
                        if adv::hung(&base_ms, control.elapsed_ms) {
                            notes.push("request_smuggling: even a well-framed probe is slow; skipped".into());
                            continue;
                        }
                        for (name, probe) in [("TE.CL", &probes.te_cl), ("CL.TE", &probes.cl_te)] {
                            if sent_count + 2 > limit {
                                break;
                            }
                            sent_count += 1;
                            let first = send_exact(probe.clone()).await?;
                            if !adv::hung(&base_ms, first.elapsed_ms) {
                                continue;
                            }
                            // Again, to rule out a slow moment.
                            sent_count += 1;
                            let again = send_exact(probe.clone()).await?;
                            if adv::hung(&base_ms, again.elapsed_ms) {
                                let evidence = format!(
                                    "with conflicting Content-Length and Transfer-Encoding ({name}), the server waited \
                                     {} ms and {} ms for the rest of the body, against {} ms for the same request \
                                     framed consistently (baseline {:?} ms): the front end and back end disagree on \
                                     where requests end",
                                    first.elapsed_ms, again.elapsed_ms, control.elapsed_ms, base_ms
                                );
                                issues.push(ActiveFinding {
                                    issue: adv_issue(
                                        "request_smuggling",
                                        "HTTP request smuggling (front end and back end disagree on framing)",
                                        "high",
                                        "request framing",
                                        name,
                                        evidence,
                                    ),
                                    exchange_id: again.exchange_id,
                                });
                                break;
                            }
                        }
                    }
                    Plan::Upload(probes) => {
                        for (kind, r) in probes {
                            if sent_count + 1 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let up = seen_of(send(r.clone()).await?.response.as_deref());
                            if !up.status.is_some_and(|s| (200..300).contains(&s)) {
                                continue;
                            }
                            let file = kind.file_name(&marker);
                            for loc in pm_scan::advanced::upload_locations(&up.body, &file) {
                                let Some(get) = act::get_request(&raw, &loc) else { continue };
                                if sent_count + 1 > limit {
                                    break;
                                }
                                sent_count += 1;
                                let f_sent = send(get).await?;
                                let got = seen_of(f_sent.response.as_deref());
                                if kind.verdict(&got, &marker) {
                                    let (title, what) = match kind {
                                        pm_scan::advanced::UploadKind::Php => (
                                            "File upload: uploaded server code runs (remote code execution)",
                                            "the uploaded PHP file ran when fetched",
                                        ),
                                        _ => (
                                            "File upload: HTML or SVG files are served from the site (stored XSS)",
                                            "the uploaded file is served back as a page that runs script",
                                        ),
                                    };
                                    let evidence = format!(
                                        "{file} was accepted and is served at {loc} ({}): {what}",
                                        got.content_type.clone().unwrap_or_default()
                                    );
                                    issues.push(ActiveFinding {
                                        issue: adv_issue("file_upload", title, "high", "request file", &file, evidence),
                                        exchange_id: f_sent.exchange_id,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    Plan::Proto(probes) => {
                        for (how, r) in probes {
                            if sent_count + 1 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            sent_count += 1;
                            let p_sent = send(r.clone()).await?;
                            if pm_scan::advanced::polluted(&seen_of(p_sent.response.as_deref()), &marker) {
                                let evidence = format!(
                                    "a property sent inside {how} shows up as an ordinary property in the response: \
                                     the object was merged into a prototype (the server may stay polluted until it \
                                     restarts)"
                                );
                                issues.push(ActiveFinding {
                                    issue: adv_issue(
                                        "proto_pollution",
                                        "Server-side prototype pollution",
                                        "high",
                                        "request body",
                                        how,
                                        evidence,
                                    ),
                                    exchange_id: p_sent.exchange_id,
                                });
                                break;
                            }
                        }
                    }
                    Plan::Time(check, pt, list) => {
                        let family = if *check == "sql_time" { "sql" } else { "cmd" };
                        if !timing_ok || found(&issues, family, &pt.name) {
                            continue;
                        }
                        for tp in list {
                            if sent_count + 1 > limit {
                                notes.push(format!("stopped at the request limit ({limit})"));
                                break 'plans;
                            }
                            let Some(slow) = act::inject(&raw, pt, &tp.with_delay(DELAY)) else { continue };
                            sent_count += 1;
                            let s1 = send(slow).await?;
                            if !act::delayed(&base_ms, s1.elapsed_ms, DELAY) {
                                continue;
                            }
                            // Confirm: no delay with 0, and a longer delay with more.
                            let (Some(zero), Some(longer)) = (
                                act::inject(&raw, pt, &tp.with_delay(0)),
                                act::inject(&raw, pt, &tp.with_delay(DELAY_CONFIRM)),
                            ) else {
                                continue;
                            };
                            sent_count += 2;
                            let s0 = send(zero).await?;
                            let s2 = send(longer).await?;
                            let fast = !act::delayed(&base_ms, s0.elapsed_ms, DELAY / 2 + 1);
                            if fast && act::delayed(&base_ms, s2.elapsed_ms, DELAY_CONFIRM) {
                                let evidence = format!(
                                    "{}: sleep {DELAY} → {} ms, sleep 0 → {} ms, sleep {DELAY_CONFIRM} → {} ms \
                                     (baseline {:?} ms)",
                                    tp.family, s1.elapsed_ms, s0.elapsed_ms, s2.elapsed_ms, base_ms
                                );
                                let issue = act::multi_step_issue(check, pt, &tp.with_delay(DELAY), evidence);
                                issues.push(ActiveFinding { issue, exchange_id: s1.exchange_id });
                                break;
                            }
                        }
                    }
                }
            }
            sent_count += 2;
        }
        // 5. Callbacks: wait out the rest of the window, then match tokens.
        if !oob_sent.is_empty() {
            let tokens: std::collections::BTreeSet<&str> = oob_sent.iter().map(|(p, _)| p.token.as_str()).collect();
            tokio::time::sleep_until(oob_deadline.into()).await;
            // Looked up by token: unrelated callbacks can't push these out of view.
            let mut hits = Vec::new();
            self.store.read(|store| -> Result<()> {
                for t in tokens {
                    hits.extend(store.rows("oast_interactions", Some(("token", &serde_json::json!(t))), 20)?);
                }
                Ok(())
            })?;
            for (p, exchange_id) in &oob_sent {
                let mine: Vec<_> =
                    hits.iter().filter(|h| h.get("token").and_then(|t| t.as_str()) == Some(p.token.as_str())).collect();
                let Some(first) = mine.last() else { continue };
                let dup = issues.iter().any(|f| {
                    f.issue.check == p.probe.check && f.issue.point.ends_with(&p.probe.point.name.to_lowercase())
                });
                if dup {
                    continue;
                }
                let field = |k: &str| first.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let seen = format!(
                    "{} {} {} from {} ({} interaction{})",
                    field("protocol").to_uppercase(),
                    field("method"),
                    field("path"),
                    field("remote"),
                    mine.len(),
                    if mine.len() == 1 { "" } else { "s" }
                );
                issues.push(ActiveFinding { issue: pm_scan::oob::issue(p, &seen), exchange_id: *exchange_id });
            }
            notes.push(
                "out-of-band: a callback that arrives after the wait still becomes a finding when it comes".into(),
            );
        }
        if actor.kind == ActorKind::Agent {
            for f in &mut issues {
                f.issue.evidence = pm_ai::wrap_untrusted(&f.issue.evidence);
            }
        }
        notes.dedup();
        Ok(ActiveScanResult::Done {
            baseline_exchange_id: b.exchange_id,
            insertion_points: points,
            requests: sent_count + 1,
            issues,
            notes,
        })
    }
}
