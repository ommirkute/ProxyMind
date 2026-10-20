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
        let summaries = self.store.lock().search_exchanges(&HistoryFilter {
            host: filter.host.clone(),
            limit: Some(limit),
            ..Default::default()
        })?;
        let mut groups: BTreeMap<(String, String, String, String), ScanIssue> = BTreeMap::new();
        let mut lines: Vec<pm_plugin::ExchangeLine> = Vec::new();
        let mut where_of: std::collections::HashMap<i64, (String, String)> = std::collections::HashMap::new();
        let plugins = self.plugins.read().clone();
        for s in summaries {
            let Some(ex) = self.store.lock().get_exchange(s.id)? else { continue };
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
}

impl Plan {
    /// Most requests it can send (with confirmations).
    fn max_requests(&self) -> usize {
        match self {
            Plan::Bool(_, pairs) => pairs.len() * 2 + 3,
            Plan::Time(_, _, list) => list.len() + 2,
        }
    }

    /// One request per payload, to classify the tier.
    fn samples(&self, raw: &str) -> Vec<Vec<u8>> {
        use pm_scan::active::inject;
        match self {
            Plan::Bool(pt, pairs) => pairs.iter().filter_map(|p| inject(raw, pt, &p.falsy)).collect(),
            Plan::Time(_, pt, list) => list.iter().filter_map(|t| inject(raw, pt, &t.with_delay(DELAY))).collect(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActiveScanRequest {
    /// The recorded request to scan (its target is used).
    pub exchange_id: i64,
    /// Checks to run (default all): sql_error, cmd_injection,
    /// reflected_input, open_redirect, path_traversal, ssti, and the
    /// multi-step sql_boolean, sql_time and cmd_time.
    pub checks: Vec<String>,
    /// Most probe requests (default 300, max 2000).
    pub max_requests: Option<usize>,
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

    pub async fn scan_active(&self, actor: &Actor, req: ActiveScanRequest) -> Result<ActiveScanResult> {
        use crate::Authorization;
        use pm_scan::active::{self as act, PointKind};
        if let Some(bad) = req.checks.iter().find(|c| !act::CHECKS.contains(&c.as_str())) {
            return Err(crate::ServiceError::Invalid(format!("unknown check {bad}; use {}", act::CHECKS.join(", "))));
        }
        let want = |c: &str| req.checks.is_empty() || req.checks.iter().any(|x| x == c);
        let ex = self
            .store
            .lock()
            .get_exchange(req.exchange_id)?
            .ok_or_else(|| crate::ServiceError::NotFound(format!("exchange {}", req.exchange_id)))?;
        let endpoint = pm_replay::Endpoint::new(&ex.summary.scheme, &ex.summary.host, ex.summary.port);
        // Work on what the actor may see: secrets stay placeholders until sent.
        let raw = self.redactor.redact(&String::from_utf8_lossy(&ex.request));
        let marker = format!("pm{}", &pm_oast::new_token()[..10]);
        let limit = req.max_requests.unwrap_or(300).clamp(1, 2000);
        // Path segments the app model knows are identifiers (`/users/{username}`) are tested too.
        let id_segments = self.id_segments(req.exchange_id, &ex.summary.path);
        let probes = act::probes_with(&raw, &req.checks, &marker, limit, &id_segments);
        let points = act::points_with(&raw, &id_segments);

        // Multi-step plans: (check, point, payloads to try), most likely first.
        let mut plans: Vec<Plan> = Vec::new();
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
        }
        if probes.is_empty() && plans.is_empty() {
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
        let mut planned = probes.len() + if plans.is_empty() { 1 } else { 3 };
        for raw in probes.iter().map(|p| p.raw.clone()).chain(plans.iter().flat_map(|p| p.samples(&raw))) {
            tier = tier.max(Tier::for_http_request(&raw).0);
        }
        planned += plans.iter().map(Plan::max_requests).sum::<usize>();
        let planned = planned.min(limit + 3);
        let extra = serde_json::json!({ "active_scan": { "checks": req.checks, "max_requests": planned } });
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
        let mut notes = Vec::new();
        let send = |raw: Vec<u8>| {
            let endpoint = endpoint.clone();
            async move {
                let mut o = self.outgoing(endpoint, &raw, true)?;
                o.hypothesis_id = req.hypothesis_id;
                let (sent, _) = self.send_as(actor, &o, identity, true, "scan").await?;
                Ok::<_, crate::ServiceError>(sent)
            }
        };
        let b = send(raw.clone().into_bytes()).await?;
        let base_seen = seen_of(b.response.as_deref());
        let mut issues: Vec<ActiveFinding> = Vec::new();
        let found = |issues: &[ActiveFinding], family: &str, pt: &str| {
            issues.iter().any(|f| f.issue.check.starts_with(family) && f.issue.point.ends_with(pt))
        };

        // 1. One-shot probes (fast).
        for p in &probes {
            // One issue per check and parameter is enough.
            if issues.iter().any(|f| f.issue.check == p.check && f.issue.point.ends_with(&p.point.name)) {
                continue;
            }
            if sent_count >= limit {
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

        // 2 and 3. Multi-step checks: boolean pairs, then delays (slowest last).
        if !plans.is_empty() {
            let b2 = send(raw.clone().into_bytes()).await?;
            let b3 = send(raw.clone().into_bytes()).await?;
            let base2 = seen_of(b2.response.as_deref());
            let base_ms = vec![b.elapsed_ms, b2.elapsed_ms, b3.elapsed_ms];
            let timing_ok = act::timing_usable(&base_ms);
            if !timing_ok && plans.iter().any(|p| matches!(p, Plan::Time(..))) {
                notes.push(format!("time-based checks skipped: the baseline is slow ({base_ms:?} ms)"));
            }
            plans.sort_by_key(|p| matches!(p, Plan::Time(..)));
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
