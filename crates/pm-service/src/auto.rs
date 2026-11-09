//! Deterministic, model-free passes: content discovery (with an API
//! description imported when one turns up), the access-control candidates
//! the app model suggests (checked as the other identities; leaks recorded
//! and proven), and an active-scanner sweep of recorded GET operations.
//! It's the "ProxyMind without an agent" baseline for benchmarks, and a
//! quick first sweep for humans. Everything goes through the same gated
//! service calls an agent would use.

use pm_policy::{Actor, Tier};
use serde_json::json;

use crate::Authorization;
use serde::Serialize;

use crate::{
    ActiveScanRequest, ActiveScanResult, AuthzCheckRequest, DiscoverRequest, DiscoverResult, FindingUpdate, NewFinding,
    OpenApiImportRequest, OpenApiImportResult, ProofRequest, ProofResult, Result, Service,
};

#[derive(Debug, Clone, Serialize)]
pub struct AutoProven {
    pub operation: String,
    pub owner: String,
    pub attacker: String,
    pub finding_id: i64,
    pub proven: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct AutoReport {
    pub candidates: usize,
    pub checks: usize,
    pub leaks: usize,
    pub results: Vec<AutoProven>,
    /// Responses to one test user that show another's email (lists of users…).
    pub exposures: Vec<ScanLead>,
}

/// A strong active-scan signal recorded as a suspected finding.
#[derive(Debug, Clone, Serialize)]
pub struct ScanLead {
    pub operation: String,
    pub check: String,
    pub finding_id: i64,
    pub evidence: String,
}

/// One operation to scan, with the example request and its checks.
#[derive(Debug, Clone)]
pub(crate) struct ScanTarget {
    pub operation: String,
    pub exchange_id: i64,
    pub checks: Vec<String>,
    /// A POST, PUT or PATCH (only re-sent by the submission checks).
    pub submission: bool,
    /// Only these checks suit it (a login, a password change): callers must
    /// not widen the list.
    pub fixed: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ScanSweep {
    pub operations: usize,
    pub requests: usize,
    pub leads: Vec<ScanLead>,
    /// Operations the gate refused or that need approval (not scanned).
    pub skipped: Vec<String>,
}

/// Checks whose hits are strong enough to record without a human (each is a
/// difference from the baseline the server can't produce by accident).
const SWEEP_CHECKS: &[(&str, &str)] = &[
    ("sql_error", "sqli"),
    ("cmd_injection", "command_injection"),
    ("ssti", "ssti"),
    ("path_traversal", "path_traversal"),
    ("open_redirect", "open_redirect"),
    ("sql_boolean", "sqli"),
    ("sql_time", "sqli"),
    ("cmd_time", "command_injection"),
    // Out of band (only with an OAST listener).
    ("ssrf_oob", "ssrf"),
    ("xxe_oob", "xxe"),
    ("sql_oob", "sqli"),
    ("cmd_oob", "command_injection"),
    ("ssti_oob", "ssti"),
    ("log4shell", "rce"),
    ("code_oob", "code_injection"),
    ("crlf", "crlf"),
    ("nosql_operator", "nosqli"),
    ("auth_bypass", "auth_bypass"),
    ("host_header", "host_header_injection"),
    ("cors", "cors"),
    // Recorded only for a debug-like name (debug, test…) that changes the
    // answer: an exposure (see `lead_class`).
    ("hidden_params", "exposure"),
    // Issues the sql_error probes report for other query languages.
    ("nosql_error", "nosqli"),
    ("ldap_error", "ldap_injection"),
    ("xpath_error", "xpath_injection"),
    // Unencoded `"'<` in an HTML page: worth a finding (prove it with the reflection oracle).
    ("reflected_input", "xss"),
    ("dom_xss", "dom_xss"),
    // Submissions only (see SWEEP_SUBMIT_CHECKS).
    ("stored_xss", "stored_xss"),
    ("csrf", "csrf"),
    // Step 4.
    ("jwt", "jwt"),
    ("graphql", "graphql"),
    ("cache_poisoning", "cache_poisoning"),
    ("cache_deception", "cache_deception"),
    ("mass_assignment", "mass_assignment"),
    ("proto_pollution", "prototype_pollution"),
    ("oauth", "oauth"),
    ("deserialization", "deserialization"),
    // Approval only: a separate pass (see auto_active_sweep).
    ("request_smuggling", "request_smuggling"),
    ("file_upload", "file_upload"),
    ("race_condition", "race_condition"),
    // Logins and password changes only (see LOGIN_CHECKS, scan_targets).
    ("user_enumeration", "user_enumeration"),
    ("password_change", "broken_authentication"),
];

/// The finding class for a sweep issue, if the sweep records it.
fn lead_class(issue: &pm_scan::active::ActiveIssue) -> Option<&'static str> {
    const DEBUG_NAMES: &[&str] = &["debug", "test", "dev", "verbose", "trace", "internal"];
    let (_, class) = SWEEP_CHECKS.iter().find(|(c, _)| *c == issue.check)?;
    if issue.check == "hidden_params" {
        // Other names (sort, callback, id…) are usually filters or echoes:
        // worth a look by hand, not a finding.
        let debug = DEBUG_NAMES.iter().any(|n| issue.payload.eq_ignore_ascii_case(n));
        return (debug && !issue.evidence.contains("come back in the response")).then_some("exposure");
    }
    Some(class)
}

/// Checks run on recorded logins: injections (the login is re-sent with a
/// payload, which changes nothing) and account enumeration.
const LOGIN_CHECKS: &[&str] = &["sql_error", "sql_boolean", "nosql_operator", "user_enumeration"];
const MAX_LOGINS: usize = 3;

/// Whether an operation is a login.
pub(crate) fn is_login(template: &str) -> bool {
    let t = template.to_ascii_lowercase();
    ["login", "signin", "sign-in", "sign_in", "authenticate", "/auth/token", "/session"].iter().any(|w| t.contains(w))
}

/// Whether an operation creates an account (a sign-up).
fn is_signup(method: &str, path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    method == "POST" && ["register", "signup", "sign-up", "sign_up", "/join", "/enroll"].iter().any(|w| p.contains(w))
}

/// Whether an operation changes a password: only the password-change check
/// runs on it (any other probe could change the test user's password).
fn is_password_change(template: &str) -> bool {
    let t = template.to_ascii_lowercase();
    t.contains("password") && !t.contains("forgot") && !t.contains("reset")
}

/// Checks run on recorded submissions (POST, PUT, PATCH): these re-send the
/// request, so they change state on the target like the original did.
const SWEEP_SUBMIT_CHECKS: &[&str] =
    &["stored_xss", "csrf", "jwt", "graphql", "mass_assignment", "proto_pollution", "deserialization", "xxe_oob"];
const SWEEP_MAX_SUBMITS: usize = 10;
/// Of those, the ones that only make sense on submissions.
const SUBMIT_ONLY: &[&str] = &["stored_xss", "csrf", "mass_assignment", "proto_pollution"];

/// Most operations with parameters one sweep scans, and most without.
const SWEEP_MAX_OPERATIONS: usize = 40;
const SWEEP_MAX_PLAIN: usize = 30;

/// Whether a path's words suggest that requesting it changes state.
pub(crate) fn changes_state(template: &str) -> bool {
    const WORDS: &[&str] = &[
        "logout", "signout", "sign-out", "log-out", "createdb", "initdb", "reset", "delete", "remove", "destroy",
        "drop", "purge", "flush", "clear", "truncate", "shutdown", "restart", "reboot", "install", "setup", "seed",
    ];
    let t = template.to_ascii_lowercase();
    WORDS.iter().any(|w| t.contains(w))
}

/// What content discovery added to the baseline.
#[derive(Debug, Clone, Serialize, Default)]
pub struct DiscoverSweep {
    pub origins: Vec<String>,
    pub found: usize,
    /// Sensitive files found, recorded as suspected exposure findings.
    pub leads: Vec<ScanLead>,
    /// An API description found and imported: (url, operations, GET examples sent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openapi: Option<(String, usize, usize)>,
    /// Sign-up examples from the description that were sent (so registration gets tested).
    pub signups: Vec<String>,
    /// Pages found in folders robots.txt hides.
    pub robots_found: usize,
    /// Other API versions of known paths that answer (`POST /api/v2/login → 401`).
    pub versions: Vec<String>,
    /// XML upload examples from the description that were sent (for the XXE checks).
    pub xml_examples: Vec<String>,
    /// What reading the app's JavaScript added, per origin.
    pub js: Vec<crate::JsSweep>,
    pub skipped: Vec<String>,
}

/// Discovery notes that mean the file itself is the problem.
const EXPOSURE_NOTES: &[&str] = &[
    "source control metadata",
    "environment file (often secrets)",
    "password file",
    "database dump",
    "memory dump",
    "server configuration",
    "metrics",
];

impl Service {
    /// Looks for hidden files at the root of every origin seen in traffic
    /// (GET only, in scope only), records sensitive ones as suspected
    /// exposure findings, and imports an API description if one turns up,
    /// sending its GET examples so later passes can test those endpoints.
    pub async fn auto_discover(&self, actor: &Actor) -> Result<DiscoverSweep> {
        let mut sweep = DiscoverSweep::default();
        let origins: std::collections::BTreeSet<String> =
            self.model()?.operations.iter().map(|o| o.origin.clone()).collect();
        for origin in origins {
            let r = self.discover(actor, DiscoverRequest { url: format!("{origin}/"), ..Default::default() }).await?;
            let found = match r {
                DiscoverResult::Done { found, .. } => found,
                DiscoverResult::Denied { reasons } => {
                    sweep.skipped.push(format!("{origin}: {}", reasons.join("; ")));
                    continue;
                }
                DiscoverResult::PendingApproval { summary, .. } => {
                    sweep.skipped.push(format!("{origin}: needs approval ({summary})"));
                    continue;
                }
            };
            sweep.origins.push(origin.clone());
            sweep.found += found.len();
            // One finding per kind of exposure (.git/HEAD and .git/config are one
            // problem), on the most telling file: a config if there is one.
            let mut by_note: std::collections::BTreeMap<&str, &crate::Found> = std::collections::BTreeMap::new();
            for f in found.iter().filter(|f| f.status == 200) {
                if let Some(note) = f.note.filter(|n| EXPOSURE_NOTES.contains(n)) {
                    let better =
                        by_note.get(note).is_none_or(|cur| !cur.url.contains("config") && f.url.contains("config"));
                    if better {
                        by_note.insert(note, f);
                    }
                }
            }
            for (note, f) in by_note {
                let finding = self.finding_create(
                    actor,
                    NewFinding {
                        title: format!("Exposed file: {} ({note})", f.url),
                        vuln_class: "exposure".into(),
                        severity: "medium".into(),
                        description: format!(
                            "Content discovery fetched {} (status {}, {} bytes). Check what it reveals.",
                            f.url, f.status, f.length
                        ),
                        url: Some(f.url.clone()),
                        evidence: vec![f.exchange_id],
                        hypothesis_id: None,
                    },
                )?;
                sweep.leads.push(ScanLead {
                    operation: format!("GET {}", f.url),
                    check: "exposure".into(),
                    finding_id: finding["id"].as_i64().unwrap_or_default(),
                    evidence: note.into(),
                });
            }
            sweep.leads.extend(self.listed_files(actor, &found).await?);
            sweep.leads.extend(self.debug_endpoints(actor, &origin).await?);
            let hidden = self.robots_discover(actor, &origin, &found).await?;
            sweep.robots_found += hidden.len();
            sweep.found += hidden.len();
            let spec = found.iter().find(|f| {
                f.status == 200
                    && f.note == Some("API description")
                    && !f.url.ends_with(".html")
                    && !f.url.ends_with('/')
            });
            if let Some(spec) = spec.filter(|_| sweep.openapi.is_none()) {
                let r = self
                    .openapi_import(
                        actor,
                        OpenApiImportRequest {
                            exchange_id: Some(spec.exchange_id),
                            send_examples: true,
                            ..Default::default()
                        },
                    )
                    .await;
                match r {
                    Ok(OpenApiImportResult::Imported { operations, sent, base_url, .. }) => {
                        sweep.openapi = Some((spec.url.clone(), operations.len(), sent.len()));
                        if let Some(base) = base_url {
                            self.send_signup_examples(actor, &base, &operations, &mut sweep).await?;
                            sweep.xml_examples.extend(self.send_xml_examples(actor, &base, &operations).await?);
                        }
                    }
                    Ok(other) => sweep.skipped.push(format!("{}: {other:?}", spec.url)),
                    // Not a spec after all (an HTML page, say): nothing to import.
                    Err(e) => sweep.skipped.push(format!("{}: {e}", spec.url)),
                }
            }
            sweep.versions.extend(self.version_siblings(actor, &origin).await?);
            sweep.js.push(self.js_discover(actor, &origin).await?);
        }
        Ok(sweep)
    }

    /// Sends the description's sign-up examples (unauthenticated POSTs to
    /// register/signup paths, at most two) once each, through the gate, so a
    /// sign-up is in history for the sweep's submission checks (mass
    /// assignment). Each creates one account.
    async fn send_signup_examples(
        &self,
        actor: &Actor,
        base: &str,
        operations: &[pm_openapi::Operation],
        sweep: &mut DiscoverSweep,
    ) -> Result<()> {
        let endpoint = crate::replay::parse_url_endpoint(base)?;
        for op in operations.iter().filter(|o| !o.auth && is_signup(&o.method, &o.path)).take(2) {
            // The description's sample values may be real users' names: make a new account.
            let marker = format!("pm{}", &pm_oast::new_token()[..6]);
            let Some(raw) = pm_scan::advanced::with_unique_account(&op.example_request, &marker) else {
                sweep.skipped.push(format!("sign-up {}: not a JSON body", op.path));
                continue;
            };
            let out = self.outgoing(endpoint.clone(), &raw, true)?;
            let extra = json!({ "openapi_signup": op.path });
            match self.gate_send_with(
                actor,
                "openapi_signup",
                &out,
                None,
                true,
                None,
                Some(Tier::ActiveIntrusive),
                extra,
            )? {
                Authorization::Allowed { .. } => {
                    let (s, _) = self.send_as(actor, &out, None, true, "openapi").await?;
                    sweep.signups.push(format!(
                        "{} {} → {}",
                        op.method,
                        op.path,
                        s.status.map_or("no answer".into(), |c| c.to_string())
                    ));
                }
                Authorization::Denied { reasons } => {
                    sweep.skipped.push(format!("sign-up {}: {}", op.path, reasons.join("; ")))
                }
                Authorization::PendingApproval { summary, .. } => {
                    sweep.skipped.push(format!("sign-up {}: needs approval ({summary})", op.path));
                }
            }
        }
        Ok(())
    }

    /// Runs the active scanner once over each recorded GET operation that
    /// takes parameters (path identifiers or query), and records strong hits
    /// as suspected findings, one per operation and check. Recorded
    /// submissions get only the stored XSS and CSRF checks, which re-send
    /// them (as a browser would); everything goes through the gate.
    pub async fn auto_active_sweep(&self, actor: &Actor) -> Result<ScanSweep> {
        let mut sweep = ScanSweep::default();
        let mut seen_jwt = std::collections::BTreeSet::new();
        for t in self.scan_targets(None, SWEEP_MAX_OPERATIONS, SWEEP_MAX_PLAIN, SWEEP_MAX_SUBMITS)? {
            let r = self
                .scan_active(
                    actor,
                    ActiveScanRequest {
                        exchange_id: t.exchange_id,
                        checks: t.checks.clone(),
                        max_requests: Some(150),
                        oob_wait_seconds: Some(3),
                        ..Default::default()
                    },
                )
                .await;
            let (requests, issues) = match r {
                Ok(ActiveScanResult::Done { requests, issues, .. }) => (requests, issues),
                Ok(ActiveScanResult::PendingApproval { .. }) => {
                    sweep.skipped.push(format!("{}: needs approval", t.operation));
                    continue;
                }
                Ok(ActiveScanResult::Denied { reasons }) => {
                    sweep.skipped.push(format!("{}: {}", t.operation, reasons.join("; ")));
                    continue;
                }
                // No insertion points, or the example vanished: nothing to scan.
                Err(_) => continue,
            };
            sweep.operations += 1;
            sweep.requests += requests;
            // Parameters the page accepts though no request sent them: scan them too.
            let hidden: Vec<String> = issues
                .iter()
                .filter(|f| f.issue.check == "hidden_params")
                .flat_map(|f| f.issue.payload.split(", ").map(str::to_string).collect::<Vec<_>>())
                .collect();
            // A token weakness (weak secret, alg none) shows on every endpoint
            // that takes the token: one finding per kind is enough.
            let issues: Vec<_> =
                issues.into_iter().filter(|f| f.issue.check != "jwt" || seen_jwt.insert(f.issue.title)).collect();
            sweep.leads.extend(self.record_scan_leads(actor, &t, &issues)?);
            if !hidden.is_empty() && !t.fixed {
                let (requests, leads) = self.scan_hidden_params(actor, &t, &hidden).await?;
                sweep.requests += requests;
                sweep.leads.extend(leads);
            }
        }
        // Checks that need approval: one more pass, only when the rules of
        // engagement let this actor run destructive-tier actions without asking.
        let allowed =
            self.policy.roe().tier_decision(actor.kind, pm_policy::Tier::Destructive) == pm_policy::Decision::Allow;
        if !allowed {
            sweep.skipped.push(
                "request smuggling, file upload and race checks: they need approval (run them with scan_active)".into(),
            );
            return Ok(sweep);
        }
        let targets = self.scan_targets(None, SWEEP_MAX_OPERATIONS, SWEEP_MAX_PLAIN, SWEEP_MAX_SUBMITS)?;
        for t in targets.into_iter().filter(|t| !t.fixed) {
            let checks: Vec<String> = if t.submission {
                vec!["file_upload".into(), "race_condition".into()]
            } else {
                vec!["request_smuggling".into()]
            };
            let r = self
                .scan_active(
                    actor,
                    ActiveScanRequest {
                        exchange_id: t.exchange_id,
                        checks,
                        max_requests: Some(60),
                        ..Default::default()
                    },
                )
                .await;
            match r {
                Ok(ActiveScanResult::Done { requests, issues, .. }) => {
                    sweep.requests += requests;
                    sweep.leads.extend(self.record_scan_leads(actor, &t, &issues)?);
                }
                Ok(ActiveScanResult::PendingApproval { .. } | ActiveScanResult::Denied { .. }) => {
                    sweep.skipped.push(
                        "request smuggling, file upload and race checks: they need approval (run them with scan_active)"
                            .into(),
                    );
                    break;
                }
                Err(_) => {}
            }
        }
        Ok(sweep)
    }

    /// Sends the target's request once more with parameters hidden-parameter
    /// discovery found (benign values), and scans those parameters with the
    /// same checks: a page that reads `url` or `file` without any request
    /// sending it gets tested like any other input. Only issues on the new
    /// parameters are recorded (the others were already scanned).
    async fn scan_hidden_params(
        &self,
        actor: &Actor,
        t: &ScanTarget,
        names: &[String],
    ) -> Result<(usize, Vec<ScanLead>)> {
        let Ok(ex) = self.exchange_raw(t.exchange_id) else { return Ok((0, Vec::new())) };
        let raw = String::from_utf8_lossy(&ex.request).into_owned();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let Some(with) = pm_scan::active::with_params(&raw, &refs, "pm") else { return Ok((0, Vec::new())) };
        let s = &ex.summary;
        let endpoint = crate::replay::parse_url_endpoint(&pm_core::url(&s.scheme, &s.host, s.port, "/"))?;
        let out = self.outgoing(endpoint, &with, true)?;
        let extra = json!({ "hidden_params": names, "operation": t.operation });
        match self.gate_send_with(actor, "scan_hidden_params", &out, None, true, None, None, extra)? {
            Authorization::Allowed { .. } => {}
            _ => return Ok((0, Vec::new())),
        }
        let (sent, _) = self.send_as(actor, &out, None, true, "scan").await?;
        let checks: Vec<String> = t.checks.iter().filter(|c| *c != "hidden_params").cloned().collect();
        let req = ActiveScanRequest {
            exchange_id: sent.exchange_id,
            checks,
            max_requests: Some(150),
            oob_wait_seconds: Some(3),
            ..Default::default()
        };
        let Ok(ActiveScanResult::Done { requests, issues, .. }) = self.scan_active(actor, req).await else {
            return Ok((1, Vec::new()));
        };
        let lower: Vec<String> = names.iter().map(|n| n.to_ascii_lowercase()).collect();
        let on_new: Vec<_> = issues
            .into_iter()
            .filter(|f| lower.iter().any(|n| f.issue.point.to_ascii_lowercase().ends_with(&format!(" {n}"))))
            .collect();
        let target = ScanTarget { exchange_id: sent.exchange_id, ..t.clone() };
        Ok((requests + 1, self.record_scan_leads(actor, &target, &on_new)?))
    }

    /// What to scan: recorded operations (optionally of one origin, e.g.
    /// `http://shop:8080`), each with its best example and the checks that
    /// suit it. GETs with parameters first, then a few without (cookies and
    /// headers are their insertion points), then submissions (stored XSS
    /// and CSRF only).
    pub(crate) fn scan_targets(
        &self,
        origin: Option<&str>,
        max_params: usize,
        max_plain: usize,
        max_submits: usize,
    ) -> Result<Vec<ScanTarget>> {
        let model = self.model()?;
        // The checks to request (issue-only names like nosql_error come from sql_error).
        let runnable = |c: &str| pm_scan::active::CHECKS.contains(&c) || pm_scan::oob::CHECKS.contains(&c);
        let checks: Vec<String> = SWEEP_CHECKS
            .iter()
            .filter(|(c, _)| {
                runnable(c)
                    && !SUBMIT_ONLY.contains(c)
                    && !pm_scan::active::APPROVAL_CHECKS.contains(c)
                    && !matches!(*c, "user_enumeration" | "password_change")
            })
            .map(|(c, _)| c.to_string())
            .collect();
        let login_checks: Vec<String> = LOGIN_CHECKS.iter().map(|c| c.to_string()).collect();
        let password_checks: Vec<String> = vec!["password_change".into()];
        let submit_checks: Vec<String> = SWEEP_SUBMIT_CHECKS.iter().map(|c| c.to_string()).collect();
        let same_origin = |o: &&pm_model::Operation| origin.is_none_or(|x| o.origin.eq_ignore_ascii_case(x));
        // GETs that worked, minus ones whose name says they change state
        // (`/createdb`, `/logout`…: a GET is not always harmless).
        let candidates: Vec<_> = model
            .operations
            .iter()
            .filter(same_origin)
            .filter(|o| o.method == "GET" && !changes_state(&o.template) && !is_password_change(&o.template))
            // Answered (2xx), redirected (3xx), or denied (401/403: auth bypass candidates).
            .filter(|o| o.statuses.keys().any(|s| (200..400).contains(s) || *s == 401 || *s == 403))
            .collect();
        let has_params = |o: &&pm_model::Operation| !o.path_params.is_empty() || !o.query_params.is_empty();
        // Among operations without parameters, ones that send credentials
        // first: their cookies and tokens are what the checks work on.
        let mut candidates = candidates;
        candidates.sort_by_key(|o| !o.authenticated);
        let ops = candidates
            .iter()
            .filter(|o| has_params(o))
            .take(max_params)
            .chain(candidates.iter().filter(|o| !has_params(o)).take(max_plain))
            .map(|o| (*o, &checks));
        // Submissions that worked, minus logins and ones whose name says they
        // delete or reset something.
        let submits = model
            .operations
            .iter()
            .filter(same_origin)
            .filter(|o| matches!(o.method.as_str(), "POST" | "PUT" | "PATCH"))
            .filter(|o| !changes_state(&o.template) && !is_login(&o.template) && !is_password_change(&o.template))
            .filter(|o| o.statuses.keys().any(|s| (200..300).contains(s)))
            .take(max_submits)
            .map(|o| (o, &submit_checks, false));
        // Logins answer 401 to a wrong password: any answer will do.
        let logins = model
            .operations
            .iter()
            .filter(same_origin)
            .filter(|o| o.method == "POST" && is_login(&o.template) && !o.statuses.is_empty())
            .take(MAX_LOGINS)
            .map(|o| (o, &login_checks, true));
        // Password changes that worked.
        let password_changes = model
            .operations
            .iter()
            .filter(same_origin)
            .filter(|o| is_password_change(&o.template) && o.statuses.keys().any(|s| (200..300).contains(s)))
            .take(MAX_LOGINS)
            .map(|o| (o, &password_checks, true));
        let mut out = Vec::new();
        let ops = ops.map(|(o, c)| (o, c, false));
        for (op, checks, fixed) in ops.chain(submits).chain(logins).chain(password_changes) {
            // The recent example with the most insertion points (an imported
            // example may lack the browser's cookies and headers).
            // Prefer a request that worked, then one carrying tokens, then
            // the most insertion points.
            let rank = |id: i64| {
                self.exchange_raw(id).map_or((false, 0, 0), |e| {
                    let raw = String::from_utf8_lossy(&e.request);
                    let ok = e.summary.status.is_some_and(|s| (200..400).contains(&s));
                    (ok, pm_scan::advanced::find_jwts(&raw).len(), pm_scan::active::points(&raw).len())
                })
            };
            if let Some(&example) = op.examples.iter().rev().take(10).max_by_key(|&&id| (rank(id), id)) {
                out.push(ScanTarget {
                    operation: op.key.clone(),
                    exchange_id: example,
                    checks: checks.clone(),
                    submission: op.method != "GET",
                    fixed,
                });
            }
        }
        Ok(out)
    }

    /// Records the strong issues of one scan as suspected findings, one per
    /// class and operation (boolean and time SQLi are one bug).
    pub(crate) fn record_scan_leads(
        &self,
        actor: &Actor,
        t: &ScanTarget,
        issues: &[crate::ActiveFinding],
    ) -> Result<Vec<ScanLead>> {
        let url = self.exchange_raw(t.exchange_id).ok().map(|e| {
            let s = &e.summary;
            pm_core::url(&s.scheme, &s.host, s.port, &s.path)
        });
        let mut seen = std::collections::BTreeSet::new();
        let mut leads = Vec::new();
        // A forwarded host the cache keeps is cache poisoning; the same
        // reflection reported again as host header injection adds nothing.
        let poisoned = issues.iter().any(|f| f.issue.check == "cache_poisoning");
        for f in issues {
            if poisoned && f.issue.check == "host_header" {
                continue;
            }
            let Some(class) = lead_class(&f.issue) else { continue };
            if !seen.insert(class) {
                continue;
            }
            let finding = self.finding_create(
                actor,
                NewFinding {
                    title: format!("{} in {} ({})", f.issue.title, t.operation, f.issue.point),
                    vuln_class: class.into(),
                    severity: f.issue.severity.into(),
                    description: format!(
                        "The active scanner sent {:?} in {} and saw: {}. Found by an automatic scan; not proven \
                         yet.",
                        f.issue.payload, f.issue.point, f.issue.evidence
                    ),
                    url: url.clone(),
                    evidence: vec![t.exchange_id, f.exchange_id],
                    hypothesis_id: None,
                },
            )?;
            leads.push(ScanLead {
                operation: t.operation.clone(),
                check: f.issue.check.into(),
                finding_id: finding["id"].as_i64().unwrap_or_default(),
                evidence: f.issue.evidence.chars().take(200).collect(),
            });
        }
        Ok(leads)
    }

    /// Checks every authorization candidate and proves the leaks it finds.
    /// One finding per operation; later leaks on it add nothing.
    pub async fn auto_access_control(&self, actor: &Actor) -> Result<AutoReport> {
        let candidates = self.authz_candidates()?;
        let roles: std::collections::BTreeMap<String, String> =
            self.identity_list()?.into_iter().map(|i| (i.name, i.role.to_ascii_lowercase())).collect();
        let is_admin = |name: &str| roles.get(name).is_some_and(|r| r.contains("admin"));
        let mut report = AutoReport { candidates: candidates.len(), ..Default::default() };
        let mut done_ops = std::collections::BTreeSet::new();
        for c in candidates {
            if done_ops.contains(&c.operation) || c.try_as.is_empty() {
                continue;
            }
            let r = self
                .authz_check(
                    actor,
                    AuthzCheckRequest {
                        exchange_id: c.exchange_id,
                        identities: c.try_as.clone(),
                        include_anonymous: Some(true),
                    },
                )
                .await?;
            report.checks += 1;
            // Anyone, logged in or not, gets the same answer: public data, not a leak.
            if r.results.iter().any(|row| row.identity == pm_identity::ANONYMOUS && row.verdict == "same_as_owner") {
                continue;
            }
            // An admin reading a user's data is expected; only a peer or a
            // less privileged identity getting it is a leak.
            let Some(leak) = r.results.iter().find(|row| {
                row.verdict == "same_as_owner"
                    && row.identity != pm_identity::ANONYMOUS
                    && (!is_admin(&row.identity) || is_admin(&c.owner))
            }) else {
                continue;
            };
            // A user reaching an admin's resource is a missing role check.
            let function_level = is_admin(&c.owner) && !is_admin(&leak.identity);
            report.leaks += 1;
            done_ops.insert(c.operation.clone());
            let finding = self.finding_create(
                actor,
                NewFinding {
                    title: if function_level {
                        format!("{} (not an admin) can call {}", leak.identity, c.operation)
                    } else {
                        format!("{} can read {}'s {}", leak.identity, c.owner, c.object)
                    },
                    vuln_class: if function_level { "bfla".into() } else { "idor".into() },
                    severity: "high".into(),
                    description: format!(
                        "{} returned {}'s data to {} ({}). Found by the automatic access-control pass.",
                        c.operation, c.owner, leak.identity, leak.summary
                    ),
                    url: None,
                    evidence: vec![c.exchange_id],
                    hypothesis_id: None,
                },
            )?;
            let finding_id = finding["id"].as_i64().unwrap_or_default();
            let proof = self
                .proof_run(
                    actor,
                    ProofRequest {
                        oracle: "differential_authz".into(),
                        exchange_id: Some(c.exchange_id),
                        attacker: Some(leak.identity.clone()),
                        owner: Some(c.owner.clone()),
                        finding_id: Some(finding_id),
                        ..Default::default()
                    },
                )
                .await?;
            let (proven, reasons) = match proof {
                ProofResult::Completed { proven, reasons, .. } => (proven, reasons),
                ProofResult::PendingApproval { summary, .. } => (false, vec![format!("needs approval: {summary}")]),
                ProofResult::Denied { reasons } => (false, reasons),
            };
            // What can't be proven isn't kept as a live finding.
            if !proven {
                self.finding_update(
                    actor,
                    FindingUpdate {
                        id: finding_id,
                        status: Some("false_positive".into()),
                        severity: None,
                        description: Some(format!("The automatic pass could not prove it: {}", reasons.join("; "))),
                        add_evidence: vec![],
                    },
                )?;
            }
            report.results.push(AutoProven {
                operation: c.operation.clone(),
                owner: c.owner.clone(),
                attacker: leak.identity.clone(),
                finding_id,
                proven,
                reasons,
            });
        }
        report.exposures = self.cross_user_exposure(actor)?;
        Ok(report)
    }

    /// Directory listings discovery found: fetches the confidential-looking
    /// files they link to (key stores, backups, documents) and records the
    /// most telling one that answers.
    async fn listed_files(&self, actor: &Actor, found: &[crate::Found]) -> Result<Vec<ScanLead>> {
        let mut leads = Vec::new();
        for f in found.iter().filter(|f| f.status == 200 && f.url.ends_with('/')) {
            let Ok(ex) = self.exchange_raw(f.exchange_id) else { continue };
            let text = ex.response.as_deref().map(pm_identity::response_text).unwrap_or_default();
            let lower = text.to_ascii_lowercase();
            if !(lower.contains("<title>index of /") || lower.contains("<title>listing directory /")) {
                continue;
            }
            let words: Vec<String> = pm_scan::advanced::sensitive_listed_files(&text)
                .iter()
                .filter_map(|h| h.trim_end_matches('/').rsplit('/').next().map(str::to_string))
                .filter(|w| !w.is_empty())
                .take(5)
                .collect();
            if words.is_empty() {
                continue;
            }
            let req = DiscoverRequest { url: f.url.clone(), words, max_requests: Some(10), ..Default::default() };
            let DiscoverResult::Done { found: files, .. } = self.discover(actor, req).await? else { continue };
            let Some(file) = files.iter().find(|x| x.status == 200) else { continue };
            let finding = self.finding_create(
                actor,
                NewFinding {
                    title: format!("Confidential file in a public directory listing: {}", file.url),
                    vuln_class: "exposure".into(),
                    severity: "medium".into(),
                    description: format!(
                        "{} lists its files to anyone, and {} answers ({} bytes). Check what the listed files \
                         reveal; take the folder off the web or require a login.",
                        f.url, file.url, file.length
                    ),
                    url: Some(file.url.clone()),
                    evidence: vec![f.exchange_id, file.exchange_id],
                    hypothesis_id: None,
                },
            )?;
            leads.push(ScanLead {
                operation: format!("GET {}", file.url),
                check: "exposure".into(),
                finding_id: finding["id"].as_i64().unwrap_or_default(),
                evidence: "file in a directory listing".into(),
            });
        }
        Ok(leads)
    }

    /// Debug and dump endpoints under the app's API collections
    /// (`/users/v1/_debug`): records any that answer with credentials.
    async fn debug_endpoints(&self, actor: &Actor, origin: &str) -> Result<Vec<ScanLead>> {
        const WORDS: &[&str] = &["_debug", "debug", "dump", "export", "_all", "all", "internal"];
        let mut prefixes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for op in self.model()?.operations.iter().filter(|o| o.origin.eq_ignore_ascii_case(origin)) {
            let fixed: Vec<&str> =
                op.template.split('/').filter(|s| !s.is_empty()).take_while(|s| !s.contains('{')).collect();
            if !fixed.is_empty() && fixed.len() <= 4 && !fixed.iter().any(|s| s.contains('.')) {
                prefixes.insert(format!("/{}", fixed.join("/")));
            }
        }
        let mut leads = Vec::new();
        for prefix in prefixes.into_iter().take(8) {
            let req = DiscoverRequest {
                url: format!("{origin}{prefix}/"),
                words: WORDS.iter().map(|w| w.to_string()).collect(),
                max_requests: Some(WORDS.len() + 4),
                ..Default::default()
            };
            let Ok(DiscoverResult::Done { found, .. }) = self.discover(actor, req).await else { continue };
            for f in found.iter().filter(|f| f.status == 200) {
                let Ok(ex) = self.exchange_raw(f.exchange_id) else { continue };
                let Some(resp) = ex.response.as_deref() else { continue };
                let (_, body) = pm_http::split_message(resp);
                let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
                let keys = pm_scan::advanced::credential_keys(&String::from_utf8_lossy(&body));
                if keys.is_empty() {
                    continue;
                }
                let finding = self.finding_create(
                    actor,
                    NewFinding {
                        title: format!("Debug endpoint exposes credentials: {}", f.url),
                        vuln_class: "exposure".into(),
                        severity: "high".into(),
                        description: format!(
                            "{} answers without being linked from the app, and its response holds {} values. \
                             Remove the endpoint from production.",
                            f.url,
                            keys.join(", ")
                        ),
                        url: Some(f.url.clone()),
                        evidence: vec![f.exchange_id],
                        hypothesis_id: None,
                    },
                )?;
                leads.push(ScanLead {
                    operation: format!("GET {}", f.url),
                    check: "exposure".into(),
                    finding_id: finding["id"].as_i64().unwrap_or_default(),
                    evidence: format!("credentials: {}", keys.join(", ")),
                });
                break;
            }
        }
        Ok(leads)
    }

    /// Recorded responses to one (non-admin) test user that show another
    /// test user's email: lists of users and other cross-account leaks.
    /// One finding per operation. Sends nothing.
    pub(crate) fn cross_user_exposure(&self, actor: &Actor) -> Result<Vec<ScanLead>> {
        let (identities, exchanges) = {
            let store = self.store.lock();
            let ids: Vec<pm_identity::Identity> =
                store.list_identities()?.iter().filter_map(|r| serde_json::from_str(&r.data).ok()).collect();
            (ids, store.recent_exchanges(crate::model::MODEL_WINDOW)?)
        };
        let users: Vec<&pm_identity::Identity> =
            identities.iter().filter(|i| !i.role.to_ascii_lowercase().contains("admin")).collect();
        if users.len() < 2 {
            return Ok(Vec::new());
        }
        // Who sent each response (recorded traffic, not ProxyMind's own probes).
        let seen: Vec<(String, &pm_store::Exchange, String)> = exchanges
            .iter()
            .filter(|e| matches!(e.summary.source.as_str(), "proxy" | "crawl" | "import"))
            .filter(|e| e.summary.method == "GET" && e.summary.status.is_some_and(|s| (200..300).contains(&s)))
            .filter_map(|e| {
                let who =
                    e.summary.identity.clone().or_else(|| crate::model::resolve_identity(&e.request, &identities))?;
                let text = String::from_utf8_lossy(pm_http::split_message(e.response.as_deref()?).1).into_owned();
                Some((who, e, text))
            })
            .collect();
        // Each user's own email: one in their responses that names them, or
        // that their own profile (`/me`, `whoami`, `/profile`, `/account`) shows.
        let mut own: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> = Default::default();
        for (who, e, text) in &seen {
            let name = who.to_ascii_lowercase();
            let path = e.summary.path.to_ascii_lowercase();
            let profile = ["/me", "whoami", "/profile", "/account"].iter().any(|p| path.contains(p));
            for m in pm_scan::advanced::emails(text) {
                let local = m.split('@').next().unwrap_or("");
                if (name.len() >= 3 && local.contains(&name)) || profile {
                    own.entry(who.clone()).or_default().insert(m);
                }
            }
        }
        let mut leads = Vec::new();
        let mut done = std::collections::BTreeSet::new();
        for (who, e, text) in &seen {
            if !users.iter().any(|u| &u.name == who) {
                continue;
            }
            let found = pm_scan::advanced::emails(text);
            let other = users.iter().filter(|u| &u.name != who).find_map(|u| {
                own.get(&u.name)
                    .and_then(|mine| mine.iter().find(|m| found.contains(*m)).map(|m| (u.name.clone(), m.clone())))
            });
            let Some((victim, email)) = other else { continue };
            let template = pm_model::template_path(e.summary.path.split('?').next().unwrap_or("")).0;
            let origin = pm_core::url(&e.summary.scheme, &e.summary.host, e.summary.port, "");
            if !done.insert(format!("{origin}{template}")) {
                continue;
            }
            let url = format!("{origin}{}", e.summary.path.split('?').next().unwrap_or(""));
            let finding = self.finding_create(
                actor,
                NewFinding {
                    title: format!("{who} sees {victim}'s data in GET {template}"),
                    vuln_class: "exposure".into(),
                    severity: "medium".into(),
                    description: format!(
                        "The response to {who} (exchange {}) contains {victim}'s email address ({email}). A list \
                         of other users, or another account's data, is open to every logged-in user.",
                        e.summary.id
                    ),
                    url: Some(url),
                    evidence: vec![e.summary.id],
                    hypothesis_id: None,
                },
            )?;
            leads.push(ScanLead {
                operation: format!("GET {origin}{template}"),
                check: "exposure".into(),
                finding_id: finding["id"].as_i64().unwrap_or_default(),
                evidence: format!("{who} sees {victim}'s email"),
            });
        }
        Ok(leads)
    }
}
