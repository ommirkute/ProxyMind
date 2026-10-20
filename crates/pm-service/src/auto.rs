//! Deterministic, model-free passes: content discovery (with an API
//! description imported when one turns up), the access-control candidates
//! the app model suggests (checked as the other identities; leaks recorded
//! and proven), and an active-scanner sweep of recorded GET operations.
//! It's the "ProxyMind without an agent" baseline for benchmarks, and a
//! quick first sweep for humans. Everything goes through the same gated
//! service calls an agent would use.

use pm_policy::Actor;
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
    // Issues the sql_error probes report for other query languages.
    ("nosql_error", "nosqli"),
    ("ldap_error", "ldap_injection"),
    ("xpath_error", "xpath_injection"),
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
];

/// Checks run on recorded submissions (POST, PUT, PATCH): these re-send the
/// request, so they change state on the target like the original did.
const SWEEP_SUBMIT_CHECKS: &[&str] = &["stored_xss", "csrf", "jwt", "graphql", "mass_assignment", "proto_pollution"];
const SWEEP_MAX_SUBMITS: usize = 10;
/// Of those, the ones that only make sense on submissions.
const SUBMIT_ONLY: &[&str] = &["stored_xss", "csrf", "mass_assignment", "proto_pollution"];

/// Most operations with parameters one sweep scans, and most without.
const SWEEP_MAX_OPERATIONS: usize = 40;
const SWEEP_MAX_PLAIN: usize = 30;

/// Whether a path's words suggest that requesting it changes state.
fn changes_state(template: &str) -> bool {
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
                    Ok(OpenApiImportResult::Imported { operations, sent, .. }) => {
                        sweep.openapi = Some((spec.url.clone(), operations.len(), sent.len()));
                    }
                    Ok(other) => sweep.skipped.push(format!("{}: {other:?}", spec.url)),
                    // Not a spec after all (an HTML page, say): nothing to import.
                    Err(e) => sweep.skipped.push(format!("{}: {e}", spec.url)),
                }
            }
        }
        Ok(sweep)
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
            // A token weakness (weak secret, alg none) shows on every endpoint
            // that takes the token: one finding per kind is enough.
            let issues: Vec<_> =
                issues.into_iter().filter(|f| f.issue.check != "jwt" || seen_jwt.insert(f.issue.title)).collect();
            sweep.leads.extend(self.record_scan_leads(actor, &t, &issues)?);
        }
        Ok(sweep)
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
            .filter(|(c, _)| runnable(c) && !SUBMIT_ONLY.contains(c))
            .map(|(c, _)| c.to_string())
            .collect();
        let submit_checks: Vec<String> = SWEEP_SUBMIT_CHECKS.iter().map(|c| c.to_string()).collect();
        let same_origin = |o: &&pm_model::Operation| origin.is_none_or(|x| o.origin.eq_ignore_ascii_case(x));
        // GETs that worked, minus ones whose name says they change state
        // (`/createdb`, `/logout`…: a GET is not always harmless).
        let candidates: Vec<_> = model
            .operations
            .iter()
            .filter(same_origin)
            .filter(|o| o.method == "GET" && !changes_state(&o.template))
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
            .filter(|o| !changes_state(&o.template) && !o.template.to_ascii_lowercase().contains("login"))
            .filter(|o| o.statuses.keys().any(|s| (200..300).contains(s)))
            .take(max_submits)
            .map(|o| (o, &submit_checks));
        let mut out = Vec::new();
        for (op, checks) in ops.chain(submits) {
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
        for f in issues {
            let Some((_, class)) = SWEEP_CHECKS.iter().find(|(c, _)| *c == f.issue.check) else { continue };
            if !seen.insert(*class) {
                continue;
            }
            let finding = self.finding_create(
                actor,
                NewFinding {
                    title: format!("{} in {} ({})", f.issue.title, t.operation, f.issue.point),
                    vuln_class: (*class).into(),
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
        Ok(report)
    }
}
