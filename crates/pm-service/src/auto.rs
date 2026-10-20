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
    ("ssti", "ssti"),
    ("path_traversal", "path_traversal"),
    ("open_redirect", "open_redirect"),
];

/// Most operations one sweep scans.
const SWEEP_MAX_OPERATIONS: usize = 40;

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
    /// as suspected findings, one per operation and check. GET only, so it
    /// changes nothing on the target; everything goes through the gate.
    pub async fn auto_active_sweep(&self, actor: &Actor) -> Result<ScanSweep> {
        let model = self.model()?;
        let mut sweep = ScanSweep::default();
        let checks: Vec<String> = SWEEP_CHECKS.iter().map(|(c, _)| c.to_string()).collect();
        let ops = model
            .operations
            .iter()
            .filter(|o| o.method == "GET" && (!o.path_params.is_empty() || !o.query_params.is_empty()))
            .filter(|o| o.statuses.keys().any(|s| (200..300).contains(s)))
            .take(SWEEP_MAX_OPERATIONS);
        for op in ops {
            let Some(&example) = op.examples.last() else { continue };
            let r = self
                .scan_active(
                    actor,
                    ActiveScanRequest {
                        exchange_id: example,
                        checks: checks.clone(),
                        max_requests: Some(40),
                        ..Default::default()
                    },
                )
                .await;
            let (requests, issues) = match r {
                Ok(ActiveScanResult::Done { requests, issues, .. }) => (requests, issues),
                Ok(ActiveScanResult::PendingApproval { .. }) => {
                    sweep.skipped.push(format!("{}: needs approval", op.key));
                    continue;
                }
                Ok(ActiveScanResult::Denied { reasons }) => {
                    sweep.skipped.push(format!("{}: {}", op.key, reasons.join("; ")));
                    continue;
                }
                // No insertion points, or the example vanished: nothing to scan.
                Err(_) => continue,
            };
            sweep.operations += 1;
            sweep.requests += requests;
            let url = self.exchange_raw(example).ok().map(|e| {
                let s = &e.summary;
                pm_core::url(&s.scheme, &s.host, s.port, &s.path)
            });
            let mut seen = std::collections::BTreeSet::new();
            for f in issues {
                let Some((_, class)) = SWEEP_CHECKS.iter().find(|(c, _)| *c == f.issue.check) else { continue };
                if !seen.insert(f.issue.check) {
                    continue;
                }
                let finding = self.finding_create(
                    actor,
                    NewFinding {
                        title: format!("{} in {} ({})", f.issue.title, op.key, f.issue.point),
                        vuln_class: (*class).into(),
                        severity: f.issue.severity.into(),
                        description: format!(
                            "The active scanner sent {:?} in {} and saw: {}. Found by the automatic sweep; not \
                             proven yet.",
                            f.issue.payload, f.issue.point, f.issue.evidence
                        ),
                        url: url.clone(),
                        evidence: vec![example, f.exchange_id],
                        hypothesis_id: None,
                    },
                )?;
                sweep.leads.push(ScanLead {
                    operation: op.key.clone(),
                    check: f.issue.check.into(),
                    finding_id: finding["id"].as_i64().unwrap_or_default(),
                    evidence: f.issue.evidence.chars().take(200).collect(),
                });
            }
        }
        Ok(sweep)
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
