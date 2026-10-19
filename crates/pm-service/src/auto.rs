//! A deterministic, model-free pass over the access-control candidates the
//! app model suggests: check each as the other identities, and record and
//! prove what leaks. It's the "ProxyMind without an agent" baseline for
//! benchmarks, and a quick first sweep for humans. Everything goes through
//! the same gated service calls an agent would use.

use pm_policy::Actor;
use serde::Serialize;

use crate::{AuthzCheckRequest, FindingUpdate, NewFinding, ProofRequest, ProofResult, Result, Service};

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

impl Service {
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
