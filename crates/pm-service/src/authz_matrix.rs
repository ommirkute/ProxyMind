//! The authorization matrix: every readable operation replayed as every
//! identity (and anonymously), as a role × endpoint grid. Cells where
//! someone else gets the owner's data are flagged (possible IDOR, missing
//! function-level checks, missing authentication) and, on request, proven
//! with the differential oracle; proven ones become findings.

use std::collections::BTreeMap;

use pm_identity::ANONYMOUS;
use pm_policy::{Actor, Tier};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{AuthzCheckRequest, NewFinding, ProofRequest, ProofResult, Result, Service};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthzMatrixRequest {
    /// Prove each flagged cell (differential oracle) and record proven ones as findings.
    pub prove: bool,
    /// Most operations to test (default 40, max 200).
    pub max_operations: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatrixCell {
    /// owner, same_as_owner, allowed_different, denied, inconclusive, needs_approval, not_allowed, error
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatrixFlag {
    pub identity: String,
    /// idor, bfla or no_auth
    pub kind: String,
    pub why: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proven: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatrixRow {
    pub operation: String,
    pub exchange_id: i64,
    /// The identity the recorded request was made as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub cells: BTreeMap<String, MatrixCell>,
    pub flags: Vec<MatrixFlag>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthzMatrix {
    /// Columns: (identity, role); `anonymous` last.
    pub identities: Vec<(String, String)>,
    pub rows: Vec<MatrixRow>,
    /// Operations not tested, and why.
    pub skipped: Vec<String>,
    pub flagged: usize,
    pub proven: usize,
}

fn privileged(role: &str) -> bool {
    let r = role.to_ascii_lowercase();
    ["admin", "staff", "manager", "support", "operator", "root", "superuser"].iter().any(|p| r.contains(p))
}

impl Service {
    /// Builds the matrix (and proves flagged cells when asked). Every request
    /// goes through the rules of engagement like any authorization check.
    pub async fn authz_matrix(&self, actor: &Actor, req: AuthzMatrixRequest) -> Result<AuthzMatrix> {
        let model = self.model()?;
        let mut ids: Vec<(String, String)> =
            self.identity_list()?.into_iter().map(|i| (i.name, i.role)).filter(|(n, _)| n != ANONYMOUS).collect();
        ids.sort();
        let role_of = |n: &str| ids.iter().find(|(x, _)| x == n).map(|(_, r)| r.clone()).unwrap_or_default();
        // Who made a recorded request: stored for replays, matched by credentials for proxied traffic.
        let identities: Vec<pm_identity::Identity> =
            self.store.lock().list_identities()?.iter().filter_map(|r| serde_json::from_str(&r.data).ok()).collect();
        let max = req.max_operations.unwrap_or(40).clamp(1, 200);
        let mut out = AuthzMatrix { identities: ids.clone(), rows: vec![], skipped: vec![], flagged: 0, proven: 0 };
        out.identities.push((ANONYMOUS.into(), String::new()));
        for op in &model.operations {
            if out.rows.len() >= max {
                out.skipped.push(format!("{}: over the limit of {max} operations", op.key));
                continue;
            }
            if Tier::for_http_method(&op.method) != Tier::ActiveSafe {
                out.skipped.push(format!("{}: changes state (test it with replay_send per identity)", op.key));
                continue;
            }
            let lower = op.template.to_ascii_lowercase();
            if ["logout", "signout", "log-out", "sign-out"].iter().any(|w| lower.contains(w)) {
                out.skipped.push(format!("{}: would end the session", op.key));
                continue;
            }
            // A recent successful example, made as a known identity if possible.
            let mut pick: Option<(i64, Option<String>)> = None;
            for id in op.examples.iter().rev() {
                let Some(ex) = self.store.lock().get_exchange(*id)? else { continue };
                if !ex.summary.status.is_some_and(|s| (200..300).contains(&s)) {
                    continue;
                }
                let owner = ex
                    .summary
                    .identity
                    .clone()
                    .or_else(|| crate::model::resolve_identity(&ex.request, &identities))
                    .filter(|i| ids.iter().any(|(n, _)| n == i));
                if owner.is_some() {
                    pick = Some((*id, owner));
                    break;
                }
                pick.get_or_insert((*id, None));
            }
            let Some((exchange_id, owner)) = pick else {
                out.skipped.push(format!("{}: no successful recorded request", op.key));
                continue;
            };
            let others: Vec<String> =
                ids.iter().map(|(n, _)| n.clone()).filter(|n| Some(n) != owner.as_ref()).collect();
            let report = match self
                .authz_check(
                    actor,
                    AuthzCheckRequest { exchange_id, identities: others, include_anonymous: Some(true) },
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    out.skipped.push(format!("{}: {e}", op.key));
                    continue;
                }
            };
            let mut cells = BTreeMap::new();
            if let Some(o) = &owner {
                cells.insert(
                    o.clone(),
                    MatrixCell {
                        verdict: "owner".into(),
                        status: report.baseline_status,
                        evidence_id: Some(exchange_id),
                    },
                );
            }
            let mut flags = Vec::new();
            for r in &report.results {
                cells.insert(
                    r.identity.clone(),
                    MatrixCell { verdict: r.verdict.clone(), status: r.status, evidence_id: r.evidence_id },
                );
                if r.verdict != "same_as_owner" {
                    continue;
                }
                let flag = if r.identity == ANONYMOUS {
                    op.authenticated.then(|| ("no_auth", "returns the same data without any credentials".to_string()))
                } else if let Some(o) = &owner {
                    let (orole, rrole) = (role_of(o), role_of(&r.identity));
                    if (privileged(&orole) && !privileged(&rrole)) || (lower.contains("/admin") && !privileged(&rrole))
                    {
                        Some(("bfla", format!("{} ({}) gets what {} ({}) gets", r.identity, rrole, o, orole)))
                    } else if op.template.contains('{') {
                        Some(("idor", format!("{} reads {}'s object", r.identity, o)))
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some((kind, why)) = flag {
                    flags.push(MatrixFlag {
                        identity: r.identity.clone(),
                        kind: kind.into(),
                        why,
                        proven: None,
                        finding_id: None,
                    });
                }
            }
            out.flagged += flags.len();
            if req.prove
                && let Some(o) = &owner
            {
                for f in &mut flags {
                    let proof = self
                        .proof_run(
                            actor,
                            ProofRequest {
                                oracle: "differential_authz".into(),
                                exchange_id: Some(exchange_id),
                                attacker: Some(f.identity.clone()),
                                owner: Some(o.clone()),
                                ..Default::default()
                            },
                        )
                        .await;
                    let Ok(ProofResult::Completed { proof_id, proven, exchange_ids, .. }) = proof else { continue };
                    f.proven = Some(proven);
                    if !proven {
                        continue;
                    }
                    let (class, label) = match f.kind.as_str() {
                        "bfla" => ("bfla", "Missing function-level access control"),
                        "no_auth" => ("authn", "Missing authentication"),
                        _ => ("idor", "Broken object level authorization"),
                    };
                    let finding = self.finding_create(
                        actor,
                        NewFinding {
                            title: format!("{label}: {} on {} {}", f.identity, op.method, op.template),
                            vuln_class: class.into(),
                            severity: "high".into(),
                            description: format!(
                                "Found by the authorization matrix and proven by the differential oracle: {}. The \
                                 request was recorded as {o}.",
                                f.why
                            ),
                            url: None,
                            evidence: std::iter::once(exchange_id).chain(exchange_ids).collect(),
                            hypothesis_id: None,
                        },
                    )?;
                    if let Some(fid) = finding["id"].as_i64() {
                        self.link_proof(proof_id, fid)?;
                        f.finding_id = Some(fid);
                        out.proven += 1;
                    }
                }
            }
            out.rows.push(MatrixRow { operation: op.key.clone(), exchange_id, owner, cells, flags });
        }
        // Flagged rows first.
        out.rows.sort_by_key(|r| std::cmp::Reverse(r.flags.len()));
        self.audit(
            &actor.id(),
            "authz_matrix",
            json!({ "operations": out.rows.len(), "flagged": out.flagged, "proven": out.proven }),
            "ok",
        )?;
        Ok(out)
    }
}
