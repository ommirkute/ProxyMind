//! Authorization checks: replay one recorded request as several identities
//! and classify each response against the original owner's.

use pm_diff::{NoiseMask, diff, learn_noise};
use pm_identity::ANONYMOUS;
use pm_policy::{Actor, Tier};
use pm_replay::Endpoint;
use pm_store::AuthzRow;
use serde::{Deserialize, Serialize};

use crate::{Authorization, Result, Service, ServiceError, now_ms};

/// Responses at least this similar to the owner's count as "the same data".
pub const SAME_DATA_THRESHOLD: f64 = 0.9;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthzCheckRequest {
    /// A recorded GET/HEAD/OPTIONS exchange, made by the data's owner.
    pub exchange_id: i64,
    /// Identities to try (names from identity_list).
    #[serde(default)]
    pub identities: Vec<String>,
    /// Also try with no credentials (default true).
    #[serde(default)]
    pub include_anonymous: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthzReport {
    pub exchange_id: i64,
    pub method: String,
    pub url: String,
    /// Status of the original request when re-sent as recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline_status: Option<u16>,
    pub baseline_exchange_ids: Vec<i64>,
    /// Fields that change between identical requests and were ignored.
    pub noise: NoiseMask,
    pub results: Vec<AuthzRow>,
    pub how_to_read: &'static str,
}

const HOW_TO_READ: &str = "denied: the identity was refused (401/403/404/redirect). same_as_owner: the identity got \
the same data as the owner; a possible broken access control if the data is not meant to be shared (prove it with \
proof_run). allowed_different: a success response with different content, e.g. the identity's own data. \
inconclusive: the baseline or response could not be compared.";

fn classify(status: Option<u16>, similarity: Option<f64>) -> &'static str {
    match status {
        None => "error",
        Some(s) if s == 401 || s == 403 || s == 404 || s == 405 || (300..400).contains(&s) => "denied",
        Some(s) if (200..300).contains(&s) => match similarity {
            Some(x) if x >= SAME_DATA_THRESHOLD => "same_as_owner",
            Some(_) => "allowed_different",
            None => "inconclusive",
        },
        Some(_) => "inconclusive",
    }
}

impl Service {
    pub async fn authz_check(&self, actor: &Actor, req: AuthzCheckRequest) -> Result<AuthzReport> {
        let ex = self
            .store
            .lock()
            .get_exchange(req.exchange_id)?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {}", req.exchange_id)))?;
        let s = &ex.summary;
        if Tier::for_http_method(&s.method) != Tier::ActiveSafe {
            return Err(ServiceError::Invalid(format!(
                "authz_check only replays GET/HEAD/OPTIONS automatically; {} changes state, so test it with \
                 replay_send and an identity (each send may need approval)",
                s.method
            )));
        }
        // Work with the redacted form so audit records hold placeholders,
        // not secrets; real values go back in when sending.
        let raw = self.redactor.redact(&String::from_utf8_lossy(&ex.request));
        let out = self.outgoing(Endpoint::new(&s.scheme, &s.host, s.port), raw.as_bytes(), false)?;
        let url = out.url();

        let mut names: Vec<String> = Vec::new();
        for n in req.identities.iter().cloned().chain(req.include_anonymous.unwrap_or(true).then(|| ANONYMOUS.into())) {
            if !names.contains(&n) {
                self.load_identity(&n)?;
                names.push(n);
            }
        }

        // Baseline: the original request twice, to learn what changes on its own.
        let mut baseline = Vec::new();
        for _ in 0..2 {
            match self.gate_send(actor, "authz_check", &out, None, false, None)? {
                Authorization::Allowed { .. } => {}
                other => return Err(ServiceError::Invalid(format!("baseline not allowed: {other:?}"))),
            }
            baseline.push(self.send_now(actor, &out, None, false, "authz").await?);
        }
        let baseline_ids: Vec<i64> = baseline.iter().map(|b| b.exchange_id).collect();
        let baseline_status = baseline[0].status;
        let owner = baseline[0].response.clone();
        let noise = match (&baseline[0].response, &baseline[1].response) {
            (Some(a), Some(b)) => learn_noise(a, b),
            _ => NoiseMask::default(),
        };
        let baseline_ok = baseline_status.is_some_and(|s| (200..300).contains(&s));

        let mut results = Vec::new();
        for name in names {
            let mut row = AuthzRow {
                id: 0,
                exchange_id: req.exchange_id,
                method: s.method.clone(),
                url: url.clone(),
                identity: name.clone(),
                verdict: String::new(),
                status: None,
                similarity: None,
                evidence_id: None,
                summary: String::new(),
                checked_by: actor.id(),
                checked_ms: now_ms(),
            };
            match self.gate_send(actor, "authz_check", &out, Some(&name), false, None)? {
                Authorization::Allowed { .. } => {
                    let (sent, notes) = self.send_as(actor, &out, Some(&name), false, "authz").await?;
                    row.evidence_id = Some(sent.exchange_id);
                    row.status = sent.status;
                    if let (Some(o), Some(r)) = (&owner, &sent.response) {
                        let d = diff(o, r, &noise);
                        row.similarity = Some(d.similarity);
                        row.summary = d.summary;
                    } else if let Some(e) = &sent.error {
                        row.summary = e.clone();
                    }
                    if !notes.is_empty() {
                        row.summary = format!("{} [{}]", row.summary, notes.join("; "));
                    }
                    row.verdict =
                        if baseline_ok { classify(row.status, row.similarity) } else { "inconclusive" }.into();
                    if !baseline_ok {
                        row.summary = format!(
                            "owner's request returned {}; {}",
                            baseline_status.map_or("no response".to_string(), |s| s.to_string()),
                            row.summary
                        );
                    }
                }
                Authorization::PendingApproval { approval_id, .. } => {
                    row.verdict = "needs_approval".into();
                    row.summary = format!("approval {approval_id} required by the rules of engagement");
                }
                Authorization::Denied { reasons } => {
                    row.verdict = "not_allowed".into();
                    row.summary = reasons.join("; ");
                }
            }
            row.id = self.store.lock().insert_authz(&row)?;
            results.push(row);
        }
        Ok(AuthzReport {
            exchange_id: req.exchange_id,
            method: s.method.clone(),
            url,
            baseline_status,
            baseline_exchange_ids: baseline_ids,
            noise,
            results,
            how_to_read: HOW_TO_READ,
        })
    }

    /// Latest authorization results (per exchange and identity).
    pub fn authz_results(&self, exchange_id: Option<i64>) -> Result<Vec<AuthzRow>> {
        Ok(self.store.lock().authz_results(exchange_id)?)
    }
}

#[cfg(test)]
mod tests {
    use super::classify;

    #[test]
    fn verdicts() {
        assert_eq!(classify(Some(403), None), "denied");
        assert_eq!(classify(Some(302), None), "denied");
        assert_eq!(classify(Some(200), Some(0.95)), "same_as_owner");
        assert_eq!(classify(Some(200), Some(0.2)), "allowed_different");
        assert_eq!(classify(Some(500), Some(1.0)), "inconclusive");
        assert_eq!(classify(None, None), "error");
    }
}
