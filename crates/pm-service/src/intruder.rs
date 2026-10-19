//! Intruder through the policy gate: one approval covers the whole attack
//! (the template, every payload set and the mode), then each request is
//! sent with the usual rate limits, identity handling and recording.

use pm_fuzz::{Mode, Observed, PayloadSet, Template};
use pm_policy::{Actor, Tier};
use pm_replay::Endpoint;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::replay::parse_url_endpoint;
use crate::{Authorization, Result, Service, ServiceError};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntruderRequest {
    /// Recorded exchange whose target to use (scheme, host, port).
    pub exchange_id: Option<i64>,
    /// Target as scheme://host[:port], when not using exchange_id.
    pub url: Option<String>,
    /// The request with positions marked §like this§.
    pub raw: String,
    pub mode: Mode,
    /// One set for sniper and battering ram; one per position otherwise.
    pub payload_sets: Vec<PayloadSet>,
    /// Report responses containing any of these (case-insensitive).
    pub grep: Vec<String>,
    pub identity: Option<String>,
    pub fix_content_length: Option<bool>,
    pub hypothesis_id: Option<i64>,
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IntruderRow {
    pub exchange_id: i64,
    /// Payload per position; null keeps the original value.
    pub payloads: Vec<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub body_length: usize,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<String>,
    pub reflected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum IntruderResult {
    Done {
        /// The request with the original values.
        baseline: IntruderRow,
        results: Vec<IntruderRow>,
        /// Results that stand out, with why; `index` points into results.
        anomalies: Vec<pm_fuzz::Anomaly>,
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

fn invalid(e: impl ToString) -> ServiceError {
    ServiceError::Invalid(e.to_string())
}

impl Service {
    /// Runs an Intruder attack if the policy allows it. Fuzzing is at least
    /// active-intrusive, and the attack takes the highest tier any of its
    /// requests calls for.
    pub async fn intruder_run(&self, actor: &Actor, req: IntruderRequest) -> Result<IntruderResult> {
        let template = Template::parse(&req.raw).map_err(invalid)?;
        let sets: Vec<Vec<String>> =
            req.payload_sets.iter().map(PayloadSet::expand).collect::<std::result::Result<_, _>>().map_err(invalid)?;
        let planned = pm_fuzz::plan(&template, req.mode, &sets).map_err(invalid)?;
        let endpoint: Endpoint = match (req.exchange_id, &req.url) {
            (Some(id), _) => {
                let ex = self
                    .store
                    .lock()
                    .get_exchange(id)?
                    .ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
                Endpoint::new(&ex.summary.scheme, &ex.summary.host, ex.summary.port)
            }
            (None, Some(u)) => parse_url_endpoint(u)?,
            _ => return Err(invalid("give exchange_id or url for the target")),
        };
        if let Some(name) = &req.identity {
            self.load_identity(name)?;
        }
        let baseline = self.outgoing(endpoint.clone(), template.baseline().as_bytes(), true)?;
        let mut outs = Vec::with_capacity(planned.len());
        let mut tier = Tier::ActiveIntrusive;
        for p in &planned {
            let mut out = self.outgoing(endpoint.clone(), p.raw.as_bytes(), true)?;
            out.hypothesis_id = req.hypothesis_id;
            tier = tier.max(Tier::for_http_request(&out.raw).0);
            outs.push(out);
        }
        let fix_cl = req.fix_content_length.unwrap_or(true);
        // The approval binds the whole attack, not just the baseline.
        let extra = json!({
            "intruder": { "template": req.raw, "mode": req.mode, "payload_sets": req.payload_sets,
                          "grep": req.grep, "requests": planned.len() }
        });
        match self.gate_send_with(
            actor,
            "intruder_run",
            &baseline,
            req.identity.as_deref(),
            fix_cl,
            req.approval_id.as_deref(),
            Some(tier),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(IntruderResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(IntruderResult::PendingApproval {
                    approval_id,
                    summary: format!("intruder ({:?}, {} requests): {summary}", req.mode, planned.len()),
                    reasons,
                });
            }
        }

        let grep: Vec<String> = req.grep.iter().filter(|g| !g.is_empty()).map(|g| g.to_lowercase()).collect();
        let mut baseline_out = baseline;
        baseline_out.hypothesis_id = req.hypothesis_id;
        let (b, _) = self.send_as(actor, &baseline_out, req.identity.as_deref(), fix_cl, "intruder").await?;
        let baseline_row = row(b, vec![None; template.positions()], &grep);
        let mut results = Vec::with_capacity(outs.len());
        for (p, out) in planned.into_iter().zip(&outs) {
            let (sent, _) = self.send_as(actor, out, req.identity.as_deref(), fix_cl, "intruder").await?;
            results.push(row(sent, p.payloads, &grep));
        }
        let observe = |r: &IntruderRow| Observed {
            status: r.status,
            body_length: r.body_length,
            elapsed_ms: r.elapsed_ms,
            matches: r.matches.clone(),
            reflected: r.reflected,
        };
        let observed: Vec<Observed> = results.iter().map(observe).collect();
        let anomalies = pm_fuzz::anomalies(Some(&observe(&baseline_row)), &observed);
        Ok(IntruderResult::Done { baseline: baseline_row, results, anomalies })
    }
}

fn row(sent: crate::replay::Sent, payloads: Vec<Option<String>>, grep: &[String]) -> IntruderRow {
    let (body, decoded) = match &sent.response {
        Some(r) => {
            let (head, body) = pm_http::split_message(r);
            let text = match pm_http::parse_response_head(head) {
                Ok(h) => pm_ai::body::decode(&h.headers, body).bytes,
                Err(_) => body.to_vec(),
            };
            (body.len(), String::from_utf8_lossy(&text).to_lowercase())
        }
        None => (0, String::new()),
    };
    let matches = grep.iter().filter(|g| decoded.contains(g.as_str())).cloned().collect();
    // Reflection matters for payloads with markup or quotes (or long unique
    // strings); an id echoed back in JSON is not interesting.
    let reflected = payloads.iter().flatten().any(|p| {
        let plain = pm_policy::payload::normalise(p);
        let telling = plain.len() >= 8 || plain.chars().any(|c| !c.is_alphanumeric() && c != ' ');
        telling && plain.len() >= 3 && (decoded.contains(&p.to_lowercase()) || decoded.contains(&plain))
    });
    IntruderRow {
        exchange_id: sent.exchange_id,
        payloads,
        status: sent.status,
        body_length: body,
        elapsed_ms: sent.elapsed_ms,
        matches,
        reflected,
        error: sent.error,
    }
}
