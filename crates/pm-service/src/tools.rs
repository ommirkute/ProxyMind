//! Decoder, Comparer and Sequencer.

use pm_policy::{Actor, ActorKind, Tier};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Authorization, Result, Service, ServiceError};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DecodeRequest {
    pub input: String,
    /// Operations in order; empty means smart decode.
    pub ops: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SequencerRequest {
    /// The request that issues a token (e.g. a login or a page setting a cookie).
    pub exchange_id: i64,
    /// Where the token is: cookie:<name>, header:<name>, json:/pointer or between:<start>|<end>.
    pub locator: String,
    /// How many tokens to collect (default 100, 10–500).
    pub samples: Option<usize>,
    pub identity: Option<String>,
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SequencerResult {
    /// Statistics only: the tokens themselves are live secrets and aren't returned.
    Done {
        requests: usize,
        found: usize,
        analysis: pm_tools::sequencer::Analysis,
        exchange_ids: Vec<i64>,
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

fn text_of(raw: &[u8], max: usize) -> String {
    let t = String::from_utf8_lossy(raw);
    if t.len() <= max {
        return t.into_owned();
    }
    let mut cut = max;
    while !t.is_char_boundary(cut) {
        cut -= 1;
    }
    t[..cut].to_string()
}

impl Service {
    /// Encodes/decodes locally (nothing is sent).
    pub fn decode(&self, req: &DecodeRequest) -> Result<Value> {
        if req.input.len() > pm_tools::codec::MAX_OUTPUT {
            return Err(ServiceError::Invalid("input larger than 4 MB".into()));
        }
        let steps = if req.ops.is_empty() {
            pm_tools::codec::smart_decode(&req.input)
        } else {
            pm_tools::codec::chain(&req.ops, &req.input).map_err(|e| ServiceError::Invalid(e.to_string()))?
        };
        Ok(json!({ "steps": steps, "ops": pm_tools::codec::OPS }))
    }

    /// Compares two recorded exchanges: a semantic response diff and line
    /// diffs of the requests and responses (secrets hidden for agents).
    pub fn compare_exchanges(&self, actor: &Actor, a: i64, b: i64) -> Result<Value> {
        let get = |id: i64| -> Result<pm_store::Exchange> {
            self.store.lock().get_exchange(id)?.ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))
        };
        let (ea, eb) = (get(a)?, get(b)?);
        let redact = |s: String| match self.redactor_for(actor) {
            Some(r) => r.redact(&s),
            None => s,
        };
        let req_a = redact(text_of(&ea.request, 200_000));
        let req_b = redact(text_of(&eb.request, 200_000));
        let resp_a = redact(ea.response.as_deref().map(|r| text_of(r, 200_000)).unwrap_or_default());
        let resp_b = redact(eb.response.as_deref().map(|r| text_of(r, 200_000)).unwrap_or_default());
        let semantic = match (&ea.response, &eb.response) {
            (Some(x), Some(y)) => {
                let d = pm_diff::diff(x, y, &Default::default());
                json!({ "similarity": d.similarity, "summary": d.summary, "differences": d.differences })
            }
            _ => Value::Null,
        };
        let mut out = json!({
            "a": a, "b": b,
            "response_semantic": semantic,
            "request_lines": pm_tools::linediff::diff(&req_a, &req_b),
            "response_lines": pm_tools::linediff::diff(&resp_a, &resp_b),
        });
        if actor.kind == ActorKind::Agent {
            out["notice"] = json!(pm_ai::UNTRUSTED_NOTICE);
        }
        Ok(out)
    }

    /// Analyses pasted tokens (nothing is sent).
    pub fn sequencer_analyze(&self, tokens: &[String]) -> Result<pm_tools::sequencer::Analysis> {
        if tokens.len() < 2 || tokens.len() > 100_000 {
            return Err(ServiceError::Invalid("give 2 to 100000 tokens".into()));
        }
        Ok(pm_tools::sequencer::analyze(tokens))
    }

    /// Re-sends a token-issuing request and analyses the tokens it returns.
    pub async fn sequencer_run(&self, actor: &Actor, req: SequencerRequest) -> Result<SequencerResult> {
        let samples = req.samples.unwrap_or(100).clamp(10, 500);
        if !["cookie:", "header:", "json:", "between:"].iter().any(|p| req.locator.starts_with(p)) {
            return Err(ServiceError::Invalid(
                "locator: cookie:<name>, header:<name>, json:/pointer or between:<a>|<b>".into(),
            ));
        }
        let ex = self
            .store
            .lock()
            .get_exchange(req.exchange_id)?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {}", req.exchange_id)))?;
        let raw = self.redactor.redact(&String::from_utf8_lossy(&ex.request));
        let endpoint = pm_replay::Endpoint::new(&ex.summary.scheme, &ex.summary.host, ex.summary.port);
        let out = self.outgoing(endpoint, raw.as_bytes(), true)?;
        // Many copies of a state-changing request (a login) is intrusive.
        let tier = Tier::for_http_request(&out.raw).0.max(Tier::ActiveSafe);
        let extra = json!({ "sequencer": { "samples": samples, "locator": req.locator } });
        match self.gate_send_with(
            actor,
            "sequencer_run",
            &out,
            req.identity.as_deref(),
            true,
            req.approval_id.as_deref(),
            Some(tier),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(SequencerResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(SequencerResult::PendingApproval {
                    approval_id,
                    summary: format!("sequencer ×{samples}: {summary}"),
                    reasons,
                });
            }
        }
        let mut tokens = Vec::new();
        let mut ids = Vec::new();
        for _ in 0..samples {
            let (sent, _) = self.send_as(actor, &out, req.identity.as_deref(), true, "sequencer").await?;
            ids.push(sent.exchange_id);
            if let Some(t) = sent
                .response
                .as_deref()
                .and_then(|r| pm_tools::sequencer::extract(&String::from_utf8_lossy(r), &req.locator))
            {
                tokens.push(t);
            }
        }
        if tokens.len() < 2 {
            return Err(ServiceError::Invalid(format!(
                "found the token in {} of {samples} responses; check the locator",
                tokens.len()
            )));
        }
        Ok(SequencerResult::Done {
            requests: samples,
            found: tokens.len(),
            analysis: pm_tools::sequencer::analyze(&tokens),
            exchange_ids: ids,
        })
    }
}
