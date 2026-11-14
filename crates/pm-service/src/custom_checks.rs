//! Custom checks (`pm_scan::custom`): saved in the project (setting
//! `custom_checks`, the YAML as written) and run against a recorded request
//! through the policy gate, with one approval for the whole run.

use pm_policy::{Actor, ActorKind, Tier};
use pm_scan::custom::{self, CustomCheck};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Authorization, Result, Service, ServiceError};

const SETTING: &str = "custom_checks";
const MAX_SAVED: usize = 100;

#[derive(Debug, Clone, Serialize)]
pub struct SavedCustomCheck {
    pub id: String,
    pub yaml: String,
    pub check: CustomCheck,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustomScanRequest {
    /// The recorded request to test.
    pub exchange_id: i64,
    /// Saved checks to run by id (default: all saved checks).
    pub checks: Vec<String>,
    /// A check to try without saving it.
    pub yaml: Option<String>,
    /// Most requests (default 200, max 2000).
    pub max_requests: Option<usize>,
    pub identity: Option<String>,
    pub approval_id: Option<String>,
    pub hypothesis_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CustomFinding {
    pub check: String,
    pub title: String,
    pub severity: String,
    pub point: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// From the target's response: untrusted.
    pub evidence: String,
    pub exchange_id: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CustomScanResult {
    Done { baseline_exchange_id: i64, requests: usize, findings: Vec<CustomFinding> },
    PendingApproval { approval_id: String, summary: String, reasons: Vec<String> },
    Denied { reasons: Vec<String> },
}

fn load(store: &pm_store::Store) -> Result<Vec<String>> {
    Ok(match store.get_setting(SETTING)? {
        Some(t) => {
            serde_json::from_str(&t).map_err(|e| ServiceError::Invalid(format!("saved checks are unreadable: {e}")))?
        }
        None => Vec::new(),
    })
}

/// Head (text) and decoded body (text) of a response.
fn split_response(raw: Option<&[u8]>) -> (String, String) {
    let Some(r) = raw else { return (String::new(), String::new()) };
    let (head, body) = pm_http::split_message(r);
    let decoded = match pm_http::parse_response_head(head) {
        Ok(h) => pm_ai::body::decode(&h.headers, body).bytes,
        Err(_) => body.to_vec(),
    };
    (String::from_utf8_lossy(head).into_owned(), String::from_utf8_lossy(&decoded).into_owned())
}

impl Service {
    pub fn custom_checks(&self) -> Result<Vec<SavedCustomCheck>> {
        let texts = self.store.read(load)?;
        Ok(texts
            .into_iter()
            .filter_map(|yaml| {
                custom::parse(&yaml).ok().map(|check| SavedCustomCheck { id: check.id.clone(), yaml, check })
            })
            .collect())
    }

    /// Adds or replaces (by id) a check. Humans only: checks decide what scans send.
    pub fn custom_check_save(&self, actor: &Actor, yaml: &str) -> Result<SavedCustomCheck> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only people can save custom checks".into()));
        }
        let check = custom::parse(yaml).map_err(ServiceError::Invalid)?;
        self.store.write(|store| -> Result<()> {
            let mut saved = load(store)?;
            saved.retain(|t| custom::parse(t).map_or(true, |c| c.id != check.id));
            if saved.len() >= MAX_SAVED {
                return Err(ServiceError::Invalid(format!("at most {MAX_SAVED} saved checks")));
            }
            saved.push(yaml.to_string());
            let text = serde_json::to_string(&saved).map_err(|e| ServiceError::Invalid(e.to_string()))?;
            store.set_setting(SETTING, &text)?;
            Ok(())
        })?;
        self.audit(&actor.id(), "custom_check_save", json!({ "id": check.id, "yaml": yaml }), "allow")?;
        Ok(SavedCustomCheck { id: check.id.clone(), yaml: yaml.to_string(), check })
    }

    pub fn custom_check_delete(&self, actor: &Actor, id: &str) -> Result<bool> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only people can delete custom checks".into()));
        }
        let removed = self.store.write(|store| -> Result<bool> {
            let mut saved = load(store)?;
            let before = saved.len();
            saved.retain(|t| custom::parse(t).map_or(true, |c| c.id != id));
            let text = serde_json::to_string(&saved).map_err(|e| ServiceError::Invalid(e.to_string()))?;
            store.set_setting(SETTING, &text)?;
            Ok(saved.len() < before)
        })?;
        self.audit(&actor.id(), "custom_check_delete", json!({ "id": id }), if removed { "allow" } else { "noop" })?;
        Ok(removed)
    }

    /// Runs custom checks on a recorded request.
    pub async fn custom_scan(&self, actor: &Actor, req: CustomScanRequest) -> Result<CustomScanResult> {
        let mut checks: Vec<CustomCheck> = match &req.yaml {
            Some(y) => vec![custom::parse(y).map_err(ServiceError::Invalid)?],
            None => {
                let saved = self.custom_checks()?;
                if let Some(bad) = req.checks.iter().find(|id| !saved.iter().any(|s| &s.id == *id)) {
                    return Err(ServiceError::NotFound(format!("custom check {bad}")));
                }
                saved
                    .into_iter()
                    .filter(|s| req.checks.is_empty() || req.checks.contains(&s.id))
                    .map(|s| s.check)
                    .collect()
            }
        };
        if checks.is_empty() {
            return Err(ServiceError::Invalid("no custom checks to run: save one first, or pass yaml".into()));
        }
        checks.sort_by(|a, b| a.id.cmp(&b.id));
        let ex = self
            .store
            .read(|db| db.get_exchange(req.exchange_id))?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {}", req.exchange_id)))?;
        if pm_http::h2text::is_http2_request(&ex.request) {
            return Err(ServiceError::Invalid("custom checks run on HTTP/1.1 requests; resend it as HTTP/1.1".into()));
        }
        let endpoint = pm_replay::Endpoint::new(&ex.summary.scheme, &ex.summary.host, ex.summary.port);
        // Work on what the actor may see: secrets stay placeholders until sent.
        let raw = self.redactor.redact(&String::from_utf8_lossy(&ex.request));
        let limit = req.max_requests.unwrap_or(200).clamp(1, 2000);
        let mut planned = Vec::new();
        for c in &checks {
            for p in custom::probes(c, &raw) {
                if planned.len() >= limit {
                    break;
                }
                planned.push((c, p));
            }
        }
        let mut baseline = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
        baseline.hypothesis_id = req.hypothesis_id;
        let mut outs = Vec::with_capacity(planned.len());
        let mut tier = Tier::ActiveSafe;
        for (c, p) in planned {
            let mut out = self.outgoing(endpoint.clone(), &p.raw, true)?;
            out.hypothesis_id = req.hypothesis_id;
            tier = tier.max(Tier::for_http_request(&out.raw).0).max(Tier::for_http_method(&out.method));
            outs.push((c, p, out));
        }
        // Payloads chosen by a person or an agent: at least intrusive.
        tier = tier.max(Tier::ActiveIntrusive);
        let extra = json!({
            "custom_checks": checks.iter().map(|c| serde_json::to_value(c).unwrap_or_default()).collect::<Vec<_>>(),
            "requests": outs.len(),
        });
        if let Some(name) = &req.identity {
            self.load_identity(name)?;
        }
        match self.gate_send_with(
            actor,
            "custom_scan",
            &baseline,
            req.identity.as_deref(),
            true,
            req.approval_id.as_deref(),
            Some(tier),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(CustomScanResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(CustomScanResult::PendingApproval {
                    approval_id,
                    summary: format!("{} custom check(s), {} requests: {summary}", checks.len(), outs.len()),
                    reasons,
                });
            }
        }
        let identity = req.identity.as_deref();
        let (base_sent, _) = self.send_as(actor, &baseline, identity, true, "scan").await?;
        let (bh, bb) = split_response(base_sent.response.as_deref());
        let base_seen =
            custom::Seen { status: base_sent.status, head: &bh, body: &bb, elapsed_ms: base_sent.elapsed_ms };
        let mut findings = Vec::new();
        let requests = outs.len();
        let redactor = self.redactor_for(actor);
        for (c, p, out) in outs {
            let (sent, _) = self.send_as(actor, &out, identity, true, "scan").await?;
            let (h, b) = split_response(sent.response.as_deref());
            let seen = custom::Seen { status: sent.status, head: &h, body: &b, elapsed_ms: sent.elapsed_ms };
            if let Some(ev) = custom::judge(c, Some(&base_seen), &seen, p.payload.as_deref()) {
                let evidence = match redactor {
                    Some(r) => pm_ai::wrap_untrusted(&r.redact(&ev)),
                    None => ev,
                };
                findings.push(CustomFinding {
                    check: c.id.clone(),
                    title: c.title.clone(),
                    severity: c.severity.clone(),
                    point: p.point.clone(),
                    payload: p.payload.clone(),
                    evidence,
                    exchange_id: sent.exchange_id,
                });
            }
        }
        Ok(CustomScanResult::Done { baseline_exchange_id: base_sent.exchange_id, requests, findings })
    }
}
