//! Sending requests (Repeater-style replays) through the policy gate.

use std::time::{Duration, Instant};

use pm_ai::{ExchangeView, View, render_exchange};
use pm_policy::{ActionRequest, Actor, Target, Tier, Wait};
use pm_replay::Endpoint;
use pm_store::NewExchange;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Authorization, Result, Service, ServiceError, now_ms};

/// How long a send may wait for a rate-limit or concurrency slot.
const MAX_LIMIT_WAIT: Duration = Duration::from_secs(30);

/// A request to send. Either `exchange_id` (resend or edit a recorded
/// request) or `url` (where to send `raw`) must be given.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReplayRequest {
    /// Raw HTTP/1.1 request text. May contain `{{secret:...}}` placeholders.
    /// If omitted, the request of `exchange_id` is resent unchanged.
    pub raw: Option<String>,
    /// Recorded exchange to base this on (its target is used).
    pub exchange_id: Option<i64>,
    /// Target as scheme://host[:port], used when there is no `exchange_id`.
    pub url: Option<String>,
    /// Update Content-Length to match the body (default true).
    pub fix_content_length: Option<bool>,
    /// Convert bare "\n" line endings in the head to "\r\n" (default true).
    pub normalize_newlines: Option<bool>,
    /// Run a previously approved send. All other fields must be identical.
    pub approval_id: Option<String>,
    /// View of the response to return (default summary).
    pub view: Option<View>,
    pub max_tokens: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ReplayResult {
    /// Sent; the response is recorded as `exchange_id`.
    Sent {
        exchange_id: i64,
        elapsed_ms: u64,
        view: Box<ExchangeView>,
    },
    /// The send failed (e.g. connection refused); recorded as `exchange_id`.
    Failed {
        exchange_id: i64,
        error: String,
    },
    /// A human must approve first; call again with `approval_id`.
    PendingApproval {
        approval_id: String,
        summary: String,
        reasons: Vec<String>,
    },
    Denied {
        reasons: Vec<String>,
    },
}

/// Normalizes bare LF line endings in the head only (the body is untouched).
fn crlf_head(raw: &[u8]) -> Vec<u8> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|p| p + 2))
        .unwrap_or(raw.len());
    let (head, body) = raw.split_at(end);
    let mut out = Vec::with_capacity(raw.len() + 16);
    let mut prev = 0u8;
    for &b in head {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out.extend_from_slice(body);
    out
}

fn parse_url_endpoint(url: &str) -> Result<Endpoint> {
    let u = url::Url::parse(url).map_err(|e| ServiceError::Invalid(format!("bad url {url:?}: {e}")))?;
    let host = u.host_str().ok_or_else(|| ServiceError::Invalid("url has no host".into()))?;
    let port = u.port_or_known_default().ok_or_else(|| ServiceError::Invalid("url has no port".into()))?;
    Ok(Endpoint::new(u.scheme(), host.trim_matches(['[', ']']), port))
}

impl Service {
    /// Sends a request on behalf of `actor`, if the policy allows it.
    pub async fn replay_send(&self, actor: &Actor, req: ReplayRequest) -> Result<ReplayResult> {
        // 1. Work out the bytes and the endpoint.
        let (endpoint, base_raw) = match req.exchange_id {
            Some(id) => {
                let ex = self
                    .store
                    .lock()
                    .get_exchange(id)?
                    .ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
                let s = ex.summary;
                (Endpoint::new(&s.scheme, &s.host, s.port), ex.request)
            }
            None => {
                let url = req.url.as_deref().ok_or_else(|| {
                    ServiceError::Invalid("give exchange_id (to resend a recorded request) or url".into())
                })?;
                let raw = req.raw.as_deref().ok_or_else(|| ServiceError::Invalid("raw is required with url".into()))?;
                (parse_url_endpoint(url)?, raw.as_bytes().to_vec())
            }
        };
        let mut raw = match &req.raw {
            Some(r) => r.as_bytes().to_vec(),
            None => base_raw,
        };
        if req.normalize_newlines.unwrap_or(true) {
            raw = crlf_head(&raw);
        }
        let unknown = self.redactor.unknown_placeholders(&raw);
        if !unknown.is_empty() {
            return Err(ServiceError::Invalid(format!("unknown secret placeholders: {}", unknown.join(", "))));
        }
        let (head, _) = pm_http::split_message(&raw);
        let head = pm_http::parse_request_head(head)
            .map_err(|e| ServiceError::Invalid(format!("request is not valid HTTP: {e}")))?;
        let path = match pm_http::split_absolute_target(&head.target) {
            Some((_, _, p)) => p.to_string(),
            None => head.target.clone(),
        };

        // 2. Ask the gate. Parameters cover exactly what will be sent.
        let target = Target::from_parts(&endpoint.scheme, &endpoint.host, endpoint.port, &path)
            .map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let tier = Tier::for_http_method(&head.method);
        let url = pm_core::url(&endpoint.scheme, &endpoint.host, endpoint.port, &path);
        let params = json!({
            "endpoint": format!("{}://{}:{}", endpoint.scheme, endpoint.host, endpoint.port),
            "request": String::from_utf8_lossy(&raw),
            "fix_content_length": req.fix_content_length.unwrap_or(true),
        });
        let action = ActionRequest {
            actor: actor.clone(),
            action: "replay_send".into(),
            tier,
            target: Some(target),
            summary: format!("{} {url}", head.method),
        };
        let auth = match &req.approval_id {
            Some(id) => self.run_approved(id, &params)?,
            None => self.authorize(action, &params)?,
        };
        match auth {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(ReplayResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(ReplayResult::PendingApproval { approval_id, summary, reasons });
            }
        }

        // 3. Rate limits, then send with real secrets and DNS check.
        let _permit = self.acquire_slot(&endpoint.host).await?;
        let mut wire = self.redactor.unredact(&raw);
        if req.fix_content_length.unwrap_or(true) {
            wire = pm_http::fix_content_length(&wire);
        }
        let check = |ips: &[std::net::IpAddr]| self.policy.check_resolved(ips);
        let started = Instant::now();
        let result = self.sender.send(&endpoint, &wire, &head.method, Some(&check)).await;

        // 4. Record and answer.
        let mut record = NewExchange {
            ts_ms: now_ms(),
            duration_ms: Some(started.elapsed().as_millis() as i64),
            source: "replay".into(),
            actor_id: actor.id(),
            scheme: endpoint.scheme.clone(),
            host: endpoint.host.clone(),
            port: endpoint.port,
            method: head.method.clone(),
            path,
            status: None,
            request: wire,
            response: None,
            error: None,
        };
        match result {
            Ok(resp) => {
                let elapsed_ms = resp.elapsed.as_millis() as u64;
                record.status = Some(resp.head.status);
                record.response = Some(resp.raw);
                let id = self.store.lock().insert_exchange(&record)?;
                let ex = self.store.lock().get_exchange(id)?.ok_or_else(|| ServiceError::NotFound(id.to_string()))?;
                let view = render_exchange(
                    &ex,
                    req.view.unwrap_or_default(),
                    req.max_tokens.unwrap_or(1500),
                    self.redactor_for(actor),
                );
                Ok(ReplayResult::Sent { exchange_id: id, elapsed_ms, view: Box::new(view) })
            }
            Err(e) => {
                let error = format!("{e:#}");
                record.error = Some(error.clone());
                let id = self.store.lock().insert_exchange(&record)?;
                Ok(ReplayResult::Failed { exchange_id: id, error })
            }
        }
    }

    async fn acquire_slot(&self, host: &str) -> Result<pm_policy::Permit> {
        let deadline = Instant::now() + MAX_LIMIT_WAIT;
        loop {
            match self.limiter.try_acquire(host, Instant::now()) {
                Ok(p) => return Ok(p),
                Err(w) if Instant::now() >= deadline => {
                    return Err(ServiceError::Invalid(format!("rate limit: still waiting after 30s ({w:?})")));
                }
                Err(Wait::Rate(d)) => tokio::time::sleep(d.min(Duration::from_secs(1))).await,
                Err(Wait::Concurrency) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_only_in_head() {
        assert_eq!(crlf_head(b"GET / HTTP/1.1\nHost: a\n\nx\ny"), b"GET / HTTP/1.1\r\nHost: a\r\n\r\nx\ny");
        assert_eq!(crlf_head(b"GET / HTTP/1.1\r\n\r\n"), b"GET / HTTP/1.1\r\n\r\n");
    }
}
