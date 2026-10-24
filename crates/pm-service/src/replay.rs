//! Sending requests (Repeater-style replays) through the policy gate, as
//! recorded or as any test identity.

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
    /// Send with this test identity's credentials instead of the request's own
    /// (use "anonymous" for none).
    pub identity: Option<String>,
    /// Update Content-Length to match the body (default true).
    pub fix_content_length: Option<bool>,
    /// Convert bare "\n" line endings in the head to "\r\n" (default true).
    pub normalize_newlines: Option<bool>,
    /// Run a previously approved send. All other fields must be identical.
    pub approval_id: Option<String>,
    /// Hypothesis this send tests (links the exchange as evidence).
    pub hypothesis_id: Option<i64>,
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
        #[serde(skip_serializing_if = "Vec::is_empty")]
        notes: Vec<String>,
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

/// A request ready to go through the gate.
#[derive(Debug, Clone)]
pub(crate) struct Outgoing {
    pub endpoint: Endpoint,
    /// Bytes as the actor sees them (may contain placeholders).
    pub raw: Vec<u8>,
    pub method: String,
    pub path: String,
    /// Hypothesis the send tests, recorded on the exchange.
    pub hypothesis_id: Option<i64>,
}

impl Outgoing {
    pub fn url(&self) -> String {
        pm_core::url(&self.endpoint.scheme, &self.endpoint.host, self.endpoint.port, &self.path)
    }
}

/// What actually happened on the wire.
pub(crate) struct Sent {
    pub exchange_id: i64,
    pub response: Option<Vec<u8>>,
    pub status: Option<u16>,
    pub error: Option<String>,
    pub elapsed_ms: u64,
}

/// Normalizes bare LF line endings in the head only (the body is untouched).
pub(crate) fn crlf_head(raw: &[u8]) -> Vec<u8> {
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

pub(crate) fn parse_url_endpoint(url: &str) -> Result<Endpoint> {
    let u = url::Url::parse(url).map_err(|e| ServiceError::Invalid(format!("bad url {url:?}: {e}")))?;
    let host = u.host_str().ok_or_else(|| ServiceError::Invalid("url has no host".into()))?;
    let port = u.port_or_known_default().ok_or_else(|| ServiceError::Invalid("url has no port".into()))?;
    Ok(Endpoint::new(u.scheme(), host.trim_matches(['[', ']']), port))
}

/// Counts of automatic logins for one identity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Relogins {
    pub ok: usize,
    pub failed: usize,
    pub failed_in_row: usize,
}

impl Service {
    pub(crate) fn outgoing(&self, endpoint: Endpoint, raw: &[u8], normalize: bool) -> Result<Outgoing> {
        let raw = if normalize { crlf_head(raw) } else { raw.to_vec() };
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
        Ok(Outgoing { endpoint, raw, method: head.method, path, hypothesis_id: None })
    }

    pub(crate) fn outgoing_from_request(&self, req: &ReplayRequest) -> Result<Outgoing> {
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
        let raw = match &req.raw {
            Some(r) => r.as_bytes().to_vec(),
            None => base_raw,
        };
        let mut out = self.outgoing(endpoint, &raw, req.normalize_newlines.unwrap_or(true))?;
        out.hypothesis_id = req.hypothesis_id;
        Ok(out)
    }

    /// Asks the gate whether `actor` may send `out`. The approval (if any)
    /// covers exactly these bytes, this identity and this action name.
    pub(crate) fn gate_send(
        &self,
        actor: &Actor,
        action: &str,
        out: &Outgoing,
        identity: Option<&str>,
        fix_cl: bool,
        approval_id: Option<&str>,
    ) -> Result<Authorization> {
        self.gate_send_with(actor, action, out, identity, fix_cl, approval_id, None, serde_json::Value::Null)
    }

    /// [`Service::gate_send`] with a tier other than the method's, and extra
    /// parameters the approval must cover (e.g. WebSocket messages).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn gate_send_with(
        &self,
        actor: &Actor,
        action: &str,
        out: &Outgoing,
        identity: Option<&str>,
        fix_cl: bool,
        approval_id: Option<&str>,
        tier: Option<Tier>,
        extra: serde_json::Value,
    ) -> Result<Authorization> {
        let target = Target::from_parts(&out.endpoint.scheme, &out.endpoint.host, out.endpoint.port, &out.path)
            .map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let mut params = json!({
            "endpoint": format!("{}://{}:{}", out.endpoint.scheme, out.endpoint.host, out.endpoint.port),
            "request": String::from_utf8_lossy(&out.raw),
            "identity": identity,
            "fix_content_length": fix_cl,
        });
        if !extra.is_null() {
            params["extra"] = extra;
        }
        let mut summary = match identity {
            Some(i) => format!("{} {} as {i}", out.method, out.url()),
            None => format!("{} {}", out.method, out.url()),
        };
        // What the payload does can raise the tier, never lower it.
        let (by_request, payload_reasons) = Tier::for_http_request(&out.raw);
        let tier = tier.map_or(by_request, |t| t.max(by_request));
        if !payload_reasons.is_empty() {
            summary.push_str(&format!(" [payload: {}]", payload_reasons.join("; ")));
        }
        let action = ActionRequest { actor: actor.clone(), action: action.into(), tier, target: Some(target), summary };
        match approval_id {
            Some(id) => self.run_approved(id, &params),
            None => self.authorize(action, &params),
        }
    }

    /// Sends now (the caller has already passed the gate) and records the
    /// exchange. Applies session rules (without an identity), rate limits,
    /// secrets, identity credentials and the DNS check.
    pub(crate) async fn send_now(
        &self,
        actor: &Actor,
        out: &Outgoing,
        identity: Option<&pm_identity::Identity>,
        fix_cl: bool,
        source: &str,
    ) -> Result<Sent> {
        if identity.is_none()
            && let Some(sent) = self.send_with_session(actor, out, fix_cl, source).await?
        {
            return Ok(sent);
        }
        let mut wire = self.redactor.unredact(&out.raw);
        if let Some(id) = identity {
            wire = pm_identity::apply(&wire, &id.auth);
        }
        self.transmit(actor, out, wire, identity, fix_cl, source).await
    }

    /// Sends `wire` (the bytes for `out`, secrets already filled in) and
    /// records the exchange. Applies rate limits and the DNS check.
    pub(crate) async fn transmit(
        &self,
        actor: &Actor,
        out: &Outgoing,
        mut wire: Vec<u8>,
        identity: Option<&pm_identity::Identity>,
        fix_cl: bool,
        source: &str,
    ) -> Result<Sent> {
        let _permit = self.acquire_slot(&out.endpoint.host).await?;
        if fix_cl {
            wire = pm_http::fix_content_length(&wire);
        }
        let check = |ips: &[std::net::IpAddr]| self.policy.check_resolved(ips);
        let started = Instant::now();
        let result = self.sender.send(&out.endpoint, &wire, &out.method, Some(&check)).await;
        let mut record = NewExchange {
            ts_ms: now_ms(),
            duration_ms: Some(started.elapsed().as_millis() as i64),
            source: source.into(),
            actor_id: actor.id(),
            scheme: out.endpoint.scheme.clone(),
            host: out.endpoint.host.clone(),
            port: out.endpoint.port,
            method: out.method.clone(),
            path: out.path.clone(),
            status: None,
            request: wire,
            response: None,
            error: None,
            identity: identity.map(|i| i.name.clone()),
            hypothesis_id: out.hypothesis_id,
        };
        let (status, error, elapsed_ms) = match result {
            Ok(resp) => {
                if let Some(sent) = resp.sent {
                    record.request = sent; // e.g. HTTP/2 downgraded for an HTTP/1.1-only server
                }
                record.status = Some(resp.head.status);
                record.response = Some(resp.raw);
                (Some(resp.head.status), None, resp.elapsed.as_millis() as u64)
            }
            Err(e) => {
                record.error = Some(format!("{e:#}"));
                (None, record.error.clone(), started.elapsed().as_millis() as u64)
            }
        };
        let response = record.response.clone();
        let exchange_id = self.store.lock().insert_exchange(&record)?;
        Ok(Sent { exchange_id, response, status, error, elapsed_ms })
    }

    /// How automatic logins for one identity have gone.
    pub(crate) fn relogins(&self, identity: &str) -> Relogins {
        self.relogins.lock().get(identity).copied().unwrap_or_default()
    }

    /// Sends as an identity, logging it in again once if the response says
    /// the session expired and the identity has a login recipe.
    pub(crate) async fn send_as(
        &self,
        actor: &Actor,
        out: &Outgoing,
        identity: Option<&str>,
        fix_cl: bool,
        source: &str,
    ) -> Result<(Sent, Vec<String>)> {
        let mut notes = Vec::new();
        let ident = identity.map(|n| self.load_identity(n)).transpose()?;
        let sent = self.send_now(actor, out, ident.as_ref(), fix_cl, source).await?;
        if let (Some(id), Some(resp)) = (&ident, &sent.response)
            && id.login.is_some()
            && id.looks_logged_out(resp)
        {
            notes.push(format!("{} looked logged out; logging in again", id.name));
            match self.identity_login(&id.name).await {
                Ok(learned) => {
                    {
                        let mut r = self.relogins.lock();
                        let e = r.entry(id.name.clone()).or_default();
                        e.ok += 1;
                        e.failed_in_row = 0;
                    }
                    notes.push(format!("login ok ({})", learned.join(", ")));
                    let fresh = self.load_identity(&id.name)?;
                    let retry = self.send_now(actor, out, Some(&fresh), fix_cl, source).await?;
                    return Ok((retry, notes));
                }
                Err(e) => {
                    let mut r = self.relogins.lock();
                    let s = r.entry(id.name.clone()).or_default();
                    s.failed += 1;
                    s.failed_in_row += 1;
                    notes.push(format!("login failed: {e}"));
                }
            }
        }
        Ok((sent, notes))
    }

    /// Sends a request on behalf of `actor`, if the policy allows it.
    pub async fn replay_send(&self, actor: &Actor, req: ReplayRequest) -> Result<ReplayResult> {
        let out = self.outgoing_from_request(&req)?;
        let fix_cl = req.fix_content_length.unwrap_or(true);
        if let Some(name) = &req.identity {
            self.load_identity(name)?; // fail early on unknown identities
        }
        match self.gate_send(actor, "replay_send", &out, req.identity.as_deref(), fix_cl, req.approval_id.as_deref())? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(ReplayResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(ReplayResult::PendingApproval { approval_id, summary, reasons });
            }
        }
        let (sent, notes) = self.send_as(actor, &out, req.identity.as_deref(), fix_cl, "replay").await?;
        if let Some(error) = sent.error {
            return Ok(ReplayResult::Failed { exchange_id: sent.exchange_id, error });
        }
        let ex = self
            .store
            .lock()
            .get_exchange(sent.exchange_id)?
            .ok_or_else(|| ServiceError::NotFound(sent.exchange_id.to_string()))?;
        let view = render_exchange(
            &ex,
            req.view.unwrap_or_default(),
            req.max_tokens.unwrap_or(1500),
            self.redactor_for(actor),
        );
        Ok(ReplayResult::Sent {
            exchange_id: sent.exchange_id,
            elapsed_ms: sent.elapsed_ms,
            notes,
            view: Box::new(view),
        })
    }

    pub(crate) async fn acquire_slot(&self, host: &str) -> Result<pm_policy::Permit> {
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
