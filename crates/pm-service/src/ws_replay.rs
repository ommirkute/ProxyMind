//! WebSocket replay: open a new WebSocket with a recorded (or edited)
//! upgrade request, send messages, and record everything, through the
//! policy gate.

use std::time::{Duration, Instant};

use pm_http::ws::{self, Decoder};
use pm_policy::{Actor, Tier};
use pm_replay::{AfterResponse, Endpoint};
use pm_store::{NewExchange, NewWsMessage};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::replay::Outgoing;
use crate::ws::WsPage;
use crate::{Authorization, Result, Service, ServiceError, now_ms};

/// Most messages in one replay.
const MAX_MESSAGES: usize = 50;
/// Most bytes sent in one replay (all messages).
const MAX_SEND_BYTES: usize = 1 << 20;
/// Longest wait after one message, and for the whole session.
const MAX_WAIT: Duration = Duration::from_secs(10);
const MAX_SESSION: Duration = Duration::from_secs(60);
/// Most bytes of a received message kept.
const KEEP: usize = 256 << 10;

/// One message to send: `text`, or `hex` for binary data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WsOut {
    /// May contain `{{secret:...}}` placeholders.
    pub text: Option<String>,
    /// Binary payload as hex (spaces allowed).
    pub hex: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct WsReplayRequest {
    /// A recorded WebSocket upgrade exchange (status 101).
    pub exchange_id: i64,
    /// Edited upgrade request (HTTP/1.1). Default: the recorded one.
    /// ProxyMind sets a fresh Sec-WebSocket-Key and turns compression off.
    pub raw: Option<String>,
    /// Sent in order, each followed by `wait_ms` of listening.
    pub messages: Vec<WsOut>,
    /// How long to listen after each message (and after opening). Default
    /// 1000, at most 10000; a whole session ends after 60 s.
    pub wait_ms: Option<u64>,
    /// Open the socket as this test identity.
    pub identity: Option<String>,
    pub approval_id: Option<String>,
    pub hypothesis_id: Option<i64>,
    /// Characters of each message shown back (default 2000).
    pub max_chars: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WsReplayResult {
    /// The socket opened; everything sent and received is recorded under
    /// `exchange_id`.
    Done {
        exchange_id: i64,
        /// "server" if the server closed the socket, else "proxymind".
        closed_by: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        messages: WsPage,
    },
    /// The server didn't switch protocols (or couldn't be reached).
    NotUpgraded {
        exchange_id: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        http_status: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
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

/// Prepares an upgrade request for a new connection: a fresh
/// Sec-WebSocket-Key, no Sec-WebSocket-Extensions (ProxyMind sends plain
/// frames). Everything else stays as written.
fn prepare_upgrade(raw: &[u8], key: &str) -> Vec<u8> {
    let (head, body) = pm_http::split_message(raw);
    let text = String::from_utf8_lossy(head);
    let mut lines: Vec<String> = Vec::new();
    let mut has_key = false;
    for (i, line) in text.split("\r\n").enumerate() {
        let name = line.split(':').next().unwrap_or_default().trim().to_ascii_lowercase();
        if i > 0 && name == "sec-websocket-extensions" {
            continue;
        }
        if i > 0 && name == "sec-websocket-key" {
            has_key = true;
            lines.push(format!("Sec-WebSocket-Key: {key}"));
            continue;
        }
        lines.push(line.to_string());
    }
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    if !has_key {
        lines.push(format!("Sec-WebSocket-Key: {key}"));
    }
    let mut out = lines.join("\r\n").into_bytes();
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(body);
    out
}

fn random<const N: usize>(rng: &SystemRandom) -> Result<[u8; N]> {
    let mut b = [0u8; N];
    rng.fill(&mut b).map_err(|_| ServiceError::Invalid("no system randomness".into()))?;
    Ok(b)
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let digits: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    // Checked first: slicing below assumes one byte per character.
    if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ServiceError::Invalid("hex payload has a non-hex character".into()));
    }
    if !digits.len().is_multiple_of(2) {
        return Err(ServiceError::Invalid("hex payload has an odd number of digits".into()));
    }
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| ServiceError::Invalid("hex payload has a non-hex character".into()))
}

impl Service {
    /// Opens a WebSocket like a recorded one, sends `messages` and records
    /// the session, if the policy allows it. Opening alone is active-safe;
    /// sending messages is active-intrusive (they can change state).
    pub async fn ws_replay(&self, actor: &Actor, req: WsReplayRequest) -> Result<WsReplayResult> {
        if req.messages.len() > MAX_MESSAGES {
            return Err(ServiceError::Invalid(format!("at most {MAX_MESSAGES} messages per replay")));
        }
        // Payloads as the actor wrote them (placeholders kept) for the gate.
        let mut payloads: Vec<(u8, Vec<u8>)> = Vec::with_capacity(req.messages.len());
        for m in &req.messages {
            payloads.push(match (&m.text, &m.hex) {
                (Some(t), None) => (ws::TEXT, t.as_bytes().to_vec()),
                (None, Some(h)) => (ws::BINARY, parse_hex(h)?),
                _ => return Err(ServiceError::Invalid("each message needs exactly one of text or hex".into())),
            });
        }
        if payloads.iter().map(|(_, p)| p.len()).sum::<usize>() > MAX_SEND_BYTES {
            return Err(ServiceError::Invalid("messages are larger than 1 MB in total".into()));
        }
        for (_, p) in &payloads {
            let unknown = self.redactor.unknown_placeholders(p);
            if !unknown.is_empty() {
                return Err(ServiceError::Invalid(format!("unknown secret placeholders: {}", unknown.join(", "))));
            }
        }

        let ex = self
            .store
            .read(|db| db.get_exchange(req.exchange_id))?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {}", req.exchange_id)))?;
        if ex.summary.status != Some(101) && req.raw.is_none() {
            return Err(ServiceError::Invalid(format!(
                "exchange {} is not a WebSocket upgrade (status {:?})",
                req.exchange_id, ex.summary.status
            )));
        }
        let raw = req.raw.as_ref().map_or_else(|| ex.request.clone(), |r| r.as_bytes().to_vec());
        if pm_http::h2text::is_http2_request(&raw) {
            return Err(ServiceError::Invalid(
                "WebSockets over HTTP/2 aren't supported; write HTTP/1.1 in the request line".into(),
            ));
        }
        let ep = Endpoint::new(&ex.summary.scheme, &ex.summary.host, ex.summary.port);
        let mut out = self.outgoing(ep, &raw, true)?;
        out.hypothesis_id = req.hypothesis_id;
        if let Some(name) = &req.identity {
            self.load_identity(name)?;
        }

        let wait = Duration::from_millis(req.wait_ms.unwrap_or(1000)).min(MAX_WAIT);
        let mut tier = if payloads.is_empty() { Tier::ActiveSafe } else { Tier::ActiveIntrusive };
        for (_, p) in &payloads {
            tier = tier.max(pm_policy::payload::classify_text(&String::from_utf8_lossy(p)).tier);
        }
        let extra = json!({ "websocket_messages": req.messages, "wait_ms": wait.as_millis() as u64 });
        let identity = req.identity.as_deref();
        match self.gate_send_with(
            actor,
            "ws_replay",
            &out,
            identity,
            false,
            req.approval_id.as_deref(),
            Some(tier),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(WsReplayResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(WsReplayResult::PendingApproval { approval_id, summary, reasons });
            }
        }
        self.ws_session(actor, &out, identity, payloads, wait, req.max_chars.unwrap_or(2000)).await
    }

    async fn ws_session(
        &self,
        actor: &Actor,
        out: &Outgoing,
        identity: Option<&str>,
        payloads: Vec<(u8, Vec<u8>)>,
        wait: Duration,
        max_chars: usize,
    ) -> Result<WsReplayResult> {
        let _permit = self.acquire_slot(&out.endpoint.host).await?;
        let rng = SystemRandom::new();
        let key = pm_core::base64(&random::<16>(&rng)?);
        let mut wire = self.redactor.unredact(&out.raw);
        if let Some(name) = identity {
            wire = pm_identity::apply(&wire, &self.load_identity(name)?.auth);
        }
        let wire = prepare_upgrade(&wire, &key);
        let check = |ips: &[std::net::IpAddr]| self.policy.check_resolved(ips);
        let started = Instant::now();
        let result = self.sender.send(&out.endpoint, &wire, "GET", Some(&check)).await;
        let mut record = NewExchange {
            ts_ms: now_ms(),
            duration_ms: Some(started.elapsed().as_millis() as i64),
            source: "ws_replay".into(),
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
            identity: identity.map(str::to_string),
            hypothesis_id: out.hypothesis_id,
        };
        let resp = match result {
            Ok(r) => r,
            Err(e) => {
                record.error = Some(format!("{e:#}"));
                let error = record.error.clone();
                let exchange_id = self.store.write(|db| db.insert_exchange(&record))?;
                return Ok(WsReplayResult::NotUpgraded { exchange_id, http_status: None, error });
            }
        };
        record.status = Some(resp.head.status);
        record.response = Some(resp.raw.clone());
        let exchange_id = self.store.write(|db| db.insert_exchange(&record))?;
        let AfterResponse::Upgraded(mut conn) = resp.conn else {
            return Ok(WsReplayResult::NotUpgraded { exchange_id, http_status: Some(resp.head.status), error: None });
        };

        let save = |from_client: bool, opcode: u8, len: u64, payload: &[u8], truncated: bool| {
            self.store.write(|db| {
                db.insert_ws_message(&NewWsMessage {
                    exchange_id,
                    ts_ms: now_ms(),
                    from_client,
                    opcode,
                    len,
                    payload: payload[..payload.len().min(KEEP)].to_vec(),
                    truncated: truncated || payload.len() > KEEP,
                    compressed: false,
                })
            })
        };
        let mut dec = Decoder::new(KEEP);
        let leftover = std::mem::take(&mut conn.buf);
        let deadline = started + MAX_SESSION;
        let mut note = None;
        let mut closed_by_server = false;
        let mut got = Vec::new();
        if !leftover.is_empty() && dec.feed(&leftover, &mut got).is_err() {
            note = Some("the server sent data that isn't valid WebSocket framing".to_string());
        }

        // Listen after opening, then send each message and listen again.
        let mut queue = payloads.into_iter();
        let mut buf = vec![0u8; 16 << 10];
        'session: loop {
            let until = (Instant::now() + wait).min(deadline);
            loop {
                for m in got.drain(..) {
                    save(false, m.opcode, m.len, &m.payload, m.truncated)?;
                    match m.opcode {
                        ws::PING => {
                            let mask = random::<4>(&rng)?;
                            let _ = conn.io.write_all(&ws::encode_frame(ws::PONG, &m.payload, Some(mask))).await;
                            save(true, ws::PONG, m.payload.len() as u64, &m.payload, false)?;
                        }
                        ws::CLOSE => closed_by_server = true,
                        _ => {}
                    }
                }
                if closed_by_server {
                    break 'session;
                }
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                match tokio::time::timeout(left, conn.io.read(&mut buf)).await {
                    Err(_) => break,
                    Ok(Ok(0)) | Ok(Err(_)) => {
                        closed_by_server = true;
                        break 'session;
                    }
                    Ok(Ok(n)) => {
                        if dec.feed(&buf[..n], &mut got).is_err() {
                            note = Some("the server sent data that isn't valid WebSocket framing".into());
                            break 'session;
                        }
                    }
                }
            }
            if Instant::now() >= deadline {
                note = Some("stopped after 60 s".into());
                break;
            }
            let Some((opcode, payload)) = queue.next() else { break };
            let real = self.redactor.unredact(&payload);
            let mask = random::<4>(&rng)?;
            if let Err(e) = conn.io.write_all(&ws::encode_frame(opcode, &real, Some(mask))).await {
                note = Some(format!("the connection broke while sending: {e}"));
                break;
            }
            save(true, opcode, real.len() as u64, &real, false)?;
        }
        // Anything decoded but not handled (framing error or session end).
        for m in got.drain(..) {
            save(false, m.opcode, m.len, &m.payload, m.truncated)?;
        }

        // Close politely (answering the server's close, if it sent one).
        let reason = ws::close_payload(1000, "");
        let mask = random::<4>(&rng)?;
        if conn.io.write_all(&ws::encode_frame(ws::CLOSE, &reason, Some(mask))).await.is_ok() {
            save(true, ws::CLOSE, reason.len() as u64, &reason, false)?;
        }
        let _ = conn.io.shutdown().await;

        let messages = self.ws_messages(actor, exchange_id, None, 500, max_chars)?;
        Ok(WsReplayResult::Done {
            exchange_id,
            closed_by: if closed_by_server { "server" } else { "proxymind" },
            note,
            messages,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_payloads_with_other_characters_are_refused_not_panicking() {
        assert_eq!(parse_hex("de ad be ef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(parse_hex("aéb").is_err(), "a two-byte character between digits");
        assert!(parse_hex("zz").is_err());
        assert!(parse_hex("abc").is_err());
    }

    #[test]
    fn upgrade_gets_a_fresh_key_and_no_extensions() {
        let raw =
            b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: old==\r\n\
                    Sec-WebSocket-Extensions: permessage-deflate\r\nCookie: s=1\r\n\r\n";
        let out = String::from_utf8(prepare_upgrade(raw, "new==")).unwrap();
        assert_eq!(
            out,
            "GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: new==\r\nCookie: s=1\r\n\r\n"
        );
        let added = String::from_utf8(prepare_upgrade(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", "k")).unwrap();
        assert!(added.ends_with("Host: a\r\nSec-WebSocket-Key: k\r\n\r\n"));
    }

    #[test]
    fn hex_payloads() {
        assert_eq!(parse_hex("00 ff\n10").unwrap(), vec![0, 255, 16]);
        assert!(parse_hex("abc").is_err() && parse_hex("zz").is_err());
    }
}
