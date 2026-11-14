//! WebSocket messages logged by the proxy.

use pm_ai::{UNTRUSTED_NOTICE, prompt_injection_signals, wrap_untrusted};
use pm_http::ws;
use pm_policy::Actor;
use pm_store::WsMessageRow;
use serde::Serialize;

use crate::{Result, Service, ServiceError};

#[derive(Debug, Clone, Serialize)]
pub struct WsMessageView {
    pub id: i64,
    pub ts_ms: i64,
    /// "client" (browser → server) or "server".
    pub from: &'static str,
    /// text, binary, close, ping, pong.
    pub kind: &'static str,
    /// Full payload length on the wire (decompressed when inflated).
    pub len: u64,
    /// Text payloads (and close reasons); binary ones get `hex` instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    /// Only part of the payload is shown.
    pub truncated: bool,
    /// permessage-deflate data that couldn't be inflated, shown as is.
    pub compressed: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub possible_prompt_injection: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WsPage {
    pub exchange_id: i64,
    pub total: i64,
    pub messages: Vec<WsMessageView>,
    /// Pass as `after_id` to read the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice: Option<&'static str>,
}

/// Bytes of a binary payload shown as hex.
const HEX_BYTES: usize = 512;

impl Service {
    /// Messages of a WebSocket exchange, oldest first. For agents, text is
    /// redacted, cut to `max_chars` and marked as untrusted target content.
    pub fn ws_messages(
        &self,
        actor: &Actor,
        exchange_id: i64,
        after_id: Option<i64>,
        limit: usize,
        max_chars: usize,
    ) -> Result<WsPage> {
        let limit = limit.clamp(1, 500);
        let (rows, total) = self.store.read(|store| -> Result<_> {
            if store.get_exchange(exchange_id)?.is_none() {
                return Err(ServiceError::NotFound(format!("exchange {exchange_id}")));
            }
            Ok((store.ws_messages(exchange_id, after_id, limit)?, store.ws_message_count(exchange_id)?))
        })?;
        let agent = actor.kind != pm_policy::ActorKind::Human;
        let redactor = self.redactor_for(actor);
        let next_after_id = (rows.len() == limit).then(|| rows.last().map(|r| r.id)).flatten();
        let messages = rows
            .into_iter()
            .map(|r| {
                let mut v = view(&r);
                if let Some(t) = v.text.as_mut() {
                    if let Some(red) = redactor {
                        *t = red.redact(t);
                    }
                    if t.chars().count() > max_chars {
                        *t = t.chars().take(max_chars).collect();
                        v.truncated = true;
                    }
                    v.possible_prompt_injection = prompt_injection_signals(t);
                    if agent {
                        *t = wrap_untrusted(t);
                    }
                }
                v
            })
            .collect();
        Ok(WsPage { exchange_id, total, messages, next_after_id, notice: agent.then_some(UNTRUSTED_NOTICE) })
    }
}

/// A message in the history across connections.
#[derive(Debug, Clone, Serialize)]
pub struct WsHistoryItem {
    pub exchange_id: i64,
    pub host: String,
    pub path: String,
    #[serde(flatten)]
    pub message: WsMessageView,
}

#[derive(Debug, Clone, Serialize)]
pub struct WsHistoryPage {
    pub messages: Vec<WsHistoryItem>,
    /// Pass as `before_id` for older messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before_id: Option<i64>,
}

impl Service {
    /// WebSocket messages across every connection, newest first, with a
    /// preview of `max_chars` (redacted and marked untrusted for agents).
    pub fn ws_history(
        &self,
        actor: &Actor,
        host: Option<&str>,
        before_id: Option<i64>,
        limit: usize,
        max_chars: usize,
    ) -> Result<WsHistoryPage> {
        let limit = limit.clamp(1, 1000);
        let rows = self.store.read(|db| db.ws_history(host, before_id, limit))?;
        let agent = actor.kind != pm_policy::ActorKind::Human;
        let redactor = self.redactor_for(actor);
        let next_before_id = (rows.len() == limit).then(|| rows.last().map(|r| r.message.id)).flatten();
        let messages = rows
            .into_iter()
            .map(|r| {
                let mut v = view(&r.message);
                if let Some(t) = v.text.as_mut() {
                    if let Some(red) = redactor {
                        *t = red.redact(t);
                    }
                    if t.chars().count() > max_chars {
                        *t = t.chars().take(max_chars).collect();
                        v.truncated = true;
                    }
                    if agent {
                        *t = wrap_untrusted(t);
                    }
                }
                let path = redactor.map_or(r.path.clone(), |red| red.redact(&r.path));
                WsHistoryItem { exchange_id: r.message.exchange_id, host: r.host, path, message: v }
            })
            .collect();
        Ok(WsHistoryPage { messages, next_before_id })
    }
}

fn view(r: &WsMessageRow) -> WsMessageView {
    let kind = ws::opcode_name(r.opcode);
    let (text, hex) = match r.opcode {
        _ if r.compressed => (None, Some(to_hex(&r.payload))),
        ws::TEXT => (Some(String::from_utf8_lossy(&r.payload).into_owned()), None),
        ws::CLOSE if r.payload.len() >= 2 => {
            let code = u16::from_be_bytes([r.payload[0], r.payload[1]]);
            (Some(format!("{code} {}", String::from_utf8_lossy(&r.payload[2..])).trim_end().to_string()), None)
        }
        ws::CLOSE => (Some(String::new()), None),
        _ if std::str::from_utf8(&r.payload).is_ok_and(|s| !s.is_empty() && !s.contains('\0')) => {
            (Some(String::from_utf8_lossy(&r.payload).into_owned()), None)
        }
        _ => (None, Some(to_hex(&r.payload))),
    };
    WsMessageView {
        id: r.id,
        ts_ms: r.ts_ms,
        from: if r.from_client { "client" } else { "server" },
        kind,
        len: r.len,
        truncated: r.truncated || (hex.is_some() && r.payload.len() > HEX_BYTES),
        text,
        hex,
        compressed: r.compressed,
        possible_prompt_injection: vec![],
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().take(HEX_BYTES).map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" ")
}
