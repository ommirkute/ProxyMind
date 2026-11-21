//! Raw TCP and TLS streams (roadmap 2.6): listing and reading what the proxy relayed and recorded, and replaying a
//! stream through the policy gate.
//!
//! Chunks are target content: for agents the text is redacted, marked untrusted and the raw bytes are not shown
//! (a base64 copy would carry what the redactor removes). Replay opens a new connection to the same target (TLS with
//! the same server name and ALPN when the original was TLS), sends the client's chunks (recorded or replaced) and
//! records the result as a new stream. It is a send like any other: scope, tier, approvals, rate limit and audit all
//! apply (`stream_replay` is the action name).

use std::time::{Duration, Instant};

use pm_ai::{UNTRUSTED_NOTICE, prompt_injection_signals, wrap_untrusted};
use pm_policy::{Actor, ActorKind, Tier};
use pm_replay::Endpoint;
use pm_store::{
    NewChunk, NewStream, STREAM_CHUNK_CAP, STREAM_RECORD_CAP, StreamChunkRow, StreamEnd, StreamFilter, StreamRow,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::replay::Outgoing;
use crate::{Authorization, Result, Service, ServiceError, now_ms};

/// Most chunks one replay sends.
const MAX_REPLAY_CHUNKS: usize = 1000;
/// Most bytes one replay sends.
const MAX_REPLAY_SEND: usize = 16 << 20;
/// Longest wait between chunks and for the answer; the whole session ends after [`MAX_SESSION`].
const MAX_WAIT_MS: u64 = 10_000;
const MAX_SESSION: Duration = Duration::from_secs(60);
/// Most bytes of the server's answer read (the default and the limit).
const DEFAULT_RESPONSE: usize = 1 << 20;
const MAX_RESPONSE: usize = 16 << 20;
/// Chunks shown on a page at most.
const MAX_PAGE: usize = 500;

/// One chunk of a stream as `actor` may see it.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct StreamChunkView {
    pub id: i64,
    pub ts_ms: i64,
    /// `client` (towards the server) or `server` (towards the client).
    pub from: &'static str,
    /// Bytes on the wire.
    pub len: u64,
    /// Bytes stored: fewer than `len` when the recording cap cut the chunk.
    pub kept: u64,
    /// The stored bytes as base64. People only: agents get the redacted `text`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_b64: Option<String>,
    /// A lossy text preview of the bytes (invalid UTF-8 becomes U+FFFD). Untrusted target content: for agents it is
    /// redacted and wrapped in `<untrusted_target_content>`.
    pub text: String,
    /// The preview is shorter than the stored bytes.
    pub text_truncated: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub possible_prompt_injection: Vec<String>,
}

/// A page of a stream's chunks, oldest first.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct StreamChunkPage {
    pub stream_id: i64,
    /// Chunks stored for the stream.
    pub total: u64,
    pub chunks: Vec<StreamChunkView>,
    /// Pass as `after` to read the next page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_after_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notice: Option<&'static str>,
}

/// One stream with its first chunks.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct StreamDetail {
    pub stream: StreamRow,
    pub chunks: StreamChunkPage,
}

/// Streams, newest first.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct StreamPage {
    pub streams: Vec<StreamRow>,
    /// Pass as `before_id` for older streams.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before_id: Option<i64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
// `default` makes every field optional to serde; the service answers "not found" for stream 0.
#[schemars(extend("required" = ["stream_id"]))]
pub struct StreamReplayRequest {
    /// The recorded stream to replay.
    pub stream_id: i64,
    /// Replacement client-to-server chunks as base64, sent in order instead of the recorded ones (at most 1000, 16 MB
    /// in all). Default: the recorded chunks. May contain `{{secret:...}}` placeholders. Not with `text_chunks`.
    pub chunks: Option<Vec<String>>,
    /// Replacement chunks as text (UTF-8), for protocols that are text. Not with `chunks`.
    pub text_chunks: Option<Vec<String>>,
    /// Wait between chunks in milliseconds (default 0, at most 10000). The server's answers are recorded meanwhile.
    #[schemars(range(max = 10000))]
    pub delay_ms: Option<u64>,
    /// After the last chunk, how long to keep reading while the server stays silent (default 2000, at most 10000). A
    /// server that spoke first in the original is waited for before the first chunk, for the same time.
    #[schemars(range(max = 10000))]
    pub read_ms: Option<u64>,
    /// Stop reading after this many bytes from the server (default 1 MB, at most 16 MB).
    #[schemars(range(max = 16777216))]
    pub max_response_bytes: Option<usize>,
    /// From a previous pending_approval result: runs the approved send. All other fields must be identical.
    pub approval_id: Option<String>,
    /// Characters of each chunk shown back (default 2000).
    pub max_chars: Option<usize>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StreamReplayResult {
    /// The connection opened; everything sent and received is recorded as the new stream `stream_id`.
    Done {
        stream_id: i64,
        /// `server_closed`, `client_closed` (ProxyMind stopped after the server went quiet), `timeout`, `limit` or
        /// `error`.
        ended: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        sent_bytes: u64,
        received_bytes: u64,
        chunks: StreamChunkPage,
    },
    /// The target could not be reached; the attempt is recorded as stream `stream_id`.
    Failed {
        stream_id: i64,
        error: String,
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

fn invalid(m: impl Into<String>) -> ServiceError {
    ServiceError::Invalid(m.into())
}

impl Service {
    /// A stream as `actor` may see it: for agents the target-derived strings go through the redactor.
    fn stream_for(&self, actor: &Actor, mut s: StreamRow) -> StreamRow {
        if let Some(r) = self.redactor_for(actor) {
            s.host = r.redact(&s.host);
            s.sni = s.sni.map(|v| r.redact(&v));
            s.error = s.error.map(|v| r.redact(&v));
        }
        s
    }

    /// Streams, newest first (a read: always allowed, not audited).
    pub fn streams_list(&self, actor: &Actor, filter: &StreamFilter) -> Result<StreamPage> {
        let limit = filter.limit.unwrap_or(50).clamp(1, 500);
        let mut f = filter.clone();
        f.limit = Some(limit);
        if let Some(c) = filter.client.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            // A device name means the addresses it was given to; an address means itself.
            f.clients = Some(self.clients_matching(c)?);
        }
        let rows = self.store.read(|db| db.list_streams(&f))?;
        let next_before_id = (rows.len() == limit).then(|| rows.last().map(|r| r.id)).flatten();
        let streams = rows.into_iter().map(|s| self.stream_for(actor, s)).collect();
        Ok(StreamPage { streams, next_before_id })
    }

    /// One stream with a page of its chunks (from the first, or after chunk id `after`; page on with
    /// `chunks.next_after_id`).
    pub fn stream_get(
        &self,
        actor: &Actor,
        id: i64,
        after: Option<i64>,
        limit: usize,
        max_chars: usize,
    ) -> Result<StreamDetail> {
        let row =
            self.store.read(|db| db.get_stream(id))?.ok_or_else(|| ServiceError::NotFound(format!("stream {id}")))?;
        let chunks = self.stream_chunks(actor, id, after, limit, max_chars)?;
        Ok(StreamDetail { stream: self.stream_for(actor, row), chunks })
    }

    /// Chunks of a stream, oldest first, after chunk id `after`.
    pub fn stream_chunks(
        &self,
        actor: &Actor,
        id: i64,
        after: Option<i64>,
        limit: usize,
        max_chars: usize,
    ) -> Result<StreamChunkPage> {
        let limit = limit.clamp(1, MAX_PAGE);
        let (rows, total) = self.store.read(|db| -> Result<_> {
            let s = db.get_stream(id)?.ok_or_else(|| ServiceError::NotFound(format!("stream {id}")))?;
            Ok((db.stream_chunks(id, after, limit, None)?, s.chunks))
        })?;
        let agent = actor.kind != ActorKind::Human;
        let redactor = self.redactor_for(actor);
        let next_after_id = (rows.len() == limit).then(|| rows.last().map(|r| r.id)).flatten();
        let chunks = rows.iter().map(|r| chunk_view(r, agent, redactor, max_chars)).collect();
        Ok(StreamChunkPage { stream_id: id, total, chunks, next_after_id, notice: agent.then_some(UNTRUSTED_NOTICE) })
    }

    /// Replays a stream: a new connection to the same target (TLS with the same server name and ALPN when the
    /// original was TLS), the client's chunks in order, the server's answer recorded as a new stream. Goes through
    /// the policy gate like `replay_send`: the target must be in scope and an agent needs approval for sending bytes
    /// (connecting and listening only is active-safe; sending is at least active-intrusive, more when the bytes
    /// look destructive). The approval covers exactly the chunks and timings.
    pub async fn stream_replay(&self, actor: &Actor, req: StreamReplayRequest) -> Result<StreamReplayResult> {
        let orig = self
            .store
            .read(|db| db.get_stream(req.stream_id))?
            .ok_or_else(|| ServiceError::NotFound(format!("stream {}", req.stream_id)))?;
        let chunks = self.replay_chunks(&req, &orig)?;
        if chunks.len() > MAX_REPLAY_CHUNKS {
            return Err(invalid(format!("at most {MAX_REPLAY_CHUNKS} chunks per replay")));
        }
        if chunks.iter().map(Vec::len).sum::<usize>() > MAX_REPLAY_SEND {
            return Err(invalid("chunks are larger than 16 MB in total"));
        }
        for c in &chunks {
            let unknown = self.redactor.unknown_placeholders(c);
            if !unknown.is_empty() {
                return Err(invalid(format!("unknown secret placeholders: {}", unknown.join(", "))));
            }
        }
        let delay_ms = req.delay_ms.unwrap_or(0).min(MAX_WAIT_MS);
        let read_ms = req.read_ms.unwrap_or(2000).min(MAX_WAIT_MS);
        let max_response = req.max_response_bytes.unwrap_or(DEFAULT_RESPONSE).min(MAX_RESPONSE);
        if delay_ms * chunks.len().saturating_sub(1) as u64 + read_ms > (MAX_SESSION.as_millis() as u64) - 5000 {
            return Err(invalid("the delays add up to more than a replay may take (55 s)"));
        }

        // What the gate sees: the target as a scope target (https for TLS, else http, path /), and the bytes as text.
        let scheme = if orig.tls { "https" } else { "http" };
        let ep = Endpoint::new(scheme, &orig.host, orig.port);
        let token = if chunks.is_empty() { "GET" } else { "STREAM" };
        let mut raw = format!("{token} {}:{} STREAM/1\r\n\r\n", orig.host, orig.port).into_bytes();
        chunks.iter().for_each(|c| raw.extend_from_slice(c));
        let out = Outgoing { endpoint: ep, raw, method: "STREAM".into(), path: "/".into(), hypothesis_id: None };
        let mut tier = if chunks.is_empty() { Tier::ActiveSafe } else { Tier::ActiveIntrusive };
        for c in &chunks {
            tier = tier.max(pm_policy::payload::classify_text(&String::from_utf8_lossy(c)).tier);
        }
        let extra = json!({
            "stream_id": orig.id,
            "chunks": chunks.iter().map(|c| pm_core::base64(c)).collect::<Vec<_>>(),
            "delay_ms": delay_ms,
            "read_ms": read_ms,
            "max_response_bytes": max_response,
        });
        match self.gate_send_with(
            actor,
            "stream_replay",
            &out,
            None,
            false,
            req.approval_id.as_deref(),
            Some(tier),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(StreamReplayResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(StreamReplayResult::PendingApproval { approval_id, summary, reasons });
            }
        }
        let plan = Plan {
            chunks: chunks.iter().map(|c| self.redactor.unredact(c)).collect(),
            delay: Duration::from_millis(delay_ms),
            read: Duration::from_millis(read_ms),
            max_response,
        };
        // A server that spoke first in the original is waited for before the first chunk goes out.
        let server_first =
            self.store.read(|db| db.stream_chunks(orig.id, None, 1, None))?.first().is_some_and(|c| !c.to_server);
        self.stream_session(actor, &orig, plan, server_first, req.max_chars.unwrap_or(2000)).await
    }

    /// The chunks to send: the request's replacements, or the recorded client-to-server chunks.
    fn replay_chunks(&self, req: &StreamReplayRequest, orig: &StreamRow) -> Result<Vec<Vec<u8>>> {
        match (&req.chunks, &req.text_chunks) {
            (Some(_), Some(_)) => Err(invalid("give chunks (base64) or text_chunks, not both")),
            (Some(list), None) => list
                .iter()
                .map(|b| {
                    pm_http::protobuf::base64_decode(b.as_bytes()).map_err(|_| invalid("a chunk is not valid base64"))
                })
                .collect(),
            (None, Some(list)) => Ok(list.iter().map(|t| t.as_bytes().to_vec()).collect()),
            (None, None) => {
                let mut out = Vec::new();
                let mut after = None;
                loop {
                    let page = self.store.read(|db| db.stream_chunks(orig.id, after, 1000, Some(true)))?;
                    let Some(last) = page.last().map(|c| c.id) else { break };
                    for c in page {
                        if (c.data.len() as u64) < c.len {
                            return Err(invalid(format!(
                                "stream {} was cut at the recording cap, so its chunks are incomplete: give replacement \
                                 chunks",
                                orig.id
                            )));
                        }
                        out.push(c.data);
                    }
                    after = Some(last);
                }
                Ok(out)
            }
        }
    }

    async fn stream_session(
        &self,
        actor: &Actor,
        orig: &StreamRow,
        plan: Plan,
        server_first: bool,
        max_chars: usize,
    ) -> Result<StreamReplayResult> {
        let _permit = self.acquire_slot(&orig.host).await?;
        let check = |ips: &[std::net::IpAddr]| self.policy.check_resolved(ips);
        let started_ms = now_ms();
        let started = Instant::now();
        let ep = Endpoint::new(if orig.tls { "https" } else { "http" }, &orig.host, orig.port);
        let connected = if orig.tls {
            // The same server name (the endpoint's host) and the ALPN protocol the original agreed.
            let alpn: Vec<Vec<u8>> = orig.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
            self.sender.connect_stream(&ep, &alpn, Some(&check)).await.map(|(io, _)| io)
        } else {
            self.sender.connect_tunnel_to(&ep, Some(&check)).await
        };
        let new = NewStream {
            start_ms: started_ms,
            host: orig.host.clone(),
            port: orig.port,
            client_addr: None,
            tls: orig.tls,
            sni: orig.tls.then(|| orig.host.clone()),
            alpn: orig.alpn.clone(),
            source: "stream_replay".into(),
            actor_id: actor.id(),
            replay_of: Some(orig.id),
        };
        let mut io = match connected {
            Ok(io) => io,
            Err(e) => {
                let error = format!("{e:#}");
                let end = StreamEnd {
                    end_ms: now_ms(),
                    ended: "error".into(),
                    error: Some(error.clone()),
                    ..Default::default()
                };
                let stream_id = self.store.write(|db| db.record_stream(&new, Vec::new(), end))?;
                return Ok(StreamReplayResult::Failed { stream_id, error });
            }
        };

        let mut cap = Capture::default();
        let mut buf = vec![0u8; 16 << 10];
        let deadline = started + MAX_SESSION;
        let hold_until = Instant::now() + plan.read.max(Duration::from_millis(200));
        let mut hold = server_first && !plan.chunks.is_empty();
        let (mut next, mut sent_idx) = (Instant::now(), 0usize);
        let mut last_activity = Instant::now();
        let (mut ended, mut note, mut error) = ("client_closed", None::<String>, None::<String>);
        loop {
            let now = Instant::now();
            if now >= deadline {
                (ended, note) = ("timeout", Some("stopped after 60 s".into()));
                break;
            }
            if hold && now >= hold_until {
                hold = false;
            }
            if !hold && sent_idx < plan.chunks.len() && now >= next {
                let chunk = &plan.chunks[sent_idx];
                let write = async {
                    io.write_all(chunk).await?;
                    io.flush().await
                };
                if let Err(e) = write.await {
                    (ended, error) = ("error", Some(format!("the connection broke while sending: {e}")));
                    break;
                }
                cap.add(true, chunk);
                sent_idx += 1;
                next = Instant::now() + plan.delay;
                last_activity = Instant::now();
                continue;
            }
            let sending = sent_idx < plan.chunks.len();
            if !sending && !hold && now >= last_activity + plan.read {
                note = Some(format!("the server was silent for {} ms", plan.read.as_millis()));
                break;
            }
            let wake = if hold {
                hold_until
            } else if sending {
                next
            } else {
                last_activity + plan.read
            };
            let wake = tokio::time::Instant::from_std(wake.min(deadline));
            tokio::select! {
                r = io.read(&mut buf) => match r {
                    Ok(0) => { ended = "server_closed"; break; }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => { ended = "server_closed"; break; }
                    Err(e) => { (ended, error) = ("error", Some(e.to_string())); break; }
                    Ok(n) => {
                        cap.add(false, &buf[..n]);
                        last_activity = Instant::now();
                        hold = false;
                        if cap.received >= plan.max_response as u64 {
                            (ended, note) = ("limit", Some(format!("stopped after {} bytes from the server", plan.max_response)));
                            break;
                        }
                    }
                },
                _ = tokio::time::sleep_until(wake) => {}
            }
        }
        let _ = io.shutdown().await;

        let end = StreamEnd {
            end_ms: now_ms(),
            bytes_to_server: cap.sent,
            bytes_to_client: cap.received,
            truncated: cap.truncated,
            ended: ended.into(),
            error: error.clone(),
        };
        let (sent_bytes, received_bytes) = (cap.sent, cap.received);
        let stream_id = self.store.write(|db| db.record_stream(&new, cap.chunks, end))?;
        let chunks = self.stream_chunks(actor, stream_id, None, 200, max_chars)?;
        if let Some(e) = error {
            note = Some(note.map_or(e.clone(), |n| format!("{n}; {e}")));
        }
        Ok(StreamReplayResult::Done { stream_id, ended: ended.into(), note, sent_bytes, received_bytes, chunks })
    }
}

struct Plan {
    /// The bytes as sent (secret placeholders filled in).
    chunks: Vec<Vec<u8>>,
    delay: Duration,
    read: Duration,
    max_response: usize,
}

/// Collects what crossed the connection, within the recording caps.
#[derive(Default)]
struct Capture {
    chunks: Vec<NewChunk>,
    sent: u64,
    received: u64,
    kept: u64,
    truncated: bool,
}

impl Capture {
    fn add(&mut self, to_server: bool, data: &[u8]) {
        if to_server {
            self.sent += data.len() as u64;
        } else {
            self.received += data.len() as u64;
        }
        if self.chunks.len() as u64 >= STREAM_CHUNK_CAP || self.kept >= STREAM_RECORD_CAP {
            self.truncated = true;
            return;
        }
        let take = data.len().min(usize::try_from(STREAM_RECORD_CAP - self.kept).unwrap_or(usize::MAX));
        self.truncated |= take < data.len();
        self.kept += take as u64;
        self.chunks.push(NewChunk { ts_ms: now_ms(), to_server, len: data.len() as u64, data: data[..take].to_vec() });
    }
}

fn chunk_view(
    r: &StreamChunkRow,
    agent: bool,
    redactor: Option<&pm_ai::Redactor>,
    max_chars: usize,
) -> StreamChunkView {
    let mut text = String::from_utf8_lossy(&r.data).into_owned();
    if let Some(red) = redactor {
        text = red.redact(&text);
    }
    let mut text_truncated = false;
    if text.chars().count() > max_chars {
        text = text.chars().take(max_chars).collect();
        text_truncated = true;
    }
    let possible_prompt_injection = prompt_injection_signals(&text);
    if agent {
        text = wrap_untrusted(&text);
    }
    StreamChunkView {
        id: r.id,
        ts_ms: r.ts_ms,
        from: if r.to_server { "client" } else { "server" },
        len: r.len,
        kept: r.data.len() as u64,
        data_b64: (!agent).then(|| pm_core::base64(&r.data)),
        text,
        text_truncated,
        possible_prompt_injection,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_keeps_chunks_up_to_the_cap_and_counts_the_rest() {
        let mut c = Capture::default();
        c.add(true, &vec![1u8; (STREAM_RECORD_CAP - 2) as usize]);
        c.add(false, &[2u8; 10]);
        c.add(true, &[3u8; 5]);
        assert_eq!((c.sent, c.received, c.kept, c.truncated), (STREAM_RECORD_CAP - 2 + 5, 10, STREAM_RECORD_CAP, true));
        assert_eq!(c.chunks.len(), 2, "the chunk after the cap is not stored");
        assert_eq!((c.chunks[1].len, c.chunks[1].data.len()), (10, 2));
    }
}
