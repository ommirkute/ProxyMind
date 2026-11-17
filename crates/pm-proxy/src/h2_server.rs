//! HTTP/2 from the browser. Each stream becomes an HTTP/2 text request and
//! goes through the same steps as HTTP/1.1: rules, intercept, send, record.
//! The sender speaks HTTP/2 to the server when it can and downgrades when
//! it can't; history records what was actually sent.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use h2::RecvStream;
use h2::server::SendResponse;
use pm_core::now_ms;
use pm_http::h2text::{H2Request, h2_response, render_h2_request};
use pm_replay::{Endpoint, Io};
use pm_store::NewExchange;

use crate::{Ctx, HOOK_MAX, HookKind, HookTarget, Proxy, ResponseEdit, hook_changes, message_content_type};

/// Largest request body accepted from the browser over HTTP/2.
const MAX_BODY: usize = 64 << 20;

impl Proxy {
    pub(crate) async fn serve_h2<S: Io + 'static>(
        self: Arc<Self>,
        io: S,
        host: String,
        port: u16,
        ctx: Ctx,
    ) -> Result<()> {
        // Each stream may buffer a body: bound how many run at once.
        let mut conn = h2::server::Builder::new()
            .max_concurrent_streams(128)
            .handshake(io)
            .await
            .context("HTTP/2 handshake with client")?;
        while let Some(next) = conn.accept().await {
            let (req, respond) = next.context("HTTP/2 stream from client")?;
            let this = self.clone();
            let host = host.clone();
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = this.h2_stream(req, respond, &host, port, ctx).await {
                    tracing::debug!(error = %e, "HTTP/2 stream ended with error");
                }
            });
        }
        Ok(())
    }

    async fn h2_stream(
        &self,
        req: http::Request<RecvStream>,
        mut respond: SendResponse<Bytes>,
        host: &str,
        port: u16,
        ctx: Ctx,
    ) -> Result<()> {
        let (me, peer, pin) = (ctx.me, ctx.peer, ctx.pin());
        let (parts, mut body) = req.into_parts();
        // Answer 100 Continue ourselves: the body goes upstream only once
        // it has arrived whole.
        if parts.headers.get("expect").is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"100-continue")) {
            let _ = respond.send_informational(http::Response::builder().status(100).body(())?);
        }
        let mut data = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.context("reading the request body")?;
            let _ = body.flow_control().release_capacity(chunk.len());
            data.extend_from_slice(&chunk);
            if data.len() > MAX_BODY {
                respond.send_reset(h2::Reason::REFUSED_STREAM);
                bail!("request body over {} MB", MAX_BODY >> 20);
            }
        }
        let path = parts.uri.path_and_query().map_or_else(|| "/".to_string(), |p| p.as_str().to_string());
        let authority =
            parts.uri.authority().map_or_else(|| pm_core::authority("https", host, port), |a| a.to_string());
        let mut headers = parts.headers.iter().map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec())).collect();
        pm_http::h2text::join_cookies(&mut headers);
        let method = parts.method.as_str().to_string();
        let request = render_h2_request(&H2Request {
            method: method.clone(),
            path: path.clone(),
            authority: Some(authority),
            headers,
            body: data,
        });

        let (request, method, path, edits) = match self.before_send("https", host, port, request, &method, &path).await
        {
            Ok(r) => r,
            Err(msg) => return reply(&mut respond, 403, msg.as_bytes()),
        };

        let started = Instant::now();
        let guard = self.loop_guard(&me, host, port);
        let check = guard.as_ref().map(|g| g as pm_replay::AddrCheck<'_>);
        if pm_http::h2text::is_http2_request(&request) && !self.buffers_response("https", host, port, &path) {
            return self
                .h2_streamed(respond, host, port, (request, edits), method, path, check, started, (peer, pin))
                .await;
        }
        let ep = Endpoint::new("https", host, port).with_pin(pin);
        let result = self.sender.send(&ep, &request, &method, check).await;
        let mut record = NewExchange {
            client_addr: peer.map(|ip| ip.to_string()),
            ts_ms: now_ms(),
            duration_ms: Some(started.elapsed().as_millis() as i64),
            source: "proxy".into(),
            actor_id: "human:local".into(),
            scheme: "https".into(),
            host: host.to_string(),
            port,
            method: method.clone(),
            path: path.clone(),
            status: None,
            request,
            response: None,
            error: None,
            identity: None,
            hypothesis_id: None,
            ..Default::default()
        };
        edits.note_on(&mut record);
        match result {
            Ok(resp) => {
                if let Some(sent) = resp.sent {
                    record.request = sent;
                }
                record.status = Some(resp.head.status);
                let decision = self.before_respond("https", host, port, &method, &path, &resp.raw).await;
                record.response = Some(resp.raw);
                let Some(edit) = decision else {
                    self.recorder.record(record);
                    respond.send_reset(h2::Reason::CANCEL);
                    return Ok(());
                };
                if let Some(msg) = edit.blocked.clone() {
                    edit.note_on(&mut record);
                    self.recorder.record(record);
                    return reply(&mut respond, 502, msg.as_bytes());
                }
                let to_client = edit.bytes.clone().unwrap_or_else(|| record.response.clone().unwrap_or_default());
                edit.note_on(&mut record);
                self.recorder.record(record);
                let r = match h2_response(&to_client) {
                    Ok(r) => r,
                    Err(e) => {
                        return reply(&mut respond, 502, format!("ProxyMind can't send this response: {e}").as_bytes());
                    }
                };
                let mut b = http::Response::builder().status(r.status);
                for (n, v) in &r.headers {
                    if let (Ok(n), Ok(v)) =
                        (http::HeaderName::from_bytes(n.as_bytes()), http::HeaderValue::from_bytes(v))
                    {
                        b = b.header(n, v);
                    }
                }
                let head = b.body(()).context("building the HTTP/2 response")?;
                let end = r.body.is_empty() || method.eq_ignore_ascii_case("HEAD");
                let mut stream = respond.send_response(head, end)?;
                if !end {
                    stream.send_data(Bytes::from(r.body), true)?;
                }
                Ok(())
            }
            Err(e) => {
                let msg = format!("ProxyMind could not reach {host}:{port}: {e:#}");
                tracing::warn!("{msg}");
                record.error = Some(format!("{e:#}"));
                self.recorder.record(record);
                reply(&mut respond, 502, msg.as_bytes())
            }
        }
    }
}

impl Proxy {
    /// Sends the request and passes the response on as it streams, within
    /// the browser's flow-control window.
    #[allow(clippy::too_many_arguments)]
    async fn h2_streamed(
        &self,
        mut respond: SendResponse<Bytes>,
        host: &str,
        port: u16,
        (request, edits): (Vec<u8>, crate::Edits),
        method: String,
        path: String,
        check: Option<pm_replay::AddrCheck<'_>>,
        started: Instant,
        (peer, pin): (Option<std::net::IpAddr>, Option<std::net::IpAddr>),
    ) -> Result<()> {
        let mut record = NewExchange {
            client_addr: peer.map(|ip| ip.to_string()),
            ts_ms: now_ms(),
            duration_ms: None,
            source: "proxy".into(),
            actor_id: "human:local".into(),
            scheme: "https".into(),
            host: host.to_string(),
            port,
            method: method.clone(),
            path,
            status: None,
            request,
            response: None,
            error: None,
            identity: None,
            hypothesis_id: None,
            ..Default::default()
        };
        edits.note_on(&mut record);
        let ep = Endpoint::new("https", host, port).with_pin(pin);
        let mut r = match self.sender.send_h2_start(&ep, &record.request, &method, check, crate::HEAD_TIMEOUT).await {
            Ok(r) => r,
            Err(e) => {
                let msg = format!("ProxyMind could not reach {host}:{port}: {e:#}");
                tracing::warn!("{msg}");
                record.error = Some(format!("{e:#}"));
                record.duration_ms = Some(started.elapsed().as_millis() as i64);
                self.recorder.record(record);
                return reply(&mut respond, 502, msg.as_bytes());
            }
        };
        if let Some(sent) = r.sent.take() {
            record.request = sent;
        }
        record.status = Some(r.head.status);
        let mut b = http::Response::builder().status(r.head.status);
        for (n, v) in pm_http::h2text::h2_headers(&r.head) {
            if let (Ok(n), Ok(v)) = (http::HeaderName::from_bytes(n.as_bytes()), http::HeaderValue::from_bytes(&v)) {
                b = b.header(n, v);
            }
        }
        let head_only = method.eq_ignore_ascii_case("HEAD") || matches!(r.head.status, 204 | 304);
        let mut capture = r.raw_head.clone();
        let mut truncated = false;
        let mut reusable = head_only;
        // A response hook needs the whole message: hold the response back (up to 8 MB) while one matches.
        let hook_path = record.path.clone();
        let hook_target = HookTarget { scheme: "https", host, port, method: &method, path: &hook_path };
        let mut holding = false;
        if let Some(h) = self.hooks.plugin_hooks.as_ref().filter(|h| h.wants(HookKind::Response))
            && h.may_apply(HookKind::Response, &hook_target, &r.raw_head)
        {
            let why = if message_content_type(&r.raw_head).as_deref() == Some("text/event-stream") {
                Some("streamed (server-sent events) responses bypass hooks")
            } else {
                match r.head.body_kind(&method) {
                    Ok(pm_http::BodyKind::ContentLength(n)) if n > HOOK_MAX as u64 => Some("message over 8 MB"),
                    _ => None,
                }
            };
            match why {
                Some(why) => record
                    .changes
                    .extend(hook_changes("response", h.skipped(HookKind::Response, &hook_target, &r.raw_head, why))),
                None => holding = true,
            }
        }
        let mut held: Vec<u8> = Vec::new();
        let mut stream: Option<h2::SendStream<Bytes>> = None;
        let mut b_slot = Some(b);
        if !holding {
            match b_slot.take().unwrap_or_default().body(()).context("building the HTTP/2 response").and_then(|head| {
                respond.send_response(head, head_only).context("sending the response head to the browser")
            }) {
                Ok(s) => stream = Some(s),
                Err(e) => record.error = Some(format!("{e:#}")),
            }
        }
        let mut failed = false;
        if !head_only && (holding || stream.is_some()) {
            loop {
                let (raw, payload) = match r.next(crate::BODY_IDLE).await {
                    Ok(Some(p)) => p,
                    Ok(None) => break,
                    Err(e) => {
                        record.error = Some(format!("{e:#}"));
                        failed = true;
                        break;
                    }
                };
                let room = crate::RECORD_CAP.saturating_sub(capture.len());
                truncated |= raw.len() > room;
                capture.extend_from_slice(&raw[..raw.len().min(room)]);
                if holding {
                    held.extend_from_slice(&payload);
                    if capture.len() <= HOOK_MAX {
                        continue;
                    }
                    // Too big for a hook after all: send what was held and stream the rest.
                    holding = false;
                    if let Some(h) = &self.hooks.plugin_hooks {
                        record.changes.extend(hook_changes(
                            "response",
                            h.skipped(HookKind::Response, &hook_target, &capture, "message over 8 MB"),
                        ));
                    }
                    let sent = http::Response::builder()
                        .status(r.head.status)
                        .body(())
                        .context("building the HTTP/2 response")
                        .and_then(|mut head| {
                            for (n, v) in pm_http::h2text::h2_headers(&r.head) {
                                if let (Ok(n), Ok(v)) =
                                    (http::HeaderName::from_bytes(n.as_bytes()), http::HeaderValue::from_bytes(&v))
                                {
                                    head.headers_mut().append(n, v);
                                }
                            }
                            respond.send_response(head, false).context("sending the response head to the browser")
                        });
                    match sent {
                        Ok(s) => stream = Some(s),
                        Err(e) => {
                            record.error = Some(format!("{e:#}"));
                            failed = true;
                            break;
                        }
                    }
                    let first = std::mem::take(&mut held);
                    if let Some(s) = stream.as_mut()
                        && !first.is_empty()
                        && send_within_window(s, first).await.is_err()
                    {
                        record.error = Some(format!("the browser closed the stream after {} body bytes", r.read));
                        failed = true;
                        break;
                    }
                    continue;
                }
                if let Some(s) = stream.as_mut()
                    && !payload.is_empty()
                    && send_within_window(s, payload).await.is_err()
                {
                    record.error = Some(format!("the browser closed the stream after {} body bytes", r.read));
                    failed = true;
                    break;
                }
            }
        }
        if holding {
            // The whole response is here (or the server failed): the hooks decide what the browser gets.
            let hooks = self.hooks.plugin_hooks.as_ref().filter(|_| !failed && r.cut_short.is_none());
            let edit = match hooks {
                Some(h) => {
                    Some(ResponseEdit::from_run(h.run(HookKind::Response, &hook_target, &capture).await, &capture))
                }
                None => None,
            };
            let blocked = edit.as_ref().and_then(|e| e.blocked.clone());
            let replaced = edit.as_ref().and_then(|e| e.bytes.clone());
            if let Some(e) = edit {
                e.note_on(&mut record);
            }
            let delivered = if failed {
                respond.send_reset(h2::Reason::INTERNAL_ERROR);
                Ok(())
            } else if let Some(msg) = blocked {
                reusable = true;
                reply(&mut respond, 502, msg.as_bytes())
            } else if let Some(bytes) = replaced {
                reusable = true;
                send_raw_response(&mut respond, &bytes, &method)
            } else {
                reusable = true;
                send_held(&mut respond, b_slot.take().unwrap_or_default(), head_only, held).await
            };
            if let Err(e) = delivered {
                record.error.get_or_insert(format!("{e:#}"));
                reusable = false;
            }
        } else if let Some(mut stream) = stream {
            if failed {
                stream.send_reset(h2::Reason::INTERNAL_ERROR);
            } else {
                let _ = stream.send_data(Bytes::new(), true);
                reusable = true;
            }
        }
        if record.error.is_none() {
            record.error = r.cut_short.clone();
        }
        if truncated {
            let note = format!(
                "history keeps the first {} MB of this response ({} body bytes in all)",
                crate::RECORD_CAP >> 20,
                r.read
            );
            record.error = Some(record.error.map_or(note.clone(), |e| format!("{e}; {note}")));
        }
        record.duration_ms = Some(started.elapsed().as_millis() as i64);
        record.response = Some(capture);
        self.recorder.record(record);
        if reusable && let Some(conn) = r.into_reusable() {
            self.sender.release(&ep, conn);
        }
        Ok(())
    }
}

/// Sends a response given as raw (HTTP/2 text or HTTP/1.1) bytes, exactly as a hook returned it.
fn send_raw_response(respond: &mut SendResponse<Bytes>, bytes: &[u8], method: &str) -> Result<()> {
    let r = match h2_response(bytes) {
        Ok(r) => r,
        Err(e) => return reply(respond, 502, format!("ProxyMind can't send this response: {e}").as_bytes()),
    };
    let mut b = http::Response::builder().status(r.status);
    for (n, v) in &r.headers {
        if let (Ok(n), Ok(v)) = (http::HeaderName::from_bytes(n.as_bytes()), http::HeaderValue::from_bytes(v)) {
            b = b.header(n, v);
        }
    }
    let head = b.body(()).context("building the HTTP/2 response")?;
    let end = r.body.is_empty() || method.eq_ignore_ascii_case("HEAD");
    let mut stream = respond.send_response(head, end)?;
    if !end {
        stream.send_data(Bytes::from(r.body), true)?;
    }
    Ok(())
}

/// Sends the server's own response after a hook looked at it and changed nothing.
async fn send_held(
    respond: &mut SendResponse<Bytes>,
    builder: http::response::Builder,
    head_only: bool,
    body: Vec<u8>,
) -> Result<()> {
    let head = builder.body(()).context("building the HTTP/2 response")?;
    let mut stream = respond.send_response(head, head_only)?;
    if !head_only {
        send_within_window(&mut stream, body).await?;
        stream.send_data(Bytes::new(), true)?;
    }
    Ok(())
}

/// Sends `data` on an HTTP/2 stream, waiting for the browser's
/// flow-control window instead of buffering without limit.
async fn send_within_window(stream: &mut h2::SendStream<Bytes>, data: Vec<u8>) -> Result<()> {
    let mut data = Bytes::from(data);
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        let cap = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| anyhow::anyhow!("the stream closed"))??;
        if cap == 0 {
            continue;
        }
        let n = cap.min(data.len());
        stream.send_data(data.split_to(n), false)?;
    }
    Ok(())
}

/// A short plain-text response from ProxyMind itself.
fn reply(respond: &mut SendResponse<Bytes>, status: u16, body: &[u8]) -> Result<()> {
    let head = http::Response::builder()
        .status(status)
        .header("content-type", "text/plain")
        .header("content-length", body.len())
        .body(())?;
    let mut s = respond.send_response(head, false)?;
    s.send_data(Bytes::copy_from_slice(body), true)?;
    Ok(())
}
