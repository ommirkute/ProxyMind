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

use crate::{DROPPED_MSG, Proxy, SelfAddr};

/// Largest request body accepted from the browser over HTTP/2.
const MAX_BODY: usize = 64 << 20;

impl Proxy {
    pub(crate) async fn serve_h2<S: Io + 'static>(
        self: Arc<Self>,
        io: S,
        host: String,
        port: u16,
        me: Option<SelfAddr>,
    ) -> Result<()> {
        let mut conn = h2::server::handshake(io).await.context("HTTP/2 handshake with client")?;
        while let Some(next) = conn.accept().await {
            let (req, respond) = next.context("HTTP/2 stream from client")?;
            let this = self.clone();
            let host = host.clone();
            tokio::spawn(async move {
                if let Err(e) = this.h2_stream(req, respond, &host, port, me).await {
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
        me: Option<SelfAddr>,
    ) -> Result<()> {
        let (parts, mut body) = req.into_parts();
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

        let Some((request, method, path)) = self.before_send("https", host, port, request, &method, &path).await else {
            return reply(&mut respond, 403, DROPPED_MSG.as_bytes());
        };

        let started = Instant::now();
        let guard = self.loop_guard(&me, host, port);
        let check = guard.as_ref().map(|g| g as pm_replay::AddrCheck<'_>);
        let result = self.sender.send(&Endpoint::new("https", host, port), &request, &method, check).await;
        let mut record = NewExchange {
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
        };
        match result {
            Ok(resp) => {
                if let Some(sent) = resp.sent {
                    record.request = sent;
                }
                record.status = Some(resp.head.status);
                let decision = self.before_respond("https", host, port, &method, &path, &resp.raw).await;
                record.response = Some(resp.raw);
                let to_client = match decision {
                    None => {
                        self.recorder.record(record);
                        respond.send_reset(h2::Reason::CANCEL);
                        return Ok(());
                    }
                    Some(edited) => edited.unwrap_or_else(|| record.response.clone().unwrap_or_default()),
                };
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
