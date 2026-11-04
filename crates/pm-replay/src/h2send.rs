//! Sending requests written in HTTP/2 text form (see `pm_http::h2text`).

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use pm_http::h2text::{downgrade_request, h2_request, render_h2_response};
use pm_http::{BodyKind, ChunkDecoder, ResponseHead};
use tokio::io::AsyncWriteExt;

use crate::{AddrCheck, AfterResponse, BodyStream, Conn, Endpoint, Io, Response, Sender, read_response};

/// Largest response body read over HTTP/2.
const MAX_BODY: usize = 64 << 20;

impl Sender {
    /// Sends an HTTP/2 text request. Over HTTPS, ALPN decides: if the server
    /// only speaks HTTP/1.1, the request is downgraded and `Response::sent`
    /// holds the bytes actually sent. Plain HTTP uses h2c (prior knowledge).
    pub(crate) async fn send_h2(
        &self,
        ep: &Endpoint,
        request: &[u8],
        method: &str,
        check: Option<AddrCheck<'_>>,
    ) -> Result<Response> {
        let started = Instant::now();
        let req = h2_request(request).map_err(|e| anyhow!("not a valid HTTP/2 request: {e}"))?;
        let authority = req.authority.clone().unwrap_or_else(|| pm_core::authority(&ep.scheme, &ep.host, ep.port));
        let (io, h2) = self.connect_with(ep, check, true).await?;
        if !h2 {
            let bytes = downgrade_request(&req, &authority);
            let mut conn = Conn::new(io);
            conn.io.write_all(&bytes).await?;
            conn.io.flush().await?;
            let mut resp = tokio::time::timeout(self.read_timeout, read_response(conn, method, started))
                .await
                .context("timed out waiting for the response")??;
            resp.sent = Some(bytes);
            return Ok(resp);
        }

        let (client, connection) = h2::client::handshake(io).await.context("HTTP/2 handshake")?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await.context("HTTP/2 connection")?;
        let uri = format!("{}://{authority}{}", ep.scheme, req.path);
        let mut builder = http::Request::builder().method(req.method.as_str()).uri(&uri);
        for (name, value) in &req.headers {
            let value =
                http::HeaderValue::from_bytes(value).with_context(|| format!("header {name} has a bad value"))?;
            builder = builder.header(name.as_str(), value);
        }
        let http_req = builder.body(()).with_context(|| format!("can't send {} {uri} over HTTP/2", req.method))?;
        let end = req.body.is_empty();
        let (resp, mut stream) = client.send_request(http_req, end).context("sending the HTTP/2 request")?;
        if !end {
            stream.send_data(Bytes::from(req.body.clone()), true).context("sending the HTTP/2 body")?;
        }

        let read = async {
            let resp = resp.await.context("HTTP/2 response")?;
            let (parts, mut body) = resp.into_parts();
            let mut data = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.context("reading the HTTP/2 body")?;
                let _ = body.flow_control().release_capacity(chunk.len());
                data.extend_from_slice(&chunk);
                if data.len() > MAX_BODY {
                    bail!("HTTP/2 response body is larger than {} MB", MAX_BODY >> 20);
                }
            }
            let mut headers: Vec<(String, Vec<u8>)> =
                parts.headers.iter().map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec())).collect();
            // Trailers are rare; show them after the headers.
            if let Ok(Some(trailers)) = body.trailers().await {
                headers.extend(trailers.iter().map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec())));
            }
            let raw = render_h2_response(parts.status.as_u16(), &headers, &data);
            let end = pm_http::find_head_end(&raw)?.unwrap_or(raw.len());
            let head = pm_http::parse_response_head(&raw[..end])?;
            Ok(Response {
                raw,
                head,
                conn: AfterResponse::Done,
                elapsed: started.elapsed(),
                sent: None,
                cut_short: None,
            })
        };
        tokio::time::timeout(self.read_timeout, read).await.context("timed out waiting for the response")?
    }
}

/// The body of a streaming response from [`Sender::send_h2_start`].
enum StreamBody {
    /// The server only spoke HTTP/1.1: the request was downgraded.
    H1 {
        conn: Conn<Box<dyn Io>>,
        body: BodyStream,
        decoder: Option<ChunkDecoder>,
    },
    H2 {
        body: h2::RecvStream,
        done: bool,
    },
}

/// A response to an HTTP/2 text request whose head has arrived.
pub struct StreamedResponse {
    /// The head as history shows it (HTTP/2 text, or the HTTP/1.1 head received).
    pub raw_head: Vec<u8>,
    pub head: ResponseHead,
    /// The bytes actually sent, when the request was downgraded.
    pub sent: Option<Vec<u8>>,
    /// Payload bytes passed on so far.
    pub read: u64,
    /// Set when the server stopped before the body was complete.
    pub cut_short: Option<String>,
    body: StreamBody,
}

impl StreamedResponse {
    /// The next piece of the body: `(raw, payload)`, where `raw` is how
    /// history records it and `payload` is the content (chunked framing
    /// removed). `None` once the body is complete.
    pub async fn next(&mut self, idle: Duration) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        match &mut self.body {
            StreamBody::H1 { conn, body, decoder } => {
                let piece = conn.body_chunk(body, idle).await?;
                if body.cut_short.is_some() {
                    self.cut_short.clone_from(&body.cut_short);
                }
                let Some(raw) = piece else { return Ok(None) };
                let payload = match decoder {
                    Some(d) => {
                        let mut out = Vec::with_capacity(raw.len());
                        d.feed(&raw, &mut out)?;
                        out
                    }
                    None => raw.clone(),
                };
                self.read += payload.len() as u64;
                Ok(Some((raw, payload)))
            }
            StreamBody::H2 { body, done } => {
                if *done {
                    return Ok(None);
                }
                let next = tokio::time::timeout(idle, body.data())
                    .await
                    .map_err(|_| anyhow!("nothing arrived for {} s", idle.as_secs()))?;
                match next {
                    None => {
                        *done = true;
                        Ok(None)
                    }
                    Some(Err(e)) => {
                        *done = true;
                        self.cut_short = Some(format!("the HTTP/2 stream ended early: {e}"));
                        Ok(None)
                    }
                    Some(Ok(chunk)) => {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        self.read += chunk.len() as u64;
                        Ok(Some((chunk.to_vec(), chunk.to_vec())))
                    }
                }
            }
        }
    }
}

impl Sender {
    /// Like [`Sender::send_h2`], but returns once the response head has
    /// arrived, so the body can be passed on while it streams.
    pub async fn send_h2_start(
        &self,
        ep: &Endpoint,
        request: &[u8],
        method: &str,
        check: Option<AddrCheck<'_>>,
        head_timeout: Duration,
    ) -> Result<StreamedResponse> {
        let req = h2_request(request).map_err(|e| anyhow!("not a valid HTTP/2 request: {e}"))?;
        let authority = req.authority.clone().unwrap_or_else(|| pm_core::authority(&ep.scheme, &ep.host, ep.port));
        let (io, h2) = self.connect_with(ep, check, true).await?;
        if !h2 {
            let bytes = downgrade_request(&req, &authority);
            let mut conn = Conn::new(io);
            conn.io.write_all(&bytes).await?;
            conn.io.flush().await?;
            let read_heads = async {
                let mut raw = Vec::new();
                loop {
                    let head_raw =
                        conn.read_head().await?.ok_or_else(|| anyhow!("server closed without responding"))?;
                    let head = pm_http::parse_response_head(&head_raw)?;
                    raw.extend_from_slice(&head_raw);
                    if !(100..200).contains(&head.status) {
                        return anyhow::Ok((raw, head));
                    }
                }
            };
            let (raw_head, head) = tokio::time::timeout(head_timeout, read_heads)
                .await
                .map_err(|_| anyhow!("no response within {} s", head_timeout.as_secs()))??;
            let kind = head.body_kind(method)?;
            let decoder = (kind == BodyKind::Chunked).then(ChunkDecoder::new);
            return Ok(StreamedResponse {
                raw_head,
                head,
                sent: Some(bytes),
                read: 0,
                cut_short: None,
                body: StreamBody::H1 { conn, body: BodyStream::new(kind), decoder },
            });
        }

        let (client, connection) = h2::client::handshake(io).await.context("HTTP/2 handshake")?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut client = client.ready().await.context("HTTP/2 connection")?;
        let uri = format!("{}://{authority}{}", ep.scheme, req.path);
        let mut builder = http::Request::builder().method(req.method.as_str()).uri(&uri);
        for (name, value) in &req.headers {
            let value =
                http::HeaderValue::from_bytes(value).with_context(|| format!("header {name} has a bad value"))?;
            builder = builder.header(name.as_str(), value);
        }
        let http_req = builder.body(()).with_context(|| format!("can't send {} {uri} over HTTP/2", req.method))?;
        let end = req.body.is_empty();
        let (resp, mut stream) = client.send_request(http_req, end).context("sending the HTTP/2 request")?;
        if !end {
            stream.send_data(Bytes::from(req.body.clone()), true).context("sending the HTTP/2 body")?;
        }
        let resp = tokio::time::timeout(head_timeout, resp)
            .await
            .map_err(|_| anyhow!("no response within {} s", head_timeout.as_secs()))?
            .context("HTTP/2 response")?;
        let (parts, body) = resp.into_parts();
        let headers: Vec<(String, Vec<u8>)> =
            parts.headers.iter().map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec())).collect();
        let raw_head = render_h2_response(parts.status.as_u16(), &headers, &[]);
        let head = pm_http::parse_response_head(&raw_head)?;
        Ok(StreamedResponse {
            raw_head,
            head,
            sent: None,
            read: 0,
            cut_short: None,
            body: StreamBody::H2 { body, done: false },
        })
    }
}
