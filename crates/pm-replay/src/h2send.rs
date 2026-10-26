//! Sending requests written in HTTP/2 text form (see `pm_http::h2text`).

use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use pm_http::h2text::{downgrade_request, h2_request, render_h2_response};
use tokio::io::AsyncWriteExt;

use crate::{AddrCheck, AfterResponse, Conn, Endpoint, Response, Sender, read_response};

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
