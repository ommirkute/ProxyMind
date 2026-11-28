//! Sending requests written in HTTP/3 text form (ADR-0021; see `pm_http::h3text`) over QUIC.
//!
//! The request goes straight to the target over UDP. HTTP and SOCKS5 upstream proxies carry TCP only, so a host
//! that an upstream rule routes through a proxy is refused, never sent around it. Like every other send, the
//! host's addresses are resolved here, passed to the caller's check, and the QUIC socket connects to exactly those
//! addresses (DNS rebinding protection); the server name for TLS is the host name.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Buf, Bytes};
use pm_http::h3text::{h3_request, render_h3_response};

use crate::{AddrCheck, AfterResponse, Endpoint, Response, Sender};

/// Largest response body read over HTTP/3 by default (the same limit as HTTP/2).
pub(crate) const MAX_BODY: usize = 64 << 20;
/// Most addresses of one host tried at once.
const MAX_ADDRS: usize = 4;

/// The reason an HTTP/3 request is refused because an upstream rule sends the host through a proxy.
fn proxy_refusal(host: &str, proxy: &crate::UpstreamProxy) -> anyhow::Error {
    anyhow!(
        "HTTP/3 can't go through the upstream proxy {}:{} that the rules choose for {host}: HTTP and SOCKS5 proxies \
         carry TCP, QUIC is UDP. Send with HTTP/1.1 or HTTP/2, or make the upstream rule for this host `direct`",
        proxy.host,
        proxy.port
    )
}

impl Sender {
    /// Why this host can't be reached over HTTP/3 right now, if it can't: needs `https` (QUIC always uses TLS) and
    /// a direct route.
    pub fn h3_refusal(&self, ep: &Endpoint) -> Option<String> {
        if ep.scheme != "https" {
            return Some("HTTP/3 needs an https target (QUIC always uses TLS)".into());
        }
        self.net.upstream_for(&ep.host).map(|p| proxy_refusal(&ep.host, &p).to_string())
    }

    /// Sends an HTTP/3 text request on a new QUIC connection and reads the whole response (as HTTP/3 text).
    pub(crate) async fn send_h3(
        &self,
        ep: &Endpoint,
        request: &[u8],
        check: Option<AddrCheck<'_>>,
    ) -> Result<Response> {
        let started = Instant::now();
        let req = h3_request(request).map_err(|e| anyhow!("not a valid HTTP/3 request: {e}"))?;
        if let Some(why) = self.h3_refusal(ep) {
            bail!("{why}");
        }
        let authority = req.authority.clone().unwrap_or_else(|| pm_core::authority(&ep.scheme, &ep.host, ep.port));
        let uri = format!("https://{authority}{}", req.path);
        let mut builder = http::Request::builder().method(req.method.as_str()).uri(&uri);
        for (name, value) in &req.headers {
            let value =
                http::HeaderValue::from_bytes(value).with_context(|| format!("header {name} has a bad value"))?;
            builder = builder.header(name.as_str(), value);
        }
        let http_req = builder.body(()).with_context(|| format!("can't send {} {uri} over HTTP/3", req.method))?;

        let (endpoint, conn) = self.quic_connect(ep, check).await?;
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(conn.clone())).await.context("HTTP/3 handshake")?;
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let max_body = self.h3_max_body;
        let exchange = async {
            let mut stream = send_request.send_request(http_req).await.context("sending the HTTP/3 request")?;
            if !req.body.is_empty() {
                stream.send_data(Bytes::from(req.body.clone())).await.context("sending the HTTP/3 body")?;
            }
            stream.finish().await.context("finishing the HTTP/3 request")?;
            let mut resp = stream.recv_response().await.context("HTTP/3 response")?;
            // Interim responses (1xx) are not part of the answer: wait for the final one.
            while resp.status().is_informational() {
                resp = stream.recv_response().await.context("HTTP/3 response")?;
            }
            let mut data = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await.context("reading the HTTP/3 body")? {
                while chunk.has_remaining() {
                    let piece = chunk.chunk();
                    data.extend_from_slice(piece);
                    let n = piece.len();
                    chunk.advance(n);
                }
                if data.len() > max_body {
                    bail!("HTTP/3 response body is larger than {}", size(max_body));
                }
            }
            let mut headers: Vec<(String, Vec<u8>)> =
                resp.headers().iter().map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec())).collect();
            // Trailers are rare; show them after the headers, as for HTTP/2.
            if let Ok(Some(trailers)) = stream.recv_trailers().await {
                headers.extend(trailers.iter().map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec())));
            }
            anyhow::Ok((resp.status().as_u16(), headers, data))
        };
        let outcome = tokio::time::timeout(self.read_timeout, exchange).await;
        // Close politely, then let the driver and the socket go.
        conn.close(0u32.into(), b"done");
        drive.abort();
        drop(endpoint);
        let (status, headers, data) = outcome.context("timed out waiting for the response")??;
        let raw = render_h3_response(status, &headers, &data);
        let end = pm_http::find_head_end(&raw)?.unwrap_or(raw.len());
        let head = pm_http::parse_response_head(&raw[..end])?;
        Ok(Response { raw, head, conn: AfterResponse::Done, elapsed: started.elapsed(), sent: None, cut_short: None })
    }

    /// Resolves the host, passes the addresses to `check`, and opens a QUIC connection to the first of exactly those
    /// addresses that answers. The server name is the endpoint's host.
    async fn quic_connect(
        &self,
        ep: &Endpoint,
        check: Option<AddrCheck<'_>>,
    ) -> Result<(quinn::Endpoint, quinn::Connection)> {
        let pinned = self.net.address_for(&ep.host).or(ep.pin);
        let addrs: Vec<SocketAddr> = match pinned {
            Some(ip) => vec![SocketAddr::new(ip, ep.port)],
            None => tokio::time::timeout(self.connect_timeout, tokio::net::lookup_host((ep.host.as_str(), ep.port)))
                .await
                .context("DNS lookup timed out")?
                .with_context(|| format!("cannot resolve {}", ep.host))?
                .collect(),
        };
        if addrs.is_empty() {
            bail!("{} did not resolve to any address", ep.host);
        }
        if let Some(check) = check {
            let ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
            check(&ips).map_err(|why| anyhow!("refused before connecting: {why}"))?;
        }

        let mut tls = (**self.net.tls_for(&ep.host, self.verify).unwrap_or_else(|| self.tls.clone()).config()).clone();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
            .context("the TLS settings can't be used for QUIC")?;
        let mut client = quinn::ClientConfig::new(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            self.read_timeout.try_into().unwrap_or_else(|_| quinn::VarInt::from_u32(60_000).into()),
        ));
        client.transport_config(Arc::new(transport));

        // Every checked address is tried at once and the first handshake that completes wins: an address that
        // never answers (UDP gives no refusal) must not hold up one that does. Only checked addresses are used.
        let mut attempts = tokio::task::JoinSet::new();
        for addr in addrs.into_iter().take(MAX_ADDRS) {
            let (client, host, timeout) = (client.clone(), ep.host.clone(), self.connect_timeout);
            attempts.spawn(async move {
                let bind: SocketAddr = if addr.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
                let endpoint = quinn::Endpoint::client(bind).context("opening a UDP socket").map_err(|e| (false, e))?;
                let connecting = endpoint
                    .connect_with(client, addr, &host)
                    .context("starting the QUIC connection")
                    .map_err(|e| (false, e))?;
                match tokio::time::timeout(timeout, connecting).await {
                    Ok(Ok(conn)) => Ok((endpoint, conn)),
                    Ok(Err(e)) => Err((false, anyhow!(e).context(format!("QUIC handshake with {addr}")))),
                    Err(_) => Err((true, anyhow!("QUIC handshake with {addr} timed out"))),
                }
            });
        }
        // When every address fails, report a real refusal (a certificate error, say) over a timeout: an address that
        // never answers, such as `::1` when the server listens on IPv4 only, tells the user nothing.
        let mut best: Option<(bool, anyhow::Error)> = None;
        while let Some(done) = attempts.join_next().await {
            let (timed_out, e) = match done {
                Ok(Ok(connected)) => return Ok(connected), // the others are dropped (aborted) with the set
                Ok(Err(failed)) => failed,
                Err(e) => (false, anyhow!(e)),
            };
            if best.as_ref().is_none_or(|(best_timed_out, _)| *best_timed_out && !timed_out) {
                best = Some((timed_out, e));
            }
        }
        Err(best.map(|(_, e)| e).unwrap_or_else(|| anyhow!("could not connect over QUIC")))
    }
}

fn size(bytes: usize) -> String {
    if bytes >= 1 << 20 { format!("{} MB", bytes >> 20) } else { format!("{bytes} bytes") }
}
