//! Race-condition sends: many requests that reach the server at the same
//! moment.
//!
//! Over HTTP/2 this is the single-packet attack: every request's headers
//! and all but the last byte of its body go out first; then the final DATA
//! frames of all streams are written together, in one TCP packet. Servers
//! without HTTP/2 get last-byte sync over separate connections instead.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use pm_http::h2text::{h2_request, render_h2_request, render_h2_response};
use serde::Serialize;

use crate::{AddrCheck, AfterResponse, Endpoint, Response, Sender};

/// Most requests in one race.
pub const MAX_RACE: usize = 50;
/// Pause between sending the first parts and releasing the final frames,
/// so the first parts have certainly left (and been processed) first.
const SETTLE: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RaceMode {
    /// HTTP/2, final frames of all requests in one packet.
    SinglePacket,
    /// Separate connections, last bytes released together.
    LastByte,
}

pub struct RaceOutcome {
    pub mode: RaceMode,
    /// One result per request, in order. For single-packet races,
    /// `Response::sent` holds the request as sent (HTTP/2 text).
    pub results: Vec<Result<Response>>,
}

impl Sender {
    /// Sends `requests` (HTTP/1.x or HTTP/2 text) so they arrive together.
    /// `prefer_h2`: try the single-packet attack first.
    pub async fn send_race(
        &self,
        ep: &Endpoint,
        requests: &[(Vec<u8>, String)],
        prefer_h2: bool,
        check: Option<AddrCheck<'_>>,
    ) -> Result<RaceOutcome> {
        anyhow::ensure!(!requests.is_empty() && requests.len() <= MAX_RACE, "a race needs 1 to {MAX_RACE} requests");
        if prefer_h2 {
            let (io, is_h2) = self.connect_with(ep, check, true).await?;
            if is_h2 {
                let results = self.single_packet(ep, io, requests).await?;
                return Ok(RaceOutcome { mode: RaceMode::SinglePacket, results });
            }
        }
        // HTTP/1.1: requests written as HTTP/2 text are downgraded by
        // send_parallel (see wire_bytes).
        let results = self.send_parallel(ep, requests, check).await;
        Ok(RaceOutcome { mode: RaceMode::LastByte, results })
    }

    async fn single_packet(
        &self,
        ep: &Endpoint,
        io: Box<dyn crate::Io>,
        requests: &[(Vec<u8>, String)],
    ) -> Result<Vec<Result<Response>>> {
        let (client, mut connection) = h2::client::handshake(io).await.context("HTTP/2 handshake")?;
        let default_authority = pm_core::authority(&ep.scheme, &ep.host, ep.port);
        let read_timeout = self.read_timeout;

        // The connection is driven here, not on its own task: it only writes
        // while the code below is waiting, so everything queued in one go
        // leaves in one write.
        let work = async move {
            let mut client = client.ready().await.context("HTTP/2 connection")?;
            let mut pending = Vec::with_capacity(requests.len());
            for (raw, _) in requests {
                let mut req = h2_request(raw).map_err(|e| anyhow!("not a valid request: {e}"))?;
                req.headers.retain(|(n, _)| n != "content-length" || !req.body.is_empty());
                let authority = req.authority.clone().unwrap_or_else(|| default_authority.clone());
                let uri = format!("{}://{authority}{}", ep.scheme, req.path);
                let mut b = http::Request::builder().method(req.method.as_str()).uri(&uri);
                for (n, v) in &req.headers {
                    b = b.header(n.as_str(), http::HeaderValue::from_bytes(v).context("bad header value")?);
                }
                let http_req = b.body(()).with_context(|| format!("can't send {} {uri}", req.method))?;
                client = client.ready().await.context("HTTP/2 stream limit")?;
                // Never end the stream yet: the final frame is held back.
                let (resp, mut stream) = client.send_request(http_req, false).context("sending headers")?;
                let last = match req.body.split_last() {
                    Some((last, rest)) => {
                        if !rest.is_empty() {
                            stream.send_data(Bytes::copy_from_slice(rest), false).context("sending the body")?;
                        }
                        Bytes::copy_from_slice(&[*last])
                    }
                    None => Bytes::new(),
                };
                req.authority = Some(authority);
                pending.push((resp, stream, last, render_h2_request(&req)));
            }
            tokio::time::sleep(SETTLE).await;

            // Release: queue every final frame without yielding.
            let started = Instant::now();
            let mut waits = Vec::with_capacity(pending.len());
            for (resp, mut stream, last, sent) in pending {
                let r = stream.send_data(last, true).map(|()| resp).context("releasing the final frame");
                waits.push((r, sent));
            }

            let mut out = Vec::with_capacity(waits.len());
            let reads = waits.into_iter().map(|(r, sent)| async move {
                let resp = r?;
                let read = async {
                    let resp = resp.await.context("HTTP/2 response")?;
                    let elapsed = started.elapsed();
                    let (parts, mut body) = resp.into_parts();
                    let mut data = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.context("reading the body")?;
                        let _ = body.flow_control().release_capacity(chunk.len());
                        data.extend_from_slice(&chunk);
                    }
                    let headers: Vec<(String, Vec<u8>)> =
                        parts.headers.iter().map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec())).collect();
                    let raw = render_h2_response(parts.status.as_u16(), &headers, &data);
                    let end = pm_http::find_head_end(&raw)?.unwrap_or(raw.len());
                    let head = pm_http::parse_response_head(&raw[..end])?;
                    // `elapsed`: release to response headers, the useful timing in a race.
                    Ok(Response { raw, head, conn: AfterResponse::Done, elapsed, sent: Some(sent) })
                };
                tokio::time::timeout(read_timeout, read).await.context("timed out waiting for the response")?
            });
            for r in join_in_place(reads).await {
                out.push(r);
            }
            anyhow::Ok(out)
        };
        tokio::pin!(work);
        tokio::select! {
            r = &mut work => r,
            c = &mut connection => match c {
                // The connection ended first: finish whatever can still finish.
                Ok(()) => work.await,
                Err(e) => Err(anyhow!("HTTP/2 connection failed: {e}")),
            },
        }
    }
}

/// Polls futures together in the current task (no spawning, so the HTTP/2
/// connection driven alongside keeps making progress).
async fn join_in_place<F: std::future::Future>(futs: impl IntoIterator<Item = F>) -> Vec<F::Output> {
    let mut futs: Vec<_> = futs.into_iter().map(Box::pin).collect();
    let mut out: Vec<Option<F::Output>> = futs.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut done = true;
        for (f, slot) in futs.iter_mut().zip(out.iter_mut()) {
            if slot.is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => *slot = Some(v),
                    std::task::Poll::Pending => done = false,
                }
            }
        }
        if done { std::task::Poll::Ready(()) } else { std::task::Poll::Pending }
    })
    .await;
    out.into_iter().map(|o| o.expect("every future finished")).collect()
}
