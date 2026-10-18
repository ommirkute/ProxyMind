//! The send engine: delivers raw HTTP/1.x requests to targets and reads
//! raw responses. Used by the proxy, by replays, and by agents.
//!
//! Requests are sent byte-for-byte as given (ADR-0002). Before connecting,
//! every resolved address is passed to a caller-supplied check, so the
//! policy gate can refuse hosts that resolve into denied networks.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use pm_http::{BodyKind, ChunkedScanner, ResponseHead};
use pm_tls::TlsConnector;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const READ_CHUNK: usize = 16 * 1024;

pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

/// Where to send a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    pub fn new(scheme: &str, host: &str, port: u16) -> Self {
        Self { scheme: scheme.to_ascii_lowercase(), host: host.to_string(), port }
    }
}

/// Checks resolved addresses before connecting. Return `Err(reason)` to refuse.
pub type AddrCheck<'a> = &'a (dyn Fn(&[IpAddr]) -> std::result::Result<(), String> + Sync);

/// A connection plus bytes read from it but not yet used.
pub struct Conn<S> {
    pub io: S,
    pub buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Conn<S> {
    pub fn new(io: S) -> Self {
        Self { io, buf: Vec::new() }
    }

    /// Reads more bytes into the buffer. Returns false at end of stream.
    async fn fill(&mut self) -> Result<bool> {
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let n = self.io.read(&mut self.buf[start..]).await;
        self.buf.truncate(start + *n.as_ref().unwrap_or(&0));
        Ok(n? > 0)
    }

    /// Reads one message head. `None` means the peer closed cleanly between messages.
    pub async fn read_head(&mut self) -> Result<Option<Vec<u8>>> {
        loop {
            if let Some(end) = pm_http::find_head_end(&self.buf)? {
                return Ok(Some(self.buf.drain(..end).collect()));
            }
            if !self.fill().await? {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                bail!("connection closed in the middle of a message head");
            }
        }
    }

    /// Reads a body exactly as framed on the wire (chunked bodies stay chunked).
    pub async fn read_body(&mut self, kind: BodyKind) -> Result<Vec<u8>> {
        match kind {
            BodyKind::None => Ok(Vec::new()),
            BodyKind::ContentLength(n) => {
                let n = usize::try_from(n)?;
                while self.buf.len() < n {
                    if !self.fill().await? {
                        bail!("connection closed before the body was complete");
                    }
                }
                Ok(self.buf.drain(..n).collect())
            }
            BodyKind::Chunked => {
                let mut scanner = ChunkedScanner::new();
                loop {
                    if let Some(len) = scanner.scan(&self.buf)? {
                        return Ok(self.buf.drain(..len).collect());
                    }
                    if !self.fill().await? {
                        bail!("connection closed in the middle of a chunked body");
                    }
                }
            }
            BodyKind::UntilClose => {
                while self.fill().await? {}
                Ok(std::mem::take(&mut self.buf))
            }
        }
    }
}

/// A response read from a server.
pub struct Response {
    /// Raw bytes, including any interim 1xx responses before the final one.
    pub raw: Vec<u8>,
    pub head: ResponseHead,
    pub conn: AfterResponse,
    /// Time from starting to connect until the full response was read.
    pub elapsed: Duration,
}

/// What happens to the connection after the response.
pub enum AfterResponse {
    Done,
    /// The body ran until the server closed the connection.
    ClosedAfterBody,
    /// `101 Switching Protocols`: the connection now carries another protocol.
    Upgraded(Conn<Box<dyn Io>>),
}

/// Sends requests to targets.
pub struct Sender {
    tls: TlsConnector,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl Sender {
    pub fn new(verify_upstream: bool) -> Result<Self> {
        Ok(Self {
            tls: TlsConnector::from(pm_tls::upstream_client_config(verify_upstream)?),
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(60),
        })
    }

    pub fn with_timeouts(mut self, connect: Duration, read: Duration) -> Self {
        self.connect_timeout = connect;
        self.read_timeout = read;
        self
    }

    /// Resolves, checks and connects.
    pub async fn connect(&self, ep: &Endpoint, check: Option<AddrCheck<'_>>) -> Result<Box<dyn Io>> {
        let addrs: Vec<SocketAddr> =
            tokio::time::timeout(self.connect_timeout, tokio::net::lookup_host((ep.host.as_str(), ep.port)))
                .await
                .context("DNS lookup timed out")?
                .with_context(|| format!("cannot resolve {}", ep.host))?
                .collect();
        if addrs.is_empty() {
            bail!("{} did not resolve to any address", ep.host);
        }
        if let Some(check) = check {
            let ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
            check(&ips).map_err(|why| anyhow!("refused before connecting: {why}"))?;
        }
        // Connect only to the addresses that were checked (no second lookup).
        let mut last_err = None;
        let mut tcp = None;
        for addr in &addrs {
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    tcp = Some(s);
                    break;
                }
                Ok(Err(e)) => last_err = Some(anyhow!(e)),
                Err(_) => last_err = Some(anyhow!("connect timed out")),
            }
        }
        let tcp = match tcp {
            Some(t) => t,
            None => return Err(last_err.unwrap_or_else(|| anyhow!("could not connect"))),
        };
        tcp.set_nodelay(true)?;
        if ep.scheme == "https" {
            let name = pm_tls::server_name(&ep.host)?;
            let tls = tokio::time::timeout(self.connect_timeout, self.tls.connect(name, tcp))
                .await
                .context("TLS handshake timed out")?
                .context("TLS handshake with server")?;
            Ok(Box::new(tls))
        } else {
            Ok(Box::new(tcp))
        }
    }

    /// Sends one raw request on a new connection and reads the response.
    /// `method` decides response framing (e.g. HEAD has no body).
    pub async fn send(
        &self,
        ep: &Endpoint,
        request: &[u8],
        method: &str,
        check: Option<AddrCheck<'_>>,
    ) -> Result<Response> {
        let started = Instant::now();
        let io = self.connect(ep, check).await?;
        let mut conn = Conn::new(io);
        conn.io.write_all(request).await?;
        conn.io.flush().await?;
        tokio::time::timeout(self.read_timeout, read_response(conn, method, started))
            .await
            .context("timed out waiting for the response")?
    }

    /// Sends several requests so they arrive at (almost) the same moment, for
    /// race-condition testing. Each request gets its own connection; all but
    /// the last byte of every request is sent first, then the final bytes are
    /// released together (the "last-byte sync" technique).
    pub async fn send_parallel(
        &self,
        ep: &Endpoint,
        requests: &[(Vec<u8>, String)],
        check: Option<AddrCheck<'_>>,
    ) -> Vec<Result<Response>> {
        let mut conns = Vec::with_capacity(requests.len());
        for (req, _) in requests {
            let r = async {
                let mut c = Conn::new(self.connect(ep, check).await?);
                if req.len() > 1 {
                    c.io.write_all(&req[..req.len() - 1]).await?;
                    c.io.flush().await?;
                }
                Ok::<_, anyhow::Error>(c)
            }
            .await;
            conns.push(r);
        }
        let started = Instant::now();
        // Release the last bytes as close together as possible.
        for (c, (req, _)) in conns.iter_mut().zip(requests) {
            if let Ok(c) = c
                && let Some(last) = req.last()
            {
                let _ = c.io.write_all(std::slice::from_ref(last)).await;
                let _ = c.io.flush().await;
            }
        }
        let read_timeout = self.read_timeout;
        let reads = conns.into_iter().zip(requests).map(|(c, (_, method))| {
            let method = method.clone();
            async move {
                let c = c?;
                tokio::time::timeout(read_timeout, read_response(c, &method, started))
                    .await
                    .context("timed out waiting for the response")?
            }
        });
        futures_join_all(reads).await
    }
}

/// Minimal join_all without pulling in the `futures` crate.
async fn futures_join_all<F>(futs: impl IntoIterator<Item = F>) -> Vec<F::Output>
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    let mut out = Vec::new();
    let handles: Vec<_> = futs.into_iter().map(tokio::spawn).collect();
    for h in handles {
        match h.await {
            Ok(v) => out.push(v),
            Err(e) => std::panic::resume_unwind(e.into_panic()),
        }
    }
    out
}

async fn read_response(mut conn: Conn<Box<dyn Io>>, method: &str, started: Instant) -> Result<Response> {
    let mut raw = Vec::new();
    loop {
        let head_raw = conn.read_head().await?.ok_or_else(|| anyhow!("server closed without responding"))?;
        let head = pm_http::parse_response_head(&head_raw)?;
        raw.extend_from_slice(&head_raw);
        if head.status == 101 {
            return Ok(Response { raw, head, conn: AfterResponse::Upgraded(conn), elapsed: started.elapsed() });
        }
        if (100..200).contains(&head.status) {
            continue;
        }
        let kind = head.body_kind(method)?;
        raw.extend_from_slice(&conn.read_body(kind).await?);
        let after = if kind == BodyKind::UntilClose { AfterResponse::ClosedAfterBody } else { AfterResponse::Done };
        return Ok(Response { raw, head, conn: after, elapsed: started.elapsed() });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Tiny server: answers each connection with the request line it saw.
    async fn echo_server() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut c = Conn::new(s);
                    if let Ok(Some(head)) = c.read_head().await {
                        let line = head.split(|&b| b == b'\r').next().unwrap_or_default().to_vec();
                        let mut resp =
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", line.len()).into_bytes();
                        resp.extend_from_slice(&line);
                        let _ = c.io.write_all(&resp).await;
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn sends_raw_and_reads_response() {
        let port = echo_server().await;
        let s = Sender::new(false).unwrap();
        let ep = Endpoint::new("http", "127.0.0.1", port);
        let r = s.send(&ep, b"GET /a%2e%2e HTTP/1.1\r\nHost: x\r\n\r\n", "GET", None).await.unwrap();
        assert_eq!(r.head.status, 200);
        assert!(r.raw.ends_with(b"GET /a%2e%2e HTTP/1.1"));
    }

    #[tokio::test]
    async fn address_check_runs_before_connecting() {
        let port = echo_server().await;
        let s = Sender::new(false).unwrap();
        let ep = Endpoint::new("http", "127.0.0.1", port);
        let deny = |_: &[IpAddr]| Err("loopback is denied".to_string());
        let err = s.send(&ep, b"GET / HTTP/1.1\r\n\r\n", "GET", Some(&deny)).await.err().unwrap();
        assert!(err.to_string().contains("loopback is denied"));
    }

    #[tokio::test]
    async fn parallel_sends_all_complete() {
        let port = echo_server().await;
        let s = Sender::new(false).unwrap();
        let ep = Endpoint::new("http", "127.0.0.1", port);
        let reqs: Vec<(Vec<u8>, String)> =
            (0..5).map(|i| (format!("GET /{i} HTTP/1.1\r\nHost: x\r\n\r\n").into_bytes(), "GET".into())).collect();
        let results = s.send_parallel(&ep, &reqs, None).await;
        assert_eq!(results.len(), 5);
        for (i, r) in results.into_iter().enumerate() {
            assert!(r.unwrap().raw.ends_with(format!("GET /{i} HTTP/1.1").as_bytes()));
        }
    }
}
