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

mod h2send;
pub mod net;
pub mod race;

pub use net::{ClientCert, HostOverride, NetConfig, Network, ProxyKind, UpstreamProxy};

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

    /// Like [`Conn::read_body`], but a server that closes before the body it
    /// announced is complete still yields what it sent, with a note saying
    /// so (some servers send a wrong Content-Length).
    pub async fn read_body_lenient(&mut self, kind: BodyKind) -> Result<(Vec<u8>, Option<String>)> {
        match kind {
            BodyKind::ContentLength(n) => {
                let n = usize::try_from(n)?;
                while self.buf.len() < n {
                    if !self.fill().await? {
                        let got = self.buf.len();
                        let note = format!("the server closed the connection after {got} of {n} announced body bytes");
                        return Ok((std::mem::take(&mut self.buf), Some(note)));
                    }
                }
                Ok((self.buf.drain(..n).collect(), None))
            }
            BodyKind::Chunked => {
                let mut scanner = ChunkedScanner::new();
                loop {
                    if let Some(len) = scanner.scan(&self.buf)? {
                        return Ok((self.buf.drain(..len).collect(), None));
                    }
                    if !self.fill().await? {
                        let note = "the server closed the connection in the middle of a chunked body".to_string();
                        return Ok((std::mem::take(&mut self.buf), Some(note)));
                    }
                }
            }
            other => Ok((self.read_body(other).await?, None)),
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
    /// The bytes actually sent, when they differ from the request given
    /// (an HTTP/2 request downgraded to HTTP/1.1).
    pub sent: Option<Vec<u8>>,
    /// Set when the server closed before the body it announced was
    /// complete: `raw` holds what arrived.
    pub cut_short: Option<String>,
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
    verify: bool,
    net: Network,
    connect_timeout: Duration,
    read_timeout: Duration,
}

impl Sender {
    pub fn new(verify_upstream: bool) -> Result<Self> {
        Ok(Self {
            tls: TlsConnector::from(pm_tls::upstream_client_config(verify_upstream)?),
            verify: verify_upstream,
            net: Network::default(),
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(60),
        })
    }

    /// Uses shared, live network settings (upstream proxy, client certificates).
    pub fn with_network(mut self, net: Network) -> Self {
        self.net = net;
        self
    }

    pub fn network(&self) -> &Network {
        &self.net
    }

    /// Whether connections to this host go directly (no upstream proxy).
    pub fn goes_direct(&self, host: &str) -> bool {
        self.net.upstream_for(host).is_none()
    }

    /// The bytes to write for `request`: unchanged, except when plain HTTP
    /// goes through an HTTP proxy (absolute-form target, proxy login).
    fn wire_bytes<'a>(&self, ep: &Endpoint, request: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        // Parallel sends speak HTTP/1.1: HTTP/2 text is downgraded for them.
        if pm_http::h2text::is_http2_request(request)
            && let Ok(r) = pm_http::h2text::h2_request(request)
        {
            let h1 = pm_http::h2text::downgrade_request(&r, &pm_core::authority(&ep.scheme, &ep.host, ep.port));
            return std::borrow::Cow::Owned(self.wire_bytes(ep, &h1).into_owned());
        }
        match self.net.upstream_for(&ep.host) {
            Some(p) if p.kind == ProxyKind::Http && ep.scheme != "https" => {
                std::borrow::Cow::Owned(net::for_http_proxy(request, &ep.host, ep.port, &p))
            }
            _ => std::borrow::Cow::Borrowed(request),
        }
    }

    pub fn with_timeouts(mut self, connect: Duration, read: Duration) -> Self {
        self.connect_timeout = connect;
        self.read_timeout = read;
        self
    }

    /// Resolves, checks and connects, through the upstream proxy if one
    /// applies. With a check, names are always resolved here so the check
    /// sees the addresses in use (except with SOCKS5 remote DNS).
    pub async fn connect(&self, ep: &Endpoint, check: Option<AddrCheck<'_>>) -> Result<Box<dyn Io>> {
        Ok(self.connect_with(ep, check, false).await?.0)
    }

    /// A raw TCP connection to `host:port` (through the upstream proxy if one
    /// applies, with CONNECT for HTTP proxies), for tunnels that pass bytes
    /// through untouched.
    pub async fn connect_tunnel(&self, host: &str, port: u16, check: Option<AddrCheck<'_>>) -> Result<Box<dyn Io>> {
        Ok(self.connect_with(&Endpoint::new("tcp", host, port), check, false).await?.0)
    }

    /// Like [`Sender::connect`]; with `h2`, offers HTTP/2 over TLS (or assumes
    /// it for plain HTTP). Returns whether HTTP/2 is in use.
    pub(crate) async fn connect_with(
        &self,
        ep: &Endpoint,
        check: Option<AddrCheck<'_>>,
        h2: bool,
    ) -> Result<(Box<dyn Io>, bool)> {
        let upstream = self.net.upstream_for(&ep.host);
        // A hostname override replaces DNS (for SOCKS5 too: the proxy gets the address).
        let pinned = self.net.address_for(&ep.host);
        let remote_dns = pinned.is_none()
            && (upstream.as_ref().is_some_and(|u| u.kind == ProxyKind::Socks5 && u.remote_dns)
                || upstream.as_ref().is_some_and(|u| u.kind == ProxyKind::Http));
        // Direct connections and IP-based SOCKS need the target's addresses;
        // checks need them in every case.
        let addrs: Vec<SocketAddr> = if upstream.is_none() || check.is_some() || !remote_dns {
            let addrs: Vec<SocketAddr> = match pinned {
                Some(ip) => vec![SocketAddr::new(ip, ep.port)],
                None => {
                    tokio::time::timeout(self.connect_timeout, tokio::net::lookup_host((ep.host.as_str(), ep.port)))
                        .await
                        .context("DNS lookup timed out")?
                        .with_context(|| format!("cannot resolve {}", ep.host))?
                        .collect()
                }
            };
            if addrs.is_empty() {
                bail!("{} did not resolve to any address", ep.host);
            }
            if let Some(check) = check {
                let ips: Vec<IpAddr> = addrs.iter().map(SocketAddr::ip).collect();
                check(&ips).map_err(|why| anyhow!("refused before connecting: {why}"))?;
            }
            addrs
        } else {
            vec![]
        };
        let tcp = match &upstream {
            None => self.tcp_any(&addrs).await?,
            Some(p) => {
                let proxy_addrs: Vec<SocketAddr> =
                    tokio::time::timeout(self.connect_timeout, tokio::net::lookup_host((p.host.as_str(), p.port)))
                        .await
                        .context("DNS lookup of the upstream proxy timed out")?
                        .with_context(|| format!("cannot resolve the upstream proxy {}", p.host))?
                        .collect();
                // SOCKS5 with local DNS tries each checked address in turn,
                // like a direct connection; everything else makes one attempt.
                let targets: Vec<net::SocksTarget<'_>> = match p.kind {
                    ProxyKind::Socks5 if (!p.remote_dns || pinned.is_some()) && !addrs.is_empty() => {
                        addrs.iter().map(|a| net::SocksTarget::Ip(a.ip())).collect()
                    }
                    _ => vec![net::SocksTarget::Name(&ep.host)],
                };
                let mut last_err = None;
                let mut opened = None;
                for target in targets {
                    let attempt = async {
                        let mut tcp = self.tcp_any(&proxy_addrs).await.context("connecting to the upstream proxy")?;
                        match p.kind {
                            ProxyKind::Socks5 => net::socks5_connect(&mut tcp, p, target, ep.port).await?,
                            ProxyKind::Http if ep.scheme == "https" || ep.scheme == "tcp" => {
                                let host = pinned.map_or_else(|| ep.host.clone(), |ip| ip.to_string());
                                net::http_connect(&mut tcp, p, &host, ep.port).await?
                            }
                            ProxyKind::Http => {} // plain HTTP: absolute-form requests
                        }
                        anyhow::Ok(tcp)
                    };
                    match tokio::time::timeout(self.connect_timeout, attempt).await {
                        Ok(Ok(tcp)) => {
                            opened = Some(tcp);
                            break;
                        }
                        Ok(Err(e)) => last_err = Some(e),
                        Err(_) => last_err = Some(anyhow!("upstream proxy timed out")),
                    }
                }
                match opened {
                    Some(tcp) => tcp,
                    None => {
                        return Err(last_err.unwrap_or_else(|| anyhow!("could not connect through the upstream proxy")));
                    }
                }
            }
        };
        if ep.scheme == "https" {
            let name = pm_tls::server_name(&ep.host)?;
            let mut tls = self.net.tls_for(&ep.host, self.verify).unwrap_or_else(|| self.tls.clone());
            if h2 {
                let mut cfg = (**tls.config()).clone();
                cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
                tls = TlsConnector::from(std::sync::Arc::new(cfg));
            }
            let tls = tokio::time::timeout(self.connect_timeout, tls.connect(name, tcp))
                .await
                .context("TLS handshake timed out")?
                .context("TLS handshake with server")?;
            let is_h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
            Ok((Box::new(tls), is_h2))
        } else {
            Ok((Box::new(tcp), h2))
        }
    }

    /// Connects to the first address that answers.
    async fn tcp_any(&self, addrs: &[SocketAddr]) -> Result<TcpStream> {
        let mut last_err = None;
        for addr in addrs {
            match tokio::time::timeout(self.connect_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => {
                    s.set_nodelay(true)?;
                    return Ok(s);
                }
                Ok(Err(e)) => last_err = Some(anyhow!(e)),
                Err(_) => last_err = Some(anyhow!("connect timed out")),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("could not connect")))
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
        if pm_http::h2text::is_http2_request(request) {
            return self.send_h2(ep, request, method, check).await;
        }
        let started = Instant::now();
        let io = self.connect(ep, check).await?;
        let mut conn = Conn::new(io);
        conn.io.write_all(&self.wire_bytes(ep, request)).await?;
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
        let wire: Vec<Vec<u8>> = requests.iter().map(|(r, _)| self.wire_bytes(ep, r).into_owned()).collect();
        let mut conns = Vec::with_capacity(requests.len());
        for req in &wire {
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
        for (c, req) in conns.iter_mut().zip(&wire) {
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
            return Ok(Response {
                raw,
                head,
                conn: AfterResponse::Upgraded(conn),
                elapsed: started.elapsed(),
                sent: None,
                cut_short: None,
            });
        }
        if (100..200).contains(&head.status) {
            continue;
        }
        let kind = head.body_kind(method)?;
        let (body, cut_short) = conn.read_body_lenient(kind).await?;
        raw.extend_from_slice(&body);
        let after = if kind == BodyKind::UntilClose || cut_short.is_some() {
            AfterResponse::ClosedAfterBody
        } else {
            AfterResponse::Done
        };
        return Ok(Response { raw, head, conn: after, elapsed: started.elapsed(), sent: None, cut_short });
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
    async fn a_body_cut_short_is_kept_with_a_note() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let mut c = Conn::new(s);
            let _ = c.read_head().await;
            // Announces 10 bytes, sends 5, closes (a wrong Content-Length).
            let _ = c.io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello").await;
        });
        let s = Sender::new(false).unwrap();
        let ep = Endpoint::new("http", "127.0.0.1", port);
        let r = s.send(&ep, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "GET", None).await.unwrap();
        assert_eq!(r.head.status, 200);
        assert!(r.raw.ends_with(b"\r\n\r\nhello"));
        assert!(r.cut_short.as_deref().is_some_and(|n| n.contains("5 of 10")), "{:?}", r.cut_short);
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
