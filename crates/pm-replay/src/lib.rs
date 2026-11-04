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
mod pool;
pub mod race;

pub use h2send::StreamedResponse;
pub use net::{ClientCert, HostOverride, NetConfig, Network, ProxyKind, UpstreamProxy};

const READ_CHUNK: usize = 16 * 1024;
/// The most a connection buffers for one message (a hostile peer could
/// otherwise send an endless body and exhaust memory).
pub const MAX_MESSAGE: usize = 256 << 20;

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
        if start >= MAX_MESSAGE {
            bail!("message larger than {} MB", MAX_MESSAGE >> 20);
        }
        self.buf.resize(start + READ_CHUNK, 0);
        let n = match self.io.read(&mut self.buf[start..]).await {
            // Many TLS servers close without a close_notify alert. HTTP
            // framing (Content-Length, chunked) still tells a complete body
            // from a cut one, so treat it as the end of the stream.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(0),
            other => other,
        };
        self.buf.truncate(start + *n.as_ref().unwrap_or(&0));
        Ok(n? > 0)
    }

    async fn fill_within(&mut self, idle: Duration) -> Result<bool> {
        tokio::time::timeout(idle, self.fill())
            .await
            .map_err(|_| anyhow!("nothing arrived for {} s", idle.as_secs()))?
    }

    /// The next piece of a body, exactly as framed on the wire (chunked
    /// bodies stay chunked). `None` once the body is complete; waits at most
    /// `idle` for more bytes.
    pub async fn body_chunk(&mut self, b: &mut BodyStream, idle: Duration) -> Result<Option<Vec<u8>>> {
        if b.done {
            return Ok(None);
        }
        loop {
            match b.kind {
                BodyKind::None => {
                    b.done = true;
                    return Ok(None);
                }
                BodyKind::ContentLength(n) => {
                    if b.read >= n {
                        b.done = true;
                        return Ok(None);
                    }
                    if self.buf.is_empty() && !self.fill_within(idle).await? {
                        b.cut_short = Some(format!(
                            "the server closed the connection after {} of {n} announced body bytes",
                            b.read
                        ));
                        b.done = true;
                        return Ok(None);
                    }
                    let k = (self.buf.len() as u64).min(n - b.read) as usize;
                    b.read += k as u64;
                    return Ok(Some(self.buf.drain(..k).collect()));
                }
                BodyKind::UntilClose => {
                    if self.buf.is_empty() && !self.fill_within(idle).await? {
                        b.done = true;
                        return Ok(None);
                    }
                    b.read += self.buf.len() as u64;
                    return Ok(Some(std::mem::take(&mut self.buf)));
                }
                BodyKind::Chunked => {
                    if let Some(len) = b.scanner.scan(&self.buf)? {
                        b.done = true;
                        b.read += len as u64;
                        return Ok(Some(self.buf.drain(..len).collect()));
                    }
                    let n = b.scanner.scanned();
                    if n > 0 {
                        b.scanner.consume(n);
                        b.read += n as u64;
                        return Ok(Some(self.buf.drain(..n).collect()));
                    }
                    if !self.fill_within(idle).await? {
                        b.cut_short = Some("the server closed the connection in the middle of a chunked body".into());
                        b.done = true;
                        if self.buf.is_empty() {
                            return Ok(None);
                        }
                        b.read += self.buf.len() as u64;
                        return Ok(Some(std::mem::take(&mut self.buf)));
                    }
                }
            }
        }
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

/// Reading a body piece by piece (see [`Conn::body_chunk`]).
#[derive(Debug)]
pub struct BodyStream {
    kind: BodyKind,
    scanner: ChunkedScanner,
    done: bool,
    /// Body bytes read so far (as framed).
    pub read: u64,
    /// Set when the server closed before the body it announced was complete.
    pub cut_short: Option<String>,
}

impl BodyStream {
    pub fn new(kind: BodyKind) -> Self {
        Self { kind, scanner: ChunkedScanner::new(), done: false, read: 0, cut_short: None }
    }

    pub fn kind(&self) -> BodyKind {
        self.kind
    }

    /// The whole body arrived (nothing was cut short).
    pub fn is_complete(&self) -> bool {
        self.done && self.cut_short.is_none()
    }
}

/// A response whose head has arrived; read the body with [`Conn::body_chunk`].
pub struct ResponseStart {
    /// Interim (1xx) heads, then the final head, as received.
    pub raw_head: Vec<u8>,
    pub head: ResponseHead,
    pub body: BodyStream,
    /// The connection, positioned at the body (after `101`, at the new protocol).
    pub conn: Conn<Box<dyn Io>>,
    /// The bytes actually sent, when they differ from the request given.
    pub sent: Option<Vec<u8>>,
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
    /// Connections kept for the proxy (see [`Sender::send_start_pooled`]).
    pool: std::sync::Arc<pool::Pool>,
}

impl Sender {
    pub fn new(verify_upstream: bool) -> Result<Self> {
        Ok(Self {
            tls: TlsConnector::from(pm_tls::upstream_client_config(verify_upstream)?),
            verify: verify_upstream,
            net: Network::default(),
            connect_timeout: Duration::from_secs(15),
            read_timeout: Duration::from_secs(60),
            pool: std::sync::Arc::default(),
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
    fn wire_bytes<'a>(&self, ep: &Endpoint, request: &'a [u8]) -> Result<std::borrow::Cow<'a, [u8]>> {
        // Parallel sends speak HTTP/1.1: HTTP/2 text is downgraded for them.
        if pm_http::h2text::is_http2_request(request)
            && let Ok(r) = pm_http::h2text::h2_request(request)
        {
            let h1 = pm_http::h2text::downgrade_request(&r, &pm_core::authority(&ep.scheme, &ep.host, ep.port));
            return Ok(std::borrow::Cow::Owned(self.wire_bytes(ep, &h1)?.into_owned()));
        }
        match self.net.upstream_for(&ep.host) {
            Some(p) if p.kind == ProxyKind::Http && ep.scheme != "https" => {
                Ok(std::borrow::Cow::Owned(net::for_http_proxy(request, &ep.host, ep.port, &p)?))
            }
            _ => Ok(std::borrow::Cow::Borrowed(request)),
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
        let wire = self.wire_bytes(ep, request)?;
        let io = self.connect(ep, check).await?;
        let mut conn = Conn::new(io);
        conn.io.write_all(&wire).await?;
        conn.io.flush().await?;
        tokio::time::timeout(self.read_timeout, read_response(conn, method, started))
            .await
            .context("timed out waiting for the response")?
    }

    /// Sends one raw HTTP/1.1 request and returns as soon as the response
    /// head has arrived (waiting at most `head_timeout` for it), so the body
    /// can be passed on while it streams.
    pub async fn send_start(
        &self,
        ep: &Endpoint,
        request: &[u8],
        method: &str,
        check: Option<AddrCheck<'_>>,
        head_timeout: Duration,
    ) -> Result<ResponseStart> {
        if pm_http::h2text::is_http2_request(request) {
            bail!("streaming sends speak HTTP/1.1");
        }
        let wire = self.wire_bytes(ep, request)?;
        let sent = (wire.as_ref() != request).then(|| wire.to_vec());
        let io = self.connect(ep, check).await?;
        let mut conn = Conn::new(io);
        conn.io.write_all(&wire).await?;
        conn.io.flush().await?;
        let (raw_head, head) = read_heads(&mut conn, head_timeout).await?;
        let kind = if head.status == 101 { BodyKind::None } else { head.body_kind(method)? };
        Ok(ResponseStart { raw_head, head, body: BodyStream::new(kind), conn, sent })
    }

    /// The pool key for an endpoint: same target, same way of reaching it.
    pub(crate) fn pool_key(&self, ep: &Endpoint) -> String {
        format!(
            "{}|{}|{}|{:?}|{:?}",
            ep.scheme,
            ep.host.to_ascii_lowercase(),
            ep.port,
            self.net.upstream_for(&ep.host),
            self.net.address_for(&ep.host)
        )
    }

    /// Like [`Sender::send_start`], reusing a kept connection for requests
    /// that are safe to retry (GET, HEAD, OPTIONS). If the kept connection
    /// turns out closed before anything came back, it sends on a new one.
    /// For the proxy: hand the connection back with [`Sender::release`].
    pub async fn send_start_pooled(
        &self,
        ep: &Endpoint,
        request: &[u8],
        method: &str,
        check: Option<AddrCheck<'_>>,
        head_timeout: Duration,
    ) -> Result<ResponseStart> {
        if pm_http::h2text::is_http2_request(request) || !retry_safe(method) {
            return self.send_start(ep, request, method, check, head_timeout).await;
        }
        let key = self.pool_key(ep);
        let wire = self.wire_bytes(ep, request)?;
        let sent = (wire.as_ref() != request).then(|| wire.to_vec());
        while let Some(mut conn) = self.pool.take_h1(&key) {
            if !pool::alive(&mut conn).await {
                continue;
            }
            if conn.io.write_all(&wire).await.is_err() || conn.io.flush().await.is_err() {
                continue;
            }
            match read_heads(&mut conn, head_timeout).await {
                Ok((raw_head, head)) => {
                    let kind = if head.status == 101 { BodyKind::None } else { head.body_kind(method)? };
                    return Ok(ResponseStart { raw_head, head, body: BodyStream::new(kind), conn, sent });
                }
                // Closed before anything came back: the server dropped the
                // idle connection. Try the next one, then a new one.
                Err(_) if conn.buf.is_empty() => continue,
                Err(e) => return Err(e),
            }
        }
        self.send_start(ep, request, method, check, head_timeout).await
    }

    /// Keeps a connection whose response was read completely, for reuse.
    pub fn release(&self, ep: &Endpoint, conn: Conn<Box<dyn Io>>) {
        if conn.buf.is_empty() {
            self.pool.put_h1(self.pool_key(ep), conn);
        }
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
        let wire: Vec<Vec<u8>> =
            requests.iter().map(|(r, _)| self.wire_bytes(ep, r).map(|w| w.into_owned()).unwrap_or_default()).collect();
        let mut conns = Vec::with_capacity(requests.len());
        for req in &wire {
            let r = async {
                if req.is_empty() {
                    bail!("cannot send this request through the HTTP upstream proxy");
                }
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

/// Requests that may be sent again if a kept connection was closed.
pub(crate) fn retry_safe(method: &str) -> bool {
    matches!(method.to_ascii_uppercase().as_str(), "GET" | "HEAD" | "OPTIONS")
}

/// Reads interim (1xx) heads and the final head (or `101`).
pub(crate) async fn read_heads(
    conn: &mut Conn<Box<dyn Io>>,
    head_timeout: Duration,
) -> Result<(Vec<u8>, ResponseHead)> {
    let read = async {
        let mut raw = Vec::new();
        loop {
            let head_raw = conn.read_head().await?.ok_or_else(|| anyhow!("server closed without responding"))?;
            let head = pm_http::parse_response_head(&head_raw)?;
            raw.extend_from_slice(&head_raw);
            if head.status == 101 || !(100..200).contains(&head.status) {
                return anyhow::Ok((raw, head));
            }
        }
    };
    tokio::time::timeout(head_timeout, read)
        .await
        .map_err(|_| anyhow!("no response within {} s", head_timeout.as_secs()))?
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

    async fn pieces(kind: BodyKind, wire: &'static [&'static [u8]]) -> (Vec<u8>, BodyStream) {
        let (mut tx, rx) = tokio::io::duplex(64);
        tokio::spawn(async move {
            for w in wire {
                tx.write_all(w).await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
        let mut c = Conn::new(rx);
        let mut b = BodyStream::new(kind);
        let mut out = Vec::new();
        while let Some(p) = c.body_chunk(&mut b, Duration::from_secs(2)).await.unwrap() {
            out.extend_from_slice(&p);
        }
        (out, b)
    }

    #[tokio::test]
    async fn bodies_stream_piece_by_piece() {
        let (body, b) = pieces(BodyKind::ContentLength(10), &[b"01234", b"56789", b"NEXT"]).await;
        assert_eq!((body.as_slice(), b.read, b.cut_short.is_none()), (&b"0123456789"[..], 10, true));
        let (body, b) = pieces(BodyKind::Chunked, &[b"5\r\nhel", b"lo\r\n0\r\n\r\n", b"NEXT"]).await;
        assert_eq!(body, b"5\r\nhello\r\n0\r\n\r\n", "framing kept, the next message left alone");
        assert!(b.cut_short.is_none());
        let (body, b) = pieces(BodyKind::ContentLength(10), &[b"01234"]).await;
        assert_eq!(body, b"01234");
        assert!(b.cut_short.unwrap().contains("5 of 10"));
        let (body, _) = pieces(BodyKind::UntilClose, &[b"a", b"b"]).await;
        assert_eq!(body, b"ab");
        // Nothing for longer than the idle time: an error, not a hang.
        let (_tx, rx) = tokio::io::duplex(64);
        let mut c = Conn::new(rx);
        let mut b = BodyStream::new(BodyKind::Chunked);
        assert!(c.body_chunk(&mut b, Duration::from_millis(50)).await.is_err());
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
