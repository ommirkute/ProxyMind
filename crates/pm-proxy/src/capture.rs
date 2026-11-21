//! Capture modes beyond the HTTP proxy port: SOCKS5 clients (RFC 1928) and transparent (redirected) traffic.
//!
//! After the SOCKS5 handshake a connection is treated like a CONNECT tunnel to `host:port`: TLS is intercepted with
//! ProxyMind's CA (HTTP/1.1 and HTTP/2), plain HTTP is read and recorded (WebSockets included), pass-through hosts
//! are tunnelled untouched, and the setup page answers for its reserved name. Streams that are not HTTP (SSH,
//! databases, anything the server speaks first in, a custom protocol inside TLS) are relayed byte for byte and, when
//! the recording settings allow, recorded as raw streams (roadmap 2.6, `docs/capture.md`). The relay never changes
//! a byte: the recorder gets a copy of each chunk after it has been passed on.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use parking_lot::RwLock;
use pm_http::socks5;
use pm_replay::{Conn, Endpoint, Io};
use pm_store::NewStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::stream_rec::StreamTap;
use crate::transparent::{Flow, OriginalDst, Sniff, classify, effective_orig, flow_for};
use crate::{Ctx, Proxy, Redirect, SelfAddr, setup_page};

/// How long a SOCKS5 client has to finish the handshake (greeting, login and request).
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a tunnel may stay silent before the proxy looks for a server that speaks first.
const SERVER_FIRST_WAIT: Duration = Duration::from_millis(500);
/// How long to wait for the rest of a first line that is still ambiguous.
const SNIFF_TIMEOUT: Duration = Duration::from_secs(5);

/// The login a SOCKS5 listener asks for, `(username, password)`; `None`: no login. Shared so it can change while
/// the listener runs.
pub type SocksLogin = Arc<RwLock<Option<(String, String)>>>;

/// What a listener's connections are.
#[derive(Clone)]
pub(crate) enum Accept {
    Http,
    Socks5(SocksLogin),
    Transparent(Arc<dyn OriginalDst>),
}

/// Non-HTTP streams relayed since start, recorded or not (pass-through tunnels count too).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RawStats {
    pub streams: u64,
    /// Bytes sent towards the target and towards the client, summed over finished streams.
    pub bytes_to_target: u64,
    pub bytes_to_client: u64,
}

#[derive(Default)]
pub(crate) struct RawCounters {
    streams: std::sync::atomic::AtomicU64,
    to_target: std::sync::atomic::AtomicU64,
    to_client: std::sync::atomic::AtomicU64,
}

impl RawCounters {
    pub(crate) fn snapshot(&self) -> RawStats {
        RawStats {
            streams: self.streams.load(Relaxed),
            bytes_to_target: self.to_target.load(Relaxed),
            bytes_to_client: self.to_client.load(Relaxed),
        }
    }
}

impl Proxy {
    /// Accepts SOCKS5 clients until the task is cancelled. `login`: when set, clients must log in with it.
    pub async fn run_socks5(
        self: Arc<Self>,
        listener: TcpListener,
        redirect: Arc<RwLock<Option<Redirect>>>,
        login: SocksLogin,
    ) -> Result<()> {
        self.run_mode(listener, Accept::Socks5(login), redirect).await
    }

    /// Accepts connections that the operating system redirected here, using `provider` to find where each was going.
    /// Connections that were not redirected are handled like ordinary proxy connections.
    pub async fn run_transparent(
        self: Arc<Self>,
        listener: TcpListener,
        redirect: Arc<RwLock<Option<Redirect>>>,
        provider: Arc<dyn OriginalDst>,
    ) -> Result<()> {
        self.run_mode(listener, Accept::Transparent(provider), redirect).await
    }

    /// Non-HTTP streams relayed (see [`RawStats`]).
    pub fn raw_stats(&self) -> RawStats {
        self.raw.snapshot()
    }

    pub(crate) async fn run_mode(
        self: Arc<Self>,
        listener: TcpListener,
        mode: Accept,
        redirect: Arc<RwLock<Option<Redirect>>>,
    ) -> Result<()> {
        loop {
            let (tcp, peer) = listener.accept().await?;
            let this = self.clone();
            let mode = mode.clone();
            let ctx = Ctx {
                me: SelfAddr::of(&tcp),
                peer: Some(peer.ip().to_canonical()),
                redirect: redirect.read().clone(),
                ..Ctx::default()
            };
            tokio::spawn(async move {
                let result = match mode {
                    Accept::Http => this.handle_client(tcp, ctx).await,
                    Accept::Socks5(login) => this.handle_socks5(tcp, ctx, login).await,
                    Accept::Transparent(p) => this.handle_transparent(tcp, ctx, p).await,
                };
                if let Err(e) = result {
                    tracing::debug!(%peer, error = %e, "client connection ended with error");
                }
            });
        }
    }

    async fn handle_transparent(
        self: Arc<Self>,
        tcp: TcpStream,
        ctx: Ctx,
        provider: Arc<dyn OriginalDst>,
    ) -> Result<()> {
        let Some(orig) = effective_orig(provider.original_dst(&tcp), ctx.me) else {
            // Not redirected: whoever connected, they talk to the proxy directly.
            return self.handle_client(tcp, ctx).await;
        };
        tcp.set_nodelay(true)?;
        self.serve_stream(tcp, orig.ip().to_string(), orig.port(), ctx).await
    }

    async fn handle_socks5(self: Arc<Self>, mut tcp: TcpStream, ctx: Ctx, login: SocksLogin) -> Result<()> {
        tcp.set_nodelay(true)?;
        let required = login.read().clone();
        let handshake = socks5_handshake(&mut tcp, required.as_ref());
        let outcome = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| anyhow::anyhow!("SOCKS5 handshake timed out"))??;
        let request = match outcome {
            Handshake::Connect(r) => r,
            Handshake::Refused(why) => {
                tracing::debug!(peer = ?ctx.peer, "SOCKS5 client refused: {why}");
                return Ok(());
            }
        };
        let (host, port) = (request.address.host(), request.port);
        // A host that is tunnelled untouched is reached first, so the client hears whether that worked.
        if !host.parse::<IpAddr>().is_ok() && self.passthrough(&host) {
            return match self.connect_raw(&host, port, &ctx).await {
                Ok(up) => {
                    tcp.write_all(&socks5::reply(socks5::REP_SUCCEEDED, None)).await?;
                    // Pass-through hosts are tunnelled untouched and not recorded.
                    self.relay_raw(tcp, up, Vec::new(), Vec::new(), Raw::plain(&host, port), &ctx, false).await
                }
                Err(e) => {
                    let _ = tcp.write_all(&socks5::reply(reply_code(&e), None)).await;
                    tracing::debug!(host, port, "SOCKS5 pass-through connect failed: {e:#}");
                    Ok(())
                }
            };
        }
        tcp.write_all(&socks5::reply(socks5::REP_SUCCEEDED, None)).await?;
        self.serve_stream(tcp, host, port, ctx).await
    }

    /// A stream whose target is known (a SOCKS5 CONNECT or a redirected connection): intercept HTTP and TLS, relay
    /// anything else.
    pub(crate) async fn serve_stream(
        self: Arc<Self>,
        tcp: TcpStream,
        host: String,
        port: u16,
        mut ctx: Ctx,
    ) -> Result<()> {
        let addressed = host.parse::<IpAddr>().ok();
        if let Some(ip) = addressed {
            ctx.orig = Some(SocketAddr::new(ip, port));
            ctx.pin = Some(ip);
        }
        self.serve_flow(tcp, host, port, ctx, addressed.is_some()).await
    }

    /// Decides what a stream to `host:port` is from its first bytes and serves it. `addressed`: the target is an IP
    /// address the client dialled (see [`flow_for`]); a CONNECT tunnel names its target, so it is `false` there.
    pub(crate) async fn serve_flow(
        self: Arc<Self>,
        tcp: TcpStream,
        host: String,
        port: u16,
        ctx: Ctx,
        addressed: bool,
    ) -> Result<()> {
        let idle = match self.first_bytes(&tcp, &host, port, &ctx).await? {
            First::Closed => return Ok(()),
            First::ServerFirst { up, bytes } => {
                return self.relay_raw(tcp, up, Vec::new(), bytes, Raw::plain(&host, port), &ctx, true).await;
            }
            First::Client(idle) => idle,
        };
        let sniff = sniff_client(&tcp).await;
        match flow_for(addressed, sniff) {
            // Boxed: `handle_client` reaches this function again for a CONNECT.
            Flow::Proxy => Box::pin(self.handle_client(tcp, ctx)).await,
            Flow::InterceptTls => self.intercept_tunnel(tcp, host, port, ctx, true).await,
            Flow::InterceptHttp => self.intercept_tunnel(tcp, host, port, ctx, false).await,
            Flow::Raw => {
                let up = match idle {
                    Some(up) => up,
                    None => self.connect_raw(&host, port, &ctx).await?,
                };
                self.relay_raw(tcp, up, Vec::new(), Vec::new(), Raw::plain(&host, port), &ctx, true).await
            }
        }
    }

    /// Inside a tunnel to `host:port`: TLS is accepted with a certificate for the host (HTTP/2 when the client asks
    /// for it; a protocol that is not HTTP is relayed as a raw stream, see [`Proxy::serve_tls_client`]), anything
    /// else is read as HTTP/1.x.
    pub(crate) async fn intercept_tunnel(
        self: Arc<Self>,
        tcp: TcpStream,
        host: String,
        port: u16,
        ctx: Ctx,
        tls: bool,
    ) -> Result<()> {
        if !tls {
            return self.serve_http(Conn::new(tcp), "http", Some((host, port)), None, ctx).await;
        }
        let start =
            pm_tls::LazyConfigAcceptor::new(pm_tls::Acceptor::default(), tcp).await.context("reading the TLS hello")?;
        let tunnel = Some((host.clone(), port));
        self.serve_tls_client(start, host.clone(), (host, port), tunnel, ctx).await
    }

    /// A TLS client whose hello has been read: `cert_host` names the certificate, `target` is where the stream is
    /// going (a redirect replaces it) and `tunnel` is passed to the HTTP/1.x reader.
    ///
    /// - Offered ALPN values other than `h2` and `http/1.1` mean a protocol that is not HTTP: the client's values
    ///   are offered to the target, the one it chooses is offered back, and the decrypted stream is relayed raw.
    /// - `h2` negotiated: HTTP/2 as before.
    /// - Otherwise the first decrypted bytes decide: an HTTP/1.x request line is served as HTTP, anything else is a
    ///   raw stream inside TLS (a server that speaks first is found by waiting 500 ms for the client, as for plain
    ///   streams).
    pub(crate) async fn serve_tls_client(
        self: Arc<Self>,
        start: pm_tls::StartHandshake<TcpStream>,
        cert_host: String,
        target: (String, u16),
        tunnel: Option<(String, u16)>,
        ctx: Ctx,
    ) -> Result<()> {
        let (host, port) = ctx.redirect.as_ref().map_or(target, |r| (r.host.clone(), r.port));
        let custom: Vec<Vec<u8>> = start
            .client_hello()
            .alpn()
            .map(|offered| {
                offered.filter(|a| *a != b"h2".as_slice() && *a != b"http/1.1".as_slice()).map(<[u8]>::to_vec).collect()
            })
            .unwrap_or_default();
        if !custom.is_empty() {
            let (up, chosen) = self.connect_raw_tls(&host, port, &ctx, &custom).await?;
            let mut cfg = (*self.ca.server_config(&cert_host)?).clone();
            cfg.alpn_protocols = chosen.iter().cloned().collect();
            let tls = start.into_stream(Arc::new(cfg)).await.context("TLS handshake with client")?;
            let raw = Raw::tls(&host, port, chosen.as_deref());
            return self.relay_raw(tls, up, Vec::new(), Vec::new(), raw, &ctx, true).await;
        }
        let mut tls = start.into_stream(self.tls_config(&cert_host)?).await.context("TLS handshake with client")?;
        let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        if alpn.as_deref() == Some(b"h2") {
            return self.serve_h2(tls, host, port, ctx).await;
        }
        let offered: Vec<Vec<u8>> = alpn.iter().cloned().collect();
        let (first, idle) = match self.first_tls_bytes(&mut tls, &host, port, &ctx, &offered).await? {
            TlsFirst::Closed => return Ok(()),
            TlsFirst::ServerFirst { up, bytes } => {
                let raw = Raw::tls(&host, port, alpn.as_deref());
                return self.relay_raw(tls, up, Vec::new(), bytes, raw, &ctx, true).await;
            }
            TlsFirst::Client { bytes, idle } => (bytes, idle),
        };
        let first = match sniff_bytes(&mut tls, first).await {
            Some(v) => v,
            None => return Ok(()),
        };
        if first.sniff == Sniff::Http {
            let client = Conn { io: tls, buf: first.bytes };
            return self.serve_http(client, "https", tunnel, None, ctx).await;
        }
        // Not HTTP inside TLS: the decrypted bytes are relayed to a TLS connection to the target.
        let up = match idle {
            Some(up) => up,
            None => self.connect_raw_tls(&host, port, &ctx, &offered).await?.0,
        };
        let raw = Raw::tls(&host, port, alpn.as_deref());
        self.relay_raw(tls, up, first.bytes, Vec::new(), raw, &ctx, true).await
    }

    /// Waits for the first decrypted bytes of a TLS client. Like [`Proxy::first_bytes`]: a client that stays silent
    /// for 500 ms may be waiting for the server to speak (IMAPS, SMTPS), so the target is connected and, if it
    /// speaks first, the stream is relayed as it is.
    async fn first_tls_bytes<S>(
        &self,
        tls: &mut S,
        host: &str,
        port: u16,
        ctx: &Ctx,
        alpn: &[Vec<u8>],
    ) -> Result<TlsFirst>
    where
        S: AsyncRead + Unpin,
    {
        let mut buf = vec![0u8; 16 * 1024];
        match tokio::time::timeout(SERVER_FIRST_WAIT, tls.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Ok(TlsFirst::Closed),
            Ok(Ok(n)) => {
                buf.truncate(n);
                return Ok(TlsFirst::Client { bytes: buf, idle: None });
            }
            Err(_) => {}
        }
        let client_bytes = |r: std::io::Result<usize>, mut b: Vec<u8>, up: Option<Box<dyn Io>>| match r {
            Ok(n) if n > 0 => {
                b.truncate(n);
                TlsFirst::Client { bytes: b, idle: up }
            }
            _ => TlsFirst::Closed,
        };
        if setup_page::is_setup_host(host) {
            let r = tls.read(&mut buf).await;
            return Ok(client_bytes(r, buf, None));
        }
        let mut quiet = vec![0u8; 16 * 1024];
        let connect = self.connect_raw_tls(host, port, ctx, alpn);
        tokio::pin!(connect);
        let mut up = tokio::select! {
            r = tls.read(&mut quiet) => return Ok(client_bytes(r, quiet, None)),
            r = &mut connect => match r {
                Ok((up, _)) => up,
                Err(e) => {
                    // Not reachable: let the client speak, so HTTP gets its 502 page and the exchange is recorded.
                    tracing::debug!(host, port, "could not connect while waiting for the client: {e:#}");
                    let r = tls.read(&mut buf).await;
                    return Ok(client_bytes(r, buf, None));
                }
            },
        };
        let mut from_server = vec![0u8; 16 * 1024];
        tokio::select! {
            r = tls.read(&mut quiet) => Ok(client_bytes(r, quiet, Some(up))),
            n = up.read(&mut from_server) => match n {
                Ok(n) if n > 0 => { from_server.truncate(n); Ok(TlsFirst::ServerFirst { up, bytes: from_server }) }
                _ => {
                    let r = tls.read(&mut buf).await;
                    Ok(client_bytes(r, buf, None))
                }
            },
        }
    }

    /// Waits for the first bytes of a tunnel. Clients of HTTP and TLS speak first, so a tunnel that stays quiet may
    /// be a protocol where the server speaks first (SSH, SMTP, databases): after a short wait the target is
    /// connected, and if it speaks before the client does, the stream is relayed as it is. A client that speaks
    /// first at any time (a browser's idle pre-connection) is still read as usual.
    async fn first_bytes(&self, tcp: &TcpStream, host: &str, port: u16, ctx: &Ctx) -> Result<First> {
        let mut b = [0u8; 1];
        match tokio::time::timeout(SERVER_FIRST_WAIT, tcp.peek(&mut b)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return Ok(First::Closed),
            Ok(Ok(_)) => return Ok(First::Client(None)),
            Err(_) => {}
        }
        if setup_page::is_setup_host(host) {
            return Ok(wait_for_client(tcp).await);
        }
        let connect = self.connect_raw(host, port, ctx);
        tokio::pin!(connect);
        let mut up = tokio::select! {
            r = tcp.peek(&mut b) => return Ok(match r { Ok(0) | Err(_) => First::Closed, Ok(_) => First::Client(None) }),
            r = &mut connect => match r {
                Ok(up) => up,
                Err(e) => {
                    // Not reachable: let the client speak, so HTTP gets its 502 page and the exchange is recorded.
                    tracing::debug!(host, port, "could not connect while waiting for the client: {e:#}");
                    return Ok(wait_for_client(tcp).await);
                }
            },
        };
        let mut buf = vec![0u8; 16 * 1024];
        tokio::select! {
            r = tcp.peek(&mut b) => Ok(match r { Ok(0) | Err(_) => First::Closed, Ok(_) => First::Client(Some(up)) }),
            n = up.read(&mut buf) => match n {
                Ok(n) if n > 0 => { buf.truncate(n); Ok(First::ServerFirst { up, bytes: buf }) }
                _ => Ok(wait_for_client(tcp).await),
            },
        }
    }

    /// A raw connection to the stream's target (through the upstream rules), refusing ProxyMind's own address.
    async fn connect_raw(&self, host: &str, port: u16, ctx: &Ctx) -> Result<Box<dyn Io>> {
        let (host, port) = ctx.redirect.as_ref().map_or((host, port), |r| (r.host.as_str(), r.port));
        let ep = Endpoint::new("tcp", host, port).with_pin(ctx.pin());
        let guard = self.loop_guard(&ctx.me, host, port);
        let check = guard.as_ref().map(|g| g as pm_replay::AddrCheck<'_>);
        self.sender.connect_tunnel_to(&ep, check).await
    }

    /// A TLS connection to the stream's target offering exactly `alpn`, through the upstream rules; returns the
    /// protocol the target chose.
    async fn connect_raw_tls(
        &self,
        host: &str,
        port: u16,
        ctx: &Ctx,
        alpn: &[Vec<u8>],
    ) -> Result<(Box<dyn Io>, Option<Vec<u8>>)> {
        let (host, port) = ctx.redirect.as_ref().map_or((host, port), |r| (r.host.as_str(), r.port));
        let ep = Endpoint::new("https", host, port).with_pin(ctx.pin());
        let guard = self.loop_guard(&ctx.me, host, port);
        let check = guard.as_ref().map(|g| g as pm_replay::AddrCheck<'_>);
        self.sender.connect_stream(&ep, alpn, check).await
    }

    /// Passes bytes both ways, unchanged, and counts the stream. With `record`, the recording settings decide
    /// whether a copy goes into the project as a raw stream (see [`StreamTap`]); a pass-through tunnel is not
    /// recorded. `to_server` and `from_server` are bytes already read from one side that go first.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn relay_raw<C>(
        &self,
        mut client: C,
        mut up: Box<dyn Io>,
        to_server: Vec<u8>,
        from_server: Vec<u8>,
        raw: Raw<'_>,
        ctx: &Ctx,
        record: bool,
    ) -> Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
    {
        self.raw.streams.fetch_add(1, Relaxed);
        tracing::info!(host = raw.host, port = raw.port, tls = raw.tls, record, "relaying a non-HTTP stream");
        let started = Instant::now();
        let tap = StreamTap::open(
            &self.recorder,
            record,
            NewStream {
                start_ms: pm_core::now_ms(),
                host: raw.host.to_string(),
                port: raw.port,
                client_addr: ctx.peer.map(|ip| ip.to_string()),
                tls: raw.tls,
                sni: raw.tls.then(|| raw.host.to_string()),
                alpn: raw.alpn.clone(),
                source: "proxy".into(),
                actor_id: String::new(),
                replay_of: None,
            },
        );
        let (ended, error) = if record {
            match pump(&mut client, &mut up, &to_server, &from_server, &tap).await {
                Ok(by) => (by, None),
                Err(e) => ("error", Some(e.to_string())),
            }
        } else {
            // Untouched tunnel: nothing is recorded, so the plain copy loop is enough.
            let result = async {
                if !from_server.is_empty() {
                    client.write_all(&from_server).await?;
                    self.raw.to_client.fetch_add(from_server.len() as u64, Relaxed);
                }
                tokio::io::copy_bidirectional(&mut client, &mut up).await
            }
            .await;
            match result {
                Ok((a, b)) => {
                    self.raw.to_target.fetch_add(a, Relaxed);
                    self.raw.to_client.fetch_add(b, Relaxed);
                    ("closed", None)
                }
                Err(e) => ("error", Some(e.to_string())),
            }
        };
        let (up_bytes, down_bytes) = tap.totals();
        if record {
            self.raw.to_target.fetch_add(up_bytes, Relaxed);
            self.raw.to_client.fetch_add(down_bytes, Relaxed);
        }
        tap.finish(ended, error.clone());
        tracing::debug!(
            host = raw.host,
            port = raw.port,
            to_server = up_bytes,
            to_client = down_bytes,
            ended,
            ms = started.elapsed().as_millis() as u64,
            "raw stream finished"
        );
        Ok(())
    }
}

/// Where a raw stream goes and how: for the stream's row.
pub(crate) struct Raw<'a> {
    host: &'a str,
    port: u16,
    tls: bool,
    alpn: Option<String>,
}

impl<'a> Raw<'a> {
    pub(crate) fn plain(host: &'a str, port: u16) -> Self {
        Self { host, port, tls: false, alpn: None }
    }

    pub(crate) fn tls(host: &'a str, port: u16, alpn: Option<&[u8]>) -> Self {
        Self { host, port, tls: true, alpn: alpn.map(|a| String::from_utf8_lossy(a).into_owned()) }
    }
}

/// Moves bytes both ways until both sides are done or one fails, recording each chunk after it was written to the
/// other side. `to_server` and `from_server` are written first (bytes that were read while sniffing). Returns how
/// the stream ended: `client_closed` or `server_closed` (whichever side finished first).
async fn pump<C>(
    client: &mut C,
    up: &mut Box<dyn Io>,
    to_server: &[u8],
    from_server: &[u8],
    tap: &StreamTap,
) -> std::io::Result<&'static str>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    if !from_server.is_empty() {
        client.write_all(from_server).await?;
        client.flush().await?;
        tap.chunk(false, from_server);
    }
    if !to_server.is_empty() {
        up.write_all(to_server).await?;
        up.flush().await?;
        tap.chunk(true, to_server);
    }
    let first = AtomicU8::new(0);
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = tokio::io::split(up);
    tokio::try_join!(half(&mut cr, &mut uw, true, tap, &first), half(&mut ur, &mut cw, false, tap, &first))?;
    Ok(if first.load(Relaxed) == 2 { "server_closed" } else { "client_closed" })
}

/// One direction of [`pump`]: reads, writes the same bytes to the other side, then hands them to the tap. At end of
/// stream the other side's write half is shut down (a half-close is passed on).
async fn half<R, W>(r: &mut R, w: &mut W, to_server: bool, tap: &StreamTap, first: &AtomicU8) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(n) => n,
            // TLS peers that close without a close_notify alert.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e),
        };
        if n == 0 {
            let _ = first.compare_exchange(0, if to_server { 1 } else { 2 }, Relaxed, Relaxed);
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        w.flush().await?;
        // No await between the write and this call: chunks reach the recorder in the order they were relayed.
        tap.chunk(to_server, &buf[..n]);
    }
}

/// The result of [`Proxy::first_tls_bytes`].
enum TlsFirst {
    Closed,
    /// The client sent these decrypted bytes (a connection to the target made while waiting, if any, is kept).
    Client {
        bytes: Vec<u8>,
        idle: Option<Box<dyn Io>>,
    },
    /// The server spoke first.
    ServerFirst {
        up: Box<dyn Io>,
        bytes: Vec<u8>,
    },
}

/// What the first decrypted bytes of a TLS client look like, with those bytes (and any read to decide).
struct Sniffed {
    sniff: Sniff,
    bytes: Vec<u8>,
}

/// Classifies `bytes` (reading more while a first line is still ambiguous); `None` when the client went away.
async fn sniff_bytes<S: AsyncRead + Unpin>(tls: &mut S, mut bytes: Vec<u8>) -> Option<Sniffed> {
    let deadline = Instant::now() + SNIFF_TIMEOUT;
    loop {
        if let Some(sniff) = classify(&bytes[..bytes.len().min(32)]) {
            return Some(Sniffed { sniff, bytes });
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let mut more = vec![0u8; 4096];
        match tokio::time::timeout(left, tls.read(&mut more)).await {
            Ok(Ok(n)) if n > 0 => bytes.extend_from_slice(&more[..n]),
            Ok(Ok(_)) | Ok(Err(_)) => return None,
            // Still ambiguous after the wait: not something to read as HTTP.
            Err(_) => return Some(Sniffed { sniff: Sniff::Other, bytes }),
        }
    }
}

/// Waits for the client's first byte, however long that takes.
async fn wait_for_client(tcp: &TcpStream) -> First {
    let mut b = [0u8; 1];
    match tcp.peek(&mut b).await {
        Ok(0) | Err(_) => First::Closed,
        Ok(_) => First::Client(None),
    }
}

#[allow(clippy::enum_variant_names)]
enum First {
    Closed,
    /// The client sent something (the connection to the target made while waiting, if any, is kept for a raw relay).
    Client(Option<Box<dyn Io>>),
    /// The server spoke first.
    ServerFirst {
        up: Box<dyn Io>,
        bytes: Vec<u8>,
    },
}

/// Looks at the first bytes the client sent (it has sent at least one) without consuming them.
async fn sniff_client(tcp: &TcpStream) -> Sniff {
    let mut buf = [0u8; 32];
    let deadline = Instant::now() + SNIFF_TIMEOUT;
    let mut seen = 0;
    loop {
        let Ok(n) = tcp.peek(&mut buf).await else { return Sniff::Other };
        if let Some(s) = classify(&buf[..n]) {
            return s;
        }
        if n == 0 || Instant::now() > deadline {
            return Sniff::Other;
        }
        if n == seen {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        seen = n;
    }
}

/// The SOCKS5 reply code for a failed connection.
fn reply_code(e: &anyhow::Error) -> u8 {
    let text = format!("{e:#}");
    if text.contains("refused before connecting") || text.contains("ProxyMind itself") {
        return socks5::REP_NOT_ALLOWED;
    }
    let io_kind = e.chain().find_map(|c| c.downcast_ref::<std::io::Error>()).map(std::io::Error::kind);
    match io_kind {
        Some(std::io::ErrorKind::ConnectionRefused) => socks5::REP_CONNECTION_REFUSED,
        Some(std::io::ErrorKind::NetworkUnreachable) => socks5::REP_NETWORK_UNREACHABLE,
        _ => socks5::REP_HOST_UNREACHABLE,
    }
}

/// How a SOCKS5 handshake ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Handshake {
    /// The client asked to CONNECT; no reply has been sent yet.
    Connect(socks5::Request),
    /// The client was turned away (the reply is sent); the reason is for the log.
    Refused(String),
}

/// One handshake message, read a byte at a time so nothing after it (the tunnel's first bytes) is consumed.
async fn read_msg<S, T>(
    s: &mut S,
    parse: impl Fn(&[u8]) -> std::result::Result<Option<(T, usize)>, socks5::Error>,
) -> Result<std::result::Result<T, socks5::Error>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    loop {
        match parse(&buf) {
            Ok(Some((v, _))) => return Ok(Ok(v)),
            Ok(None) => {}
            Err(e) => return Ok(Err(e)),
        }
        if buf.len() >= socks5::MAX_MESSAGE {
            bail!("oversized SOCKS5 message");
        }
        let mut b = [0u8; 1];
        if s.read(&mut b).await? == 0 {
            bail!("the client closed the connection during the SOCKS5 handshake");
        }
        buf.push(b[0]);
    }
}

/// Runs the server side of the SOCKS5 handshake: greeting, login when `login` is set, and the request. Only CONNECT
/// is served; BIND, UDP ASSOCIATE and unknown commands get "command not supported" and unknown address types get
/// "address type not supported". On `Connect` the caller sends the reply.
pub(crate) async fn socks5_handshake<S>(s: &mut S, login: Option<&(String, String)>) -> Result<Handshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let greeting = match read_msg(s, socks5::parse_greeting).await? {
        Ok(g) => g,
        Err(e) => return Ok(Handshake::Refused(e.to_string())),
    };
    let method = socks5::choose_method(&greeting.methods, login.is_some());
    s.write_all(&socks5::method_reply(method)).await?;
    if method == socks5::METHOD_NONE_ACCEPTABLE {
        return Ok(Handshake::Refused("no acceptable login method".into()));
    }
    if let (socks5::METHOD_PASSWORD, Some((user, pass))) = (method, login) {
        let creds = match read_msg(s, socks5::parse_auth).await? {
            Ok(c) => c,
            Err(e) => {
                let _ = s.write_all(&socks5::auth_reply(false)).await;
                return Ok(Handshake::Refused(e.to_string()));
            }
        };
        let ok = socks5::credentials_match(&creds, user, pass);
        s.write_all(&socks5::auth_reply(ok)).await?;
        if !ok {
            // The credentials themselves are never logged.
            return Ok(Handshake::Refused("wrong username or password".into()));
        }
    }
    let request = match read_msg(s, socks5::parse_request).await? {
        Ok(r) => r,
        Err(socks5::Error::BadAddressType(t)) => {
            s.write_all(&socks5::reply(socks5::REP_ADDRESS_TYPE_NOT_SUPPORTED, None)).await?;
            return Ok(Handshake::Refused(format!("address type {t} not supported")));
        }
        Err(e) => {
            let _ = s.write_all(&socks5::reply(socks5::REP_GENERAL_FAILURE, None)).await;
            return Ok(Handshake::Refused(e.to_string()));
        }
    };
    if request.command != socks5::CMD_CONNECT {
        s.write_all(&socks5::reply(socks5::REP_COMMAND_NOT_SUPPORTED, None)).await?;
        return Ok(Handshake::Refused(format!("command {} not supported", request.command)));
    }
    Ok(Handshake::Connect(request))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn run(client_bytes: &[u8], login: Option<(&str, &str)>) -> (Result<Handshake>, Vec<u8>) {
        let (mut client, mut server) = duplex(4096);
        client.write_all(client_bytes).await.unwrap();
        client.shutdown().await.unwrap();
        let login = login.map(|(u, p)| (u.to_string(), p.to_string()));
        let r = socks5_handshake(&mut server, login.as_ref()).await;
        drop(server);
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        (r, out)
    }

    fn connect_domain(name: &str, port: u16) -> Vec<u8> {
        let mut v = vec![5, 1, 0, 3, name.len() as u8];
        v.extend_from_slice(name.as_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    #[tokio::test]
    async fn connect_without_login() {
        let mut bytes = vec![5, 1, 0];
        bytes.extend(connect_domain("shop.test", 8080));
        let (r, out) = run(&bytes, None).await;
        match r.unwrap() {
            Handshake::Connect(req) => {
                assert_eq!((req.address.host().as_str(), req.port), ("shop.test", 8080));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(out, [5, 0], "only the method answer; the caller sends the request reply");
    }

    #[tokio::test]
    async fn login_is_required_checked_and_never_skipped() {
        let mut ok = vec![5, 2, 0, 2, 1, 3, b'b', b'o', b'b', 2, b'p', b'w'];
        ok.extend(connect_domain("a.test", 80));
        let (r, out) = run(&ok, Some(("bob", "pw"))).await;
        assert!(matches!(r.unwrap(), Handshake::Connect(_)));
        assert_eq!(out, [5, 2, 1, 0]);

        let bad = [5, 1, 2, 1, 3, b'b', b'o', b'b', 2, b'p', b'x'];
        let (r, out) = run(&bad, Some(("bob", "pw"))).await;
        assert!(matches!(r.unwrap(), Handshake::Refused(_)));
        assert_eq!(out, [5, 2, 1, 1], "login failure status");

        // A client that offers only "no login" is turned away when a login is required.
        let (r, out) = run(&[5, 1, 0], Some(("bob", "pw"))).await;
        assert!(matches!(r.unwrap(), Handshake::Refused(_)));
        assert_eq!(out, [5, 0xFF]);

        // And a login the listener does not ask for is not forced on a client that offers none.
        let (r, out) = run(&[5, 1, 2], None).await;
        assert!(matches!(r.unwrap(), Handshake::Refused(_)));
        assert_eq!(out, [5, 0xFF]);
    }

    #[tokio::test]
    async fn bind_udp_and_odd_requests_are_refused_with_the_right_code() {
        for (cmd, name) in [(2u8, "bind"), (3, "udp"), (9, "unknown")] {
            let mut bytes = vec![5, 1, 0, 5, cmd, 0, 1, 1, 2, 3, 4, 0, 80];
            let (r, out) = run(&bytes, None).await;
            assert!(matches!(r.unwrap(), Handshake::Refused(_)), "{name}");
            assert_eq!(&out[..2], [5, 0]);
            assert_eq!(out[3], 7, "{name}: command not supported");
            bytes.clear();
        }
        let (r, out) = run(&[5, 1, 0, 5, 1, 0, 9, 1, 2], None).await;
        assert!(matches!(r.unwrap(), Handshake::Refused(_)));
        assert_eq!(out[3], 8, "address type not supported");
    }

    #[tokio::test]
    async fn garbage_truncation_and_wrong_versions() {
        let (r, out) = run(b"GET / HTTP/1.1\r\n\r\n", None).await;
        assert!(matches!(r.unwrap(), Handshake::Refused(_)));
        assert!(out.is_empty(), "nothing is said to a client that is not speaking SOCKS5");
        let (r, _) = run(&[4, 1, 0, 80, 1, 2, 3, 4, 0], None).await;
        assert!(matches!(r.unwrap(), Handshake::Refused(_)), "SOCKS4");
        let (r, _) = run(&[5, 1, 0, 5, 1, 0, 3, 9, b'a'], None).await;
        assert!(r.is_err(), "the client hung up in the middle of the request");
        let (r, _) = run(&[5], None).await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn bytes_after_the_request_are_left_unread() {
        let (mut client, mut server) = duplex(4096);
        let mut bytes = vec![5, 1, 0];
        bytes.extend(connect_domain("a.test", 80));
        bytes.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        client.write_all(&bytes).await.unwrap();
        let r = socks5_handshake(&mut server, None).await.unwrap();
        assert!(matches!(r, Handshake::Connect(_)));
        let mut rest = vec![0u8; 18];
        server.read_exact(&mut rest).await.unwrap();
        assert_eq!(rest, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn failure_codes() {
        let refused = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)).context("x");
        assert_eq!(reply_code(&refused), socks5::REP_CONNECTION_REFUSED);
        assert_eq!(reply_code(&anyhow::anyhow!("refused before connecting: denied")), socks5::REP_NOT_ALLOWED);
        assert_eq!(reply_code(&anyhow::anyhow!("cannot resolve x")), socks5::REP_HOST_UNREACHABLE);
    }
}
