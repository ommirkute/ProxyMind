//! Capture modes beyond the HTTP proxy port: SOCKS5 clients (RFC 1928) and transparent (redirected) traffic.
//!
//! After the SOCKS5 handshake a connection is treated like a CONNECT tunnel to `host:port`: TLS is intercepted with
//! ProxyMind's CA (HTTP/1.1 and HTTP/2), plain HTTP is read and recorded (WebSockets included), pass-through hosts
//! are tunnelled untouched, and the setup page answers for its reserved name. Streams that are not HTTP or TLS
//! (SSH, databases, anything the server speaks first in) are relayed byte for byte without recording and counted.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use parking_lot::RwLock;
use pm_http::socks5;
use pm_replay::{Conn, Endpoint, Io};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::transparent::{Flow, OriginalDst, Sniff, classify, effective_orig, flow_for};
use crate::{Ctx, Proxy, Redirect, SelfAddr, TlsAcceptor, setup_page};

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

/// Streams relayed without recording since start (not HTTP or TLS).
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

    /// Streams relayed without recording (see [`RawStats`]).
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
                    self.relay_raw(tcp, up, Vec::new(), &host, port).await
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
        let idle = match self.first_bytes(&tcp, &host, port, &ctx).await? {
            First::Closed => return Ok(()),
            First::ServerFirst { up, bytes } => return self.relay_raw(tcp, up, bytes, &host, port).await,
            First::Client(idle) => idle,
        };
        let sniff = sniff_client(&tcp).await;
        match flow_for(addressed.is_some(), sniff) {
            Flow::Proxy => self.handle_client(tcp, ctx).await,
            Flow::InterceptTls => self.intercept_tunnel(tcp, host, port, ctx, true).await,
            Flow::InterceptHttp => self.intercept_tunnel(tcp, host, port, ctx, false).await,
            Flow::Raw => {
                let up = match idle {
                    Some(up) => up,
                    None => self.connect_raw(&host, port, &ctx).await?,
                };
                self.relay_raw(tcp, up, Vec::new(), &host, port).await
            }
        }
    }

    /// Inside a tunnel to `host:port`: TLS is accepted with a certificate for the host (HTTP/2 when the client asks
    /// for it), anything else is read as HTTP/1.x.
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
        let tls = TlsAcceptor::from(self.tls_config(&host)?).accept(tcp).await.context("TLS handshake with client")?;
        if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
            let (host, port) = ctx.redirect.as_ref().map_or((host, port), |r| (r.host.clone(), r.port));
            return self.serve_h2(tls, host, port, ctx).await;
        }
        self.serve_http(Conn::new(tls), "https", Some((host, port)), None, ctx).await
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

    /// Passes bytes both ways, unchanged and unrecorded, and counts the stream.
    pub(crate) async fn relay_raw(
        &self,
        mut client: TcpStream,
        mut up: Box<dyn Io>,
        from_server: Vec<u8>,
        host: &str,
        port: u16,
    ) -> Result<()> {
        self.raw.streams.fetch_add(1, Relaxed);
        tracing::info!(host, port, "relaying a non-HTTP stream without recording it");
        let started = Instant::now();
        if !from_server.is_empty() {
            client.write_all(&from_server).await?;
            self.raw.to_client.fetch_add(from_server.len() as u64, Relaxed);
        }
        if let Ok((to_target, to_client)) = tokio::io::copy_bidirectional(&mut client, &mut up).await {
            self.raw.to_target.fetch_add(to_target, Relaxed);
            self.raw.to_client.fetch_add(to_client, Relaxed);
            tracing::debug!(
                host,
                port,
                to_target,
                to_client,
                ms = started.elapsed().as_millis() as u64,
                "raw stream finished"
            );
        }
        Ok(())
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
