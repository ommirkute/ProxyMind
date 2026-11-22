//! Where the project server listens and how it answers (ADR-0022, "Transport for the project server").
//!
//! * [`plan`] is the **pure decision** made before anything is bound: which combinations of listen address, TLS and
//!   reverse proxy are allowed, and what the public origin, the allowed host names and the allowed origins are. The
//!   CLI calls it and refuses to start on an error; nothing else decides this.
//! * [`TlsListener`] wraps a TCP listener so that `axum::serve` gets established TLS connections. Handshakes run in
//!   their own tasks with a timeout, so a client that stalls or fails a handshake never blocks or ends the accept loop.
//! * [`serve_app`] serves the router with the peer address attached to every request (`ConnectInfo`), over TLS or not.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::serve::{Listener, ListenerExt};
use pm_tls::ServerConfig;
use pm_tls::TlsAcceptor;
use pm_tls::server::ServerTlsStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;

/// How the server gets its TLS certificate (or that it has none).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsKind {
    /// Plain HTTP: loopback only.
    None,
    /// The operator's certificate and key (`--tls-cert`, `--tls-key`).
    Own,
    /// A self-signed certificate that clients pin (`--tls-self-signed`).
    SelfSigned,
}

/// What the operator asked for.
#[derive(Debug, Clone)]
pub struct ListenInput<'a> {
    pub listen: SocketAddr,
    pub tls: TlsKind,
    /// A reverse proxy terminates TLS in front of this server.
    pub behind_proxy: bool,
    /// The proxy's addresses; `X-Forwarded-*` are believed only from these peers.
    pub trusted_proxies: &'a [IpAddr],
    /// `--public-url`: the address people type, e.g. `https://pm.example.com`.
    pub public_url: Option<&'a str>,
    /// `--allowed-host`: more `Host` names to answer to.
    pub extra_hosts: &'a [String],
}

/// What the server will do, decided once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenPlan {
    pub tls: TlsKind,
    pub behind_proxy: bool,
    pub trusted_proxies: Vec<IpAddr>,
    /// The main origin (`https://pm.example.com`, no path), for printed URLs.
    pub public_origin: String,
    /// Every `Origin` a browser may send on a state-changing request (normalised).
    pub allowed_origins: Vec<String>,
    /// Lower-case `Host` names (no port, no brackets) the server answers to.
    pub allowed_hosts: Vec<String>,
    /// Send `Strict-Transport-Security` (when the request came in over TLS): an own certificate or a proxy, never a
    /// self-signed one.
    pub hsts: bool,
}

/// Why a combination is refused. Each message says what to change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenError {
    PlainBeyondLoopback(SocketAddr),
    TlsAndProxy,
    ProxyNotPrivate(SocketAddr),
    NoTrustedProxy,
    TrustedWithoutProxy,
    PublicUrlRequired,
    BadPublicUrl(String),
    PublicUrlNotHttps,
    PublicUrlNotPlain,
}

impl std::fmt::Display for ListenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PlainBeyondLoopback(a) => write!(
                f,
                "refusing to listen on {a} without TLS: use --tls-cert and --tls-key, --tls-self-signed, or \
                 --behind-proxy behind a reverse proxy that terminates TLS (plain HTTP is for loopback only)"
            ),
            Self::TlsAndProxy => f.write_str(
                "--behind-proxy means the proxy terminates TLS; do not combine it with --tls-cert or --tls-self-signed",
            ),
            Self::ProxyNotPrivate(a) => write!(
                f,
                "--behind-proxy must listen on a loopback or private address (the proxy reaches it there), not {a}"
            ),
            Self::NoTrustedProxy => f.write_str(
                "--behind-proxy needs --trusted-proxy <IP> (the reverse proxy's address); forwarded headers are \
                 believed only from it",
            ),
            Self::TrustedWithoutProxy => f.write_str("--trusted-proxy only makes sense with --behind-proxy"),
            Self::PublicUrlRequired => f.write_str(
                "--public-url is required here: browsers must send an Origin that matches it (for example \
                 --public-url https://pm.example.com)",
            ),
            Self::BadPublicUrl(why) => write!(f, "--public-url is not usable: {why}"),
            Self::PublicUrlNotHttps => {
                f.write_str("--public-url must be https when the server uses TLS or sits behind a TLS proxy")
            }
            Self::PublicUrlNotPlain => f.write_str("--public-url must be http when the server listens without TLS"),
        }
    }
}

impl std::error::Error for ListenError {}

/// `https://Host:443/` -> `https://host`: the form an `Origin` header has. `None` when it is not an http(s) origin.
pub fn normalise_origin(text: &str) -> Option<String> {
    let url = url::Url::parse(text.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() || !url.username().is_empty() {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn host_of(url: &url::Url) -> String {
    url.host_str().unwrap_or_default().trim_matches(['[', ']']).to_ascii_lowercase()
}

/// The decision. Pure: no sockets, no files.
pub fn plan(input: &ListenInput<'_>) -> Result<ListenPlan, ListenError> {
    let ListenInput { listen, tls, behind_proxy, trusted_proxies, public_url, extra_hosts } = input.clone();
    let loopback = listen.ip().to_canonical().is_loopback();
    if behind_proxy && tls != TlsKind::None {
        return Err(ListenError::TlsAndProxy);
    }
    if behind_proxy {
        if listen.ip().is_unspecified() || !is_private(listen.ip()) {
            return Err(ListenError::ProxyNotPrivate(listen));
        }
        if trusted_proxies.is_empty() {
            return Err(ListenError::NoTrustedProxy);
        }
        // Browsers reach the server through the proxy's name, which only the operator knows.
        if public_url.is_none() {
            return Err(ListenError::PublicUrlRequired);
        }
    } else {
        if !trusted_proxies.is_empty() {
            return Err(ListenError::TrustedWithoutProxy);
        }
        if tls == TlsKind::None && !loopback {
            return Err(ListenError::PlainBeyondLoopback(listen));
        }
    }
    let secure = behind_proxy || tls != TlsKind::None;
    let scheme = if secure { "https" } else { "http" };

    let (public_origin, mut allowed_origins, mut allowed_hosts) = match public_url {
        Some(text) => {
            let url = url::Url::parse(text).map_err(|e| ListenError::BadPublicUrl(e.to_string()))?;
            let origin =
                normalise_origin(text).ok_or_else(|| ListenError::BadPublicUrl("not an http(s) address".into()))?;
            if !matches!(url.path(), "" | "/") || url.query().is_some() || url.fragment().is_some() {
                return Err(ListenError::BadPublicUrl(
                    "give the address without a path, e.g. https://pm.example.com".into(),
                ));
            }
            match (url.scheme(), secure) {
                ("http", true) => return Err(ListenError::PublicUrlNotHttps),
                ("https", false) => return Err(ListenError::PublicUrlNotPlain),
                _ => {}
            }
            (origin.clone(), vec![origin], vec![host_of(&url)])
        }
        None => {
            if !loopback {
                return Err(ListenError::PublicUrlRequired);
            }
            let port = listen.port();
            let origins: Vec<String> = ["127.0.0.1", "localhost", "[::1]"]
                .iter()
                .filter_map(|h| normalise_origin(&format!("{scheme}://{h}:{port}")))
                .collect();
            let main = if listen.ip().is_ipv6() {
                format!("{scheme}://[::1]:{port}")
            } else {
                format!("{scheme}://127.0.0.1:{port}")
            };
            let main = normalise_origin(&main).unwrap_or(main);
            (main, origins, vec!["localhost".into(), "127.0.0.1".into(), "::1".into()])
        }
    };
    // A browser that reaches the server by another allowed name sends that name in `Origin`; same scheme and port as
    // the public origin.
    let public_port = url::Url::parse(&public_origin).ok().and_then(|u| u.port_or_known_default());
    for h in extra_hosts {
        let h = h.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        if !h.is_empty() && !allowed_hosts.contains(&h) {
            let shown = if h.contains(':') { format!("[{h}]") } else { h.clone() };
            if let Some(o) = public_port.and_then(|port| normalise_origin(&format!("{scheme}://{shown}:{port}")))
                && !allowed_origins.contains(&o)
            {
                allowed_origins.push(o);
            }
            allowed_hosts.push(h);
        }
    }
    Ok(ListenPlan {
        tls,
        behind_proxy,
        trusted_proxies: trusted_proxies.iter().map(|i| i.to_canonical()).collect(),
        public_origin,
        allowed_origins,
        allowed_hosts,
        hsts: behind_proxy || tls == TlsKind::Own,
    })
}

impl ListenPlan {
    /// The names a self-signed certificate must cover: every allowed host, and the address bound when it is a
    /// specific one.
    pub fn certificate_names(&self, listen: SocketAddr) -> Vec<String> {
        let mut names = self.allowed_hosts.clone();
        if !listen.ip().is_unspecified() {
            let ip = listen.ip().to_string();
            if !names.contains(&ip) {
                names.push(ip);
            }
        }
        names
    }
}

// ---- the TLS listener ------------------------------------------------------------------------------------------

/// A handshake that has not finished after this long is dropped.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes in flight at once; further connections wait in the kernel's backlog until one finishes.
const MAX_HANDSHAKES: usize = 256;

/// Accepts TCP connections, completes their TLS handshakes in separate tasks and hands the established streams to
/// `axum::serve`. A failed or stalled handshake is logged at debug level and forgotten; the loop goes on.
pub struct TlsListener {
    rx: mpsc::Receiver<(ServerTlsStream<TcpStream>, SocketAddr)>,
    local: SocketAddr,
    task: JoinHandle<()>,
}

impl TlsListener {
    pub fn new(tcp: TcpListener, config: Arc<ServerConfig>) -> io::Result<Self> {
        let local = tcp.local_addr()?;
        let (tx, rx) = mpsc::channel(64);
        let acceptor = TlsAcceptor::from(config);
        let permits = Arc::new(Semaphore::new(MAX_HANDSHAKES));
        let task = tokio::spawn(async move {
            loop {
                // Wait for a free handshake slot before taking the next connection.
                let Ok(permit) = permits.clone().acquire_owned().await else { return };
                let (stream, peer) = match tcp.accept().await {
                    Ok(x) => x,
                    Err(e) => {
                        if !matches!(
                            e.kind(),
                            io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::ConnectionRefused
                                | io::ErrorKind::ConnectionReset
                        ) {
                            tracing::error!("accept error: {e}");
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                        continue;
                    }
                };
                let _ = stream.set_nodelay(true);
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = tx.send((tls, peer)).await;
                        }
                        Ok(Err(e)) => tracing::debug!("TLS handshake with {peer} failed: {e}"),
                        Err(_) => tracing::debug!("TLS handshake with {peer} timed out"),
                    }
                });
            }
        });
        Ok(Self { rx, local, task })
    }
}

impl Drop for TlsListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Listener for TlsListener {
    type Io = ServerTlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(x) => x,
            // The accept task is gone (it only ends when the listener is dropped); never hand out anything again.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        Ok(self.local)
    }
}

/// Serves `app` on `listener` until the future is dropped, over TLS when `tls` is given. Every request carries the
/// peer's address (`ConnectInfo<SocketAddr>`), which server mode needs for throttling and for trusting a proxy.
pub async fn serve_app(listener: TcpListener, app: Router, tls: Option<Arc<ServerConfig>>) -> io::Result<()> {
    let svc = app.into_make_service_with_connect_info::<SocketAddr>();
    match tls {
        None => axum::serve(listener, svc).await,
        Some(cfg) => axum::serve(TlsListener::new(listener, cfg)?.tap_io(|_| {}), svc).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn input<'a>(
        listen: &str,
        tls: TlsKind,
        proxy: bool,
        trusted: &'a [IpAddr],
        url: Option<&'a str>,
    ) -> ListenInput<'a> {
        ListenInput {
            listen: sa(listen),
            tls,
            behind_proxy: proxy,
            trusted_proxies: trusted,
            public_url: url,
            extra_hosts: &[],
        }
    }

    #[test]
    fn plain_http_is_for_loopback_only() {
        for listen in ["127.0.0.1:7777", "[::1]:7777", "127.0.0.2:1"] {
            let p = plan(&input(listen, TlsKind::None, false, &[], None)).unwrap();
            assert!(!p.hsts && p.public_origin.starts_with("http://"), "{listen}: {p:?}");
        }
        for listen in ["0.0.0.0:7777", "192.168.1.10:7777", "10.0.0.5:80", "[::]:7777", "203.0.113.9:7777"] {
            assert_eq!(
                plan(&input(listen, TlsKind::None, false, &[], Some("http://pm.example.com"))).unwrap_err(),
                ListenError::PlainBeyondLoopback(sa(listen)),
                "{listen}"
            );
        }
        // Even with a public URL and an allowed host: no TLS, no listening beyond loopback.
        let msg = plan(&input("0.0.0.0:80", TlsKind::None, false, &[], None)).unwrap_err().to_string();
        assert!(msg.contains("without TLS") && msg.contains("--behind-proxy"), "{msg}");
    }

    #[test]
    fn tls_allows_any_address_but_needs_the_public_url_beyond_loopback() {
        let url = "https://pm.example.com";
        for kind in [TlsKind::Own, TlsKind::SelfSigned] {
            let p = plan(&input("0.0.0.0:443", kind, false, &[], Some(url))).unwrap();
            assert_eq!(p.public_origin, "https://pm.example.com");
            assert_eq!(p.allowed_origins, vec!["https://pm.example.com".to_string()]);
            assert_eq!(p.allowed_hosts, vec!["pm.example.com".to_string()]);
            assert_eq!(p.hsts, kind == TlsKind::Own, "HSTS only for a certificate that is not self-signed");
            assert_eq!(
                plan(&input("0.0.0.0:443", kind, false, &[], None)).unwrap_err(),
                ListenError::PublicUrlRequired
            );
        }
        // Loopback with TLS needs no URL; the origins are the loopback names with https.
        let p = plan(&input("127.0.0.1:8443", TlsKind::SelfSigned, false, &[], None)).unwrap();
        assert!(p.allowed_origins.contains(&"https://localhost:8443".to_string()));
        assert!(p.allowed_origins.contains(&"https://127.0.0.1:8443".to_string()));
        assert!(p.allowed_origins.contains(&"https://[::1]:8443".to_string()));
    }

    #[test]
    fn behind_proxy_rules() {
        let proxy = [ip("127.0.0.1")];
        let url = Some("https://pm.example.com");
        let p = plan(&input("127.0.0.1:7777", TlsKind::None, true, &proxy, url)).unwrap();
        assert!(p.hsts && p.behind_proxy && p.trusted_proxies == vec![ip("127.0.0.1")]);
        // A private address is fine (the proxy is another machine on the LAN).
        plan(&input("10.0.0.5:7777", TlsKind::None, true, &[ip("10.0.0.2")], url)).unwrap();
        plan(&input("[fd00::5]:7777", TlsKind::None, true, &[ip("fd00::2")], url)).unwrap();
        // Not a public address, not all interfaces.
        for listen in ["0.0.0.0:7777", "203.0.113.9:7777", "[::]:7777"] {
            assert_eq!(
                plan(&input(listen, TlsKind::None, true, &proxy, url)).unwrap_err(),
                ListenError::ProxyNotPrivate(sa(listen)),
                "{listen}"
            );
        }
        assert_eq!(
            plan(&input("127.0.0.1:7777", TlsKind::None, true, &[], url)).unwrap_err(),
            ListenError::NoTrustedProxy
        );
        assert_eq!(
            plan(&input("127.0.0.1:7777", TlsKind::Own, true, &proxy, url)).unwrap_err(),
            ListenError::TlsAndProxy
        );
        assert_eq!(
            plan(&input("127.0.0.1:7777", TlsKind::None, false, &proxy, None)).unwrap_err(),
            ListenError::TrustedWithoutProxy
        );
        assert_eq!(
            plan(&input("127.0.0.1:7777", TlsKind::None, true, &proxy, None)).unwrap_err(),
            ListenError::PublicUrlRequired
        );
        // The proxy terminates TLS, so the public URL is https.
        assert_eq!(
            plan(&input("127.0.0.1:7777", TlsKind::None, true, &proxy, Some("http://pm.example.com"))).unwrap_err(),
            ListenError::PublicUrlNotHttps
        );
    }

    #[test]
    fn public_url_checks_and_allowed_hosts() {
        let bad = |u: &str| plan(&input("127.0.0.1:7777", TlsKind::None, false, &[], Some(u))).unwrap_err();
        assert!(matches!(bad("not a url"), ListenError::BadPublicUrl(_)));
        assert!(matches!(bad("ftp://x.example"), ListenError::BadPublicUrl(_)));
        assert!(matches!(bad("http://x.example/ui"), ListenError::BadPublicUrl(_)));
        assert!(matches!(bad("http://x.example/?a=1"), ListenError::BadPublicUrl(_)));
        assert_eq!(bad("https://x.example"), ListenError::PublicUrlNotPlain);
        let mut i = input("127.0.0.1:7777", TlsKind::None, false, &[], Some("http://localhost:7777/"));
        let extra = ["Alias.Example".to_string(), "alias.example".to_string(), "[::1]".to_string()];
        i.extra_hosts = &extra;
        let p = plan(&i).unwrap();
        assert_eq!(p.public_origin, "http://localhost:7777");
        assert_eq!(p.allowed_hosts, vec!["localhost", "alias.example", "::1"]);
        assert_eq!(p.allowed_origins, vec!["http://localhost:7777", "http://alias.example:7777", "http://[::1]:7777"]);
        // Default ports are dropped from the origin, as browsers send it.
        let p = plan(&input("0.0.0.0:443", TlsKind::Own, false, &[], Some("https://PM.example.com:443"))).unwrap();
        assert_eq!(p.public_origin, "https://pm.example.com");
    }

    #[test]
    fn origins_are_normalised() {
        assert_eq!(normalise_origin("HTTPS://Example.com:443").as_deref(), Some("https://example.com"));
        assert_eq!(normalise_origin("http://example.com:8080").as_deref(), Some("http://example.com:8080"));
        assert_eq!(normalise_origin("null"), None);
        assert_eq!(normalise_origin("file:///etc/passwd"), None);
        assert_eq!(normalise_origin("https://user@example.com"), None);
    }

    #[test]
    fn certificate_names_include_the_bound_address() {
        let p = plan(&input("0.0.0.0:443", TlsKind::SelfSigned, false, &[], Some("https://pm.example.com"))).unwrap();
        assert_eq!(p.certificate_names(sa("0.0.0.0:443")), vec!["pm.example.com"]);
        assert_eq!(p.certificate_names(sa("192.0.2.7:443")), vec!["pm.example.com", "192.0.2.7"]);
    }
}
