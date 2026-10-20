//! The intercepting proxy.
//!
//! HTTP/1.1, CONNECT with TLS interception, WebSocket upgrade pass-through,
//! match-and-replace rules, an intercept queue, and recording of every
//! exchange. One upstream connection per request; pooling and HTTP/2 come next.

mod h2_server;
pub mod intercept;
pub mod listeners;
pub mod rewrite;
mod ws_relay;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use pm_core::now_ms;
use pm_http::RequestHead;
use pm_replay::{AfterResponse, Conn, Endpoint, Io, Sender};

use intercept::{Decision, Kind};
pub use intercept::{InterceptQueue, InterceptSettings};
pub use listeners::{ListenerConfig, ListenerStatus, Listeners, Redirect};
use pm_store::{NewExchange, NewWsMessage, Store};
use pm_tls::{CertAuthority, TlsAcceptor};
pub use rewrite::{Rewriter, Rule as RewriteRule};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

enum Record {
    Exchange(Box<NewExchange>, Option<u64>),
    Ws(u64, NewWsMessage),
    WsDone(u64),
}

/// Sends finished exchanges to a dedicated writer thread, so the proxy
/// never waits on the database.
#[derive(Clone)]
pub struct Recorder {
    tx: std::sync::mpsc::Sender<Record>,
    next_key: Arc<std::sync::atomic::AtomicU64>,
}

impl Recorder {
    /// Starts the writer thread. It runs until every `Recorder` is dropped.
    pub fn spawn(mut store: Store) -> (Self, std::thread::JoinHandle<()>) {
        let (tx, rx) = std::sync::mpsc::channel::<Record>();
        let handle = std::thread::spawn(move || {
            // Upgraded exchanges by key, so their WebSocket messages can be
            // linked to the row id. Records arrive in order on one thread.
            let mut ids = std::collections::HashMap::<u64, i64>::new();
            for rec in rx {
                let r = match rec {
                    Record::Exchange(ex, key) => store.insert_exchange(&ex).map(|id| {
                        if let Some(k) = key {
                            ids.insert(k, id);
                        }
                    }),
                    Record::Ws(key, mut m) => match ids.get(&key) {
                        Some(&id) => {
                            m.exchange_id = id;
                            store.insert_ws_message(&m).map(drop)
                        }
                        None => Ok(()),
                    },
                    Record::WsDone(key) => {
                        ids.remove(&key);
                        Ok(())
                    }
                };
                if let Err(e) = r {
                    tracing::error!(error = %e, "failed to record traffic");
                }
            }
        });
        (Self { tx, next_key: Arc::default() }, handle)
    }

    pub fn record(&self, ex: NewExchange) {
        let _ = self.tx.send(Record::Exchange(Box::new(ex), None));
    }

    /// Records an upgraded exchange; the key links its WebSocket messages.
    fn record_upgrade(&self, ex: NewExchange) -> u64 {
        let key = self.next_key.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = self.tx.send(Record::Exchange(Box::new(ex), Some(key)));
        key
    }

    fn record_ws(&self, key: u64, m: NewWsMessage) {
        let _ = self.tx.send(Record::Ws(key, m));
    }

    fn ws_done(&self, key: u64) {
        let _ = self.tx.send(Record::WsDone(key));
    }
}

/// The address a client reached the proxy on. Requests that would connect
/// straight back to it (a transparent-mode Host pointing at ProxyMind)
/// are refused instead of looping forever.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SelfAddr {
    ip: std::net::IpAddr,
    port: u16,
}

impl SelfAddr {
    fn of(tcp: &TcpStream) -> Option<Self> {
        tcp.local_addr().ok().map(|a| Self { ip: a.ip(), port: a.port() })
    }

    fn check(&self, ips: &[std::net::IpAddr], port: u16) -> std::result::Result<(), String> {
        let me = |ip: &std::net::IpAddr| {
            *ip == self.ip || ip.is_unspecified() || (ip.is_loopback() && self.ip.is_loopback())
        };
        if port == self.port && ips.iter().any(me) {
            return Err(format!("that is ProxyMind itself ({}:{}); refusing a request loop", self.ip, self.port));
        }
        Ok(())
    }
}

/// Per-connection context: the listener's address and its redirect, if any.
#[derive(Clone, Default)]
pub(crate) struct Ctx {
    me: Option<SelfAddr>,
    redirect: Option<Redirect>,
}

const DROPPED_MSG: &str = "Request dropped in ProxyMind's intercept queue.";

pub struct ProxyConfig {
    pub listen: SocketAddr,
    /// Verify upstream TLS certificates. Off by default for pentesting.
    pub verify_upstream: bool,
}

pub struct Proxy {
    ca: Arc<CertAuthority>,
    sender: Sender,
    recorder: Recorder,
    hooks: Hooks,
}

/// Optional user controls over live traffic.
#[derive(Default, Clone)]
pub struct Hooks {
    /// Match-and-replace rules, applied first.
    pub rewrite: Option<Arc<Rewriter>>,
    /// The intercept queue; a human sees messages after the rules ran.
    pub intercept: Option<Arc<InterceptQueue>>,
    /// Shared network settings (upstream proxy, client certificates).
    pub network: Option<pm_replay::Network>,
    /// Offer HTTP/2 to browsers on intercepted TLS connections.
    pub http2: bool,
}

impl Proxy {
    pub fn new(ca: Arc<CertAuthority>, recorder: Recorder, verify_upstream: bool) -> Result<Arc<Self>> {
        Self::with_hooks(ca, recorder, verify_upstream, Hooks::default())
    }

    pub fn with_hooks(
        ca: Arc<CertAuthority>,
        recorder: Recorder,
        verify_upstream: bool,
        hooks: Hooks,
    ) -> Result<Arc<Self>> {
        let mut sender = Sender::new(verify_upstream)?;
        if let Some(n) = &hooks.network {
            sender = sender.with_network(n.clone());
        }
        Ok(Arc::new(Self { ca, sender, recorder, hooks }))
    }

    /// Accepts connections until the task is cancelled.
    pub async fn run(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        self.run_with(listener, Arc::default()).await
    }

    /// Like [`Proxy::run`], sending every request to the listener's redirect
    /// target while one is set (it can change while running).
    pub async fn run_with(
        self: Arc<Self>,
        listener: TcpListener,
        redirect: Arc<parking_lot::RwLock<Option<Redirect>>>,
    ) -> Result<()> {
        loop {
            let (tcp, peer) = listener.accept().await?;
            let this = self.clone();
            let ctx = Ctx { me: SelfAddr::of(&tcp), redirect: redirect.read().clone() };
            tokio::spawn(async move {
                if let Err(e) = this.handle_client(tcp, ctx).await {
                    tracing::debug!(%peer, error = %e, "client connection ended with error");
                }
            });
        }
    }

    async fn handle_client(self: Arc<Self>, tcp: TcpStream, ctx: Ctx) -> Result<()> {
        tcp.set_nodelay(true)?;
        // Transparent mode: a TLS handshake straight away (no CONNECT) from a
        // client sent here by DNS or a port redirect.
        let mut first = [0u8; 1];
        if tcp.peek(&mut first).await? == 0 {
            return Ok(());
        }
        if first[0] == 0x16 {
            return self.serve_transparent_tls(tcp, ctx).await;
        }
        let mut client = Conn::new(tcp);
        let Some(head_raw) = client.read_head().await? else { return Ok(()) };
        let head = pm_http::parse_request_head(&head_raw)?;

        if !head.method.eq_ignore_ascii_case("CONNECT") {
            return self.serve_http(client, "http", None, Some(head_raw), ctx).await;
        }

        let (host, port) = pm_http::split_host_port(&head.target, 443).ok_or_else(|| anyhow!("bad CONNECT target"))?;
        client.io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        if !client.buf.is_empty() {
            bail!("client sent data before the CONNECT tunnel was ready");
        }
        let tcp = client.io;
        if self.passthrough(&host) {
            let (to_host, to_port) = ctx.redirect.as_ref().map_or((host, port), |r| (r.host.clone(), r.port));
            return self.tunnel(tcp, &to_host, to_port, &ctx).await;
        }

        // Peek at the first byte: 0x16 starts a TLS handshake. Anything else
        // is plain HTTP inside the tunnel (e.g. WebSockets on port 80).
        if tcp.peek(&mut first).await? == 0 {
            return Ok(());
        }
        if first[0] == 0x16 {
            let tls =
                TlsAcceptor::from(self.tls_config(&host)?).accept(tcp).await.context("TLS handshake with client")?;
            if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                let (host, port) = ctx.redirect.as_ref().map_or((host, port), |r| (r.host.clone(), r.port));
                return self.serve_h2(tls, host, port, ctx).await;
            }
            self.serve_http(Conn::new(tls), "https", Some((host, port)), None, ctx).await
        } else {
            self.serve_http(Conn::new(tcp), "http", Some((host, port)), None, ctx).await
        }
    }

    /// Whether TLS to this host is passed through without interception.
    fn passthrough(&self, host: &str) -> bool {
        self.sender.network().passthrough(host)
    }

    /// Passes bytes both ways between the client and `host:port`, untouched
    /// and unrecorded (TLS pass-through).
    async fn tunnel(&self, mut client: TcpStream, host: &str, port: u16, ctx: &Ctx) -> Result<()> {
        let guard = self.loop_guard(&ctx.me, host, port);
        let check = guard.as_ref().map(|g| g as pm_replay::AddrCheck<'_>);
        let mut upstream = self.sender.connect_tunnel(host, port, check).await?;
        tracing::debug!(host, port, "TLS pass-through");
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        Ok(())
    }

    /// The certificate (and ALPN) ProxyMind presents for a host.
    fn tls_config(&self, host: &str) -> Result<Arc<pm_tls::ServerConfig>> {
        let mut cfg = self.ca.server_config(host)?;
        if self.hooks.http2 {
            let mut c = (*cfg).clone();
            c.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            cfg = Arc::new(c);
        }
        Ok(cfg)
    }

    /// TLS without CONNECT: the server name (SNI) picks the certificate;
    /// requests go to their Host header (default port 443).
    async fn serve_transparent_tls(self: Arc<Self>, tcp: TcpStream, ctx: Ctx) -> Result<()> {
        // Peek at the ClientHello for pass-through hosts (the bytes stay
        // unread for the tunnel or the TLS acceptor).
        if !self.sender.network().config().tls_passthrough.is_empty()
            && let Some(sni) = peek_sni(&tcp).await
            && self.passthrough(&sni)
        {
            let (host, port) = ctx.redirect.as_ref().map_or((sni, 443), |r| (r.host.clone(), r.port));
            return self.tunnel(tcp, &host, port, &ctx).await;
        }
        let start =
            pm_tls::LazyConfigAcceptor::new(pm_tls::Acceptor::default(), tcp).await.context("reading the TLS hello")?;
        let Some(sni) = start.client_hello().server_name().map(|n| n.to_string()) else {
            bail!("transparent HTTPS needs the client to send a server name (SNI)");
        };
        let tls = start.into_stream(self.tls_config(&sni)?).await.context("TLS handshake with client")?;
        if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
            let (host, port) = ctx.redirect.as_ref().map_or((sni, 443), |r| (r.host.clone(), r.port));
            return self.serve_h2(tls, host, port, ctx).await;
        }
        self.serve_http(Conn::new(tls), "https", None, None, ctx).await
    }

    /// Checks resolved addresses against ProxyMind's own (direct connections only).
    fn loop_guard<'a>(
        &self,
        me: &'a Option<SelfAddr>,
        host: &str,
        port: u16,
    ) -> Option<impl Fn(&[std::net::IpAddr]) -> std::result::Result<(), String> + Sync + 'a> {
        let me = (*me)?;
        self.sender.goes_direct(host).then_some(move |ips: &[std::net::IpAddr]| me.check(ips, port))
    }

    /// Match-and-replace rules, then the intercept queue, where a human may
    /// forward, edit or drop the request. Returns the request to send with
    /// its method and path, or None if it was dropped.
    async fn before_send(
        &self,
        scheme: &str,
        host: &str,
        port: u16,
        request: Vec<u8>,
        method: &str,
        path: &str,
    ) -> Option<(Vec<u8>, String, String)> {
        let mut edited = None;
        if let Some(r) = &self.hooks.rewrite {
            edited = r.apply_request(scheme, host, port, path, &request);
        }
        if let Some(q) = &self.hooks.intercept {
            let current = edited.as_deref().unwrap_or(&request);
            match q.hold(Kind::Request, scheme, host, port, method, path, current).await {
                Decision::Forward(None) => {}
                Decision::Forward(Some(e)) => edited = Some(e),
                Decision::Drop => return None,
            }
        }
        let Some(edited) = edited else { return Some((request, method.to_string(), path.to_string())) };
        let (mut method, mut path) = (method.to_string(), path.to_string());
        if let Ok(Some(end)) = pm_http::find_head_end(&edited)
            && let Ok(h) = pm_http::parse_request_head(&edited[..end])
        {
            path =
                pm_http::split_absolute_target(&h.target).map_or_else(|| h.target.clone(), |(_, _, p)| p.to_string());
            method = h.method;
        }
        Some((edited, method, path))
    }

    /// Rules and the intercept queue for a response. `Some(None)`: send the
    /// original; `Some(Some(bytes))`: send these instead; None: dropped.
    async fn before_respond(
        &self,
        scheme: &str,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
        raw: &[u8],
    ) -> Option<Option<Vec<u8>>> {
        let mut to_client = None;
        if let Some(r) = &self.hooks.rewrite {
            to_client = r.apply_response(scheme, host, port, path, raw);
        }
        if let Some(q) = &self.hooks.intercept {
            let current = to_client.as_deref().unwrap_or(raw);
            match q.hold(Kind::Response, scheme, host, port, method, path, current).await {
                Decision::Forward(None) => {}
                Decision::Forward(Some(edited)) => to_client = Some(edited),
                Decision::Drop => return None,
            }
        }
        Some(to_client)
    }

    /// Serves requests on one client connection until it closes.
    async fn serve_http<S: Io + 'static>(
        &self,
        mut client: Conn<S>,
        scheme: &str,
        tunnel_target: Option<(String, u16)>,
        mut first_head: Option<Vec<u8>>,
        ctx: Ctx,
    ) -> Result<()> {
        loop {
            let head_raw = match first_head.take() {
                Some(h) => h,
                None => match client.read_head().await? {
                    Some(h) => h,
                    None => return Ok(()),
                },
            };
            let head = pm_http::parse_request_head(&head_raw)?;
            let mut target = resolve_target(&head, &head_raw, scheme, tunnel_target.as_ref())?;
            if let Some(r) = &ctx.redirect {
                target.host.clone_from(&r.host);
                target.port = r.port;
                if r.force_tls {
                    target.scheme = "https".into();
                }
            }
            let body = client.read_body(head.body_kind()?).await?;
            let mut request = target.head_raw.clone();
            request.extend_from_slice(&body);

            let (mut request, method, path) = match self
                .before_send(&target.scheme, &target.host, target.port, request, &head.method, &target.path)
                .await
            {
                Some(r) => r,
                None => {
                    let msg = DROPPED_MSG;
                    let resp = format!(
                        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
                        msg.len()
                    );
                    let _ = client.io.write_all(resp.as_bytes()).await;
                    let _ = client.io.shutdown().await;
                    return Ok(());
                }
            };

            // WebSocket interception: open without compression so messages
            // can be edited (only while the user has it turned on).
            let mut ws_hold = None;
            if let Some(q) = &self.hooks.intercept
                && pm_http::header(&head.headers, "upgrade")
                    .is_some_and(|v| v.trim_ascii().eq_ignore_ascii_case(b"websocket"))
                && q.wants_websocket(&target.scheme, &target.host, target.port, &path)
            {
                request = pm_http::remove_header(&request, "sec-websocket-extensions");
                ws_hold = Some(ws_relay::WsHold {
                    queue: q.clone(),
                    scheme: target.scheme.clone(),
                    host: target.host.clone(),
                    port: target.port,
                    path: path.clone(),
                });
            }

            let started = Instant::now();
            let ep = Endpoint::new(&target.scheme, &target.host, target.port);
            let guard = self.loop_guard(&ctx.me, &target.host, target.port);
            let check = guard.as_ref().map(|g| g as pm_replay::AddrCheck<'_>);
            let result = self.sender.send(&ep, &request, &method, check).await;
            let mut record = NewExchange {
                ts_ms: now_ms(),
                duration_ms: Some(started.elapsed().as_millis() as i64),
                source: "proxy".into(),
                actor_id: "human:local".into(),
                scheme: target.scheme.clone(),
                host: target.host.clone(),
                port: target.port,
                method: method.clone(),
                path: path.clone(),
                status: None,
                request,
                response: None,
                error: None,
                identity: None,
                hypothesis_id: None,
            };

            match result {
                Ok(resp) => {
                    if let Some(sent) = &resp.sent {
                        record.request = sent.clone();
                    }
                    // Rules and intercept apply to responses too. The project
                    // keeps the server's original; the browser gets the edit.
                    let upgraded = matches!(resp.conn, AfterResponse::Upgraded(_));
                    let mut to_client = None;
                    if !upgraded {
                        match self
                            .before_respond(&target.scheme, &target.host, target.port, &method, &path, &resp.raw)
                            .await
                        {
                            Some(edited) => to_client = edited,
                            None => {
                                record.status = Some(resp.head.status);
                                record.response = Some(resp.raw);
                                self.recorder.record(record);
                                let _ = client.io.shutdown().await;
                                return Ok(());
                            }
                        }
                    }
                    // An HTTP/1.1 client can't read an HTTP/2 response (the
                    // request was edited to HTTP/2 in the intercept queue).
                    if pm_http::h2text::is_http2_response(to_client.as_deref().unwrap_or(&resp.raw)) {
                        to_client = pm_http::h2text::to_http1_response(to_client.as_deref().unwrap_or(&resp.raw));
                    }
                    client.io.write_all(to_client.as_deref().unwrap_or(&resp.raw)).await?;
                    client.io.flush().await?;
                    let close = head.wants_close()
                        || resp.head.wants_close()
                        || matches!(resp.conn, AfterResponse::ClosedAfterBody);
                    record.status = Some(resp.head.status);
                    let is_ws = pm_http::header(&resp.head.headers, "upgrade")
                        .is_some_and(|v| v.trim_ascii().eq_ignore_ascii_case(b"websocket"));
                    let deflate = ws_relay::Deflate::from_response(&resp.head.headers);
                    record.response = Some(resp.raw);

                    if let AfterResponse::Upgraded(mut up) = resp.conn {
                        if is_ws {
                            // Relay byte for byte and log each message.
                            let key = self.recorder.record_upgrade(record);
                            let recorder = self.recorder.clone();
                            ws_relay::relay(client.io, client.buf, up.io, up.buf, deflate, ws_hold, recorder, key)
                                .await;
                            return Ok(());
                        }
                        // Another protocol switch: pass bytes both ways.
                        self.recorder.record(record);
                        if !up.buf.is_empty() {
                            client.io.write_all(&up.buf).await?;
                        }
                        if !client.buf.is_empty() {
                            up.io.write_all(&client.buf).await?;
                        }
                        let _ = tokio::io::copy_bidirectional(&mut client.io, &mut up.io).await;
                        return Ok(());
                    }
                    self.recorder.record(record);
                    if close {
                        let _ = client.io.shutdown().await;
                        return Ok(());
                    }
                }
                Err(e) => {
                    let msg = format!("ProxyMind could not reach {}:{}: {e:#}", target.host, target.port);
                    tracing::warn!("{msg}");
                    let resp = format!(
                        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
                        msg.len()
                    );
                    let _ = client.io.write_all(resp.as_bytes()).await;
                    let _ = client.io.shutdown().await;
                    record.error = Some(format!("{e:#}"));
                    self.recorder.record(record);
                    return Ok(());
                }
            }
        }
    }
}

/// The server name from a ClientHello the client has sent, without reading it.
async fn peek_sni(tcp: &TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 16 * 1024 + 5];
    let deadline = Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let n = tcp.peek(&mut buf).await.ok()?;
        match pm_tls::peek_client_hello(&buf[..n]) {
            pm_tls::Hello::Sni(name) => return name,
            pm_tls::Hello::NotHello => return None,
            pm_tls::Hello::Incomplete if n == buf.len() || Instant::now() > deadline => return None,
            pm_tls::Hello::Incomplete => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    }
}

/// Where a request goes, and the head bytes to send there.
struct Target {
    scheme: String,
    host: String,
    port: u16,
    path: String,
    head_raw: Vec<u8>,
}

fn resolve_target(
    head: &RequestHead,
    head_raw: &[u8],
    tunnel_scheme: &str,
    tunnel_target: Option<&(String, u16)>,
) -> Result<Target> {
    // Absolute-form (`GET http://host/path`): sent by browsers to a plain
    // HTTP proxy. Servers expect origin-form, so rewrite only the target.
    if let Some((scheme, authority, path)) = pm_http::split_absolute_target(&head.target) {
        let default_port = if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 };
        let (host, port) =
            pm_http::split_host_port(authority, default_port).ok_or_else(|| anyhow!("bad host in target"))?;
        let head_raw = pm_http::replace_request_target(head_raw, path).ok_or_else(|| anyhow!("bad request line"))?;
        return Ok(Target { scheme: scheme.to_ascii_lowercase(), host, port, path: path.to_string(), head_raw });
    }
    // Origin-form inside a CONNECT tunnel: the tunnel says where it goes.
    if let Some((host, port)) = tunnel_target {
        return Ok(Target {
            scheme: tunnel_scheme.to_string(),
            host: host.clone(),
            port: *port,
            path: head.target.clone(),
            head_raw: head_raw.to_vec(),
        });
    }
    // Origin-form without a tunnel (transparent proxying): use the Host header.
    let host_hdr = pm_http::header(&head.headers, "host").ok_or_else(|| anyhow!("request has no Host header"))?;
    let default_port = if tunnel_scheme == "https" { 443 } else { 80 };
    let (host, port) = pm_http::split_host_port(std::str::from_utf8(host_hdr)?.trim(), default_port)
        .ok_or_else(|| anyhow!("bad Host header"))?;
    Ok(Target { scheme: tunnel_scheme.into(), host, port, path: head.target.clone(), head_raw: head_raw.to_vec() })
}
