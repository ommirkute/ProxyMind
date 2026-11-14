//! The intercepting proxy.
//!
//! HTTP/1.1 and HTTP/2 to browsers, CONNECT with TLS interception,
//! WebSocket relaying, match-and-replace rules, an intercept queue, and
//! recording of every exchange.
//!
//! Responses stream to the browser as they arrive (server-sent events,
//! long downloads, long polling) unless something needs the whole message
//! first: a response rule or the intercept queue. History keeps the first
//! [`RECORD_CAP`] bytes of a response.

mod h2_server;
pub mod intercept;
pub mod listeners;
pub mod presets;
pub mod rewrite;
mod ws_relay;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use pm_core::now_ms;
use pm_http::{BodyKind, RequestHead, ResponseHead};
use pm_replay::{AfterResponse, Conn, Endpoint, Io, Sender};

use intercept::{Decision, Kind};
pub use intercept::{InterceptQueue, InterceptSettings};
pub use listeners::{ListenerConfig, ListenerStatus, Listeners, Redirect};
pub use pm_store::NewExchange as RecordedExchange;
use pm_store::{NewExchange, NewWsMessage, Store, StoreHandle, WsTarget};
use pm_tls::{CertAuthority, TlsAcceptor};
pub use rewrite::{Rewriter, Rule as RewriteRule};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// How long the proxy waits for a response head (long polling can be slow).
pub(crate) const HEAD_TIMEOUT: Duration = Duration::from_secs(300);
/// How long a streaming response may go quiet.
pub(crate) const BODY_IDLE: Duration = Duration::from_secs(300);
/// Bytes of a response kept in history; the rest still reaches the browser.
pub const RECORD_CAP: usize = 64 << 20;

/// Records waiting for the writer thread at most.
const RECORD_QUEUE: usize = 4096;
/// The most records one `spawn_shared` transaction holds.
const BATCH_MAX: usize = 256;
/// How long the shared writer keeps draining the queue into one transaction.
const BATCH_WINDOW: Duration = Duration::from_millis(20);

enum Record {
    Exchange(Box<NewExchange>, Option<u64>),
    Ws(u64, NewWsMessage),
    WsDone(u64),
}

/// Counters shared by every clone of a [`Recorder`].
#[derive(Default)]
struct RecorderStats {
    /// Records the writer thread has handled (committed, or failed and logged).
    written: std::sync::atomic::AtomicU64,
    /// Write transactions the writer thread has run (`spawn_shared`: one per drained batch).
    batches: std::sync::atomic::AtomicU64,
    /// Records that could not be queued because the writer thread is gone.
    lost: std::sync::atomic::AtomicU64,
}

/// Decides whether an exchange goes into history (e.g. in scope only).
pub type RecordFilter = Arc<dyn Fn(&NewExchange) -> bool + Send + Sync>;

/// Sends finished exchanges to a dedicated writer thread, so the proxy
/// doesn't wait on the database. The queue is bounded: if the disk falls
/// far behind, the proxy waits rather than holding traffic in memory.
#[derive(Clone)]
pub struct Recorder {
    tx: std::sync::mpsc::SyncSender<Record>,
    next_key: Arc<std::sync::atomic::AtomicU64>,
    filter: Arc<parking_lot::RwLock<Option<RecordFilter>>>,
    stats: Arc<RecorderStats>,
}

impl Recorder {
    /// Starts the writer thread on its own connection, one transaction per record. For a process without a
    /// `Service`; with one, use [`Recorder::spawn_shared`]. It runs until every `Recorder` is dropped.
    pub fn spawn(mut store: Store) -> (Self, std::thread::JoinHandle<()>) {
        use std::sync::atomic::Ordering::Relaxed;
        let (tx, rx) = std::sync::mpsc::sync_channel::<Record>(RECORD_QUEUE);
        let stats = Arc::new(RecorderStats::default());
        let st = stats.clone();
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
                st.written.fetch_add(1, Relaxed);
                st.batches.fetch_add(1, Relaxed);
            }
        });
        (Self { tx, next_key: Arc::default(), filter: Arc::default(), stats }, handle)
    }

    /// Starts the writer thread on the process's shared write connection (ADR-0017), so recording, the full-text
    /// indexer and `Service` writes take turns on one lock instead of fighting over SQLite's. The thread blocks for
    /// a record, then drains what else is queued (up to 256 records or 20 ms, never waiting for more) and writes it
    /// all in ONE transaction, in arrival order. A WebSocket message goes in after its exchange (it may be in the
    /// same batch). If a batch fails, its records are retried one by one so a single bad row costs one row.
    /// The queue is as bounded as in [`Recorder::spawn`]: a full queue makes senders wait.
    ///
    /// The thread keeps `handle` alive until every `Recorder` clone is dropped.
    pub fn spawn_shared(handle: Arc<StoreHandle>) -> (Self, std::thread::JoinHandle<()>) {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Record>(RECORD_QUEUE);
        let stats = Arc::new(RecorderStats::default());
        let st = stats.clone();
        let join = std::thread::Builder::new()
            .name("recorder".into())
            .spawn(move || {
                let mut ids = std::collections::HashMap::<u64, i64>::new();
                let mut batch = Vec::with_capacity(BATCH_MAX);
                while let Ok(first) = rx.recv() {
                    batch.push(first);
                    let deadline = Instant::now() + BATCH_WINDOW;
                    while batch.len() < BATCH_MAX && Instant::now() < deadline {
                        match rx.try_recv() {
                            Ok(r) => batch.push(r),
                            Err(_) => break,
                        }
                    }
                    let n = batch.len() as u64;
                    write_batch(&handle, &mut ids, std::mem::take(&mut batch));
                    st.written.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                    st.batches.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            })
            .expect("spawning the recorder thread");
        (Self { tx, next_key: Arc::default(), filter: Arc::default(), stats }, join)
    }

    /// Records the writer thread has handled so far (stored, or failed and logged).
    pub fn written_records(&self) -> u64 {
        self.stats.written.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Write transactions the writer thread has run: with `spawn_shared`, one per drained batch.
    pub fn write_batches(&self) -> u64 {
        self.stats.batches.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Records that could not be queued because the writer thread has exited (it panicked). Zero in normal use.
    pub fn lost_records(&self) -> u64 {
        self.stats.lost.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Queues a record, waiting while the queue is full (never dropping for load). Fails only when the writer
    /// thread is gone: that is counted and logged once, not silently ignored.
    fn send(&self, rec: Record) {
        if self.tx.send(rec).is_err() && self.stats.lost.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
            tracing::error!("the recorder's writer thread has stopped; traffic is no longer being recorded");
        }
    }

    /// Sets (or removes) the filter for every clone of this recorder.
    pub fn set_filter(&self, f: Option<RecordFilter>) {
        *self.filter.write() = f;
    }

    fn keep(&self, ex: &NewExchange) -> bool {
        self.filter.read().as_ref().is_none_or(|f| f(ex))
    }

    pub fn record(&self, ex: NewExchange) {
        if self.keep(&ex) {
            self.send(Record::Exchange(Box::new(ex), None));
        }
    }

    /// Records an upgraded exchange; the key links its WebSocket messages
    /// (which are dropped too when the exchange isn't kept).
    fn record_upgrade(&self, ex: NewExchange) -> u64 {
        let key = self.next_key.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.keep(&ex) {
            self.send(Record::Exchange(Box::new(ex), Some(key)));
        }
        key
    }

    fn record_ws(&self, key: u64, m: NewWsMessage) {
        self.send(Record::Ws(key, m));
    }

    fn ws_done(&self, key: u64) {
        self.send(Record::WsDone(key));
    }
}

/// Writes drained records through the shared handle in one transaction, then updates the key -> row id map.
/// Records are never reordered: exchanges go in arrival order, and each WebSocket message is resolved against the
/// exchange it follows (in this batch or an earlier one).
fn write_batch(handle: &StoreHandle, ids: &mut std::collections::HashMap<u64, i64>, records: Vec<Record>) {
    use std::collections::{HashMap, HashSet};
    let mut exchanges: Vec<NewExchange> = Vec::new();
    let mut keys: Vec<Option<u64>> = Vec::new();
    let mut ws: Vec<(WsTarget, NewWsMessage)> = Vec::new();
    let mut pending = HashMap::<u64, usize>::new();
    let mut done = HashSet::<u64>::new();
    for rec in records {
        match rec {
            Record::Exchange(ex, key) => {
                if let Some(k) = key {
                    pending.insert(k, exchanges.len());
                }
                exchanges.push(*ex);
                keys.push(key);
            }
            Record::Ws(key, m) => {
                if done.contains(&key) {
                    // The socket is over; nothing may follow (the unbatched path drops these too).
                } else if let Some(&i) = pending.get(&key) {
                    ws.push((WsTarget::InBatch(i), m));
                } else if let Some(&id) = ids.get(&key) {
                    ws.push((WsTarget::Exchange(id), m));
                } // else: its exchange wasn't kept (filtered out), so the message isn't either
            }
            Record::WsDone(key) => {
                pending.remove(&key);
                done.insert(key);
            }
        }
    }
    let mut row_ids: Vec<Option<i64>> = vec![None; exchanges.len()];
    match handle.write(|s| s.insert_batch(&exchanges, &ws)) {
        Ok(new_ids) => row_ids = new_ids.into_iter().map(Some).collect(),
        Err(e) if exchanges.len() + ws.len() <= 1 => tracing::error!(error = %e, "failed to record traffic"),
        Err(e) => {
            // Nothing was stored (one transaction). Find the bad record by writing one at a time.
            tracing::warn!(error = %e, "batch write failed; retrying its records one by one");
            for (i, ex) in exchanges.iter().enumerate() {
                let own: Vec<(WsTarget, NewWsMessage)> = ws
                    .iter()
                    .filter(|(t, _)| *t == WsTarget::InBatch(i))
                    .map(|(_, m)| (WsTarget::InBatch(0), m.clone()))
                    .collect();
                match handle.write(|s| s.insert_batch(std::slice::from_ref(ex), &own)) {
                    Ok(v) => row_ids[i] = v.first().copied(),
                    Err(e) => tracing::error!(error = %e, "failed to record traffic"),
                }
            }
            for (t, m) in &ws {
                if let WsTarget::Exchange(id) = *t {
                    let m = NewWsMessage { exchange_id: id, ..m.clone() };
                    if let Err(e) = handle.write(|s| s.insert_ws_message(&m)) {
                        tracing::error!(error = %e, "failed to record traffic");
                    }
                }
            }
        }
    }
    for (key, id) in keys.iter().zip(&row_ids) {
        if let (Some(k), Some(id)) = (key, id)
            && !done.contains(k)
        {
            ids.insert(*k, *id);
        }
    }
    for k in done {
        ids.remove(&k);
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
        let mut sender = Sender::new(verify_upstream)?.with_timeouts(Duration::from_secs(15), HEAD_TIMEOUT);
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
            // A client that asked to wait for 100 Continue would wait for
            // the full body to reach the server first; answer it ourselves.
            let kind = head.body_kind()?;
            if head.version == "HTTP/1.1"
                && kind != BodyKind::None
                && pm_http::header(&head.headers, "expect")
                    .is_some_and(|v| v.trim_ascii().eq_ignore_ascii_case(b"100-continue"))
            {
                client.io.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
                client.io.flush().await?;
            }
            let body = client.read_body(kind).await?;
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
            let mut record = NewExchange {
                ts_ms: now_ms(),
                duration_ms: None,
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

            let buffered = pm_http::h2text::is_http2_request(&record.request)
                || self.buffers_response(&target.scheme, &target.host, target.port, &path);
            if !buffered {
                let start =
                    match self.sender.send_start_pooled(&ep, &record.request, &method, check, HEAD_TIMEOUT).await {
                        Ok(start) => start,
                        Err(e) => return self.bad_gateway(client, &target.host, target.port, record, started, e).await,
                    };
                if let Some(sent) = &start.sent {
                    record.request.clone_from(sent);
                }
                record.status = Some(start.head.status);
                client.io.write_all(&start.raw_head).await?;
                if start.head.status == 101 {
                    client.io.flush().await?;
                    record.duration_ms = Some(started.elapsed().as_millis() as i64);
                    record.response = Some(start.raw_head);
                    return self.finish_upgrade(client, start.conn, &start.head, record, ws_hold).await;
                }
                let server_close = start.head.wants_close();
                let (mut up, mut body) = (start.conn, start.body);
                let mut capture = start.raw_head;
                let (mut client_gone, mut failed, mut truncated) = (false, false, false);
                loop {
                    let piece = match up.body_chunk(&mut body, BODY_IDLE).await {
                        Ok(Some(p)) => p,
                        Ok(None) => break,
                        Err(e) => {
                            record.error = Some(format!("{e:#}"));
                            failed = true;
                            break;
                        }
                    };
                    let room = RECORD_CAP.saturating_sub(capture.len());
                    truncated |= piece.len() > room;
                    capture.extend_from_slice(&piece[..piece.len().min(room)]);
                    if client.io.write_all(&piece).await.is_err() || client.io.flush().await.is_err() {
                        client_gone = true;
                        break;
                    }
                }
                if record.error.is_none() {
                    record.error = body.cut_short.clone();
                }
                if truncated {
                    let note = format!(
                        "history keeps the first {} MB of this response ({} body bytes in all)",
                        RECORD_CAP >> 20,
                        body.read
                    );
                    record.error = Some(record.error.map_or(note.clone(), |e| format!("{e}; {note}")));
                }
                if client_gone && record.error.is_none() {
                    record.error = Some(format!("the browser closed the connection after {} body bytes", body.read));
                }
                record.duration_ms = Some(started.elapsed().as_millis() as i64);
                record.response = Some(capture);
                self.recorder.record(record);
                // A complete response leaves the server connection reusable.
                if !client_gone && !failed && !server_close && body.is_complete() && body.kind() != BodyKind::UntilClose
                {
                    self.sender.release(&ep, up);
                }
                let close = client_gone
                    || failed
                    || head.wants_close()
                    || body.kind() == BodyKind::UntilClose
                    || body.cut_short.is_some()
                    || server_close;
                if close {
                    let _ = client.io.shutdown().await;
                    return Ok(());
                }
                continue;
            }

            let result = self.sender.send(&ep, &record.request, &method, check).await;
            record.duration_ms = Some(started.elapsed().as_millis() as i64);
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
                    record.error = resp.cut_short.clone();
                    record.response = Some(resp.raw);
                    if let AfterResponse::Upgraded(up) = resp.conn {
                        return self.finish_upgrade(client, up, &resp.head, record, ws_hold).await;
                    }
                    self.recorder.record(record);
                    if close {
                        let _ = client.io.shutdown().await;
                        return Ok(());
                    }
                }
                Err(e) => return self.bad_gateway(client, &target.host, target.port, record, started, e).await,
            }
        }
    }

    /// Whether a response must be read whole before the browser gets it:
    /// a response rule may change it, or the intercept queue holds it.
    pub(crate) fn buffers_response(&self, scheme: &str, host: &str, port: u16, path: &str) -> bool {
        self.hooks.rewrite.as_ref().is_some_and(|r| r.has_response_rules())
            || self.hooks.intercept.as_ref().is_some_and(|q| q.wants(Kind::Response, scheme, host, port, path))
    }

    /// Tells the browser the target couldn't be reached, and records why.
    async fn bad_gateway<S: Io + 'static>(
        &self,
        mut client: Conn<S>,
        host: &str,
        port: u16,
        mut record: NewExchange,
        started: Instant,
        e: anyhow::Error,
    ) -> Result<()> {
        let msg = format!("ProxyMind could not reach {host}:{port}: {e:#}");
        tracing::warn!("{msg}");
        let resp = format!(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
            msg.len()
        );
        let _ = client.io.write_all(resp.as_bytes()).await;
        let _ = client.io.shutdown().await;
        record.duration_ms = Some(started.elapsed().as_millis() as i64);
        record.error = Some(format!("{e:#}"));
        self.recorder.record(record);
        Ok(())
    }

    /// After `101 Switching Protocols`: relay WebSocket messages (logging
    /// each one), or pass any other protocol through byte for byte.
    async fn finish_upgrade<S: Io + 'static>(
        &self,
        mut client: Conn<S>,
        mut up: Conn<Box<dyn Io>>,
        head: &ResponseHead,
        record: NewExchange,
        ws_hold: Option<ws_relay::WsHold>,
    ) -> Result<()> {
        let is_ws = pm_http::header(&head.headers, "upgrade")
            .is_some_and(|v| v.trim_ascii().eq_ignore_ascii_case(b"websocket"));
        if is_ws {
            let deflate = ws_relay::Deflate::from_response(&head.headers);
            let key = self.recorder.record_upgrade(record);
            let recorder = self.recorder.clone();
            ws_relay::relay(client.io, client.buf, up.io, up.buf, deflate, ws_hold, recorder, key).await;
            return Ok(());
        }
        self.recorder.record(record);
        if !up.buf.is_empty() {
            client.io.write_all(&up.buf).await?;
        }
        if !client.buf.is_empty() {
            up.io.write_all(&client.buf).await?;
        }
        let _ = tokio::io::copy_bidirectional(&mut client.io, &mut up.io).await;
        Ok(())
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

#[cfg(test)]
mod recorder_tests {
    use super::*;

    fn exchange(i: usize) -> NewExchange {
        NewExchange {
            ts_ms: i as i64,
            duration_ms: Some(1),
            source: "proxy".into(),
            actor_id: "human:local".into(),
            scheme: "http".into(),
            host: "rec.test".into(),
            port: 80,
            method: "GET".into(),
            path: format!("/{i}"),
            status: Some(200),
            // Not valid UTF-8, and not trimmed or normalised anywhere on the way.
            request: [format!("GET /{i} HTTP/1.1\r\nHost: rec.test\r\n\r\n").into_bytes(), vec![0, 255, 13, 10]]
                .concat(),
            response: Some(
                [b"HTTP/1.1 200 OK\r\n\r\n".to_vec(), format!("body {i}").into_bytes(), vec![0, 254]].concat(),
            ),
            error: None,
            identity: None,
            hypothesis_id: None,
        }
    }

    fn project(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("pm-recorder-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (dir.join("p.pmproj"), dir)
    }

    #[test]
    fn shared_recorder_writes_every_record_in_order_in_batches() {
        const N: usize = 5000;
        let (path, dir) = project("order");
        let handle = Arc::new(StoreHandle::new(Store::open(&path).unwrap()));
        let (rec, join) = Recorder::spawn_shared(handle.clone());
        // Two producers, so records interleave, but each producer's own order must hold.
        let producers: Vec<_> = (0..2)
            .map(|p| {
                let rec = rec.clone();
                std::thread::spawn(move || {
                    for i in (p..N).step_by(2) {
                        rec.record(exchange(i));
                    }
                })
            })
            .collect();
        for p in producers {
            p.join().unwrap();
        }
        let stats = rec.stats.clone();
        drop(rec);
        join.join().unwrap(); // drains the queue before returning
        assert_eq!(stats.lost.load(std::sync::atomic::Ordering::Relaxed), 0);
        assert_eq!(stats.written.load(std::sync::atomic::Ordering::Relaxed), N as u64);
        let batches = stats.batches.load(std::sync::atomic::Ordering::Relaxed);
        assert!(batches >= 1 && batches < N as u64 / 4, "records were batched: {batches} transactions for {N}");

        let rows = handle.read(|s| {
            assert_eq!(s.count_exchanges().unwrap(), N as i64);
            (1..=N as i64).map(|id| s.get_exchange(id).unwrap().unwrap()).collect::<Vec<_>>()
        });
        assert_eq!(rows.len(), N, "nothing lost");
        for p in 0..2usize {
            let mine: Vec<usize> = rows.iter().map(|r| r.summary.ts_ms as usize).filter(|t| t % 2 == p).collect();
            assert_eq!(mine, (p..N).step_by(2).collect::<Vec<_>>(), "producer {p}'s records stay in order");
        }
        for r in &rows {
            let want = exchange(r.summary.ts_ms as usize);
            assert_eq!(r.request, want.request, "request bytes exactly as recorded");
            assert_eq!(r.response, want.response, "response bytes exactly as recorded");
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn shared_recorder_links_websocket_messages_across_and_within_batches() {
        let (path, dir) = project("ws");
        let handle = Arc::new(StoreHandle::new(Store::open(&path).unwrap()));
        let (rec, join) = Recorder::spawn_shared(handle.clone());
        let msg = |tag: u8| NewWsMessage {
            exchange_id: -1,
            ts_ms: tag as i64,
            from_client: true,
            opcode: 1,
            len: 1,
            payload: vec![tag],
            truncated: false,
            compressed: false,
        };
        // Two sockets whose messages interleave, with plain exchanges between them; some arrive in a batch with
        // their exchange, some after it was committed (the sleep forces a batch boundary).
        let a = rec.record_upgrade(exchange(0));
        rec.record_ws(a, msg(1));
        rec.record(exchange(1));
        let b = rec.record_upgrade(exchange(2));
        rec.record_ws(b, msg(2));
        rec.record_ws(a, msg(3));
        while rec.written_records() < 6 {
            std::thread::sleep(Duration::from_millis(5));
        }
        rec.record_ws(b, msg(4));
        rec.record_ws(a, msg(5));
        rec.ws_done(a);
        rec.record_ws(a, msg(99)); // after done: its key is gone, so it is dropped
        let filtered = rec.record_upgrade(exchange(3));
        rec.set_filter(Some(Arc::new(|_| false)));
        let dropped = rec.record_upgrade(exchange(4)); // filtered out
        rec.record_ws(dropped, msg(98));
        rec.ws_done(b);
        let _ = filtered;
        drop(rec);
        join.join().unwrap();
        handle.read(|s| {
            let all = s.search_exchanges(&pm_store::HistoryFilter::default()).unwrap();
            assert_eq!(all.len(), 4, "the filtered exchange is not stored");
            let id_of = |ts: i64| all.iter().find(|r| r.ts_ms == ts).unwrap().id;
            let payloads = |id: i64| -> Vec<u8> {
                s.ws_messages(id, None, 100).unwrap().iter().flat_map(|m| m.payload.clone()).collect()
            };
            assert_eq!(payloads(id_of(0)), [1, 3, 5]);
            assert_eq!(payloads(id_of(2)), [2, 4]);
            assert!(payloads(id_of(1)).is_empty() && payloads(id_of(3)).is_empty());
        });
        let _ = std::fs::remove_dir_all(dir);
    }
}
