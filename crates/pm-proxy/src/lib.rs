//! The intercepting proxy.
//!
//! HTTP/1.1, CONNECT with TLS interception, WebSocket upgrade pass-through,
//! match-and-replace rules, an intercept queue, and recording of every
//! exchange. One upstream connection per request; pooling and HTTP/2 come next.

pub mod intercept;
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
        loop {
            let (tcp, peer) = listener.accept().await?;
            let this = self.clone();
            tokio::spawn(async move {
                if let Err(e) = this.handle_client(tcp).await {
                    tracing::debug!(%peer, error = %e, "client connection ended with error");
                }
            });
        }
    }

    async fn handle_client(self: Arc<Self>, tcp: TcpStream) -> Result<()> {
        tcp.set_nodelay(true)?;
        let mut client = Conn::new(tcp);
        let Some(head_raw) = client.read_head().await? else { return Ok(()) };
        let head = pm_http::parse_request_head(&head_raw)?;

        if !head.method.eq_ignore_ascii_case("CONNECT") {
            return self.serve_http(client, "http", None, Some(head_raw)).await;
        }

        let (host, port) = pm_http::split_host_port(&head.target, 443).ok_or_else(|| anyhow!("bad CONNECT target"))?;
        client.io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
        if !client.buf.is_empty() {
            bail!("client sent data before the CONNECT tunnel was ready");
        }
        let tcp = client.io;

        // Peek at the first byte: 0x16 starts a TLS handshake. Anything else
        // is plain HTTP inside the tunnel (e.g. WebSockets on port 80).
        let mut first = [0u8; 1];
        if tcp.peek(&mut first).await? == 0 {
            return Ok(());
        }
        if first[0] == 0x16 {
            let acceptor = TlsAcceptor::from(self.ca.server_config(&host)?);
            let tls = acceptor.accept(tcp).await.context("TLS handshake with client")?;
            self.serve_http(Conn::new(tls), "https", Some((host, port)), None).await
        } else {
            self.serve_http(Conn::new(tcp), "http", Some((host, port)), None).await
        }
    }

    /// Serves requests on one client connection until it closes.
    async fn serve_http<S: Io + 'static>(
        &self,
        mut client: Conn<S>,
        scheme: &str,
        tunnel_target: Option<(String, u16)>,
        mut first_head: Option<Vec<u8>>,
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
            let target = resolve_target(&head, &head_raw, scheme, tunnel_target.as_ref())?;
            let body = client.read_body(head.body_kind()?).await?;
            let mut request = target.head_raw.clone();
            request.extend_from_slice(&body);

            // Match-and-replace rules, then the intercept queue, where a
            // human may forward, edit or drop the request.
            let mut method = head.method.clone();
            let mut path = target.path.clone();
            let mut edited_request = None;
            if let Some(r) = &self.hooks.rewrite {
                edited_request = r.apply_request(&target.scheme, &target.host, target.port, &path, &request);
            }
            if let Some(q) = &self.hooks.intercept {
                let current = edited_request.as_deref().unwrap_or(&request);
                match q.hold(Kind::Request, &target.scheme, &target.host, target.port, &method, &path, current).await {
                    Decision::Forward(None) => {}
                    Decision::Forward(Some(edited)) => edited_request = Some(edited),
                    Decision::Drop => {
                        let msg = "Request dropped in ProxyMind's intercept queue.";
                        let resp = format!(
                            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{msg}",
                            msg.len()
                        );
                        let _ = client.io.write_all(resp.as_bytes()).await;
                        let _ = client.io.shutdown().await;
                        return Ok(());
                    }
                }
            }
            if let Some(edited) = edited_request {
                if let Ok(Some(end)) = pm_http::find_head_end(&edited)
                    && let Ok(h) = pm_http::parse_request_head(&edited[..end])
                {
                    path = pm_http::split_absolute_target(&h.target)
                        .map_or_else(|| h.target.clone(), |(_, _, p)| p.to_string());
                    method = h.method;
                }
                request = edited;
            }

            let started = Instant::now();
            let ep = Endpoint::new(&target.scheme, &target.host, target.port);
            let result = self.sender.send(&ep, &request, &method, None).await;
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
                    // Rules and intercept apply to responses too. The project
                    // keeps the server's original; the browser gets the edit.
                    let mut to_client: Option<Vec<u8>> = None;
                    let upgraded = matches!(resp.conn, AfterResponse::Upgraded(_));
                    if let Some(r) = &self.hooks.rewrite
                        && !upgraded
                    {
                        to_client = r.apply_response(&target.scheme, &target.host, target.port, &path, &resp.raw);
                    }
                    if let Some(q) = &self.hooks.intercept
                        && !upgraded
                    {
                        let current = to_client.as_deref().unwrap_or(&resp.raw);
                        match q
                            .hold(Kind::Response, &target.scheme, &target.host, target.port, &method, &path, current)
                            .await
                        {
                            Decision::Forward(None) => {}
                            Decision::Forward(Some(edited)) => to_client = Some(edited),
                            Decision::Drop => {
                                record.status = Some(resp.head.status);
                                record.response = Some(resp.raw);
                                self.recorder.record(record);
                                let _ = client.io.shutdown().await;
                                return Ok(());
                            }
                        }
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
                            ws_relay::relay(client.io, client.buf, up.io, up.buf, deflate, recorder, key).await;
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
    // Origin-form without a tunnel (invisible proxying): use the Host header.
    let host_hdr = pm_http::header(&head.headers, "host").ok_or_else(|| anyhow!("request has no Host header"))?;
    let (host, port) =
        pm_http::split_host_port(std::str::from_utf8(host_hdr)?, 80).ok_or_else(|| anyhow!("bad Host header"))?;
    Ok(Target { scheme: "http".into(), host, port, path: head.target.clone(), head_raw: head_raw.to_vec() })
}
