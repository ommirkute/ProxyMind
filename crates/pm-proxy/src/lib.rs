//! The intercepting proxy.
//!
//! Spike scope (milestone M0/M1): HTTP/1.1, CONNECT with TLS interception,
//! WebSocket upgrade pass-through, and recording of every exchange. One
//! upstream connection per request; pooling, HTTP/2 and the intercept queue
//! come next.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use pm_core::now_ms;
use pm_http::RequestHead;
use pm_replay::{AfterResponse, Conn, Endpoint, Io, Sender};
use pm_store::{NewExchange, Store};
use pm_tls::{CertAuthority, TlsAcceptor};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// Sends finished exchanges to a dedicated writer thread, so the proxy
/// never waits on the database.
#[derive(Clone)]
pub struct Recorder(std::sync::mpsc::Sender<NewExchange>);

impl Recorder {
    /// Starts the writer thread. It runs until every `Recorder` is dropped.
    pub fn spawn(mut store: Store) -> (Self, std::thread::JoinHandle<()>) {
        let (tx, rx) = std::sync::mpsc::channel::<NewExchange>();
        let handle = std::thread::spawn(move || {
            for ex in rx {
                if let Err(e) = store.insert_exchange(&ex) {
                    tracing::error!(error = %e, "failed to record exchange");
                }
            }
        });
        (Self(tx), handle)
    }

    pub fn record(&self, ex: NewExchange) {
        let _ = self.0.send(ex);
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
}

impl Proxy {
    pub fn new(ca: Arc<CertAuthority>, recorder: Recorder, verify_upstream: bool) -> Result<Arc<Self>> {
        Ok(Arc::new(Self { ca, sender: Sender::new(verify_upstream)?, recorder }))
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

            let started = Instant::now();
            let ep = Endpoint::new(&target.scheme, &target.host, target.port);
            let result = self.sender.send(&ep, &request, &head.method, None).await;
            let mut record = NewExchange {
                ts_ms: now_ms(),
                duration_ms: Some(started.elapsed().as_millis() as i64),
                source: "proxy".into(),
                actor_id: "human:local".into(),
                scheme: target.scheme.clone(),
                host: target.host.clone(),
                port: target.port,
                method: head.method.clone(),
                path: target.path.clone(),
                status: None,
                request,
                response: None,
                error: None,
                identity: None,
            };

            match result {
                Ok(resp) => {
                    client.io.write_all(&resp.raw).await?;
                    client.io.flush().await?;
                    let close = head.wants_close()
                        || resp.head.wants_close()
                        || matches!(resp.conn, AfterResponse::ClosedAfterBody);
                    record.status = Some(resp.head.status);
                    record.response = Some(resp.raw);
                    self.recorder.record(record);

                    if let AfterResponse::Upgraded(mut up) = resp.conn {
                        // WebSocket or other protocol switch: pass bytes both ways.
                        // Frame-level logging comes later.
                        if !up.buf.is_empty() {
                            client.io.write_all(&up.buf).await?;
                        }
                        if !client.buf.is_empty() {
                            up.io.write_all(&client.buf).await?;
                        }
                        let _ = tokio::io::copy_bidirectional(&mut client.io, &mut up.io).await;
                        return Ok(());
                    }
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
