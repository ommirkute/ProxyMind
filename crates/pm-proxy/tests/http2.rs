//! HTTP/2 from the browser side through the real proxy.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use pm_proxy::rewrite::Part;
use pm_proxy::{Hooks, Proxy, Recorder, RewriteRule, Rewriter};
use pm_store::Store;
use pm_tls::CertAuthority;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn acceptor(alpn: &[&[u8]]) -> pm_tls::TlsAcceptor {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    pm_tls::TlsAcceptor::from(Arc::new(cfg))
}

/// An HTTP/2 server answering "METHOD path x-added body".
async fn h2_backend() -> u16 {
    let acc = acceptor(&[b"h2"]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (t, _) = l.accept().await.unwrap();
            let acc = acc.clone();
            tokio::spawn(async move {
                let mut conn = h2::server::handshake(acc.accept(t).await.unwrap()).await.unwrap();
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let (parts, mut body) = req.into_parts();
                    let mut data = Vec::new();
                    while let Some(Ok(c)) = body.data().await {
                        let _ = body.flow_control().release_capacity(c.len());
                        data.extend_from_slice(&c);
                    }
                    let added =
                        parts.headers.get("x-added").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
                    let text =
                        format!("{} {} {added} {}", parts.method, parts.uri.path(), String::from_utf8_lossy(&data));
                    let resp = http::Response::builder().status(201).body(()).unwrap();
                    let mut s = respond.send_response(resp, false).unwrap();
                    s.send_data(Bytes::from(text), true).unwrap();
                }
            });
        }
    });
    port
}

async fn start_proxy(name: &str, rewrite: Option<Arc<Rewriter>>) -> (u16, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("pm-h2-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let project = dir.join("p.pmproj");
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let hooks = Hooks { rewrite, http2: true, ..Default::default() };
    let proxy = Proxy::with_hooks(ca, recorder, false, hooks).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));
    (port, project)
}

/// A browser-like HTTP/2 client: CONNECT through the proxy, TLS with ALPN h2.
async fn h2_request(proxy: u16, port: u16, method: &str, path: &str, body: &'static [u8]) -> (u16, String) {
    let mut tcp = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    tcp.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = [0u8; 39];
    tcp.read_exact(&mut buf).await.unwrap();
    assert!(buf.starts_with(b"HTTP/1.1 200"));
    let mut cfg = (*pm_tls::upstream_client_config(false).unwrap()).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let tls = pm_tls::TlsConnector::from(Arc::new(cfg))
        .connect(pm_tls::server_name("localhost").unwrap(), tcp)
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]), "the proxy speaks HTTP/2 to the browser");
    let (client, conn) = h2::client::handshake(tls).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut client = client.ready().await.unwrap();
    let req = http::Request::builder().method(method).uri(format!("https://localhost:{port}{path}")).body(()).unwrap();
    let (resp, mut stream) = client.send_request(req, body.is_empty()).unwrap();
    if !body.is_empty() {
        stream.send_data(Bytes::from_static(body), true).unwrap();
    }
    let resp = resp.await.unwrap();
    let status = resp.status().as_u16();
    let mut b = resp.into_body();
    let mut out = Vec::new();
    while let Some(Ok(c)) = b.data().await {
        let _ = b.flow_control().release_capacity(c.len());
        out.extend_from_slice(&c);
    }
    (status, String::from_utf8(out).unwrap())
}

async fn recorded(project: &std::path::Path) -> (String, String) {
    for _ in 0..100 {
        let s = Store::open(project).unwrap();
        if let Some(e) = s.list_exchanges(1, None).unwrap().first() {
            let ex = s.get_exchange(e.id).unwrap().unwrap();
            return (
                String::from_utf8(ex.request).unwrap(),
                String::from_utf8(ex.response.unwrap_or_default()).unwrap(),
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing recorded");
}

#[tokio::test]
async fn http2_end_to_end_with_rules() {
    let backend = h2_backend().await;
    let rw = Arc::new(Rewriter::new());
    rw.set_rules(vec![RewriteRule {
        part: Part::RequestHeader,
        replace: "x-added: by-rule".into(),
        in_scope_only: false,
        ..Default::default()
    }])
    .unwrap();
    let (proxy, project) = start_proxy("e2e", Some(rw)).await;
    let (status, body) = h2_request(proxy, backend, "POST", "/echo", b"hello").await;
    assert_eq!((status, body.as_str()), (201, "POST /echo by-rule hello"));
    let (req, resp) = recorded(&project).await;
    assert!(req.starts_with(&format!("POST /echo HTTP/2\r\nhost: localhost:{backend}\r\n")), "{req}");
    assert!(req.contains("x-added: by-rule\r\n") && req.ends_with("\r\n\r\nhello"), "{req}");
    assert!(resp.starts_with("HTTP/2 201\r\n") && resp.ends_with("by-rule hello"), "{resp}");
}

#[tokio::test]
async fn http1_only_servers_get_a_downgraded_request_that_is_recorded() {
    let acc = acceptor(&[b"http/1.1"]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (t, _) = l.accept().await.unwrap();
        let mut t = acc.accept(t).await.unwrap();
        let mut b = vec![0u8; 4096];
        let _ = t.read(&mut b).await.unwrap();
        t.write_all(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nold!\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
    });
    let (proxy, project) = start_proxy("down", None).await;
    let (status, body) = h2_request(proxy, backend, "GET", "/legacy", b"").await;
    assert_eq!((status, body.as_str()), (200, "old!"), "chunked HTTP/1.1 reaches the browser as HTTP/2");
    let (req, resp) = recorded(&project).await;
    assert_eq!(req, format!("GET /legacy HTTP/1.1\r\nHost: localhost:{backend}\r\n\r\n"), "records what was sent");
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "and what the server said");
}
