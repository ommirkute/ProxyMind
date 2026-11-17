//! Plugin traffic hooks on the HTTP/2 path (ADR-0020), through the real proxy.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use pm_plugin::Registry;
use pm_plugin::hooks::HookEngine;
use pm_plugin::v2::HookKind;
use pm_proxy::{Hooks, Proxy, Recorder};
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
                        parts.headers.get("x-hooked").map(|v| v.to_str().unwrap().to_string()).unwrap_or_default();
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

fn python_works() -> bool {
    std::process::Command::new("python3").arg("--version").output().is_ok_and(|o| o.status.success())
}

async fn start_proxy(script: &str, kind: HookKind) -> (u16, std::path::PathBuf) {
    let home = std::env::temp_dir().join(format!("pm-h2hooks-{}-{}-{}", script, kind.as_str(), std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let dir = home.join("plugin");
    std::fs::create_dir_all(&dir).unwrap();
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../pm-plugin/tests/fixtures").join(script);
    std::fs::copy(src, dir.join("hook.py")).unwrap();
    let k = kind.as_str();
    std::fs::write(
        dir.join("proxymind-plugin.yaml"),
        format!("name: fx\nversion: 1\napi: 2\npermissions: [hooks.{k}]\nhooks:\n  {k}:\n    command: [\"python3\", \"hook.py\"]\n    timeout_ms: 2000\n"),
    )
    .unwrap();
    let mut reg = Registry::load(&home).unwrap();
    reg.add(&dir).unwrap();
    reg.accept_permissions("fx").unwrap();
    reg.set_hook_on("fx", kind, true);
    let engine = Arc::new(HookEngine::new());
    engine.set_scope(Arc::new(|_, _, _, _| true));
    engine.configure(reg.active_hooks());
    let ca = Arc::new(CertAuthority::load_or_create(&home).unwrap());
    let project = home.join("p.pmproj");
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let hooks = Hooks { plugin_hooks: Some(engine), http2: true, ..Default::default() };
    let proxy = Proxy::with_hooks(ca, recorder, false, hooks).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));
    (port, project)
}

/// A browser-like HTTP/2 client: CONNECT through the proxy, TLS with ALPN h2.
async fn h2_request(
    proxy: u16,
    port: u16,
    method: &str,
    path: &str,
    body: &'static [u8],
) -> (u16, http::HeaderMap, String) {
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
    let headers = resp.headers().clone();
    let mut b = resp.into_body();
    let mut out = Vec::new();
    while let Some(Ok(c)) = b.data().await {
        let _ = b.flow_control().release_capacity(c.len());
        out.extend_from_slice(&c);
    }
    (status, headers, String::from_utf8(out).unwrap())
}

async fn recorded_exchange(project: &std::path::Path) -> pm_store::Exchange {
    for _ in 0..100 {
        let s = Store::open(project).unwrap();
        if let Some(e) = s.list_exchanges(1, None).unwrap().first() {
            return s.get_exchange(e.id).unwrap().unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing recorded");
}

#[tokio::test]
async fn a_request_hook_works_on_http2() {
    if !python_works() {
        return;
    }
    let backend = h2_backend().await;
    let (proxy, project) = start_proxy("replace.py", HookKind::Request).await;
    let (status, _, body) = h2_request(proxy, backend, "POST", "/a", b"hello").await;
    // The backend saw the header the hook added (it echoes x-hooked).
    assert_eq!((status, body.as_str()), (201, "POST /a yes hello"));
    let ex = recorded_exchange(&project).await;
    assert!(String::from_utf8_lossy(&ex.request).contains("X-Hooked: yes"));
    let original = String::from_utf8_lossy(ex.request_original.as_deref().expect("original kept")).into_owned();
    assert!(!original.contains("X-Hooked"));
    assert_eq!((ex.changes[0].by.as_str(), ex.changes[0].name.as_str()), ("hook", "fx/request"));
}

#[tokio::test]
async fn a_response_hook_works_on_http2() {
    if !python_works() {
        return;
    }
    let backend = h2_backend().await;
    let (proxy, project) = start_proxy("replace.py", HookKind::Response).await;
    let (status, headers, body) = h2_request(proxy, backend, "GET", "/a", b"").await;
    assert_eq!(status, 201);
    assert_eq!(body, "GET /a  ");
    assert_eq!(
        headers.get("x-hooked").map(|v| v.to_str().unwrap()),
        Some("yes"),
        "the browser got the hook's response"
    );
    let ex = recorded_exchange(&project).await;
    assert!(
        !String::from_utf8_lossy(ex.response.as_deref().unwrap()).contains("X-Hooked"),
        "the record keeps the server's"
    );
    assert!(String::from_utf8_lossy(ex.response_delivered.as_deref().expect("delivered kept")).contains("X-Hooked"));
    assert_eq!((ex.changes[0].by.as_str(), ex.changes[0].name.as_str()), ("hook", "fx/response"));
}

#[tokio::test]
async fn a_failing_hook_is_bypassed_on_http2() {
    if !python_works() {
        return;
    }
    let backend = h2_backend().await;
    let (proxy, project) = start_proxy("crash.py", HookKind::Request).await;
    let (status, _, body) = h2_request(proxy, backend, "POST", "/a", b"hello").await;
    assert_eq!((status, body.as_str()), (201, "POST /a  hello"), "the original went through");
    let ex = recorded_exchange(&project).await;
    assert!(ex.request_original.is_none() && !ex.summary.modified);
    assert!(ex.changes[0].note.as_deref().unwrap().starts_with("failed:"));
}
