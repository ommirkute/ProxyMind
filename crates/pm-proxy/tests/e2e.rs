//! End-to-end proxy tests against local servers.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pm_proxy::{Proxy, Recorder};
use pm_store::Store;
use pm_tls::CertAuthority;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Backend that records the raw request bytes and replies with a fixed body.
async fn backend(seen: Arc<Mutex<Vec<Vec<u8>>>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                seen.lock().unwrap().push(buf);
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
                    .await;
            });
        }
    });
    port
}

struct Setup {
    proxy_port: u16,
    ca: Arc<CertAuthority>,
    project: std::path::PathBuf,
    _dir: std::path::PathBuf,
}

async fn setup(name: &str) -> Setup {
    let dir = std::env::temp_dir().join(format!("pm-proxy-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let project = dir.join("p.pmproj");
    let (recorder, _writer) = Recorder::spawn(Store::open(&project).unwrap());
    let proxy = Proxy::new(ca.clone(), recorder, false).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));
    Setup { proxy_port, ca, project, _dir: dir }
}

async fn read_all(mut s: impl AsyncReadExt + Unpin) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    out
}

async fn wait_for_records(project: &std::path::Path, n: i64) -> Store {
    for _ in 0..50 {
        let s = Store::open(project).unwrap();
        if s.count_exchanges().unwrap() >= n {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("exchanges were not recorded");
}

#[tokio::test]
async fn plain_http_is_forwarded_byte_exact_and_recorded() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone()).await;
    let st = setup("plain").await;

    let mut c = TcpStream::connect(("127.0.0.1", st.proxy_port)).await.unwrap();
    let req = format!("GET http://127.0.0.1:{port}/a%2e%2e/x HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Odd  :  v\r\n\r\n");
    c.write_all(req.as_bytes()).await.unwrap();
    let resp = read_all(c).await;
    assert!(resp.ends_with(b"3\r\nabc\r\n0\r\n\r\n"), "{}", String::from_utf8_lossy(&resp));

    let got = seen.lock().unwrap()[0].clone();
    assert_eq!(got, b"GET /a%2e%2e/x HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Odd  :  v\r\n\r\n");

    let store = wait_for_records(&st.project, 1).await;
    let ex = store.list_exchanges(10, None).unwrap();
    assert_eq!((ex[0].status, ex[0].path.as_str()), (Some(200), "/a%2e%2e/x"));
}

#[tokio::test]
async fn https_is_intercepted_with_the_proxymind_ca() {
    // The backend speaks TLS using a certificate from a second ProxyMind CA,
    // so this test needs no extra certificate tooling.
    let backend_dir = std::env::temp_dir().join(format!("pm-proxy-e2e-backend-{}", std::process::id()));
    let backend_ca = CertAuthority::load_or_create(&backend_dir).unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(backend_ca.server_config("localhost").unwrap());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        let mut tls = acceptor.accept(s).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let _ = tls.read(&mut buf).await.unwrap();
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret").await.unwrap();
        let _ = tls.shutdown().await;
    });

    let st = setup("tls").await;
    let mut c = TcpStream::connect(("127.0.0.1", st.proxy_port)).await.unwrap();
    c.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut ok = [0u8; 39];
    c.read_exact(&mut ok).await.unwrap();
    assert!(ok.starts_with(b"HTTP/1.1 200"));

    // The client trusts only the proxy's CA: the handshake succeeds only if
    // the proxy intercepted TLS with a certificate for "localhost".
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_slice(st.ca.ca_pem().as_bytes()).unwrap()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let mut tls = connector.connect(ServerName::try_from("localhost").unwrap(), c).await.unwrap();
    tls.write_all(b"GET /private HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let resp = read_all(tls).await;
    assert!(resp.ends_with(b"secret"), "{}", String::from_utf8_lossy(&resp));

    let store = wait_for_records(&st.project, 1).await;
    let ex = store.list_exchanges(10, None).unwrap();
    assert_eq!((ex[0].scheme.as_str(), ex[0].host.as_str(), ex[0].path.as_str()), ("https", "localhost", "/private"));
    let _ = std::fs::remove_dir_all(backend_dir);
}

#[tokio::test]
async fn unreachable_targets_get_502_and_are_recorded_as_errors() {
    let st = setup("err").await;
    let mut c = TcpStream::connect(("127.0.0.1", st.proxy_port)).await.unwrap();
    c.write_all(b"GET http://127.0.0.1:1/ HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
    let resp = read_all(c).await;
    assert!(resp.starts_with(b"HTTP/1.1 502"));
    let store = wait_for_records(&st.project, 1).await;
    assert!(store.list_exchanges(1, None).unwrap()[0].error.is_some());
}
