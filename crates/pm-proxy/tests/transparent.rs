//! Transparent (invisible) proxying: clients that don't know about the
//! proxy, sent to it by DNS or a port redirect.

use std::sync::Arc;
use std::time::Duration;

use pm_proxy::{Proxy, Recorder};
use pm_store::Store;
use pm_tls::CertAuthority;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Setup {
    proxy: u16,
    project: std::path::PathBuf,
    ca: Arc<CertAuthority>,
}

async fn setup(name: &str) -> Setup {
    let dir = std::env::temp_dir().join(format!("pm-tp-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let project = dir.join("p.pmproj");
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let proxy = Proxy::new(ca.clone(), recorder, false).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));
    Setup { proxy: port, project, ca }
}

/// Answers every request with its request line.
async fn serve_echo<S: AsyncRead + AsyncWrite + Unpin>(mut s: S) {
    let mut buf = vec![0u8; 4096];
    let mut got = Vec::new();
    while !got.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = s.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        got.extend_from_slice(&buf[..n]);
    }
    let line = String::from_utf8_lossy(&got).lines().next().unwrap_or_default().to_string();
    let body = format!("backend saw: {line}");
    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.shutdown().await;
}

async fn read_all<S: AsyncRead + Unpin>(mut s: S) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

async fn recorded(project: &std::path::Path) -> (String, String, u16, String) {
    for _ in 0..100 {
        let s = Store::open(project).unwrap();
        if let Some(e) = s.list_exchanges(1, None).unwrap().first() {
            return (e.scheme.clone(), e.host.clone(), e.port, e.path.clone());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing recorded");
}

#[tokio::test]
async fn plain_http_goes_where_the_host_header_says() {
    let s = setup("http").await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = l.local_addr().unwrap().port();
    tokio::spawn(async move { serve_echo(l.accept().await.unwrap().0).await });
    let mut c = TcpStream::connect(("127.0.0.1", s.proxy)).await.unwrap();
    c.write_all(format!("GET /plain?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{backend}\r\n\r\n").as_bytes()).await.unwrap();
    let resp = read_all(c).await;
    assert!(resp.ends_with("backend saw: GET /plain?x=1 HTTP/1.1"), "{resp}");
    assert_eq!(recorded(&s.project).await, ("http".into(), "127.0.0.1".into(), backend, "/plain?x=1".into()));
}

#[tokio::test]
async fn a_url_in_the_query_leaves_the_target_untouched() {
    // An origin-form target whose query carries a URL must not be read as absolute-form.
    let s = setup("urlquery").await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = l.local_addr().unwrap().port();
    tokio::spawn(async move { serve_echo(l.accept().await.unwrap().0).await });
    let mut c = TcpStream::connect(("127.0.0.1", s.proxy)).await.unwrap();
    let target = "/fetch?url=http://example.test/a&b=https://x.test";
    c.write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{backend}\r\n\r\n").as_bytes()).await.unwrap();
    let resp = read_all(c).await;
    assert!(resp.ends_with(&format!("backend saw: GET {target} HTTP/1.1")), "{resp}");
    assert_eq!(recorded(&s.project).await.3, target);
}

#[tokio::test]
async fn tls_without_connect_uses_sni_for_the_certificate_and_host_for_the_target() {
    let s = setup("tls").await;
    // A TLS backend on localhost.
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let acceptor = pm_tls::TlsAcceptor::from(Arc::new(server_cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (t, _) = l.accept().await.unwrap();
        serve_echo(acceptor.accept(t).await.unwrap()).await;
    });

    // The client trusts only ProxyMind's CA and checks the name "localhost".
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile_certs(s.ca.ca_pem()) {
        roots.add(c).unwrap();
    }
    let client_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tcp = TcpStream::connect(("127.0.0.1", s.proxy)).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(client_cfg))
        .connect(pm_tls::server_name("localhost").unwrap(), tcp)
        .await
        .expect("ProxyMind presents a certificate for the SNI name, signed by its CA");
    tls.write_all(format!("GET /secure HTTP/1.1\r\nHost: localhost:{backend}\r\n\r\n").as_bytes()).await.unwrap();
    let resp = read_all(tls).await;
    assert!(resp.ends_with("backend saw: GET /secure HTTP/1.1"), "{resp}");
    assert_eq!(recorded(&s.project).await, ("https".into(), "localhost".into(), backend, "/secure".into()));
}

fn rustls_pemfile_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem.as_bytes()).map(Result::unwrap).collect()
}

#[tokio::test]
async fn requests_to_proxymind_itself_are_refused_not_looped() {
    let s = setup("loop").await;
    let mut c = TcpStream::connect(("127.0.0.1", s.proxy)).await.unwrap();
    c.write_all(format!("GET /again HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n", s.proxy).as_bytes()).await.unwrap();
    let resp = read_all(c).await;
    assert!(resp.starts_with("HTTP/1.1 502") && resp.contains("request loop"), "{resp}");
}

#[tokio::test]
async fn tls_without_a_server_name_is_closed_quickly() {
    let s = setup("nosni").await;
    let tcp = TcpStream::connect(("127.0.0.1", s.proxy)).await.unwrap();
    let cfg = pm_tls::upstream_client_config(false).unwrap();
    // An IP address as the name: rustls sends no SNI.
    let name = rustls::pki_types::ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into());
    let r = tokio::time::timeout(Duration::from_secs(5), pm_tls::TlsConnector::from(cfg).connect(name, tcp)).await;
    assert!(matches!(r, Ok(Err(_))), "the handshake fails instead of hanging");
}
