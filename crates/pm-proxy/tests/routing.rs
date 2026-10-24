//! TLS pass-through, extra listeners with redirects, and hostname overrides.

use std::sync::Arc;
use std::time::Duration;

use pm_proxy::{Hooks, ListenerConfig, Listeners, Proxy, Recorder};
use pm_replay::{HostOverride, NetConfig, Network};
use pm_store::Store;
use pm_tls::CertAuthority;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Setup {
    proxy: Arc<Proxy>,
    port: u16,
    project: std::path::PathBuf,
}

async fn setup(name: &str, net: NetConfig) -> Setup {
    let dir = std::env::temp_dir().join(format!("pm-route-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let project = dir.join("p.pmproj");
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let network = Network::new();
    network.set(net).unwrap();
    let hooks = Hooks { network: Some(network), ..Default::default() };
    let proxy = Proxy::with_hooks(ca, recorder, false, hooks).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.clone().run(l));
    Setup { proxy, port, project }
}

/// Answers each connection's first request with its request line and Host.
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
    let text = String::from_utf8_lossy(&got).to_string();
    let line = text.lines().next().unwrap_or_default();
    let host = text.lines().find_map(|l| l.strip_prefix("Host: ")).unwrap_or_default();
    let body = format!("backend saw: {line} for {host}");
    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.shutdown().await;
}

async fn http_backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((t, _)) = l.accept().await {
            tokio::spawn(serve_echo(t));
        }
    });
    port
}

/// A TLS backend with its own self-signed certificate for "localhost".
async fn tls_backend() -> (u16, CertificateDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
        .unwrap();
    let acceptor = pm_tls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((t, _)) = l.accept().await {
            let a = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(s) = a.accept(t).await {
                    serve_echo(s).await;
                }
            });
        }
    });
    (port, der)
}

/// A TLS client that trusts only `cert` (the backend's own certificate).
async fn tls_client(tcp: TcpStream, cert: &CertificateDer<'static>) -> std::io::Result<impl AsyncRead + AsyncWrite> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(pm_tls::server_name("localhost").unwrap(), tcp).await
}

async fn read_all<S: AsyncRead + Unpin>(mut s: S) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

async fn recorded(project: &std::path::Path, n: usize) -> Vec<(String, String, u16, String)> {
    for _ in 0..100 {
        let rows = Store::open(project).unwrap().list_exchanges(10, None).unwrap();
        if rows.len() >= n {
            return rows.iter().map(|e| (e.scheme.clone(), e.host.clone(), e.port, e.path.clone())).collect();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("fewer than {n} exchanges recorded");
}

#[tokio::test]
async fn pass_through_hosts_keep_their_own_certificate_and_are_not_recorded() {
    let (backend, cert) = tls_backend().await;
    let s = setup("pt", NetConfig { tls_passthrough: vec!["localhost".into()], ..Default::default() }).await;
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
    c.write_all(format!("CONNECT localhost:{backend} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = [0u8; 39];
    c.read_exact(&mut head).await.unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"));
    let mut tls = tls_client(c, &cert).await.expect("the client sees the server's own certificate");
    tls.write_all(b"GET /pinned HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let resp = read_all(tls).await;
    assert!(resp.ends_with("backend saw: GET /pinned HTTP/1.1 for localhost"), "{resp}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(Store::open(&s.project).unwrap().count_exchanges().unwrap(), 0, "tunnels are not recorded");
}

#[tokio::test]
async fn listeners_redirect_plain_and_invisible_tls_clients() {
    let http = http_backend().await;
    let (tls_port, cert) = tls_backend().await;
    let s = setup("listen", NetConfig { tls_passthrough: vec!["localhost".into()], ..Default::default() }).await;
    let free = |_: ()| std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (a, b) = (free(()), free(()));
    let listeners = Listeners::new(s.proxy.clone(), None);
    let cfg = vec![
        ListenerConfig {
            bind: format!("127.0.0.1:{a}"),
            redirect_host: "127.0.0.1".into(),
            redirect_port: http,
            ..Default::default()
        },
        ListenerConfig {
            bind: format!("127.0.0.1:{b}"),
            redirect_host: "127.0.0.1".into(),
            redirect_port: tls_port,
            ..Default::default()
        },
    ];
    pm_proxy::listeners::validate(&cfg).unwrap();
    listeners.sync(&cfg);
    assert!(listeners.status().iter().all(|l| l.running), "{:?}", listeners.status());

    // A client that knows nothing about proxies: origin-form, any Host.
    let mut c = TcpStream::connect(("127.0.0.1", a)).await.unwrap();
    c.write_all(b"GET /device?id=1 HTTP/1.1\r\nHost: api.device.test\r\n\r\n").await.unwrap();
    let resp = read_all(c).await;
    assert!(resp.ends_with("backend saw: GET /device?id=1 HTTP/1.1 for api.device.test"), "{resp}");
    assert_eq!(recorded(&s.project, 1).await[0], ("http".into(), "127.0.0.1".into(), http, "/device?id=1".into()));

    // TLS straight to the listener, for a pass-through name: tunnelled to the redirect.
    let tcp = TcpStream::connect(("127.0.0.1", b)).await.unwrap();
    let mut tls = tls_client(tcp, &cert).await.expect("tunnelled to the real server");
    tls.write_all(b"GET /tls HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    assert!(read_all(tls).await.ends_with("backend saw: GET /tls HTTP/1.1 for localhost"));

    // Removing a listener closes it; a taken port is reported, not fatal.
    listeners.sync(&cfg[..1]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(TcpStream::connect(("127.0.0.1", b)).await.is_err(), "the second listener stopped");
    let taken = ListenerConfig { bind: format!("127.0.0.1:{}", s.port), ..Default::default() };
    listeners.sync(&[cfg[0].clone(), taken]);
    let st = listeners.status();
    assert_eq!(st.len(), 2);
    assert!(st.iter().any(|l| !l.running && l.error.as_deref().is_some_and(|e| e.contains("cannot listen"))));
}

#[tokio::test]
async fn hostname_overrides_replace_dns() {
    let http = http_backend().await;
    let net = NetConfig {
        hosts: vec![HostOverride { host: "*.staging.invalid".into(), address: "127.0.0.1".parse().unwrap() }],
        ..Default::default()
    };
    let s = setup("hosts", net).await;
    let mut c = TcpStream::connect(("127.0.0.1", s.port)).await.unwrap();
    let req = format!("GET http://api.staging.invalid:{http}/v1 HTTP/1.1\r\nHost: api.staging.invalid:{http}\r\n\r\n");
    c.write_all(req.as_bytes()).await.unwrap();
    let resp = read_all(c).await;
    assert!(resp.ends_with(&format!("backend saw: GET /v1 HTTP/1.1 for api.staging.invalid:{http}")), "{resp}");
    assert_eq!(recorded(&s.project, 1).await[0].1, "api.staging.invalid", "history keeps the name");
}
