//! Upstream proxies (HTTP and SOCKS5) and client certificates, against
//! small local servers.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use pm_replay::{ClientCert, Endpoint, NetConfig, Network, ProxyKind, Sender, UpstreamProxy};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type Seen = Arc<Mutex<Vec<String>>>;

async fn read_head(s: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.unwrap_or(0) == 0 {
            break;
        }
        head.push(b[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// Answers with the request line it received.
async fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let head = read_head(&mut s).await;
                let line = head.lines().next().unwrap_or("").to_string();
                let _ = s
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{line}", line.len()).as_bytes())
                    .await;
            });
        }
    });
    port
}

/// A tiny HTTP proxy: CONNECT tunnels and absolute-form forwarding.
async fn http_proxy(auth: &'static str) -> (u16, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut c, _) = l.accept().await.unwrap();
            let seen = seen2.clone();
            tokio::spawn(async move {
                let head = read_head(&mut c).await;
                seen.lock().unwrap().push(head.clone());
                if !head.contains(&format!("Proxy-Authorization: {auth}\r\n")) {
                    let _ =
                        c.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n").await;
                    return;
                }
                let target = head.split_whitespace().nth(1).unwrap().to_string();
                let authority = if head.starts_with("CONNECT") {
                    target
                } else {
                    target.trim_start_matches("http://").split('/').next().unwrap().to_string()
                };
                let mut up = TcpStream::connect(authority).await.unwrap();
                if head.starts_with("CONNECT") {
                    c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                } else {
                    up.write_all(head.as_bytes()).await.unwrap();
                }
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
            });
        }
    });
    (port, seen)
}

/// A tiny SOCKS5 proxy with username/password login.
async fn socks5_proxy() -> (u16, Seen) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Seen = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut c, _) = l.accept().await.unwrap();
            let seen = seen2.clone();
            tokio::spawn(async move {
                let mut g = [0u8; 2];
                c.read_exact(&mut g).await.unwrap();
                let mut methods = vec![0u8; g[1] as usize];
                c.read_exact(&mut methods).await.unwrap();
                assert!(methods.contains(&2));
                c.write_all(&[5, 2]).await.unwrap();
                let mut v = [0u8; 2];
                c.read_exact(&mut v).await.unwrap();
                let mut user = vec![0u8; v[1] as usize];
                c.read_exact(&mut user).await.unwrap();
                let mut pl = [0u8; 1];
                c.read_exact(&mut pl).await.unwrap();
                let mut pass = vec![0u8; pl[0] as usize];
                c.read_exact(&mut pass).await.unwrap();
                let ok = user == b"sock" && pass == b"s3cret";
                c.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                if !ok {
                    return;
                }
                let mut h = [0u8; 4];
                c.read_exact(&mut h).await.unwrap();
                let host = match h[3] {
                    1 => {
                        let mut a = [0u8; 4];
                        c.read_exact(&mut a).await.unwrap();
                        IpAddr::from(a).to_string()
                    }
                    3 => {
                        let mut n = [0u8; 1];
                        c.read_exact(&mut n).await.unwrap();
                        let mut name = vec![0u8; n[0] as usize];
                        c.read_exact(&mut name).await.unwrap();
                        String::from_utf8(name).unwrap()
                    }
                    _ => panic!("unexpected address type"),
                };
                let mut p = [0u8; 2];
                c.read_exact(&mut p).await.unwrap();
                let port = u16::from_be_bytes(p);
                seen.lock().unwrap().push(format!("{host}:{port}"));
                let mut up = TcpStream::connect((host.as_str(), port)).await.unwrap();
                c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
            });
        }
    });
    (port, seen)
}

fn sender(net: NetConfig) -> Sender {
    let n = Network::new();
    n.set(net).unwrap();
    Sender::new(false).unwrap().with_network(n)
}

fn body(r: &pm_replay::Response) -> String {
    String::from_utf8_lossy(pm_http::split_message(&r.raw).1).into_owned()
}

const GET: &[u8] = b"GET /path?x=1 HTTP/1.1\r\nHost: shop\r\n\r\n";

#[tokio::test]
async fn http_proxy_plain_and_tls() {
    let echo = echo_server().await;
    let (proxy, seen) = http_proxy("Basic dXNlcjpwYXNz").await;
    let up = UpstreamProxy {
        kind: ProxyKind::Http,
        host: "127.0.0.1".into(),
        port: proxy,
        username: "user".into(),
        password: "pass".into(),
        ..Default::default()
    };
    let s = sender(NetConfig { upstream: Some(up.clone()), client_certs: vec![] });
    let r = s.send(&Endpoint::new("http", "127.0.0.1", echo), GET, "GET", None).await.unwrap();
    assert_eq!(body(&r), format!("GET http://127.0.0.1:{echo}/path?x=1 HTTP/1.1"), "absolute form via the proxy");

    // HTTPS goes through a CONNECT tunnel.
    let dir = std::env::temp_dir().join(format!("pm-upstream-{}", std::process::id()));
    let ca = pm_tls::CertAuthority::load_or_create(&dir).unwrap();
    let acceptor = pm_tls::TlsAcceptor::from(ca.server_config("localhost").unwrap());
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tls_port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (t, _) = l.accept().await.unwrap();
        let mut t = acceptor.accept(t).await.unwrap();
        let mut b = vec![0u8; 1024];
        let _ = t.read(&mut b).await.unwrap();
        t.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure").await.unwrap();
    });
    let r = s.send(&Endpoint::new("https", "localhost", tls_port), GET, "GET", None).await.unwrap();
    assert_eq!(body(&r), "secure");
    assert!(seen.lock().unwrap().iter().any(|h| h.starts_with(&format!("CONNECT localhost:{tls_port} HTTP/1.1"))));

    // Wrong password: the proxy's refusal is reported.
    let bad =
        sender(NetConfig { upstream: Some(UpstreamProxy { password: "nope".into(), ..up }), client_certs: vec![] });
    let e = bad.send(&Endpoint::new("https", "localhost", tls_port), GET, "GET", None).await.err().unwrap();
    assert!(format!("{e:#}").contains("407"), "{e:#}");
}

#[tokio::test]
async fn socks5_with_login_local_or_remote_dns_and_bypass() {
    let echo = echo_server().await;
    let (proxy, seen) = socks5_proxy().await;
    let up = UpstreamProxy {
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".into(),
        port: proxy,
        username: "sock".into(),
        password: "s3cret".into(),
        ..Default::default()
    };
    let s = sender(NetConfig { upstream: Some(up.clone()), client_certs: vec![] });
    let r = s.send(&Endpoint::new("http", "localhost", echo), GET, "GET", None).await.unwrap();
    assert_eq!(body(&r), "GET /path?x=1 HTTP/1.1", "request bytes unchanged through SOCKS");
    let first = seen.lock().unwrap()[0].clone();
    assert!(first.ends_with(&format!(":{echo}")) && !first.starts_with("localhost"), "resolved locally: {first}");

    let remote =
        sender(NetConfig { upstream: Some(UpstreamProxy { remote_dns: true, ..up.clone() }), client_certs: vec![] });
    remote.send(&Endpoint::new("http", "localhost", echo), GET, "GET", None).await.unwrap();
    assert_eq!(seen.lock().unwrap()[1], format!("localhost:{echo}"), "the proxy resolves the name");

    // Bypassed hosts connect directly (the proxy port is wrong on purpose).
    let direct = sender(NetConfig {
        upstream: Some(UpstreamProxy { port: 1, bypass: vec!["127.0.0.1".into()], ..up }),
        client_certs: vec![],
    });
    direct.send(&Endpoint::new("http", "127.0.0.1", echo), GET, "GET", None).await.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn address_checks_still_apply_through_a_proxy() {
    let echo = echo_server().await;
    let (proxy, seen) = http_proxy("Basic dXNlcjpwYXNz").await;
    let s = sender(NetConfig {
        upstream: Some(UpstreamProxy { host: "127.0.0.1".into(), port: proxy, ..Default::default() }),
        client_certs: vec![],
    });
    let deny = |_: &[IpAddr]| -> Result<(), String> { Err("loopback is denied".into()) };
    let e = s.send(&Endpoint::new("http", "127.0.0.1", echo), GET, "GET", Some(&deny)).await.err().unwrap();
    assert!(format!("{e:#}").contains("refused before connecting"));
    assert!(seen.lock().unwrap().is_empty(), "nothing reached the proxy");
}

#[tokio::test]
async fn client_certificates_for_mutual_tls() {
    // A client CA, a client certificate it signed, and a server that demands one.
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_ca_cert_der(ca_cert.der(), ca_key).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let client_cert =
        CertificateParams::new(vec!["tester".to_string()]).unwrap().signed_by(&client_key, &issuer).unwrap();
    let server_key = KeyPair::generate().unwrap();
    let server_cert = CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&server_key).unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).unwrap();
    let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build().unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![CertificateDer::from(server_cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .unwrap();
    let acceptor = pm_tls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (t, _) = l.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut t) = acceptor.accept(t).await else { return };
                let mut b = vec![0u8; 1024];
                let _ = t.read(&mut b).await;
                let _ = t.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nmTLS").await;
            });
        }
    });

    let ep = Endpoint::new("https", "localhost", port);
    assert!(sender(NetConfig::default()).send(&ep, GET, "GET", None).await.is_err(), "no certificate: refused");

    let dir = std::env::temp_dir().join(format!("pm-mtls-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("client.pem"), client_cert.pem()).unwrap();
    std::fs::write(dir.join("client.key"), client_key.serialize_pem()).unwrap();
    let cert = |host: &str| ClientCert {
        host: host.into(),
        cert_file: dir.join("client.pem"),
        key_file: dir.join("client.key"),
    };
    let other = sender(NetConfig { upstream: None, client_certs: vec![cert("*.example.com")] });
    assert!(other.send(&ep, GET, "GET", None).await.is_err(), "certificate for another host isn't sent");
    let s = sender(NetConfig { upstream: None, client_certs: vec![cert("localhost")] });
    assert_eq!(body(&s.send(&ep, GET, "GET", None).await.unwrap()), "mTLS");
}
