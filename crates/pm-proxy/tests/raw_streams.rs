//! Raw TCP and TLS streams (roadmap 2.6): protocols that are not HTTP are relayed byte for byte through a CONNECT
//! tunnel, SOCKS5 and transparent TLS, and recorded as streams with their chunks in order.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use parking_lot::RwLock;
use pm_proxy::{Redirect, SocksLogin};
use pm_replay::NetConfig;
use pm_store::{Store, StreamChunkRow, StreamRow};
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A plain server that speaks first, like SMTP: greets, then answers each line until QUIT.
async fn smtp_like() -> u16 {
    let (l, port) = listener().await;
    tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            tokio::spawn(smtp_session(c));
        }
    });
    port
}

async fn smtp_session<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(mut c: S) {
    c.write_all(b"220 greetings\r\n").await.unwrap();
    let mut buf = [0u8; 64];
    loop {
        let n = c.read(&mut buf).await.unwrap_or(0);
        if n == 0 {
            return;
        }
        if buf[..n].starts_with(b"QUIT") {
            let _ = c.write_all(b"221 bye\r\n").await;
            let _ = c.shutdown().await;
            return;
        }
        let _ = c.write_all(b"250 ok\r\n").await;
    }
}

/// A plain server where the client speaks first: PING gets PONG, anything else is echoed upper-cased.
async fn ping_pong() -> u16 {
    let (l, port) = listener().await;
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 64];
                loop {
                    let n = c.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let reply: Vec<u8> =
                        if &buf[..n] == b"PING\r\n" { b"+PONG\r\n".to_vec() } else { buf[..n].to_ascii_uppercase() };
                    if c.write_all(&reply).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// CONNECT through the HTTP listener; returns the tunnel after "200 Connection Established".
async fn connect_tunnel(proxy: u16, host: &str, port: u16) -> TcpStream {
    let mut c = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    c.write_all(format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        c.read_exact(&mut b).await.unwrap();
        head.push(b[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    c
}

async fn socks_connect(proxy: u16, host: &str, port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    let mut req = vec![5, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut h = [0u8; 10];
    s.read_exact(&mut h).await.unwrap();
    assert_eq!(h[1], 0, "SOCKS5 CONNECT succeeds");
    s
}

async fn read_exactly<S: tokio::io::AsyncRead + Unpin>(s: &mut S, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut out)).await.expect("bytes arrive").unwrap();
    out
}

async fn http_listener(s: &Setup) -> u16 {
    let (l, port) = listener().await;
    tokio::spawn(s.proxy.clone().run(l));
    port
}

async fn socks_listener(s: &Setup) -> u16 {
    let (l, port) = listener().await;
    let login: SocksLogin = Arc::new(RwLock::new(None));
    tokio::spawn(s.proxy.clone().run_socks5(l, Arc::new(RwLock::new(None::<Redirect>)), login));
    port
}

type Recorded = (StreamRow, Vec<StreamChunkRow>);

/// Waits until `n` streams exist and have all ended; oldest first, with their chunks.
async fn streams(project: &std::path::Path, n: usize) -> Vec<Recorded> {
    for _ in 0..200 {
        let store = Store::open(project).unwrap();
        let mut rows = store.list_streams(&pm_store::StreamFilter { limit: Some(500), ..Default::default() }).unwrap();
        rows.reverse();
        if rows.len() >= n && rows.iter().all(|r| r.ended.is_some()) {
            return rows
                .into_iter()
                .map(|r| {
                    let chunks = store.stream_chunks(r.id, None, 5000, None).unwrap();
                    (r, chunks)
                })
                .collect();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("fewer than {n} finished streams recorded");
}

/// Consecutive chunks of one direction joined: what each side said, in order.
fn turns(chunks: &[StreamChunkRow]) -> Vec<(bool, Vec<u8>)> {
    let mut out: Vec<(bool, Vec<u8>)> = Vec::new();
    for c in chunks {
        match out.last_mut() {
            Some((dir, data)) if *dir == c.to_server => data.extend_from_slice(&c.data),
            _ => out.push((c.to_server, c.data.clone())),
        }
    }
    out
}

fn no_streams(project: &std::path::Path) -> bool {
    Store::open(project).unwrap().count_streams().unwrap() == 0
}

#[tokio::test]
async fn a_server_first_protocol_through_connect_is_relayed_exactly_and_recorded_in_order() {
    let port = smtp_like().await;
    let s = setup("raw-connect-server-first", NetConfig::default()).await;
    let proxy = http_listener(&s).await;
    let mut c = connect_tunnel(proxy, "localhost", port).await;

    // The client stays silent: the greeting still arrives (the proxy found that the server speaks first).
    assert_eq!(read_exactly(&mut c, 15).await, b"220 greetings\r\n");
    c.write_all(b"EHLO me\r\n").await.unwrap();
    assert_eq!(read_exactly(&mut c, 8).await, b"250 ok\r\n");
    c.write_all(b"QUIT\r\n").await.unwrap();
    assert_eq!(read_exactly(&mut c, 9).await, b"221 bye\r\n");
    drop(c);

    let rec = streams(&s.project, 1).await;
    let (row, chunks) = &rec[0];
    assert_eq!((row.host.as_str(), row.port, row.tls, row.source.as_str()), ("localhost", port, false, "proxy"));
    assert_eq!(row.client_addr.as_deref(), Some("127.0.0.1"));
    assert_eq!((row.bytes_to_server, row.bytes_to_client), (15, 15 + 8 + 9));
    assert!(!row.truncated);
    assert_eq!(row.ended.as_deref(), Some("server_closed"), "{row:?}");
    assert_eq!(
        turns(chunks),
        [
            (false, b"220 greetings\r\n".to_vec()),
            (true, b"EHLO me\r\n".to_vec()),
            (false, b"250 ok\r\n".to_vec()),
            (true, b"QUIT\r\n".to_vec()),
            (false, b"221 bye\r\n".to_vec()),
        ]
    );
    assert!(chunks.windows(2).all(|w| w[0].ts_ms <= w[1].ts_ms && w[0].id < w[1].id), "in order, with times");
    // Not HTTP: no exchange was recorded.
    assert_eq!(Store::open(&s.project).unwrap().count_exchanges().unwrap(), 0);
    assert_eq!(s.proxy.raw_stats().streams, 1);
}

#[tokio::test]
async fn a_client_first_protocol_through_connect_and_socks5_is_recorded_with_its_directions() {
    let port = ping_pong().await;
    let s = setup("raw-client-first", NetConfig::default()).await;
    let proxy = http_listener(&s).await;
    let socks = socks_listener(&s).await;

    let binary = [0u8, 1, 2, 255, 254, 13, 10];
    let mut c = connect_tunnel(proxy, "localhost", port).await;
    c.write_all(b"PING\r\n").await.unwrap();
    assert_eq!(read_exactly(&mut c, 7).await, b"+PONG\r\n");
    c.write_all(&binary).await.unwrap();
    assert_eq!(read_exactly(&mut c, 7).await, [0, 1, 2, 255, 254, 13, 10], "binary passes unchanged");
    drop(c);
    let mut c = socks_connect(socks, "localhost", port).await;
    c.write_all(b"PING\r\n").await.unwrap();
    assert_eq!(read_exactly(&mut c, 7).await, b"+PONG\r\n");
    drop(c);

    let rec = streams(&s.project, 2).await;
    let (first, c1) = &rec[0];
    assert_eq!((first.bytes_to_server, first.bytes_to_client), (6 + 7, 7 + 7));
    assert_eq!(first.ended.as_deref(), Some("client_closed"));
    assert_eq!(
        turns(c1),
        [
            (true, b"PING\r\n".to_vec()),
            (false, b"+PONG\r\n".to_vec()),
            (true, binary.to_vec()),
            (false, binary.to_ascii_uppercase()),
        ]
    );
    let (second, c2) = &rec[1];
    assert_eq!((second.host.as_str(), second.port, second.tls), ("localhost", port, false));
    assert_eq!(turns(c2), [(true, b"PING\r\n".to_vec()), (false, b"+PONG\r\n".to_vec())]);
    assert_eq!(s.proxy.raw_stats().streams, 2);
}

#[tokio::test]
async fn a_server_first_protocol_through_socks5_is_recorded() {
    let port = smtp_like().await;
    let s = setup("raw-socks-server-first", NetConfig::default()).await;
    let socks = socks_listener(&s).await;
    let mut c = socks_connect(socks, "localhost", port).await;
    assert_eq!(read_exactly(&mut c, 15).await, b"220 greetings\r\n");
    c.write_all(b"QUIT\r\n").await.unwrap();
    assert_eq!(read_exactly(&mut c, 9).await, b"221 bye\r\n");
    drop(c);
    let rec = streams(&s.project, 1).await;
    assert_eq!(
        turns(&rec[0].1),
        [(false, b"220 greetings\r\n".to_vec()), (true, b"QUIT\r\n".to_vec()), (false, b"221 bye\r\n".to_vec())]
    );
}

fn tls_server_config(alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    Arc::new(cfg)
}

/// A TLS server (ALPN as given) whose sessions are `handler`, which also gets the protocol that was agreed.
async fn tls_server<F, Fut>(alpn: &[&[u8]], handler: F) -> u16
where
    F: Fn(tokio_rustls::server::TlsStream<TcpStream>, Option<Vec<u8>>) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let acceptor = pm_tls::TlsAcceptor::from(tls_server_config(alpn));
    let (l, port) = listener().await;
    tokio::spawn(async move {
        while let Ok((t, _)) = l.accept().await {
            let (a, h) = (acceptor.clone(), handler.clone());
            tokio::spawn(async move {
                let Ok(tls) = a.accept(t).await else { return };
                let alpn = tls.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
                h(tls, alpn).await;
            });
        }
    });
    port
}

/// A TLS client trusting `trust`, offering `alpn`.
async fn tls_connect(
    io: TcpStream,
    sni: &str,
    trust: &[CertificateDer<'static>],
    alpn: &[&[u8]],
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let mut roots = rustls::RootCertStore::empty();
    for c in trust {
        roots.add(c.clone()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(pm_tls::server_name(sni).unwrap(), io).await
}

#[tokio::test]
async fn a_custom_protocol_inside_tls_is_recorded_decrypted_as_a_tls_stream() {
    // A line protocol the client opens (HELLO -> WORLD) and one where the server speaks first (a banner).
    let hello = tls_server(&[], |mut tls, _| async move {
        let mut buf = [0u8; 64];
        while let Ok(n) = tls.read(&mut buf).await {
            if n == 0 || tls.write_all(b"WORLD\n").await.is_err() {
                return;
            }
        }
    })
    .await;
    let banner = tls_server(&[], |mut tls, _| async move {
        let _ = tls.write_all(b"READY\n").await;
        let mut buf = [0u8; 64];
        if tls.read(&mut buf).await.unwrap_or(0) > 0 {
            let _ = tls.write_all(b"BYE\n").await;
        }
        let _ = tls.shutdown().await;
    })
    .await;
    let s = setup("raw-tls", NetConfig::default()).await;
    let proxy = http_listener(&s).await;
    let trust = ca_certs(&s.ca);

    let mut c = tls_connect(connect_tunnel(proxy, "localhost", hello).await, "localhost", &trust, &[])
        .await
        .expect("a certificate for localhost signed by the ProxyMind CA");
    c.write_all(b"HELLO\n").await.unwrap();
    assert_eq!(read_exactly(&mut c, 6).await, b"WORLD\n");
    drop(c);
    let mut c = tls_connect(connect_tunnel(proxy, "localhost", banner).await, "localhost", &trust, &[]).await.unwrap();
    assert_eq!(read_exactly(&mut c, 6).await, b"READY\n", "the banner arrives without the client speaking");
    c.write_all(b"HI\n").await.unwrap();
    assert_eq!(read_exactly(&mut c, 4).await, b"BYE\n");
    drop(c);

    let rec = streams(&s.project, 2).await;
    let (a, ca) = &rec[0];
    assert_eq!((a.host.as_str(), a.port, a.tls, a.sni.as_deref()), ("localhost", hello, true, Some("localhost")));
    assert_eq!(turns(ca), [(true, b"HELLO\n".to_vec()), (false, b"WORLD\n".to_vec())]);
    let (b, cb) = &rec[1];
    assert!(b.tls);
    assert_eq!(turns(cb), [(false, b"READY\n".to_vec()), (true, b"HI\n".to_vec()), (false, b"BYE\n".to_vec())]);
    // The chunks are the decrypted bytes, not TLS records.
    assert!(ca.iter().all(|c| !c.data.starts_with(&[0x17, 0x03])));
    assert_eq!(Store::open(&s.project).unwrap().count_exchanges().unwrap(), 0);
}

#[tokio::test]
async fn http_inside_tls_is_still_http_and_makes_no_stream() {
    let shop = demo().await;
    let (front, _) = tls_front(shop).await;
    let s = setup("raw-tls-http", NetConfig::default()).await;
    let proxy = http_listener(&s).await;
    let trust = ca_certs(&s.ca);
    let tls = tls_connect(connect_tunnel(proxy, "localhost", front).await, "localhost", &trust, &[b"http/1.1"])
        .await
        .unwrap();
    let resp =
        get(tls, &format!("GET /api/products HTTP/1.1\r\nHost: localhost:{front}\r\nConnection: close\r\n\r\n")).await;
    assert!(resp.starts_with("HTTP/1.1 200") && resp.contains("Coffee"), "{resp}");
    assert_eq!(recorded(&s.project, 1).await.len(), 1);
    assert!(no_streams(&s.project));
    assert_eq!(s.proxy.raw_stats().streams, 0);
}

#[tokio::test]
async fn alpn_values_other_than_http_pass_through_and_the_stream_is_raw() {
    // The target speaks a protocol named "x-test" in ALPN; it answers with the protocol it agreed.
    let port = tls_server(&[b"x-test"], |mut tls, alpn| async move {
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).await.unwrap_or(0);
        if n > 0 {
            let mut reply =
                format!("alpn={}:", String::from_utf8_lossy(alpn.as_deref().unwrap_or(b"none"))).into_bytes();
            reply.extend_from_slice(&buf[..n]);
            let _ = tls.write_all(&reply).await;
        }
        let _ = tls.shutdown().await;
    })
    .await;
    let s = setup("raw-alpn", NetConfig::default()).await;
    let proxy = http_listener(&s).await;
    let trust = ca_certs(&s.ca);

    // The client offers h2 as well; the custom value makes it a raw stream and only "x-test" is passed on.
    let mut c = tls_connect(connect_tunnel(proxy, "localhost", port).await, "localhost", &trust, &[b"h2", b"x-test"])
        .await
        .expect("the proxy agrees to the protocol the target agreed to");
    assert_eq!(c.get_ref().1.alpn_protocol(), Some(b"x-test".as_slice()));
    c.write_all(b"ping").await.unwrap();
    let mut got = Vec::new();
    let _ = c.read_to_end(&mut got).await;
    assert_eq!(got, b"alpn=x-test:ping", "the target saw the client's protocol, not http/1.1");
    drop(c);
    let rec = streams(&s.project, 1).await;
    let (row, chunks) = &rec[0];
    assert_eq!((row.tls, row.alpn.as_deref()), (true, Some("x-test")));
    assert_eq!(turns(chunks), [(true, b"ping".to_vec()), (false, b"alpn=x-test:ping".to_vec())]);

    // A client offering a protocol the target does not speak is refused (as the target would).
    let refused = tls_connect(connect_tunnel(proxy, "localhost", port).await, "localhost", &trust, &[b"other"]).await;
    assert!(refused.is_err());
}

#[tokio::test]
async fn a_stream_past_the_recording_cap_is_relayed_whole_and_recorded_up_to_the_cap() {
    // A sink: counts and checks every byte, then reports the count.
    let (l, port) = listener().await;
    let total: usize = (16 << 20) + (1 << 20);
    tokio::spawn(async move {
        let (mut c, _) = l.accept().await.unwrap();
        let mut seen = 0usize;
        let mut buf = vec![0u8; 64 << 10];
        let mut ok = true;
        while seen < total {
            let n = c.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            ok &= buf[..n].iter().enumerate().all(|(i, b)| *b == ((seen + i) % 251) as u8);
            seen += n;
        }
        let _ = c.write_all(format!("got {seen} {ok}\n").as_bytes()).await;
    });
    let s = setup("raw-cap", NetConfig::default()).await;
    let socks = socks_listener(&s).await;
    let mut c = socks_connect(socks, "localhost", port).await;
    let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    c.write_all(&data).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), c.read_to_end(&mut answer)).await.expect("answer").unwrap();
    assert_eq!(String::from_utf8_lossy(&answer), format!("got {total} true\n"), "every byte arrived unchanged");
    drop(c);

    let rec = streams(&s.project, 1).await;
    let (row, chunks) = &rec[0];
    assert_eq!(row.bytes_to_server, total as u64, "all bytes counted");
    assert!(row.truncated);
    let kept: usize = chunks.iter().filter(|c| c.to_server).map(|c| c.data.len()).sum();
    assert_eq!(kept as u64, pm_store::STREAM_RECORD_CAP, "recorded up to the cap, no further");
    let stored: Vec<u8> = chunks.iter().filter(|c| c.to_server).flat_map(|c| c.data.clone()).collect();
    assert_eq!(stored[..], data[..stored.len()], "the recorded bytes are the first ones, unchanged");
    // The answer came after the cap: counted, not kept.
    assert_eq!(row.bytes_to_client, answer.len() as u64);
}

#[tokio::test]
async fn recording_settings_decide_which_streams_are_kept_but_every_stream_is_relayed() {
    let kept_port = ping_pong().await;
    let dropped_port = ping_pong().await;
    let s = setup("raw-filter", NetConfig::default()).await;
    let proxy = http_listener(&s).await;
    // Like "record only in scope": only the first target is wanted.
    let wanted = kept_port;
    let recorder = s.recorder.clone();
    recorder.set_filter(Some(Arc::new(move |ex| ex.port == wanted && ex.client_addr.as_deref() == Some("127.0.0.1"))));

    for port in [dropped_port, kept_port] {
        let mut c = connect_tunnel(proxy, "localhost", port).await;
        c.write_all(b"PING\r\n").await.unwrap();
        assert_eq!(read_exactly(&mut c, 7).await, b"+PONG\r\n", "relayed either way");
    }
    let rec = streams(&s.project, 1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(rec[0].0.port, kept_port);
    assert_eq!(Store::open(&s.project).unwrap().count_streams().unwrap(), 1, "the other stream is not recorded");
    assert_eq!(s.proxy.raw_stats().streams, 2, "but both were relayed and counted");
}

#[tokio::test]
async fn pass_through_tunnels_are_not_recorded_as_streams() {
    let port = ping_pong().await;
    let net = NetConfig { tls_passthrough: vec!["localhost".into()], ..Default::default() };
    let s = setup("raw-passthrough", net).await;
    let socks = socks_listener(&s).await;
    let proxy = http_listener(&s).await;
    let mut c = socks_connect(socks, "localhost", port).await;
    c.write_all(b"PING\r\n").await.unwrap();
    assert_eq!(read_exactly(&mut c, 7).await, b"+PONG\r\n");
    let mut c2 = connect_tunnel(proxy, "localhost", port).await;
    c2.write_all(b"PING\r\n").await.unwrap();
    assert_eq!(read_exactly(&mut c2, 7).await, b"+PONG\r\n");
    drop((c, c2));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(no_streams(&s.project));
}

#[tokio::test]
async fn a_target_that_closes_is_recorded_as_closed_by_the_server() {
    // Answers once and closes.
    let (l, port) = listener().await;
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 16];
                let _ = c.read(&mut buf).await;
                let _ = c.write_all(b"once\n").await;
            });
        }
    });
    let s = setup("raw-end", NetConfig::default()).await;
    let socks = socks_listener(&s).await;
    let mut c = socks_connect(socks, "localhost", port).await;
    c.write_all(b"x").await.unwrap();
    assert_eq!(read_all(c).await, "once\n");
    let rec = streams(&s.project, 1).await;
    assert_eq!(rec[0].0.ended.as_deref(), Some("server_closed"));
    assert_eq!(rec[0].0.error, None);
}
