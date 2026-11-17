//! SOCKS5 listeners: a minimal SOCKS5 client in the test tunnels HTTP, HTTPS and other protocols through ProxyMind
//! to the demo shop and to small test servers.

mod common;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use common::*;
use parking_lot::RwLock;
use pm_proxy::{Redirect, SocksLogin};
use pm_replay::{NetConfig, UpstreamRule};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

enum Dest<'a> {
    Name(&'a str),
    Ip(IpAddr),
}

/// Why the proxy turned the client away.
#[derive(Debug, PartialEq, Eq)]
enum Refused {
    /// The method answer (0xFF: nothing acceptable).
    Method(u8),
    /// The login answer's status.
    Login(u8),
    /// The reply code to the request.
    Reply(u8),
}

fn request_bytes(cmd: u8, dest: &Dest, port: u16) -> Vec<u8> {
    let mut req = vec![5, cmd, 0];
    match dest {
        Dest::Ip(IpAddr::V4(ip)) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        Dest::Ip(IpAddr::V6(ip)) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
        Dest::Name(n) => {
            req.push(3);
            req.push(n.len() as u8);
            req.extend_from_slice(n.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    req
}

/// A minimal SOCKS5 client: greeting, optional login, then `cmd` to `dest`.
async fn socks5(
    proxy: u16,
    login: Option<(&str, &str)>,
    cmd: u8,
    dest: Dest<'_>,
    port: u16,
) -> Result<TcpStream, Refused> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    s.write_all(if login.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] }).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    if m[1] == 0xFF {
        return Err(Refused::Method(m[1]));
    }
    if m[1] == 2 {
        let (u, p) = login.expect("the proxy asked for a login");
        let mut a = vec![1, u.len() as u8];
        a.extend_from_slice(u.as_bytes());
        a.push(p.len() as u8);
        a.extend_from_slice(p.as_bytes());
        s.write_all(&a).await.unwrap();
        let mut r = [0u8; 2];
        s.read_exact(&mut r).await.unwrap();
        if r[1] != 0 {
            return Err(Refused::Login(r[1]));
        }
    }
    s.write_all(&request_bytes(cmd, &dest, port)).await.unwrap();
    let mut h = [0u8; 10];
    s.read_exact(&mut h).await.unwrap();
    assert_eq!((h[0], h[2], h[3]), (5, 0, 1), "a well-formed reply: {h:?}");
    if h[1] != 0 {
        return Err(Refused::Reply(h[1]));
    }
    Ok(s)
}

async fn connect(proxy: u16, dest: Dest<'_>, port: u16) -> TcpStream {
    socks5(proxy, None, 1, dest, port).await.expect("CONNECT succeeds")
}

async fn socks_listener(s: &Setup, login: Option<(&str, &str)>) -> u16 {
    let (l, port) = listener().await;
    let login: SocksLogin = Arc::new(RwLock::new(login.map(|(u, p)| (u.to_string(), p.to_string()))));
    tokio::spawn(s.proxy.clone().run_socks5(l, Arc::new(RwLock::new(None::<Redirect>)), login));
    port
}

fn products_request(host: &str) -> String {
    format!("GET /api/products HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

#[tokio::test]
async fn http_through_socks5_is_recorded_exactly_like_proxy_traffic() {
    let shop = demo().await;
    let s = setup("socks-http", NetConfig::default()).await;
    let socks = socks_listener(&s, None).await;
    let (l, http_proxy) = listener().await;
    tokio::spawn(s.proxy.clone().run(l));

    let req = products_request(&format!("localhost:{shop}"));
    // 1. SOCKS5 by name (curl --socks5-hostname).
    let resp = get(connect(socks, Dest::Name("localhost"), shop).await, &req).await;
    assert!(resp.starts_with("HTTP/1.1 200") && resp.contains("Coffee"), "{resp}");
    // 2. The same request straight to the HTTP listener (a client that ignores proxies).
    let direct = get(TcpStream::connect(("127.0.0.1", http_proxy)).await.unwrap(), &req).await;
    // 3. SOCKS5 by address (curl --socks5): the Host header still names the target, the connection goes to the IP.
    let by_ip_req = products_request(&format!("shop.test:{shop}"));
    let by_ip = get(connect(socks, Dest::Ip("127.0.0.1".parse().unwrap()), shop).await, &by_ip_req).await;
    assert!(by_ip.starts_with("HTTP/1.1 200") && by_ip.contains("Coffee"), "{by_ip}");

    let rows = recorded(&s.project, 3).await;
    let (via_socks, via_http, via_ip) = (&rows[0], &rows[1], &rows[2]);
    assert_eq!(via_socks.request, req.as_bytes(), "request bytes recorded exactly as the client sent them");
    assert_eq!(via_http.request, via_socks.request);
    for r in [via_socks, via_http] {
        let m = &r.summary;
        assert_eq!(
            (
                m.source.as_str(),
                m.scheme.as_str(),
                m.host.as_str(),
                m.port,
                m.method.as_str(),
                m.path.as_str(),
                m.status
            ),
            ("proxy", "http", "localhost", shop, "GET", "/api/products", Some(200))
        );
    }
    assert_eq!(via_socks.response.as_deref().map(|r| r.len() > 100), Some(true));
    assert_eq!(via_ip.summary.host, "shop.test", "named by the Host header");
    assert_eq!(via_ip.summary.port, shop);
    assert_eq!(via_ip.request, by_ip_req.as_bytes());
    // (the shop numbers its responses, so that header differs)
    let plain = |r: &str| r.lines().filter(|l| !l.starts_with("X-Request-Id")).collect::<Vec<_>>().join("\n");
    assert_eq!(plain(&resp), plain(&direct), "the same response either way");
    assert_eq!(s.proxy.raw_stats().streams, 0, "HTTP is not a raw stream");
}

#[tokio::test]
async fn https_through_socks5_is_intercepted_with_the_proxymind_ca() {
    let shop = demo().await;
    let (front, front_cert) = tls_front(shop).await;
    let s = setup("socks-https", NetConfig::default()).await;
    let socks = socks_listener(&s, None).await;
    let trust = ca_certs(&s.ca);
    let req = products_request(&format!("localhost:{front}"));

    // By name: ProxyMind answers with a certificate for the name, signed by its CA (the client trusts only that).
    let tls = tls_client(connect(socks, Dest::Name("localhost"), front).await, "localhost", &trust)
        .await
        .expect("a certificate for localhost signed by the ProxyMind CA");
    let resp = get(tls, &req).await;
    assert!(resp.starts_with("HTTP/1.1 200") && resp.contains("Coffee"), "{resp}");
    // By address: the TLS server name picks the certificate, the connection goes to that address.
    let tls = tls_client(connect(socks, Dest::Ip("127.0.0.1".parse().unwrap()), front).await, "localhost", &trust)
        .await
        .expect("the server name picks the certificate");
    let resp2 = get(tls, &req).await;
    assert!(resp2.contains("Coffee"), "{resp2}");

    let rows = recorded(&s.project, 2).await;
    for r in &rows {
        let m = &r.summary;
        assert_eq!(
            (m.scheme.as_str(), m.host.as_str(), m.port, m.path.as_str(), m.status),
            ("https", "localhost", front, "/api/products", Some(200))
        );
        assert_eq!(r.request, req.as_bytes());
    }
    // The front's own certificate is not what the client saw.
    assert!(
        tls_client(connect(socks, Dest::Name("localhost"), front).await, "localhost", &[front_cert]).await.is_err()
    );
}

#[tokio::test]
async fn login_is_required_and_checked() {
    let shop = demo().await;
    let s = setup("socks-login", NetConfig::default()).await;
    let socks = socks_listener(&s, Some(("scout", "s3cret"))).await;
    let req = products_request(&format!("localhost:{shop}"));

    let ok = socks5(socks, Some(("scout", "s3cret")), 1, Dest::Name("localhost"), shop).await.expect("right login");
    assert!(get(ok, &req).await.contains("Coffee"));
    assert_eq!(
        socks5(socks, Some(("scout", "wrong")), 1, Dest::Name("localhost"), shop).await.err(),
        Some(Refused::Login(1))
    );
    assert_eq!(
        socks5(socks, Some(("other", "s3cret")), 1, Dest::Name("localhost"), shop).await.err(),
        Some(Refused::Login(1))
    );
    assert_eq!(
        socks5(socks, None, 1, Dest::Name("localhost"), shop).await.err(),
        Some(Refused::Method(0xFF)),
        "no login offered"
    );
    // Only the successful session was recorded.
    assert_eq!(recorded(&s.project, 1).await.len(), 1);
}

#[tokio::test]
async fn bind_and_udp_associate_are_refused_with_command_not_supported() {
    let s = setup("socks-cmds", NetConfig::default()).await;
    let socks = socks_listener(&s, None).await;
    for cmd in [2u8, 3] {
        assert_eq!(
            socks5(socks, None, cmd, Dest::Name("localhost"), 80).await.err(),
            Some(Refused::Reply(7)),
            "command {cmd}"
        );
    }
    // An address type the proxy does not know: "address type not supported".
    let mut c = TcpStream::connect(("127.0.0.1", socks)).await.unwrap();
    c.write_all(&[5, 1, 0, 5, 1, 0, 9, 1, 2, 3, 4, 0, 80]).await.unwrap();
    let mut out = vec![0u8; 12];
    c.read_exact(&mut out).await.unwrap();
    assert_eq!(out[..2], [5, 0], "the method answer");
    assert_eq!(out[3], 8, "reply code 8: address type not supported");
}

#[tokio::test]
async fn pass_through_hosts_are_tunnelled_untouched_and_unrecorded() {
    let shop = demo().await;
    let (front, front_cert) = tls_front(shop).await;
    let net = NetConfig { tls_passthrough: vec!["localhost".into()], ..Default::default() };
    let s = setup("socks-pt", net).await;
    let socks = socks_listener(&s, None).await;
    // The client trusts only the server's own certificate, so this works only if nothing is intercepted.
    let tls = tls_client(connect(socks, Dest::Name("localhost"), front).await, "localhost", &[front_cert])
        .await
        .expect("the server's own certificate reaches the client");
    assert!(get(tls, &products_request("localhost")).await.contains("Coffee"));
    nothing_recorded(&s.project).await;
    // A pass-through target that cannot be reached is reported to the client with the right code.
    let dead = {
        let (l, p) = listener().await;
        drop(l);
        p
    };
    assert_eq!(socks5(socks, None, 1, Dest::Name("localhost"), dead).await.err(), Some(Refused::Reply(5)));
}

#[tokio::test]
async fn other_protocols_are_relayed_unchanged_and_counted() {
    let s = setup("socks-raw", NetConfig::default()).await;
    let socks = socks_listener(&s, None).await;

    // A server that speaks first (an SSH-like banner), then echoes.
    let (l, banner_port) = listener().await;
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                c.write_all(b"SSH-2.0-test\r\n").await.unwrap();
                let mut buf = [0u8; 64];
                loop {
                    let n = c.read(&mut buf).await.unwrap_or(0);
                    if n == 0 || c.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    let mut c = connect(socks, Dest::Name("localhost"), banner_port).await;
    let mut banner = [0u8; 14];
    tokio::time::timeout(std::time::Duration::from_secs(5), c.read_exact(&mut banner))
        .await
        .expect("the banner arrives without the client speaking")
        .unwrap();
    assert_eq!(&banner, b"SSH-2.0-test\r\n");
    c.write_all(&[0, 1, 2, 255, 254, 13, 10]).await.unwrap();
    let mut echoed = [0u8; 7];
    c.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed, [0, 1, 2, 255, 254, 13, 10], "binary data passes unchanged");

    // A protocol where the client speaks first (a Redis-like PING).
    let (l, ping_port) = listener().await;
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 6];
                if c.read_exact(&mut buf).await.is_ok() && &buf == b"PING\r\n" {
                    let _ = c.write_all(b"+PONG\r\n").await;
                }
            });
        }
    });
    let mut c = connect(socks, Dest::Name("localhost"), ping_port).await;
    c.write_all(b"PING\r\n").await.unwrap();
    assert_eq!(read_all(c).await, "+PONG\r\n");

    let stats = s.proxy.raw_stats();
    assert_eq!(stats.streams, 2, "{stats:?}");
    nothing_recorded(&s.project).await;
}

#[tokio::test]
async fn the_setup_page_answers_through_socks5() {
    let s = setup("socks-setup", NetConfig::default()).await;
    let socks = socks_listener(&s, None).await;
    let resp = get(
        connect(socks, Dest::Name("proxymind.setup"), 80).await,
        "GET / HTTP/1.1\r\nHost: proxymind.setup\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(resp.starts_with("HTTP/1.1 200") && resp.contains("ProxyMind setup"), "{resp}");
    nothing_recorded(&s.project).await;
}

#[tokio::test]
async fn a_request_for_the_listeners_own_address_is_not_looped() {
    let s = setup("socks-loop", NetConfig::default()).await;
    let socks = socks_listener(&s, None).await;
    // A non-HTTP stream to the SOCKS listener itself would connect back into it: refused by the loop guard.
    let mut c = connect(socks, Dest::Ip("127.0.0.1".parse().unwrap()), socks).await;
    c.write_all(b"\x00\x01binary").await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), c.read_to_end(&mut out)).await;
    assert!(out.is_empty(), "the connection is closed, not forwarded");
    assert_eq!(s.proxy.raw_stats().streams, 0);
}

/// A tiny SOCKS5 server (no login) that records what it is asked to connect to.
async fn upstream_socks5() -> (u16, Arc<Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let seen = seen2.clone();
            tokio::spawn(async move {
                let mut g = [0u8; 2];
                c.read_exact(&mut g).await.unwrap();
                let mut methods = vec![0u8; g[1] as usize];
                c.read_exact(&mut methods).await.unwrap();
                c.write_all(&[5, 0]).await.unwrap();
                let mut h = [0u8; 4];
                c.read_exact(&mut h).await.unwrap();
                let host = match h[3] {
                    1 => {
                        let mut a = [0u8; 4];
                        c.read_exact(&mut a).await.unwrap();
                        IpAddr::from(a).to_string()
                    }
                    _ => {
                        let mut n = [0u8; 1];
                        c.read_exact(&mut n).await.unwrap();
                        let mut name = vec![0u8; n[0] as usize];
                        c.read_exact(&mut name).await.unwrap();
                        String::from_utf8(name).unwrap()
                    }
                };
                let mut p = [0u8; 2];
                c.read_exact(&mut p).await.unwrap();
                let port = u16::from_be_bytes(p);
                seen.lock().unwrap().push(format!("{host}:{port}"));
                let Ok(mut up) = TcpStream::connect(format!("{host}:{port}")).await else { return };
                c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
            });
        }
    });
    (port, seen)
}

#[tokio::test]
async fn socks5_clients_follow_the_upstream_rules() {
    let shop = demo().await;
    let (up, seen) = upstream_socks5().await;
    let rule = |m: &[&str], via: &str| UpstreamRule {
        matches: m.iter().map(|x| x.to_string()).collect(),
        via: via.into(),
        ..Default::default()
    };
    let net = NetConfig {
        upstream_rules: vec![rule(&["localhost"], &format!("socks5://127.0.0.1:{up}")), rule(&[], "direct")],
        ..Default::default()
    };
    let s = setup("socks-chain", net).await;
    let socks = socks_listener(&s, None).await;
    let resp =
        get(connect(socks, Dest::Name("localhost"), shop).await, &products_request(&format!("localhost:{shop}"))).await;
    assert!(resp.contains("Coffee"), "{resp}");
    let asked = seen.lock().unwrap().clone();
    assert!(
        !asked.is_empty() && asked.iter().all(|a| a.ends_with(&format!(":{shop}"))),
        "the upstream proxy carried it: {asked:?}"
    );
    // 127.0.0.1 matches no rule: direct, the upstream proxy is not asked again.
    let before = asked.len();
    let resp = get(
        connect(socks, Dest::Ip("127.0.0.1".parse().unwrap()), shop).await,
        &products_request(&format!("127.0.0.1:{shop}")),
    )
    .await;
    assert!(resp.contains("Coffee"));
    assert_eq!(seen.lock().unwrap().len(), before);
    assert_eq!(recorded(&s.project, 2).await.len(), 2);
}
