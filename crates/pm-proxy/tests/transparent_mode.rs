//! Transparent mode: connections the OS redirected to a listener. The original destination comes from a fake
//! provider here (the real `SO_ORIGINAL_DST` needs iptables and root: see the gated test at the end).

mod common;

use std::net::SocketAddr;
use std::sync::Arc;

use common::*;
use parking_lot::RwLock;
use pm_proxy::{OriginalDst, Redirect};
use pm_replay::NetConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Says every connection was going to `0`, or was not redirected (`None`).
struct Fake(Option<SocketAddr>);

impl OriginalDst for Fake {
    fn original_dst(&self, _tcp: &TcpStream) -> Option<SocketAddr> {
        self.0
    }
}

async fn transparent_listener(s: &Setup, orig: Option<SocketAddr>) -> u16 {
    let (l, port) = listener().await;
    tokio::spawn(s.proxy.clone().run_transparent(l, Arc::new(RwLock::new(None::<Redirect>)), Arc::new(Fake(orig))));
    port
}

fn products(host: &str) -> String {
    format!("GET /api/products HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

#[tokio::test]
async fn plain_http_connects_to_the_original_destination_and_is_named_by_its_host_header() {
    let shop = demo().await;
    let s = setup("tp-http", NetConfig::default()).await;
    // "shop.test" does not resolve: only the original destination makes this work.
    let port = transparent_listener(&s, Some(format!("127.0.0.1:{shop}").parse().unwrap())).await;
    let req = products("shop.test");
    let resp = get(TcpStream::connect(("127.0.0.1", port)).await.unwrap(), &req).await;
    assert!(resp.starts_with("HTTP/1.1 200") && resp.contains("Coffee"), "{resp}");
    let rows = recorded(&s.project, 1).await;
    let m = &rows[0].summary;
    assert_eq!(
        (m.scheme.as_str(), m.host.as_str(), m.port, m.path.as_str()),
        ("http", "shop.test", shop, "/api/products")
    );
    assert_eq!(rows[0].request, req.as_bytes(), "byte-exact");

    // No Host header (HTTP/1.0): the original address names the target.
    let resp = get(TcpStream::connect(("127.0.0.1", port)).await.unwrap(), "GET /api/products HTTP/1.0\r\n\r\n").await;
    assert!(resp.contains("Coffee"), "{resp}");
    assert_eq!(recorded(&s.project, 2).await[1].summary.host, "127.0.0.1");
}

#[tokio::test]
async fn tls_is_intercepted_for_the_server_name_and_sent_to_the_original_destination() {
    let shop = demo().await;
    let (front, _cert) = tls_front(shop).await;
    let s = setup("tp-tls", NetConfig::default()).await;
    let port = transparent_listener(&s, Some(format!("127.0.0.1:{front}").parse().unwrap())).await;
    let trust = ca_certs(&s.ca);
    let tls = tls_client(TcpStream::connect(("127.0.0.1", port)).await.unwrap(), "shop.test", &trust)
        .await
        .expect("a certificate for the SNI name, signed by the ProxyMind CA");
    let req = products("shop.test");
    let resp = get(tls, &req).await;
    assert!(resp.contains("Coffee"), "{resp}");
    let m = recorded(&s.project, 1).await.remove(0).summary;
    assert_eq!((m.scheme.as_str(), m.host.as_str(), m.port), ("https", "shop.test", front));
}

#[tokio::test]
async fn other_protocols_go_to_the_original_destination_unchanged() {
    let s = setup("tp-raw", NetConfig::default()).await;
    let (l, echo) = listener().await;
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                c.write_all(b"220 hello\r\n").await.unwrap(); // server speaks first
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
    let port = transparent_listener(&s, Some(format!("127.0.0.1:{echo}").parse().unwrap())).await;
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut banner = [0u8; 11];
    c.read_exact(&mut banner).await.unwrap();
    assert_eq!(&banner, b"220 hello\r\n");
    c.write_all(b"EHLO client.test\r\n").await.unwrap();
    let mut back = [0u8; 18];
    c.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"EHLO client.test\r\n");
    assert_eq!(s.proxy.raw_stats().streams, 1);
    nothing_recorded(&s.project).await;
}

#[tokio::test]
async fn proxy_style_requests_and_unredirected_connections_still_work() {
    let shop = demo().await;
    let s = setup("tp-mixed", NetConfig::default()).await;
    // Redirected to somewhere unrelated, but the client speaks proxy protocol: its own target wins.
    let elsewhere: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let port = transparent_listener(&s, Some(elsewhere)).await;
    let abs = format!(
        "GET http://localhost:{shop}/api/products HTTP/1.1\r\nHost: localhost:{shop}\r\nConnection: close\r\n\r\n"
    );
    let resp = get(TcpStream::connect(("127.0.0.1", port)).await.unwrap(), &abs).await;
    assert!(resp.contains("Coffee"), "absolute-form is not sent to the original destination: {resp}");
    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    c.write_all(format!("CONNECT localhost:{shop} HTTP/1.1\r\nHost: localhost:{shop}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = vec![0u8; 39];
    c.read_exact(&mut head).await.unwrap();
    assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));
    assert!(get(c, &products(&format!("localhost:{shop}"))).await.contains("Coffee"));

    // A client that connected straight to the listener (not redirected) is an ordinary invisible client.
    let direct = transparent_listener(&s, None).await;
    let resp =
        get(TcpStream::connect(("127.0.0.1", direct)).await.unwrap(), &products(&format!("localhost:{shop}"))).await;
    assert!(resp.contains("Coffee"), "{resp}");
    let rows = recorded(&s.project, 3).await;
    assert!(rows.iter().all(|r| r.summary.host == "localhost" && r.summary.port == shop));
}

#[tokio::test]
async fn a_destination_that_is_proxymind_itself_is_not_followed() {
    let s = setup("tp-self", NetConfig::default()).await;
    let (l, port) = listener().await;
    let me: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    tokio::spawn(s.proxy.clone().run_transparent(l, Arc::new(RwLock::new(None::<Redirect>)), Arc::new(Fake(Some(me)))));
    // Treated as not redirected: the Host header decides, and a Host that is the listener itself is the setup page.
    let resp = get(
        TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
        &format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(resp.contains("ProxyMind setup"), "{resp}");
}

/// The real thing, on Linux with root and iptables: a nat rule redirects connections from a range of client source
/// ports to the listener, and `SystemOriginalDst` must report the address the client dialled (a shop on 127.0.0.2).
/// ProxyMind's own outbound connections use other source ports, so the rule does not loop them. Run as root with
/// `PROXYMIND_TEST_TRANSPARENT=1 cargo test -p pm-proxy --test transparent_mode -- real_redirect`.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn real_redirect_reports_the_original_destination() {
    if std::env::var_os("PROXYMIND_TEST_TRANSPARENT").is_none() {
        eprintln!("skipped: set PROXYMIND_TEST_TRANSPARENT=1 (needs root and iptables) to run this test");
        return;
    }
    let shop_listener = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
    let shop = shop_listener.local_addr().unwrap().port();
    tokio::spawn(pm_demo::VulnShop::new().serve(shop_listener));
    let s = setup("tp-real", NetConfig::default()).await;
    let (l, port) = listener().await;
    let provider = Arc::new(pm_proxy::SystemOriginalDst::new(l.local_addr().unwrap()));
    tokio::spawn(s.proxy.clone().run_transparent(l, Arc::new(RwLock::new(None::<Redirect>)), provider));
    let (shop_s, port_s) = (shop.to_string(), port.to_string());
    let rule = [
        "-t",
        "nat",
        "-A",
        "OUTPUT",
        "-p",
        "tcp",
        "-d",
        "127.0.0.2",
        "--dport",
        &shop_s,
        "--sport",
        "40000:40999",
        "-j",
        "REDIRECT",
        "--to-ports",
        &port_s,
    ];
    let add = std::process::Command::new("iptables").args(rule).status().expect("iptables is installed");
    assert!(add.success(), "adding the nat rule (root needed)");
    let attempt = async {
        for src in 40000..40999u16 {
            let sock = tokio::net::TcpSocket::new_v4().unwrap();
            if sock.bind(format!("127.0.0.1:{src}").parse().unwrap()).is_err() {
                continue;
            }
            let c = sock.connect(format!("127.0.0.2:{shop}").parse().unwrap()).await.unwrap();
            return get(c, &products("shop.test")).await;
        }
        panic!("no free source port in the redirected range");
    };
    let resp = tokio::time::timeout(std::time::Duration::from_secs(10), attempt).await;
    let mut del = rule;
    del[2] = "-D";
    let _ = std::process::Command::new("iptables").args(del).status();
    let resp = resp.expect("the redirected request was answered");
    // "shop.test" does not resolve: the answer can only have come through the original destination.
    assert!(resp.contains("Coffee"), "{resp}");
    let rows = recorded(&s.project, 1).await;
    assert_eq!((rows[0].summary.host.as_str(), rows[0].summary.port), ("shop.test", shop));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn the_system_lookup_finds_nothing_for_a_direct_connection() {
    let (l, port) = listener().await;
    let provider = pm_proxy::SystemOriginalDst::new(l.local_addr().unwrap());
    let client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (accepted, _) = l.accept().await.unwrap();
    assert_eq!(provider.original_dst(&accepted), None, "not redirected, not TPROXY");
    drop(client);
    // A listener bound to every address (the usual way to take redirected traffic) behaves the same.
    let any = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
    let any_addr = any.local_addr().unwrap();
    let provider = pm_proxy::SystemOriginalDst::new(any_addr);
    let _client = TcpStream::connect(("127.0.0.1", any_addr.port())).await.unwrap();
    let (accepted, _) = any.accept().await.unwrap();
    assert_eq!(provider.original_dst(&accepted), None);
}
