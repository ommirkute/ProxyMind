//! Requests written as HTTP/3 text (ADR-0021), sent over QUIC to an in-process HTTP/3 server.

mod common;

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::h3_server::{self, H3Server};
use pm_replay::{Endpoint, HostOverride, NetConfig, Network, Sender, UpstreamRule};

fn server() -> H3Server {
    h3_server::start("127.0.0.1:0".parse().unwrap())
}

fn sender(net: NetConfig) -> Sender {
    let n = Network::new();
    n.set(net).unwrap();
    Sender::new(false).unwrap().with_network(n)
}

fn ep(s: &H3Server) -> Endpoint {
    Endpoint::new("https", "localhost", s.port())
}

fn text(r: &pm_replay::Response) -> String {
    String::from_utf8_lossy(&r.raw).into_owned()
}

const GET: &[u8] = b"GET /echo?x=1 HTTP/3\r\nhost: localhost\r\naccept: */*\r\n\r\n";

#[tokio::test]
async fn get_and_post_are_recorded_as_http3_text() {
    let s = server();
    let sender = Sender::new(false).unwrap();
    let r = sender.send(&ep(&s), GET, "GET", None).await.unwrap();
    let t = text(&r);
    assert!(t.starts_with("HTTP/3 201\r\n"), "{t}");
    assert!(t.contains("x-proto: h3\r\n") && t.contains(&format!("alt-svc: h3=\":{}\"; ma=60\r\n", s.port())), "{t}");
    assert!(t.ends_with("\r\n\r\nGET /echo?x=1 localhost "), "{t}");
    assert_eq!(r.head.status, 201);
    assert!(r.sent.is_none() && r.cut_short.is_none());

    // A body goes out and comes back byte for byte; the response is the server's headers in its own order.
    let post =
        b"POST /submit HTTP/3\r\nhost: localhost\r\ncontent-type: application/octet-stream\r\n\r\n\x00\x01body\xff";
    let r = sender.send(&ep(&s), post, "POST", None).await.unwrap();
    let (head, body) = pm_http::split_message(&r.raw);
    assert!(head.starts_with(b"HTTP/3 201\r\n"));
    assert!(body.ends_with(b"\x00\x01body\xff") && body.starts_with(b"POST /submit localhost "), "{body:?}");
    // The same text reads back as an HTTP/3 request.
    assert!(pm_http::h3text::is_http3_response(&r.raw) && pm_http::h3text::alt_svc_h3(&r.raw).unwrap().len() == 1);
    assert_eq!(s.requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn trailers_follow_the_headers() {
    let s = server();
    let r = Sender::new(false)
        .unwrap()
        .send(&ep(&s), b"GET /trailers HTTP/3\r\nhost: localhost\r\n\r\n", "GET", None)
        .await
        .unwrap();
    assert!(text(&r).contains("x-trailer: end\r\n"), "{}", text(&r));
}

#[tokio::test]
async fn certificates_are_checked_only_when_asked() {
    let s = server();
    // The server's certificate is self-signed: accepted by default, refused with verification on.
    assert!(Sender::new(false).unwrap().send(&ep(&s), GET, "GET", None).await.is_ok());
    let strict = Sender::new(true).unwrap().with_timeouts(Duration::from_secs(5), Duration::from_secs(5));
    let e = strict.send(&ep(&s), GET, "GET", None).await.err().expect("verification must fail");
    let msg = format!("{e:#}").to_lowercase();
    assert!(msg.contains("handshake") && (msg.contains("certificate") || msg.contains("unknownissuer")), "{msg}");
    assert_eq!(s.requests.load(Ordering::SeqCst), 1, "the refused connection sent no request");
}

#[tokio::test]
async fn the_response_size_is_limited() {
    let s = server();
    let small = Sender::new(false).unwrap().with_h3_max_body(1024);
    let ok = small.send(&ep(&s), b"GET /big?n=1000 HTTP/3\r\nhost: localhost\r\n\r\n", "GET", None).await.unwrap();
    assert!(ok.raw.ends_with(&[b'x'; 1000]));
    let e = small
        .send(&ep(&s), b"GET /big?n=100000 HTTP/3\r\nhost: localhost\r\n\r\n", "GET", None)
        .await
        .err()
        .expect("over the limit");
    assert!(format!("{e:#}").contains("larger than 1024 bytes"), "{e:#}");
}

#[tokio::test]
async fn a_slow_response_times_out() {
    let s = server();
    let sender = Sender::new(false).unwrap().with_timeouts(Duration::from_secs(5), Duration::from_millis(500));
    let started = std::time::Instant::now();
    let e = sender
        .send(&ep(&s), b"GET /slow HTTP/3\r\nhost: localhost\r\n\r\n", "GET", None)
        .await
        .err()
        .expect("must time out");
    assert!(format!("{e:#}").contains("timed out waiting for the response"), "{e:#}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn nothing_listening_fails_by_the_connect_timeout() {
    // A UDP port nobody serves: QUIC gives no refusal, so the connect timeout ends it.
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    let sender = Sender::new(false).unwrap().with_timeouts(Duration::from_millis(400), Duration::from_secs(5));
    let e = sender.send(&Endpoint::new("https", "127.0.0.1", port), GET, "GET", None).await.err().expect("no server");
    assert!(format!("{e:#}").contains("QUIC handshake"), "{e:#}");
}

#[tokio::test]
async fn the_server_name_is_the_host_and_dns_is_not_asked_for_pinned_hosts() {
    let s = server();
    let net = NetConfig {
        hosts: vec![HostOverride { host: "h3.rebind.test".into(), address: "127.0.0.1".parse().unwrap() }],
        ..Default::default()
    };
    let r = sender(net)
        .send(
            &Endpoint::new("https", "h3.rebind.test", s.port()),
            b"GET / HTTP/3\r\nhost: h3.rebind.test\r\n\r\n",
            "GET",
            None,
        )
        .await
        .unwrap();
    assert!(text(&r).contains("x-sni: h3.rebind.test\r\n"), "SNI is the host name, not the address: {}", text(&r));
}

#[tokio::test]
async fn the_socket_connects_to_the_checked_address() {
    let s = server();
    let net = NetConfig {
        hosts: vec![HostOverride { host: "h3.rebind.test".into(), address: "127.0.0.1".parse().unwrap() }],
        ..Default::default()
    };
    let sender = sender(net);
    let target = Endpoint::new("https", "h3.rebind.test", s.port());
    let req = b"GET / HTTP/3\r\nhost: h3.rebind.test\r\n\r\n";

    // The check sees the addresses in use, and the connection goes to one of them.
    let seen = std::sync::Mutex::new(Vec::<IpAddr>::new());
    let record = |ips: &[IpAddr]| {
        seen.lock().unwrap().extend_from_slice(ips);
        Ok(())
    };
    sender.send(&target, req, "GET", Some(&record)).await.unwrap();
    assert_eq!(*seen.lock().unwrap(), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
    assert_eq!(s.connections.load(Ordering::SeqCst), 1);

    // A denied address: refused before any packet is sent.
    let deny = |ips: &[IpAddr]| Err(format!("{} is in a denied network", ips[0]));
    let e = sender.send(&target, req, "GET", Some(&deny)).await.err().expect("denied");
    assert!(format!("{e:#}").contains("refused before connecting: 127.0.0.1 is in a denied network"), "{e:#}");
    assert_eq!(s.connections.load(Ordering::SeqCst), 1, "no new QUIC connection");

    // A pinned address (transparent mode) is the one checked and used, whatever the name resolves to.
    let seen2 = std::sync::Mutex::new(Vec::<IpAddr>::new());
    let record2 = |ips: &[IpAddr]| {
        seen2.lock().unwrap().extend_from_slice(ips);
        Ok(())
    };
    let pinned = Endpoint::new("https", "unresolvable.invalid", s.port()).with_pin(Some("127.0.0.1".parse().unwrap()));
    Sender::new(false)
        .unwrap()
        .send(&pinned, b"GET / HTTP/3\r\nhost: unresolvable.invalid\r\n\r\n", "GET", Some(&record2))
        .await
        .unwrap();
    assert_eq!(*seen2.lock().unwrap(), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
}

fn rule(via: &str) -> UpstreamRule {
    UpstreamRule { matches: vec!["localhost".into()], via: via.into(), ..Default::default() }
}

#[tokio::test]
async fn hosts_routed_through_a_proxy_refuse_http3() {
    let s = server();
    for via in ["http://127.0.0.1:9", "socks5://127.0.0.1:9"] {
        let sender = sender(NetConfig { upstream_rules: vec![rule(via)], ..Default::default() });
        let e = sender.send(&ep(&s), GET, "GET", None).await.err().expect("refused");
        let msg = format!("{e:#}");
        assert!(msg.contains("HTTP/3 can't go through the upstream proxy 127.0.0.1:9"), "{msg}");
        assert!(msg.contains("QUIC is UDP"), "{msg}");
        assert!(sender.h3_refusal(&ep(&s)).is_some());
    }
    assert_eq!(s.connections.load(Ordering::SeqCst), 0, "nothing went direct behind the rule's back");
    // A `direct` rule, or a host no rule covers, goes out over QUIC.
    let direct = sender(NetConfig { upstream_rules: vec![rule("direct")], ..Default::default() });
    assert!(direct.send(&ep(&s), GET, "GET", None).await.is_ok());
    let other = sender(NetConfig {
        upstream_rules: vec![UpstreamRule { matches: vec!["elsewhere.test".into()], ..rule("http://127.0.0.1:9") }],
        ..Default::default()
    });
    assert!(other.send(&ep(&s), GET, "GET", None).await.is_ok());
}

#[tokio::test]
async fn http3_needs_https_and_is_not_used_for_parallel_sends() {
    let s = server();
    let sender = Sender::new(false).unwrap();
    let e =
        sender.send(&Endpoint::new("http", "localhost", s.port()), GET, "GET", None).await.err().expect("plain http");
    assert!(format!("{e:#}").contains("needs an https target"), "{e:#}");
    let reqs = vec![(GET.to_vec(), "GET".to_string()); 2];
    let results = sender.send_parallel(&ep(&s), &reqs, None).await;
    assert!(results.iter().all(|r| r.as_ref().err().is_some_and(|e| e.to_string().contains("HTTP/3"))));
    let e = sender.send_race(&ep(&s), &reqs, true, None).await.err().expect("races speak HTTP/1.1 and HTTP/2");
    assert!(e.to_string().contains("HTTP/3"), "{e}");
    assert_eq!(s.connections.load(Ordering::SeqCst), 0);
    let _ = SocketAddr::from(([127, 0, 0, 1], 0)); // keeps the import used on all platforms
}
