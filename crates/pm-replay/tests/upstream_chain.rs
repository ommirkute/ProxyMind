//! Ordered upstream rules: which proxy each host goes through, and which address a proxy is asked for. Two test
//! proxies (an HTTP CONNECT proxy and a SOCKS5 proxy) record what they are asked to connect to.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use pm_replay::{Endpoint, NetConfig, Network, Sender, UpstreamRule};
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

/// Answers every request with a fixed body.
async fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                read_head(&mut s).await;
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\necho").await;
            });
        }
    });
    port
}

/// Names the test proxies can resolve by themselves (what "remote DNS" means here).
fn remote_resolve(name: &str) -> String {
    if name == "remote.test" { "127.0.0.1".into() } else { name.to_string() }
}

async fn http_connect_proxy() -> (u16, Seen) {
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
                let target = head.split_whitespace().nth(1).unwrap().to_string();
                seen.lock().unwrap().push(target.clone());
                let (host, port) = target.rsplit_once(':').unwrap();
                let host = remote_resolve(host.trim_matches(['[', ']']));
                let Ok(mut up) = TcpStream::connect(format!("{host}:{port}")).await else {
                    let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
                    return;
                };
                c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
            });
        }
    });
    (port, seen)
}

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
                c.write_all(&[5, 0]).await.unwrap();
                let mut h = [0u8; 4];
                c.read_exact(&mut h).await.unwrap();
                let host = match h[3] {
                    1 => {
                        let mut a = [0u8; 4];
                        c.read_exact(&mut a).await.unwrap();
                        IpAddr::from(a).to_string()
                    }
                    4 => {
                        let mut a = [0u8; 16];
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
                let Ok(mut up) = TcpStream::connect(format!("{}:{port}", remote_resolve(&host))).await else {
                    let _ = c.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    return;
                };
                c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
            });
        }
    });
    (port, seen)
}

fn rule(matches: &[&str], via: &str, remote_dns: bool) -> UpstreamRule {
    UpstreamRule {
        matches: matches.iter().map(|m| m.to_string()).collect(),
        via: via.into(),
        remote_dns,
        ..Default::default()
    }
}

fn sender(rules: Vec<UpstreamRule>, hosts: Vec<(&str, &str)>) -> Sender {
    let n = Network::new();
    n.set(NetConfig {
        upstream_rules: rules,
        hosts: hosts
            .into_iter()
            .map(|(h, a)| pm_replay::HostOverride { host: h.into(), address: a.parse().unwrap() })
            .collect(),
        ..Default::default()
    })
    .unwrap();
    Sender::new(false).unwrap().with_network(n)
}

/// Opens a tunnel to the endpoint and reads the echo server's answer through it.
async fn fetch(s: &Sender, ep: &Endpoint, check: Option<pm_replay::AddrCheck<'_>>) -> anyhow::Result<String> {
    let mut io = s.connect_with_endpoint(ep, check).await?;
    io.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await?;
    let mut out = Vec::new();
    io.read_to_end(&mut out).await?;
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[tokio::test]
async fn first_matching_rule_decides_and_the_default_is_direct() {
    let echo = echo_server().await;
    let (http, http_seen) = http_connect_proxy().await;
    let (socks, socks_seen) = socks5_proxy().await;
    let rules = vec![
        rule(&["localhost"], &format!("socks5://127.0.0.1:{socks}"), false),
        rule(&["127.0.0.0/8"], &format!("http://127.0.0.1:{http}"), false),
        rule(&["remote.test", "*.remote.test"], &format!("socks5://127.0.0.1:{socks}"), true),
        rule(&[], "direct", false),
    ];
    let s = sender(rules, vec![("direct.test", "127.0.0.1")]);
    let net = s.network();
    assert_eq!(net.resolve("localhost").map(|r| r.0), Some(0));
    assert_eq!(net.resolve("127.0.0.1").map(|r| r.0), Some(1));
    assert_eq!(net.resolve("a.remote.test"), Some((2, Some("*.remote.test".into()))));
    assert_eq!(net.resolve("direct.test"), Some((3, None)));

    // localhost: SOCKS5 without remote DNS: the proxy is asked for the address that was checked.
    let checked = Arc::new(Mutex::new(Vec::<IpAddr>::new()));
    let log = checked.clone();
    let check = move |ips: &[IpAddr]| -> Result<(), String> {
        log.lock().unwrap().extend_from_slice(ips);
        Ok(())
    };
    let body = fetch(&s, &Endpoint::new("tcp", "localhost", echo), Some(&check)).await.unwrap();
    assert!(body.ends_with("echo"));
    let asked = socks_seen.lock().unwrap().clone();
    assert!(!asked.is_empty() && asked.iter().all(|a| !a.starts_with("localhost")), "asked for names: {asked:?}");
    let checked = checked.lock().unwrap().clone();
    for a in &asked {
        let ip: IpAddr = a.rsplit_once(':').unwrap().0.trim_matches(['[', ']']).parse().unwrap();
        assert!(checked.contains(&ip), "{a} was asked for but never checked ({checked:?})");
    }
    assert!(http_seen.lock().unwrap().is_empty(), "the HTTP proxy was not used for localhost");

    // 127.0.0.1: the CIDR rule, an HTTP CONNECT proxy asked for the checked address.
    let ok = |_: &[IpAddr]| -> Result<(), String> { Ok(()) };
    fetch(&s, &Endpoint::new("tcp", "127.0.0.1", echo), Some(&ok)).await.unwrap();
    assert_eq!(http_seen.lock().unwrap().clone(), vec![format!("127.0.0.1:{echo}")]);

    // remote.test: remote DNS: the SOCKS5 proxy gets the name.
    let before = socks_seen.lock().unwrap().len();
    fetch(&s, &Endpoint::new("tcp", "remote.test", echo), None).await.unwrap();
    assert_eq!(socks_seen.lock().unwrap()[before], format!("remote.test:{echo}"));

    // Anything else is direct: neither proxy sees it.
    let (a, b) = (socks_seen.lock().unwrap().len(), http_seen.lock().unwrap().len());
    fetch(&s, &Endpoint::new("tcp", "direct.test", echo), Some(&ok)).await.unwrap();
    assert_eq!((socks_seen.lock().unwrap().len(), http_seen.lock().unwrap().len()), (a, b));
}

#[tokio::test]
async fn denied_addresses_never_reach_a_proxy_unless_remote_dns_is_chosen() {
    let echo = echo_server().await;
    let (socks, socks_seen) = socks5_proxy().await;
    let s = sender(vec![rule(&["localhost"], &format!("socks5://127.0.0.1:{socks}"), false)], vec![]);
    let deny = |_: &[IpAddr]| -> Result<(), String> { Err("loopback is denied".into()) };
    let e = fetch(&s, &Endpoint::new("tcp", "localhost", echo), Some(&deny)).await.err().unwrap();
    assert!(format!("{e:#}").contains("refused before connecting"), "{e:#}");
    assert!(socks_seen.lock().unwrap().is_empty(), "the check runs before the proxy is contacted");
}

#[tokio::test]
async fn a_pinned_address_replaces_dns_for_direct_connections_and_is_checked() {
    let echo = echo_server().await;
    let s = sender(vec![], vec![]);
    let seen = Arc::new(Mutex::new(Vec::<IpAddr>::new()));
    let log = seen.clone();
    let check = move |ips: &[IpAddr]| -> Result<(), String> {
        log.lock().unwrap().extend_from_slice(ips);
        Ok(())
    };
    // "never-resolves.test" has no DNS record: only the pin makes the connection possible.
    let ep = Endpoint::new("tcp", "never-resolves.test", echo).with_pin(Some("127.0.0.1".parse().unwrap()));
    assert!(fetch(&s, &ep, Some(&check)).await.unwrap().ends_with("echo"));
    assert_eq!(seen.lock().unwrap().clone(), vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
}

#[tokio::test]
async fn rules_can_be_validated_and_old_settings_still_load() {
    // The single-upstream form becomes one bypass rule and one proxy rule.
    let old: NetConfig = serde_json::from_str(
        r#"{"upstream":{"kind":"socks5","host":"127.0.0.1","port":1080,"username":"u","password":"p","remote_dns":true,"bypass":["localhost","*.lan"]}}"#,
    )
    .unwrap();
    let n = old.normalized().unwrap();
    assert!(n.upstream.is_none());
    assert_eq!(n.upstream_rules.len(), 2);
    assert_eq!(
        (n.upstream_rules[0].via.as_str(), n.upstream_rules[0].matches.clone()),
        ("direct", vec!["localhost".into(), "*.lan".into()])
    );
    let r = &n.upstream_rules[1];
    assert_eq!(
        (r.via.as_str(), r.username.as_str(), r.password.as_str(), r.remote_dns),
        ("socks5://127.0.0.1:1080", "u", "p", true)
    );
    assert!(r.matches.is_empty());
    assert_eq!(n.resolve("localhost").map(|r| r.0), Some(0));
    assert_eq!(n.resolve("anything.test").map(|r| r.0), Some(1));
    n.validate().unwrap();
    let text = serde_json::to_string(&n).unwrap();
    assert!(!text.contains("\"upstream\":"), "the old field is not written back: {text}");
    assert_eq!(serde_json::from_str::<NetConfig>(&text).unwrap(), n);

    // Mistakes are named.
    let bad_via = NetConfig { upstream_rules: vec![rule(&["a"], "ftp://x:1", false)], ..Default::default() };
    assert!(bad_via.validate().is_err());
    let creds_in_url = NetConfig { upstream_rules: vec![rule(&["a"], "http://u:p@x:1", false)], ..Default::default() };
    assert!(creds_in_url.validate().is_err());
    let catch_all_first = NetConfig {
        upstream_rules: vec![rule(&[], "direct", false), rule(&["a"], "http://x:1", false)],
        ..Default::default()
    };
    assert!(format!("{:#}", catch_all_first.validate().unwrap_err()).contains("must be the last"));
    let bad_cidr = NetConfig { upstream_rules: vec![rule(&["10.0.0.0/33"], "direct", false)], ..Default::default() };
    assert!(bad_cidr.validate().is_err());
    let both = NetConfig {
        upstream: Some(Default::default()),
        upstream_rules: vec![rule(&[], "direct", false)],
        ..Default::default()
    };
    assert!(both.normalized().is_err());
    let masked = NetConfig {
        upstream_rules: vec![UpstreamRule {
            password: "hunter2".into(),
            username: "u".into(),
            ..rule(&[], "http://x:1", false)
        }],
        ..Default::default()
    };
    assert_eq!(masked.masked().upstream_rules[0].password, "********");
    assert!(!format!("{:?}", masked.masked()).contains("hunter2"));
}

#[test]
fn match_patterns() {
    use pm_replay::net::pattern_matches as m;
    assert!(m("*", "x.test") && m("*.corp.test", "corp.test") && m("*.corp.test", "a.b.corp.test"));
    assert!(m("api-?.test", "api-1.test") && !m("api-?.test", "api-12.test"));
    assert!(m("*.test", "A.TEST") && m("web*.corp.test", "web01.corp.test") && !m("web*.corp.test", "db.corp.test"));
    assert!(m("10.0.0.0/8", "10.9.8.7") && !m("10.0.0.0/8", "11.0.0.1") && !m("10.0.0.0/8", "ten.test"));
    assert!(m("192.168.1.0/24", "192.168.1.200") && !m("192.168.1.0/24", "192.168.2.1"));
    assert!(m("fd00::/8", "[fd12::1]") && !m("fd00::/8", "fe80::1") && !m("fd00::/8", "10.0.0.1"));
    assert!(m("10.0.0.0/8", "::ffff:10.1.1.1"), "mapped addresses are compared as IPv4");
    assert!(m("0.0.0.0/0", "8.8.8.8") && m("1.2.3.4/32", "1.2.3.4") && !m("1.2.3.4/32", "1.2.3.5"));
}
