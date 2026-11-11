//! Passive recon against stand-ins: a local DNS server and a local "archive".
//! Neither lookup sends anything to the target, and both stay within scope.

use pm_service::Service;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

fn service() -> Service {
    let roe = "version: 1\nscope:\n  include: [\"https://shop.test/\", \"https://*.corp.test/\"]\n";
    Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(roe).unwrap())).unwrap()
}

/// Answers each query with records for the asked type (the name as a pointer to the question).
async fn dns_server() -> std::net::SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let q = &buf[..n];
            let qend = n - 11; // without the OPT record
            let qtype = u16::from_be_bytes([q[qend - 4], q[qend - 3]]);
            let name = String::from_utf8_lossy(&q[12..qend - 4]).to_string();
            let answers: Vec<(u16, Vec<u8>)> = match qtype {
                1 => vec![(1, vec![10, 0, 0, 5])],
                15 => vec![(15, b"\x00\x0a\x02mx\xc0\x0c".to_vec())],
                16 if name.contains("_dmarc") => vec![(16, b"\x15v=DMARC1; p=none; x=y".to_vec())],
                16 => vec![(16, b"\x0bv=spf1 +all".to_vec())],
                5 => vec![(5, b"\x04shop\x09herokuapp\x03com\x00".to_vec())],
                _ => vec![],
            };
            let mut r = q[..qend].to_vec();
            r[2] = 0x81;
            r[3] = 0x80;
            r[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
            r[10..12].copy_from_slice(&[0, 0]);
            for (t, data) in answers {
                r.extend_from_slice(&[0xc0, 12]);
                r.extend_from_slice(&t.to_be_bytes());
                r.extend_from_slice(&[0, 1, 0, 0, 1, 44]);
                r.extend_from_slice(&(data.len() as u16).to_be_bytes());
                r.extend_from_slice(&data);
            }
            let _ = sock.send_to(&r, from).await;
        }
    });
    addr
}

#[tokio::test]
async fn dns_records_with_notes_only_in_scope() {
    let s = service();
    let resolver = dns_server().await;
    let r = s.recon_dns(&human(), "shop.test", Some(resolver)).await.unwrap();
    let kinds: Vec<&str> = r.records.iter().map(|r| r.kind.as_str()).collect();
    for k in ["A", "MX", "TXT", "CNAME"] {
        assert!(kinds.contains(&k), "{k} in {kinds:?}");
    }
    let notes = r.notes.join("\n");
    assert!(notes.contains("+all"), "{notes}");
    assert!(notes.contains("p=none"), "{notes}");
    assert!(notes.contains("no CAA"), "{notes}");
    assert!(notes.contains("herokuapp.com"), "{notes}");

    // Parent domains of a wildcard and hosts under it are allowed; others are not.
    assert!(s.recon_dns(&human(), "api.corp.test", Some(resolver)).await.is_ok());
    assert!(s.recon_dns(&human(), "corp.test", Some(resolver)).await.is_ok());
    for bad in ["evil.test", "test", "shop.test.evil.test"] {
        assert!(s.recon_dns(&human(), bad, Some(resolver)).await.is_err(), "{bad}");
    }
    let audit = s.audit_list(100).unwrap();
    assert_eq!(audit.iter().filter(|a| a.action == "recon_dns").count(), 3);
}

/// A one-shot HTTP server that answers every request with `body`.
async fn archive(body: &'static str) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let mut buf = vec![0u8; 4096];
            let n = c.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(head.starts_with("GET /cdx/search/cdx?url=shop.test/*&output=json"), "{head}");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = c.write_all(resp.as_bytes()).await;
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn wayback_lists_interesting_urls_first_for_the_host_only() {
    let s = service();
    let base = archive(
        r#"[["original","statuscode","mimetype","timestamp"],
            ["https://shop.test/about","200","text/html","20190101000000"],
            ["https://shop.test/backup/db.sql","200","text/plain","20180101000000"],
            ["https://cdn.other.test/x.js","200","application/javascript","20180101000000"],
            ["https://shop.test/api/v1/users?id=1","200","application/json","20200101000000"]]"#,
    )
    .await;
    let r = s.recon_wayback(&human(), "shop.test", 10, Some(&base)).await.unwrap();
    assert_eq!(r.total, 3, "other hosts dropped: {r:?}");
    assert_eq!(r.interesting, 2);
    assert!(r.captures[0].capture.note.is_some() && r.captures[1].capture.note.is_some());
    assert_eq!(r.captures[2].capture.url, "https://shop.test/about");
    assert!(r.captures.iter().all(|c| !c.known));

    let r = s.recon_wayback(&human(), "shop.test", 1, Some(&base)).await.unwrap();
    assert_eq!((r.total, r.captures.len()), (3, 1));

    assert!(s.recon_wayback(&human(), "evil.test", 10, Some(&base)).await.is_err());
    assert!(s.audit_list(100).unwrap().iter().any(|a| a.action == "recon_wayback"));
}
