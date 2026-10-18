//! Race sends: the single-packet attack over HTTP/2, and last-byte sync
//! for servers without it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use pm_replay::race::RaceMode;
use pm_replay::{Endpoint, Sender};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct Seen {
    /// When each stream's headers arrived, and when its last frame did.
    headers: Vec<Instant>,
    done: Vec<Instant>,
}

/// An h2c server that notes arrival times and answers "body=<body>".
async fn h2c_server(seen: Arc<Mutex<Seen>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (t, _) = l.accept().await.unwrap();
        let mut conn = h2::server::handshake(t).await.unwrap();
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            seen.lock().unwrap().headers.push(Instant::now());
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut body = req.into_body();
                let mut data = Vec::new();
                while let Some(Ok(c)) = body.data().await {
                    let _ = body.flow_control().release_capacity(c.len());
                    data.extend_from_slice(&c);
                }
                seen.lock().unwrap().done.push(Instant::now());
                let mut s =
                    respond.send_response(http::Response::builder().status(200).body(()).unwrap(), false).unwrap();
                s.send_data(Bytes::from(format!("body={}", String::from_utf8_lossy(&data))), true).unwrap();
            });
        }
    });
    port
}

#[tokio::test]
async fn single_packet_holds_every_final_frame_until_all_requests_are_in() {
    let seen = Arc::new(Mutex::new(Seen::default()));
    let port = h2c_server(seen.clone()).await;
    let ep = Endpoint::new("http", "127.0.0.1", port);
    let reqs: Vec<(Vec<u8>, String)> = (0..10)
        .map(|i| {
            let body = format!("coupon=SAVE10&n={i}");
            let raw = format!(
                "POST /redeem HTTP/1.1\r\nHost: shop\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            (raw.into_bytes(), "POST".to_string())
        })
        .chain(std::iter::once((b"GET /balance HTTP/1.1\r\nHost: shop\r\n\r\n".to_vec(), "GET".to_string())))
        .collect();
    // h2c: plain HTTP with prior knowledge.
    let out = Sender::new(false).unwrap().send_race(&ep, &reqs, true, None).await.unwrap();
    assert_eq!(out.mode, RaceMode::SinglePacket);
    assert_eq!(out.results.len(), 11);
    for (i, r) in out.results.iter().enumerate() {
        let r = r.as_ref().unwrap();
        let text = String::from_utf8_lossy(&r.raw);
        assert!(text.starts_with("HTTP/2 200"), "{text}");
        if i < 10 {
            assert!(text.ends_with(&format!("body=coupon=SAVE10&n={i}")), "bodies arrive whole: {text}");
            let sent = String::from_utf8(r.sent.clone().unwrap()).unwrap();
            assert!(sent.starts_with("POST /redeem HTTP/2\r\nhost: shop\r\n"), "recorded as sent: {sent}");
        }
    }
    let s = seen.lock().unwrap();
    let last_header = *s.headers.iter().max().unwrap();
    let first_done = *s.done.iter().min().unwrap();
    let last_done = *s.done.iter().max().unwrap();
    assert!(last_header < first_done, "no request completed before every request had arrived");
    assert!(
        last_done.duration_since(first_done) < Duration::from_millis(100),
        "final frames arrive together (spread {:?})",
        last_done.duration_since(first_done)
    );
}

#[tokio::test]
async fn http1_servers_get_last_byte_sync() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = s.read(&mut buf).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                }
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
            });
        }
    });
    // An HTTP/1.1 server answering h2c prior knowledge garbage would fail, so
    // plain-HTTP races that don't prefer HTTP/2 use last-byte sync directly.
    let ep = Endpoint::new("http", "127.0.0.1", port);
    let reqs = vec![(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(), "GET".to_string()); 3];
    let out = Sender::new(false).unwrap().send_race(&ep, &reqs, false, None).await.unwrap();
    assert_eq!(out.mode, RaceMode::LastByte);
    assert!(out.results.iter().all(|r| r.as_ref().unwrap().head.status == 200));
}
