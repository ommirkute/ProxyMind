//! Responses stream through the proxy as they arrive; 100-continue is
//! answered by the proxy.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pm_proxy::{Proxy, Recorder};
use pm_store::Store;
use pm_tls::CertAuthority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn proxy(name: &str) -> (u16, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("pm-proxy-stream-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let project = dir.join("p.pmproj");
    let (recorder, _writer) = Recorder::spawn(Store::open(&project).unwrap());
    let p = Proxy::new(ca, recorder, false).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(p.run(l));
    (port, project)
}

/// A server that sends one event, waits, then sends a second and ends.
async fn slow_events() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
                    )
                    .await;
                let _ = s.write_all(b"e\r\ndata: first\n\n\r\n").await;
                tokio::time::sleep(Duration::from_millis(1500)).await;
                let _ = s.write_all(b"f\r\ndata: second\n\n\r\n0\r\n\r\n").await;
            });
        }
    });
    port
}

#[tokio::test]
async fn events_reach_the_client_before_the_response_ends() {
    let (proxy_port, project) = proxy("sse").await;
    let backend = slow_events().await;
    let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    c.write_all(format!("GET http://127.0.0.1:{backend}/events HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
    let started = Instant::now();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    while !got.windows(11).any(|w| w == b"data: first") {
        let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await.unwrap().unwrap();
        assert!(n > 0, "closed early");
        got.extend_from_slice(&buf[..n]);
    }
    assert!(started.elapsed() < Duration::from_millis(1000), "the first event waited for the whole response");
    while !got.ends_with(b"0\r\n\r\n") {
        let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await.unwrap().unwrap();
        assert!(n > 0, "closed early");
        got.extend_from_slice(&buf[..n]);
    }
    assert!(got.windows(12).any(|w| w == b"data: second"));
    // History has the whole stream, byte for byte.
    for _ in 0..50 {
        let s = Store::open(&project).unwrap();
        if let Some(row) = s.list_exchanges(1, None).unwrap().first() {
            let ex = s.get_exchange(row.id).unwrap().unwrap();
            let resp = ex.response.unwrap();
            assert!(resp.ends_with(b"f\r\ndata: second\n\n\r\n0\r\n\r\n"), "{}", String::from_utf8_lossy(&resp));
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not recorded");
}

#[tokio::test]
async fn the_proxy_answers_100_continue() {
    let (proxy_port, _) = proxy("expect").await;
    // The backend never sends 100 Continue: it reads the body, then answers.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        while !got.ends_with(b"hello") {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                return;
            }
            got.extend_from_slice(&buf[..n]);
        }
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
    });
    let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    c.write_all(
        format!(
            "POST http://127.0.0.1:{backend}/up HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(2), c.read(&mut buf)).await.expect("no 100 Continue").unwrap();
    assert!(buf[..n].starts_with(b"HTTP/1.1 100 Continue\r\n\r\n"));
    c.write_all(b"hello").await.unwrap();
    let mut got = buf[..n].to_vec();
    while !got.ends_with(b"ok") {
        let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await.unwrap().unwrap();
        assert!(n > 0);
        got.extend_from_slice(&buf[..n]);
    }
}

/// A keep-alive backend that counts connections. With `drop_after_each`, it
/// closes every connection after one response without saying so (like a
/// server whose idle timeout just expired).
async fn counting_backend(drop_after_each: bool) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c2 = count.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                loop {
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match s.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&tmp[..n]),
                        }
                    }
                    let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    buf.drain(..end);
                    if s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await.is_err() || drop_after_each
                    {
                        return;
                    }
                }
            });
        }
    });
    (port, count)
}

async fn get_via(proxy_port: u16, backend: u16, n: usize) -> usize {
    let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    let mut ok = 0;
    for _ in 0..n {
        c.write_all(format!("GET http://127.0.0.1:{backend}/ HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 1024];
        while !got.ends_with(b"\r\n\r\nok") {
            let n = tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await.unwrap().unwrap();
            if n == 0 {
                return ok;
            }
            got.extend_from_slice(&buf[..n]);
        }
        ok += 1;
    }
    ok
}

#[tokio::test]
async fn server_connections_are_reused_and_dead_ones_retried() {
    let (proxy_port, _) = proxy("pool").await;
    let (backend, count) = counting_backend(false).await;
    assert_eq!(get_via(proxy_port, backend, 10).await, 10);
    assert_eq!(get_via(proxy_port, backend, 5).await, 5, "a second browser connection");
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1, "one server connection for all 15");

    // The server drops each connection after its response: the kept one is
    // dead next time, and the proxy notices and sends on a new one.
    let (flaky, opened) = counting_backend(true).await;
    assert_eq!(get_via(proxy_port, flaky, 4).await, 4);
    assert_eq!(opened.load(std::sync::atomic::Ordering::SeqCst), 4);
}
