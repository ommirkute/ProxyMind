//! Intercept queue and match-and-replace rules through the real proxy.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pm_proxy::intercept::Decision;
use pm_proxy::rewrite::Part;
use pm_proxy::{InterceptQueue, InterceptSettings, Proxy, Recorder, RewriteRule, Rewriter};
use pm_store::Store;
use pm_tls::CertAuthority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn backend(seen: Arc<Mutex<Vec<Vec<u8>>>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                seen.lock().unwrap().push(buf[..n].to_vec());
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\noriginal").await;
            });
        }
    });
    port
}

async fn setup(name: &str) -> (u16, Arc<InterceptQueue>, std::path::PathBuf) {
    setup_with(name, None).await
}

async fn setup_with(name: &str, rewrite: Option<Arc<Rewriter>>) -> (u16, Arc<InterceptQueue>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("pm-intercept-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let project = dir.join("p.pmproj");
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let q = Arc::new(InterceptQueue::new());
    q.set_settings(InterceptSettings { enabled: true, in_scope_only: false, ..Default::default() });
    let proxy = Proxy::with_hooks(
        ca,
        recorder,
        false,
        pm_proxy::Hooks { intercept: Some(q.clone()), rewrite, ..Default::default() },
    )
    .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));
    (port, q, project)
}

async fn send(proxy: u16, req: String) -> tokio::task::JoinHandle<String> {
    tokio::spawn(async move {
        let mut c = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
        c.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_string(&mut out)).await;
        out
    })
}

async fn wait_held(q: &InterceptQueue) -> pm_proxy::intercept::Held {
    for _ in 0..200 {
        if let Some(h) = q.held().pop() {
            return h;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("nothing was held");
}

#[tokio::test]
async fn edited_request_reaches_the_server_byte_for_byte() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone()).await;
    let (proxy, q, _) = setup("edit").await;
    let client = send(proxy, format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\nHost: x\r\n\r\n")).await;
    let held = wait_held(&q).await;
    assert_eq!(held.path, "/a");
    assert!(seen.lock().unwrap().is_empty(), "nothing sent while held");
    let edited = b"GET /b?admin=1 HTTP/1.1\r\nHost: x\r\nX-Edited:  yes\r\n\r\n".to_vec();
    q.decide(held.id, Decision::Forward(Some(edited.clone())));
    assert!(client.await.unwrap().ends_with("original"));
    assert_eq!(seen.lock().unwrap()[0], edited);
}

#[tokio::test]
async fn dropped_request_never_reaches_the_server() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone()).await;
    let (proxy, q, _) = setup("drop").await;
    let client = send(proxy, format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\nHost: x\r\n\r\n")).await;
    let held = wait_held(&q).await;
    q.decide(held.id, Decision::Drop);
    assert!(client.await.unwrap().starts_with("HTTP/1.1 403"));
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn edited_response_reaches_the_browser_and_the_original_is_recorded() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone()).await;
    let (proxy, q, project) = setup("resp").await;
    q.set_settings(InterceptSettings {
        enabled: true,
        in_scope_only: false,
        requests: false,
        responses: true,
        ..Default::default()
    });
    let client = send(proxy, format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\nHost: x\r\n\r\n")).await;
    let held = wait_held(&q).await;
    assert!(held.raw.ends_with("original"));
    q.decide(held.id, Decision::Forward(Some(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nEDITED".to_vec())));
    assert!(client.await.unwrap().ends_with("EDITED"));
    for _ in 0..50 {
        let s = Store::open(&project).unwrap();
        if let Some(e) = s.list_exchanges(1, None).unwrap().first() {
            let ex = s.get_exchange(e.id).unwrap().unwrap();
            assert!(ex.response.unwrap().ends_with(b"original"));
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not recorded");
}

#[tokio::test]
async fn rules_rewrite_traffic_before_the_intercept_queue_sees_it() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone()).await;
    let rw = Arc::new(Rewriter::new());
    rw.set_rules(vec![
        RewriteRule { replace: "X-Pentest: proxymind".into(), in_scope_only: false, ..Default::default() },
        RewriteRule {
            part: Part::ResponseBody,
            pattern: "original".into(),
            replace: "rewritten!".into(),
            in_scope_only: false,
            ..Default::default()
        },
    ])
    .unwrap();
    let (proxy, q, project) = setup_with("rules", Some(rw)).await;
    let client = send(proxy, format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\nHost: x\r\n\r\n")).await;
    let held = wait_held(&q).await;
    assert!(held.raw.contains("X-Pentest: proxymind"), "the human sees the rewritten request: {}", held.raw);
    q.decide(held.id, Decision::Forward(None));
    let out = client.await.unwrap();
    assert!(out.contains("Content-Length: 10\r\n") && out.ends_with("rewritten!"), "{out}");
    assert_eq!(seen.lock().unwrap()[0], b"GET /a HTTP/1.1\r\nHost: x\r\nX-Pentest: proxymind\r\n\r\n".to_vec());
    for _ in 0..50 {
        let s = Store::open(&project).unwrap();
        if let Some(e) = s.list_exchanges(1, None).unwrap().first() {
            let ex = s.get_exchange(e.id).unwrap().unwrap();
            assert!(ex.request.ends_with(b"X-Pentest: proxymind\r\n\r\n"), "records what was sent");
            assert!(ex.response.unwrap().ends_with(b"original"), "records what the server said");
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not recorded");
}
