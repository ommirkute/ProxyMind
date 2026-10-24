//! "Record only in-scope traffic": the proxy still forwards everything.

use std::sync::Arc;
use std::time::Duration;

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_proxy::{Proxy, Recorder};
use pm_service::pm_store::Store;
use pm_service::{RecordingSettings, Service};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut t, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 2048];
                let _ = t.read(&mut b).await;
                let _ = t.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
            });
        }
    });
    port
}

async fn get(proxy: u16, port: u16, path: &str) -> String {
    let mut c = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    let req = format!("GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    c.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_string(&mut out)).await;
    out
}

#[tokio::test]
async fn out_of_scope_traffic_is_forwarded_but_not_recorded() {
    let (inside, outside) = (backend().await, backend().await);
    let dir = std::env::temp_dir().join(format!("pm-rec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.pmproj");
    let roe = format!("version: 1\nscope:\n  include: [\"http://127.0.0.1:{inside}/\"]\n");
    let svc = Arc::new(Service::new(Store::open(&project).unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    svc.attach_recorder(&recorder).unwrap();
    let ca = Arc::new(pm_tls::CertAuthority::load_or_create(&dir).unwrap());
    let proxy = Proxy::new(ca, recorder, false).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));

    let human = Actor::parse("human:tester").unwrap();
    assert!(svc.recording_set(&Actor::parse("agent:x").unwrap(), RecordingSettings { in_scope_only: true }).is_err());
    svc.recording_set(&human, RecordingSettings { in_scope_only: true }).unwrap();
    let t = pm_service::pm_policy::Target::from_parts("http", "127.0.0.1", inside, "/target").unwrap();
    eprintln!("DEBUG scope: {:?}", svc.policy().scope_check(&t));
    let ex = pm_service::pm_store::NewExchange {
        ts_ms: 0,
        duration_ms: None,
        source: "proxy".into(),
        actor_id: "human:local".into(),
        scheme: "http".into(),
        host: "127.0.0.1".into(),
        port: inside,
        method: "GET".into(),
        path: "/target".into(),
        status: None,
        request: vec![],
        response: None,
        error: None,
        identity: None,
        hypothesis_id: None,
    };
    eprintln!("DEBUG should_record: {}", svc.should_record(&ex));
    assert!(get(port, outside, "/elsewhere").await.ends_with("ok"), "still proxied");
    let t0 = std::time::Instant::now();
    let r = get(port, inside, "/target").await;
    eprintln!("DEBUG target resp {:?} in {:?}", r, t0.elapsed());
    assert!(r.ends_with("ok"));
    svc.recording_set(&human, RecordingSettings { in_scope_only: false }).unwrap();
    assert!(get(port, outside, "/again").await.ends_with("ok"));

    let mut paths = Vec::new();
    for _ in 0..100 {
        paths = Store::open(&project).unwrap().list_exchanges(10, None).unwrap().into_iter().map(|e| e.path).collect();
        if paths.len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let st = Store::open(&project).unwrap();
    eprintln!(
        "DEBUG count {} rows {:?}",
        st.count_exchanges().unwrap(),
        st.list_exchanges(10, None).unwrap().iter().map(|e| (e.id, e.path.clone(), e.port)).collect::<Vec<_>>()
    );
    eprintln!("DEBUG ports inside {inside} outside {outside}");
    assert_eq!(paths, vec!["/again".to_string(), "/target".to_string()]);
}
