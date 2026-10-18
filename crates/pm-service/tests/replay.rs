//! Replay through the service against a local server.

use std::sync::{Arc, Mutex};

use pm_service::pm_ai::View;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{HistoryFilter, NewExchange, Store};
use pm_service::{ReplayRequest, ReplayResult, Service};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Server that records raw requests and sets a session cookie.
async fn server(seen: Arc<Mutex<Vec<String>>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap();
                seen.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let body = r#"{"id":1,"owner":"alice"}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nSet-Cookie: session=SuperSecretSession123; Path=/\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

fn service(roe: &str) -> Service {
    Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(roe).unwrap())).unwrap()
}

const ROE: &str = r#"
version: 1
scope:
  include: ["http://127.0.0.1:*/"]
"#;

fn agent() -> Actor {
    Actor::parse("agent:test").unwrap()
}

#[tokio::test]
async fn agent_get_is_sent_recorded_and_redacted() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = server(seen.clone()).await;
    let s = service(ROE);
    let r = s
        .replay_send(
            &agent(),
            ReplayRequest {
                url: Some(format!("http://127.0.0.1:{port}")),
                raw: Some("GET /api/orders/1 HTTP/1.1\nHost: 127.0.0.1\n\n".into()),
                view: Some(View::Full),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let ReplayResult::Sent { exchange_id, view, .. } = r else { panic!("{r:?}") };
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("SuperSecretSession123"), "agent saw the secret: {json}");
    assert!(json.contains("{{secret:cookie_session_1}}"));
    assert!(seen.lock().unwrap()[0].starts_with("GET /api/orders/1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));

    let page = s.history_search(&agent(), &HistoryFilter { actor: Some("agent:test".into()), ..Default::default() });
    assert_eq!(page.unwrap().exchanges[0].id, exchange_id);
}

#[tokio::test]
async fn placeholders_are_swapped_for_real_secrets_when_sending() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = server(seen.clone()).await;
    let s = service(ROE);
    // First response teaches the redactor the cookie.
    let first = s
        .replay_send(
            &agent(),
            ReplayRequest {
                url: Some(format!("http://127.0.0.1:{port}")),
                raw: Some("GET /login HTTP/1.1\r\nHost: x\r\n\r\n".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(first, ReplayResult::Sent { .. }));
    // The agent uses the placeholder it was shown.
    let r = s
        .replay_send(
            &agent(),
            ReplayRequest {
                url: Some(format!("http://127.0.0.1:{port}")),
                raw: Some("GET /me HTTP/1.1\r\nHost: x\r\nCookie: session={{secret:cookie_session_1}}\r\n\r\n".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(r, ReplayResult::Sent { .. }), "{r:?}");
    assert!(seen.lock().unwrap()[1].contains("Cookie: session=SuperSecretSession123\r\n"));

    // Made-up placeholders are refused before anything is sent.
    let err = s
        .replay_send(
            &agent(),
            ReplayRequest {
                url: Some(format!("http://127.0.0.1:{port}")),
                raw: Some("GET / HTTP/1.1\r\nCookie: a={{secret:invented_1}}\r\n\r\n".into()),
                ..Default::default()
            },
        )
        .await;
    assert!(err.is_err());
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn agent_post_needs_approval_and_runs_once_approved() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = server(seen.clone()).await;
    let s = service(ROE);
    let req = ReplayRequest {
        url: Some(format!("http://127.0.0.1:{port}")),
        raw: Some("POST /api/orders HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n{\"qty\":-1}".into()),
        ..Default::default()
    };
    let ReplayResult::PendingApproval { approval_id, .. } = s.replay_send(&agent(), req.clone()).await.unwrap() else {
        panic!("expected approval")
    };
    assert!(seen.lock().unwrap().is_empty(), "nothing sent before approval");
    s.decide_approval(&approval_id, &Actor::parse("human:omkar").unwrap(), true).unwrap();
    let approved = ReplayRequest { approval_id: Some(approval_id), ..req };
    let r = s.replay_send(&agent(), approved).await.unwrap();
    assert!(matches!(r, ReplayResult::Sent { .. }), "{r:?}");
    // Content-Length was fixed to the real body length.
    assert!(seen.lock().unwrap()[0].contains("Content-Length: 10\r\n"));
}

#[tokio::test]
async fn out_of_scope_and_denied_networks_are_never_contacted() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = server(seen.clone()).await;

    let s = service(ROE);
    let r = s
        .replay_send(
            &agent(),
            ReplayRequest {
                url: Some(format!("http://localhost:{port}")),
                raw: Some("GET / HTTP/1.1\r\n\r\n".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(r, ReplayResult::Denied { .. }), "localhost is not 127.0.0.1 in scope terms: {r:?}");

    // In scope by name, but resolves into a denied network (DNS rebinding).
    let s = service(
        r#"
version: 1
scope:
  include: ["http://localhost:*/"]
  deny_networks: ["127.0.0.0/8", "::1/128"]
"#,
    );
    let r = s
        .replay_send(
            &agent(),
            ReplayRequest {
                url: Some(format!("http://localhost:{port}")),
                raw: Some("GET / HTTP/1.1\r\n\r\n".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let ReplayResult::Failed { error, .. } = r else { panic!("{r:?}") };
    assert!(error.contains("denied network"), "{error}");
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn resending_a_recorded_exchange_uses_its_target() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = server(seen.clone()).await;
    let mut store = Store::open_in_memory().unwrap();
    let id = store
        .insert_exchange(&NewExchange {
            ts_ms: 0,
            duration_ms: None,
            source: "proxy".into(),
            actor_id: "human:local".into(),
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port,
            method: "GET".into(),
            path: "/orig".into(),
            status: Some(200),
            request: b"GET /orig HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(),
            response: None,
            error: None,
            identity: None,
        })
        .unwrap();
    let s = Service::new(store, Policy::new(Roe::parse(ROE).unwrap())).unwrap();
    let r = s.replay_send(&agent(), ReplayRequest { exchange_id: Some(id), ..Default::default() }).await.unwrap();
    assert!(matches!(r, ReplayResult::Sent { .. }), "{r:?}");
    assert!(seen.lock().unwrap()[0].starts_with("GET /orig HTTP/1.1"));
}
