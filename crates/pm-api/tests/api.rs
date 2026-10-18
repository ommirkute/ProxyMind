//! The API over real HTTP: security checks and the main flows.

use std::sync::Arc;
use std::time::Duration;

use pm_service::Service;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TOKEN: &str = "t0k3n-for-tests-0123456789abcdef0123456789";

async fn start() -> (u16, u16) {
    let shop = pm_demo::VulnShop::start_local().await.unwrap().port();
    let roe = format!("version: 1\nscope:\n  include: [\"http://127.0.0.1:{shop}/\"]\n");
    let svc = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let state = pm_api::AppState {
        service: Arc::new(svc),
        actor: Actor::parse("human:tester").unwrap(),
        token: Arc::new(TOKEN.into()),
        project: Arc::new("test.pmproj".into()),
    };
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, pm_api::router(state)).await.unwrap() });
    (port, shop)
}

/// Minimal HTTP/1.1 client: returns (status, headers, body).
async fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (u16, String, String) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
        req.push_str(&format!("Host: 127.0.0.1:{port}\r\n"));
    }
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(&body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_string(&mut out)).await;
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    let status = head.split(' ').nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
    (status, head.to_string(), body.to_string())
}

const AUTH: (&str, &str) = ("Authorization", "Bearer t0k3n-for-tests-0123456789abcdef0123456789");
const CHANGE: (&str, &str) = ("X-ProxyMind", "1");

#[tokio::test]
async fn security_checks() {
    let (port, _) = start().await;
    assert_eq!(http(port, "GET", "/api/v1/status", &[], None).await.0, 401, "no token");
    assert_eq!(http(port, "GET", "/api/v1/status", &[("Authorization", "Bearer nope")], None).await.0, 401);
    assert_eq!(http(port, "GET", "/api/v1/status", &[AUTH, ("Host", "evil.com")], None).await.0, 403, "DNS rebinding");
    let r = http(port, "POST", "/api/v1/findings", &[AUTH], Some(json!({}))).await;
    assert_eq!(r.0, 403, "state change without X-ProxyMind");
    // The login link swaps the token for an HttpOnly, SameSite=Strict cookie.
    let (st, head, _) = http(port, "GET", &format!("/auth?token={TOKEN}"), &[], None).await;
    assert_eq!(st, 303);
    assert!(head.contains("HttpOnly") && head.contains("SameSite=Strict"), "{head}");
    let cookie = format!("pm_token={TOKEN}");
    assert_eq!(http(port, "GET", "/api/v1/status", &[("Cookie", &cookie)], None).await.0, 200);
    assert_eq!(http(port, "GET", "/auth?token=wrong", &[], None).await.0, 401);
    // Pages are served with a restrictive CSP.
    let (st, head, body) = http(port, "GET", "/", &[], None).await;
    assert_eq!(st, 200);
    assert!(head.to_lowercase().contains("content-security-policy") && body.contains("ProxyMind"));
}

#[tokio::test]
async fn replay_history_findings_and_events() {
    let (port, shop) = start().await;
    let r = http(
        port,
        "POST",
        "/api/v1/replay",
        &[AUTH, CHANGE],
        Some(json!({"url": format!("http://127.0.0.1:{shop}"), "raw": "GET /api/products HTTP/1.1\nHost: x\n\n"})),
    )
    .await;
    assert_eq!(r.0, 200, "{}", r.2);
    let v: Value = serde_json::from_str(&r.2).unwrap();
    assert_eq!(v["status"], "sent");
    let id = v["exchange_id"].as_i64().unwrap();

    let (_, _, body) = http(port, "GET", "/api/v1/exchanges?limit=10", &[AUTH], None).await;
    let page: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(page["exchanges"][0]["id"], id);
    let (_, _, body) = http(port, "GET", &format!("/api/v1/exchanges/{id}"), &[AUTH], None).await;
    let ex: Value = serde_json::from_str(&body).unwrap();
    assert!(ex["response"].as_str().unwrap().contains("Coffee"));

    let (st, _, body) = http(
        port,
        "POST",
        "/api/v1/findings",
        &[AUTH, CHANGE],
        Some(json!({"title":"t","vuln_class":"idor","severity":"low","description":"d","evidence":[id]})),
    )
    .await;
    assert_eq!(st, 200, "{body}");
    let fid = serde_json::from_str::<Value>(&body).unwrap()["id"].as_i64().unwrap();
    let (st, _, body) = http(
        port,
        "PATCH",
        &format!("/api/v1/findings/{fid}"),
        &[AUTH, CHANGE],
        Some(json!({"id": 0, "status": "confirmed"})),
    )
    .await;
    assert_eq!((st, serde_json::from_str::<Value>(&body).unwrap()["status"].clone()), (200, json!("confirmed")));
    // Proven can't be set by hand, even by a human.
    let (st, _, _) = http(
        port,
        "PATCH",
        &format!("/api/v1/findings/{fid}"),
        &[AUTH, CHANGE],
        Some(json!({"id": 0, "status": "proven"})),
    )
    .await;
    assert_eq!(st, 400);

    // Errors are JSON with a message.
    let (st, _, body) = http(port, "GET", "/api/v1/exchanges/9999", &[AUTH], None).await;
    assert_eq!(st, 404);
    assert!(body.contains("error"));

    // The event stream sends counters straight away.
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(
        format!("GET /api/v1/events HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = vec![0u8; 4096];
    let mut got = String::new();
    while !got.contains("event: counters") {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf)).await.unwrap().unwrap();
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    assert!(got.contains("\"findings\":1"), "{got}");
}

#[tokio::test]
async fn match_and_replace_rules() {
    let (port, _) = start().await;
    let (st, _, body) = http(port, "GET", "/api/v1/match-replace", &[AUTH], None).await;
    assert_eq!((st, body.as_str()), (200, r#"{"rules":[]}"#));
    let bad = json!({"rules": [{"part": "request_body", "match": "(", "replace": "x", "regex": true}]});
    assert_eq!(http(port, "PUT", "/api/v1/match-replace", &[AUTH, CHANGE], Some(bad)).await.0, 400, "bad regex");
    let smuggle = json!({"rules": [{"replace": "A: 1\r\nB: 2"}]});
    assert_eq!(http(port, "PUT", "/api/v1/match-replace", &[AUTH, CHANGE], Some(smuggle)).await.0, 400);
    let good = json!({"rules": [{"replace": "X-Test: 1"}]});
    assert_eq!(http(port, "PUT", "/api/v1/match-replace", &[AUTH, CHANGE], Some(good)).await.0, 200);
    let (_, _, body) = http(port, "GET", "/api/v1/match-replace", &[AUTH], None).await;
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["rules"][0]["replace"], "X-Test: 1");
    assert_eq!(v["rules"][0]["in_scope_only"], true, "in scope only by default");
    let (_, _, audit) = http(port, "GET", "/api/v1/audit", &[AUTH], None).await;
    assert!(audit.contains("match_replace_rules"), "changes are audited");
}

#[tokio::test]
async fn network_settings_hide_the_password() {
    let (port, _) = start().await;
    let cfg = json!({"upstream": {"kind": "socks5", "host": "127.0.0.1", "port": 1080, "username": "u", "password": "hunter2"}});
    let (st, _, body) = http(port, "PUT", "/api/v1/network", &[AUTH, CHANGE], Some(cfg)).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("********") && !body.contains("hunter2"));
    // Sending the masked value back keeps the saved password.
    let again = json!({"upstream": {"kind": "socks5", "host": "127.0.0.1", "port": 1081, "username": "u", "password": "********"}});
    assert_eq!(http(port, "PUT", "/api/v1/network", &[AUTH, CHANGE], Some(again)).await.0, 200);
    let (_, _, audit) = http(port, "GET", "/api/v1/audit", &[AUTH], None).await;
    assert!(audit.contains("network_settings") && !audit.contains("hunter2"), "audited without the password");
    let bad = json!({"client_certs": [{"host": "*", "cert_file": "/nope.pem", "key_file": "/nope.key"}]});
    assert_eq!(http(port, "PUT", "/api/v1/network", &[AUTH, CHANGE], Some(bad)).await.0, 400);
    let unknown = json!({"upstream": {"host": "x", "port": 1, "typo": true}});
    assert_eq!(http(port, "PUT", "/api/v1/network", &[AUTH, CHANGE], Some(unknown)).await.0, 422);
}
