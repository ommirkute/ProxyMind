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
    start_with("").await
}

/// `start` with extra top-level rules-of-engagement YAML appended.
async fn start_with(extra_roe: &str) -> (u16, u16) {
    let shop = pm_demo::VulnShop::start_local().await.unwrap().port();
    let roe = format!("version: 1\nscope:\n  include: [\"http://127.0.0.1:{shop}/\"]\n{extra_roe}");
    let svc = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let state =
        pm_api::AppState::new(Arc::new(svc), Actor::parse("human:tester").unwrap(), TOKEN.into(), "test.pmproj".into())
            .unwrap();
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
    // The old contract, byte for byte: the event name and exactly these keys (the UI reads them).
    let data = got.lines().find_map(|l| l.strip_prefix("data: ")).expect("a data line");
    let c: Value = serde_json::from_str(data).unwrap();
    let mut keys: Vec<_> = c.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        ["audit_records", "exchanges", "findings", "intercepted", "last_exchange_id", "pending_approvals"]
    );
    assert!(!got.contains("\nid:"), "the legacy stream has no ids: {got}");
}

async fn open_events(port: u16, query: &str, extra: &str) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    s.write_all(
        format!(
            "GET /api/v1/events{query} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\n{extra}\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    s
}

/// Reads until `needle` appears (or fails after 5 s), appending to `got`.
async fn read_until(s: &mut TcpStream, got: &mut String, needle: &str) {
    let mut buf = vec![0u8; 4096];
    while !got.contains(needle) {
        let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("no {needle:?} in {got}"))
            .unwrap();
        assert!(n > 0, "stream ended before {needle:?}: {got}");
        got.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
}

fn new_finding(evidence: i64) -> Value {
    json!({"title":"t","vuln_class":"idor","severity":"low","description":"d","evidence":[evidence]})
}

#[tokio::test]
async fn event_topics_filter_resync_and_keep_the_counters_live() {
    let (port, shop) = start().await;
    // Unknown topics are refused before the stream opens; so is an empty list.
    let (st, _, body) = http(port, "GET", "/api/v1/events?topics=findings,nope", &[AUTH], None).await;
    assert_eq!(st, 400, "{body}");
    assert!(body.contains("nope"), "{body}");
    assert_eq!(http(port, "GET", "/api/v1/events?topics=", &[AUTH], None).await.0, 400);

    let mut typed = open_events(port, "?topics=findings,audit", "").await;
    let mut legacy = open_events(port, "", "").await;
    let (mut got_typed, mut got_legacy) = (String::new(), String::new());
    read_until(&mut legacy, &mut got_legacy, "\"findings\":0").await;

    // A replay records an exchange (topic exchanges, not subscribed to by `typed`) ...
    let r = http(
        port,
        "POST",
        "/api/v1/replay",
        &[AUTH, CHANGE],
        Some(json!({"url": format!("http://127.0.0.1:{shop}"), "raw": "GET /api/products HTTP/1.1\nHost: x\n\n"})),
    )
    .await;
    let ex = serde_json::from_str::<Value>(&r.2).unwrap()["exchange_id"].as_i64().unwrap();
    // ... and a finding changes (topic findings), which the audit log also records.
    let (st, _, body) = http(port, "POST", "/api/v1/findings", &[AUTH, CHANGE], Some(new_finding(ex))).await;
    assert_eq!(st, 200, "{body}");
    let fid = serde_json::from_str::<Value>(&body).unwrap()["id"].as_i64().unwrap();

    read_until(&mut typed, &mut got_typed, "event: findings").await;
    read_until(&mut typed, &mut got_typed, "event: audit").await;
    assert!(!got_typed.contains("event: exchanges") && !got_typed.contains("event: counters"), "{got_typed}");
    let block = got_typed.split("\n\n").find(|b| b.contains("event: findings")).unwrap();
    assert!(block.lines().any(|l| l.starts_with("id: ") && l[4..].parse::<u64>().is_ok()), "{block}");
    let data: Value = serde_json::from_str(block.lines().find_map(|l| l.strip_prefix("data: ")).unwrap()).unwrap();
    assert_eq!(
        (data["type"].as_str(), data["id"].as_i64(), data["status"].as_str()),
        (Some("finding_changed"), Some(fid), Some("suspected"))
    );
    assert_eq!(data["topic"], "findings");

    // The old client sees the new totals through the bus (a fresh counters event, no polling).
    read_until(&mut legacy, &mut got_legacy, "\"findings\":1").await;
    assert!(got_legacy.matches("event: counters").count() >= 2, "{got_legacy}");

    // A reconnect that missed events gets one resync, then the live stream; the exchange is not replayed.
    let mut again = open_events(port, "?topics=exchanges", "Last-Event-ID: 0\r\n").await;
    let mut got_again = String::new();
    read_until(&mut again, &mut got_again, "event: resync").await;
    assert!(got_again.contains("\"missed\":"), "{got_again}");
    assert!(!got_again.contains("event: exchanges"), "{got_again}");

    // `all` means every topic this actor may read, counters excluded.
    let mut all = open_events(port, "?topics=all", "").await;
    let mut got_all = String::new();
    let (st, _, _) = http(port, "POST", "/api/v1/findings", &[AUTH, CHANGE], Some(new_finding(ex))).await;
    assert_eq!(st, 200);
    read_until(&mut all, &mut got_all, "event: audit").await;
    assert!(!got_all.contains("event: counters"), "{got_all}");
}

#[tokio::test]
async fn the_scans_fuzzer_and_ai_scan_topics_deliver_progress_without_polling() {
    let (port, shop) = start().await;
    // Every topic name is accepted, alone or with others; `all` includes the new ones.
    for q in ["?topics=fuzzer", "?topics=ai_scan", "?topics=scans,fuzzer,ai_scan,counters"] {
        let mut s = open_events(port, q, "").await;
        let mut got = String::new();
        read_until(&mut s, &mut got, "HTTP/1.1 200").await;
    }
    let msg = http(port, "GET", "/api/v1/events?topics=fuzzers", &[AUTH], None).await;
    assert!(msg.0 == 400 && msg.2.contains("fuzzer") && msg.2.contains("ai_scan"), "{}", msg.2);

    let mut typed = open_events(port, "?topics=fuzzer,scans,ai_scan", "").await;
    let mut all = open_events(port, "?topics=all", "").await;
    let (mut got, mut got_all) = (String::new(), String::new());
    read_until(&mut typed, &mut got, "\r\n\r\n").await;
    read_until(&mut all, &mut got_all, "\r\n\r\n").await;

    let url = format!("http://127.0.0.1:{shop}");
    let body = json!({"url": url, "raw": "GET /api/products?x=§a§ HTTP/1.1\nHost: x\n\n",
                      "payload_sets": [{"null_payloads": 3}]});
    let (st, _, b) = http(port, "POST", "/api/v1/fuzzer/attacks", &[AUTH, CHANGE], Some(body)).await;
    assert_eq!(st, 200, "{b}");
    let attack = serde_json::from_str::<Value>(&b).unwrap()["attack_id"].as_str().unwrap().to_string();
    // The attack's progress and end arrive as events; no status request is made.
    read_until(&mut typed, &mut got, "\"state\":\"done\"").await;
    let block = got.split("\n\n").find(|b| b.contains("event: fuzzer")).unwrap();
    let data: Value = serde_json::from_str(block.lines().find_map(|l| l.strip_prefix("data: ")).unwrap()).unwrap();
    assert_eq!((data["type"].as_str(), data["attack"].as_str()), (Some("fuzzer_progress"), Some(attack.as_str())));
    assert_eq!((data["topic"].as_str(), data["total"].as_u64()), (Some("fuzzer"), Some(3)));
    read_until(&mut all, &mut got_all, "event: fuzzer").await;

    let body = json!({"url": format!("{url}/"), "max_pages": 3, "browser": false, "checks": ["reflected_input"]});
    let (st, _, b) = http(port, "POST", "/api/v1/scan/tasks", &[AUTH, CHANGE], Some(body)).await;
    assert_eq!(st, 200, "{b}");
    let task = serde_json::from_str::<Value>(&b).unwrap()["task_id"].as_str().unwrap().to_string();
    let finished = format!("\"type\":\"scan_state_changed\",\"task\":\"{task}\",\"state\":\"done\"");
    read_until(&mut typed, &mut got, &finished).await;
    assert!(got.contains("event: scans"), "{got}");
    assert!(got.contains("\"state\":\"crawling\"") && got.contains("scan_progress"), "{got}");
}

#[tokio::test]
async fn the_websockets_topic_reports_each_exchange_once_per_batch() {
    use pm_service::pm_store::{NewExchange, NewWsMessage, WsTarget};
    let svc = Arc::new(
        Service::new(
            Store::open_in_memory().unwrap(),
            Policy::new(Roe::parse("version: 1\nscope:\n  include: [\"http://127.0.0.1/\"]\n").unwrap()),
        )
        .unwrap(),
    );
    let state =
        pm_api::AppState::new(svc.clone(), Actor::parse("human:tester").unwrap(), TOKEN.into(), "test.pmproj".into())
            .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, pm_api::router(state)).await.unwrap() });

    let mut ws = open_events(port, "?topics=websockets", "").await;
    let mut all = open_events(port, "?topics=all", "").await;
    let (mut got, mut got_all) = (String::new(), String::new());
    // Both streams are open once their headers arrive; only then is it safe to publish.
    read_until(&mut ws, &mut got, "\r\n\r\n").await;
    read_until(&mut all, &mut got_all, "\r\n\r\n").await;
    let ex = NewExchange {
        client_addr: None,
        ts_ms: 1,
        duration_ms: None,
        source: "proxy".into(),
        actor_id: "human:tester".into(),
        scheme: "http".into(),
        host: "127.0.0.1".into(),
        port: 80,
        method: "GET".into(),
        path: "/ws".into(),
        status: Some(101),
        request: b"GET /ws HTTP/1.1\r\n\r\n".to_vec(),
        response: None,
        error: None,
        identity: None,
        hypothesis_id: None,
    };
    let msg = || NewWsMessage {
        exchange_id: 0,
        ts_ms: 2,
        from_client: true,
        opcode: 1,
        len: 1,
        payload: b"x".to_vec(),
        truncated: false,
        compressed: false,
    };
    let id = svc.store_handle().write(|s| s.insert_exchange(&ex)).unwrap();
    let burst = [(WsTarget::Exchange(id), msg()), (WsTarget::Exchange(id), msg()), (WsTarget::Exchange(id), msg())];
    svc.store_handle().write(|s| s.insert_batch(&[], &burst)).unwrap();
    read_until(&mut ws, &mut got, "event: websockets").await;
    let block = got.split("\n\n").find(|b| b.contains("event: websockets")).unwrap();
    let data: Value = serde_json::from_str(block.lines().find_map(|l| l.strip_prefix("data: ")).unwrap()).unwrap();
    assert_eq!(
        (data["type"].as_str(), data["exchange_id"].as_i64(), data["topic"].as_str()),
        (Some("ws_message_recorded"), Some(id), Some("websockets"))
    );
    assert!(!got.contains("event: exchanges"), "only the requested topic: {got}");
    read_until(&mut all, &mut got_all, "event: websockets").await;
    // Three messages in one batch, one event.
    assert_eq!(got.matches("event: websockets").count(), 1, "{got}");
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
    let hosts =
        json!({"hosts": [{"host": "*.staging.test", "address": "10.1.2.3"}], "tls_passthrough": ["pinned.test"]});
    let (st, _, body) = http(port, "PUT", "/api/v1/network", &[AUTH, CHANGE], Some(hosts)).await;
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("10.1.2.3") && body.contains("pinned.test"));
    let bad_ip = json!({"hosts": [{"host": "a.test", "address": "not-an-ip"}]});
    assert_eq!(http(port, "PUT", "/api/v1/network", &[AUTH, CHANGE], Some(bad_ip)).await.0, 422);
}

#[tokio::test]
async fn proxy_listeners_are_saved_and_validated() {
    let (port, _) = start().await;
    let l = json!({"listeners": [{"bind": "127.0.0.1:18089", "redirect_host": "api.test", "redirect_port": 443, "force_tls": true}]});
    let (st, _, body) = http(port, "PUT", "/api/v1/proxy/listeners", &[AUTH, CHANGE], Some(l)).await;
    assert_eq!(st, 200, "{body}");
    let (_, _, body) = http(port, "GET", "/api/v1/proxy/listeners", &[AUTH], None).await;
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["listeners"][0]["redirect_host"], "api.test");
    assert_eq!(v["listeners"][0]["enabled"], true);
    let bad = json!({"listeners": [{"bind": "nowhere"}]});
    assert_eq!(http(port, "PUT", "/api/v1/proxy/listeners", &[AUTH, CHANGE], Some(bad)).await.0, 400);
    let (_, _, audit) = http(port, "GET", "/api/v1/audit", &[AUTH], None).await;
    assert!(audit.contains("proxy_listeners"));
}

#[tokio::test]
async fn assistant_settings_and_refusals() {
    // Cloud models are allowed by default; this engagement keeps its data on the machine.
    let (port, _) = start_with("data:\n  allow_cloud_models: false\n").await;
    let (st, _, body) = http(port, "GET", "/api/v1/assistant", &[AUTH], None).await;
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(st, 200);
    assert_eq!(v["acts_as"], "agent:assistant");
    assert!(v["problem"].as_str().unwrap().contains("choose a model"));
    // A cloud model the ROE does not allow is refused before anything is sent.
    let cloud = json!({"provider": "anthropic", "base_url": "https://api.anthropic.com/v1", "model": "m"});
    assert_eq!(http(port, "PUT", "/api/v1/assistant/config", &[AUTH, CHANGE], Some(cloud)).await.0, 200);
    let (st, _, body) =
        http(port, "POST", "/api/v1/assistant/send", &[AUTH, CHANGE], Some(json!({"text": "hi"}))).await;
    assert_eq!(st, 403, "{body}");
    assert!(body.contains("allow_cloud_models"));
    let (_, _, audit) = http(port, "GET", "/api/v1/audit", &[AUTH], None).await;
    assert!(audit.contains("assistant_model_call") && audit.contains("assistant_settings"));
}

/// gRPC and Protobuf: the two tool routes, and `request_protobuf` / `response_protobuf` on an exchange.
#[tokio::test]
async fn protobuf_tools_and_exchange_fields() {
    let (port, shop) = start().await;
    let post = |path: &'static str, body: Value| async move {
        let (st, _, b) = http(port, "POST", path, &[AUTH, CHANGE], Some(body)).await;
        (st, serde_json::from_str::<Value>(&b).unwrap_or(Value::Null))
    };

    // Decode: one gRPC frame holding `1: "world"`, as base64 (flag 0, length 7).
    let body = pm_http_frame(&[0x0a, 5, b'w', b'o', b'r', b'l', b'd']);
    let (st, v) = post(
        "/api/v1/tools/protobuf/decode",
        json!({"body_b64": body, "content_type": "application/grpc", "annotate": false}),
    )
    .await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["kind"], "grpc");
    assert_eq!(v["text"], "@message\n1: \"world\"\n");
    assert_eq!((v["exact"].clone(), v["messages"].clone()), (json!(true), json!(1)));

    // Encode the edited text back; the bytes are re-framed.
    let (st, e) =
        post("/api/v1/tools/protobuf/encode", json!({"kind": "grpc", "text": "@message\n1: \"galaxy\"\n2: 300\n"}))
            .await;
    assert_eq!(st, 200, "{e}");
    let want = pm_http_frame(&[0x0a, 6, b'g', b'a', b'l', b'a', b'x', b'y', 0x10, 0xac, 0x02]);
    assert_eq!(e["body_b64"], json!(want));
    assert_eq!(e["length"], 5 + 11);
    // Plain Protobuf is not framed.
    let (_, e) = post("/api/v1/tools/protobuf/encode", json!({"text": "1: 150"})).await;
    assert_eq!(e["body_b64"], "CJYB");

    // Mistakes are 400s that say what is wrong.
    let (st, v) = post("/api/v1/tools/protobuf/encode", json!({"text": "1: nope"})).await;
    assert_eq!(st, 400);
    assert!(v["error"].as_str().unwrap().contains("line 1"), "{v}");
    let (st, _) = post("/api/v1/tools/protobuf/decode", json!({"body_b64": body})).await;
    assert_eq!(st, 400, "no content type");
    let (st, _) = post("/api/v1/tools/protobuf/decode", json!({})).await;
    assert_eq!(st, 400, "no body");
    let (st, _) = post("/api/v1/tools/protobuf/decode", json!({"body_b64": "@@", "kind": "grpc"})).await;
    assert_eq!(st, 400, "bad base64");
    let (st, _) = post("/api/v1/tools/protobuf/decode", json!({"exchange_id": 1, "oops": 1})).await;
    assert_eq!(st, 422, "unknown field");

    // Replay a gRPC call to the demo shop: the head is text, the body travels as base64 (it is not UTF-8). The
    // exchange then shows both sides as text.
    let (st, r) = post(
        "/api/v1/replay",
        json!({
            "url": format!("http://127.0.0.1:{shop}"),
            "raw": "POST /grpc/demo.Greeter/SayHello HTTP/1.1\r\nHost: x\r\nContent-Type: application/grpc\r\n\r\n",
            "body_b64": body,
        }),
    )
    .await;
    assert_eq!(st, 200, "{r}");
    let id = r["exchange_id"].as_i64().unwrap();
    let (st, _, b) = http(port, "GET", &format!("/api/v1/exchanges/{id}"), &[AUTH], None).await;
    assert_eq!(st, 200);
    let ex: Value = serde_json::from_str(&b).unwrap();
    assert_eq!(ex["request_protobuf"], "@message\n1: \"world\"\n", "{ex}");
    let resp = ex["response_protobuf"].as_str().unwrap();
    assert!(resp.starts_with("@message\n1: \"Hello, world\"\n2: 5"), "{resp}");
    assert!(resp.contains("# grpc-status: 0"), "{resp}");

    // The same through the decode route by exchange id.
    let (st, v) = post("/api/v1/tools/protobuf/decode", json!({"exchange_id": id, "part": "response"})).await;
    assert_eq!(st, 200, "{v}");
    assert_eq!(v["grpc_status"], "0");
    assert!(v["text"].as_str().unwrap().contains("Hello, world"));

    // Other traffic has no protobuf fields.
    let (_, _, b) = http(port, "GET", "/api/v1/exchanges?limit=1", &[AUTH], None).await;
    assert!(serde_json::from_str::<Value>(&b).is_ok());
}

fn pm_http_frame(payload: &[u8]) -> String {
    pm_core_b64(&pm_service::pm_http::protobuf::frame_message(0, payload))
}

fn pm_core_b64(b: &[u8]) -> String {
    pm_service::pm_http::protobuf::base64_encode(b)
}

/// A server over this service (no demo target); returns the API port.
async fn serve(svc: Service) -> u16 {
    let state =
        pm_api::AppState::new(Arc::new(svc), Actor::parse("human:tester").unwrap(), TOKEN.into(), "test.pmproj".into())
            .unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, pm_api::router(state)).await.unwrap() });
    port
}

fn service_with_proxy(proxy: Option<&str>) -> Service {
    let roe = "version: 1\nscope:\n  include: [\"http://shop.test/\"]\n";
    let svc = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(roe).unwrap())).unwrap();
    if let Some(addr) = proxy {
        let dir =
            std::env::temp_dir().join(format!("pm-api-ca-{}-{}", std::process::id(), addr.replace([':', '.'], "-")));
        let ca = pm_service::pm_tls::CertAuthority::load_or_create(&dir).unwrap();
        svc.attach_proxy_info(pm_service::ProxyInfo {
            addr: addr.into(),
            ca_pem: ca.ca_pem().to_string(),
            profile_dir: dir,
        });
    }
    svc
}

#[tokio::test]
async fn mobile_setup_route_gives_urls_a_qr_image_and_the_fingerprint() {
    // A listener a phone can reach.
    let port = serve(service_with_proxy(Some("192.168.1.5:8080"))).await;
    assert_eq!(http(port, "GET", "/api/v1/setup/mobile", &[], None).await.0, 401, "behind the token like the rest");
    let (st, _, body) = http(port, "GET", "/api/v1/setup/mobile", &[AUTH], None).await;
    assert_eq!(st, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["proxy_running"], true);
    assert_eq!(v["listener_reachable"], true);
    assert_eq!(v["urls"], json!(["http://192.168.1.5:8080/"]));
    assert_eq!(v["proxy_addresses"], json!(["192.168.1.5:8080"]));
    assert_eq!(v["qr_url"], "http://192.168.1.5:8080/");
    assert_eq!(v["setup_host_url"], "http://proxymind.setup/");
    let svg = v["qr_svg"].as_str().unwrap();
    assert!(svg.starts_with("<svg ") && !svg.contains("<script"));
    let fp = v["ca_fingerprint"].as_str().unwrap();
    assert_eq!(fp.split(':').count(), 32, "{fp}");
    assert!(!body.contains(TOKEN), "the API token never appears");

    // A loopback-only proxy cannot be reached from a phone: no URL, no QR code.
    let port = serve(service_with_proxy(Some("127.0.0.1:8080"))).await;
    let v: Value = serde_json::from_str(&http(port, "GET", "/api/v1/setup/mobile", &[AUTH], None).await.2).unwrap();
    assert_eq!((v["proxy_running"].clone(), v["listener_reachable"].clone()), (json!(true), json!(false)));
    assert_eq!(v["urls"], json!([]));
    assert!(v.get("qr_svg").is_none());

    // No proxy in the process.
    let port = serve(service_with_proxy(None)).await;
    let v: Value = serde_json::from_str(&http(port, "GET", "/api/v1/setup/mobile", &[AUTH], None).await.2).unwrap();
    assert_eq!(v["proxy_running"], false);
}

#[tokio::test]
async fn devices_can_be_named_listed_filtered_and_recorded_alone() {
    let svc = service_with_proxy(None);
    svc.store_handle().write(|s| {
        for (path, ts, ip) in [("/a", 10, "192.168.1.23"), ("/b", 20, "192.168.1.24"), ("/c", 30, "192.168.1.23")] {
            s.insert_exchange(&pm_service::pm_store::NewExchange {
                ts_ms: ts,
                duration_ms: None,
                source: "proxy".into(),
                actor_id: "human:local".into(),
                scheme: "http".into(),
                host: "shop.test".into(),
                port: 80,
                method: "GET".into(),
                path: path.into(),
                status: Some(200),
                request: format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\n\r\n").into_bytes(),
                response: Some(b"HTTP/1.1 200 OK\r\n\r\n".to_vec()),
                error: None,
                identity: None,
                hypothesis_id: None,
                client_addr: Some(ip.into()),
            })
            .unwrap();
        }
    });
    let port = serve(svc).await;
    let rw = [AUTH, CHANGE];
    let get = |path: &'static str| async move {
        let (st, _, body) = http(port, "GET", path, &[AUTH], None).await;
        assert_eq!(st, 200, "{path}: {body}");
        serde_json::from_str::<Value>(&body).unwrap()
    };

    let v = get("/api/v1/devices").await;
    assert_eq!(
        v["devices"][0],
        json!({"addr": "192.168.1.23", "exchanges": 2, "last_seen_ms": 30, "record_only": false})
    );
    assert_eq!(v["devices"][1]["addr"], "192.168.1.24");

    // Naming needs the header that marks a deliberate change; the name must be sensible and the address valid.
    assert_eq!(
        http(port, "PUT", "/api/v1/devices/192.168.1.23", &[AUTH], Some(json!({"name": "Pixel 8"}))).await.0,
        403
    );
    let bad = http(port, "PUT", "/api/v1/devices/not-an-ip", &rw, Some(json!({"name": "x"}))).await;
    assert_eq!(bad.0, 400, "{}", bad.2);
    assert_eq!(http(port, "PUT", "/api/v1/devices/192.168.1.23", &rw, Some(json!({"name": ""}))).await.0, 400);
    assert_eq!(
        http(port, "PUT", "/api/v1/devices/192.168.1.23", &rw, Some(json!({"name": "x", "extra": 1}))).await.0,
        422
    );
    let (st, _, body) = http(port, "PUT", "/api/v1/devices/192.168.1.23", &rw, Some(json!({"name": "Pixel 8"}))).await;
    assert_eq!(st, 200, "{body}");
    let v: Value = serde_json::from_str(&body).unwrap();
    assert_eq!((v["name"].clone(), v["exchanges"].clone()), (json!("Pixel 8"), json!(2)));
    assert_eq!(get("/api/v1/devices").await["devices"][0]["name"], "Pixel 8");

    // History filters by address or by name, and shows the address.
    let v = get("/api/v1/exchanges?client=Pixel%208").await;
    let paths: Vec<&str> = v["exchanges"].as_array().unwrap().iter().map(|e| e["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["/c", "/a"]);
    assert_eq!(v["exchanges"][0]["client_addr"], "192.168.1.23");
    assert_eq!(get("/api/v1/exchanges?client=192.168.1.24").await["exchanges"][0]["path"], "/b");
    let v = get("/api/v1/exchanges?q=client%3A%22pixel%208%22").await;
    assert_eq!(v["exchanges"].as_array().unwrap().len(), 2);

    // Record only one device.
    let (st, _, body) =
        http(port, "PUT", "/api/v1/history/recording", &rw, Some(json!({"record_devices": ["192.168.1.24"]}))).await;
    assert_eq!(st, 200, "{body}");
    let v = get("/api/v1/history/recording").await;
    assert_eq!(v, json!({"in_scope_only": false, "record_devices": ["192.168.1.24"]}));
    assert_eq!(get("/api/v1/devices").await["devices"][1]["record_only"], true);
    let bad = http(port, "PUT", "/api/v1/history/recording", &rw, Some(json!({"record_devices": ["nope"]}))).await;
    assert_eq!(bad.0, 400);

    // Removing a name.
    let (st, _, body) = http(port, "DELETE", "/api/v1/devices/192.168.1.23", &rw, None).await;
    assert_eq!((st, body.as_str()), (200, r#"{"deleted":"192.168.1.23"}"#));
    assert_eq!(http(port, "DELETE", "/api/v1/devices/192.168.1.23", &rw, None).await.0, 404);
    assert!(get("/api/v1/devices").await["devices"][0].get("name").is_none());
}
