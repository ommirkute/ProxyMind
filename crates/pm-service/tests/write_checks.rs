//! Write checks (ReDoS and cross-user writes) against a small API that has
//! one real bug of each kind and a look-alike that only changes the caller.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use pm_service::pm_identity::{AuthMaterial, Identity};
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{OpenApiImportRequest, ReplayRequest, Service};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const SPEC: &str = r#"{"openapi":"3.0.0","info":{"title":"t"},"servers":[{"url":""}],"paths":{
 "/users/{username}":{"get":{"parameters":[{"name":"username","in":"path","required":true,"schema":{"type":"string"}}]}},
 "/users/{username}/password":{"put":{"parameters":[{"name":"username","in":"path","required":true,"schema":{"type":"string"}}],
   "requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"password":{"type":"string","example":"new"}}}}}}}},
 "/users/{username}/email":{"put":{"parameters":[{"name":"username","in":"path","required":true,"schema":{"type":"string"}}],
   "requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"email":{"type":"string","example":"a@b.test"}}}}}}}}}}"#;

/// Users alice and bob (tokens "ta", "tb"). Password: changes the user in the
/// path (the bug). Email: changes the caller (safe), and its validator slows
/// down exponentially on "aaaa…!" (the ReDoS).
async fn server() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let state: Arc<Mutex<HashMap<String, (String, String)>>> = Arc::new(Mutex::new(HashMap::from([
        ("alice".into(), ("pa".into(), "alice@x.test".into())),
        ("bob".into(), ("pb".into(), "bob@x.test".into())),
    ])));
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = l.accept().await else { return };
            let state = state.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = c.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let line = req.lines().next().unwrap_or("").to_string();
                let mut parts = line.split(' ');
                let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
                let caller = if req.contains("Bearer ta") {
                    Some("alice")
                } else if req.contains("Bearer tb") {
                    Some("bob")
                } else {
                    None
                };
                let body = req.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
                let field = |k: &str| {
                    serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| v[k].as_str().map(str::to_string))
                };
                let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                let (status, out) = match (method, segs.as_slice()) {
                    ("GET", ["openapi.json"]) => (200, SPEC.to_string()),
                    (_, ["users", ..]) if caller.is_none() => (401, "{\"error\":\"login\"}".into()),
                    ("GET", ["users", u]) => match state.lock().unwrap().get(*u) {
                        Some((_, e)) => (200, format!("{{\"username\":\"{u}\",\"email\":\"{e}\"}}")),
                        None => (404, "{}".into()),
                    },
                    ("PUT", ["users", u, "password"]) => {
                        let p = field("password").unwrap_or_default();
                        match state.lock().unwrap().get_mut(*u) {
                            Some(x) => {
                                x.0 = p;
                                (204, String::new())
                            }
                            None => (404, "{}".into()),
                        }
                    }
                    ("PUT", ["users", _, "email"]) => {
                        let e = field("email").unwrap_or_default();
                        if !e.contains('@') {
                            // A backtracking validator: time grows ×4 every two characters.
                            let a = e.chars().take_while(|c| *c == 'a').count();
                            let ms = if a >= 16 { 2u64 * 4u64.pow(((a - 16) / 2) as u32) } else { 0 };
                            tokio::time::sleep(std::time::Duration::from_millis(ms.min(4000))).await;
                            (400, "{\"error\":\"bad email\"}".into())
                        } else {
                            state.lock().unwrap().get_mut(caller.unwrap()).unwrap().1 = e;
                            (204, String::new())
                        }
                    }
                    _ => (404, "{}".into()),
                };
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}",
                    out.len()
                );
                let _ = c.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

#[tokio::test]
async fn write_checks_find_the_cross_user_write_and_the_redos_only() {
    let port = server().await;
    let url = format!("http://127.0.0.1:{port}");
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\ntiers:\n  human:\n    destructive: allow\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    for (name, tok) in [("alice", "ta"), ("bob", "tb")] {
        s.identity_set(
            &human(),
            Identity {
                name: name.into(),
                role: "user".into(),
                auth: AuthMaterial {
                    cookies: vec![],
                    headers: vec![("Authorization".into(), format!("Bearer {tok}"))],
                },
                health: None,
                logged_out: None,
                login: None,
            },
        )
        .unwrap();
        // Each user reads their own profile: the model learns who owns what.
        s.replay_send(
            &human(),
            ReplayRequest {
                url: Some(url.clone()),
                raw: Some(format!("GET /users/{name} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {tok}\r\n\r\n")),
                identity: Some(name.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let spec = s
        .replay_send(
            &human(),
            ReplayRequest {
                url: Some(url.clone()),
                raw: Some("GET /openapi.json HTTP/1.1\r\nHost: x\r\n\r\n".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let pm_service::ReplayResult::Sent { exchange_id, .. } = spec else { panic!() };
    s.openapi_import(&human(), OpenApiImportRequest { exchange_id: Some(exchange_id), ..Default::default() })
        .await
        .unwrap();

    // Destructive tier: an agent is refused under these rules, and nothing is sent.
    let agent = Actor::parse("agent:claude").unwrap();
    let w = s.auto_write_checks(&agent).await.unwrap();
    assert!(
        w.requests == 0 && (w.pending_approval.is_some() || w.notes.iter().any(|n| n.starts_with("denied"))),
        "{w:?}"
    );

    let w = s.auto_write_checks(&human()).await.unwrap();
    let mut got: Vec<(String, String)> = w.leads.iter().map(|l| (l.check.clone(), l.operation.clone())).collect();
    got.sort();
    assert_eq!(
        got,
        [
            ("bola".to_string(), "PUT /users/{username}/password".to_string()),
            ("redos".to_string(), "PUT /users/{username}/email".to_string()),
        ],
        "the email write only changes the caller: read back, it isn't a cross-user write ({w:?})"
    );
}
