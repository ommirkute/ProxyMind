//! Recorded logins: a login done in the browser becomes a login recipe that
//! fetches fresh CSRF tokens, and an expired session that still answers 200
//! is noticed and logged in again.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use parking_lot::Mutex;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{NewExchange, Store};
use pm_service::{ReplayRequest, ReplayResult, Service};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct App {
    next: AtomicU64,
    logins: AtomicU64,
    /// Pre-login cookie → the CSRF token its form showed.
    forms: Mutex<Vec<(String, String)>>,
    /// Session id → bearer token.
    sessions: Mutex<Vec<(String, String)>>,
    fail_logins: AtomicBool,
}

fn cookie<'a>(req: &'a str, name: &str) -> &'a str {
    req.lines()
        .find_map(|l| l.strip_prefix("Cookie: "))
        .and_then(|c| c.split("; ").find_map(|p| p.strip_prefix(name).and_then(|v| v.strip_prefix('='))))
        .unwrap_or_default()
}

impl App {
    fn handle(&self, req: &str) -> String {
        let line = req.lines().next().unwrap_or_default();
        let body = req.split("\r\n\r\n").nth(1).unwrap_or_default();
        let reply = |extra: &str, body: &str| {
            format!("HTTP/1.1 200 OK\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        };
        let n = self.next.fetch_add(1, Ordering::SeqCst) * 7919 + 4242;
        if line.starts_with("GET /login") {
            let (pre, csrf) = (format!("P{n:06}k"), format!("csrf{n:08x}"));
            self.forms.lock().push((pre.clone(), csrf.clone()));
            return reply(
                &format!("Set-Cookie: pre={pre}; HttpOnly\r\nContent-Type: text/html\r\n"),
                &format!("<form method=post action=/login><input type=hidden name=csrf value=\"{csrf}\"></form>"),
            );
        }
        if line.starts_with("POST /login") {
            let pre = cookie(req, "pre");
            let ok_form = self.forms.lock().iter().any(|(p, c)| p == pre && body.contains(&format!("csrf={c}")));
            if !ok_form || !body.contains("user=alice&pass=secret") || self.fail_logins.load(Ordering::SeqCst) {
                return reply("", "{\"error\":\"bad login\"}");
            }
            self.logins.fetch_add(1, Ordering::SeqCst);
            let (sid, tok) = (format!("S{n:06}q"), format!("tok{n:08x}z"));
            self.sessions.lock().push((sid.clone(), tok.clone()));
            return reply(
                &format!("Set-Cookie: sid={sid}; HttpOnly\r\nContent-Type: application/json\r\n"),
                &format!("{{\"token\":\"{tok}\",\"user\":\"alice\"}}"),
            );
        }
        let sid = cookie(req, "sid");
        let bearer = req.lines().find_map(|l| l.strip_prefix("Authorization: Bearer ")).unwrap_or_default();
        let valid = self.sessions.lock().iter().any(|(s, t)| s == sid && t == bearer);
        if !valid {
            return reply("Content-Type: text/html\r\n", "<html><a href=/login>Please sign in</a></html>");
        }
        if line.starts_with("GET /api/me") {
            return reply("Content-Type: application/json\r\n", "{\"email\":\"alice@x.test\",\"id\":7}");
        }
        reply("", "ok")
    }
}

async fn start(app: Arc<App>) -> (String, u16) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut t, _)) = l.accept().await {
            let app = app.clone();
            tokio::spawn(async move {
                let mut got = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = t.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length: ").map(str::to_string))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if body.len() >= len {
                            let _ = t.write_all(app.handle(&text).as_bytes()).await;
                            return;
                        }
                    }
                }
            });
        }
    });
    (format!("http://127.0.0.1:{port}"), port)
}

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

/// What the browser sent while a human logged in (old, now useless values).
fn recording(port: u16) -> Vec<(&'static str, &'static str, String, String)> {
    let h = format!("Host: 127.0.0.1:{port}");
    vec![
        (
            "GET",
            "/login",
            format!("GET /login HTTP/1.1\r\n{h}\r\n\r\n"),
            "HTTP/1.1 200 OK\r\nSet-Cookie: pre=Pold1234; HttpOnly\r\nContent-Type: text/html\r\n\r\n\
             <form method=post action=/login><input type=hidden name=csrf value=\"csrf0000beef\"></form>"
                .into(),
        ),
        (
            "GET",
            "/static/app.js",
            format!("GET /static/app.js HTTP/1.1\r\n{h}\r\n\r\n"),
            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nlet token = 1;".into(),
        ),
        (
            "POST",
            "/login",
            format!(
                "POST /login HTTP/1.1\r\n{h}\r\nCookie: pre=Pold1234\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 40\r\n\r\n\
                 user=alice&pass=secret&csrf=csrf0000beef"
            ),
            "HTTP/1.1 200 OK\r\nSet-Cookie: sid=Sold9876; HttpOnly\r\nContent-Type: application/json\r\n\r\n\
             {\"token\":\"tok00aa11bb\",\"user\":\"alice\"}"
                .into(),
        ),
        (
            "GET",
            "/api/me",
            format!(
                "GET /api/me HTTP/1.1\r\n{h}\r\nCookie: pre=Pold1234; sid=Sold9876\r\n\
                 Authorization: Bearer tok00aa11bb\r\n\r\n"
            ),
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"email\":\"alice@x.test\",\"id\":7}".into(),
        ),
        (
            "POST",
            "/api/cart",
            format!(
                "POST /api/cart HTTP/1.1\r\n{h}\r\nCookie: pre=Pold1234; sid=Sold9876\r\n\
                 Authorization: Bearer tok00aa11bb\r\nContent-Length: 5\r\n\r\nqty=1"
            ),
            "HTTP/1.1 200 OK\r\n\r\nok".into(),
        ),
    ]
}

async fn me(s: &Service, url: &str) -> String {
    let req = ReplayRequest {
        url: Some(url.into()),
        raw: Some("GET /api/me HTTP/1.1\r\nHost: x\r\n\r\n".into()),
        identity: Some("alice".into()),
        ..Default::default()
    };
    match s.replay_send(&human(), req).await.unwrap() {
        ReplayResult::Sent { exchange_id, .. } => {
            let ex = s.exchange_raw(exchange_id).unwrap();
            String::from_utf8_lossy(ex.response.as_deref().unwrap_or_default()).to_string()
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_recorded_login_runs_again_with_fresh_tokens_and_expiry_is_noticed() {
    let app = Arc::new(App::default());
    let (url, port) = start(app.clone()).await;
    let mut store = Store::open_in_memory().unwrap();
    let mut ids = Vec::new();
    for (method, path, req, resp) in recording(port) {
        let status = Some(200);
        ids.push(
            store
                .insert_exchange(&NewExchange {
                    ts_ms: 0,
                    duration_ms: None,
                    source: "proxy".into(),
                    actor_id: "human:local".into(),
                    scheme: "http".into(),
                    host: "127.0.0.1".into(),
                    port,
                    method: method.into(),
                    path: path.into(),
                    status,
                    request: req.into_bytes(),
                    response: Some(resp.into_bytes()),
                    error: None,
                    identity: None,
                    hypothesis_id: None,
                })
                .unwrap(),
        );
    }
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(store, Policy::new(Roe::parse(&roe).unwrap())).unwrap();

    // Agents can't record (recipes hold passwords).
    let agent = Actor::parse("agent:bot").unwrap();
    assert!(s.identity_record_login(&agent, "alice", "user", 0, None).is_err());

    let rec = s.identity_record_login(&human(), "alice", "user", 0, None).unwrap();
    let paths: Vec<&str> = rec.steps.iter().map(|st| st.url.rsplit_once('/').unwrap().1).collect();
    assert_eq!(paths, vec!["login", "login"], "{rec:?}");
    assert_eq!(rec.steps[0].method, "GET");
    assert!(!rec.steps[0].extracts.is_empty() && !rec.steps[1].uses.is_empty(), "{rec:?}");
    assert!(!rec.steps[1].extracts.is_empty(), "the token comes from the login response: {rec:?}");
    assert_eq!(rec.headers, vec!["Authorization"]);
    assert_eq!(rec.health_check, Some(ids[3]));

    // The recorded values are stale; the recipe fetches fresh ones.
    let learned = s.identity_learn_logged_out(&human(), "alice").await.unwrap();
    assert_eq!(app.logins.load(Ordering::SeqCst), 1);
    assert_eq!(learned.logged_out.body_contains, "Please sign in", "{learned:?}");
    assert_eq!(learned.health_contains.as_deref(), Some("alice@x.test"));
    assert!(me(&s, &url).await.contains("alice@x.test"));

    // The app forgets every session but still answers 200.
    app.sessions.lock().clear();
    assert!(me(&s, &url).await.contains("alice@x.test"), "logged in again by itself");
    assert_eq!(app.logins.load(Ordering::SeqCst), 2);
    let check = s.identity_check(&human(), "alice").await.unwrap();
    assert_eq!(check.status, "ok");

    // When logging in fails, the health check says so.
    app.sessions.lock().clear();
    app.fail_logins.store(true, Ordering::SeqCst);
    let check = s.identity_check(&human(), "alice").await.unwrap();
    assert_eq!(check.status, "logged_out", "{check:?}");
}
