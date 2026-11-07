//! Session handling against a small app with login sessions and CSRF tokens.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use pm_service::pm_fuzz::PayloadSet;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{
    ExtractKind, Extraction, FuzzerRequest, FuzzerResult, Macro, MacroStep, ReplayRequest, ReplayResult, RunWhen,
    Service, SessionConfig, SessionRule, SetValue, SetWhere,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Default)]
struct App {
    next: AtomicU64,
    logins: AtomicU64,
    /// Valid session ids and their current CSRF token.
    sessions: Mutex<Vec<(String, String)>>,
}

impl App {
    fn handle(&self, req: &str) -> String {
        let line = req.lines().next().unwrap_or_default();
        let sid = req
            .lines()
            .find_map(|l| l.strip_prefix("Cookie: "))
            .and_then(|c| c.split("; ").find_map(|p| p.strip_prefix("sid=")))
            .unwrap_or_default()
            .to_string();
        let body = req.split("\r\n\r\n").nth(1).unwrap_or_default();
        let valid = self.sessions.lock().iter().any(|(s, _)| *s == sid);
        let reply = |status: &str, extra: &str, body: &str| {
            format!("HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        };
        if line.starts_with("POST /login") {
            if !body.contains("user=alice&pass=secret") {
                return reply("403 Forbidden", "", "bad login");
            }
            self.logins.fetch_add(1, Ordering::SeqCst);
            let sid = format!("S{}", self.next.fetch_add(1, Ordering::SeqCst));
            self.sessions.lock().push((sid.clone(), String::new()));
            return reply("200 OK", &format!("Set-Cookie: sid={sid}; HttpOnly\r\n"), "welcome");
        }
        if !valid {
            return reply("302 Found", "Location: /login\r\n", "");
        }
        if line.starts_with("GET /form") {
            let tok = format!("T{}", self.next.fetch_add(1, Ordering::SeqCst));
            for s in self.sessions.lock().iter_mut().filter(|(s, _)| *s == sid) {
                s.1.clone_from(&tok);
            }
            return reply("200 OK", "", &format!("<form><input type=hidden name=csrf value=\"{tok}\"></form>"));
        }
        if line.starts_with("POST /transfer") {
            let expected =
                self.sessions.lock().iter().find(|(s, _)| *s == sid).map(|s| s.1.clone()).unwrap_or_default();
            let ok = !expected.is_empty() && body.contains(&format!("csrf={expected}"));
            return if ok { reply("200 OK", "", "transferred") } else { reply("403 Forbidden", "", "bad csrf") };
        }
        reply("404 Not Found", "", "")
    }
}

async fn start(app: Arc<App>) -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
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
    url
}

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

const TRANSFER: &str = "POST /transfer HTTP/1.1\r\nHost: bank\r\nCookie: sid=stale; theme=dark\r\n\
Content-Type: application/x-www-form-urlencoded\r\n\r\namount=5&csrf=none";

async fn transfer(s: &Service, url: &str, actor: &Actor) -> (u16, String) {
    let req = ReplayRequest { url: Some(url.into()), raw: Some(TRANSFER.into()), ..Default::default() };
    match s.replay_send(actor, req).await.unwrap() {
        ReplayResult::Sent { exchange_id, .. } => {
            let ex = s.exchange_raw(exchange_id).unwrap();
            let resp = String::from_utf8_lossy(ex.response.as_deref().unwrap_or_default()).to_string();
            (ex.summary.status.unwrap_or(0), resp.split("\r\n\r\n").nth(1).unwrap_or_default().to_string())
        }
        other => panic!("{other:?}"),
    }
}

fn config(url: &str) -> SessionConfig {
    let login = Macro {
        name: "login".into(),
        steps: vec![MacroStep {
            url: url.into(),
            request: "POST /login HTTP/1.1\r\nHost: bank\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n\
                      user=alice&pass=secret"
                .into(),
            extract: vec![],
        }],
        use_cookie_jar: false,
    };
    let csrf = Macro {
        name: "csrf".into(),
        steps: vec![MacroStep {
            url: url.into(),
            request: "GET /form HTTP/1.1\r\nHost: bank\r\n\r\n".into(),
            extract: vec![Extraction {
                name: "csrf".into(),
                kind: ExtractKind::Regex,
                expr: r#"name=csrf value="(\w+)""#.into(),
            }],
        }],
        use_cookie_jar: true,
    };
    SessionConfig {
        macros: vec![login, csrf],
        rules: vec![
            SessionRule { name: "stay logged in".into(), macro_name: "login".into(), ..Default::default() },
            SessionRule {
                name: "fresh CSRF token".into(),
                use_cookie_jar: false,
                macro_name: "csrf".into(),
                run: RunWhen::Always,
                tools: vec!["replay".into(), "fuzzer".into()],
                set: vec![SetValue { location: SetWhere::Param, name: "csrf".into(), value: "{{csrf}}".into() }],
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

#[tokio::test]
async fn rules_log_in_again_and_fetch_csrf_tokens() {
    let app = Arc::new(App::default());
    let url = start(app.clone()).await;
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();

    // Without rules the stale session is sent as is.
    let (status, _) = transfer(&s, &url, &human()).await;
    assert_eq!(status, 302);

    // Agents can't see or change the rules (macros hold passwords).
    let agent = Actor::parse("agent:claude").unwrap();
    assert!(s.session_set(&agent, config(&url)).is_err());
    assert!(s.session_get(&agent).is_err());
    s.session_set(&human(), config(&url)).unwrap();

    let (status, body) = transfer(&s, &url, &human()).await;
    assert_eq!((status, body.as_str()), (200, "transferred"), "logged in, fresh token, sent again");
    let jar = s.session_jar(&human()).unwrap();
    assert!(jar.iter().any(|c| c.name == "sid" && c.value.starts_with('S')), "{jar:?}");
    let view = s.session_get(&human()).unwrap();
    assert!(view.variables.get("csrf").is_some_and(|v| v.starts_with('T')));

    // The server forgets every session: the next send recovers by itself.
    app.sessions.lock().clear();
    let (status, body) = transfer(&s, &url, &human()).await;
    assert_eq!((status, body.as_str()), (200, "transferred"));

    // Macro traffic is recorded and audited; the audit log has no password.
    let filter = pm_service::pm_store::HistoryFilter { source: Some("macro".into()), ..Default::default() };
    assert!(s.history_search(&human(), &filter).unwrap().exchanges.len() >= 4);
    let audit = s.audit_list(1000).unwrap();
    assert!(audit.iter().any(|r| r.action == "session_macro" && r.detail.contains("triggered_by")));
    let saved = audit.iter().find(|r| r.action == "session_handling").unwrap();
    assert!(saved.detail.contains("POST /login") && !saved.detail.contains("pass=secret"), "{}", saved.detail);

    // A test macro run reports what it learned.
    let run = s.session_macro_run(&human(), "csrf").await.unwrap();
    assert!(run.variables["csrf"].starts_with('T') && run.exchange_ids.len() == 1);

    // Clearing the jar drops the session cookie; the rules log in again.
    s.session_jar_clear(&human()).unwrap();
    assert!(s.session_jar(&human()).unwrap().is_empty());
    let (status, _) = transfer(&s, &url, &human()).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn concurrent_requests_share_one_login() {
    let app = Arc::new(App::default());
    let url = start(app.clone()).await;
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let mut cfg = config(&url);
    cfg.rules.truncate(1); // just "stay logged in", for every tool
    s.session_set(&human(), cfg).unwrap();
    let form = |n: u32| {
        let req = ReplayRequest {
            url: Some(url.clone()),
            raw: Some(format!("GET /form?n={n} HTTP/1.1\r\nHost: bank\r\nCookie: sid=stale\r\n\r\n")),
            ..Default::default()
        };
        let s = &s;
        async move {
            match s.replay_send(&human(), req).await.unwrap() {
                ReplayResult::Sent { exchange_id, .. } => s.exchange_raw(exchange_id).unwrap().summary.status,
                other => panic!("{other:?}"),
            }
        }
    };
    let all = tokio::join!(form(1), form(2), form(3), form(4), form(5), form(6));
    assert_eq!(all, (Some(200), Some(200), Some(200), Some(200), Some(200), Some(200)));
    assert_eq!(app.logins.load(Ordering::SeqCst), 1, "one login for six requests that found the session gone");

    // Fuzzer gets the same treatment.
    app.sessions.lock().clear();
    let req = FuzzerRequest {
        url: Some(url.clone()),
        raw: "GET /form?n=§1§ HTTP/1.1\r\nHost: bank\r\n\r\n".into(),
        payload_sets: vec![PayloadSet { list: (1..=8).map(|i| i.to_string()).collect(), ..Default::default() }],
        concurrency: Some(8),
        ..Default::default()
    };
    let FuzzerResult::Done { results, .. } = s.fuzzer_run(&human(), req).await.unwrap() else { panic!() };
    assert!(results.iter().all(|r| r.status == Some(200)));
    assert_eq!(app.logins.load(Ordering::SeqCst), 2);
}
