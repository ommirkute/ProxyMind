//! `pm3_` tokens in single-user mode (ADR-0022 step 5): the install token keeps its meaning, a token acts as its
//! own actor, and the file behind them is private. The server-mode half is in `server_mode.rs`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pm_accounts::{Clock, ManualClock, NewTokenSpec, TokenFile, TokenKind};
use pm_api::AppState;
use pm_service::Service;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const INSTALL: &str = "pm2_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const T0: i64 = 1_700_000_000;

struct Resp {
    status: u16,
    body: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }
    fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_string()
    }
}

struct Harness {
    port: u16,
    dir: PathBuf,
    clock: Arc<ManualClock>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Harness {
    async fn start(name: &str, with_store: bool) -> Self {
        let dir = std::env::temp_dir().join(format!("pm-api-tokens-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let clock = Arc::new(ManualClock::new(T0));
        let svc = Service::new(
            Store::open_in_memory().unwrap(),
            Policy::new(Roe::parse("version: 1\nscope:\n  include: [\"http://127.0.0.1:9/\"]\n").unwrap()),
        )
        .unwrap();
        let mut state =
            AppState::new(Arc::new(svc), Actor::parse("human:tester").unwrap(), INSTALL.into(), "p".into()).unwrap();
        if with_store {
            state = state.with_tokens(TokenFile::open_with_clock(&dir, clock.clone() as Arc<dyn Clock>).unwrap());
        }
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(l, pm_api::router(state)).await.unwrap() });
        Self { port, dir, clock }
    }

    async fn raw(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> Resp {
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\nHost: 127.0.0.1:{}\r\n",
            body.len(),
            self.port
        );
        if !body.is_empty() {
            req.push_str("Content-Type: application/json\r\n");
        }
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(&body);
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf)).await;
        let text = String::from_utf8_lossy(&buf).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
        let status = head.lines().next().and_then(|l| l.split(' ').nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
        Resp { status, body: body.to_string() }
    }

    /// The person: the install token, as the UI's script or the CLI sends it.
    async fn human(&self, method: &str, path: &str, body: Option<Value>) -> Resp {
        self.raw(method, path, &[("Authorization", format!("Bearer {INSTALL}")), ("X-ProxyMind", "1".into())], body)
            .await
    }

    /// An agent, CI job or script with a `pm3_` token: the bearer header and nothing else.
    async fn bearer(&self, method: &str, path: &str, token: &str, body: Option<Value>) -> Resp {
        self.raw(method, path, &[("Authorization", format!("Bearer {token}"))], body).await
    }

    async fn make(&self, body: Value) -> (String, Value) {
        let r = self.human("POST", "/api/v1/tokens", Some(body)).await;
        assert_eq!(r.status, 200, "{}", r.body);
        (r.json()["token"].as_str().unwrap().to_string(), r.json())
    }
}

fn mcp(id: u32, name: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})
}

fn tool(r: &Resp) -> Value {
    assert_eq!(r.status, 200, "{}", r.body);
    serde_json::from_str(r.json()["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn the_install_token_keeps_meaning_the_human_and_a_pm3_token_is_its_agent() {
    let h = Harness::start("actor", true).await;
    // Today's behaviour, unchanged: the install token as a bearer or a cookie is the human.
    assert_eq!(h.human("GET", "/api/v1/status", None).await.json()["you_are"], "human:tester");
    let r = h.raw("GET", "/api/v1/status", &[("Cookie", format!("pm_token={INSTALL}"))], None).await;
    assert_eq!(r.json()["you_are"], "human:tester");
    assert_eq!(h.raw("GET", "/api/v1/status", &[], None).await.status, 401);
    let (secret, made) = h.make(json!({"kind": "agent", "name": "claude"})).await;
    assert_eq!(made["actor"], "agent:claude");
    assert!(made["owner"].is_null() && made["project_id"].is_null(), "single-user tokens have no owner or project");
    let r = h.bearer("GET", "/api/v1/status", &secret, None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["you_are"], "agent:claude", "the token's actor, not the human");
    // The client cannot pick another actor.
    let r = h
        .raw(
            "GET",
            "/api/v1/status?actor=human:tester",
            &[("Authorization", format!("Bearer {secret}")), ("X-ProxyMind-Actor", "human:tester".into())],
            None,
        )
        .await;
    assert_eq!(r.json()["you_are"], "agent:claude");
    // Each kind is its own actor.
    for (kind, name) in [("ci", "pipeline"), ("plugin", "panel")] {
        let (s, _) = h.make(json!({"kind": kind, "name": name})).await;
        assert_eq!(h.bearer("GET", "/api/v1/status", &s, None).await.json()["you_are"], format!("{kind}:{name}"));
    }
    // In the header only.
    assert_eq!(h.raw("GET", &format!("/api/v1/status?token={secret}"), &[], None).await.status, 401);
    let r = h.raw("GET", "/api/v1/status", &[("Cookie", format!("pm_token={secret}"))], None).await;
    assert_eq!(r.status, 401);
    // A wrong, malformed or other token: one answer.
    for t in [format!("pm3_agent_{}", "0".repeat(64)), "pm3_agent_x".to_string(), "pm3_".to_string()] {
        let r = h.bearer("GET", "/api/v1/status", &t, None).await;
        assert_eq!((r.status, r.code().as_str()), (401, "invalid_token"), "{t}");
    }
    // The account endpoints do not exist here, for a token either.
    assert_eq!(h.bearer("GET", "/api/v1/auth/me", &secret, None).await.status, 404);
}

#[tokio::test]
async fn without_a_token_store_a_pm3_bearer_is_refused() {
    let h = Harness::start("nostore", false).await;
    let t = format!("pm3_agent_{}", "ab".repeat(32));
    assert_eq!(h.bearer("GET", "/api/v1/status", &t, None).await.status, 401);
    assert_eq!(h.human("GET", "/api/v1/status", None).await.status, 200);
    let r = h.human("GET", "/api/v1/tokens", None).await;
    assert_eq!((r.status, r.code().as_str()), (404, "tokens_unavailable"));
}

#[tokio::test]
async fn bearer_requests_need_no_browser_headers_but_the_cookie_path_keeps_its_check() {
    let h = Harness::start("csrf", true).await;
    let (secret, _) = h.make(json!({"kind": "agent", "name": "claude"})).await;
    let auth = ("Authorization", format!("Bearer {secret}"));
    // No X-ProxyMind needed by a plain bearer client (the SDKs, curl, the MCP bridge).
    let r = h
        .raw("POST", "/api/v1/mcp", std::slice::from_ref(&auth), Some(json!({"jsonrpc":"2.0","id":1,"method":"ping"})))
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    // The install cookie on the request brings the check back, with the token alongside.
    let cookie = ("Cookie", format!("pm_token={INSTALL}"));
    let r = h
        .raw(
            "POST",
            "/api/v1/mcp",
            &[auth.clone(), cookie.clone()],
            Some(json!({"jsonrpc":"2.0","id":1,"method":"ping"})),
        )
        .await;
    assert_eq!(r.status, 403, "{}", r.body);
    let r = h
        .raw(
            "POST",
            "/api/v1/mcp",
            &[auth, cookie, ("X-ProxyMind", "1".into())],
            Some(json!({"jsonrpc":"2.0","id":1,"method":"ping"})),
        )
        .await;
    assert_eq!(r.status, 200);
    // The install token as a bearer still needs the header, as before.
    let r = h.raw("POST", "/api/v1/mcp", &[("Authorization", format!("Bearer {INSTALL}"))], Some(json!({}))).await;
    assert_eq!(r.status, 403);
    // And a token never opens the launch link.
    assert_ne!(h.raw("GET", &format!("/auth?token={secret}"), &[], None).await.status, 200);
}

#[tokio::test]
async fn a_token_cannot_manage_tokens_only_the_person_can() {
    let h = Harness::start("manage", true).await;
    let (secret, made) = h.make(json!({"kind": "agent", "name": "claude"})).await;
    let id = made["id"].as_str().unwrap().to_string();
    for (m, p, b) in [
        ("POST", "/api/v1/tokens".to_string(), Some(json!({"kind": "agent", "name": "child"}))),
        ("GET", "/api/v1/tokens".to_string(), None),
        ("DELETE", format!("/api/v1/tokens/{id}"), None),
    ] {
        let r = h.bearer(m, &p, &secret, b).await;
        assert_eq!((r.status, r.code().as_str()), (403, "tokens_need_a_person"), "{m} {p}");
    }
    assert_eq!(h.bearer("GET", "/api/v1/status", &secret, None).await.status, 200);
    // The person lists (no secrets), and for_user means nothing with one user.
    let r = h.human("GET", "/api/v1/tokens", None).await;
    assert!(!r.body.contains(&secret) && r.json().as_array().unwrap().len() == 1);
    let r = h.human("POST", "/api/v1/tokens", Some(json!({"kind": "ci", "name": "x", "for_user": "someone"}))).await;
    assert_eq!(r.status, 400);
    // The same rules as in server mode when making one.
    for body in [
        json!({"kind": "agent", "name": "x", "role": "owner"}),
        json!({"kind": "human", "name": "x"}),
        json!({"kind": "agent", "name": "a b"}),
        json!({"kind": "agent", "name": "x", "expires_days": 366}),
    ] {
        let r = h.human("POST", "/api/v1/tokens", Some(body.clone())).await;
        assert!(r.status == 400 || r.status == 422, "{body}: {}", r.status);
    }
    let r = h.human("POST", "/api/v1/tokens", Some(json!({"kind": "agent", "name": "Claude"}))).await;
    assert_eq!((r.status, r.code().as_str()), (409, "token_name_taken"));
}

#[tokio::test]
async fn expiry_revocation_and_a_revoke_from_another_process_take_effect_at_once() {
    let h = Harness::start("life", true).await;
    let (short, _) = h.make(json!({"kind": "ci", "name": "job", "expires_days": 1})).await;
    h.clock.advance(86_399);
    assert_eq!(h.bearer("GET", "/api/v1/status", &short, None).await.status, 200);
    h.clock.advance(1);
    assert_eq!(h.bearer("GET", "/api/v1/status", &short, None).await.status, 401);
    // Revoke through the API.
    let (s1, m1) = h.make(json!({"kind": "agent", "name": "a1"})).await;
    assert_eq!(h.bearer("GET", "/api/v1/status", &s1, None).await.status, 200);
    let r = h.human("DELETE", &format!("/api/v1/tokens/{}", m1["id"].as_str().unwrap()), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(h.bearer("GET", "/api/v1/status", &s1, None).await.status, 401);
    let r = h.human("DELETE", &format!("/api/v1/tokens/{}", m1["id"].as_str().unwrap()), None).await;
    assert_eq!((r.status, r.code().as_str()), (404, "no_such_token"));
    // Revoke from another process (`proxymind token revoke` opens the file itself): seen at the next request.
    let (s2, m2) = h.make(json!({"kind": "agent", "name": "a2"})).await;
    assert_eq!(h.bearer("GET", "/api/v1/status", &s2, None).await.status, 200);
    let cli = TokenFile::open_with_clock(&h.dir, h.clock.clone() as Arc<dyn Clock>).unwrap();
    cli.revoke(m2["id"].as_str().unwrap()).unwrap();
    assert_eq!(h.bearer("GET", "/api/v1/status", &s2, None).await.status, 401);
    // ...and a token made from another process works without a restart.
    let made = cli.create(&NewTokenSpec::new(TokenKind::Agent, "from-cli")).unwrap();
    let r = h.bearer("GET", "/api/v1/status", made.token.expose(), None).await;
    assert_eq!(r.json()["you_are"], "agent:from-cli");
    let listed = h.human("GET", "/api/v1/tokens", None).await.json();
    assert!(listed.as_array().unwrap().iter().any(|t| t["name"] == "from-cli" && t["status"] == "active"));
    assert!(listed.as_array().unwrap().iter().any(|t| t["name"] == "a2" && t["status"] == "revoked"));
}

#[tokio::test]
async fn a_viewer_token_reads_and_a_tier_cap_stops_the_gate() {
    let h = Harness::start("caps", true).await;
    let (viewer, v) = h.make(json!({"kind": "plugin", "name": "reader", "role": "viewer"})).await;
    assert_eq!(v["role"], "viewer");
    assert_eq!(h.bearer("GET", "/api/v1/exchanges", &viewer, None).await.status, 200);
    let r = h.bearer("POST", "/api/v1/findings", &viewer, Some(json!({}))).await;
    assert_eq!((r.status, r.code().as_str()), (403, "read_only_token"));
    // A viewer's tools: the read ones are called (roles are per tool, ADR-0022 step 6), the others refused.
    let r = h.bearer("POST", "/api/v1/mcp", &viewer, Some(mcp(1, "roe_get", json!({})))).await;
    assert_eq!(r.json()["result"]["isError"], false, "{}", r.body);
    let r = h.bearer("POST", "/api/v1/mcp", &viewer, Some(mcp(2, "replay_send", json!({})))).await;
    assert!(r.json()["result"]["content"][0]["text"].as_str().unwrap().starts_with("access denied:"), "{}", r.body);
    // A cap: the same request is allowed for an uncapped agent and denied, with the reason and an audit entry, for a
    // capped one. The cap is the gate's, so the CLI, MCP and REST all get it.
    let (capped, _) = h.make(json!({"kind": "agent", "name": "careful", "tier_cap": "passive"})).await;
    let (free, _) = h.make(json!({"kind": "agent", "name": "free"})).await;
    let send = json!({"url": "http://127.0.0.1:9/", "raw": "GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"});
    let r = h.bearer("POST", "/api/v1/replay", &capped, Some(send.clone())).await;
    assert_eq!(r.json()["status"], "denied", "{}", r.body);
    assert!(r.json()["reasons"][0].as_str().unwrap().contains("limited to passive"));
    let r = h.bearer("POST", "/api/v1/replay", &free, Some(send.clone())).await;
    assert_ne!(r.json()["status"], "denied", "{}", r.body);
    let r = h.bearer("POST", "/api/v1/mcp", &capped, Some(mcp(2, "replay_send", send))).await;
    assert_eq!(tool(&r)["status"], "denied");
    let audit = h.human("GET", "/api/v1/audit", None).await.json();
    let denied =
        audit.as_array().unwrap().iter().filter(|a| a["actor"] == "agent:careful" && a["decision"] == "deny").count();
    assert_eq!(denied, 2, "one by REST and one by MCP: {audit}");
    // The person is never capped, and a token cannot do a person's things.
    let r = h
        .human(
            "POST",
            "/api/v1/replay",
            Some(json!({"url": "http://127.0.0.1:9/", "raw": "GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"})),
        )
        .await;
    assert_ne!(r.json()["status"], "denied");
    let r = h
        .bearer("PUT", "/api/v1/roe", &free, Some(json!({"yaml": "version: 1\nscope:\n  include: [\"http://x/\"]\n"})))
        .await;
    assert!(r.status >= 400, "an agent cannot change the rules of engagement: {} {}", r.status, r.body);
}

#[tokio::test]
async fn mcp_over_http_as_the_agent_and_as_the_person() {
    let h = Harness::start("mcp", true).await;
    let (secret, _) = h.make(json!({"kind": "agent", "name": "claude"})).await;
    let r = h.bearer("POST", "/api/v1/mcp", &secret, Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))).await;
    assert!(r.json()["result"]["tools"].as_array().unwrap().len() > 80);
    // An actor named in the message is ignored.
    let mut call = mcp(2, "roe_get", json!({}));
    call["params"]["actor"] = json!("human:tester");
    let roe = tool(&h.bearer("POST", "/api/v1/mcp", &secret, Some(call)).await);
    assert_eq!(roe["you_are"], "agent:claude");
    assert_eq!(roe["secrets_redacted"], true);
    assert!(roe.get("credential_tier_cap").is_none());
    let me = tool(&h.human("POST", "/api/v1/mcp", Some(mcp(3, "roe_get", json!({})))).await);
    assert_eq!(me["you_are"], "human:tester");
    assert_eq!(
        h.bearer("POST", "/api/v1/mcp", &secret, Some(json!({"jsonrpc":"2.0","method":"notifications/initialized"})))
            .await
            .status,
        204
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_token_file_others_can_read_is_refused_and_says_so() {
    use std::os::unix::fs::PermissionsExt;
    let h = Harness::start("perm", true).await;
    let (secret, _) = h.make(json!({"kind": "agent", "name": "claude"})).await;
    for name in ["tokens.json", "tokens.key"] {
        let mode = std::fs::metadata(h.dir.join(name)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
    assert_eq!(h.bearer("GET", "/api/v1/status", &secret, None).await.status, 200);
    std::fs::set_permissions(h.dir.join("tokens.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
    // No token works while the file is exposed; the person is told why when they manage tokens.
    assert_eq!(h.bearer("GET", "/api/v1/status", &secret, None).await.status, 401);
    let r = h.human("GET", "/api/v1/tokens", None).await;
    assert_eq!((r.status, r.code().as_str()), (500, "token_store"));
    assert!(r.json()["error"].as_str().unwrap().contains("readable by other users"), "{}", r.body);
    assert!(!r.body.contains(&secret));
    std::fs::set_permissions(h.dir.join("tokens.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(h.bearer("GET", "/api/v1/status", &secret, None).await.status, 200);
    // The file holds a hash, not the token.
    let text = std::fs::read_to_string(h.dir.join("tokens.json")).unwrap();
    assert!(!text.contains(&secret) && !text.contains(&secret[secret.len() - 24..]));
}
