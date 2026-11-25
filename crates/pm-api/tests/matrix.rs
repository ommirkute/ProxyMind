//! ADR-0022 step 6: the access matrix. Every REST route and every MCP tool is driven, in server mode over a real
//! socket, as an owner, a tester, a viewer, an agent token (ceiling tester, owned by the owner), a viewer token and
//! an unauthenticated client, and the answers are compared with `docs/access-matrix.md`.
//!
//! *Allowed* means authorization let the request through: any answer except 401 and 403 (a 400, 404 or 422 for the
//! empty input this test sends counts as allowed). *Denied* means 401 or 403 and, for an MCP tool, the tool's
//! `access denied:` error. The committed table is the review artifact: a role that gains or loses a route shows up
//! as a diff. To refresh it after changing the rules:
//! `UPDATE_ACCESS_MATRIX=1 cargo test -p pm-api --test matrix`.
//!
//! Nothing here reaches a real target: the project's scope is a closed port, and every request carries an empty body.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pm_accounts::{Accounts, ClientInfo, Clock, Config, ManualClock, NewTokenSpec, Role, ServerKey, TokenKind};
use pm_api::listen::{ListenInput, TlsKind, plan, serve_app};
use pm_api::{AppState, ServerMode};
use pm_service::Service;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PW: &str = "correct horse battery staple";
const PRINCIPALS: [&str; 6] = ["owner", "tester", "viewer", "agent token", "viewer token", "anonymous"];

struct Server {
    port: u16,
    accounts: Arc<Accounts>,
    ids: [String; 3],
    tokens: [String; 2],
    _svc: Arc<Service>,
}

enum Who {
    Session(usize),
    Token(usize),
    Nobody,
}

impl Server {
    async fn start() -> Self {
        let clock = Arc::new(ManualClock::new(1_700_000_000));
        let accounts = Arc::new(
            Accounts::open_in_memory(ServerKey::from_bytes([9; 32]), Config::insecure_for_tests(), clock.clone())
                .unwrap(),
        );
        let svc = Arc::new(
            Service::new(
                Store::open_in_memory().unwrap(),
                Policy::new(Roe::parse("version: 1\nscope:\n  include: [\"http://127.0.0.1:9/\"]\n").unwrap()),
            )
            .unwrap(),
        );
        let project = svc.project_id().unwrap();
        let client = ClientInfo::default();
        let setup = accounts.create_setup_token().unwrap();
        let owner = accounts.bootstrap_owner(setup.token.expose(), "owner", "Owner", PW, &client).unwrap();
        accounts.set_membership(&owner.id, &project, &owner.id, Role::Owner).unwrap();
        let mut ids = vec![owner.id.clone()];
        for (name, role) in [("tess", Role::Tester), ("vic", Role::Viewer)] {
            let invite = accounts.create_invite(&owner.id, role, Some(&project), Duration::from_secs(3600)).unwrap();
            let user = accounts.accept_invite(invite.token.expose(), name, name, PW, &client).unwrap();
            ids.push(user.id);
        }
        let token = |name: &str, role: Role| {
            let mut spec = NewTokenSpec::new(TokenKind::Agent, name);
            spec.role = role;
            accounts.create_token(&owner.id, &owner.id, &project, &spec).unwrap().token.expose().to_string()
        };
        let tokens = [token("matrix-agent", Role::Tester), token("matrix-viewer", Role::Viewer)];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let listen: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let plan = plan(&ListenInput {
            listen,
            tls: TlsKind::None,
            behind_proxy: false,
            trusted_proxies: &[],
            public_url: None,
            extra_hosts: &[],
        })
        .unwrap();
        let sm = ServerMode::new(accounts.clone(), clock as Arc<dyn Clock>, project, plan);
        let state = AppState::new(
            svc.clone(),
            Actor::parse("human:unused").unwrap(),
            "install-token-that-server-mode-must-refuse".into(),
            "matrix.pmproj".into(),
        )
        .unwrap()
        .with_server_mode(sm);
        tokio::spawn(async move { serve_app(listener, pm_api::router(state), None).await.unwrap() });
        Self { port, accounts, ids: [ids[0].clone(), ids[1].clone(), ids[2].clone()], tokens, _svc: svc }
    }

    /// One request as `who`. A session principal gets a fresh session each time, so a route that ends sessions
    /// (sign out, revoke all) does not change what the next request is.
    async fn call(&self, who: &Who, method: &str, path: &str, body: Option<&Value>) -> (u16, String) {
        let mut headers = vec![
            ("Host".to_string(), format!("127.0.0.1:{}", self.port)),
            ("Connection".to_string(), "close".to_string()),
        ];
        match who {
            Who::Session(i) => {
                let s = self.accounts.create_session(&self.ids[*i], "test", &ClientInfo::default()).unwrap();
                headers.push(("Cookie".into(), format!("pm_session={}", s.id.expose())));
                headers.push(("X-ProxyMind".into(), "1".into()));
                headers.push(("Origin".into(), format!("http://127.0.0.1:{}", self.port)));
            }
            Who::Token(i) => headers.push(("Authorization".into(), format!("Bearer {}", self.tokens[*i]))),
            Who::Nobody => {
                headers.push(("X-ProxyMind".into(), "1".into()));
                headers.push(("Origin".into(), format!("http://127.0.0.1:{}", self.port)));
            }
        }
        let body = body.map(Value::to_string).unwrap_or_default();
        let mut req = format!("{method} {path} HTTP/1.1\r\n");
        for (k, v) in &headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        if !body.is_empty() {
            req.push_str(&format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body.len()));
        } else if method != "GET" {
            req.push_str("Content-Length: 0\r\n");
        }
        req.push_str("\r\n");
        req.push_str(&body);
        let mut s = TcpStream::connect(("127.0.0.1", self.port)).await.unwrap();
        s.write_all(req.as_bytes()).await.unwrap();
        // An event stream never ends: the status line and headers are the answer.
        let events = path.starts_with("/api/v1/events");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let read = async {
            loop {
                match s.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if events && buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
        };
        let _ = tokio::time::timeout(Duration::from_secs(20), read).await;
        let text = String::from_utf8_lossy(&buf).to_string();
        let status = text.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
        (status, body)
    }
}

fn who(i: usize) -> Who {
    match i {
        0..=2 => Who::Session(i),
        3 | 4 => Who::Token(i - 3),
        _ => Who::Nobody,
    }
}

/// A concrete path for a route template: ids that name nothing, so no real object is touched.
fn concrete(path: &str, id_is_string: bool) -> String {
    path.split('/')
        .map(|seg| match seg {
            "{id}" if id_is_string => "x".to_string(),
            "{id}" => "999999".to_string(),
            "{action}" => "cancel".into(),
            "{decision}" => "approve".into(),
            "{kind}" => "request".into(),
            "{addr}" => "192.0.2.1".into(),
            "{user_id}" => "u_00000000000000000000000000000000".into(),
            s if s.starts_with('{') => "x".to_string(),
            s => s.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn letter(allowed: bool) -> &'static str {
    if allowed { "allow" } else { "deny" }
}

async fn rest_rows(server: &Server) -> Vec<(String, [bool; 6])> {
    let mut rows = Vec::new();
    for op in pm_api::contracts::operations() {
        let path = concrete(&op.path, op.id_is_string);
        let method = op.method.to_ascii_uppercase();
        // Empty input, except where the handler reads the body before it asks about the role (invites, tokens).
        let body = match (method.as_str(), op.path.as_str()) {
            ("POST", "/api/v1/auth/invites") => Some(json!({ "role": "viewer" })),
            ("POST", "/api/v1/tokens") => Some(json!({ "kind": "agent", "name": "matrix-made" })),
            ("GET" | "DELETE", _) => None,
            _ => Some(json!({})),
        };
        let mut answers = [false; 6];
        for (i, slot) in answers.iter_mut().enumerate() {
            let (status, _) = server.call(&who(i), &method, &path, body.as_ref()).await;
            assert_ne!(status, 0, "{method} {path} as {}: no answer", PRINCIPALS[i]);
            *slot = !matches!(status, 401 | 403);
        }
        rows.push((format!("{method} {}", op.path.trim_start_matches("/api/v1")), answers));
    }
    rows
}

async fn mcp_rows(server: &Server) -> Vec<(String, [bool; 6])> {
    let mut rows = Vec::new();
    for tool in pm_mcp::tool_definitions() {
        let name = tool["name"].as_str().unwrap().to_string();
        let msg =
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": { "name": name, "arguments": {} } });
        let mut answers = [false; 6];
        for (i, slot) in answers.iter_mut().enumerate() {
            let (status, body) = server.call(&who(i), "POST", "/api/v1/mcp", Some(&msg)).await;
            *slot = match status {
                401 | 403 => false,
                200 => {
                    let v: Value = serde_json::from_str(&body).unwrap_or_else(|e| panic!("{name}: {e}: {body}"));
                    let text = v["result"]["content"][0]["text"].as_str().unwrap_or_default();
                    !(v["result"]["isError"] == true && text.starts_with("access denied:"))
                }
                other => panic!("{name} as {}: unexpected status {other}: {body}", PRINCIPALS[i]),
            };
        }
        rows.push((name, answers));
    }
    rows
}

fn render(rest: &[(String, [bool; 6])], tools: &[(String, [bool; 6])]) -> String {
    let mut s = String::from(
        "# Access matrix\n\n\
         <!-- Generated by `crates/pm-api/tests/matrix.rs`. Do not edit by hand: run \
         `UPDATE_ACCESS_MATRIX=1 cargo test -p pm-api --test matrix`. -->\n\n\
         What each kind of caller may do on a project server (ADR-0022 step 6, `docs/access.md`). Every REST route and \
         every MCP tool is driven as an **owner**, a **tester** and a **viewer** (signed-in sessions), an **agent \
         token** (ceiling tester, owned by the owner), a **viewer token** and an **anonymous** client. `allow` means \
         authorization let the request through (the request itself may still be refused for bad input: 400, 404, 422); \
         `deny` means 401 or 403, or for a tool the `access denied` error. The sign-in routes are open to anonymous \
         clients on purpose; the account routes decide for themselves (server admins manage accounts; an owner of the \
         project manages members). The test fails when this file and the server disagree.\n\n",
    );
    for (title, rows, first) in [("REST routes", rest, "Route"), ("MCP tools", tools, "Tool")] {
        s.push_str(&format!(
            "## {title}\n\n| {first} | owner | tester | viewer | agent token | viewer token | anonymous |\n"
        ));
        s.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
        for (name, a) in rows {
            let cells: Vec<&str> = a.iter().map(|x| letter(*x)).collect();
            s.push_str(&format!("| `{name}` | {} |\n", cells.join(" | ")));
        }
        s.push('\n');
    }
    s
}

fn doc_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/access-matrix.md")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_access_matrix_matches_the_committed_table() {
    let server = Server::start().await;
    let rest = rest_rows(&server).await;
    let tools = mcp_rows(&server).await;
    assert!(rest.len() > 230, "only {} routes were driven", rest.len());
    assert!(tools.len() > 80, "only {} tools were driven", tools.len());

    // The structural promises, whatever the table says.
    let find =
        |rows: &[(String, [bool; 6])], name: &str| rows.iter().find(|(n, _)| n == name).map(|(_, a)| *a).unwrap();
    for (name, a) in rest.iter().chain(tools.iter()) {
        // Roles only ever narrow: a viewer may do nothing a tester may not, a tester nothing an owner may not.
        assert!(!a[2] || a[1], "{name}: a viewer may but a tester may not");
        assert!(!a[1] || a[0], "{name}: a tester may but an owner may not");
        // A viewer token acts as a viewer: no more than the viewer, and no more than the agent token.
        assert!(!a[4] || a[2], "{name}: a viewer token may but a viewer may not");
        assert!(!a[4] || a[3], "{name}: a viewer token may but the agent token may not");
    }
    // An owner's agent token is still an agent: nothing people-only, nothing owner-only.
    for route in ["PUT /roe", "POST /approvals/{id}/{decision}", "PUT /network", "PUT /auth/members/{user_id}"] {
        assert!(!find(&rest, route)[3], "{route} must stay closed to an agent token");
    }
    // The anonymous client reaches only the sign-in routes and the setup probe.
    for (name, a) in &rest {
        if a[5] {
            assert!(
                name.starts_with("GET /auth/state") || name.starts_with("POST /auth/"),
                "{name} is open to anonymous clients"
            );
        }
    }
    assert!(find(&rest, "GET /exchanges")[2], "a viewer reads history");
    assert!(!find(&rest, "POST /replay")[2], "a viewer does not send");
    assert!(find(&rest, "POST /replay")[1], "a tester sends");
    assert!(!find(&rest, "PUT /roe")[1] && find(&rest, "PUT /roe")[0], "only the owner changes the ROE");
    assert!(find(&rest, "PUT /auth/members/{user_id}")[0], "an owner manages members");
    assert!(!find(&rest, "GET /auth/members")[1], "a tester does not");
    assert!(!find(&rest, "GET /events")[5] && find(&rest, "GET /events")[2], "viewers get the stream");

    let want = render(&rest, &tools);
    let path = doc_path();
    if std::env::var_os("UPDATE_ACCESS_MATRIX").is_some() {
        std::fs::write(&path, &want).unwrap();
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    if have != want {
        let diff: Vec<String> = want
            .lines()
            .zip(have.lines().chain(std::iter::repeat("")))
            .filter(|(a, b)| a != b)
            .take(12)
            .map(|(a, b)| format!("  now:  {a}\n  file: {b}"))
            .collect();
        panic!(
            "docs/access-matrix.md is out of date: run `UPDATE_ACCESS_MATRIX=1 cargo test -p pm-api --test matrix`\n{}",
            diff.join("\n")
        );
    }
}
