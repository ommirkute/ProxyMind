//! The v0.1 demo, end to end, with the real binary:
//! browse VulnShop through the proxy as three users, capture identities,
//! then let an "agent" work purely over MCP to find and prove the access
//! control bugs, and score the result against the ground truth.

use std::process::Stdio;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const BIN: &str = env!("CARGO_BIN_EXE_proxymind");

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn cli(project: &std::path::Path, args: &[&str]) -> String {
    let out = std::process::Command::new(BIN).arg("-p").arg(project).args(args).output().unwrap();
    assert!(out.status.success(), "proxymind {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Waits until something listens on the port (a cold binary can take a while to start on CI).
async fn wait_for_port(port: u16) {
    for _ in 0..300 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing listening on port {port} after 15 s");
}

/// Sends one request through the proxy and returns the raw response.
async fn via_proxy(proxy: u16, shop: u16, req: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    let req = req.replacen(" /", &format!(" http://127.0.0.1:{shop}/"), 1);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut out)).await;
    out
}

async fn browse_as(proxy: u16, shop: u16, user: &str, paths: &[&str]) {
    let body = format!("{{\"username\":\"{user}\",\"password\":\"{user}123\"}}");
    let login = via_proxy(
        proxy,
        shop,
        &format!("POST /api/login HTTP/1.1\r\nHost: shop\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()),
    )
    .await;
    let session = login.split("session=").nth(1).unwrap().split(';').next().unwrap().to_string();
    for p in paths {
        via_proxy(proxy, shop, &format!("GET {p} HTTP/1.1\r\nHost: shop\r\nCookie: session={session}\r\n\r\n")).await;
    }
}

struct Mcp {
    _child: Child,
    stdin: ChildStdin,
    stdout: tokio::io::Lines<BufReader<ChildStdout>>,
    id: i64,
}

impl Mcp {
    async fn call(&mut self, name: &str, args: Value) -> Value {
        self.id += 1;
        let msg = json!({"jsonrpc":"2.0","id":self.id,"method":"tools/call","params":{"name":name,"arguments":args}});
        self.stdin.write_all(format!("{msg}\n").as_bytes()).await.unwrap();
        let line =
            tokio::time::timeout(Duration::from_secs(30), self.stdout.next_line()).await.unwrap().unwrap().unwrap();
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["result"]["isError"], false, "{name}: {v}");
        serde_json::from_str(v["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }
}

#[tokio::test]
async fn agent_finds_and_proves_access_control_bugs_over_mcp() {
    let shop = pm_demo::VulnShop::start_local().await.unwrap().port();
    let dir = std::env::temp_dir().join(format!("pm-demo-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("demo.pmproj");

    // 1. A human browses as three users through the proxy.
    let proxy_port = free_port();
    let mut proxy = Command::new(BIN)
        .arg("-p")
        .arg(&project)
        .arg("--home")
        .arg(dir.join("home"))
        .args(["proxy", "--listen", &format!("127.0.0.1:{proxy_port}")])
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    wait_for_port(proxy_port).await;
    browse_as(proxy_port, shop, "alice", &["/api/me", "/api/orders", "/api/orders/1001", "/api/invoices/5001"]).await;
    browse_as(proxy_port, shop, "bob", &["/api/me", "/api/orders", "/api/orders/2001"]).await;
    browse_as(proxy_port, shop, "admin", &["/api/me", "/api/admin/users"]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    proxy.kill().await.unwrap();

    // 2. The human sets the rules and captures the three sessions.
    std::fs::write(dir.join("roe.yaml"), format!("version: 1\nscope:\n  include: [\"http://127.0.0.1:{shop}/\"]\n"))
        .unwrap();
    cli(&project, &["roe", "use", dir.join("roe.yaml").to_str().unwrap()]);
    let history: Value = serde_json::from_str(&cli(&project, &["history", "--json", "-n", "100"])).unwrap();
    let rows = history.as_array().unwrap();
    // Each user's /api/me request (oldest first: alice, bob, admin).
    let mut me: Vec<i64> = rows.iter().filter(|r| r["path"] == "/api/me").map(|r| r["id"].as_i64().unwrap()).collect();
    me.sort();
    for (who, role, id) in [("alice", "user", me[0]), ("bob", "user", me[1]), ("admin", "admin", me[2])] {
        cli(&project, &["identity", "capture", who, "--from", &id.to_string(), "--role", role]);
    }

    // 3. The agent works only through MCP.
    let mut child = Command::new(BIN)
        .arg("-p")
        .arg(&project)
        .args(["mcp", "--actor", "agent:claude"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut mcp = Mcp { _child: child, stdin, stdout, id: 0 };

    let model = mcp.call("model_get", json!({})).await;
    let model_text = model.to_string();
    assert!(model_text.contains("/api/orders/{id}"), "{model_text}");

    let ids = mcp.call("identity_list", json!({})).await;
    assert_eq!(ids.as_array().unwrap().len(), 3);

    let candidates = mcp.call("authz_candidates", json!({})).await;
    let cands = candidates.as_array().unwrap();
    let order = cands.iter().find(|c| c["object"] == "Order 1001").expect("order candidate");
    let admin_fn =
        cands.iter().find(|c| c["operation"].as_str().unwrap().contains("/api/admin/users")).expect("admin candidate");

    let mut proven = 0;
    for (cand, class, title) in
        [(order, "idor", "Any user can read any order"), (admin_fn, "bfla", "Users can list all accounts")]
    {
        let ex = cand["exchange_id"].as_i64().unwrap();
        let check = mcp.call("authz_check", json!({"exchange_id": ex, "identities": cand["try_as"]})).await;
        let hit = check["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["verdict"] == "same_as_owner" && r["identity"] == "bob")
            .unwrap_or_else(|| panic!("no hit for {class}: {check}"));
        let finding = mcp
            .call(
                "finding_create",
                json!({"title": title, "vuln_class": class, "severity": "high",
                       "description": "bob received another user's data", "evidence": [ex, hit["evidence_id"]]}),
            )
            .await;
        let proof = mcp
            .call(
                "proof_run",
                json!({"oracle": "differential_authz", "exchange_id": ex, "attacker": "bob", "finding_id": finding["id"]}),
            )
            .await;
        assert_eq!(proof["proven"], true, "{proof}");
        proven += 1;
    }
    assert_eq!(proven, 2);

    // The secure invoice must not be provable.
    let invoice = rows.iter().find(|r| r["path"] == "/api/invoices/5001").unwrap()["id"].as_i64().unwrap();
    let p =
        mcp.call("proof_run", json!({"oracle": "differential_authz", "exchange_id": invoice, "attacker": "bob"})).await;
    assert_eq!(p["proven"], false, "{p}");

    // The agent never saw a session value.
    for id in &me {
        let raw = cli(&project, &["show", &id.to_string()]);
        let session = raw.split("session=").nth(1).unwrap().split(['\r', '\n', ';']).next().unwrap().to_string();
        assert!(!model_text.contains(&session) && !candidates.to_string().contains(&session));
    }
    drop(mcp);

    // 4. Score and report.
    let score: Value = serde_json::from_str(&cli(&project, &["bench", "score", "--json"])).unwrap();
    let state = |id: &str| score["vulns"].as_array().unwrap().iter().find(|v| v["id"] == id).unwrap()["proven"].clone();
    assert_eq!((state("VS-1"), state("VS-2")), (json!(true), json!(true)), "{score}");
    assert!(score["findings_on_secure_endpoints"].as_array().unwrap().is_empty());
    let report = cli(&project, &["report"]);
    assert!(report.contains("Any user can read any order") && report.contains("hash chain verified"));
    assert!(cli(&project, &["audit", "verify"]).contains("audit log intact"));
    let _ = std::fs::remove_dir_all(dir);
}
