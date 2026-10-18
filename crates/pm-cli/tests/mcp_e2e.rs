//! Drives the real `proxymind` binary: an MCP server for an agent, plus a
//! separate CLI process for the human who approves.

use std::process::Stdio;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const BIN: &str = env!("CARGO_BIN_EXE_proxymind");

async fn backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                let first = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or_default().to_string();
                let body = format!("{{\"you_sent\":\"{first}\"}}");
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

struct Mcp {
    _child: Child,
    stdin: ChildStdin,
    stdout: tokio::io::Lines<BufReader<ChildStdout>>,
    next_id: i64,
}

impl Mcp {
    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let msg = json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params});
        self.stdin.write_all(format!("{msg}\n").as_bytes()).await.unwrap();
        let line = tokio::time::timeout(std::time::Duration::from_secs(20), self.stdout.next_line())
            .await
            .expect("MCP server answered in time")
            .unwrap()
            .expect("MCP server still running");
        let v: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["id"], self.next_id);
        v
    }

    async fn tool(&mut self, name: &str, args: Value) -> Value {
        let r = self.request("tools/call", json!({"name": name, "arguments": args})).await;
        assert_eq!(r["result"]["isError"], false, "{r}");
        serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }
}

fn cli(project: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(BIN).arg("-p").arg(project).args(args).output().unwrap()
}

#[tokio::test]
async fn agent_and_human_work_through_mcp_and_cli() {
    let port = backend().await;
    let dir = std::env::temp_dir().join(format!("pm-cli-mcp-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.pmproj");
    let roe = dir.join("roe.yaml");
    std::fs::write(&roe, "version: 1\nscope:\n  include: [\"http://127.0.0.1:*/\"]\n").unwrap();

    let mut child = Command::new(BIN)
        .arg("-p")
        .arg(&project)
        .args(["mcp", "--actor", "agent:claude", "--roe"])
        .arg(&roe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut mcp = Mcp { _child: child, stdin, stdout, next_id: 0 };

    let init = mcp
        .request(
            "initialize",
            json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}),
        )
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "proxymind");
    mcp.stdin.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n").await.unwrap();

    let roe_view = mcp.tool("roe_get", json!({})).await;
    assert_eq!(roe_view["you_are"], "agent:claude");
    assert_eq!(roe_view["your_permissions"]["active_intrusive"], "approve");

    // GET runs directly.
    let url = format!("http://127.0.0.1:{port}");
    let sent = mcp.tool("replay_send", json!({"url": url, "raw": "GET /api/items/1 HTTP/1.1\nHost: x\n\n"})).await;
    assert_eq!(sent["status"], "sent", "{sent}");

    // POST waits for a human.
    let post = json!({"url": url, "raw": "POST /api/items HTTP/1.1\nHost: x\n\n{\"name\":\"x\"}"});
    let pending = mcp.tool("replay_send", post.clone()).await;
    assert_eq!(pending["status"], "pending_approval", "{pending}");
    let approval_id = pending["approval_id"].as_str().unwrap().to_string();

    // The human, in another process, sees and approves it.
    let list = cli(&project, &["approvals", "list"]);
    assert!(String::from_utf8_lossy(&list.stdout).contains(&approval_id));
    let ok = cli(&project, &["approvals", "approve", &approval_id, "--as", "human:omkar"]);
    assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
    let status = mcp.tool("approval_status", json!({"approval_id": approval_id})).await;
    assert_eq!(status["status"], "approved");

    let mut approved = post.clone();
    approved["approval_id"] = json!(approval_id);
    let done = mcp.tool("replay_send", approved.clone()).await;
    assert_eq!(done["status"], "sent", "{done}");
    // Single use.
    let again = mcp.request("tools/call", json!({"name":"replay_send","arguments": approved})).await;
    assert_eq!(again["result"]["isError"], true);

    // History shows the agent's work, and the audit chain is intact.
    let hist = mcp.tool("history_search", json!({"actor": "agent:claude"})).await;
    assert_eq!(hist["exchanges"].as_array().unwrap().len(), 2);
    let verify = cli(&project, &["audit", "verify"]);
    assert!(String::from_utf8_lossy(&verify.stdout).contains("audit log intact"), "{verify:?}");

    drop(mcp);
    let _ = std::fs::remove_dir_all(dir);
}
