//! `proxymind token`, `proxymind login` and the MCP bridge (ADR-0022 step 5), with the real binary: the single-user
//! file, a running `ui`, and a self-signed `serve --accounts` reached by pin.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pm-tok-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pm(dir: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_proxymind"));
    c.args(["--home", dir.join("home").to_str().unwrap(), "--project", dir.join("p.pmproj").to_str().unwrap()])
        .args(args);
    c
}

fn with_roe(dir: &Path) {
    let roe = dir.join("roe.yaml");
    std::fs::write(&roe, "version: 1\nscope:\n  include: [\"http://127.0.0.1:9/\"]\n").unwrap();
    assert!(pm(dir, &["roe", "use", roe.to_str().unwrap()]).output().unwrap().status.success());
}

struct Out {
    ok: bool,
    stdout: String,
    stderr: String,
}

fn run(c: &mut Command) -> Out {
    let o = c.output().unwrap();
    Out {
        ok: o.status.success(),
        stdout: String::from_utf8_lossy(&o.stdout).to_string(),
        stderr: String::from_utf8_lossy(&o.stderr).to_string(),
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn http(port: u16, method: &str, path: &str, token: &str, body: Option<&str>) -> (u16, String) {
    let body = body.unwrap_or_default();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return (0, String::new()) };
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    (head.split(' ').nth(1).and_then(|x| x.parse().ok()).unwrap_or(0), body.to_string())
}

fn wait_for(port: u16, token: &str) {
    for _ in 0..200 {
        // Any answer at all (even a 401) means it listens.
        if http(port, "GET", "/api/v1/status", token, None).0 != 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the server did not start");
}

/// One line to the bridge's stdin, and the next line of its stdout parsed.
fn ask(stdin: &mut std::process::ChildStdin, lines: &mpsc::Receiver<String>, line: &str) -> serde_json::Value {
    writeln!(stdin, "{line}").unwrap();
    serde_json::from_str(&lines.recv_timeout(Duration::from_secs(30)).expect("an answer from the bridge")).unwrap()
}

struct Proc {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn(c: &mut Command) -> Proc {
    let mut child = c.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (tx, rx) = mpsc::channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let err = child.stderr.take().unwrap();
    std::thread::spawn(move || for _ in BufReader::new(err).lines().map_while(Result::ok) {});
    Proc { child, lines: rx }
}

// ---- the single-user file -------------------------------------------------------------------------------------

#[test]
fn token_create_list_revoke_in_single_user_mode() {
    let dir = home("file");
    let create = |extra: &[&str]| {
        let mut args = vec!["token", "create"];
        args.extend_from_slice(extra);
        run(&mut pm(&dir, &args))
    };
    let made = create(&["--kind", "agent", "--name", "claude", "--tier-cap", "active_safe", "--expires", "7d"]);
    assert!(made.ok, "{}", made.stderr);
    // The secret is on stdout alone; the description and the warning are on stderr.
    let secret = made.stdout.trim().to_string();
    assert!(secret.starts_with("pm3_agent_") && !secret.contains(' ') && !secret.contains('\n'), "{secret}");
    assert!(made.stderr.contains("agent:claude") && made.stderr.contains("shown once"), "{}", made.stderr);
    assert!(!made.stderr.contains(&secret));
    // Private files, and only a hash in the file.
    let h = dir.join("home");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in ["tokens.json", "tokens.key"] {
            assert_eq!(std::fs::metadata(h.join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
        }
    }
    assert!(!std::fs::read_to_string(h.join("tokens.json")).unwrap().contains(&secret));
    // The rules: never owner, names, caps, lifetimes, duplicates.
    for bad in [
        &["--kind", "agent", "--name", "x", "--role", "owner"][..],
        &["--kind", "human", "--name", "x"],
        &["--kind", "agent", "--name", "bad name"],
        &["--kind", "agent", "--name", "x", "--tier-cap", "everything"],
        &["--kind", "agent", "--name", "x", "--expires", "400d"],
        &["--kind", "agent", "--name", "x", "--expires", "soon"],
        &["--kind", "agent", "--name", "CLAUDE"],
    ] {
        assert!(!create(bad).ok, "{bad:?}");
    }
    let list = run(&mut pm(&dir, &["token", "list"]));
    assert!(list.ok);
    assert!(
        list.stdout.contains("agent:claude") && list.stdout.contains("active_safe") && list.stdout.contains("active")
    );
    assert!(!list.stdout.contains(&secret));
    let json = run(&mut pm(&dir, &["token", "list", "--json"]));
    let rows: serde_json::Value = serde_json::from_str(&json.stdout).unwrap();
    let id = rows[0]["id"].as_str().unwrap().to_string();
    assert_eq!((rows[0]["actor"].as_str(), rows[0]["role"].as_str()), (Some("agent:claude"), Some("tester")));
    assert!(!json.stdout.contains(&secret) && !json.stdout.contains("hash"));
    let r = run(&mut pm(&dir, &["token", "revoke", &id]));
    assert!(r.ok, "{}", r.stderr);
    assert!(run(&mut pm(&dir, &["token", "list"])).stdout.contains("revoked"));
    assert!(!run(&mut pm(&dir, &["token", "revoke", &id])).ok, "twice");
    // Server-only options are refused without --server-home.
    assert!(!run(&mut pm(&dir, &["token", "list", "--user", "x"])).ok);
    // A file others can read is refused, and the message says so.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(h.join("tokens.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
        let r = run(&mut pm(&dir, &["token", "list"]));
        assert!(!r.ok && r.stderr.contains("readable by other users"), "{}", r.stderr);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_running_ui_uses_tokens_made_and_revoked_by_the_cli_and_the_bridge_reaches_it() {
    let dir = home("ui");
    with_roe(&dir);
    let port = free_port();
    let ui = spawn(&mut pm(&dir, &["ui", "--listen", &format!("127.0.0.1:{port}"), "--no-proxy"]));
    let install = {
        let mut token = String::new();
        for _ in 0..200 {
            if let Ok(t) = std::fs::read_to_string(dir.join("home").join("api-token")) {
                token = t.trim().to_string();
                if http(port, "GET", "/api/v1/status", &token, None).0 == 200 {
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        token
    };
    assert!(!install.is_empty());
    let _keep = &ui.lines;
    // Made while it runs: works at once.
    let made = run(&mut pm(&dir, &["token", "create", "--kind", "agent", "--name", "claude"]));
    let secret = made.stdout.trim().to_string();
    let (st, body) = http(port, "GET", "/api/v1/status", &secret, None);
    assert_eq!(st, 200, "{body}");
    assert!(body.contains("\"you_are\":\"agent:claude\""), "{body}");
    assert!(
        http(port, "GET", "/api/v1/status", &install, None).1.contains("human:"),
        "the install token is still the human"
    );
    // The bridge over plain HTTP on loopback: the agent's tools through the server.
    let mut bridge = spawn(
        pm(&dir, &["mcp", "--server", &format!("http://127.0.0.1:{port}"), "--token-env", "PM_TEST_TOKEN_UI"])
            .env("PM_TEST_TOKEN_UI", &secret)
            .stdin(Stdio::piped()),
    );
    let mut stdin = bridge.child.stdin.take().unwrap();
    let init = ask(
        &mut stdin,
        &bridge.lines,
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
    );
    assert_eq!(init["result"]["serverInfo"]["name"], "proxymind");
    writeln!(stdin, r#"{{"jsonrpc":"2.0","method":"notifications/initialized"}}"#).unwrap();
    let tools = ask(&mut stdin, &bridge.lines, r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#);
    assert!(tools["result"]["tools"].as_array().unwrap().len() > 80);
    let roe = ask(
        &mut stdin,
        &bridge.lines,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"roe_get","arguments":{}}}"#,
    );
    let text = roe["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("\"you_are\":\"agent:claude\""), "{text}");
    // Revoked by the CLI: the next message is refused, as an error to the client; the bridge itself goes on.
    let list = run(&mut pm(&dir, &["token", "list", "--json"]));
    let id = serde_json::from_str::<serde_json::Value>(&list.stdout).unwrap()[0]["id"].as_str().unwrap().to_string();
    assert!(run(&mut pm(&dir, &["token", "revoke", &id])).ok);
    let refused = ask(
        &mut stdin,
        &bridge.lines,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"roe_get","arguments":{}}}"#,
    );
    assert_eq!(refused["id"], 4);
    assert!(refused["error"]["message"].as_str().unwrap().contains("refused the token"), "{refused}");
    assert_eq!(http(port, "GET", "/api/v1/status", &secret, None).0, 401);
    drop(stdin);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- a self-signed server, by pin -----------------------------------------------------------------------------

/// A server home with an owner who is a member of the project, made before the server starts (the CLI's
/// `--server-home` is what an operator uses on the host).
fn prepare_server(dir: &Path, port: u16) {
    // First start: makes server.db, server.key and the project's id; stopped once it answers.
    let first = spawn(&mut pm(
        dir,
        &[
            "serve",
            "--accounts",
            "--server-home",
            dir.join("server").to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{port}"),
        ],
    ));
    wait_for(port, "x");
    drop(first);
    let project = pm_store::Store::open(&dir.join("p.pmproj")).unwrap().get_setting("project_id").unwrap().unwrap();
    let key = pm_accounts::ServerKey::load_or_create(&dir.join("server").join("server.key")).unwrap();
    let acc = pm_accounts::Accounts::open(&dir.join("server").join("server.db"), key).unwrap();
    let setup = acc.create_setup_token().unwrap();
    let owner = acc
        .bootstrap_owner(
            setup.token.expose(),
            "owner",
            "Owner",
            "correct horse battery staple",
            &pm_accounts::ClientInfo::new("127.0.0.1"),
        )
        .unwrap();
    acc.set_membership(&owner.id, &project, &owner.id, pm_accounts::Role::Owner).unwrap();
}

#[test]
fn login_and_the_bridge_against_a_self_signed_server_need_the_right_pin() {
    let dir = home("tls");
    with_roe(&dir);
    let port = free_port();
    prepare_server(&dir, port);
    let sh = dir.join("server");
    let sh = sh.to_str().unwrap();
    // Start it again with a self-signed certificate; the pin is on its console.
    let url = format!("https://localhost:{port}");
    let server = spawn(&mut pm(
        &dir,
        &[
            "serve",
            "--accounts",
            "--server-home",
            sh,
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--tls-self-signed",
            "--public-url",
            &url,
        ],
    ));
    let pin = loop {
        let l = server.lines.recv_timeout(Duration::from_secs(60)).expect("the server printed its pin");
        if let Some(p) = l.strip_prefix("Pin (SHA-256 of its public key): ") {
            break p.trim().to_string();
        }
    };
    assert!(pin.starts_with("sha256:"));
    std::thread::sleep(Duration::from_millis(500));

    // The operator makes a token on the host, for the owner.
    let made = run(&mut pm(
        &dir,
        &[
            "token",
            "create",
            "--server-home",
            sh,
            "--user",
            "owner",
            "--kind",
            "agent",
            "--name",
            "claude",
            "--tier-cap",
            "active_safe",
        ],
    ));
    assert!(made.ok, "{}", made.stderr);
    let secret = made.stdout.trim().to_string();
    // Without --user a server's token has no owner; for an unknown user, a refusal.
    assert!(!run(&mut pm(&dir, &["token", "create", "--server-home", sh, "--kind", "agent", "--name", "x"])).ok);
    assert!(
        !run(&mut pm(
            &dir,
            &["token", "create", "--server-home", sh, "--user", "nobody", "--kind", "agent", "--name", "x"]
        ))
        .ok
    );
    let list = run(&mut pm(&dir, &["token", "list", "--server-home", sh, "--user", "owner"]));
    assert!(list.stdout.contains("agent:claude"), "{}{}", list.stdout, list.stderr);
    let servers = dir.join("home").join("servers.json");

    // A wrong pin fails hard and saves nothing.
    let wrong = "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    let r = run(pm(&dir, &["login", &url, "--pin", wrong, "--token-env", "PM_TEST_TOKEN_TLS"])
        .env("PM_TEST_TOKEN_TLS", &secret));
    assert!(!r.ok, "{}", r.stdout);
    assert!(r.stderr.contains("does not match the pin") && r.stderr.contains(&pin), "{}", r.stderr);
    assert!(!servers.exists(), "nothing is saved after a failed check");
    assert!(!r.stderr.contains(&secret) && !r.stdout.contains(&secret));
    // No pin for a certificate no public CA signed: refused too (never trusted silently).
    let r = run(pm(&dir, &["login", &url, "--token-env", "PM_TEST_TOKEN_TLS"]).env("PM_TEST_TOKEN_TLS", &secret));
    assert!(!r.ok && r.stderr.contains("TLS verification failed"), "{}", r.stderr);
    assert!(!servers.exists());
    // Not a token at all: refused before anything is sent.
    let r = run(pm(&dir, &["login", &url, "--pin", &pin, "--token-env", "PM_TEST_TOKEN_TLS"])
        .env("PM_TEST_TOKEN_TLS", "not-a-token"));
    assert!(!r.ok && r.stderr.contains("not a ProxyMind token"), "{}", r.stderr);
    // The right pin: signed in as the token's agent, and saved owner-only.
    let r =
        run(pm(&dir, &["login", &url, "--pin", &pin, "--token-env", "PM_TEST_TOKEN_TLS"])
            .env("PM_TEST_TOKEN_TLS", &secret));
    assert!(r.ok, "{}", r.stderr);
    assert!(r.stdout.contains("as agent:claude") && r.stdout.contains("p.pmproj"), "{}", r.stdout);
    assert!(!r.stdout.contains(&secret));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&servers).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let saved: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&servers).unwrap()).unwrap();
    assert_eq!(saved["servers"][0]["pin"], pin.as_str());
    assert_eq!(saved["servers"][0]["url"], url.as_str());
    // The token can also come from stdin (no terminal): no echo to worry about, nothing on the command line.
    let mut c = pm(&dir, &["login", &url, "--pin", &pin]);
    let mut child = c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    writeln!(child.stdin.take().unwrap(), "{secret}").unwrap();
    let o = child.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // A saved pin is used when none is given, and a login without --pin cannot weaken it.
    let r = run(pm(&dir, &["login", &url, "--token-env", "PM_TEST_TOKEN_TLS"]).env("PM_TEST_TOKEN_TLS", &secret));
    assert!(r.ok, "{}", r.stderr);

    // The bridge: the saved pin and token are used; the agent's tools run on the server.
    let mut bridge = spawn(pm(&dir, &["mcp", "--server", &url]).stdin(Stdio::piped()));
    let mut stdin = bridge.child.stdin.take().unwrap();
    let roe = ask(
        &mut stdin,
        &bridge.lines,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"roe_get","arguments":{}}}"#,
    );
    let text = roe["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("\"you_are\":\"agent:claude\"") && text.contains("\"credential_tier_cap\":\"active_safe\""),
        "{text}"
    );
    drop(stdin);
    // A wrong pin on the bridge: it ends at once with the reason, and answers nothing.
    let r = run(&mut pm(&dir, &["mcp", "--server", &url, "--pin", wrong]));
    assert!(!r.ok && r.stderr.contains("does not match the pin"), "{}", r.stderr);
    assert!(r.stdout.is_empty());
    // Revoked on the host: login and the bridge both say the server refused it.
    let id = serde_json::from_str::<serde_json::Value>(
        &run(&mut pm(&dir, &["token", "list", "--server-home", sh, "--user", "owner", "--json"])).stdout,
    )
    .unwrap()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(run(&mut pm(&dir, &["token", "revoke", "--server-home", sh, &id])).ok);
    let r = run(&mut pm(&dir, &["mcp", "--server", &url]));
    assert!(!r.ok && r.stderr.contains("refused the token"), "{}", r.stderr);
    // Logout forgets the entry.
    assert!(run(&mut pm(&dir, &["logout", &url])).ok);
    let r = run(&mut pm(&dir, &["mcp", "--server", &url]));
    assert!(!r.ok && r.stderr.contains("proxymind login"), "{}", r.stderr);
    drop(server);
    let _ = std::fs::remove_dir_all(&dir);
}
