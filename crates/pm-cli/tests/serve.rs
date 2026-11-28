//! `proxymind serve --accounts` and `proxymind server reset-owner` (ADR-0022 step 4): refusals before anything is
//! touched, and one real start with a setup, a sign-in and a reset.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

fn home(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pm-serve-{name}-{}", std::process::id()));
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
    std::fs::write(&roe, "version: 1\nscope:\n  include: [\"https://client.example/\"]\n").unwrap();
    assert!(pm(dir, &["roe", "use", roe.to_str().unwrap()]).output().unwrap().status.success());
}

fn refused(dir: &Path, args: &[&str]) -> String {
    let out = pm(dir, args).output().unwrap();
    assert!(!out.status.success(), "{args:?} must be refused");
    String::from_utf8_lossy(&out.stderr).to_string()
}

#[test]
fn unsafe_combinations_are_refused_before_anything_is_opened() {
    let dir = home("refuse");
    with_roe(&dir);
    let sh = dir.join("server");
    let sh = sh.to_str().unwrap();
    let base = ["serve", "--accounts", "--server-home", sh];
    let run = |extra: &[&str]| refused(&dir, &[&base[..], extra].concat());
    // Plain HTTP beyond loopback: refused, the message names the way out.
    for listen in ["0.0.0.0:7777", "192.168.1.10:7777", "[::]:7777"] {
        let e = run(&["--listen", listen]);
        assert!(e.contains("without TLS") && e.contains("--behind-proxy"), "{listen}: {e}");
    }
    // The same with a public URL and allowed hosts: still plain HTTP.
    assert!(
        run(&["--listen", "0.0.0.0:7777", "--public-url", "http://pm.example.com", "--allowed-host", "pm.example.com"])
            .contains("without TLS")
    );
    // TLS needs the public URL beyond loopback; a proxy needs its address; the two do not mix.
    assert!(run(&["--listen", "0.0.0.0:7777", "--tls-self-signed"]).contains("--public-url"));
    assert!(
        run(&["--listen", "127.0.0.1:7777", "--behind-proxy", "--public-url", "https://pm.example.com"])
            .contains("--trusted-proxy")
    );
    assert!(
        run(&[
            "--listen",
            "0.0.0.0:7777",
            "--behind-proxy",
            "--trusted-proxy",
            "10.0.0.2",
            "--public-url",
            "https://pm.example.com"
        ])
        .contains("loopback or private")
    );
    assert!(
        run(&[
            "--behind-proxy",
            "--tls-self-signed",
            "--trusted-proxy",
            "10.0.0.2",
            "--public-url",
            "https://pm.example.com"
        ])
        .contains("terminates TLS")
    );
    assert!(
        run(&["--tls-self-signed", "--tls-cert", "a.pem", "--tls-key", "b.pem"]).contains("one certificate source")
    );
    assert!(run(&["--tls-cert", "a.pem"]).contains("--tls-key"));
    assert!(run(&["--trusted-proxy", "10.0.0.2"]).contains("--behind-proxy"));
    // `serve` without --accounts is not a mode of its own.
    assert!(refused(&dir, &["serve", "--server-home", sh]).contains("--accounts"));
    assert!(!Path::new(sh).exists(), "a refused start creates nothing");
    let _ = std::fs::remove_dir_all(&dir);
}

fn spawn_server(dir: &Path, port: u16, extra: &[&str]) -> (Child, mpsc::Receiver<String>) {
    let sh = dir.join("server");
    let mut child = pm(
        dir,
        &["serve", "--accounts", "--server-home", sh.to_str().unwrap(), "--listen", &format!("127.0.0.1:{port}")],
    )
    .args(extra)
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let (tx, rx) = mpsc::channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    (child, rx)
}

fn http(
    port: u16,
    method: &str,
    path: &str,
    cookie: Option<&str>,
    body: Option<serde_json::Value>,
) -> (u16, String, String) {
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nX-ProxyMind: 1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(c) = cookie {
        req.push_str(&format!("Cookie: pm_session={c}\r\n"));
    }
    if !body.is_empty() {
        req.push_str("Content-Type: application/json\r\n");
    }
    req.push_str("\r\n");
    req.push_str(&body);
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return (0, String::new(), String::new()) };
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(req.as_bytes()).unwrap();
    let mut out = String::new();
    let _ = s.read_to_string(&mut out);
    let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
    let status = head.split(' ').nth(1).and_then(|x| x.parse().ok()).unwrap_or(0);
    (status, head.to_string(), body.to_string())
}

fn b32(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buf, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.bytes() {
        buf = (buf << 5) | A.iter().position(|a| *a == c).unwrap() as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

#[test]
fn serve_sets_up_an_owner_and_reset_owner_ends_sessions() {
    let dir = home("run");
    with_roe(&dir);
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (mut child, lines) = spawn_server(&dir, port, &[]);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // The setup URL appears on the console, with the token in the fragment.
        let setup = loop {
            let l = lines.recv_timeout(Duration::from_secs(60)).expect("the server printed a setup URL");
            if let Some(i) = l.find("#setup=") {
                break l[i + "#setup=".len()..].trim().to_string();
            }
        };
        assert!(setup.starts_with("pmset_"));
        let server = dir.join("server");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&server.join("server.key")), 0o600);
            assert_eq!(mode(&server.join("server.db")), 0o600);
        }
        // Wait until it answers, then set up, enrol and use the session.
        let pw = "correct horse battery staple";
        let mut tries = 0;
        let (st, _, body) = loop {
            let r = http(port, "GET", "/api/v1/auth/state", None, None);
            if r.0 == 200 || tries > 100 {
                break r;
            }
            tries += 1;
            std::thread::sleep(Duration::from_millis(100));
        };
        assert_eq!(st, 200, "{body}");
        assert!(body.contains("\"setup_required\":true"));
        let (st, _, body) = http(
            port,
            "POST",
            "/api/v1/auth/setup",
            None,
            Some(serde_json::json!({"setup_token": setup, "username": "owner", "password": pw})),
        );
        assert_eq!(st, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let pending = v["pending"].as_str().unwrap().to_string();
        let (_, _, body) =
            http(port, "POST", "/api/v1/auth/login/enrol", None, Some(serde_json::json!({ "pending": pending })));
        let secret =
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["secret_base32"].as_str().unwrap().to_string();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let code = format!("{:06}", pm_accounts::totp(&b32(&secret), now, 30, 6));
        let (st, head, body) = http(
            port,
            "POST",
            "/api/v1/auth/login/enrol/confirm",
            None,
            Some(serde_json::json!({"pending": pending, "code": code})),
        );
        assert_eq!(st, 200, "{body}");
        let cookie = head
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .starts_with("set-cookie: pm_session=")
                    .then(|| l.split(['=', ';']).nth(1).unwrap().to_string())
            })
            .expect("a session cookie");
        let (st, _, body) = http(port, "GET", "/api/v1/status", Some(&cookie), None);
        assert_eq!(st, 200, "{body}");
        assert!(body.contains("human:owner"), "{body}");
        // The install token's launch link is not a door here.
        assert_eq!(http(port, "GET", "/auth?token=x", None, None).0, 404);

        // reset-owner, from the server's own host, while it runs: a new URL, and every session is over.
        let out = pm(
            &dir,
            &[
                "server",
                "reset-owner",
                "--server-home",
                server.to_str().unwrap(),
                "--public-url",
                &format!("http://127.0.0.1:{port}"),
            ],
        )
        .output()
        .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let new_token = text.split("#setup=").nth(1).expect("a setup URL").trim().to_string();
        assert!(new_token.starts_with("pmset_") && new_token != setup);
        assert!(text.contains(&format!("http://127.0.0.1:{port}/#setup=")));
        assert_eq!(http(port, "GET", "/api/v1/status", Some(&cookie), None).0, 401, "the session ended");
        let (st, _, body) = http(
            port,
            "POST",
            "/api/v1/auth/setup",
            None,
            Some(serde_json::json!({"setup_token": new_token, "username": "second", "password": pw})),
        );
        assert_eq!(st, 200, "{body}");
    }));
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(e) = result {
        std::panic::resume_unwind(e);
    }
}

#[cfg(unix)]
#[test]
fn a_server_key_other_users_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = home("keymode");
    with_roe(&dir);
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let (mut child, lines) = spawn_server(&dir, port, &[]);
    // Wait for the first start to have made the key, then stop it and loosen the mode.
    loop {
        let l = lines.recv_timeout(Duration::from_secs(60)).expect("the server started");
        if l.contains("#setup=") {
            break;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let key = dir.join("server").join("server.key");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let e = refused(
        &dir,
        &[
            "serve",
            "--accounts",
            "--server-home",
            dir.join("server").to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{port}"),
        ],
    );
    assert!(e.contains("readable by other users"), "{e}");
    let e = refused(&dir, &["server", "reset-owner", "--server-home", dir.join("server").to_str().unwrap()]);
    assert!(e.contains("readable by other users"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}
