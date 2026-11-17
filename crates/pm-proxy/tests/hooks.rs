//! Plugin traffic hooks (ADR-0020) through the real proxy: byte-exact replacements, fail-open, bypass, recording.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pm_plugin::Registry;
use pm_plugin::hooks::HookEngine;
use pm_plugin::v2::HookKind;
use pm_proxy::{Hooks, Proxy, Recorder};
use pm_store::Store;
use pm_tls::CertAuthority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn python_works() -> bool {
    std::process::Command::new("python3").arg("--version").output().is_ok_and(|o| o.status.success())
}

static N: AtomicUsize = AtomicUsize::new(0);

/// A backend that records what it receives and answers with `reply`.
async fn backend(seen: Arc<Mutex<Vec<Vec<u8>>>>, reply: &'static [u8]) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap_or(0);
                seen.lock().unwrap().push(buf[..n].to_vec());
                let _ = s.write_all(reply).await;
            });
        }
    });
    port
}

const PLAIN: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\noriginal";

struct Setup {
    proxy: u16,
    project: std::path::PathBuf,
    engine: Arc<HookEngine>,
}

/// A proxy with one hook running `pm-plugin/tests/fixtures/<script>`, installed and accepted as a person would.
async fn setup(script: &str, kind: HookKind, extra: &str) -> Setup {
    let home = std::env::temp_dir().join(format!(
        "pm-proxyhooks-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&home);
    let dir = home.join("plugin");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../pm-plugin/tests/fixtures").join(script),
        dir.join("hook.py"),
    )
    .unwrap();
    let k = kind.as_str();
    std::fs::write(
        dir.join("proxymind-plugin.yaml"),
        format!("name: fx\nversion: 1\napi: 2\npermissions: [hooks.{k}]\nhooks:\n  {k}:\n    command: [\"python3\", \"hook.py\"]\n{extra}"),
    )
    .unwrap();
    let mut reg = Registry::load(&home).unwrap();
    reg.add(&dir).unwrap();
    reg.accept_permissions("fx").unwrap();
    reg.set_hook_on("fx", kind, true);
    let engine = Arc::new(HookEngine::new());
    engine.set_scope(Arc::new(|_, _, _, _| true));
    engine.configure(reg.active_hooks());

    let ca = Arc::new(CertAuthority::load_or_create(&home).unwrap());
    let project = home.join("p.pmproj");
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let hooks = Hooks { plugin_hooks: Some(engine.clone()), ..Default::default() };
    let proxy = Proxy::with_hooks(ca, recorder, false, hooks).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));
    Setup { proxy: port, project, engine }
}

async fn send(proxy: u16, req: String) -> String {
    let mut c = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    c.write_all(req.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

async fn recorded(project: &Path) -> pm_store::Exchange {
    for _ in 0..100 {
        let s = Store::open(project).unwrap();
        if let Some(e) = s.list_exchanges(1, None).unwrap().first() {
            return s.get_exchange(e.id).unwrap().unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not recorded");
}

fn get(port: u16, extra: &str) -> (String, Vec<u8>) {
    let raw = format!("GET /a HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra}\r\n");
    (format!("GET http://127.0.0.1:{port}/a HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{extra}\r\n"), raw.into_bytes())
}

#[tokio::test]
async fn a_request_hook_changes_what_the_server_gets_exactly() {
    if !python_works() {
        return;
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone(), PLAIN).await;
    let s = setup("replace.py", HookKind::Request, "").await;
    let (wire, original) = get(port, "");
    assert!(send(s.proxy, wire).await.ends_with("original"));
    let mut sent = original.clone();
    sent.truncate(sent.len() - 2);
    sent.extend_from_slice(b"X-Hooked: yes\r\n\r\n");
    assert_eq!(seen.lock().unwrap()[0], sent, "the server got the hook's bytes, nothing fixed up");
    let ex = recorded(&s.project).await;
    assert_eq!(ex.request, sent);
    assert_eq!(ex.request_original.as_deref(), Some(&original[..]), "the browser's request is kept");
    assert_eq!(ex.changes.len(), 1);
    let c = &ex.changes[0];
    assert_eq!(
        (c.phase.as_str(), c.by.as_str(), c.name.as_str(), c.note.as_deref()),
        ("request", "hook", "fx/request", Some("added X-Hooked"))
    );
    assert!(ex.summary.modified);
}

#[tokio::test]
async fn a_paused_hook_lets_the_original_through() {
    if !python_works() {
        return;
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone(), PLAIN).await;
    let s = setup("replace.py", HookKind::Request, "").await;
    assert!(s.engine.pause("fx", HookKind::Request));
    let (wire, original) = get(port, "");
    assert!(send(s.proxy, wire).await.ends_with("original"));
    assert_eq!(seen.lock().unwrap()[0], original);
    let ex = recorded(&s.project).await;
    assert!(ex.request_original.is_none() && ex.changes.is_empty() && !ex.summary.modified);
}

#[tokio::test]
async fn a_failing_hook_is_bypassed_and_noted() {
    if !python_works() {
        return;
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone(), PLAIN).await;
    let s = setup("crash.py", HookKind::Request, "").await;
    let (wire, original) = get(port, "");
    assert!(send(s.proxy, wire).await.ends_with("original"));
    assert_eq!(seen.lock().unwrap()[0], original, "fail open: the original goes through");
    let ex = recorded(&s.project).await;
    assert!(ex.request_original.is_none());
    assert_eq!(ex.changes.len(), 1);
    assert_eq!((ex.changes[0].by.as_str(), ex.changes[0].name.as_str()), ("hook", "fx/request"));
    assert!(ex.changes[0].note.as_deref().unwrap().starts_with("failed:"), "{:?}", ex.changes[0]);
    assert!(!ex.summary.modified, "a note is not a change");
}

#[tokio::test]
async fn dropped_and_fail_closed_requests_get_a_403() {
    if !python_works() {
        return;
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone(), PLAIN).await;
    for (script, extra) in [("drop.py", ""), ("crash.py", "    on_error: drop\n")] {
        let s = setup(script, HookKind::Request, extra).await;
        let (wire, _) = get(port, "");
        let out = send(s.proxy, wire).await;
        assert!(out.starts_with("HTTP/1.1 403 Forbidden") && out.contains("fx/request"), "{script}: {out}");
    }
    assert!(seen.lock().unwrap().is_empty(), "nothing reached the server");
}

#[tokio::test]
async fn a_response_hook_changes_what_the_browser_gets_and_history_keeps_both() {
    if !python_works() {
        return;
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone(), PLAIN).await;
    let s = setup("replace.py", HookKind::Response, "").await;
    let (wire, original) = get(port, "");
    let out = send(s.proxy, wire).await;
    let delivered = "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\nX-Hooked: yes\r\n\r\noriginal";
    assert_eq!(out, delivered, "the browser got the hook's bytes exactly");
    assert_eq!(seen.lock().unwrap()[0], original, "the request was not touched");
    let ex = recorded(&s.project).await;
    assert_eq!(ex.response.as_deref(), Some(PLAIN), "the record keeps what the server sent");
    assert_eq!(ex.response_delivered.as_deref(), Some(delivered.as_bytes()));
    assert_eq!(
        (ex.changes[0].phase.as_str(), ex.changes[0].by.as_str(), ex.changes[0].name.as_str()),
        ("response", "hook", "fx/response")
    );
    assert!(ex.summary.modified);
}

#[tokio::test]
async fn a_fail_closed_response_hook_gives_a_502() {
    if !python_works() {
        return;
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen, PLAIN).await;
    let s = setup("crash.py", HookKind::Response, "    on_error: drop\n").await;
    let (wire, _) = get(port, "");
    let out = send(s.proxy, wire).await;
    assert!(out.starts_with("HTTP/1.1 502 Bad Gateway") && out.contains("fx/response"), "{out}");
    let ex = recorded(&s.project).await;
    assert_eq!(ex.response.as_deref(), Some(PLAIN));
    assert!(ex.changes[0].note.as_deref().unwrap().starts_with("failed:"));
}

#[tokio::test]
async fn streamed_responses_bypass_response_hooks_and_say_so() {
    if !python_works() {
        return;
    }
    const SSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: hi\n\n";
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen, SSE).await;
    let s = setup("replace.py", HookKind::Response, "").await;
    let (wire, _) = get(port, "");
    let out = send(s.proxy, wire).await;
    assert_eq!(out.as_bytes(), SSE, "untouched");
    let ex = recorded(&s.project).await;
    assert!(ex.response_delivered.is_none() && !ex.summary.modified);
    assert_eq!(ex.changes.len(), 1);
    assert!(ex.changes[0].note.as_deref().unwrap().starts_with("bypassed:"), "{:?}", ex.changes[0]);
}

#[tokio::test]
async fn hook_matchers_decide_which_messages_reach_a_hook() {
    if !python_works() {
        return;
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = backend(seen.clone(), PLAIN).await;
    let s = setup("replace.py", HookKind::Request, "    match: { methods: [POST] }\n").await;
    let (wire, original) = get(port, "");
    send(s.proxy, wire).await;
    assert_eq!(seen.lock().unwrap()[0], original, "a GET does not match a POST hook");
    assert_eq!(s.engine.status("fx", HookKind::Request).unwrap().calls, 0);
}
