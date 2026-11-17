//! Hook workers against tiny Python scripts (tests/fixtures): answers, bypass on every kind of failure, pausing.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use pm_plugin::Registry;
use pm_plugin::hooks::{HookEngine, Target};
use pm_plugin::v2::HookKind;

fn python_works() -> bool {
    std::process::Command::new("python3").arg("--version").output().is_ok_and(|o| o.status.success())
}

static N: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    engine: HookEngine,
    kind: HookKind,
    home: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

/// An engine with one hook running `tests/fixtures/<script>`, set up the way a person would: installed, permissions
/// accepted, hook turned on.
fn fixture(script: &str, kind: HookKind, extra: &str) -> Fixture {
    let home =
        std::env::temp_dir().join(format!("pm-hooks-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
    let dir = home.join("plugin");
    std::fs::create_dir_all(&dir).unwrap();
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(script);
    std::fs::copy(src, dir.join("hook.py")).unwrap();
    let k = kind.as_str();
    std::fs::write(
        dir.join("proxymind-plugin.yaml"),
        format!(
            "name: fx\nversion: 1\napi: 2\npermissions: [hooks.{k}]\nhooks:\n  {k}:\n    command: [\"python3\", \"hook.py\"]\n{extra}"
        ),
    )
    .unwrap();
    let mut reg = Registry::load(&home).unwrap();
    reg.add(&dir).unwrap();
    assert!(!reg.find("fx").unwrap().enabled, "a v2 plugin waits for its permissions to be accepted");
    reg.accept_permissions("fx").unwrap();
    reg.set_hook_on("fx", kind, true);
    reg.save().unwrap();
    let engine = HookEngine::new();
    engine.set_scope(Arc::new(|_, host, _, _| host != "out.of.scope"));
    engine.configure(Registry::load(&home).unwrap().active_hooks());
    Fixture { engine, kind, home }
}

const REQ: &[u8] = b"POST /api/x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\nhi";
const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

fn target(host: &str) -> Target<'_> {
    Target { scheme: "http", host, port: 80, method: "POST", path: "/api/x" }
}

impl Fixture {
    fn msg(&self) -> &'static [u8] {
        if self.kind == HookKind::Request { REQ } else { RESP }
    }

    async fn run(&self) -> pm_plugin::hooks::Run {
        self.engine.run(self.kind, &target("a.test"), self.msg()).await
    }

    fn status(&self) -> pm_plugin::hooks::HookStatus {
        self.engine.status("fx", self.kind).unwrap()
    }
}

#[tokio::test]
async fn pass_leaves_the_message_alone() {
    if !python_works() {
        return;
    }
    let f = fixture("pass.py", HookKind::Request, "");
    for _ in 0..3 {
        let r = f.run().await;
        assert_eq!(r, Default::default());
    }
    let s = f.status();
    assert_eq!((s.calls, s.changed, s.paused, s.failures.len()), (3, 0, false, 0));
}

#[tokio::test]
async fn replace_returns_the_hooks_bytes_exactly() {
    if !python_works() {
        return;
    }
    let f = fixture("replace.py", HookKind::Request, "");
    let r = f.run().await;
    let expect = b"POST /api/x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\nX-Hooked: yes\r\n\r\nhi".to_vec();
    assert_eq!(r.bytes, Some(expect), "no Content-Length fix-ups or other changes");
    assert_eq!(r.notes.len(), 1);
    assert_eq!(
        (r.notes[0].name.as_str(), r.notes[0].note.as_deref(), r.notes[0].applied),
        ("fx/request", Some("added X-Hooked"), true)
    );
    assert!(r.block.is_none());
    assert_eq!(f.status().changed, 1);
}

#[tokio::test]
async fn drop_blocks_a_request() {
    if !python_works() {
        return;
    }
    let f = fixture("drop.py", HookKind::Request, "");
    let r = f.run().await;
    let b = r.block.expect("blocked");
    assert!(b.dropped && b.name == "fx/request");
    assert_eq!(r.bytes, None);
}

#[tokio::test]
async fn a_response_hook_cannot_drop() {
    if !python_works() {
        return;
    }
    let f = fixture("drop.py", HookKind::Response, "");
    let r = f.run().await;
    assert!(r.block.is_none(), "fail open");
    assert!(r.notes[0].note.as_deref().unwrap().starts_with("failed:"), "{:?}", r.notes);
    assert_eq!(f.status().failures.len(), 1);
}

#[tokio::test]
async fn slow_hooks_time_out_and_are_bypassed_then_paused() {
    if !python_works() {
        return;
    }
    let f = fixture("slow.py", HookKind::Request, "    timeout_ms: 50\n");
    let started = std::time::Instant::now();
    let r = f.run().await;
    assert_eq!(r.bytes, None);
    assert!(r.block.is_none());
    let note = r.notes[0].note.as_deref().unwrap();
    assert!(note.contains("failed") && note.contains("50 ms") && note.contains("original forwarded"), "{note}");
    assert!(
        started.elapsed() < std::time::Duration::from_millis(1400),
        "gave up at the deadline, not when the hook answered"
    );
    for _ in 0..4 {
        f.run().await;
    }
    let s = f.status();
    assert!(s.paused, "5 failures within a minute pause the hook: {s:?}");
    assert_eq!(s.failures.len(), 5);
    // Paused: the message goes through untouched and the hook isn't asked.
    let calls = s.calls;
    let r = f.run().await;
    assert_eq!(r, Default::default());
    assert_eq!(f.status().calls, calls);
    // A person resumes it.
    assert!(f.engine.resume("fx", HookKind::Request));
    assert!(!f.status().paused);
}

#[tokio::test]
async fn crashes_are_bypassed_and_pause_the_hook() {
    if !python_works() {
        return;
    }
    let f = fixture("crash.py", HookKind::Request, "");
    for i in 0..5 {
        let r = f.run().await;
        assert_eq!(r.bytes, None, "call {i}");
        assert!(r.notes[0].note.as_deref().unwrap().contains("exited"), "{:?}", r.notes);
    }
    assert!(f.status().paused);
}

#[tokio::test]
async fn garbage_and_unparseable_replacements_are_failures() {
    if !python_works() {
        return;
    }
    let g = fixture("garbage.py", HookKind::Request, "");
    for _ in 0..5 {
        let r = g.run().await;
        assert_eq!(r.bytes, None);
        assert!(r.notes[0].note.as_deref().unwrap().contains("not a JSON object"), "{:?}", r.notes);
    }
    assert!(g.status().paused);

    let b = fixture("badreplace.py", HookKind::Request, "");
    let r = b.run().await;
    assert_eq!(r.bytes, None);
    assert!(r.notes[0].note.as_deref().unwrap().contains("not an HTTP request"), "{:?}", r.notes);
}

#[tokio::test]
async fn on_error_drop_blocks_instead_of_passing() {
    if !python_works() {
        return;
    }
    let f = fixture("crash.py", HookKind::Request, "    on_error: drop\n");
    let r = f.run().await;
    let b = r.block.expect("blocked");
    assert!(!b.dropped && b.name == "fx/request", "{b:?}");
    assert!(r.notes[0].note.as_deref().unwrap().contains("blocked"));
}

#[tokio::test]
async fn calls_beyond_the_in_flight_bound_bypass_instead_of_waiting() {
    if !python_works() {
        return;
    }
    let f = Arc::new(fixture("slow.py", HookKind::Request, "    timeout_ms: 2000\n"));
    let mut tasks = Vec::new();
    for _ in 0..6 {
        let f = f.clone();
        tasks.push(tokio::spawn(async move { f.run().await }));
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    }
    let mut busy = 0;
    for t in tasks {
        let r = t.await.unwrap();
        busy += r.notes.iter().filter(|n| n.note.as_deref().is_some_and(|x| x.contains("busy"))).count();
        assert!(r.notes.iter().all(|n| !n.applied) && r.bytes.is_none());
    }
    assert!(busy >= 2, "calls 5 and 6 found the worker full: {busy}");
}

#[tokio::test]
async fn scope_and_size_limits() {
    if !python_works() {
        return;
    }
    let f = fixture("replace.py", HookKind::Request, "");
    // Out of scope: the hook never sees it.
    let r = f.engine.run(HookKind::Request, &target("out.of.scope"), REQ).await;
    assert_eq!(r, Default::default());
    assert_eq!(f.status().calls, 0);
    // Over 8 MB: bypassed with a note, and not a failure.
    let mut big = b"POST / HTTP/1.1\r\nHost: a.test\r\n\r\n".to_vec();
    big.resize(9 << 20, b'x');
    let r = f.engine.run(HookKind::Request, &target("a.test"), &big).await;
    assert_eq!(r.bytes, None);
    assert_eq!(r.notes[0].note.as_deref(), Some("bypassed: message over 8 MB"));
    assert_eq!(f.status().failures.len(), 0);
}

#[tokio::test]
async fn unchanged_configuration_keeps_state_and_removal_stops_hooks() {
    if !python_works() {
        return;
    }
    let f = fixture("pass.py", HookKind::Request, "");
    assert!(f.engine.pause("fx", HookKind::Request));
    f.engine.configure(Registry::load(&f.home).unwrap().active_hooks());
    assert!(f.status().paused, "same hook, same state");
    assert!(f.engine.wants(HookKind::Request) && !f.engine.wants(HookKind::Response));
    f.engine.configure(vec![]);
    assert!(!f.engine.wants(HookKind::Request));
    assert_eq!(f.run().await, Default::default());
}
