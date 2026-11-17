//! Plugin API v2 and traffic hooks end to end (ADR-0020): permission review, who may turn things on, hooks through
//! the real proxy with History recording, and run-time refusal of what a plugin did not declare.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pm_service::api_types::HookAction;
use pm_service::pm_plugin::hooks::HookEngine;
use pm_service::pm_plugin::v2::HookKind;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_proxy::{Hooks, Proxy, Recorder};
use pm_service::pm_store::Store;
use pm_service::{Delivery, PluginCheckRequest, Service};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn python_works() -> bool {
    std::process::Command::new("python3").arg("--version").output().is_ok_and(|o| o.status.success())
}

fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/plugins")
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

async fn backend(seen: Arc<Mutex<Vec<Vec<u8>>>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut t, _)) = l.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut b = vec![0u8; 8192];
                let n = t.read(&mut b).await.unwrap_or(0);
                seen.lock().unwrap().push(b[..n].to_vec());
                let _ = t.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
            });
        }
    });
    port
}

struct Env {
    svc: Arc<Service>,
    engine: Arc<HookEngine>,
    home: PathBuf,
    plugin_dir: PathBuf,
    project: PathBuf,
    proxy: u16,
    backend: u16,
    seen: Arc<Mutex<Vec<Vec<u8>>>>,
}

/// A service with the sign-request example installed (not yet accepted), the proxy running with its hook engine,
/// and a backend in scope.
async fn env(name: &str) -> Env {
    let home = std::env::temp_dir().join(format!("pm-svchooks-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let plugin_dir = home.join("sign-request");
    copy_dir(&examples().join("sign-request"), &plugin_dir);
    let mut reg = pm_service::pm_plugin::Registry::load(&home).unwrap();
    reg.add(&plugin_dir).unwrap();
    reg.save().unwrap();

    let seen = Arc::new(Mutex::new(Vec::new()));
    let backend = backend(seen.clone()).await;
    let project = home.join("p.pmproj");
    let roe = format!("version: 1\nscope:\n  include: [\"http://127.0.0.1:{backend}/\"]\n");
    let svc = Arc::new(Service::new(Store::open(&project).unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    svc.attach_plugin_home(home.clone());
    let engine = Arc::new(HookEngine::new());
    svc.attach_hooks(engine.clone());
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let ca = Arc::new(pm_service::pm_tls::CertAuthority::load_or_create(&home).unwrap());
    let proxy =
        Proxy::with_hooks(ca, recorder, false, Hooks { plugin_hooks: Some(engine.clone()), ..Default::default() })
            .unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));
    Env { svc, engine, home, plugin_dir, project, proxy: port, backend, seen }
}

impl Env {
    async fn post(&self, body: &str) -> String {
        let mut c = TcpStream::connect(("127.0.0.1", self.proxy)).await.unwrap();
        let req = format!(
            "POST http://127.0.0.1:{}/api/x HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.backend,
            body.len()
        );
        c.write_all(req.as_bytes()).await.unwrap();
        let mut out = String::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_string(&mut out)).await;
        out
    }

    async fn newest(&self, count: usize) -> pm_service::pm_store::Exchange {
        for _ in 0..100 {
            let s = Store::open(&self.project).unwrap();
            let rows = s.list_exchanges(10, None).unwrap();
            if rows.len() >= count {
                return s.get_exchange(rows[0].id).unwrap().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("not recorded");
    }

    fn turn_everything_on(&self, human: &Actor) {
        self.svc.plugin_accept_permissions(human, "sign-request").unwrap();
        self.svc.plugin_hook_set(human, "sign-request", HookKind::Request, HookAction::Enable).unwrap();
    }
}

#[tokio::test]
async fn only_people_accept_permissions_and_turn_plugins_and_hooks_on() {
    if !python_works() {
        return;
    }
    let e = env("people").await;
    let (human, agent) = (Actor::parse("human:tester").unwrap(), Actor::parse("agent:test").unwrap());

    let view = e.svc.plugin_list();
    let p = &view.plugins[0];
    assert_eq!((p.api, p.enabled, p.needs_review), (2, false, true), "a v2 install waits for review");
    assert_eq!(p.permissions, ["hooks.request"]);
    assert!(p.accepted_permissions.is_empty());
    assert_eq!((p.hooks.len(), p.hooks[0].state.as_str()), (1, "off"));

    // Agents get a clear refusal for each of these, and the refusal is audited.
    for r in [
        e.svc.plugin_accept_permissions(&agent, "sign-request").map(drop),
        e.svc.plugin_set_enabled(&agent, "sign-request", true).map(drop),
        e.svc.plugin_hook_set(&agent, "sign-request", HookKind::Request, HookAction::Enable).map(drop),
    ] {
        let msg = r.unwrap_err().to_string();
        assert!(msg.contains("only people"), "{msg}");
    }
    assert!(!e.engine.wants(HookKind::Request));
    let audit = e.svc.audit_list(50).unwrap();
    assert_eq!(audit.iter().filter(|a| a.decision == "deny" && a.actor == "agent:test").count(), 3);

    // Nothing runs before the permissions are accepted.
    let msg = e.svc.plugin_set_enabled(&human, "sign-request", true).unwrap_err().to_string();
    assert!(msg.contains("accept"), "{msg}");
    let msg =
        e.svc.plugin_hook_set(&human, "sign-request", HookKind::Request, HookAction::Enable).unwrap_err().to_string();
    assert!(msg.contains("can't turn on") && msg.contains("accepted"), "{msg}");
    assert!(
        e.svc.plugin_hook_set(&human, "sign-request", HookKind::Response, HookAction::Enable).is_err(),
        "no such hook"
    );

    // A person accepts: the plugin is on, the hook still waits for its own switch.
    let view = e.svc.plugin_accept_permissions(&human, "sign-request").unwrap();
    let p = &view.plugins[0];
    assert_eq!((p.enabled, p.needs_review), (true, false));
    assert_eq!(p.accepted_permissions, ["hooks.request"]);
    assert!(!e.engine.wants(HookKind::Request));
    let view = e.svc.plugin_hook_set(&human, "sign-request", HookKind::Request, HookAction::Enable).unwrap();
    assert_eq!(view.plugins[0].hooks[0].state, "on");
    assert!(e.engine.wants(HookKind::Request));
    let actions: Vec<String> =
        e.svc.audit_list(50).unwrap().into_iter().filter(|a| a.decision == "allow").map(|a| a.action).collect();
    assert!(
        actions.contains(&"plugin_accept_permissions".to_string()) && actions.contains(&"plugin_hook".to_string()),
        "{actions:?}"
    );

    // Turning the plugin off stops its hook; turning it back on starts it again.
    e.svc.plugin_set_enabled(&human, "sign-request", false).unwrap();
    assert!(!e.engine.wants(HookKind::Request));
    e.svc.plugin_set_enabled(&human, "sign-request", true).unwrap();
    assert!(e.engine.wants(HookKind::Request));
    // Pausing and moving are people's acts too.
    assert!(e.svc.plugin_hook_set(&agent, "sign-request", HookKind::Request, HookAction::Pause).is_err());
    let view = e.svc.plugin_hook_set(&human, "sign-request", HookKind::Request, HookAction::Pause).unwrap();
    assert_eq!(view.plugins[0].hooks[0].state, "paused");
    let view = e.svc.plugin_hook_set(&human, "sign-request", HookKind::Request, HookAction::Resume).unwrap();
    assert_eq!(view.plugins[0].hooks[0].state, "on");
    e.svc.plugin_hook_set(&human, "sign-request", HookKind::Request, HookAction::Down).unwrap();
    e.svc.plugin_hook_set(&human, "sign-request", HookKind::Request, HookAction::Disable).unwrap();
    assert!(!e.engine.wants(HookKind::Request));
    let _ = std::fs::remove_dir_all(&e.home);
}

#[tokio::test]
async fn changed_permissions_keep_the_plugin_off_until_a_person_accepts_again() {
    if !python_works() {
        return;
    }
    let e = env("changed").await;
    let human = Actor::parse("human:tester").unwrap();
    e.turn_everything_on(&human);
    assert!(e.engine.wants(HookKind::Request));

    // The author ships an update that also wants to read history.
    let manifest = e.plugin_dir.join("proxymind-plugin.yaml");
    let text = std::fs::read_to_string(&manifest).unwrap().replace("[hooks.request]", "[hooks.request, history.read]");
    std::fs::write(&manifest, text).unwrap();
    let mut reg = pm_service::pm_plugin::Registry::load(&e.home).unwrap();
    reg.add(&e.plugin_dir).unwrap();
    reg.save().unwrap();

    let p = e.svc.plugin_list().plugins.remove(0);
    assert_eq!((p.enabled, p.needs_review), (false, true));
    assert_eq!(p.permissions, ["history.read", "hooks.request"]);
    // Listing plugins brings the running hooks in line with the registry: the update's hook is not running.
    assert!(!e.engine.wants(HookKind::Request));
    assert!(e.svc.plugin_set_enabled(&human, "sign-request", true).is_err());
    assert!(e.svc.plugin_hook_set(&human, "sign-request", HookKind::Request, HookAction::Enable).is_err());
    let view = e.svc.plugin_accept_permissions(&human, "sign-request").unwrap();
    assert_eq!(view.plugins[0].accepted_permissions, ["history.read", "hooks.request"]);
    assert!(view.plugins[0].enabled);
    let _ = std::fs::remove_dir_all(&e.home);
}

#[tokio::test]
async fn a_hook_signs_requests_through_the_proxy_and_history_keeps_both_sides() {
    if !python_works() {
        return;
    }
    let e = env("traffic").await;
    let human = Actor::parse("human:tester").unwrap();
    let mut events = e.svc.subscribe();
    e.turn_everything_on(&human);

    // The change reached the event bus (the Plugins page refetches on it).
    let mut seen_types = Vec::new();
    while let Ok(Some(Delivery::Event(p))) = tokio::time::timeout(Duration::from_millis(500), events.recv()).await {
        if let Some(v) = e.svc.event_for(&human, &p)
            && v["topic"] == "plugins"
        {
            seen_types.push(v["what"].as_str().unwrap().to_string());
        }
    }
    assert!(
        seen_types.contains(&"permissions_accepted".to_string()) && seen_types.contains(&"hook_enabled".to_string()),
        "{seen_types:?}"
    );

    let key = std::fs::read(e.plugin_dir.join("signing.key")).unwrap();
    let key = String::from_utf8(key).unwrap();
    assert!(e.post("hi").await.ends_with("ok"));
    let sig = hmac_hex(key.lines().next().unwrap().trim().as_bytes(), b"hi");
    let sent = e.seen.lock().unwrap()[0].clone();
    let original = "POST /api/x HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi".to_string();
    let expected = format!(
        "POST /api/x HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nConnection: close\r\nX-Signature: {sig}\r\n\r\nhi"
    );
    assert_eq!(String::from_utf8_lossy(&sent), expected, "the backend got the hook's bytes exactly");
    let ex = e.newest(1).await;
    assert_eq!(String::from_utf8_lossy(&ex.request), expected);
    assert_eq!(String::from_utf8_lossy(ex.request_original.as_deref().unwrap()), original);
    assert_eq!((ex.changes[0].by.as_str(), ex.changes[0].name.as_str()), ("hook", "sign-request/request"));
    assert_eq!(ex.changes[0].note.as_deref(), Some("added X-Signature"));

    // Paused: the original passes and nothing is recorded as changed.
    e.svc.plugin_hook_set(&human, "sign-request", HookKind::Request, HookAction::Pause).unwrap();
    assert!(e.post("hi").await.ends_with("ok"));
    assert_eq!(String::from_utf8_lossy(&e.seen.lock().unwrap()[1]), original);
    let ex = e.newest(2).await;
    assert!(ex.request_original.is_none() && ex.changes.is_empty());
    // Resumed: it signs again.
    e.svc.plugin_hook_set(&human, "sign-request", HookKind::Request, HookAction::Resume).unwrap();
    assert!(e.post("hi").await.ends_with("ok"));
    assert!(String::from_utf8_lossy(&e.seen.lock().unwrap()[2]).contains("X-Signature:"));

    // Out of scope traffic never reaches the hook.
    let other = backend(e.seen.clone()).await;
    let mut c = TcpStream::connect(("127.0.0.1", e.proxy)).await.unwrap();
    c.write_all(
        format!("POST http://127.0.0.1:{other}/ HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_string(&mut out)).await;
    assert!(!String::from_utf8_lossy(&e.seen.lock().unwrap()[3]).contains("X-Signature"));
    let _ = std::fs::remove_dir_all(&e.home);
}

fn hmac_hex(key: &[u8], msg: &[u8]) -> String {
    // The same HMAC-SHA256 the hook computes, from the standard library only (RFC 2104).
    let out = std::process::Command::new("python3")
        .args(["-c", "import hmac,hashlib,sys; print(hmac.new(sys.argv[1].encode(), sys.argv[2].encode(), hashlib.sha256).hexdigest())"])
        .arg(String::from_utf8_lossy(key).as_ref())
        .arg(String::from_utf8_lossy(msg).as_ref())
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

#[tokio::test]
async fn a_v2_plugin_can_only_use_what_it_declared() {
    if !python_works() {
        return;
    }
    let roe = "version: 1\nscope:\n  include: [\"http://127.0.0.1/\"]\n";
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(roe).unwrap())).unwrap();
    let human = Actor::parse("human:tester").unwrap();
    let load = |name: &str| {
        let dir = examples().join(name);
        (dir.clone(), pm_service::pm_plugin::load_manifest(&dir).unwrap())
    };
    // The debug-switch active plugin, re-labelled as API 2 with no checks.active permission (install would refuse
    // this; the service must too, if such a manifest ever got in).
    let (dir, mut manifest) = load("debug-switch");
    manifest.api = Some(2);
    manifest.permissions = vec!["panels".into()];
    s.set_plugins(vec![pm_service::pm_plugin::Installed {
        dir: dir.clone(),
        manifest: manifest.clone(),
        enabled: true,
        signature: Default::default(),
        files: vec![],
    }]);
    let e = s
        .plugin_check(
            &human,
            PluginCheckRequest { plugin: "debug-switch".into(), exchange_id: 1, ..Default::default() },
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("did not declare the checks.active permission"), "{e}");

    // The same for a passive check: the plugin is not run by the scan.
    let (dir, mut manifest) = load("jwt-check");
    manifest.api = Some(2);
    manifest.permissions = vec!["panels".into()];
    s.set_plugins(vec![pm_service::pm_plugin::Installed {
        dir,
        manifest,
        enabled: true,
        signature: Default::default(),
        files: vec![],
    }]);
    let issues = s.scan_passive(&human, &Default::default()).unwrap();
    assert!(issues.iter().all(|i| !i.check.starts_with("jwt-check/")));

    // And a panel gets no exchanges without history.read.
    let (dir, mut manifest) = load("hosts-panel");
    manifest.api = Some(2);
    manifest.permissions = vec!["panels".into()];
    s.set_plugins(vec![pm_service::pm_plugin::Installed {
        dir,
        manifest,
        enabled: true,
        signature: Default::default(),
        files: vec![],
    }]);
    let ex = pm_service::pm_store::NewExchange {
        ts_ms: 1,
        source: "proxy".into(),
        actor_id: "human:local".into(),
        scheme: "http".into(),
        host: "127.0.0.1".into(),
        port: 80,
        method: "GET".into(),
        path: "/".into(),
        status: Some(200),
        request: b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".to_vec(),
        response: Some(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ..Default::default()
    };
    s.store_handle().write(|st| st.insert_exchange(&ex)).unwrap();
    let data = s.plugin_panel(&human, "hosts-panel", "hosts", None).unwrap();
    assert!(data.rows.is_empty(), "no history.read: the panel saw nothing: {data:?}");
}

#[test]
fn version_1_plugins_are_unchanged() {
    let s = Service::new(
        Store::open_in_memory().unwrap(),
        Policy::new(Roe::parse("version: 1\nscope:\n  include: [\"http://127.0.0.1/\"]\n").unwrap()),
    )
    .unwrap();
    let dir = examples().join("debug-switch");
    let manifest = pm_service::pm_plugin::load_manifest(&dir).unwrap();
    s.set_plugins(vec![pm_service::pm_plugin::Installed {
        dir,
        manifest,
        enabled: true,
        signature: Default::default(),
        files: vec![],
    }]);
    let p = s.plugin_list().plugins.remove(0);
    assert_eq!((p.api, p.needs_review, p.permissions.len(), p.hooks.len()), (1, false, 0, 0));
}
