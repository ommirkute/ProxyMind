//! Passive scan of crawled VulnShop traffic: issues grouped, nothing sent.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{CrawlRequest, ScanFilter, Service};

#[tokio::test]
async fn finds_passive_issues_in_history_without_sending() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let human = Actor::parse("human:tester").unwrap();
    s.crawl(&human, CrawlRequest { url: format!("{url}/"), ..Default::default() }).await.unwrap();
    let before = s.counters().unwrap().exchanges;

    let issues = s.scan_passive(&human, &ScanFilter::default()).unwrap();
    let checks: Vec<&str> = issues.iter().map(|i| i.check.as_str()).collect();
    assert!(checks.contains(&"password_over_http"), "{checks:?}");
    let csp = issues.iter().find(|i| i.check == "missing_csp").unwrap();
    assert_eq!(csp.path, "*", "host-wide issues are grouped per origin");
    assert!(csp.count >= 3, "several HTML pages: {}", csp.count);
    assert_eq!(s.counters().unwrap().exchanges, before, "passive: nothing sent");
    // Most severe first.
    assert!(issues.windows(2).all(|w| w[0].severity >= w[1].severity));

    // Filters, and evidence is wrapped as untrusted for agents.
    let medium =
        s.scan_passive(&human, &ScanFilter { min_severity: Some("medium".into()), ..Default::default() }).unwrap();
    assert!(medium.iter().all(|i| i.check != "missing_csp"));
    let agent = Actor::parse("agent:test").unwrap();
    let a = s.scan_passive(&agent, &ScanFilter::default()).unwrap();
    assert!(a[0].evidence.starts_with("<untrusted_target_content>"));
    assert!(s.scan_passive(&human, &ScanFilter { min_severity: Some("bad".into()), ..Default::default() }).is_err());
}

#[test]
fn plugins_add_issues_to_the_passive_scan() {
    use pm_service::pm_store::NewExchange;
    // Windows may have a python3 stub that runs but fails.
    if !std::process::Command::new("python3").arg("--version").output().is_ok_and(|o| o.status.success()) {
        eprintln!("python3 not found; skipping the example plugin test");
        return;
    }
    let mut store = Store::open_in_memory().unwrap();
    let jwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.";
    let id = store
        .insert_exchange(&NewExchange {
            ts_ms: 0,
            duration_ms: None,
            source: "proxy".into(),
            actor_id: "human:local".into(),
            scheme: "https".into(),
            host: "api.example".into(),
            port: 443,
            method: "GET".into(),
            path: "/api/me".into(),
            status: Some(200),
            request: format!("GET /api/me HTTP/1.1\r\nHost: api.example\r\nAuthorization: Bearer {jwt}\r\n\r\n")
                .into_bytes(),
            response: Some(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            ),
            error: None,
            identity: None,
            hypothesis_id: None,
        })
        .unwrap();
    let roe = "version: 1\nscope:\n  include: [\"https://api.example/\"]\n";
    let s = Service::new(store, Policy::new(Roe::parse(roe).unwrap())).unwrap();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/plugins/jwt-check");
    let manifest = pm_service::pm_plugin::load_manifest(&dir).unwrap();
    s.set_plugins(vec![pm_service::pm_plugin::Installed {
        dir,
        manifest,
        enabled: true,
        signature: Default::default(),
        files: vec![],
    }]);
    let human = Actor::parse("human:tester").unwrap();
    let issues = s.scan_passive(&human, &ScanFilter::default()).unwrap();
    let none = issues.iter().find(|i| i.check == "jwt-check/jwt_alg_none").expect("plugin issue");
    assert_eq!(
        (none.severity, none.path.as_str(), none.exchange_ids.clone()),
        (pm_service::pm_scan::Severity::High, "/api/me", vec![id])
    );
    assert!(issues.iter().any(|i| i.check == "jwt-check/jwt_no_expiry"));

    // A broken plugin is reported, not fatal.
    let bad_dir = std::env::temp_dir().join(format!("pm-bad-plugin-{}", std::process::id()));
    std::fs::create_dir_all(&bad_dir).unwrap();
    std::fs::write(
        bad_dir.join("proxymind-plugin.yaml"),
        "name: broken\nversion: 1\npassive:\n  command: [\"./missing\"]\n",
    )
    .unwrap();
    let manifest = pm_service::pm_plugin::load_manifest(&bad_dir).unwrap();
    s.set_plugins(vec![pm_service::pm_plugin::Installed {
        dir: bad_dir.clone(),
        manifest,
        enabled: true,
        signature: Default::default(),
        files: vec![],
    }]);
    let issues = s.scan_passive(&human, &ScanFilter::default()).unwrap();
    assert!(issues.iter().any(|i| i.check == "broken/plugin_error"));
    let _ = std::fs::remove_dir_all(&bad_dir);
}
