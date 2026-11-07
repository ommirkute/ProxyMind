//! Active-check plugins against VulnShop: requests proposed by the plugin
//! go through the gate (approval for agents), the plugin judges the
//! responses, and plugins can be turned off.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{PluginCheckRequest, PluginCheckResult, ReplayRequest, ReplayResult, Service};

fn python_works() -> bool {
    // Windows may have a python3 stub that runs but fails.
    std::process::Command::new("python3").arg("--version").output().is_ok_and(|o| o.status.success())
}

#[tokio::test]
async fn an_active_plugin_finds_the_debug_switch_through_the_gate() {
    if !python_works() {
        eprintln!("python3 not found; skipping the active plugin test");
        return;
    }
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let home = std::env::temp_dir().join(format!("pm-plugins-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    let mut reg = pm_service::pm_plugin::Registry::load(&home).unwrap();
    reg.add(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/plugins/debug-switch")).unwrap();
    reg.save().unwrap();
    s.attach_plugin_home(home.clone());

    let view = s.plugin_list();
    assert_eq!(view.plugins[0].kinds, ["active"]);
    assert_eq!(view.plugins[0].max_requests, Some(8));

    let human = Actor::parse("human:tester").unwrap();
    let sent = s
        .replay_send(
            &human,
            ReplayRequest {
                url: Some(url.clone()),
                raw: Some("GET /api/products HTTP/1.1\r\nHost: x\r\n\r\n".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let ReplayResult::Sent { exchange_id, .. } = sent else { panic!("{sent:?}") };
    let req = PluginCheckRequest { plugin: "debug-switch".into(), exchange_id, ..Default::default() };

    // An agent needs approval, and sees exactly the requests it covers.
    let agent = Actor::parse("agent:test").unwrap();
    let r = s.plugin_check(&agent, req.clone()).await.unwrap();
    let PluginCheckResult::PendingApproval { approval_id, requests, .. } = r else { panic!("{r:?}") };
    assert_eq!(requests.len(), 8);
    assert!(requests[0].raw.starts_with("GET /api/products?debug=1 HTTP/1.1"), "{:?}", requests[0]);
    let before = s.counters().unwrap().exchanges;
    s.decide_approval(&approval_id, &human, true).unwrap();
    let r = s.plugin_check(&agent, PluginCheckRequest { approval_id: Some(approval_id.clone()), ..req.clone() }).await;
    let PluginCheckResult::Done { issues, exchange_ids, .. } = r.unwrap() else { panic!() };
    assert_eq!(exchange_ids.len(), 8);
    assert_eq!(s.counters().unwrap().exchanges, before + 8, "the approved requests, nothing else");
    let hit = issues.iter().find(|i| i.check == "debug-switch/debug_switch").expect("VS-22 found");
    assert!(hit.title.contains("debug=1") && hit.evidence.contains("password"), "{hit:?}");
    // The approval was used up.
    assert!(
        s.plugin_check(&agent, PluginCheckRequest { approval_id: Some(approval_id), ..req.clone() }).await.is_err()
    );

    // A person runs it directly; turned off, it doesn't run.
    assert!(matches!(s.plugin_check(&human, req.clone()).await.unwrap(), PluginCheckResult::Done { .. }));
    assert!(s.plugin_set_enabled(&agent, "debug-switch", false).is_err(), "agents can't switch plugins");
    s.plugin_set_enabled(&human, "debug-switch", false).unwrap();
    assert!(!s.plugin_list().plugins[0].enabled);
    assert!(s.plugin_check(&human, req).await.is_err());
    let _ = std::fs::remove_dir_all(&home);
}
