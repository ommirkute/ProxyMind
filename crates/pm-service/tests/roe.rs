//! Changing the rules of engagement: humans only, audited, in force at once
//! (gate, scope, rate limits), and picked up by other processes.

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{ROE_SETTING, ReplayRequest, ReplayResult, Service};

const A: &str = "version: 1\nengagement:\n  name: first\nscope:\n  include: [\"https://a.test/\"]\n";
const B: &str = "version: 1\nengagement:\n  name: second\nscope:\n  include: [\"https://b.test/\"]\nlimits:\n  max_rps_per_host: 3\n";

fn service_on(path: &std::path::Path) -> Service {
    let mut store = Store::open(path).unwrap();
    store.set_setting(ROE_SETTING, A).unwrap();
    Service::new(store, Policy::new(Roe::parse(A).unwrap())).unwrap()
}

#[tokio::test]
async fn humans_change_the_rules_and_they_apply_at_once() {
    let dir = std::env::temp_dir().join(format!("pm-roe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("p.pmproj");
    let _ = std::fs::remove_file(&path);
    let s = service_on(&path);
    let human = Actor::parse("human:t").unwrap();
    let agent = Actor::parse("agent:a").unwrap();

    let view = s.roe_get().unwrap();
    assert_eq!(view.text.as_deref(), Some(A));
    assert_eq!(view.summary["engagement"]["name"], "first");
    assert_eq!(view.summary["permissions"]["agent"]["destructive"], "deny");

    // Agents can't change the rules; bad YAML is refused and changes nothing.
    assert!(s.roe_set(&agent, B).is_err());
    assert!(s.roe_set(&human, "version: 1\nscope:\n  include: []\n").is_err());
    assert!(s.roe_check("nope: [").is_err());
    assert_eq!(s.roe_check(B).unwrap()["in_scope"][0], "https://b.test/");
    assert_eq!(s.roe_get().unwrap().summary["engagement"]["name"], "first");

    // b.test is out of scope now…
    let to_b = || ReplayRequest {
        url: Some("https://b.test".into()),
        raw: Some("GET / HTTP/1.1\r\nHost: b.test\r\n\r\n".into()),
        ..Default::default()
    };
    assert!(matches!(s.replay_send(&agent, to_b()).await.unwrap(), ReplayResult::Denied { .. }));
    // …and in scope right after the change.
    let v = s.roe_set(&human, B).unwrap();
    assert_eq!(v.summary["limits"]["max_requests_per_second_per_host"], 3.0);
    let target = pm_service::pm_policy::Target::from_url("https://b.test/x").unwrap();
    assert!(s.policy().scope_check(&target).is_ok());
    let audit: Vec<String> = s.audit_list(5).unwrap().into_iter().map(|a| a.action).collect();
    assert!(audit.contains(&"roe_change".to_string()));
    s.audit_verify().unwrap();

    // Another process on the same project sees the change on its next sync.
    let mut store = Store::open(&path).unwrap();
    let second = Service::new(Store::open(&path).unwrap(), Policy::new(Roe::parse(A).unwrap())).unwrap();
    assert!(!second.sync_roe().unwrap(), "the first sync applies what is saved without reporting a change");
    assert_eq!(second.policy().roe().engagement.name.as_deref(), Some("second"));
    store.set_setting(ROE_SETTING, A).unwrap();
    assert!(second.sync_roe().unwrap());
    assert_eq!(second.policy().roe().engagement.name.as_deref(), Some("first"));
    store.set_setting(ROE_SETTING, "broken: [").unwrap();
    assert!(second.sync_roe().is_err(), "a broken saved ROE is reported…");
    assert_eq!(second.policy().roe().engagement.name.as_deref(), Some("first"), "…and the rules in force stay");
    let _ = std::fs::remove_dir_all(&dir);
}
