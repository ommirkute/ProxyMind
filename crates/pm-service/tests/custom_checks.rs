//! Custom checks written as YAML, run against VulnShop through the gate.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{CustomScanRequest, CustomScanResult, ReplayRequest, ReplayResult, Service};

const DEBUG_CHECK: &str = r#"
id: debug-switch
title: Hidden debug switch
severity: high
run: per_request
request:
  add_query: { debug: "1" }
match:
  status: [200]
  body_regex: "\"db_password\":\"[^\"]+\""
  not_in_baseline: true
"#;

const REFLECT_CHECK: &str = r#"
id: reflected-markup
title: Markup comes back unencoded
severity: medium
payloads: ["<pm-x>"]
points: [query]
match:
  reflected: true
"#;

#[tokio::test]
async fn custom_checks_find_what_they_describe() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let me = Actor::parse("human:tester").unwrap();
    let agent = Actor::parse("agent:claude").unwrap();
    let send = |raw: &str| ReplayRequest { url: Some(url.clone()), raw: Some(raw.into()), ..Default::default() };
    let ReplayResult::Sent { exchange_id: products, .. } =
        s.replay_send(&me, send("GET /api/products HTTP/1.1\r\nHost: x\r\n\r\n")).await.unwrap()
    else {
        panic!()
    };
    let ReplayResult::Sent { exchange_id: search, .. } =
        s.replay_send(&me, send("GET /search?q=shoes HTTP/1.1\r\nHost: x\r\n\r\n")).await.unwrap()
    else {
        panic!()
    };

    // Saving: people only, validated, replaced by id.
    assert!(s.custom_check_save(&agent, DEBUG_CHECK).is_err());
    assert!(s.custom_check_save(&me, "id: x\ntitle: y\nmatch: {}\n").is_err());
    s.custom_check_save(&me, DEBUG_CHECK).unwrap();
    s.custom_check_save(&me, REFLECT_CHECK).unwrap();
    s.custom_check_save(&me, DEBUG_CHECK).unwrap();
    assert_eq!(s.custom_checks().unwrap().len(), 2);

    let run = |id: i64, checks: &[&str]| CustomScanRequest {
        exchange_id: id,
        checks: checks.iter().map(|c| c.to_string()).collect(),
        ..Default::default()
    };
    let CustomScanResult::Done { findings, requests, .. } =
        s.custom_scan(&me, run(products, &["debug-switch"])).await.unwrap()
    else {
        panic!()
    };
    assert_eq!(requests, 1);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].evidence.contains("db_password"), "{findings:?}");

    // The debug check doesn't fire where there is no debug switch; the reflection check does on /search.
    let CustomScanResult::Done { findings, .. } = s.custom_scan(&me, run(search, &[])).await.unwrap() else { panic!() };
    let ids: Vec<_> = findings.iter().map(|f| f.check.as_str()).collect();
    assert_eq!(ids, ["reflected-markup"], "{findings:?}");
    assert_eq!(findings[0].point, "query q");

    // An unsaved check can be tried as is; agents need approval (payloads are intrusive).
    let try_it = CustomScanRequest { exchange_id: products, yaml: Some(DEBUG_CHECK.into()), ..Default::default() };
    assert!(matches!(s.custom_scan(&agent, try_it).await.unwrap(), CustomScanResult::PendingApproval { .. }));

    assert!(s.custom_check_delete(&me, "debug-switch").unwrap());
    assert!(s.custom_scan(&me, run(products, &["debug-switch"])).await.is_err());
}
