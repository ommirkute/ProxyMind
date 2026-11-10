//! A callback that arrives after the scan stopped waiting still becomes a
//! finding (once), and the Collaborator shows which probe caused it.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{ActiveScanRequest, ActiveScanResult, ReplayRequest, ReplayResult, Service};

#[tokio::test]
async fn late_callbacks_become_findings_once() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    let human = Actor::parse("human:tester").unwrap();
    s.collaborator_listen(&human, "127.0.0.1:0".parse().unwrap(), None).await.unwrap();

    // A page that never calls back: probes go out (pingback headers), nothing returns in time.
    let req = ReplayRequest {
        url: Some(url.clone()),
        raw: Some("GET /api/products?q=tea HTTP/1.1\r\nHost: x\r\n\r\n".into()),
        ..Default::default()
    };
    let ReplayResult::Sent { exchange_id, .. } = s.replay_send(&human, req).await.unwrap() else { panic!() };
    let scan = ActiveScanRequest {
        exchange_id,
        checks: vec!["ssrf_oob".into()],
        oob_wait_seconds: Some(1),
        ..Default::default()
    };
    let ActiveScanResult::Done { issues, .. } = s.scan_active(&human, scan).await.unwrap() else { panic!() };
    assert!(issues.is_empty(), "{issues:?}");
    let probes = s.collaborator_probes(50).unwrap();
    let pingback = probes.iter().find(|p| p.point == "request referer header").expect("a Referer pingback");
    assert!(pingback.finding_id.is_none());

    // The callback comes later (a log processor, say).
    let hit = |n: u8| pm_service::pm_oast::Interaction {
        token: pingback.token.clone(),
        protocol: "http".into(),
        remote: format!("10.0.0.{n}:5000"),
        method: "GET".into(),
        path: format!("/{}", pingback.token),
        ts_ms: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64,
        raw: String::new(),
    };
    s.record_oast(&hit(9)).unwrap();
    s.record_oast(&hit(10)).unwrap();
    let probe = s.collaborator_probes(50).unwrap().into_iter().find(|p| p.token == pingback.token).unwrap();
    let id = probe.finding_id.expect("a finding from the late callback");
    let f = s.finding_get(id).unwrap();
    assert_eq!(f["vuln_class"], "ssrf");
    assert!(f["title"].as_str().unwrap().contains("late callback"), "{f}");
    assert!(f["description"].as_str().unwrap().contains("from 10.0.0.9"), "the first callback is described");
    let late = s.collaborator_status().unwrap().late_findings;
    assert_eq!(late, 1, "a second callback on the same token adds nothing");
    let shown = s.collaborator_interactions(Some(&pingback.token), 10).unwrap();
    assert!(shown[0].note.as_deref().unwrap().starts_with("scanner: ssrf_oob on"));
    assert_eq!(shown[0].finding_id, Some(id));
}
