//! Active scan against VulnShop: each check finds its planted bug, and the
//! correctly built look-alikes stay quiet.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{ActiveScanRequest, ActiveScanResult, ReplayRequest, ReplayResult, Service};

async fn setup() -> (Service, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    (Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap(), url)
}

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn record(s: &Service, url: &str, path: &str) -> i64 {
    match s
        .replay_send(
            &human(),
            ReplayRequest {
                url: Some(url.into()),
                raw: Some(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")),
                ..Default::default()
            },
        )
        .await
        .unwrap()
    {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

async fn checks_found(s: &Service, ex: i64) -> Vec<String> {
    match s.scan_active(&human(), ActiveScanRequest { exchange_id: ex, ..Default::default() }).await.unwrap() {
        ActiveScanResult::Done { issues, .. } => issues.iter().map(|i| i.issue.check.to_string()).collect(),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn each_check_finds_its_bug_and_traps_stay_quiet() {
    let (s, url) = setup().await;
    for (path, want) in [
        ("/api/reviews?product=1", "sql_error"),
        ("/search?q=coffee", "reflected_input"),
        ("/go?url=/home", "open_redirect"),
        ("/download?file=report.pdf", "path_traversal"),
        ("/greet?name=ann", "ssti"),
    ] {
        let ex = record(&s, &url, path).await;
        let found = checks_found(&s, ex).await;
        assert!(found.contains(&want.to_string()), "{path}: {found:?}");
    }
    for trap in ["/help?topic=orders", "/out?url=/home", "/docs?file=menu.txt"] {
        let ex = record(&s, &url, trap).await;
        let found = checks_found(&s, ex).await;
        assert!(found.is_empty(), "{trap} is built correctly: {found:?}");
    }
}

#[tokio::test]
async fn agents_need_approval_and_get_a_proof_hint() {
    let (s, url) = setup().await;
    let ex = record(&s, &url, "/search?q=coffee").await;
    let agent = Actor::parse("agent:test").unwrap();
    let r = s.scan_active(&agent, ActiveScanRequest { exchange_id: ex, ..Default::default() }).await.unwrap();
    assert!(matches!(r, ActiveScanResult::PendingApproval { .. }), "{r:?}");
    let r = s
        .scan_active(
            &human(),
            ActiveScanRequest { exchange_id: ex, checks: vec!["reflected_input".into()], ..Default::default() },
        )
        .await
        .unwrap();
    let ActiveScanResult::Done { issues, requests, .. } = r else { panic!() };
    assert_eq!(requests, 1);
    assert!(issues[0].issue.prove_with.as_deref().unwrap().contains("reflection"));
    let bad = ActiveScanRequest { exchange_id: ex, checks: vec!["nope".into()], ..Default::default() };
    assert!(s.scan_active(&human(), bad).await.is_err());
}
