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
    let checks: Vec<&str> = issues.iter().map(|i| i.check).collect();
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
