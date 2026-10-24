//! Crawl and audit as one background task against VulnShop.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{ScanTaskRequest, ScanTaskStatus, Service};

#[tokio::test]
async fn crawls_then_audits_with_progress() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    let human = Actor::parse("human:tester").unwrap();
    let req = ScanTaskRequest {
        url: format!("{url}/"),
        max_pages: Some(20),
        checks: vec!["reflected_input".into(), "sql_error".into()],
        ..Default::default()
    };
    let started = s.scan_task_start(&human, req).unwrap();
    assert_eq!(started.status, ScanTaskStatus::Crawling);
    let id = started.task_id;
    let mut seen_progress = false;
    let v = loop {
        let v = s.scan_task_status(&human, &id).unwrap();
        seen_progress |= v.status == ScanTaskStatus::Auditing && v.targets_total > 0;
        if !matches!(v.status, ScanTaskStatus::Crawling | ScanTaskStatus::Auditing) {
            break v;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    assert_eq!(v.status, ScanTaskStatus::Done, "{v:?}");
    assert!(seen_progress && v.pages_crawled > 3 && v.targets_done == v.targets_total, "{v:?}");
    let found: Vec<(&str, &str)> = v.issues.iter().map(|i| (i.operation.as_str(), i.check.as_str())).collect();
    assert!(found.iter().any(|(op, c)| op.ends_with("/search") && *c == "reflected_input"), "{found:?}");
    assert!(found.iter().any(|(op, c)| op.ends_with("/api/recommend") && *c == "sql_error"), "{found:?}");
    // Strong issues became suspected findings; the list leaves issues out.
    assert!(v.issues.iter().any(|i| i.finding_id.is_some()));
    let list = s.scan_task_list(&human);
    assert_eq!(list.len(), 1);
    assert!(list[0].issues.is_empty());
    // Agents don't see other actors' tasks.
    let agent = Actor::parse("agent:other").unwrap();
    assert!(s.scan_task_status(&agent, &id).is_err());
    assert!(s.scan_task_list(&agent).is_empty());
}
