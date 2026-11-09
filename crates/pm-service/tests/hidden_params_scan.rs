//! A parameter the page reads though no request sent it gets scanned:
//! VulnShop's /go redirects to `url`, which nothing links with.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{ReplayRequest, ReplayResult, Service};

#[tokio::test]
async fn hidden_url_parameter_is_scanned_for_open_redirect() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let human = Actor::parse("human:tester").unwrap();
    let req = ReplayRequest {
        url: Some(url.clone()),
        raw: Some("GET /go HTTP/1.1\r\nHost: x\r\n\r\n".into()),
        ..Default::default()
    };
    assert!(matches!(s.replay_send(&human, req).await.unwrap(), ReplayResult::Sent { .. }));

    let sweep = s.auto_active_sweep(&human).await.unwrap();
    let redirect = sweep.leads.iter().find(|l| l.check == "open_redirect");
    assert!(redirect.is_some(), "{:?}", sweep.leads);
    let f = s.finding_get(redirect.unwrap().finding_id).unwrap();
    assert!(f["title"].as_str().unwrap().contains("url"), "{f}");
}
