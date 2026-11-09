//! Endpoints in recorded JavaScript: VulnShop's single-page app script
//! mentions routes no page links to.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{EngageFilter, ReplayRequest, ReplayResult, Service};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn get(s: &Service, url: &str, path: &str) {
    let req = ReplayRequest {
        url: Some(url.into()),
        raw: Some(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")),
        ..Default::default()
    };
    assert!(matches!(s.replay_send(&human(), req).await.unwrap(), ReplayResult::Sent { .. }));
}

#[tokio::test]
async fn endpoints_in_scripts_new_and_known() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let f = EngageFilter::default();
    assert!(s.engage_js_endpoints(&human(), &f).unwrap().is_empty(), "nothing recorded yet");

    get(&s, &url, "/static/spa.js").await;
    let found = s.engage_js_endpoints(&human(), &f).unwrap();
    let urls: Vec<&str> = found.iter().map(|e| e.url.as_str()).collect();
    for path in ["/spa", "/spa/catalog", "/spa/account", "/api/me"] {
        assert!(urls.contains(&format!("{url}{path}").as_str()), "{path} in {urls:?}");
    }
    assert!(found.iter().all(|e| !e.known && !e.external), "{found:?}");

    // Once traffic shows /api/me, it is known (and sorts after the new ones).
    get(&s, &url, "/api/me").await;
    let found = s.engage_js_endpoints(&human(), &f).unwrap();
    let me = found.iter().find(|e| e.url.ends_with("/api/me")).unwrap();
    assert!(me.known);
    assert!(found.last().unwrap().known, "new endpoints first");
}
