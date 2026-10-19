//! Crawling VulnShop: in scope only, never state-changing links, feeds history.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{CrawlRequest, CrawlResult, Service};

#[tokio::test]
async fn crawls_in_scope_and_skips_risky_links() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let agent = Actor::parse("agent:test").unwrap();

    let r = s.crawl(&agent, CrawlRequest { url: format!("{url}/"), ..Default::default() }).await.unwrap();
    let CrawlResult::Done { pages, forms, skipped, .. } = r else { panic!("{r:?}") };
    let paths: Vec<String> = pages.iter().map(|p| p.url.trim_start_matches(&url).to_string()).collect();
    for want in
        ["/", "/robots.txt", "/api/products", "/search?q=coffee", "/help?topic=orders", "/search", "/api/admin/"]
    {
        assert!(paths.contains(&want.to_string()), "{want} not crawled: {paths:?}");
    }
    let reason =
        |frag: &str| skipped.iter().find(|s| s.url.contains(frag)).map(|s| s.reason.clone()).unwrap_or_default();
    assert!(reason("/api/logout").contains("logs out"), "{skipped:?}");
    assert!(reason("example.org").starts_with("out of scope"), "{skipped:?}");
    assert!(!paths.iter().any(|p| p.contains("logout")));
    let search = forms.iter().find(|f| f.action.ends_with("/search")).unwrap();
    assert_eq!((search.method.as_str(), search.inputs.clone()), ("GET", vec!["q".to_string()]));
    assert!(forms.iter().any(|f| f.method == "POST" && f.action.ends_with("/api/login")));

    // Pages are in history and feed the app model.
    let model = s.model_get(&Default::default()).unwrap();
    assert!(serde_json::to_string(&model).unwrap().contains("/api/products"));

    // Limits hold.
    let r = s
        .crawl(&agent, CrawlRequest { url: format!("{url}/"), max_pages: Some(2), ..Default::default() })
        .await
        .unwrap();
    let CrawlResult::Done { pages, not_visited, .. } = r else { panic!() };
    assert_eq!(pages.len(), 2);
    assert!(not_visited > 0);

    // Starting out of scope is refused before anything is sent.
    let r = s.crawl(&agent, CrawlRequest { url: "http://example.org/".into(), ..Default::default() }).await.unwrap();
    assert!(matches!(r, CrawlResult::Denied { .. }), "{r:?}");
}
