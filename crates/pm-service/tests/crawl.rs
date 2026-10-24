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

#[tokio::test]
async fn a_browser_crawl_runs_the_app_and_finds_what_its_scripts_call() {
    if pm_service::pm_browser::find_chromium().is_none() {
        eprintln!("skipping: no Chromium");
        return;
    }
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let human = Actor::parse("human:tester").unwrap();
    let crawled_api = |s: &Service| {
        let f = pm_service::pm_store::HistoryFilter { limit: Some(500), ..Default::default() };
        s.history_search(&human, &f)
            .unwrap()
            .exchanges
            .iter()
            .any(|e| e.path.starts_with("/api/spa/catalog?category=tea") && e.source == "crawl")
    };

    // Links only: the app's API stays hidden.
    let plain = CrawlRequest { url: format!("{url}/spa"), max_pages: Some(10), ..Default::default() };
    s.crawl(&human, plain).await.unwrap();
    assert!(!crawled_api(&s));

    let req =
        CrawlRequest { url: format!("{url}/spa"), max_pages: Some(10), browser: Some(true), ..Default::default() };
    let r = s.crawl(&human, req).await.unwrap();
    let CrawlResult::Done { pages, browser, .. } = r else { panic!("{r:?}") };
    assert!(browser);
    let urls: Vec<&str> = pages.iter().map(|p| p.url.as_str()).collect();
    assert!(urls.iter().any(|u| u.ends_with("/spa/catalog")), "routes pushed by the app are visited: {urls:?}");
    assert!(pages.iter().all(|p| p.exchange_id > 0 || p.status.is_none()), "{pages:?}");
    assert!(crawled_api(&s), "the API the app's script calls is recorded");
}
