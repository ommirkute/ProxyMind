//! Content discovery against VulnShop: real hidden files are found, a
//! single-page app's catch-all (soft 404) is not reported, scope holds.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{DiscoverRequest, DiscoverResult, Service};

async fn setup() -> (Service, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    (Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap(), url)
}

#[tokio::test]
async fn finds_hidden_files_with_the_builtin_list() {
    let (s, url) = setup().await;
    let human = Actor::parse("human:t").unwrap();
    let r = s.discover(&human, DiscoverRequest { url: format!("{url}/"), ..Default::default() }).await.unwrap();
    let DiscoverResult::Done { found, soft_404, tried, .. } = r else { panic!("{r:?}") };
    assert!(!soft_404, "VulnShop answers 404 at the root");
    assert_eq!(tried, pm_service::pm_crawl::discover::BUILTIN_WORDS.len());
    let paths: Vec<&str> = found.iter().map(|f| f.url.trim_start_matches(&url)).collect();
    for p in ["/.git/config", "/.git/HEAD", "/openapi.json", "/robots.txt"] {
        assert!(paths.contains(&p), "{p} in {paths:?}");
    }
    let git = found.iter().find(|f| f.url.ends_with("/.git/config")).unwrap();
    assert_eq!((git.status, git.note), (200, Some("source control metadata")));
    // Every request is in history, tagged as discovery.
    assert!(s.counters().unwrap().exchanges as usize > tried);
}

#[tokio::test]
async fn soft_404s_are_not_reported() {
    let (s, url) = setup().await;
    let human = Actor::parse("human:t").unwrap();
    let words = ["admin", "config.json", "settings", "logout", "../api/me"].map(String::from).to_vec();
    let req =
        DiscoverRequest { url: format!("{url}/app"), words, extensions: vec!["bak".into()], ..Default::default() };
    let r = s.discover(&human, req).await.unwrap();
    let DiscoverResult::Done { found, soft_404, skipped, .. } = r else { panic!("{r:?}") };
    assert!(soft_404, "the app shell answers 200 for anything");
    let paths: Vec<&str> = found.iter().map(|f| f.url.trim_start_matches(&url)).collect();
    assert_eq!(paths, ["/app/config.json"]);
    assert_eq!(skipped, ["/app/logout: the path probably logs out", "/app/logout.bak: the path probably logs out"]);
}

#[tokio::test]
async fn agents_out_of_scope_are_denied() {
    let (s, _) = setup().await;
    let agent = Actor::parse("agent:a").unwrap();
    let r = s
        .discover(&agent, DiscoverRequest { url: "http://elsewhere.test/".into(), ..Default::default() })
        .await
        .unwrap();
    assert!(matches!(r, DiscoverResult::Denied { .. }), "{r:?}");
}

#[tokio::test]
async fn the_baseline_discovers_imports_and_sweeps() {
    let (s, url) = setup().await;
    let human = Actor::parse("human:t").unwrap();
    // A little browsing so the model knows the origin.
    let get = |path: &str| pm_service::ReplayRequest {
        url: Some(url.clone()),
        raw: Some(format!("GET {path} HTTP/1.1\r\nHost: shop\r\n\r\n")),
        ..Default::default()
    };
    s.replay_send(&human, get("/")).await.unwrap();

    let d = s.auto_discover(&human).await.unwrap();
    assert_eq!(d.origins, std::slice::from_ref(&url));
    let exposed: Vec<&str> = d.leads.iter().map(|l| l.operation.as_str()).collect();
    assert_eq!(exposed, [format!("GET {url}/.git/config").as_str()], "one finding per kind of exposure");
    let (spec, ops, sent) = d.openapi.clone().expect("openapi.json imported");
    assert!(spec.ends_with("/openapi.json"));
    assert_eq!(ops, 12, "including POST /api/import");
    assert!(sent > 0);

    // The sweep reaches what the spec's examples recorded: error-based SQLi in /api/reviews.
    let sweep = s.auto_active_sweep(&human).await.unwrap();
    assert!(sweep.leads.iter().any(|l| l.check == "sql_error" && l.operation.ends_with("/api/reviews")), "{sweep:?}");
    let findings = s.finding_list(None).unwrap();
    let classes: Vec<&str> = findings.iter().filter_map(|f| f["vuln_class"].as_str()).collect();
    assert!(classes.contains(&"exposure") && classes.contains(&"sqli"), "{classes:?}");
}
