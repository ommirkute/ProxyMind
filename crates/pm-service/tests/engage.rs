//! Engagement tools and the Collaborator against VulnShop's recorded traffic.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{CrawlRequest, EngageFilter, ReplayRequest, ReplayResult, Service};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

#[tokio::test]
async fn engagement_tools_read_the_recorded_target() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    s.crawl(&human(), CrawlRequest { url: format!("{url}/"), ..Default::default() }).await.unwrap();
    let before = s.counters().unwrap().exchanges;
    let all = EngageFilter::default();

    let comments = s.engage_comments(&human(), &all).unwrap();
    let todo = comments.iter().find(|c| c.text.contains("debug switch")).expect("the TODO comment");
    assert_eq!((todo.kind, todo.url.ends_with('/')), ("html", true), "{todo:?}");

    let scripts = s.engage_scripts(&human(), &all).unwrap();
    assert!(scripts.iter().any(|x| x.src.as_deref() == Some(&format!("{url}/static/app.js"))), "{scripts:?}");

    let analysis = s.engage_analyze(&human(), &all).unwrap();
    assert!(analysis.params.iter().any(|p| p.name == "q"), "{:?}", analysis.params);
    assert!(analysis.requests > 5 && analysis.methods.contains_key("GET"));

    // What links to the products page?
    let products = s
        .history_search(
            &human(),
            &pm_service::pm_store::HistoryFilter { path: Some("/api/products".into()), ..Default::default() },
        )
        .unwrap()
        .exchanges
        .into_iter()
        .find(|e| e.path == "/api/products")
        .expect("crawled");
    let refs = s.engage_references(&human(), products.id, &all).unwrap();
    assert!(refs.iter().any(|e| e.path == "/"), "the home page links to it: {refs:?}");

    // CSRF proof for the login form, and a clickjacking check of the home page.
    let login = s
        .replay_send(
            &human(),
            ReplayRequest {
                url: Some(url.clone()),
                raw: Some("POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password=alice123".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let ReplayResult::Sent { exchange_id, .. } = login else { panic!("{login:?}") };
    let poc = s.engage_csrf_poc(&human(), exchange_id, Default::default(), true).unwrap();
    assert!(
        poc.contains(&format!(r#"action="{url}/api/login""#)) && poc.contains(r#"name="username" value="alice""#),
        "{poc}"
    );
    let home =
        s.history_search(&human(), &Default::default()).unwrap().exchanges.into_iter().find(|e| e.path == "/").unwrap();
    let cj = s.engage_clickjacking(home.id).unwrap();
    assert!(cj.framable, "VulnShop sends no framing headers: {:?}", cj.reasons);
    assert!(cj.poc.contains("<iframe"));

    assert_eq!(s.counters().unwrap().exchanges, before + 1, "the tools send nothing (only the replayed login)");
}

#[tokio::test]
async fn collaborator_payloads_and_interactions() {
    let s = Arc::new(
        Service::new(
            Store::open_in_memory().unwrap(),
            Policy::new(Roe::parse("version: 1\nscope:\n  include: [\"https://app.test/\"]\n").unwrap()),
        )
        .unwrap(),
    );
    assert!(s.collaborator_payload(&human(), "x").is_err(), "no listener yet");
    let agent = Actor::parse("agent:a").unwrap();
    assert!(s.collaborator_listen(&agent, "127.0.0.1:0".parse().unwrap(), None).await.is_err(), "people only");
    let status = s.collaborator_listen(&human(), "127.0.0.1:0".parse().unwrap(), None).await.unwrap();
    let listen = status.listening.clone().unwrap();
    assert_eq!(status.public_url.as_deref(), Some(format!("http://{listen}").as_str()));

    let p = s.collaborator_payload(&agent, "ssrf in avatar url").unwrap();
    let http = p.http_url.clone().unwrap();
    assert!(http.ends_with(&p.token));
    // The "target" calls back.
    let mut c = tokio::net::TcpStream::connect(&listen).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    c.write_all(format!("GET /{}/fetched HTTP/1.1\r\nHost: x\r\n\r\n", p.token).as_bytes()).await.unwrap();
    let mut buf = [0u8; 256];
    let _ = c.read(&mut buf).await;
    for _ in 0..50 {
        let seen = s.collaborator_interactions(Some(&p.token), 10).unwrap();
        if let Some(i) = seen.first() {
            assert_eq!((i.protocol.as_str(), i.method.as_str()), ("http", "GET"));
            assert_eq!(i.note.as_deref(), Some("ssrf in avatar url"));
            assert_eq!(s.collaborator_payloads(10).unwrap()[0].interactions, 1);
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("the callback was not recorded");
}
