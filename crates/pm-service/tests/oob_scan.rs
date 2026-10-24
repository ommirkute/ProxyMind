//! Out-of-band scan checks against VulnShop, with a real OAST listener.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{ActiveScanRequest, ActiveScanResult, ReplayRequest, ReplayResult, Service};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn setup(with_oast: bool) -> (Arc<Service>, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    if with_oast {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        s.set_oast_public_url(&format!("http://127.0.0.1:{}", l.local_addr().unwrap().port())).unwrap();
        let s2 = s.clone();
        tokio::spawn(pm_service::pm_oast::serve(l, move |i| {
            let _ = s2.record_oast(&i);
        }));
    }
    (s, url)
}

async fn record(s: &Service, url: &str, raw: &str) -> i64 {
    let req = ReplayRequest { url: Some(url.into()), raw: Some(raw.into()), ..Default::default() };
    match s.replay_send(&human(), req).await.unwrap() {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

/// (check, point, evidence) and the notes.
async fn scan(s: &Service, ex: i64, checks: &[&str]) -> (Vec<(String, String, String)>, Vec<String>) {
    let req = ActiveScanRequest {
        exchange_id: ex,
        checks: checks.iter().map(|c| c.to_string()).collect(),
        oob_wait_seconds: Some(2),
        ..Default::default()
    };
    match s.scan_active(&human(), req).await.unwrap() {
        ActiveScanResult::Done { issues, notes, .. } => (
            issues
                .iter()
                .map(|i| (i.issue.check.to_string(), i.issue.point.clone(), i.issue.evidence.clone()))
                .collect(),
            notes,
        ),
        other => panic!("{other:?}"),
    }
}

const OOB: &[&str] = &["ssrf_oob", "xxe_oob", "sql_oob", "cmd_oob", "ssti_oob", "log4shell", "code_oob"];

#[tokio::test]
async fn callbacks_reveal_blind_bugs_and_name_the_point() {
    let (s, url) = setup(true).await;
    // VS-4: SSRF.
    let ex = record(&s, &url, "GET /api/fetch?url=http://example.org/ HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let (found, _) = scan(&s, ex, OOB).await;
    assert_eq!(found.iter().map(|f| (f.0.as_str(), f.1.as_str())).collect::<Vec<_>>(), [("ssrf_oob", "query url")]);
    assert!(found[0].2.contains("HTTP GET /"), "{}", found[0].2);

    // VS-14: command injection seen out of band.
    let ex = record(&s, &url, "GET /api/tools/ping?host=127.0.0.1 HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let (found, _) = scan(&s, ex, &["cmd_oob"]).await;
    assert_eq!(found.iter().map(|f| (f.0.as_str(), f.1.as_str())).collect::<Vec<_>>(), [("cmd_oob", "query host")]);

    // VS-16: blind XXE in an XML import.
    let xml = "<?xml version=\"1.0\"?><items><item>Coffee</item></items>";
    let raw = format!("POST /api/import HTTP/1.1\r\nHost: x\r\nContent-Type: application/xml\r\n\r\n{xml}");
    let ex = record(&s, &url, &raw).await;
    let (found, _) = scan(&s, ex, &["xxe_oob"]).await;
    assert_eq!(found.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["xxe_oob"]);
    assert!(found[0].2.starts_with("external DTD payload"), "{}", found[0].2);

    // Look-alikes make no callbacks.
    for trap in ["/help?topic=orders", "/search?q=coffee", "/api/products/search?q=Coffee"] {
        let ex = record(&s, &url, &format!("GET {trap} HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\n\r\n")).await;
        let (found, _) = scan(&s, ex, OOB).await;
        assert!(found.is_empty(), "{trap}: {found:?}");
    }
}

#[tokio::test]
async fn without_a_listener_the_checks_are_skipped_with_a_note() {
    let (s, url) = setup(false).await;
    let ex = record(&s, &url, "GET /api/fetch?url=http://example.org/ HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let req = ActiveScanRequest { exchange_id: ex, checks: vec!["ssrf_oob".into()], ..Default::default() };
    // Nothing else to run: a note, and nothing sent.
    match s.scan_active(&human(), req).await.unwrap() {
        ActiveScanResult::Done { requests, notes, .. } => {
            assert_eq!(requests, 0);
            assert!(notes.iter().any(|n| n.contains("no OAST listener")), "{notes:?}");
        }
        other => panic!("{other:?}"),
    }
    let (found, notes) = scan(&s, ex, &["ssrf_oob", "sql_error"]).await;
    assert!(found.is_empty());
    assert!(notes.iter().any(|n| n.contains("no OAST listener")), "{notes:?}");
}
