//! Agent memory across scans, learning from people's verdicts, and traffic
//! triage.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{AiScanRequest, EngageFilter, FindingUpdate, NewFinding, ReplayRequest, Service, scan_actor};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

fn agent() -> Actor {
    Actor::parse("agent:claude").unwrap()
}

fn service(scope: &str) -> Service {
    let roe = format!("version: 1\nscope:\n  include: [\"{scope}\"]\n");
    Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap()
}

fn finding(title: &str, url: &str) -> NewFinding {
    NewFinding {
        title: title.into(),
        vuln_class: "reflected_xss".into(),
        severity: "medium".into(),
        description: "x".into(),
        url: Some(url.into()),
        evidence: vec![],
        hypothesis_id: None,
    }
}

#[test]
fn notes_and_verdicts_brief_the_next_scan() {
    let s = service("http://shop.test/");
    let note = s.memory_save(&agent(), Some("shop.test"), "login", "identity alice logs in via POST /login").unwrap();
    assert_eq!(note.host, "shop.test");
    assert!(s.memory_save(&agent(), Some("evil.test"), "note", "x").is_err(), "out of scope");
    assert!(s.memory_save(&agent(), Some("shop.test"), "secret", "x").is_err(), "unknown kind");
    assert!(s.memory_save(&agent(), None, "note", "x").is_err(), "a plain agent must name the host");

    // An AI scan's agent defaults to the scan's host.
    let scan = s.ai_scan_create(&human(), &AiScanRequest::default(), "m").unwrap();
    let m = s.memory_save(&scan_actor(scan.id), None, "dead_end", "/api/v1 is gone (404 everywhere)").unwrap();
    assert_eq!(m.host, "shop.test");
    assert!(s.ai_scan_get(scan.id).unwrap().log.iter().any(|l| l.kind == "memory"));

    // People's verdicts: a false positive and a confirmed finding.
    let fp = s.finding_create(&agent(), finding("XSS in search", "http://shop.test/search?q=1")).unwrap();
    let fp_id = fp["id"].as_i64().unwrap();
    s.finding_update(
        &human(),
        FindingUpdate {
            id: fp_id,
            status: Some("false_positive".into()),
            severity: None,
            description: None,
            add_evidence: vec![],
        },
    )
    .unwrap();
    let ok = s.finding_create(&agent(), finding("XSS in name", "http://shop.test/profile")).unwrap();
    let ok_id = ok["id"].as_i64().unwrap();
    s.finding_update(
        &human(),
        FindingUpdate {
            id: ok_id,
            status: Some("confirmed".into()),
            severity: None,
            description: None,
            add_evidence: vec![],
        },
    )
    .unwrap();

    let brief = s.memory_brief("http://shop.test/").unwrap();
    assert!(brief.contains(&format!("#{fp_id} [false_positive] XSS in search")), "{brief}");
    assert!(brief.contains(&format!("#{ok_id} [confirmed] XSS in name")));
    assert!(brief.contains("<untrusted_target_content>") && brief.contains("[login] identity alice"), "{brief}");
    assert!(s.memory_brief("http://other.test/").unwrap().is_empty());

    // Reporting the rejected issue again comes back with a warning.
    let again = s.finding_create(&agent(), finding("XSS in search (again)", "http://shop.test/search?q=2")).unwrap();
    assert_eq!(again["similar_false_positive"]["id"], fp_id, "{again}");
    let fresh = s.finding_create(&agent(), finding("XSS elsewhere", "http://shop.test/contact")).unwrap();
    assert!(fresh.get("similar_false_positive").is_none());

    // Only people delete notes.
    assert!(s.memory_delete(&agent(), note.id).is_err());
    s.memory_delete(&human(), note.id).unwrap();
    assert_eq!(s.memory_list(Some("shop.test")).unwrap().len(), 1);
}

#[tokio::test]
async fn triage_ranks_recorded_requests() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let s = service(&format!("{url}/"));
    for raw in [
        "GET /api/orders/1001 HTTP/1.1\r\nHost: x\r\nCookie: s=1\r\n\r\n",
        "GET /api/orders/1002 HTTP/1.1\r\nHost: x\r\nCookie: s=1\r\n\r\n",
        "GET /fetch?url=http://example.test/ HTTP/1.1\r\nHost: x\r\nCookie: s=1\r\n\r\n",
        "GET /about HTTP/1.1\r\nHost: x\r\nCookie: s=1\r\n\r\n",
    ] {
        let req = ReplayRequest { url: Some(url.clone()), raw: Some(raw.into()), ..Default::default() };
        s.replay_send(&human(), req).await.unwrap();
    }
    let t = s.traffic_triage(&human(), &EngageFilter::default(), 50).unwrap();
    let ssrf = t.iter().find(|i| i.url.contains("/fetch")).unwrap_or_else(|| panic!("{t:#?}"));
    assert!(ssrf.hints.iter().any(|h| h.kind == "ssrf"), "{ssrf:?}");
    let orders: Vec<_> = t.iter().filter(|i| i.url.contains("/api/orders/")).collect();
    if let Some(o) = orders.first() {
        assert_eq!(orders.len(), 1, "one entry per path shape");
        assert_eq!(o.similar, 1);
    }
    assert!(!t.iter().any(|i| i.url.ends_with("/about")), "nothing to say about /about");
    assert!(t.windows(2).all(|w| w[0].score >= w[1].score), "highest score first");
}
