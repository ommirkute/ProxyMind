//! History queries (`q`): metadata and content terms, paging, errors, export.

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{HistoryFilter, NewExchange, Store};
use pm_service::{ExportRequest, Service};

fn ex(host: &str, method: &str, path: &str, status: u16, body: &str) -> NewExchange {
    NewExchange {
        ts_ms: 1,
        duration_ms: Some(10),
        source: "proxy".into(),
        actor_id: "human:local".into(),
        scheme: "https".into(),
        host: host.into(),
        port: 443,
        method: method.into(),
        path: path.into(),
        status: Some(status),
        request: format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
        response: Some(
            format!("HTTP/1.1 {status} X\r\nContent-Type: text/html\r\nSet-Cookie: s=1\r\n\r\n{body}").into_bytes(),
        ),
        error: None,
        identity: None,
        hypothesis_id: None,
    }
}

fn setup() -> Service {
    let dir = std::env::temp_dir().join(format!("pm-hq-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("p.pmproj");
    let mut s = Store::open(&path).unwrap();
    s.insert_exchange(&ex("shop.test", "GET", "/", 200, "<h1>home</h1>")).unwrap();
    s.insert_exchange(&ex("shop.test", "POST", "/api/login?next=/", 500, "SQL syntax error near 'x'")).unwrap();
    s.insert_exchange(&ex("cdn.other.test", "GET", "/logo.png", 200, "PNG")).unwrap();
    for i in 0..1200 {
        s.insert_exchange(&ex("shop.test", "GET", &format!("/item/{i}"), 200, "ok")).unwrap();
    }
    let roe = Roe::parse("version: 1\nscope:\n  include: [\"https://shop.test/\"]\n").unwrap();
    Service::new(Store::open(&path).unwrap(), Policy::new(roe)).unwrap()
}

fn paths(s: &Service, q: &str) -> Vec<String> {
    let f = HistoryFilter { q: Some(q.into()), limit: Some(500), ..Default::default() };
    s.history_search(&Actor::parse("human:t").unwrap(), &f).unwrap().exchanges.into_iter().map(|e| e.path).collect()
}

#[test]
fn queries_filter_history() {
    let s = setup();
    assert_eq!(paths(&s, "status:5xx"), ["/api/login?next=/"]);
    assert_eq!(paths(&s, "resp~\"(?i)sql syntax\" method:POST"), ["/api/login?next=/"]);
    assert_eq!(paths(&s, "ext:png OR param:next"), ["/logo.png", "/api/login?next=/"]);
    assert_eq!(paths(&s, "-is:inscope"), ["/logo.png"]);
    assert_eq!(paths(&s, "resp:home respheader:set-cookie=s"), ["/"]);
    assert!(paths(&s, "host:*.other.test resp:nothing").is_empty());

    // Pages: 500 matches, then the rest from next_before_id.
    let me = Actor::parse("human:t").unwrap();
    let f = HistoryFilter { q: Some("path:/item/".into()), limit: Some(500), ..Default::default() };
    let p1 = s.history_search(&me, &f).unwrap();
    assert_eq!(p1.exchanges.len(), 500);
    let mut f2 = f.clone();
    f2.before_id = p1.next_before_id;
    let p2 = s.history_search(&me, &f2).unwrap();
    assert_eq!(p2.exchanges.len(), 500);
    assert!(p2.exchanges[0].id < p1.exchanges[499].id);
    assert!(p1.scanned.is_some());

    // Mistakes say where.
    let bad = HistoryFilter { q: Some("status:500 stauts:2".into()), ..Default::default() };
    let e = s.history_search(&me, &bad).unwrap_err().to_string();
    assert!(e.contains("unknown field") && e.contains("character 12"), "{e}");

    // HAR export takes the same query.
    let har = s
        .traffic_export_har(
            &me,
            &ExportRequest { ids: None, filter: HistoryFilter { q: Some("status:500".into()), ..Default::default() } },
        )
        .unwrap();
    assert_eq!(har["log"]["entries"].as_array().unwrap().len(), 1);
}
