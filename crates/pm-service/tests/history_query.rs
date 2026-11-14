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

// ---- the full-text pre-filter only narrows what is evaluated; results must equal a full scan ----

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn chunked(parts: &[&[u8]]) -> Vec<u8> {
    let mut body = Vec::new();
    for p in parts {
        body.extend_from_slice(format!("{:x}\r\n", p.len()).as_bytes());
        body.extend_from_slice(p);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    body
}

/// 1,300 exchanges: every 7th mentions "needle-alpha" (plain, gzip, chunked across a boundary, or
/// in the request), every 11th "beta-marker", the rest neither; statuses 200 and 404, two hosts.
fn indexed_service() -> Service {
    let mut store = Store::open_in_memory().unwrap();
    store.set_text_extractor(pm_service::searchable);
    for i in 0..1300 {
        let path = format!("/p/{i}");
        let mut e = ex(if i % 5 == 0 { "cdn.other" } else { "shop.test" }, "GET", &path, 200, "plain");
        if i % 4 == 3 {
            e.status = Some(404);
        }
        let mut resp = b"HTTP/1.1 200 OK\r\n".to_vec();
        if i % 7 == 0 {
            match i % 4 {
                0 => resp.extend_from_slice(b"Content-Length: 22\r\n\r\nxx Needle-Alpha inside"),
                1 => {
                    let body = gzip(b"{\"k\":\"NEEDLE-alpha\"}");
                    resp.extend_from_slice(
                        format!("Content-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
                    );
                    resp.extend_from_slice(&body);
                }
                2 => {
                    resp.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n");
                    resp.extend_from_slice(&chunked(&[b"aa needle-al", b"pha bb"]));
                }
                _ => {
                    e.request =
                        format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\nX-Note: needle-alpha\r\n\r\n").into_bytes();
                    resp.extend_from_slice(b"Content-Length: 2\r\n\r\nok");
                }
            }
        } else if i % 11 == 0 {
            resp.extend_from_slice(b"Content-Length: 11\r\n\r\nBETA-marker!");
        } else if i % 13 == 0 {
            // Same trigrams as the needle, not the phrase: a candidate that evaluation must drop.
            resp.extend_from_slice(b"Content-Length: 31\r\n\r\nneedle- alpha needle-al pha -ne\n");
        } else {
            resp.extend_from_slice(b"Content-Length: 2\r\n\r\nok");
        }
        e.response = Some(resp);
        store.insert_exchange(&e).unwrap();
    }
    let roe = Roe::parse("version: 1\nscope:\n  include: [\"https://shop.test/\"]\n").unwrap();
    Service::new(store, Policy::new(roe)).unwrap()
}

/// Every page of a query: (ids, number of pages, rows looked at).
fn pages(s: &Service, actor: &Actor, q: &str, base: &HistoryFilter) -> (Vec<i64>, usize, usize) {
    let mut f = HistoryFilter { q: Some(q.into()), ..base.clone() };
    let (mut ids, mut n, mut scanned) = (Vec::new(), 0, 0);
    loop {
        let p = s.history_search(actor, &f).unwrap();
        n += 1;
        scanned += p.scanned.unwrap();
        ids.extend(p.exchanges.iter().map(|e| e.id));
        match p.next_before_id {
            Some(b) if f.after_id.is_none() => f.before_id = Some(b),
            Some(_) | None => return (ids, n, scanned),
        }
        assert!(n < 2000, "paging did not finish");
    }
}

#[test]
fn the_prefilter_gives_the_same_rows_as_a_full_scan() {
    let s = indexed_service();
    let human = Actor::parse("human:t").unwrap();
    let agent = Actor::parse("agent:a").unwrap();
    let queries = [
        "resp:\"needle-alpha\"",
        "resp:\"NEEDLE-ALPHA\" status:404",
        "resp:needle-alpha host:shop.test",
        "req:needle-alpha",
        "any:needle-alpha",
        "resp:\"needle-alpha\" OR resp:\"beta-marker\"",
        "(resp:\"needle-alpha\" status:200) OR (req:\"x-note\" host:cdn)",
        "resp:\"needle-alpha\" -status:404",
        "resp:\"needle-alpha\" is:inscope",
        "resp:\"beta-marker\" resp:\"needle-alpha\"",
        "resp:\"absent-needle\"",
        "resp:ne",
    ];
    let mut compared = 0;
    for actor in [&human, &agent] {
        for limit in [500, 7] {
            for (after_id, before_id) in [(None, None), (None, Some(900)), (Some(300), None), (Some(300), Some(1000))] {
                for in_scope in [None, Some(true)] {
                    // Small pages only for the plain cases: each one re-runs a full scan.
                    if limit != 500 && (in_scope.is_some() || after_id.is_some() && before_id.is_some()) {
                        continue;
                    }
                    let base =
                        HistoryFilter { limit: Some(limit), after_id, before_id, in_scope, ..Default::default() };
                    for q in queries {
                        // `OR status:999` leaves no content term every match needs: a full scan.
                        let (fast, _, fast_scanned) = pages(&s, actor, q, &base);
                        let (slow, _, slow_scanned) = pages(&s, actor, &format!("({q}) OR status:999"), &base);
                        assert_eq!(fast, slow, "{q} {actor:?} limit={limit} after={after_id:?} before={before_id:?}");
                        assert!(fast_scanned <= slow_scanned, "{q}: {fast_scanned} vs {slow_scanned}");
                        compared += 1;
                    }
                }
            }
        }
    }
    assert_eq!(compared, 2 * (8 + 3) * queries.len());

    // The comparison isn't vacuous, and the index really narrows.
    let all = HistoryFilter { limit: Some(500), ..Default::default() };
    let (alpha, ..) = pages(&s, &human, "resp:needle-alpha", &all);
    assert_eq!(alpha.len(), (0..1300).filter(|i| i % 7 == 0 && i % 4 != 3).count());
    let (_, _, fast) = pages(&s, &human, "resp:needle-alpha", &all);
    let (_, _, slow) = pages(&s, &human, "(resp:needle-alpha) OR status:999", &all);
    assert_eq!(slow, 1300);
    assert!(fast < 300, "{fast} rows looked at");

    // Paging with a small limit walks the same ids in several pages.
    let small = HistoryFilter { limit: Some(7), ..Default::default() };
    let (ids, n, _) = pages(&s, &human, "resp:needle-alpha", &small);
    assert_eq!((ids, n > 10), (alpha, true));

    // A caller's own `ids` are kept, not replaced by the index's.
    let f = HistoryFilter { q: Some("resp:needle-alpha".into()), ids: Some(vec![1, 2, 8, 9, 15]), ..all.clone() };
    let got: Vec<i64> = s.history_search(&human, &f).unwrap().exchanges.iter().map(|e| e.id).collect();
    assert_eq!(got, [15, 1]);
}
