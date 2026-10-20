//! Searching history contents and the site map: reads only, secrets hidden from agents.

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{HistoryFilter, NewExchange, Store};
use pm_service::{SearchRequest, Service};

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// (host, path, request, response)
type Row<'a> = (&'a str, &'a str, &'a [u8], Option<Vec<u8>>);

fn service() -> Service {
    let mut store = Store::open_in_memory().unwrap();
    let body = gzip(br#"{"email":"alice@example.com","role":"admin"}"#);
    let mut resp =
        format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
    resp.extend_from_slice(&body);
    let rows: [Row; 4] = [
        (
            "shop.test",
            "/api/users/1",
            b"GET /api/users/1 HTTP/1.1\r\nHost: shop.test\r\nCookie: session=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5\r\n\r\n",
            Some(resp),
        ),
        (
            "shop.test",
            "/api/users/2?v=1",
            b"GET /api/users/2?v=1 HTTP/1.1\r\nHost: shop.test\r\n\r\n",
            Some(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ),
        (
            "shop.test",
            "/login",
            b"POST /login HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 18\r\n\r\nuser=ADMIN&pw=hunter2",
            None,
        ),
        (
            "cdn.other",
            "/app.js",
            b"GET /app.js HTTP/1.1\r\nHost: cdn.other\r\n\r\n",
            Some(b"HTTP/1.1 200 OK\r\n\r\nvar role='admin';".to_vec()),
        ),
    ];
    for (host, path, req, resp) in rows {
        let status = resp.as_ref().map(|r| String::from_utf8_lossy(&r[9..12]).parse().unwrap());
        store
            .insert_exchange(&NewExchange {
                ts_ms: 1,
                duration_ms: None,
                source: "proxy".into(),
                actor_id: "human:t".into(),
                scheme: "https".into(),
                host: host.into(),
                port: 443,
                method: String::from_utf8_lossy(&req[..req.iter().position(|&b| b == b' ').unwrap()]).into(),
                path: path.into(),
                status,
                request: req.to_vec(),
                response: resp,
                error: None,
                identity: None,
                hypothesis_id: None,
            })
            .unwrap();
    }
    let roe = "version: 1\nscope:\n  include: [\"https://shop.test/\"]\n";
    Service::new(store, Policy::new(Roe::parse(roe).unwrap())).unwrap()
}

fn q(query: &str) -> SearchRequest {
    SearchRequest { query: query.into(), ..Default::default() }
}

#[test]
fn searches_decoded_contents() {
    let s = service();
    let human = Actor::parse("human:t").unwrap();
    let before = s.counters().unwrap().exchanges;

    // Found inside a gzip body; literal search is case-insensitive by default.
    let r = s.history_search_text(&human, &q("ALICE@example")).unwrap();
    assert_eq!(r.hits.len(), 1);
    assert_eq!((r.hits[0].part, r.hits[0].exchange.path.as_str()), ("response", "/api/users/1"));
    let snip = &r.hits[0].snippets[0];
    let chars: Vec<char> = snip.text.chars().collect();
    assert_eq!(chars[snip.start..snip.end].iter().collect::<String>(), "alice@example");
    assert_eq!(r.scanned, 4);
    assert!(r.next_before_id.is_none());

    // Parts, case, regex and filters.
    assert_eq!(s.history_search_text(&human, &q("admin")).unwrap().hits.len(), 3);
    let req_only = SearchRequest { part: Some("request".into()), ..q("admin") };
    assert_eq!(s.history_search_text(&human, &req_only).unwrap().hits.len(), 1);
    let cased = SearchRequest { case_sensitive: true, ..q("admin") };
    assert_eq!(s.history_search_text(&human, &cased).unwrap().hits.len(), 2);
    let re = SearchRequest { regex: true, ..q(r"role'?\W+'?admin") };
    assert_eq!(s.history_search_text(&human, &re).unwrap().hits.len(), 2);
    let host = SearchRequest { filter: HistoryFilter { host: Some("cdn".into()), ..Default::default() }, ..q("admin") };
    assert_eq!(s.history_search_text(&human, &host).unwrap().hits.len(), 1);
    assert!(s.history_search_text(&human, &SearchRequest { part: Some("x".into()), ..q("a") }).is_err());
    assert!(s.history_search_text(&human, &SearchRequest { regex: true, ..q("(") }).is_err());

    // Paging: one exchange at a time continues where it stopped.
    let one = SearchRequest { max_scan: Some(1), ..q("admin") };
    let first = s.history_search_text(&human, &one).unwrap();
    assert_eq!((first.scanned, first.hits.len()), (1, 1));
    let next = first.next_before_id.expect("more to search");
    let more = SearchRequest {
        max_scan: Some(10),
        filter: HistoryFilter { before_id: Some(next), ..Default::default() },
        ..q("admin")
    };
    assert_eq!(s.history_search_text(&human, &more).unwrap().hits.len(), 2);

    // Agents can't use search to confirm a secret, and snippets are untrusted.
    let agent = Actor::parse("agent:a").unwrap();
    assert!(s.history_search_text(&agent, &q("Zm9vYmFyYmF6")).unwrap().hits.is_empty());
    let a = s.history_search_text(&agent, &q("session=")).unwrap();
    assert!(a.hits[0].snippets[0].text.starts_with("<untrusted_target_content>"));
    assert_eq!(s.counters().unwrap().exchanges, before, "nothing sent");
}

#[test]
fn builds_the_site_map() {
    let s = service();
    let human = Actor::parse("human:t").unwrap();
    let sites = s.site_map(&human, None).unwrap();
    assert_eq!(sites.len(), 2);
    let cdn = &sites[0];
    assert_eq!((cdn.site.origin.as_str(), cdn.in_scope), ("https://cdn.other", false));
    let shop = &sites[1];
    assert!(shop.in_scope);
    assert_eq!(shop.site.total, 3);
    let users = &shop.site.root.children[0].children[0];
    assert_eq!((users.path.as_str(), users.total, users.children.len()), ("/api/users", 2, 2));
    assert_eq!(users.children[1].statuses, vec![404]);
    assert_eq!(s.site_map(&human, Some("cdn")).unwrap().len(), 1);
}
