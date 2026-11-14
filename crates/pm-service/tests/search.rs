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

// ---- the full-text index only narrows candidates; results must equal a full scan ----

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

fn insert(store: &mut Store, host: &str, path: &str, req: Vec<u8>, resp: Vec<u8>) {
    store
        .insert_exchange(&NewExchange {
            ts_ms: 1,
            duration_ms: None,
            source: "proxy".into(),
            actor_id: "human:t".into(),
            scheme: "https".into(),
            host: host.into(),
            port: 443,
            method: "GET".into(),
            path: path.into(),
            status: Some(200),
            request: req,
            response: Some(resp),
            error: None,
            identity: None,
            hypothesis_id: None,
        })
        .unwrap();
}

/// Many exchanges mentioning "needle-split-here" in different ways.
fn indexed_service() -> Service {
    let mut store = Store::open_in_memory().unwrap();
    store.set_text_extractor(pm_service::searchable);
    for i in 0..30 {
        let path = format!("/p/{i}");
        let req =
            format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\nX-Note: Needle-Split-Here {i}\r\n\r\n").into_bytes();
        let resp = match i % 6 {
            // Plain body.
            0 => b"HTTP/1.1 200 OK\r\nContent-Length: 29\r\n\r\nxx needle-split-here in body.".to_vec(),
            // Gzip body.
            1 => {
                let body = gzip(b"{\"k\":\"NEEDLE-split-here\"}");
                let mut r =
                    format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", body.len())
                        .into_bytes();
                r.extend_from_slice(&body);
                r
            }
            // The needle straddles a chunk boundary.
            2 => {
                let mut r = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
                r.extend_from_slice(&chunked(&[b"aaa needle-sp", b"lit-here bbb"]));
                r
            }
            // Only in a header.
            3 => b"HTTP/1.1 200 OK\r\nX-Hint: needle-split-here\r\nContent-Length: 2\r\n\r\nok".to_vec(),
            // Same trigrams, not the phrase: a candidate that verification must drop.
            4 => b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\nneedle- split- here needle-split here -ne".to_vec(),
            _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
        };
        insert(&mut store, if i % 5 == 0 { "cdn.other" } else { "shop.test" }, &path, req, resp);
    }
    let roe = "version: 1\nscope:\n  include: [\"https://shop.test/\"]\n";
    Service::new(store, Policy::new(Roe::parse(roe).unwrap())).unwrap()
}

/// A regex matching `s` literally; regex searches always scan everything.
fn escaped(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_string() } else { format!("\\{c}") }).collect()
}

type Flat = Vec<(i64, &'static str, usize, Vec<(String, usize, usize)>)>;

/// Every hit across all pages of `limit` hits.
fn all_hits(s: &Service, actor: &Actor, req: &SearchRequest) -> Flat {
    let mut out = Vec::new();
    let mut req = req.clone();
    for _ in 0..200 {
        let r = s.history_search_text(actor, &req).unwrap();
        for h in &r.hits {
            let snips = h.snippets.iter().map(|x| (x.text.clone(), x.start, x.end)).collect();
            out.push((h.exchange.id, h.part, h.matches, snips));
        }
        match r.next_before_id {
            Some(b) => req.filter.before_id = Some(b),
            None => return out,
        }
    }
    panic!("paging did not finish");
}

#[test]
fn the_index_gives_the_same_hits_as_a_full_scan() {
    let s = indexed_service();
    let human = Actor::parse("human:t").unwrap();
    let agent = Actor::parse("agent:a").unwrap();
    let needle = "needle-split-here";
    let mut checked = 0;
    for actor in [&human, &agent] {
        for case_sensitive in [false, true] {
            for part in
                [None, Some("request"), Some("response"), Some("headers"), Some("bodies"), Some("response_body")]
            {
                for limit in [None, Some(1), Some(4)] {
                    for host in [None, Some("shop")] {
                        let base = SearchRequest {
                            case_sensitive,
                            part: part.map(Into::into),
                            max_scan: Some(1000),
                            filter: HistoryFilter { limit, host: host.map(Into::into), ..Default::default() },
                            ..Default::default()
                        };
                        let indexed = SearchRequest { query: needle.into(), ..base.clone() };
                        let scan = SearchRequest { query: escaped(needle), regex: true, ..base };
                        let (a, b) = (all_hits(&s, actor, &indexed), all_hits(&s, actor, &scan));
                        assert_eq!(a, b, "{actor:?} cs={case_sensitive} part={part:?} limit={limit:?} host={host:?}");
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 2 * 2 * 6 * 3 * 2);

    // Spot checks that the comparison isn't vacuous.
    let find = |req: SearchRequest| all_hits(&s, &human, &req).len();
    let q = |query: &str| SearchRequest { query: query.into(), max_scan: Some(1000), ..Default::default() };
    // 30 requests carry the header (case-insensitive), plus bodies 0, 1, 2 and header 3, 5 each.
    assert_eq!(find(q(needle)), 30 + 5 * 4);
    assert_eq!(find(SearchRequest { case_sensitive: true, ..q(needle) }), 5 * 3, "case-sensitive: fewer");
    assert_eq!(find(SearchRequest { part: Some("response_headers".into()), ..q(needle) }), 5);
    assert_eq!(find(SearchRequest { part: Some("bodies".into()), ..q("split-here") }), 15, "chunk boundary found");

    // The index really narrows: a needle nothing contains verifies nothing, a scan looks at all 30.
    let none = |regex: bool, query: String| {
        let r = SearchRequest { query, regex, max_scan: Some(1000), ..Default::default() };
        s.history_search_text(&human, &r).unwrap().scanned
    };
    assert_eq!((none(false, "zzz-absent".into()), none(true, escaped("zzz-absent"))), (0, 30));

    // Two characters can't use the index but still work; so does a query with a placeholder mark.
    assert!(find(q("ne")) > 0);
    assert_eq!(find(q("{{secret:nothing_1}}")), 0);
    // Inverted searches skip the index and still agree with the matcher.
    let inv = SearchRequest { invert: true, ..q(needle) };
    assert_eq!(find(inv), 30 - 30, "every request carries the header");
}

#[test]
fn paging_with_the_index_covers_each_hit_once() {
    let s = indexed_service();
    let human = Actor::parse("human:t").unwrap();
    let one_page = |before: Option<i64>| {
        let req = SearchRequest {
            query: "needle-split-here".into(),
            part: Some("response".into()),
            max_scan: Some(1000),
            filter: HistoryFilter { limit: Some(3), before_id: before, ..Default::default() },
            ..Default::default()
        };
        s.history_search_text(&human, &req).unwrap()
    };
    let mut ids = Vec::new();
    let mut before = None;
    loop {
        let r = one_page(before);
        assert!(r.hits.len() <= 3);
        ids.extend(r.hits.iter().map(|h| h.exchange.id));
        match r.next_before_id {
            Some(b) => before = Some(b),
            None => break,
        }
    }
    let mut sorted = ids.clone();
    sorted.sort_unstable_by(|a, b| b.cmp(a));
    sorted.dedup();
    assert_eq!(ids, sorted, "newest first, no repeats");
    assert_eq!(ids.len(), 5 * 4, "response matches in bodies 0-2 and header 3");
}
