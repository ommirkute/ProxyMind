//! History at scale: 100 000 exchanges. Ignored by default (slow in debug
//! builds); run with `cargo test -p pm-service --test scale -- --ignored --nocapture`.

use std::time::Instant;

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{HistoryFilter, NewExchange, Store};
use pm_service::{SearchRequest, Service};

const N: usize = 100_000;

fn exchange(i: usize) -> NewExchange {
    let host = ["shop.test", "api.shop.test", "cdn.shop.test", "tracker.other.test"][i % 4];
    let path = match i % 5 {
        0 => format!("/api/orders/{i}"),
        1 => format!("/static/app.{i}.js"),
        2 => format!("/img/p{i}.png"),
        3 => format!("/search?q=item{i}"),
        _ => format!("/api/users/{}/profile", i % 997),
    };
    let status = [200u16, 200, 304, 404, 500, 302][i % 6];
    let body = format!("{{\"id\":{i},\"email\":\"user{}@shop.test\",\"pad\":\"{}\"}}", i % 997, "x".repeat(i % 3000));
    NewExchange {
        ts_ms: 1_700_000_000_000 + i as i64,
        duration_ms: Some((i % 900) as i64),
        source: if i.is_multiple_of(10) { "fuzzer".into() } else { "proxy".into() },
        actor_id: "human:local".into(),
        scheme: "https".into(),
        host: host.into(),
        port: 443,
        method: if i.is_multiple_of(7) { "POST".into() } else { "GET".into() },
        path: path.clone(),
        status: Some(status),
        request: format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nCookie: sid=abc{}\r\n\r\n", i % 50).into_bytes(),
        response: Some(
            format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .into_bytes(),
        ),
        error: None,
        identity: None,
        hypothesis_id: None,
    }
}

fn time<T>(label: &str, f: impl FnOnce() -> T) -> T {
    let t = Instant::now();
    let r = f();
    println!("{label:<48} {:>8.1} ms", t.elapsed().as_secs_f64() * 1000.0);
    r
}

#[test]
#[ignore]
fn history_with_100k_exchanges() {
    let dir = std::env::temp_dir().join(format!("pm-scale-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("big.pmproj");
    if !path.exists() {
        let mut s = Store::open(&path).unwrap();
        time("insert 100k (one transaction each)", || {
            for i in 0..N {
                s.insert_exchange(&exchange(i)).unwrap();
            }
        });
    }
    let roe = Roe::parse("version: 1\nscope:\n  include: [\"https://shop.test/\"]\n").unwrap();
    let svc = Service::new(Store::open(&path).unwrap(), Policy::new(roe)).unwrap();
    let me = Actor::parse("human:local").unwrap();
    let f = |x: HistoryFilter| HistoryFilter { limit: Some(500), ..x };
    time("first page (500)", || svc.history_search(&me, &f(HistoryFilter::default())).unwrap());
    time("status class 5xx", || {
        svc.history_search(&me, &f(HistoryFilter { status_class: Some("5".into()), ..Default::default() })).unwrap()
    });
    time("hide extensions png,js,css", || {
        svc.history_search(&me, &f(HistoryFilter { hide_ext: Some("png,js,css".into()), ..Default::default() }))
            .unwrap()
    });
    time("text filter (rare)", || {
        svc.history_search(&me, &f(HistoryFilter { text: Some("users/996/".into()), ..Default::default() })).unwrap()
    });
    time("in scope only", || {
        svc.history_search(&me, &f(HistoryFilter { in_scope: Some(true), ..Default::default() })).unwrap()
    });
    time("page from the middle (before_id)", || {
        svc.history_search(&me, &f(HistoryFilter { before_id: Some(50_000), ..Default::default() })).unwrap()
    });
    let q = |q: &str| HistoryFilter { q: Some(q.into()), limit: Some(500), ..Default::default() };
    for query in [
        "status:5xx host:*.shop.test",
        "is:inscope -ext:png,js method:POST",
        "path~\"users/99[0-9]/\" time:>800",
        "resp:\"user996@shop.test\"",
        "respheader:content-type=json len:>3100",
    ] {
        let page = time(&format!("query {query}"), || svc.history_search(&me, &q(query)).unwrap());
        println!(
            "    {} rows, {:?} scanned, more: {}",
            page.exchanges.len(),
            page.scanned,
            page.next_before_id.is_some()
        );
    }
    time("counters", || svc.counters().unwrap());
    time("content search, 5000 scanned", || {
        svc.history_search_text(&me, &SearchRequest { query: "nothing-matches".into(), ..Default::default() }).unwrap()
    });
    time("site map", || svc.site_map(&me, None).unwrap());
}
