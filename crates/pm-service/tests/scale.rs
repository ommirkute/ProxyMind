//! Large-project benchmark (roadmap work package 1.6, target scenario of 1.1).
//!
//! Ignored by default (slow). Run it, release build recommended for real numbers:
//!
//! ```text
//! PM_SCALE_EXCHANGES=1000000 PM_SCALE_FINDINGS=10000 \
//!     cargo test --release -p pm-service --test scale -- --ignored --nocapture
//! ```
//!
//! `PM_SCALE_EXCHANGES` (default 100 000) and `PM_SCALE_FINDINGS` (default 10 000) size the project.
//! `PM_SCALE_CONCURRENT_SECS` (default 5) is the length of the recording-while-searching phase.
//!
//! The last line is `SCALE {json}`:
//! - `exchanges`, `findings`: project size.
//! - `insert_per_s`: sequential inserts a second (one transaction each) while loading.
//! - `finding_create_per_s`: findings created through `Service::finding_create`.
//! - `meta_query_ms_max`: slowest metadata query (filters and HQL that need no bodies).
//! - `content_search_ms`: one content search (`history_search_text`, scans up to 5000 bodies).
//! - `rss_mb`, `hwm_mb`: resident and peak resident memory after loading (null off Linux).
//! - `concurrent_inserts_per_s`: inserts a second while content searches run back to back.
//! - `write_stall_ms_max`: slowest single insert during that phase (the 1.1 gate is 50 ms at 2000 inserts/s).
//! - `write_stall_ms_p99`: 99th percentile of the same inserts.
//! - `searches_during_inserts`: content searches completed in that window.
//!
//! The concurrent writer uses its own `Store` handle on the same file, which is how production records:
//! `pm_proxy::Recorder` owns a separate connection on a writer thread, next to the `Service` connection.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{HistoryFilter, NewExchange, Store};
use pm_service::{NewFinding, SearchRequest, Service};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// (VmRSS, VmHWM) in MB from /proc/self/status; None where unavailable.
fn memory_mb() -> Option<(f64, f64)> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kb = |key: &str| -> Option<f64> {
        let line = status.lines().find(|l| l.starts_with(key))?;
        Some(line.split_whitespace().nth(1)?.parse::<f64>().ok()? / 1024.0)
    };
    Some((kb("VmRSS:")?, kb("VmHWM:")?))
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

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

#[test]
#[ignore]
fn history_at_scale() {
    let n = env_usize("PM_SCALE_EXCHANGES", 100_000);
    let n_findings = env_usize("PM_SCALE_FINDINGS", 10_000);
    let concurrent_secs = env_usize("PM_SCALE_CONCURRENT_SECS", 5) as u64;
    let dir = std::env::temp_dir().join(format!("pm-scale-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("big.pmproj");
    let mut s = Store::open(&path).unwrap();
    let t = Instant::now();
    for i in 0..n {
        s.insert_exchange(&exchange(i)).unwrap();
    }
    let insert_secs = t.elapsed().as_secs_f64();
    println!("{:<48} {:>8.1} ms", format!("insert {n} (one transaction each)"), insert_secs * 1000.0);
    drop(s);
    let roe = Roe::parse("version: 1\nscope:\n  include: [\"https://shop.test/\"]\n").unwrap();
    let svc = Service::new(Store::open(&path).unwrap(), Policy::new(roe)).unwrap();
    let me = Actor::parse("human:local").unwrap();

    let t = Instant::now();
    for i in 0..n_findings {
        // A distinct url per finding, so none dedupes into an open one.
        svc.finding_create(
            &me,
            NewFinding {
                title: format!("Finding {i}"),
                vuln_class: ["idor", "xss", "sqli", "ssrf"][i % 4].into(),
                severity: ["low", "medium", "high", "info"][i % 4].into(),
                description: format!("scale finding {i}"),
                url: Some(format!("https://shop.test/api/orders/{i}")),
                evidence: vec![(i % n.max(1)) as i64 + 1],
                hypothesis_id: None,
            },
        )
        .unwrap();
    }
    let finding_secs = t.elapsed().as_secs_f64();
    println!("{:<48} {:>8.1} ms", format!("create {n_findings} findings"), finding_secs * 1000.0);

    let mem = memory_mb();
    match mem {
        Some((rss, hwm)) => println!("memory after loading: VmRSS {rss:.0} MB, VmHWM {hwm:.0} MB"),
        None => println!("memory after loading: n/a"),
    }

    let mut meta_max = 0f64;
    let mut meta = |label: &str, ms: f64| {
        println!("{label:<48} {ms:>8.1} ms");
        meta_max = meta_max.max(ms);
    };
    let f = |x: HistoryFilter| HistoryFilter { limit: Some(500), ..x };
    let mut timed = |label: &str, run: &mut dyn FnMut()| {
        let t = Instant::now();
        run();
        meta(label, t.elapsed().as_secs_f64() * 1000.0);
    };
    timed("first page (500)", &mut || drop(svc.history_search(&me, &f(HistoryFilter::default())).unwrap()));
    timed("status class 5xx", &mut || {
        drop(
            svc.history_search(&me, &f(HistoryFilter { status_class: Some("5".into()), ..Default::default() }))
                .unwrap(),
        )
    });
    timed("hide extensions png,js,css", &mut || {
        drop(
            svc.history_search(&me, &f(HistoryFilter { hide_ext: Some("png,js,css".into()), ..Default::default() }))
                .unwrap(),
        )
    });
    timed("text filter (rare)", &mut || {
        drop(
            svc.history_search(&me, &f(HistoryFilter { text: Some("users/996/".into()), ..Default::default() }))
                .unwrap(),
        )
    });
    timed("in scope only", &mut || {
        drop(svc.history_search(&me, &f(HistoryFilter { in_scope: Some(true), ..Default::default() })).unwrap())
    });
    timed("page from the middle (before_id)", &mut || {
        drop(
            svc.history_search(&me, &f(HistoryFilter { before_id: Some(n as i64 / 2), ..Default::default() })).unwrap(),
        )
    });
    let q = |q: &str| HistoryFilter { q: Some(q.into()), limit: Some(500), ..Default::default() };
    for query in [
        "status:5xx host:*.shop.test",
        "is:inscope -ext:png,js method:POST",
        "path~\"users/99[0-9]/\" time:>800",
        "resp:\"user996@shop.test\"",
        "respheader:content-type=json len:>3100",
    ] {
        let mut page = None;
        timed(&format!("query {query}"), &mut || page = Some(svc.history_search(&me, &q(query)).unwrap()));
        let page = page.unwrap();
        println!(
            "    {} rows, {:?} scanned, more: {}",
            page.exchanges.len(),
            page.scanned,
            page.next_before_id.is_some()
        );
    }
    timed("counters", &mut || {
        let _ = svc.counters().unwrap();
    });
    timed("site map", &mut || drop(svc.site_map(&me, None).unwrap()));
    let search_req = SearchRequest { query: "nothing-matches".into(), ..Default::default() };
    let t = Instant::now();
    svc.history_search_text(&me, &search_req).unwrap();
    let content_search_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("{:<48} {content_search_ms:>8.1} ms", "content search, 5000 scanned");

    // Recording while content searches run: the 1.1 scenario.
    let stop = AtomicBool::new(false);
    let window = Duration::from_secs(concurrent_secs);
    let (latencies, searches) = std::thread::scope(|sc| {
        let searcher = sc.spawn(|| {
            let mut done = 0usize;
            while !stop.load(Ordering::Relaxed) {
                svc.history_search_text(&me, &search_req).unwrap();
                done += 1;
            }
            done
        });
        let writer = sc.spawn(|| {
            let mut store = Store::open(&path).unwrap();
            let mut lat = Vec::<f64>::new();
            let start = Instant::now();
            let mut i = n;
            while start.elapsed() < window {
                let ex = exchange(i);
                let t = Instant::now();
                store.insert_exchange(&ex).unwrap();
                lat.push(t.elapsed().as_secs_f64() * 1000.0);
                i += 1;
            }
            lat
        });
        let lat = writer.join().unwrap();
        stop.store(true, Ordering::Relaxed);
        (lat, searcher.join().unwrap())
    });
    let mut sorted = latencies.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let stall_max = sorted.last().copied().unwrap_or(0.0);
    let p99 = sorted.get((sorted.len() * 99 / 100).min(sorted.len().saturating_sub(1))).copied().unwrap_or(0.0);
    let per_s = latencies.len() as f64 / concurrent_secs.max(1) as f64;
    println!(
        "recording during content search: {per_s:.0} inserts/s, max stall {stall_max:.1} ms, p99 {p99:.1} ms, {searches} searches"
    );

    let summary = serde_json::json!({
        "exchanges": n,
        "findings": n_findings,
        "insert_per_s": (n as f64 / insert_secs).round(),
        "finding_create_per_s": (n_findings as f64 / finding_secs.max(1e-9)).round(),
        "meta_query_ms_max": round1(meta_max),
        "content_search_ms": round1(content_search_ms),
        "rss_mb": mem.map(|m| m.0.round()),
        "hwm_mb": mem.map(|m| m.1.round()),
        "concurrent_inserts_per_s": per_s.round(),
        "write_stall_ms_max": round1(stall_max),
        "write_stall_ms_p99": round1(p99),
        "searches_during_inserts": searches,
    });
    println!("SCALE {summary}");
    let _ = std::fs::remove_dir_all(&dir);
}
