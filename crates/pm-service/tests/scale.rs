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
//! - `concurrent_inserts_per_s`: records a second the recorder (`Recorder::spawn_shared`, one batched transaction per
//!   drain, on the Service's shared write connection) commits while content searches run, with a producer that
//!   never pauses.
//! - `write_stall_ms_max`, `write_stall_ms_p99`: enqueue-to-commit latency (observer polls every 200 us) of records
//!   produced at `PM_SCALE_RECORD_RATE` (default 2000) a second while searches run. The 1.1 gate is 50 ms.
//!   (Before ADR-0017 steps 3 and 4 these were the duration of one `insert_exchange` on a separate connection.)
//! - `enqueue_wait_ms_max`, `enqueue_wait_ms_p99`: how long `Recorder::record` blocked in that paced phase.
//! - `searches_during_inserts`: content searches completed in that window.
//! - `service_write_ms_max`, `service_write_ms_p99`: slowest and 99th-percentile latency of `Service::finding_create`
//!   (an audited service write) while another thread runs regex content searches back to back (they scan bodies and
//!   cannot use the full-text index). This is the case ADR-0017's read pool targets.
//! - `service_writes_per_s`, `regex_searches_during_service_writes`: throughput of that phase.
//!
//! The concurrent writer is a real `pm_proxy::Recorder::spawn_shared`, as in production: it writes through the
//! `Service`'s own write connection (`Service::store_handle`), taking turns with the full-text indexer.

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
    // As the proxy's recorder does: a file store leaves indexing to the Service's background indexer.
    s.set_text_extractor(pm_service::searchable);
    let t = Instant::now();
    for i in 0..n {
        s.insert_exchange(&exchange(i)).unwrap();
    }
    let insert_secs = t.elapsed().as_secs_f64();
    println!("{:<48} {:>8.1} ms", format!("insert {n} (one transaction each)"), insert_secs * 1000.0);
    drop(s);
    let file_mb = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len() as f64 / 1e6).unwrap_or(0.0);
    let index_mb = rusqlite::Connection::open(&path)
        .and_then(|c| {
            c.query_row("SELECT coalesce(sum(pgsize), 0) FROM dbstat WHERE name LIKE 'exchange_text%'", [], |r| {
                r.get::<_, i64>(0)
            })
        })
        .map(|b| b as f64 / 1e6)
        .ok();
    println!("project file {:.1} MB, of which full-text index {index_mb:?} MB", file_mb(&path));
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
    // The recorder doesn't index; the Service's background thread does. Wait for it to drain the tail
    // so the content-search timings below measure the index, not the tail fallback.
    let t = Instant::now();
    {
        let probe = Store::open(&path).unwrap();
        while probe.text_candidates("nothing-matches").unwrap().is_none_or(|ids| !ids.is_empty()) {
            assert!(t.elapsed() < Duration::from_secs(300), "indexer did not catch up");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    println!("{:<48} {:>8.1} ms", "background indexer caught up (after loading)", t.elapsed().as_secs_f64() * 1000.0);
    let search_req = SearchRequest { query: "nothing-matches".into(), ..Default::default() };
    let t = Instant::now();
    svc.history_search_text(&me, &search_req).unwrap();
    let content_search_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("{:<48} {content_search_ms:>8.1} ms", "content search, 5000 scanned");
    let hit_req = SearchRequest { query: "user996@shop.test".into(), ..Default::default() };
    let t = Instant::now();
    let found = svc.history_search_text(&me, &hit_req).unwrap();
    println!(
        "{:<48} {:>8.1} ms ({} hits, {} verified)",
        "content search, a needle that occurs",
        t.elapsed().as_secs_f64() * 1000.0,
        found.hits.len(),
        found.scanned
    );

    // Recording while content searches run: the 1.1 scenario. Records go through a real `Recorder::spawn_shared` on
    // the Service's shared write connection (batched, with the indexer taking turns), as production does.
    let (recorder, rec_thread) = pm_service::pm_proxy::Recorder::spawn_shared(svc.store_handle());
    let rate = env_usize("PM_SCALE_RECORD_RATE", 2000);
    let stop = AtomicBool::new(false);
    let window = Duration::from_secs(concurrent_secs);
    let mut next_i = n;
    let (saturated, paced, searches) = std::thread::scope(|sc| {
        let searcher = sc.spawn(|| {
            let mut done = 0usize;
            // A busy UI: a search every `pace` (PM_SCALE_SEARCH_PACE_MS, default 50 ms; 0 = back to back).
            let pace = Duration::from_millis(
                std::env::var("PM_SCALE_SEARCH_PACE_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(50),
            );
            while !stop.load(Ordering::Relaxed) {
                svc.history_search_text(&me, &search_req).unwrap();
                done += 1;
                std::thread::sleep(pace);
            }
            done
        });
        let drain = |sent: u64, base: u64| {
            while recorder.written_records() < base + sent {
                std::thread::sleep(Duration::from_millis(5));
            }
        };

        // Phase 1, saturated: a producer that never pauses (blocking when the queue is full); the number is how
        // many records the writer commits a second.
        let base = recorder.written_records();
        let start = Instant::now();
        let mut sent = 0u64;
        while start.elapsed() < window {
            recorder.record(exchange(next_i));
            next_i += 1;
            sent += 1;
        }
        let committed = recorder.written_records() - base;
        let saturated = committed as f64 / start.elapsed().as_secs_f64();
        drain(sent, base);

        // Phase 2, paced at `rate` records a second (the 1.1 gate is 2000): the time each `record` call waits to
        // enqueue, and enqueue-to-commit latency (an observer polls the committed count every 200 us).
        let base = recorder.written_records();
        let enq = parking_lot::Mutex::new(Vec::<Instant>::new());
        let committed_at = parking_lot::Mutex::new(Vec::<Instant>::new());
        let producing = AtomicBool::new(true);
        let (waits, count) = std::thread::scope(|inner| {
            let observer = inner.spawn(|| {
                loop {
                    let done_n = (recorder.written_records() - base) as usize;
                    let now = Instant::now();
                    let mut c = committed_at.lock();
                    while c.len() < done_n {
                        c.push(now);
                    }
                    drop(c);
                    if !producing.load(Ordering::Acquire) && done_n >= enq.lock().len() {
                        return;
                    }
                    std::thread::sleep(Duration::from_micros(200));
                }
            });
            let mut waits = Vec::<f64>::new();
            let start = Instant::now();
            let mut k = 0u64;
            while start.elapsed() < window {
                let due = start + Duration::from_secs_f64(k as f64 / rate.max(1) as f64);
                if let Some(wait) = due.checked_duration_since(Instant::now()) {
                    std::thread::sleep(wait);
                }
                let t = Instant::now();
                enq.lock().push(t);
                recorder.record(exchange(next_i));
                waits.push(t.elapsed().as_secs_f64() * 1000.0);
                next_i += 1;
                k += 1;
            }
            producing.store(false, Ordering::Release);
            observer.join().unwrap();
            (waits, k)
        });
        let lat: Vec<f64> = enq
            .lock()
            .iter()
            .zip(committed_at.lock().iter())
            .map(|(e, c)| c.duration_since(*e).as_secs_f64() * 1000.0)
            .collect();
        stop.store(true, Ordering::Relaxed);
        (saturated, (waits, lat, count), searcher.join().unwrap())
    });
    drop(recorder);
    rec_thread.join().unwrap();
    let pct = |v: &[f64]| -> (f64, f64) {
        let mut sorted = v.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let max = sorted.last().copied().unwrap_or(0.0);
        let p99 = sorted.get((sorted.len() * 99 / 100).min(sorted.len().saturating_sub(1))).copied().unwrap_or(0.0);
        (max, p99)
    };
    let per_s = saturated;
    let (enqueue_max, enqueue_p99) = pct(&paced.0);
    let (stall_max, p99) = pct(&paced.1);
    let p50 = {
        let mut v = paced.1.clone();
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v.get(v.len() / 2).copied().unwrap_or(0.0)
    };
    println!("recording during content search, saturated: {per_s:.0} inserts/s ({searches} searches in both phases)");
    println!(
        "recording paced at {rate}/s ({} records): enqueue wait max {enqueue_max:.1} ms p99 {enqueue_p99:.1} ms; \
         enqueue-to-commit max {stall_max:.1} ms p99 {p99:.1} ms p50 {p50:.1} ms",
        paced.2
    );

    // Service writes while regex content searches run back to back: reads and writes go through one `Service`.
    let regex_req = SearchRequest { query: "user99[0-9]@nomatch\\.test".into(), regex: true, ..Default::default() };
    let stop = AtomicBool::new(false);
    let (svc_lat, regex_searches) = std::thread::scope(|sc| {
        let searcher = sc.spawn(|| {
            let mut done = 0usize;
            while !stop.load(Ordering::Relaxed) {
                svc.history_search_text(&me, &regex_req).unwrap();
                done += 1;
            }
            done
        });
        let writer = sc.spawn(|| {
            let mut lat = Vec::<f64>::new();
            let start = Instant::now();
            let mut i = 0usize;
            // Let the searcher get going before the first write.
            std::thread::sleep(Duration::from_millis(100));
            while start.elapsed() < window {
                let t = Instant::now();
                svc.finding_create(
                    &me,
                    NewFinding {
                        title: format!("Concurrent finding {i}"),
                        vuln_class: "idor".into(),
                        severity: "low".into(),
                        description: "written while a regex search runs".into(),
                        url: Some(format!("https://shop.test/concurrent/{i}")),
                        evidence: vec![(i % n.max(1)) as i64 + 1],
                        hypothesis_id: None,
                    },
                )
                .unwrap();
                lat.push(t.elapsed().as_secs_f64() * 1000.0);
                i += 1;
            }
            lat
        });
        let lat = writer.join().unwrap();
        stop.store(true, Ordering::Relaxed);
        (lat, searcher.join().unwrap())
    });
    let mut sorted = svc_lat.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let svc_max = sorted.last().copied().unwrap_or(0.0);
    let svc_p99 = sorted.get((sorted.len() * 99 / 100).min(sorted.len().saturating_sub(1))).copied().unwrap_or(0.0);
    let svc_per_s = svc_lat.len() as f64 / concurrent_secs.max(1) as f64;
    println!(
        "service writes during regex search: {svc_per_s:.0} writes/s, max {svc_max:.1} ms, p99 {svc_p99:.1} ms, \
         {regex_searches} regex searches"
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
        "enqueue_wait_ms_max": round1(enqueue_max),
        "enqueue_wait_ms_p99": round1(enqueue_p99),
        "searches_during_inserts": searches,
        "service_writes_per_s": svc_per_s.round(),
        "service_write_ms_max": round1(svc_max),
        "service_write_ms_p99": round1(svc_p99),
        "regex_searches_during_service_writes": regex_searches,
    });
    println!("SCALE {summary}");
    let _ = std::fs::remove_dir_all(&dir);
}
