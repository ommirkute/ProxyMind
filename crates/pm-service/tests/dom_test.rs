//! DOM testing on recorded pages, offline in a headless browser.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{DomTestRequest, ReplayRequest, ReplayResult, Service};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn record(s: &Service, url: &str, path: &str) -> i64 {
    let r = s
        .replay_send(
            &human(),
            ReplayRequest {
                url: Some(url.into()),
                raw: Some(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let ReplayResult::Sent { exchange_id, .. } = r else { panic!("{r:?}") };
    exchange_id
}

/// A page whose script deep-merges the query string into an object (client-side prototype pollution).
async fn pollution_server() -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut c, _)) = l.accept().await else { return };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = c.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let (ct, body) = if req.starts_with("GET /deparam.js") {
                    (
                        "application/javascript",
                        "const o = {}; for (const [k, v] of new URLSearchParams(location.search)) {\n\
                         const m = k.match(/^(\\w+)\\[(\\w+)\\]$/); if (m) { o[m[1]] = o[m[1]] || {}; o[m[1]][m[2]] = v; } }\n"
                            .to_string(),
                    )
                } else {
                    (
                        "text/html",
                        "<html><body><p>filters</p><script src=/deparam.js></script></body></html>".to_string(),
                    )
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = c.write_all(resp.as_bytes()).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn dom_sources_reach_sinks_and_pollution_shows() {
    if pm_browser::find_chromium().is_none() {
        eprintln!("no Chromium: skipped");
        return;
    }
    let addr = VulnShop::start_local().await.unwrap();
    let shop = format!("http://127.0.0.1:{}", addr.port());
    let pp = format!("http://127.0.0.1:{}", pollution_server().await);
    let roe = format!("version: 1\nscope:\n  include: [\"{shop}/\", \"{pp}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();

    // The page and its script are in history: the test sends nothing more.
    let welcome = record(&s, &shop, "/welcome").await;
    record(&s, &shop, "/static/welcome.js").await;
    let before = s.counters().unwrap().exchanges;
    let r = s.dom_test(&human(), DomTestRequest { exchange_id: welcome, ..Default::default() }).await.unwrap();
    assert_eq!(s.counters().unwrap().exchanges, before, "nothing sent");
    assert_eq!(r.scripts.len(), 1);
    assert!(r.scripts[0].1, "the recorded script was used");
    let f = r.flows.iter().find(|f| f.sink == "innerHTML").unwrap_or_else(|| panic!("{r:?}"));
    assert_eq!(
        (f.source.as_str(), f.key.as_deref(), f.exploitable),
        ("URL parameter (read by name)", Some("name"), true)
    );

    // The safe look-alike (textContent) has no flow into a sink.
    let hello = record(&s, &shop, "/hello").await;
    record(&s, &shop, "/static/hello.js").await;
    let r = s.dom_test(&human(), DomTestRequest { exchange_id: hello, ..Default::default() }).await.unwrap();
    assert!(r.flows.iter().all(|f| !f.exploitable), "{r:?}");

    // A missing script is reported, not fetched.
    let filters = record(&s, &pp, "/filters").await;
    let r = s
        .dom_test(&human(), DomTestRequest { exchange_id: filters, pollution: true, ..Default::default() })
        .await
        .unwrap();
    assert!(!r.scripts[0].1 && !r.notes.is_empty(), "{r:?}");
    record(&s, &pp, "/deparam.js").await;
    let r = s
        .dom_test(&human(), DomTestRequest { exchange_id: filters, pollution: true, ..Default::default() })
        .await
        .unwrap();
    assert_eq!(r.pollution, vec!["query __proto__[x]".to_string()], "{r:?}");
}
