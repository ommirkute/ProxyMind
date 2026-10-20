//! Renders recorded pages in a real headless Chromium. Skipped (with a
//! note) when no browser is installed.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pm_browser::{Document, RenderOptions, find_chromium, render};

/// One browser at a time: parallel cold starts on a busy CI runner are slow.
static BROWSER: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn html(url: &str, body: &str) -> Document {
    Document {
        url: url.into(),
        status: 200,
        headers: vec![("Content-Type".into(), "text/html; charset=utf-8".into())],
        body: body.as_bytes().to_vec(),
        resources: vec![],
    }
}

fn opts(stop: &str) -> RenderOptions {
    RenderOptions { timeout: Duration::from_secs(20), stop_on: Some(stop.into()), ..Default::default() }
}

/// A listener that counts connections: nothing may reach it.
async fn tripwire() -> (u16, Arc<AtomicUsize>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((_s, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
        }
    });
    (port, hits)
}

#[tokio::test]
async fn executes_injected_script_offline_and_blocks_all_traffic() {
    let _one = BROWSER.lock().await;
    let Some(chrome) = find_chromium() else {
        eprintln!("no Chromium found; set PROXYMIND_CHROMIUM to run this test");
        return;
    };
    let (port, hits) = tripwire().await;
    let base = format!("http://127.0.0.1:{port}");

    // Reflected payload: runs, even though the image and every other load is blocked.
    let page = html(
        &format!("{base}/search?q=x"),
        &format!(
            "<html><body><p>Results for <img src=x onerror=pmProof('tok123')></p>\
             <script src=\"{base}/app.js\"></script><iframe src=\"{base}/frame\"></iframe>\
             <script>fetch('{base}/api').catch(()=>{{}}); new WebSocket('ws://127.0.0.1:{port}/ws');</script></body></html>"
        ),
    );
    let r = render(&chrome, &page, &opts("tok123")).await.unwrap();
    assert!(r.served, "{r:?}");
    assert_eq!(r.binding_calls, vec!["tok123".to_string()], "{r:?}");
    assert!(r.stopped_early);

    // The same text, HTML-encoded: shown, not run.
    let encoded = html(&format!("{base}/search?q=x"), "<p>Results for &lt;img src=x onerror=pmProof('tok123')&gt;</p>");
    let r = render(&chrome, &encoded, &opts("tok123")).await.unwrap();
    assert!(r.served && r.loaded, "{r:?}");
    assert!(r.binding_calls.is_empty(), "{r:?}");

    // Dialogs are caught and dismissed; scripts after them keep running.
    let alert = html(&format!("{base}/a"), "<script>alert('tok456'); pmProof('after')</script>");
    let r = render(&chrome, &alert, &RenderOptions { timeout: Duration::from_secs(20), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(r.dialogs.len(), 1, "{r:?}");
    assert_eq!((r.dialogs[0].kind.as_str(), r.dialogs[0].message.as_str()), ("alert", "tok456"));
    assert_eq!(r.binding_calls, vec!["after".to_string()]);

    // Blocked loads are reported, and nothing reached the network.
    let loads = html(
        &format!("{base}/p"),
        &format!(
            "<img src=\"{base}/i.png\"><img src=\"https://example.com/x.png\"><script>location='{base}/next'</script>"
        ),
    );
    let r = render(&chrome, &loads, &RenderOptions { timeout: Duration::from_secs(20), ..Default::default() })
        .await
        .unwrap();
    assert!(r.blocked.iter().any(|u| u.ends_with("/i.png")), "{r:?}");
    assert!(r.blocked.iter().any(|u| u.starts_with("https://example.com/")), "{r:?}");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the browser must never touch the network");
}

#[tokio::test]
async fn content_security_policy_is_honoured() {
    let _one = BROWSER.lock().await;
    let Some(chrome) = find_chromium() else {
        eprintln!("no Chromium found; set PROXYMIND_CHROMIUM to run this test");
        return;
    };
    let mut page = html("http://127.0.0.1:9/csp", "<img src=x onerror=pmProof('tok789')>");
    page.headers.push(("Content-Security-Policy".into(), "script-src 'none'".into()));
    let r = render(&chrome, &page, &opts("tok789")).await.unwrap();
    assert!(r.served && r.binding_calls.is_empty(), "the recorded CSP blocks inline handlers: {r:?}");
}

#[tokio::test]
async fn serves_given_resources_and_runs_the_init_script_first() {
    let Some(chrome) = find_chromium() else {
        eprintln!("no Chromium; skipping");
        return;
    };
    let mut doc = html("http://shop.test/page", "<html><body><script src='/app.js'></script></body></html>");
    doc.resources.push(pm_browser::Resource {
        url: "http://shop.test/app.js".into(),
        status: 200,
        headers: vec![("Content-Type".into(), "text/javascript".into())],
        body: b"document.body.innerHTML = decodeURIComponent(location.hash.slice(1));".to_vec(),
    });
    doc.url.push_str("#pmMARK");
    let hook = "(() => { const d = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML'); \
        Object.defineProperty(Element.prototype, 'innerHTML', { ...d, set(v) { \
        if (String(v).includes('pmMARK')) window.pmProof('innerHTML:' + v); return d.set.call(this, v); } }); })();";
    let opts = RenderOptions {
        timeout: Duration::from_secs(20),
        init_script: Some(hook.into()),
        stop_on: Some("innerHTML:pmMARK".into()),
        ..Default::default()
    };
    let r = render(&chrome, &doc, &opts).await.unwrap();
    assert!(r.binding_calls.iter().any(|c| c == "innerHTML:pmMARK"), "{r:?}");
    assert!(r.blocked.iter().all(|u| !u.ends_with("/app.js")), "the script was served, not blocked");
}
