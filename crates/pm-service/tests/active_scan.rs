//! Active scan against VulnShop: each check finds its planted bug, and the
//! correctly built look-alikes stay quiet.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{ActiveScanRequest, ActiveScanResult, ReplayRequest, ReplayResult, Service};

async fn setup() -> (Service, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    (Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap(), url)
}

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn record(s: &Service, url: &str, path: &str) -> i64 {
    match s
        .replay_send(
            &human(),
            ReplayRequest {
                url: Some(url.into()),
                raw: Some(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")),
                ..Default::default()
            },
        )
        .await
        .unwrap()
    {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

async fn checks_found(s: &Service, ex: i64) -> Vec<String> {
    checks_with(s, ex, &[]).await.into_iter().map(|(c, _, _)| c).collect()
}

/// (check, point, evidence) of each issue.
async fn checks_with(s: &Service, ex: i64, checks: &[&str]) -> Vec<(String, String, String)> {
    let req = ActiveScanRequest {
        exchange_id: ex,
        checks: checks.iter().map(|c| c.to_string()).collect(),
        ..Default::default()
    };
    match s.scan_active(&human(), req).await.unwrap() {
        ActiveScanResult::Done { issues, .. } => issues
            .iter()
            .map(|i| (i.issue.check.to_string(), i.issue.point.clone(), i.issue.evidence.clone()))
            .collect(),
        other => panic!("{other:?}"),
    }
}

async fn record_raw(s: &Service, url: &str, raw: &str) -> i64 {
    let req = ReplayRequest { url: Some(url.into()), raw: Some(raw.into()), ..Default::default() };
    match s.replay_send(&human(), req).await.unwrap() {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn blind_sql_and_command_injection_are_confirmed() {
    let (s, url) = setup().await;
    // VS-3: boolean-based (fast), then time-based on its own.
    let ex = record(&s, &url, "/api/products/search?q=Coffee").await;
    let found = checks_with(&s, ex, &["sql_boolean"]).await;
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!((found[0].0.as_str(), found[0].1.as_str()), ("sql_boolean", "query q"));
    assert!(found[0].2.contains("confirmed with"), "{}", found[0].2);
    let found = checks_with(&s, ex, &["sql_time"]).await;
    assert_eq!(found.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["sql_time"], "{found:?}");
    assert!(found[0].2.contains("sleep 0 →"), "{}", found[0].2);

    // VS-15: time-based SQL injection in the User-Agent header.
    let ua = "GET /api/products HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n";
    let ex = record_raw(&s, &url, ua).await;
    let found = checks_with(&s, ex, &["sql_time"]).await;
    assert_eq!(
        found.iter().map(|f| (f.0.as_str(), f.1.as_str())).collect::<Vec<_>>(),
        [("sql_time", "header user-agent")]
    );

    // VS-14: command injection, output-based, and time-based on its own.
    let ex = record(&s, &url, "/api/tools/ping?host=127.0.0.1").await;
    let found = checks_with(&s, ex, &["cmd_injection", "sql_error", "ssti"]).await;
    assert_eq!(found.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["cmd_injection"], "{found:?}");
    let found = checks_with(&s, ex, &["cmd_time"]).await;
    assert_eq!(found.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["cmd_time"], "{found:?}");

    // Look-alikes stay quiet under the blind checks too.
    for trap in ["/help?topic=orders", "/search?q=coffee"] {
        let ex = record(&s, &url, trap).await;
        let found = checks_with(&s, ex, &["sql_boolean", "sql_time", "cmd_injection", "cmd_time"]).await;
        assert!(found.is_empty(), "{trap}: {found:?}");
    }
}

#[tokio::test]
async fn each_check_finds_its_bug_and_traps_stay_quiet() {
    let (s, url) = setup().await;
    for (path, want) in [
        ("/api/reviews?product=1", "sql_error"),
        ("/search?q=coffee", "reflected_input"),
        ("/go?url=/home", "open_redirect"),
        ("/download?file=report.pdf", "path_traversal"),
        ("/greet?name=ann", "ssti"),
    ] {
        let ex = record(&s, &url, path).await;
        let found = checks_found(&s, ex).await;
        assert!(found.contains(&want.to_string()), "{path}: {found:?}");
    }
    for trap in ["/help?topic=orders", "/out?url=/home", "/docs?file=menu.txt"] {
        let ex = record(&s, &url, trap).await;
        let found = checks_found(&s, ex).await;
        assert!(found.is_empty(), "{trap} is built correctly: {found:?}");
    }
}

#[tokio::test]
async fn agents_need_approval_and_get_a_proof_hint() {
    let (s, url) = setup().await;
    let ex = record(&s, &url, "/search?q=coffee").await;
    let agent = Actor::parse("agent:test").unwrap();
    let r = s.scan_active(&agent, ActiveScanRequest { exchange_id: ex, ..Default::default() }).await.unwrap();
    assert!(matches!(r, ActiveScanResult::PendingApproval { .. }), "{r:?}");
    let r = s
        .scan_active(
            &human(),
            ActiveScanRequest { exchange_id: ex, checks: vec!["reflected_input".into()], ..Default::default() },
        )
        .await
        .unwrap();
    let ActiveScanResult::Done { issues, requests, .. } = r else { panic!() };
    assert_eq!(requests, 2, "the baseline and one probe");
    assert!(issues[0].issue.prove_with.as_deref().unwrap().contains("reflection"));
    let bad = ActiveScanRequest { exchange_id: ex, checks: vec!["nope".into()], ..Default::default() };
    assert!(s.scan_active(&human(), bad).await.is_err());
}

#[tokio::test]
async fn header_operator_and_access_checks() {
    let (s, url) = setup().await;
    let get = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\n\r\n");
    let cases: [(String, &str, &str); 6] = [
        (get("/api/lang?set=en"), "crlf", "query set"),
        (get("/api/share?product=1"), "host_header", "request host header"),
        (get("/api/me"), "cors", "request origin header"),
        (get("/api/internal/config"), "auth_bypass", "request path and headers"),
        (
            "POST /api/v2/login HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/json\r\n\r\n\
             {\"username\":\"alice\",\"password\":\"wrong\"}"
                .to_string(),
            "nosql_operator",
            "json password",
        ),
        (get("/api/products"), "hidden_params", "request parameters"),
    ];
    for (raw, check, point) in cases {
        let ex = record_raw(&s, &url, &raw).await;
        let found = checks_with(&s, ex, &[check]).await;
        assert_eq!(
            found.iter().map(|f| (f.0.as_str(), f.1.as_str())).collect::<Vec<_>>(),
            [(check, point)],
            "{check}: {found:?}"
        );
        if check == "cors" {
            assert!(found[0].2.contains("credentials: true"));
        }
        if check == "auth_bypass" {
            assert!(found[0].2.contains("X-Forwarded-For"), "{}", found[0].2);
        }
        if check == "hidden_params" {
            assert!(found[0].2.contains("debug="), "{}", found[0].2);
        }
    }
    // Correctly built look-alikes stay quiet.
    let quiet = ["crlf", "host_header", "cors", "auth_bypass", "nosql_operator", "hidden_params", "sql_error"];
    for trap in ["/help?topic=orders", "/api/admin/stats", "/api/invoices/5001", "/out?url=/home"] {
        let ex = record_raw(&s, &url, &get(trap)).await;
        let found = checks_with(&s, ex, &quiet).await;
        assert!(found.is_empty(), "{trap}: {found:?}");
    }
}

#[tokio::test]
async fn stored_xss_csrf_and_dom_xss() {
    let (s, url) = setup().await;
    let login = record_raw(
        &s,
        &url,
        "POST /api/login HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/json\r\n\r\n\
         {\"username\":\"alice\",\"password\":\"alice123\"}",
    )
    .await;
    let resp = s.exchange_raw(login).unwrap().response.unwrap();
    let body = String::from_utf8_lossy(&resp);
    let token = body.split("\"token\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    let form = |path: &str, body: &str| {
        format!(
            "POST {path} HTTP/1.1\r\nHost: shop.test\r\nCookie: session={token}\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\r\n{body}"
        )
    };

    // Stored XSS: needs a page that shows the stored values in history.
    let gb = record_raw(&s, &url, &form("/api/guestbook", "name=carol&message=hi")).await;
    let none = checks_with(&s, gb, &["stored_xss"]).await;
    assert!(none.is_empty(), "no pages to look at yet: {none:?}");
    record(&s, &url, "/guestbook").await;
    let found = checks_with(&s, gb, &["stored_xss"]).await;
    // The message is shown as stored; the name is encoded.
    assert_eq!(
        found.iter().map(|f| (f.0.as_str(), f.1.as_str())).collect::<Vec<_>>(),
        [("stored_xss", "form message")]
    );
    assert!(found[0].2.contains("/guestbook"), "{}", found[0].2);

    // CSRF: the profile change is accepted from another origin; settings checks it.
    let p = record_raw(&s, &url, &form("/api/profile", "email=a%40b.c")).await;
    let found = checks_with(&s, p, &["csrf"]).await;
    assert_eq!(found.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["csrf"], "{found:?}");
    let st = record_raw(&s, &url, &form("/api/settings", "newsletter=1")).await;
    assert!(checks_with(&s, st, &["csrf"]).await.is_empty());

    // DOM XSS (needs a browser).
    if pm_browser_available() {
        let w = record(&s, &url, "/welcome?name=guest").await;
        let found = checks_with(&s, w, &["dom_xss"]).await;
        assert_eq!(found.iter().map(|f| (f.0.as_str(), f.1.as_str())).collect::<Vec<_>>(), [("dom_xss", "query name")]);
        assert!(found[0].2.contains("innerHTML"), "{}", found[0].2);
        let h = record(&s, &url, "/hello?name=guest").await;
        assert!(checks_with(&s, h, &["dom_xss"]).await.is_empty());
    } else {
        eprintln!("skipping the DOM XSS part: no Chromium");
    }
}

fn pm_browser_available() -> bool {
    pm_service::pm_browser::find_chromium().is_some()
}
