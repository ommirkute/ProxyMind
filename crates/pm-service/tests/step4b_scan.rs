//! Scanner step 4b against VulnShop: OAuth and deserialization run like any
//! check; request smuggling, file upload and race conditions need approval.

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

async fn record(s: &Service, url: &str, raw: &str) -> i64 {
    let req = ReplayRequest { url: Some(url.into()), raw: Some(raw.into()), ..Default::default() };
    match s.replay_send(&human(), req).await.unwrap() {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

type Found = Vec<(String, String, String, String)>;

/// Scans, approving once if the gate asks: (check, title, point, evidence), and notes.
async fn scan(s: &Service, ex: i64, checks: &[&str]) -> (Found, Vec<String>, bool) {
    let mut req = ActiveScanRequest {
        exchange_id: ex,
        checks: checks.iter().map(|c| c.to_string()).collect(),
        ..Default::default()
    };
    let mut asked = false;
    loop {
        match s.scan_active(&human(), req.clone()).await.unwrap() {
            ActiveScanResult::Done { issues, notes, .. } => {
                let found = issues
                    .iter()
                    .map(|i| {
                        (i.issue.check.into(), i.issue.title.into(), i.issue.point.clone(), i.issue.evidence.clone())
                    })
                    .collect();
                return (found, notes, asked);
            }
            ActiveScanResult::PendingApproval { approval_id, .. } if !asked => {
                asked = true;
                let approver = Actor::parse("human:lead").unwrap();
                s.decide_approval(&approval_id, &approver, true).unwrap();
                req.approval_id = Some(approval_id);
            }
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn oauth_and_deserialization_need_no_approval() {
    let (s, url) = setup().await;
    let get = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\n\r\n");
    let auth = "/oauth/authorize?response_type=code&client_id=shop-web&redirect_uri=http%3A%2F%2Fshop.test%2Foauth%2Fcallback&state=s1";
    let ex = record(&s, &url, &get(auth)).await;
    let (found, _, asked) = scan(&s, ex, &["oauth"]).await;
    assert!(!asked);
    let titles: Vec<&str> = found.iter().map(|f| f.1.as_str()).collect();
    assert_eq!(titles.len(), 2, "{found:?}");
    assert!(titles[0].contains("redirect_uri") && titles[1].contains("without state"));
    // The registered-URI-only look-alike stays quiet.
    let ex = record(&s, &url, &get(&auth.replace("/oauth/", "/oauth2/"))).await;
    assert!(scan(&s, ex, &["oauth"]).await.0.is_empty());

    let cart =
        "GET /api/cart HTTP/1.1\r\nHost: shop.test\r\nCookie: cart=YToxOntzOjQ6Iml0ZW0iO3M6NjoiQ29mZmVlIjt9\r\n\r\n";
    let ex = record(&s, &url, cart).await;
    let (found, _, _) = scan(&s, ex, &["deserialization"]).await;
    assert_eq!(found.iter().map(|f| f.2.as_str()).collect::<Vec<_>>(), ["cookie cart"], "{found:?}");
    assert!(found[0].3.contains("PHP") && found[0].3.contains("unserialize()"));
}

#[tokio::test]
async fn smuggling_and_uploads_are_approved_first() {
    let (s, url) = setup().await;
    let ex = record(&s, &url, "GET /legacy/status HTTP/1.1\r\nHost: shop.test\r\n\r\n").await;
    let (found, _, asked) = scan(&s, ex, &["request_smuggling"]).await;
    assert!(asked, "smuggling needs a person's approval");
    assert_eq!(found.iter().map(|f| f.2.as_str()).collect::<Vec<_>>(), ["request framing"], "{found:?}");
    assert!(found[0].3.contains("TE.CL"), "{}", found[0].3);
    // Elsewhere both framings agree: nothing.
    let ex = record(&s, &url, "GET /api/products HTTP/1.1\r\nHost: shop.test\r\n\r\n").await;
    assert!(scan(&s, ex, &["request_smuggling"]).await.0.is_empty());

    let upload = "POST /api/avatar HTTP/1.1\r\nHost: shop.test\r\nContent-Type: multipart/form-data; boundary=B0\r\n\r\n\
                  --B0\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"me.png\"\r\nContent-Type: image/png\r\n\r\n\
                  PNGDATA\r\n--B0--\r\n";
    let ex = record(&s, &url, upload).await;
    let (found, _, asked) = scan(&s, ex, &["file_upload"]).await;
    assert!(asked);
    // HTML and SVG are served as pages; PHP is stored but never runs.
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found.iter().all(|f| f.1.contains("stored XSS")));
    assert!(found[0].3.contains("/uploads/pm"), "{}", found[0].3);
}

#[tokio::test]
async fn races_run_before_the_baseline() {
    let (s, url) = setup().await;
    let login = record(
        &s,
        &url,
        "POST /api/login HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/json\r\n\r\n\
         {\"username\":\"bob\",\"password\":\"bob123\"}",
    )
    .await;
    let resp = String::from_utf8_lossy(&s.exchange_raw(login).unwrap().response.unwrap()).into_owned();
    let token = resp.split("\"token\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();
    // A redeem captured elsewhere (imported, so not sent yet): the card is still fresh.
    let har = serde_json::json!({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": [{
        "startedDateTime": "2026-10-20T10:00:00.000Z", "time": 5,
        "request": {"method": "POST", "url": format!("{url}/api/giftcard/redeem"), "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Host", "value": "shop.test"}, {"name": "Cookie", "value": format!("session={token}")},
                        {"name": "Content-Type", "value": "application/json"}],
            "queryString": [], "cookies": [], "headersSize": -1, "bodySize": 20,
            "postData": {"mimeType": "application/json", "text": "{\"code\":\"WELCOME10\"}"}},
        "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
            "headers": [{"name": "Content-Type", "value": "application/json"}], "cookies": [],
            "content": {"size": 40, "mimeType": "application/json", "text": "{\"redeemed\":\"WELCOME10\",\"credit\":10}"},
            "redirectURL": "", "headersSize": -1, "bodySize": 40},
        "cache": {}, "timings": {"send": 1, "wait": 3, "receive": 1}}]}});
    let imported = s.traffic_import_har(&human(), &pm_service::ImportRequest { har: har.to_string() }).unwrap();
    let ex = imported.exchange_ids[0];
    let (found, _, asked) = scan(&s, ex, &["race_condition"]).await;
    assert!(asked);
    assert_eq!(found.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["race_condition"], "{found:?}");
    assert!(found[0].3.contains("refused"), "{}", found[0].3);
    // Used up now: a second scan says so instead of reporting.
    let (found, notes, _) = scan(&s, ex, &["race_condition"]).await;
    assert!(found.is_empty());
    assert!(notes.iter().any(|n| n.contains("used up")), "{notes:?}");
}
