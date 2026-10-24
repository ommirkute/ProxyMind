//! Scanner step 4 against VulnShop: JWT, GraphQL, web caches, mass
//! assignment and prototype pollution, with the look-alikes staying quiet.

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

/// (check, title, point, evidence) of each issue.
async fn scan(s: &Service, ex: i64, checks: &[&str]) -> Vec<(String, String, String, String)> {
    let req = ActiveScanRequest {
        exchange_id: ex,
        checks: checks.iter().map(|c| c.to_string()).collect(),
        ..Default::default()
    };
    match s.scan_active(&human(), req).await.unwrap() {
        ActiveScanResult::Done { issues, .. } => issues
            .iter()
            .map(|i| (i.issue.check.into(), i.issue.title.into(), i.issue.point.clone(), i.issue.evidence.clone()))
            .collect(),
        other => panic!("{other:?}"),
    }
}

async fn login(s: &Service, url: &str) -> serde_json::Value {
    let ex = record(
        s,
        url,
        "POST /api/login HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/json\r\n\r\n\
         {\"username\":\"alice\",\"password\":\"alice123\"}",
    )
    .await;
    let resp = s.exchange_raw(ex).unwrap().response.unwrap();
    let text = String::from_utf8_lossy(&resp);
    serde_json::from_str(text.split("\r\n\r\n").nth(1).unwrap()).unwrap()
}

#[tokio::test]
async fn jwt_graphql_and_caches() {
    let (s, url) = setup().await;
    let l = login(&s, &url).await;
    let (jwt, session) = (l["jwt"].as_str().unwrap(), l["token"].as_str().unwrap());

    // JWT: the weak secret (offline) and alg none (sent).
    let ex = record(
        &s,
        &url,
        &format!("GET /api/v3/profile HTTP/1.1\r\nHost: shop.test\r\nAuthorization: Bearer {jwt}\r\n\r\n"),
    )
    .await;
    let found = scan(&s, ex, &["jwt"]).await;
    let titles: Vec<&str> = found.iter().map(|f| f.1.as_str()).collect();
    assert_eq!(
        titles,
        ["JWT signed with a guessable secret", "JWT forgery accepted (alg none or no signature)"],
        "{found:?}"
    );
    assert!(found.iter().all(|f| f.2 == "request jwt (authorization)" && !f.3.contains(jwt)));
    assert!(found[0].3.contains("\"secret\""));

    // GraphQL: introspection and batching (suggestions and GET are off here).
    let gql = format!(
        "POST /graphql HTTP/1.1\r\nHost: shop.test\r\nCookie: session={session}\r\nContent-Type: application/json\r\n\r\n\
         {{\"query\":\"{{ me {{ id username }} }}\"}}"
    );
    let ex = record(&s, &url, &gql).await;
    let found = scan(&s, ex, &["graphql"]).await;
    let titles: Vec<&str> = found.iter().map(|f| f.1.as_str()).collect();
    assert_eq!(titles.len(), 2, "{found:?}");
    assert!(titles[0].contains("introspection") && titles[1].contains("batching"));

    // Cache poisoning: X-Forwarded-Host sticks in the cache; the notice page ignores it.
    let get = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\n\r\n");
    let ex = record(&s, &url, &get("/api/banner?lang=en")).await;
    let found = scan(&s, ex, &["cache_poisoning"]).await;
    assert_eq!(
        found.iter().map(|f| f.2.as_str()).collect::<Vec<_>>(),
        ["request x-forwarded-host header"],
        "{found:?}"
    );
    assert!(found[0].3.contains("x-cache: hit"), "{}", found[0].3);
    let ex = record(&s, &url, &get("/api/notice?lang=en")).await;
    assert!(scan(&s, ex, &["cache_poisoning", "host_header"]).await.is_empty());
    // Probes used a buster: the real entry is untouched.
    let clean = record(&s, &url, &get("/api/banner?lang=en")).await;
    let body = String::from_utf8_lossy(&s.exchange_raw(clean).unwrap().response.unwrap()).into_owned();
    assert!(body.contains("//shop.test/static/banner.js"), "{body}");

    // Cache deception: a .css suffix on the private settings page gets cached.
    let authed = |path: &str| format!("GET {path} HTTP/1.1\r\nHost: shop.test\r\nCookie: session={session}\r\n\r\n");
    let ex = record(&s, &url, &authed("/api/account/settings")).await;
    let found = scan(&s, ex, &["cache_deception"]).await;
    assert_eq!(found.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["cache_deception"], "{found:?}");
    let ex = record(&s, &url, &authed("/api/account/keys")).await;
    assert!(scan(&s, ex, &["cache_deception"]).await.is_empty());
}

#[tokio::test]
async fn mass_assignment_and_prototype_pollution() {
    let (s, url) = setup().await;
    let post = |path: &str, body: &str| {
        format!("POST {path} HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/json\r\n\r\n{body}")
    };
    let ex = record(&s, &url, &post("/api/register", r#"{"username":"carol","password":"carol123"}"#)).await;
    let found = scan(&s, ex, &["mass_assignment"]).await;
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].3.contains("role=admin"), "{}", found[0].3);
    let ex = record(&s, &url, &post("/api/signup", r#"{"username":"dave","password":"dave123"}"#)).await;
    assert!(scan(&s, ex, &["mass_assignment"]).await.is_empty());

    // An endpoint that only echoes its input isn't polluted (the guestbook ignores JSON keys it doesn't know).
    let ex = record(&s, &url, &post("/api/signup", r#"{"username":"erin"}"#)).await;
    assert!(scan(&s, ex, &["proto_pollution"]).await.is_empty());
    let ex = record(&s, &url, &post("/api/preferences", r#"{"theme":"dark"}"#)).await;
    let found = scan(&s, ex, &["proto_pollution"]).await;
    assert_eq!(found.iter().map(|f| f.0.as_str()).collect::<Vec<_>>(), ["proto_pollution"], "{found:?}");
}
