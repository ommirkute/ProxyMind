//! Identities and authorization checks against VulnShop.

use pm_demo::VulnShop;
use pm_service::pm_identity::{AuthMaterial, HealthCheck, Identity, LoginRecipe, LoginStep};
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{NewExchange, Store};
use pm_service::{AuthzCheckRequest, ReplayRequest, ReplayResult, Service};

fn agent() -> Actor {
    Actor::parse("agent:test").unwrap()
}
fn human() -> Actor {
    Actor::parse("human:omkar").unwrap()
}

async fn setup() -> (Service, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let roe = format!("version: 1\nscope:\n  include: [\"http://127.0.0.1:{}/\"]\n", addr.port());
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    (s, format!("http://127.0.0.1:{}", addr.port()))
}

fn login_step(url: &str, user: &str) -> LoginStep {
    let body = format!("{{\"username\":\"{user}\",\"password\":\"{user}123\"}}");
    LoginStep {
        url: url.into(),
        request: format!("POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{body}"),
        token_json_pointer: None,
        token_header: None,
        token_prefix: None,
        ..Default::default()
    }
}

fn identity(url: &str, user: &str) -> Identity {
    Identity {
        name: user.into(),
        role: "user".into(),
        auth: AuthMaterial { cookies: vec![("session".into(), "expired".into())], headers: vec![] },
        health: Some(HealthCheck {
            url: url.into(),
            request: "GET /api/me HTTP/1.1\r\nHost: x\r\n\r\n".into(),
            expect_status: Some(200),
            expect_contains: Some(format!("{user}@vulnshop.test")),
        }),
        logged_out: None,
        login: Some(LoginRecipe { steps: vec![login_step(url, user)] }),
    }
}

#[tokio::test]
async fn sessions_are_revived_by_login_recipes() {
    let (s, url) = setup().await;
    s.identity_set(&human(), identity(&url, "alice")).unwrap();
    // Agents can't define identities with raw credentials.
    assert!(s.identity_set(&agent(), identity(&url, "bob")).is_err());

    let check = s.identity_check(&agent(), "alice").await.unwrap();
    assert_eq!(check.status, "ok", "{check:?}");
    assert!(check.notes.iter().any(|n| n.contains("login ok")), "{check:?}");

    // The agent sees cookie names, never values.
    let list = serde_json::to_string(&s.identity_list().unwrap()).unwrap();
    assert!(list.contains("\"session\"") && !list.contains("expired"));
}

#[tokio::test]
async fn authz_check_finds_the_idor_and_respects_secure_endpoints() {
    let (s, url) = setup().await;
    s.identity_set(&human(), identity(&url, "alice")).unwrap();
    s.identity_set(&human(), identity(&url, "bob")).unwrap();
    s.identity_check(&human(), "alice").await.unwrap();
    s.identity_check(&human(), "bob").await.unwrap();

    // Alice views her own order and invoice (the agent sends as alice).
    let mut ids = Vec::new();
    for path in ["/api/orders/1001", "/api/invoices/5001"] {
        let r = s
            .replay_send(
                &agent(),
                ReplayRequest {
                    url: Some(url.clone()),
                    raw: Some(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")),
                    identity: Some("alice".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let ReplayResult::Sent { exchange_id, .. } = r else { panic!("{r:?}") };
        ids.push(exchange_id);
    }

    let verdict = |report: &pm_service::AuthzReport, who: &str| {
        report.results.iter().find(|r| r.identity == who).unwrap().verdict.clone()
    };
    let order = s
        .authz_check(
            &agent(),
            AuthzCheckRequest { exchange_id: ids[0], identities: vec!["bob".into()], include_anonymous: None },
        )
        .await
        .unwrap();
    assert_eq!(verdict(&order, "bob"), "same_as_owner", "{order:#?}");
    assert_eq!(verdict(&order, "anonymous"), "denied");
    assert!(order.noise.json_paths.contains("/meta/request_id"), "{:?}", order.noise);

    let invoice = s
        .authz_check(
            &agent(),
            AuthzCheckRequest { exchange_id: ids[1], identities: vec!["bob".into()], include_anonymous: None },
        )
        .await
        .unwrap();
    assert_eq!(verdict(&invoice, "bob"), "denied", "{invoice:#?}");

    assert_eq!(s.authz_results(None).unwrap().len(), 4);
}

#[tokio::test]
async fn authz_check_refuses_state_changing_requests() {
    let (_, url) = setup().await;
    let port: u16 = url.rsplit(':').next().unwrap().parse().unwrap();
    let mut store = Store::open_in_memory().unwrap();
    let id = store
        .insert_exchange(&NewExchange {
            ts_ms: 0,
            duration_ms: None,
            source: "proxy".into(),
            actor_id: "human:local".into(),
            scheme: "http".into(),
            host: "127.0.0.1".into(),
            port,
            method: "POST".into(),
            path: "/api/orders".into(),
            status: None,
            request: b"POST /api/orders HTTP/1.1\r\n\r\n".to_vec(),
            response: None,
            error: None,
            identity: None,
            hypothesis_id: None,
        })
        .unwrap();
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(store, Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let err = s
        .authz_check(&agent(), AuthzCheckRequest { exchange_id: id, identities: vec![], include_anonymous: None })
        .await;
    assert!(err.unwrap_err().to_string().contains("changes state"));
}
