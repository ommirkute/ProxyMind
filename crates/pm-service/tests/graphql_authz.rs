//! GraphQL object access against VulnShop: invoice(id) returns any user's
//! invoice (VS-12), though GET /api/invoices/{id} checks ownership.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_identity::{AuthMaterial, Identity, LoginRecipe, LoginStep};
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{ProofRequest, ProofResult, ReplayRequest, ReplayResult, Service};

fn agent() -> Actor {
    Actor::parse("agent:test").unwrap()
}
fn human() -> Actor {
    Actor::parse("human:omkar").unwrap()
}

async fn setup() -> (Arc<Service>, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!(
        "version: 1\nscope:\n  include: [\"{url}/\"]\ntiers:\n  human:\n    active_intrusive: allow\n    destructive: allow\n"
    );
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    for (user, role) in [("alice", "user"), ("bob", "user"), ("admin", "admin")] {
        let body = format!("{{\"username\":\"{user}\",\"password\":\"{user}123\"}}");
        s.identity_set(
            &human(),
            Identity {
                name: user.into(),
                role: role.into(),
                auth: AuthMaterial::default(),
                health: None,
                logged_out: None,
                login: Some(LoginRecipe {
                    steps: vec![LoginStep {
                        url: url.clone(),
                        request: format!(
                            "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{body}"
                        ),
                        token_json_pointer: None,
                        token_header: None,
                        token_prefix: None,
                        ..Default::default()
                    }],
                }),
            },
        )
        .unwrap();
        s.identity_login(user).await.unwrap();
    }
    (s, url)
}

async fn get_as(s: &Service, url: &str, path: &str, who: &str) -> i64 {
    let r = s
        .replay_send(
            &agent(),
            ReplayRequest {
                url: Some(url.into()),
                raw: Some(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")),
                identity: Some(who.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    match r {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn graphql_resolver_without_ownership_check() {
    let (s, url) = setup().await;
    // Nothing recorded on GraphQL yet: nothing to test.
    assert!(s.graphql_object_access(&human()).await.unwrap().is_empty());
    // Alice reads her invoice over REST (the model learns its owner), and uses GraphQL once.
    get_as(&s, &url, "/api/invoices/5001", "alice").await;
    let body = r#"{"query":"{ me { id username } }"}"#;
    let raw = format!(
        "POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let req =
        ReplayRequest { url: Some(url.clone()), raw: Some(raw), identity: Some("alice".into()), ..Default::default() };
    assert!(matches!(s.replay_send(&human(), req).await.unwrap(), ReplayResult::Sent { .. }));

    let leads = s.graphql_object_access(&human()).await.unwrap();
    assert_eq!(leads.len(), 1, "{leads:?}");
    assert_eq!(leads[0].check, "graphql_object_access");
    assert!(leads[0].evidence.contains("bob asked for alice's Invoice 5001"), "{}", leads[0].evidence);
    let f = s.finding_get(leads[0].finding_id).unwrap();
    assert_eq!(f["vuln_class"], "idor");
}

async fn post_graphql_as(s: &Service, url: &str, query: &str, who: &str) -> i64 {
    let body = serde_json::json!({ "query": query }).to_string();
    let raw = format!(
        "POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let req = ReplayRequest { url: Some(url.into()), raw: Some(raw), identity: Some(who.into()), ..Default::default() };
    match s.replay_send(&human(), req).await.unwrap() {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

fn differential(exchange_id: i64) -> ProofRequest {
    ProofRequest {
        oracle: "differential_authz".into(),
        exchange_id: Some(exchange_id),
        attacker: Some("bob".into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn differential_authz_proves_a_graphql_query_sent_by_post() {
    let (s, url) = setup().await;
    let ex = post_graphql_as(&s, &url, "{ invoice(id: 5001) { id total } }", "alice").await;
    match s.proof_run(&human(), differential(ex)).await.unwrap() {
        ProofResult::Completed { proven, reasons, .. } => assert!(proven, "{reasons:?}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn differential_authz_refuses_a_graphql_mutation_and_sends_nothing() {
    let (s, url) = setup().await;
    let ex = post_graphql_as(&s, &url, "mutation { deleteInvoice(id: 5001) { id } }", "alice").await;
    let before = s.history_mark().unwrap();
    let err = s.proof_run(&human(), differential(ex)).await.unwrap_err().to_string();
    assert!(err.contains("mutation"), "{err}");
    assert_eq!(before, s.history_mark().unwrap(), "nothing may be re-sent");
}
