//! The authorization matrix proves VulnShop's broken access control; model
//! snapshots say what changed between two rounds of testing.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_identity::{AuthMaterial, Identity, LoginRecipe, LoginStep};
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{AuthzMatrixRequest, NewFinding, ReplayRequest, ReplayResult, Service};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn setup(users: &[(&str, &str)]) -> (Arc<Service>, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    for (user, role) in users {
        let body = format!("{{\"username\":\"{user}\",\"password\":\"{user}123\"}}");
        s.identity_set(
            &human(),
            Identity {
                name: (*user).into(),
                role: (*role).into(),
                auth: AuthMaterial::default(),
                health: None,
                logged_out: None,
                login: Some(LoginRecipe {
                    steps: vec![LoginStep {
                        url: url.clone(),
                        request: format!(
                            "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{body}"
                        ),
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

async fn get(s: &Service, url: &str, path: &str, who: Option<&str>) -> i64 {
    let r = s
        .replay_send(
            &human(),
            ReplayRequest {
                url: Some(url.into()),
                raw: Some(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")),
                identity: who.map(str::to_string),
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
async fn the_matrix_flags_and_proves_broken_access_control() {
    let (s, url) = setup(&[("alice", "user"), ("bob", "user"), ("admin", "admin")]).await;
    get(&s, &url, "/api/orders/1001", Some("alice")).await;
    get(&s, &url, "/api/orders", Some("alice")).await;
    get(&s, &url, "/api/admin/users", Some("admin")).await;

    let m = s.authz_matrix(&human(), AuthzMatrixRequest { prove: true, ..Default::default() }).await.unwrap();
    let names: Vec<&str> = m.identities.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["admin", "alice", "bob", "anonymous"]);
    let order = m.rows.iter().find(|r| r.operation.ends_with("/api/orders/{id}")).expect("orders row");
    assert_eq!(order.owner.as_deref(), Some("alice"));
    assert_eq!(order.cells["alice"].verdict, "owner");
    assert_eq!(order.cells["bob"].verdict, "same_as_owner", "{:?}", order.cells);
    let idor = order.flags.iter().find(|f| f.identity == "bob" && f.kind == "idor").expect("bob's IDOR is flagged");
    assert_eq!(idor.proven, Some(true), "{order:?}");
    let fid = idor.finding_id.expect("a proven flag becomes a finding");
    let f = s.finding_get(fid).unwrap();
    assert_eq!(f["status"], "proven");
    assert_eq!(f["vuln_class"], "idor");
    assert!(m.proven >= 1 && m.flagged >= m.proven);
    assert!(m.rows[0].flags.len() >= m.rows.last().unwrap().flags.len(), "flagged rows first");
    // The collection is each user's own list: no flag there.
    let list = m.rows.iter().find(|r| r.operation.ends_with("/api/orders")).unwrap();
    assert!(list.flags.iter().all(|f| f.identity != "bob"), "{list:?}");
}

#[tokio::test]
async fn changes_since_a_snapshot_point_the_retest() {
    let (s, url) = setup(&[("alice", "user")]).await;
    get(&s, &url, "/api/orders/1001", Some("alice")).await;
    get(&s, &url, "/api/products", None).await;
    let snap = s.model_snapshot_save(&human(), "round 1").unwrap();
    assert!(snap.operations >= 2);
    assert!(s.model_snapshot_save(&Actor::parse("agent:x").unwrap(), "no").is_err(), "people only");
    s.finding_create(
        &human(),
        NewFinding {
            title: "Products leak".into(),
            vuln_class: "exposure".into(),
            severity: "low".into(),
            description: "x".into(),
            url: Some(format!("{url}/api/products")),
            evidence: vec![],
            hypothesis_id: None,
        },
    )
    .unwrap();

    // Round 2: a new endpoint, and a new parameter on an old one.
    get(&s, &url, "/api/products?q=tea", None).await;
    get(&s, &url, "/api/invoices/5001", Some("alice")).await;
    let c = s.model_changes(snap.id).unwrap();
    assert_eq!(c.since, "snapshot \"round 1\"");
    assert!(c.added.iter().any(|a| a.template == "/api/invoices/{id}"), "{:?}", c.added);
    let products = c.changed.iter().find(|x| x.operation == "GET /api/products").expect("products changed");
    assert_eq!(products.params_added, ["q"]);
    assert!(c.removed.is_empty());
    let r = c.retest.iter().find(|x| x.operation == "GET /api/products").unwrap();
    assert!(r.why.contains("new parameters: q") && r.findings.len() == 1, "{r:?}");
    assert!(c.retest.iter().any(|x| x.operation == "GET /api/invoices/{id}" && x.why.starts_with("new endpoint")));
    assert!(c.unchanged >= 1);
    assert_eq!(s.model_snapshot_list().unwrap().len(), 1);
}
