//! The proof engine against VulnShop: real bugs are proven, traps are not.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_identity::{AuthMaterial, Identity, LoginRecipe, LoginStep};
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{NewFinding, NewHypothesis, ProofRequest, ProofResult, ReplayRequest, ReplayResult, Service};
use serde_json::Value;

fn agent() -> Actor {
    Actor::parse("agent:test").unwrap()
}
fn human() -> Actor {
    Actor::parse("human:omkar").unwrap()
}

async fn setup() -> (Arc<Service>, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
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
                login: Some(LoginRecipe {
                    steps: vec![LoginStep {
                        url: url.clone(),
                        request: format!(
                            "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{body}"
                        ),
                        token_json_pointer: None,
                        token_header: None,
                        token_prefix: None,
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

fn completed(r: ProofResult) -> (bool, String, Vec<String>) {
    match r {
        ProofResult::Completed { proven, confidence, reasons, .. } => (proven, confidence, reasons),
        other => panic!("{other:?}"),
    }
}

async fn differential(
    s: &Service,
    ex: i64,
    attacker: &str,
    finding: Option<i64>,
    hyp: Option<i64>,
) -> (bool, String, Vec<String>) {
    completed(
        s.proof_run(
            &agent(),
            ProofRequest {
                oracle: "differential_authz".into(),
                exchange_id: Some(ex),
                attacker: Some(attacker.into()),
                finding_id: finding,
                hypothesis_id: hyp,
                ..Default::default()
            },
        )
        .await
        .unwrap(),
    )
}

#[tokio::test]
async fn proves_real_access_control_bugs_and_rejects_traps() {
    let (s, url) = setup().await;
    get_as(&s, &url, "/api/orders", "alice").await;
    get_as(&s, &url, "/api/orders", "bob").await;
    let alice_order = get_as(&s, &url, "/api/orders/1001", "alice").await;
    let alice_invoice = get_as(&s, &url, "/api/invoices/5001", "alice").await;
    let admin_users = get_as(&s, &url, "/api/admin/users", "admin").await;

    // The model knows who owns what and suggests the right test.
    let cands = s.authz_candidates().unwrap();
    let c = cands.iter().find(|c| c.object == "Order 1001").expect("candidate for alice's order");
    assert_eq!((c.owner.as_str(), c.exchange_id), ("alice", alice_order));

    let op = format!("GET {url}/api/orders/{{id}}");
    let hyp = s
        .hypothesis_create(
            &agent(),
            NewHypothesis {
                operation: op.clone(),
                param: String::new(),
                vuln_class: "idor".into(),
                rationale: "no ownership check?".into(),
            },
        )
        .unwrap();
    let finding = s
        .finding_create(
            &agent(),
            NewFinding {
                title: "IDOR on orders".into(),
                vuln_class: "idor".into(),
                severity: "high".into(),
                description: "Any user can read any order.".into(),
                url: None,
                evidence: vec![alice_order],
                hypothesis_id: Some(hyp.id),
            },
        )
        .unwrap();
    let fid = finding["id"].as_i64().unwrap();

    // VS-1: proven, with alice's email as a marker.
    let (proven, conf, reasons) = differential(&s, alice_order, "bob", Some(fid), Some(hyp.id)).await;
    assert!(proven, "{reasons:?}");
    assert_eq!(conf, "high");
    assert!(reasons.iter().any(|r| r.contains("alice@vulnshop.test")), "{reasons:?}");
    assert_eq!(s.finding_get(fid).unwrap()["status"], "proven");
    assert_eq!(s.hypothesis_get(hyp.id).unwrap().status, "confirmed");

    // Traps: the secure invoice, and an admin reading an order.
    assert!(!differential(&s, alice_invoice, "bob", None, None).await.0, "invoice is protected");
    assert!(!differential(&s, alice_order, "admin", None, None).await.0, "admins may read orders");

    // VS-2: a normal user can call the admin-only function.
    let (proven, _, reasons) = differential(&s, admin_users, "bob", None, None).await;
    assert!(proven, "{reasons:?}");

    // Agents can't mark findings proven by hand; humans can confirm.
    let upd = |status: &str| pm_service::FindingUpdate {
        id: fid,
        status: Some(status.into()),
        severity: None,
        description: None,
        add_evidence: vec![],
    };
    assert!(s.finding_update(&agent(), upd("proven")).is_err());
    assert!(s.finding_update(&agent(), upd("confirmed")).is_err());
    assert_eq!(s.finding_update(&human(), upd("confirmed")).unwrap()["status"], "confirmed");

    let cov = s.coverage(false).unwrap();
    let cell = cov.cells.iter().find(|c| c.operation == op && c.vuln_class == "idor").unwrap();
    assert_eq!(cell.status, "confirmed");

    let report = s.report_markdown().unwrap();
    assert!(
        report.contains("IDOR on orders")
            && report.contains("differential_authz")
            && report.contains("hash chain verified")
    );
}

#[tokio::test]
async fn timing_proof_needs_approval_for_agents_and_separates_signal_from_noise() {
    let (s, url) = setup().await;
    let base = get_as(&s, &url, "/api/products/search?q=Coffee", "alice").await;
    let req = |payload: &str| ProofRequest {
        oracle: "timing".into(),
        exchange_id: Some(base),
        payload_raw: Some(format!("GET /api/products/search?q={payload} HTTP/1.1\r\nHost: x\r\n\r\n")),
        samples: Some(5),
        ..Default::default()
    };
    // Agents need approval for payload sends.
    assert!(matches!(
        s.proof_run(&agent(), req("x%27%20AND%20SLEEP(1)--")).await.unwrap(),
        ProofResult::PendingApproval { .. }
    ));
    // A human runs it directly.
    let (proven, _, reasons) = completed(s.proof_run(&human(), req("x%27%20AND%20SLEEP(1)--")).await.unwrap());
    assert!(proven, "{reasons:?}");
    let (proven, _, reasons) = completed(s.proof_run(&human(), req("x%27%20AND%201=1--")).await.unwrap());
    assert!(!proven, "no delay, no proof: {reasons:?}");
}

#[tokio::test]
async fn oast_proof_catches_ssrf() {
    let (s, url) = setup().await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let oast_url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let s2 = s.clone();
    tokio::spawn(pm_service::pm_oast::serve(l, move |i| {
        let _ = s2.record_oast(&i);
    }));
    s.set_oast_public_url(&oast_url).unwrap();
    let run = |raw: &str| ProofRequest {
        oracle: "oast".into(),
        url: Some(url.clone()),
        raw: Some(raw.into()),
        wait_seconds: Some(3),
        ..Default::default()
    };
    let (proven, _, reasons) = completed(
        s.proof_run(&human(), run("GET /api/fetch?url={{oast}}/x HTTP/1.1\r\nHost: x\r\n\r\n")).await.unwrap(),
    );
    assert!(proven, "{reasons:?}");
    let (proven, _, _) = completed(
        s.proof_run(&human(), run("GET /api/products/search?q={{oast}} HTTP/1.1\r\nHost: x\r\n\r\n")).await.unwrap(),
    );
    assert!(!proven, "no fetch, no callback");
    let proof: Value = s.proof_get(1).unwrap();
    assert_eq!(proof["oracle"], "oast");
}

#[tokio::test]
async fn reflection_proof_runs_the_payload_in_a_browser_and_rejects_encoded_reflection() {
    let (s, url) = setup().await;
    if s.chromium_path().unwrap().is_none() {
        eprintln!("no Chromium found; set PROXYMIND_CHROMIUM to run this test");
        return;
    }
    let run = |raw: &str| ProofRequest {
        oracle: "reflection".into(),
        url: Some(url.clone()),
        raw: Some(raw.into()),
        ..Default::default()
    };
    // Agents need approval: payload sends are intrusive.
    assert!(matches!(
        s.proof_run(&agent(), run("GET /search?q={{xss_url}} HTTP/1.1\r\nHost: x\r\n\r\n")).await.unwrap(),
        ProofResult::PendingApproval { .. }
    ));

    // VS-6: the payload runs.
    let r = s.proof_run(&human(), run("GET /search?q={{xss_url}} HTTP/1.1\r\nHost: x\r\n\r\n")).await.unwrap();
    let ProofResult::Completed { proven, confidence, reasons, details, exchange_ids, .. } = r else { panic!("{r:?}") };
    assert!(proven, "{reasons:?} {details}");
    assert_eq!(confidence, "high");
    assert!(reasons[0].contains("ran the injected script"), "{reasons:?}");
    assert_eq!(details["payload_in_body"], true);
    assert!(details["page_activity"].as_str().unwrap().starts_with("<untrusted_target_content>"));
    assert_eq!(exchange_ids.len(), 1);

    // A payload of the tester's own, using alert() with the token.
    let (proven, _, reasons) = completed(
        s.proof_run(&human(), run("GET /search?q=%3Csvg%20onload%3Dalert('{{token}}')%3E HTTP/1.1\r\nHost: x\r\n\r\n"))
            .await
            .unwrap(),
    );
    assert!(proven, "{reasons:?}");
    assert!(reasons[0].contains("opened a dialog"), "{reasons:?}");

    // Trap: /help reflects the payload HTML-encoded.
    let (proven, _, reasons) =
        completed(s.proof_run(&human(), run("GET /help?topic={{xss_url}} HTTP/1.1\r\nHost: x\r\n\r\n")).await.unwrap());
    assert!(!proven, "encoded reflection is not XSS");
    assert!(reasons[0].contains("encoded"), "{reasons:?}");

    // Trap: JSON endpoints that don't reflect.
    let (proven, _, reasons) = completed(
        s.proof_run(&human(), run("GET /api/products/search?q={{xss_url}} HTTP/1.1\r\nHost: x\r\n\r\n")).await.unwrap(),
    );
    assert!(!proven && reasons[0].contains("nothing reflected"), "{reasons:?}");

    // Re-running uses a fresh token and proves it again.
    let r = s.proof_rerun(&human(), 1).await.unwrap();
    let ProofResult::Completed { proven, details: again, .. } = r else { panic!("{r:?}") };
    assert!(proven);
    assert_ne!(again["token"], details["token"]);

    // Placeholders are required.
    assert!(s.proof_run(&human(), run("GET /search?q=x HTTP/1.1\r\nHost: x\r\n\r\n")).await.is_err());
}
