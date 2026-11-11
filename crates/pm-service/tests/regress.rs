//! Proven findings become regression tests that run without the project:
//! still vulnerable against the app, fixed against a server that refuses.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_identity::{AuthMaterial, Identity, LoginRecipe, LoginStep};
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::pm_tools::regress::{FORMAT, RegressionTest, TestFinding, VulnerableIf};
use pm_service::pm_tools::zip;
use pm_service::{NewFinding, ProofRequest, ProofResult, ReplayRequest, ReplayResult, Service, junit, run_regression};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn setup() -> (Arc<Service>, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    for user in ["alice", "bob"] {
        let body = format!("{{\"username\":\"{user}\",\"password\":\"{user}123\"}}");
        s.identity_set(
            &human(),
            Identity {
                name: user.into(),
                role: "user".into(),
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

/// A server that refuses everything: the app after the fix.
async fn refusing_server() -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf).await;
            let _ =
                c.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\nConnection: close\r\n\r\nforbidden").await;
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn a_proven_idor_runs_in_ci_until_it_is_fixed() {
    let (s, url) = setup().await;
    let r = s
        .replay_send(
            &human(),
            ReplayRequest {
                url: Some(url.clone()),
                raw: Some("GET /api/orders/1001 HTTP/1.1\r\nHost: x\r\n\r\n".into()),
                identity: Some("alice".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let ReplayResult::Sent { exchange_id, .. } = r else { panic!("{r:?}") };
    let f = s
        .finding_create(
            &human(),
            NewFinding {
                title: "IDOR on orders".into(),
                vuln_class: "idor".into(),
                severity: "high".into(),
                description: "Any user reads any order.".into(),
                url: None,
                evidence: vec![exchange_id],
                hypothesis_id: None,
            },
        )
        .unwrap();
    let fid = f["id"].as_i64().unwrap();
    // An unproven finding gets no test.
    s.finding_create(
        &human(),
        NewFinding {
            title: "Maybe SQLi".into(),
            vuln_class: "sqli".into(),
            severity: "high".into(),
            description: "x".into(),
            url: Some(format!("{url}/search?q=1")),
            evidence: vec![],
            hypothesis_id: None,
        },
    )
    .unwrap();
    let proof = s
        .proof_run(
            &human(),
            ProofRequest {
                oracle: "differential_authz".into(),
                exchange_id: Some(exchange_id),
                attacker: Some("bob".into()),
                finding_id: Some(fid),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(proof, ProofResult::Completed { proven: true, .. }), "{proof:?}");

    let export = s.regression_tests().unwrap();
    assert_eq!(export.tests.len(), 1, "{:?}", export.skipped);
    assert!(export.skipped.iter().any(|x| x.title == "Maybe SQLi" && x.reason.contains("no proof")));
    let t = &export.tests[0];
    assert_eq!((t.oracle.as_str(), t.finding.id), ("differential_authz", fid));
    assert_eq!(t.auth, ["bob"]);
    assert!(t.request.contains("{{auth:bob}}"), "{}", t.request);
    assert!(!t.request.to_ascii_lowercase().contains("authorization:"), "credentials stay out of the file");
    assert!(!t.vulnerable_if.body_contains_any.is_empty(), "the owner's data marks the leak");

    // The file round-trips, and the ZIP has the test, a README and a workflow.
    let t: RegressionTest = serde_json::from_str(&serde_json::to_string(t).unwrap()).unwrap();
    let (bytes, _) = s.regression_zip(&human()).unwrap();
    let names: Vec<String> = zip::read(&bytes).unwrap().into_iter().map(|(n, _)| n).collect();
    assert!(names.contains(&format!("tests/finding-{fid}.json")) && names.contains(&"github-workflow.yml".into()));
    let wf = zip::read(&bytes).unwrap().into_iter().find(|(n, _)| n == "github-workflow.yml").unwrap().1;
    let wf = String::from_utf8(wf).unwrap();
    assert!(wf.contains("PM_AUTH_BOB: ${{ secrets.PM_AUTH_BOB }}") && wf.contains("proxymind regress run"), "{wf}");

    // Bob's credentials, as a CI secret would hold them.
    let bob_raw = {
        let proofs = s.proofs_for_finding(fid).unwrap();
        let attacker_ex = proofs[0]["details"]["exchanges"]["attacker"].as_i64().unwrap();
        String::from_utf8_lossy(&s.exchange_raw(attacker_ex).unwrap().request).into_owned()
    };
    let creds: Vec<&str> = bob_raw
        .lines()
        .filter(|l| {
            let l = l.to_ascii_lowercase();
            l.starts_with("authorization:") || l.starts_with("cookie:")
        })
        .collect();
    assert!(!creds.is_empty(), "{bob_raw}");
    let creds = creds.join("\n");
    let env = |k: &str| (k == "PM_AUTH_BOB").then(|| creds.clone());

    let still = run_regression(&t, None, true, &env).await;
    assert_eq!(still.outcome, "vulnerable", "{still:?}");
    let fixed = run_regression(&t, Some(&refusing_server().await), true, &env).await;
    assert_eq!(fixed.outcome, "fixed", "{fixed:?}");
    let no_creds = run_regression(&t, None, true, &|_| None).await;
    assert_eq!(no_creds.outcome, "skipped");
    assert!(no_creds.detail.contains("PM_AUTH_BOB"));

    let x = junit(&[still, fixed, no_creds]);
    assert!(x.contains("tests=\"3\" failures=\"1\" errors=\"0\" skipped=\"1\""), "{x}");
    assert!(x.contains("<failure message=\"still vulnerable\">"));
}

#[tokio::test]
async fn a_reflection_test_sends_a_fresh_payload() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let t = RegressionTest {
        format: FORMAT.into(),
        finding: TestFinding {
            id: 1,
            title: "Reflected XSS in search".into(),
            severity: "medium".into(),
            vuln_class: "xss".into(),
            url: format!("{url}/search"),
        },
        origin: url.clone(),
        oracle: "reflection".into(),
        request: "GET /search?q={{xss_url}} HTTP/1.1\r\nHost: recorded.test\r\n\r\n".into(),
        baseline: None,
        auth: vec![],
        vulnerable_if: VulnerableIf { reflects_payload: true, ..Default::default() },
        samples: 1,
    };
    let r = run_regression(&t, None, true, &|_| None).await;
    assert_eq!(r.outcome, "vulnerable", "{r:?}");
    let fixed = run_regression(&t, Some(&refusing_server().await), true, &|_| None).await;
    assert_eq!(fixed.outcome, "fixed");
    let bad = RegressionTest { format: "other".into(), ..t };
    assert_eq!(run_regression(&bad, None, true, &|_| None).await.outcome, "error");
}
