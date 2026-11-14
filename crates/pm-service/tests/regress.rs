//! Proven findings become regression tests that run without the project:
//! still vulnerable against the app, fixed against a server that refuses,
//! and an error (never "fixed") when the run can't tell.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_identity::{AuthMaterial, HealthCheck, Identity, LoginRecipe, LoginStep};
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::pm_tools::regress::{AuthCheck, FORMAT_2, RegressionTest, TestFinding, VulnerableIf};
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

/// A server that gives every request the same answer.
async fn answering(status_line: &'static str) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let mut buf = [0u8; 4096];
            let _ = c.read(&mut buf).await;
            let answer = format!("HTTP/1.1 {status_line}\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope");
            let _ = c.write_all(answer.as_bytes()).await;
        }
    });
    format!("http://{addr}")
}

/// A server that refuses everything: the app after the fix.
async fn refusing_server() -> String {
    answering("403 Forbidden").await
}

/// The Cookie header a recorded request carried.
fn cookie_of(s: &Service, exchange_id: i64) -> String {
    let raw = String::from_utf8_lossy(&s.exchange_raw(exchange_id).unwrap().request).into_owned();
    raw.lines().find(|l| l.to_ascii_lowercase().starts_with("cookie:")).expect("a cookie").to_string()
}

async fn get_as(s: &Service, url: &str, path: &str, who: &str) -> i64 {
    let req = ReplayRequest {
        url: Some(url.into()),
        raw: Some(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")),
        identity: Some(who.into()),
        ..Default::default()
    };
    match s.replay_send(&human(), req).await.unwrap() {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
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
    let finding = TestFinding {
        id: 1,
        title: "Reflected XSS in search".into(),
        severity: "medium".into(),
        vuln_class: "xss".into(),
        url: format!("{url}/search"),
    };
    let request = "GET /search?q={{xss_url}} HTTP/1.1\r\nHost: recorded.test\r\n\r\n".to_string();
    let t = RegressionTest {
        vulnerable_if: VulnerableIf { reflects_payload: true, ..Default::default() },
        ..RegressionTest::new(finding, url.clone(), "reflection", request)
    };
    let r = run_regression(&t, None, true, &|_| None).await;
    assert_eq!(r.outcome, "vulnerable", "{r:?}");
    let fixed = run_regression(&t, Some(&refusing_server().await), true, &|_| None).await;
    assert_eq!(fixed.outcome, "fixed");
    // A server that fails says nothing about the fix.
    let broken = run_regression(&t, Some(&answering("500 Internal Server Error").await), true, &|_| None).await;
    assert_eq!(broken.outcome, "error", "{broken:?}");
    assert!(broken.detail.contains("server failed"), "{broken:?}");
    // Formats and kinds this runner doesn't know are refused, not guessed at.
    let bad = RegressionTest { format: "other".into(), ..t.clone() };
    assert_eq!(run_regression(&bad, None, true, &|_| None).await.outcome, "error");
    let unknown = RegressionTest { oracle: "telepathy".into(), ..t };
    assert_eq!(run_regression(&unknown, None, true, &|_| None).await.outcome, "error");
}

#[tokio::test]
async fn credentials_that_stopped_working_are_an_error_not_a_fix() {
    let (s, url) = setup().await;
    // Bob has a health check, as an identity made from a recorded login does.
    let body = "{\"username\":\"bob\",\"password\":\"bob123\"}";
    let login = LoginStep {
        url: url.clone(),
        request: format!("POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{body}"),
        ..Default::default()
    };
    let bob = Identity {
        name: "bob".into(),
        role: "user".into(),
        auth: AuthMaterial::default(),
        health: Some(HealthCheck {
            url: url.clone(),
            request: "GET /api/me HTTP/1.1\r\nHost: x\r\n\r\n".into(),
            expect_status: None,
            expect_contains: Some("bob".into()),
        }),
        logged_out: None,
        login: Some(LoginRecipe { steps: vec![login] }),
    };
    s.identity_set(&human(), bob).unwrap();
    s.identity_login("bob").await.unwrap();

    let order = get_as(&s, &url, "/api/orders/1001", "alice").await;
    let new = NewFinding {
        title: "IDOR on orders".into(),
        vuln_class: "idor".into(),
        severity: "high".into(),
        description: "Any user reads any order.".into(),
        url: None,
        evidence: vec![order],
        hypothesis_id: None,
    };
    let fid = s.finding_create(&human(), new).unwrap()["id"].as_i64().unwrap();
    let r = s.finding_prove(&human(), fid).await.unwrap();
    assert!(r.proven, "{:?}", r.reasons);

    let export = s.regression_tests().unwrap();
    let t = export.tests.iter().find(|t| t.finding.id == fid).expect("a test").clone();
    assert_eq!(t.auth, ["bob"]);
    // The identity's health check travels with the test, without credentials.
    let check = t.auth_check.clone().expect("the health check");
    assert!(check.request.contains("{{auth:bob}}") && check.request.starts_with("GET /api/me "), "{check:?}");
    assert_eq!(check.expect_contains.as_deref(), Some("bob"));

    let attacker_ex = s.proofs_for_finding(fid).unwrap()[0]["details"]["exchanges"]["attacker"].as_i64().unwrap();
    let valid = cookie_of(&s, attacker_ex);
    assert!(!serde_json::to_string(&t).unwrap().contains(valid.split('=').nth(1).unwrap()), "no secret in the file");
    let good = |k: &str| (k == "PM_AUTH_BOB").then(|| valid.clone());
    let expired = |k: &str| (k == "PM_AUTH_BOB").then(|| "Cookie: session=expired000000".to_string());

    // The bug is there: a valid session shows it, an expired one can't tell.
    assert_eq!(run_regression(&t, None, true, &good).await.outcome, "vulnerable");
    let stale = run_regression(&t, None, true, &expired).await;
    assert_eq!(stale.outcome, "error", "an expired session must not read as fixed: {stale:?}");
    assert!(stale.detail.contains("PM_AUTH_BOB") && stale.detail.contains("not accepted"), "{stale:?}");
    let x = junit(std::slice::from_ref(&stale));
    assert!(x.contains("failures=\"0\" errors=\"1\""), "{x}");

    // A request bob is refused (an invoice that isn't his): fixed, because the
    // check request shows his credentials still work.
    let refused = RegressionTest { request: t.request.replace("/api/orders/1001", "/api/invoices/5001"), ..t.clone() };
    let fixed = run_regression(&refused, None, true, &good).await;
    assert_eq!(fixed.outcome, "fixed", "{fixed:?}");

    // An app that answers 403 to an expired session looks fixed; the check request tells.
    let forbidding = refusing_server().await;
    let stale = run_regression(&t, Some(&forbidding), true, &good).await;
    assert_eq!(stale.outcome, "error", "{stale:?}");
    assert!(stale.detail.contains("no longer work"), "{stale:?}");
    // Without a check request (an identity with no health check), 403 is taken as the fix.
    let unchecked = RegressionTest { auth_check: None, ..t.clone() };
    assert_eq!(run_regression(&unchecked, Some(&forbidding), true, &good).await.outcome, "fixed");
    // A check request of a test's own.
    let own = AuthCheck {
        request: "GET /api/me HTTP/1.1\r\n{{auth:bob}}\r\nHost: x\r\n\r\n".into(),
        expect_status: Some(200),
        expect_contains: None,
    };
    let with_own = RegressionTest { auth_check: Some(own), ..refused };
    assert_eq!(run_regression(&with_own, None, true, &good).await.outcome, "fixed");
}

#[tokio::test]
async fn automatically_proven_findings_run_in_ci_without_credentials_in_the_files() {
    let (s, url) = setup().await;
    // Recorded as alice, the way traffic through the proxy carries her session.
    let cases = [
        ("open_redirect", "/go?url=/home", "Open redirect in GET /go (query url)", "marker"),
        ("crlf", "/api/lang?set=en", "Header injection in GET /api/lang (query set)", "marker"),
        ("path_traversal", "/download?file=menu.txt", "Path traversal in GET /download (query file)", "path_traversal"),
        ("sqli", "/api/reviews?product=1", "SQL injection in GET /api/reviews (query product)", "sql_error"),
        (
            "sqli",
            "/api/products/search?q=Coffee",
            "SQL injection in GET /api/products/search (query q)",
            "boolean_injection",
        ),
    ];
    let mut session = String::new();
    for (class, path, title, _) in cases {
        let ex = get_as(&s, &url, path, "alice").await;
        session = cookie_of(&s, ex);
        let new = NewFinding {
            title: title.into(),
            vuln_class: class.into(),
            severity: "high".into(),
            description: "suspected by the sweep".into(),
            url: None,
            evidence: vec![ex],
            hypothesis_id: None,
        };
        let fid = s.finding_create(&human(), new).unwrap()["id"].as_i64().unwrap();
        let r = s.finding_prove(&human(), fid).await.unwrap();
        assert!(r.proven, "{title}: {:?}", r.reasons);
    }

    let export = s.regression_tests().unwrap();
    assert!(export.skipped.is_empty(), "{:?}", export.skipped);
    let mut kinds: Vec<&str> = export.tests.iter().map(|t| t.oracle.as_str()).collect();
    kinds.sort();
    let mut expected: Vec<&str> = cases.iter().map(|c| c.3).collect();
    expected.sort();
    assert_eq!(kinds, expected);

    // The files (tests and all, as the ZIP holds them) carry no credentials.
    let secret = session.split('=').nth(1).unwrap().trim().to_string();
    assert!(secret.len() >= 8, "{session}");
    let (zip_bytes, _) = s.regression_zip(&human()).unwrap();
    for (name, bytes) in zip::read(&zip_bytes).unwrap() {
        assert!(!String::from_utf8_lossy(&bytes).contains(&secret), "{name} holds alice's session");
    }
    let alice = |k: &str| (k == "PM_AUTH_ALICE").then(|| session.clone());
    let (refusing, failing) = (refusing_server().await, answering("500 Internal Server Error").await);
    for t in &export.tests {
        let what = format!("{} #{}", t.oracle, t.finding.id);
        assert_eq!(t.format, FORMAT_2, "{what}");
        assert_eq!(t.auth, ["alice"], "{what}: the session it was recorded with becomes a placeholder");
        let all = serde_json::to_string(t).unwrap();
        assert!(all.contains("{{auth:alice}}") && !all.to_ascii_lowercase().contains("cookie:"), "{what}: {all}");
        // The file round-trips.
        let t: RegressionTest = serde_json::from_str(&all).unwrap();

        let still = run_regression(&t, None, true, &alice).await;
        assert_eq!(still.outcome, "vulnerable", "{what}: {still:?}");
        let fixed = run_regression(&t, Some(&refusing), true, &alice).await;
        assert_eq!(fixed.outcome, "fixed", "{what}: {fixed:?}");
        let broken = run_regression(&t, Some(&failing), true, &alice).await;
        assert_eq!(broken.outcome, "error", "{what}: a failing server is not a fix: {broken:?}");
        let unset = run_regression(&t, None, true, &|_| None).await;
        assert_eq!(unset.outcome, "skipped", "{what}: {unset:?}");
    }
}
