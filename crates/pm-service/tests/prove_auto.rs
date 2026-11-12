//! The automatic prove step against VulnShop: suspected findings from the
//! sweep become proven with the oracle that fits their class, and traps do not.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{NewFinding, ReplayRequest, ReplayResult, Service};

fn human() -> Actor {
    Actor::parse("human:omkar").unwrap()
}

async fn setup() -> (Arc<Service>, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    // Allow the destructive tier without asking, as the bench rules do, so the
    // human actor's payload sends run straight through.
    let roe = format!(
        "version: 1\nscope:\n  include: [\"{url}/\"]\ntiers:\n  human:\n    active_intrusive: allow\n    destructive: allow\n"
    );
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    (s, url)
}

async fn record(s: &Service, url: &str, path: &str) -> i64 {
    let r = s
        .replay_send(
            &human(),
            ReplayRequest {
                url: Some(url.into()),
                raw: Some(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")),
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

async fn suspect(s: &Service, class: &str, title: &str, evidence: i64) -> i64 {
    s.finding_create(
        &human(),
        NewFinding {
            title: title.into(),
            vuln_class: class.into(),
            severity: "high".into(),
            description: "suspected by the sweep".into(),
            url: None,
            evidence: vec![evidence],
            hypothesis_id: None,
        },
    )
    .unwrap()["id"]
        .as_i64()
        .unwrap()
}

#[tokio::test]
async fn proves_open_redirect_sqli_and_path_traversal_and_rejects_traps() {
    let (s, url) = setup().await;

    // VS-8 open redirect: /go reflects url into Location; /out only same-site.
    let go = record(&s, &url, "/go?url=/home").await;
    let go_f = suspect(&s, "open_redirect", "Open redirect in GET /go (query url)", go).await;
    let r = s.finding_prove(&human(), go_f).await.unwrap();
    assert!(r.proven, "open redirect: {:?}", r.reasons);
    assert_eq!(r.oracle.as_deref(), Some("marker"));
    assert_eq!(s.finding_get(go_f).unwrap()["status"], "proven");

    let out = record(&s, &url, "/out?url=/home").await;
    let out_f = suspect(&s, "open_redirect", "Open redirect in GET /out (query url)", out).await;
    assert!(!s.finding_prove(&human(), out_f).await.unwrap().proven, "/out only allows same-site paths");

    // VS-9 path traversal: /download joins ../ unsafely; /docs uses the base name.
    let dl = record(&s, &url, "/download?file=menu.txt").await;
    let dl_f = suspect(&s, "path_traversal", "Path traversal in GET /download (query file)", dl).await;
    let r = s.finding_prove(&human(), dl_f).await.unwrap();
    assert!(r.proven, "path traversal: {:?}", r.reasons);
    assert_eq!(r.oracle.as_deref(), Some("path_traversal"));

    let docs = record(&s, &url, "/docs?file=menu.txt").await;
    let docs_f = suspect(&s, "path_traversal", "Path traversal in GET /docs (query file)", docs).await;
    assert!(!s.finding_prove(&human(), docs_f).await.unwrap().proven, "/docs strips the path");

    // VS-3 blind SQLi: boolean conditions change the result set.
    let q = record(&s, &url, "/api/products/search?q=Coffee").await;
    let q_f = suspect(&s, "sqli", "SQL injection in GET /api/products/search (query q)", q).await;
    let r = s.finding_prove(&human(), q_f).await.unwrap();
    assert!(r.proven, "sqli: {:?}", r.reasons);
    assert!(matches!(r.oracle.as_deref(), Some("boolean_injection") | Some("timing")), "{:?}", r.oracle);

    // VS-7 error-based SQLi: a quote triggers a DB error, a benign value does not.
    let rev = record(&s, &url, "/api/reviews?product=1").await;
    let rev_f = suspect(&s, "sqli", "SQL injection in GET /api/reviews (query product)", rev).await;
    let r = s.finding_prove(&human(), rev_f).await.unwrap();
    assert!(r.proven, "error-based sqli: {:?}", r.reasons);
    assert_eq!(r.oracle.as_deref(), Some("sql_error"));

    // A non-injectable endpoint: the same class claim does not prove.
    let plain = record(&s, &url, "/api/products").await;
    let plain_f = suspect(&s, "sqli", "SQL injection in GET /api/products (query q)", plain).await;
    assert!(!s.finding_prove(&human(), plain_f).await.unwrap().proven, "no parameter, no proof");

    // Every proof is stored and linked to its finding.
    for fid in [go_f, dl_f, q_f] {
        let proofs = s.proofs_for_finding(fid).unwrap();
        assert!(proofs.iter().any(|p| p["proven"] == true), "finding {fid} has a proven proof");
    }
}

#[tokio::test]
async fn auto_prove_sweeps_suspected_findings() {
    let (s, url) = setup().await;
    let go = record(&s, &url, "/go?url=/home").await;
    suspect(&s, "open_redirect", "Open redirect in GET /go (query url)", go).await;
    let q = record(&s, &url, "/api/products/search?q=Coffee").await;
    suspect(&s, "sqli", "SQL injection in GET /api/products/search (query q)", q).await;

    let sweep = s.auto_prove(&human()).await.unwrap();
    assert!(sweep.attempted >= 2, "{sweep:?}");
    assert!(sweep.proven >= 2, "{sweep:?}");
    // Proven findings are no longer suspected.
    assert!(s.finding_list(Some("suspected")).unwrap().is_empty(), "all suspected findings were proven");
}
