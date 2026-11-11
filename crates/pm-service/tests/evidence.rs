//! Evidence packs: exported, verified, and caught when tampered with; the
//! coverage proof credits who tested what.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::pm_tools::zip;
use pm_service::{ActiveScanRequest, NewFinding, ReplayRequest, ReplayResult, Service, verify_evidence};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn engagement() -> (Service, String, std::path::PathBuf) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let home = std::env::temp_dir().join(format!("pm-evidence-{}-{}", std::process::id(), addr.port()));
    let _ = std::fs::remove_dir_all(&home);
    s.attach_plugin_home(home.clone());
    s.roe_set(&human(), &roe).unwrap();
    (s, url, home)
}

async fn send(s: &Service, url: &str, path: &str) -> i64 {
    let req = ReplayRequest {
        url: Some(url.into()),
        raw: Some(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")),
        ..Default::default()
    };
    match s.replay_send(&human(), req).await.unwrap() {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

fn rewrite(pack: &[u8], f: impl Fn(&str, &mut Vec<u8>) -> bool) -> Vec<u8> {
    let entries: Vec<(String, Vec<u8>)> =
        zip::read(pack).unwrap().into_iter().filter_map(|(n, mut d)| f(&n, &mut d).then_some((n, d))).collect();
    zip::write(&entries).unwrap()
}

fn failed(v: &pm_service::EvidenceVerification) -> Vec<&str> {
    v.checks.iter().filter(|c| !c.ok).map(|c| c.name.as_str()).collect()
}

#[tokio::test]
async fn a_pack_verifies_and_tampering_is_caught() {
    let (s, url, home) = engagement().await;
    let ex = send(&s, &url, "/search?q=shoes").await;
    send(&s, &url, "/search?q=boots").await;
    s.finding_create(
        &human(),
        NewFinding {
            title: "Reflected XSS in search".into(),
            vuln_class: "reflected_xss".into(),
            severity: "medium".into(),
            description: "q is reflected unencoded.".into(),
            url: None,
            evidence: vec![ex],
            hypothesis_id: None,
        },
    )
    .unwrap();
    let agent = Actor::parse("agent:claude").unwrap();
    assert!(s.evidence_pack(&agent, false).is_err(), "people only");
    let (pack, fp) = s.evidence_pack(&human(), false).unwrap();
    assert_eq!(fp, s.evidence_fingerprint().unwrap(), "the same key signs every pack");

    let v = verify_evidence(&pack);
    assert!(v.ok, "{:#?}", v.checks);
    assert_eq!(v.fingerprint.as_deref(), Some(fp.as_str()));
    assert_eq!(v.findings, 1);
    let names: Vec<String> = zip::read(&pack).unwrap().into_iter().map(|(n, _)| n).collect();
    for want in ["report.html", "audit.jsonl", "roe.yaml", "coverage.json", &format!("exchanges/{ex}.request.http")] {
        assert!(names.iter().any(|n| n == want), "{want} in {names:?}");
    }

    // A changed file: the hashes don't match (the signature still does).
    let edited = rewrite(&pack, |n, d| {
        if n == "report.html" {
            d.extend_from_slice(b"<!-- edited -->");
        }
        true
    });
    assert_eq!(failed(&verify_evidence(&edited)), ["files"]);
    // A changed manifest: the signature fails.
    let forged = rewrite(&pack, |n, d| {
        if n == "manifest.json" {
            *d = String::from_utf8_lossy(d).replace("\"findings\": 1", "\"findings\": 0").into_bytes();
        }
        true
    });
    assert!(failed(&verify_evidence(&forged)).contains(&"signature"));
    // A removed evidence exchange.
    let gutted = rewrite(&pack, |n, _| !n.starts_with(&format!("exchanges/{ex}.")));
    let gv = verify_evidence(&gutted);
    let f = failed(&gv);
    assert!(f.contains(&"files") && f.contains(&"evidence"), "{f:?}");
    // An edited audit record breaks the chain.
    let rewritten = rewrite(&pack, |n, d| {
        if n == "audit.jsonl" {
            *d = String::from_utf8_lossy(d).replacen("\"allow\"", "\"deny\"", 1).into_bytes();
        }
        true
    });
    assert!(failed(&verify_evidence(&rewritten)).contains(&"audit log"));
    let _ = std::fs::remove_dir_all(home);
}

#[tokio::test]
async fn requests_outside_the_final_scope_are_reported() {
    let (s, url, home) = engagement().await;
    send(&s, &url, "/search?q=shoes").await;
    // The rules narrow after the request was sent.
    let narrower = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n  exclude: [\"{url}/search\"]\n");
    s.roe_set(&human(), &narrower).unwrap();
    let (pack, _) = s.evidence_pack(&human(), false).unwrap();
    let v = verify_evidence(&pack);
    let scope = v.checks.iter().find(|c| c.name == "scope").unwrap();
    assert!(!scope.ok, "{scope:?}");
    assert!(scope.detail.contains("/search") && scope.detail.contains("rules changed"), "{}", scope.detail);
    let _ = std::fs::remove_dir_all(home);
}

#[tokio::test]
async fn coverage_credits_scans_and_findings() {
    let (s, url, home) = engagement().await;
    let ex = send(&s, &url, "/search?q=shoes").await;
    send(&s, &url, "/search?q=boots").await;
    let req = ActiveScanRequest {
        exchange_id: ex,
        checks: vec!["sql_error".into()],
        max_requests: Some(30),
        ..Default::default()
    };
    s.scan_active(&human(), req).await.unwrap();
    s.finding_create(
        &human(),
        NewFinding {
            title: "XSS".into(),
            vuln_class: "reflected_xss".into(),
            severity: "medium".into(),
            description: "x".into(),
            url: Some(format!("{url}/search?q=x")),
            evidence: vec![ex],
            hypothesis_id: None,
        },
    )
    .unwrap();
    let c = s.coverage_proof().unwrap();
    let search: Vec<_> = c.cells.iter().filter(|x| x.operation.contains("/search")).collect();
    let sqli = search.iter().find(|x| x.vuln_class == "sqli").unwrap_or_else(|| panic!("{search:#?}"));
    assert_eq!(sqli.status, "tested", "{sqli:?}");
    assert_eq!(sqli.by, ["human:tester"]);
    assert!(sqli.how.iter().any(|h| h.contains("sql_error")), "{sqli:?}");
    let xss = search.iter().find(|x| x.vuln_class == "xss").unwrap_or_else(|| panic!("{search:#?}"));
    assert_eq!(xss.status, "vulnerable");
    assert_eq!(xss.findings.len(), 1);
    assert!(c.percent_tested > 0.0);
    assert_eq!(c.totals.values().sum::<usize>(), c.cells.len());
    let _ = std::fs::remove_dir_all(home);
}
