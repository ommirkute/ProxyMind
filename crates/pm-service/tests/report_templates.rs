//! Findings filled in from the issue library, merged when repeated, retested;
//! reports rendered from built-in and saved templates (and as PDF).

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{FindingUpdate, NewFinding, ReplayRequest, ReplayResult, ReportOptions, ReportTemplate, Service};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn record(s: &Service, url: &str, path: &str) -> i64 {
    let req = ReplayRequest {
        url: Some(url.into()),
        raw: Some(format!("GET {path} HTTP/1.1\r\nHost: shop\r\n\r\n")),
        ..Default::default()
    };
    match s.replay_send(&human(), req).await.unwrap() {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

fn finding(class: &str, url: &str, evidence: Vec<i64>) -> NewFinding {
    NewFinding {
        title: format!("{class} at {url}"),
        vuln_class: class.into(),
        severity: "medium".into(),
        description: "found by hand".into(),
        url: Some(url.into()),
        evidence,
        hypothesis_id: None,
    }
}

#[tokio::test]
async fn library_workflow_and_templates() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nengagement:\n  name: Shop test\nscope:\n  include: [\"{url}/\"]\n");
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();

    // Library details come with the finding; the same issue at the same URL merges.
    let search = record(&s, &url, "/search?q=hello").await;
    let a = s.finding_create(&human(), finding("reflected_input", &format!("{url}/search?q=1"), vec![search])).unwrap();
    assert_eq!(a["issue"]["id"], "xss");
    assert_eq!(a["issue"]["cwe"][0], 79);
    let b = s.finding_create(&human(), finding("XSS", &format!("{url}/search?q=2"), vec![search + 1000])).unwrap();
    assert_eq!(b["id"], a["id"], "merged into the open finding");
    assert_eq!(b["merged"], true);
    assert_eq!(b["duplicates"], 1);
    assert_eq!(s.finding_list(None).unwrap().len(), 1);

    // Retest re-runs the scanner check for the issue type on the scanned request.
    let id = a["id"].as_i64().unwrap();
    let r = s.finding_retest(&human(), id).await.unwrap();
    assert_eq!(r.method, "scan");
    assert_eq!(r.reproduced, Some(true), "{r:?}");
    assert_eq!(s.finding_get(id).unwrap()["retest"]["reproduced"], true);
    let products = record(&s, &url, "/api/products?category=tea").await;
    let c = s.finding_create(&human(), finding("xss", &format!("{url}/api/products"), vec![products])).unwrap();
    let r2 = s.finding_retest(&human(), c["id"].as_i64().unwrap()).await.unwrap();
    assert_ne!(r2.reproduced, Some(true), "{r2:?}");

    // New statuses are for people; a fixed finding takes no more merges.
    let agent = Actor::parse("agent:bot").unwrap();
    let set = |actor: &Actor, id: i64, st: &str| {
        s.finding_update(
            actor,
            FindingUpdate { id, status: Some(st.into()), severity: None, description: None, add_evidence: vec![] },
        )
    };
    assert!(set(&agent, id, "fixed").is_err());
    set(&human(), c["id"].as_i64().unwrap(), "fixed").unwrap();
    set(&human(), id, "accepted_risk").unwrap();
    let again = s.finding_create(&human(), finding("xss", &format!("{url}/api/products"), vec![])).unwrap();
    assert_ne!(again["id"], c["id"], "a fixed finding stays closed");
    s.finding_create(
        &human(),
        NewFinding { severity: "high".into(), ..finding("sql_error", &format!("{url}/api/recommend"), vec![]) },
    )
    .unwrap();

    // Built-in templates.
    let opts = ReportOptions::default();
    let exec = s.report_render(Some("executive"), "md", &opts).await.unwrap();
    let exec = String::from_utf8(exec.body).unwrap();
    assert!(exec.contains("# Shop test: executive summary") && exec.contains("**Overall risk:** high"), "{exec}");
    assert!(exec.contains("SQL injection") && exec.contains("parameterised queries"), "{exec}");
    let comp = String::from_utf8(s.report_render(Some("compliance"), "html", &opts).await.unwrap().body).unwrap();
    assert!(comp.contains("A03:2021 Injection") && comp.contains("CWE-79"), "{comp}");
    let tech = String::from_utf8(s.report_render(None, "html", &opts).await.unwrap().body).unwrap();
    assert!(tech.contains("<h3>Remediation</h3>") && tech.contains("Last retest"), "technical report");
    let json: serde_json::Value =
        serde_json::from_slice(&s.report_render(None, "json", &opts).await.unwrap().body).unwrap();
    assert_eq!(json["risk"], "high");
    assert_eq!(json["severity_counts"][1]["count"], 1);
    let only_high = ReportOptions { min_severity: Some("high".into()), ..Default::default() };
    let filtered: serde_json::Value =
        serde_json::from_slice(&s.report_render(None, "json", &only_high).await.unwrap().body).unwrap();
    assert_eq!(filtered["findings"].as_array().unwrap().len(), 1);

    // Saved templates: checked on save, for people only.
    let t = ReportTemplate {
        name: "one-liner".into(),
        format: "md".into(),
        body: "{{ r.title }}: {% for f in r.findings %}[{{ f.severity }}] {{ f.title }}; {% endfor %}".into(),
        ..Default::default()
    };
    assert!(s.report_template_save(&agent, t.clone()).is_err());
    assert!(s.report_template_save(&human(), ReportTemplate { body: "{% if %}".into(), ..t.clone() }).is_err());
    assert!(s.report_template_save(&human(), ReportTemplate { name: "executive".into(), ..t.clone() }).is_err());
    s.report_template_save(&human(), t).unwrap();
    let mine = String::from_utf8(s.report_render(Some("one-liner"), "md", &opts).await.unwrap().body).unwrap();
    assert!(mine.starts_with("Shop test: [high]"), "{mine}");
    assert!(s.report_render(Some("one-liner"), "html", &opts).await.is_err(), "no HTML version");
    assert!(s.report_template_delete(&human(), "one-liner").unwrap());

    // PDF, where a browser is installed.
    if pm_service::pm_browser::find_chromium().is_some() {
        let pdf = s.report_render(Some("executive"), "pdf", &opts).await.unwrap();
        assert!(pdf.body.starts_with(b"%PDF"), "a PDF");
        assert!(pdf.body.len() > 1000);
    }
}
