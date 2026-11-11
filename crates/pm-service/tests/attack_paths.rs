//! Attack paths: recorded chains, merged into one graph, in the report;
//! business-logic candidates from recorded traffic.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{AttackStep, EngageFilter, NewAttackPath, NewFinding, ReplayRequest, Service};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

fn agent() -> Actor {
    Actor::parse("agent:claude").unwrap()
}

fn step(text: &str, finding_id: Option<i64>) -> AttackStep {
    AttackStep { text: text.into(), finding_id, exchange_id: None }
}

fn path(title: &str, steps: Vec<AttackStep>) -> NewAttackPath {
    NewAttackPath { title: title.into(), impact: "read every order".into(), severity: "high".into(), steps }
}

fn service(scope: &str) -> Service {
    let roe = format!("version: 1\nscope:\n  include: [\"{scope}\"]\n");
    Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap()
}

#[test]
fn paths_merge_into_a_graph_and_appear_in_the_report() {
    let s = service("http://shop.test/");
    let f = s
        .finding_create(
            &agent(),
            NewFinding {
                title: "API key in app.js".into(),
                vuln_class: "exposure".into(),
                severity: "medium".into(),
                description: "A key in the script.".into(),
                url: Some("http://shop.test/static/app.js".into()),
                evidence: vec![],
                hypothesis_id: None,
            },
        )
        .unwrap();
    let fid = f["id"].as_i64().unwrap();
    let a = s
        .attack_path_create(
            &agent(),
            path("Key to orders", vec![step("API key in app.js", Some(fid)), step("Admin API accepts it", None)]),
        )
        .unwrap();
    assert_eq!(a.scan_id, None);
    s.attack_path_create(
        &agent(),
        path(
            "Key to users",
            vec![step("the key", Some(fid)), step("admin   API accepts it", None), step("List users", None)],
        ),
    )
    .unwrap();

    let g = s.attack_graph(None).unwrap();
    assert_eq!(g.nodes.len(), 3, "the finding and the same text are one node each: {:?}", g.nodes);
    let entry = g.nodes.iter().find(|n| n.finding_id == Some(fid)).unwrap();
    assert_eq!((entry.depth, entry.severity.as_deref(), entry.impact), (0, Some("medium"), false));
    let shared = g.edges.iter().find(|e| e.from == format!("finding:{fid}")).unwrap();
    assert_eq!(shared.paths.len(), 2, "both paths take the first edge");
    assert!(g.nodes.iter().any(|n| n.label == "List users" && n.impact));

    let md = s.report_markdown().unwrap();
    assert!(md.contains("## Attack paths") && md.contains("### Key to orders (high)"), "{md}");
    assert!(md.contains(&format!("1. API key in app.js (finding #{fid})")));

    // Bad input is refused; only people delete.
    for bad in [
        path("one step", vec![step("x", None)]),
        path("ghost finding", vec![step("x", Some(999)), step("y", None)]),
        NewAttackPath { severity: "huge".into(), ..path("sev", vec![step("x", None), step("y", None)]) },
    ] {
        assert!(s.attack_path_create(&agent(), bad).is_err());
    }
    assert!(s.attack_path_delete(&agent(), a.id).is_err());
    s.attack_path_delete(&human(), a.id).unwrap();
    assert_eq!(s.attack_path_list(None).unwrap().len(), 1);
}

#[tokio::test]
async fn logic_candidates_come_from_recorded_parameters() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let s = service(&format!("{url}/"));
    for raw in [
        "POST /api/cart?qty=2&unit_price=10 HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        "POST /api/checkout?coupon=WELCOME HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        "GET /search?q=shoes HTTP/1.1\r\nHost: x\r\n\r\n",
    ] {
        let req = ReplayRequest { url: Some(url.clone()), raw: Some(raw.into()), ..Default::default() };
        s.replay_send(&human(), req).await.unwrap();
    }
    let r = s.engage_logic(&human(), &EngageFilter::default()).unwrap();
    let got: Vec<(&str, &str)> = r.candidates.iter().map(|c| (c.param.as_str(), c.category)).collect();
    assert_eq!(got, [("unit_price", "price"), ("qty", "quantity"), ("coupon", "discount")]);
    assert!(r.flow_paths.iter().any(|p| p.starts_with("/api/cart")), "{:?}", r.flow_paths);
    assert!(r.flow_paths.iter().any(|p| p.starts_with("/api/checkout")), "{:?}", r.flow_paths);
}
