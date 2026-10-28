//! Fuzzer against VulnShop, through the policy gate.

use std::sync::Arc;

use pm_demo::VulnShop;
use pm_service::pm_fuzz::{Mode, PayloadSet};
use pm_service::pm_identity::{AuthMaterial, Identity, LoginRecipe, LoginStep};
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{FuzzerRequest, FuzzerResult, Service};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn setup() -> (Arc<Service>, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    s.identity_set(
        &human(),
        Identity {
            name: "bob".into(),
            role: "user".into(),
            auth: AuthMaterial::default(),
            health: None,
            logged_out: None,
            login: Some(LoginRecipe {
                steps: vec![LoginStep {
                    url: url.clone(),
                    request: "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n\
                              {\"username\":\"bob\",\"password\":\"bob123\"}"
                        .into(),
                    token_json_pointer: None,
                    token_header: None,
                    token_prefix: None,
                    ..Default::default()
                }],
            }),
        },
    )
    .unwrap();
    s.identity_login("bob").await.unwrap();
    (s, url)
}

fn list(xs: &[&str]) -> PayloadSet {
    PayloadSet {
        list: xs.iter().map(|s| s.to_string()).collect(),
        numbers: None,
        builtin: None,
        url_encode: false,
        ..Default::default()
    }
}

#[tokio::test]
async fn fuzzes_ids_as_an_identity_and_points_out_anomalies() {
    let (s, url) = setup().await;
    let req = FuzzerRequest {
        url: Some(url.clone()),
        raw: "GET /api/orders/§2001§ HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        payload_sets: vec![list(&["1001", "1002", "9999"])],
        grep: vec!["alice@".into()],
        identity: Some("bob".into()),
        ..Default::default()
    };
    // Agents need approval: fuzzing is intrusive.
    let agent = Actor::parse("agent:test").unwrap();
    let r = s.fuzzer_run(&agent, req.clone()).await.unwrap();
    let FuzzerResult::PendingApproval { approval_id, summary, .. } = r else { panic!("{r:?}") };
    assert!(summary.starts_with("fuzzer (one at a time, 3 requests)"), "{summary}");
    // Changing the payloads invalidates the approval: it covers the whole attack.
    let changed = FuzzerRequest {
        payload_sets: vec![list(&["1001", "1002", "1003"])],
        approval_id: Some(approval_id.clone()),
        ..req.clone()
    };
    assert!(s.fuzzer_run(&agent, changed).await.is_err());

    let r = s.fuzzer_run(&human(), req).await.unwrap();
    let FuzzerResult::Done { baseline, results, anomalies } = r else { panic!("{r:?}") };
    assert_eq!(baseline.status, Some(200), "bob's own order");
    let statuses: Vec<_> = results.iter().map(|r| r.status).collect();
    assert_eq!(statuses, vec![Some(200), Some(200), Some(404)], "VS-1: bob reads alice's orders");
    assert_eq!(results[0].payloads, vec![Some("1001".to_string())]);
    assert_eq!(results[0].matches, vec!["alice@".to_string()]);
    let flagged: Vec<usize> = anomalies.iter().map(|a| a.index).collect();
    assert_eq!(flagged, vec![0, 1, 2], "{anomalies:?}");
    assert!(anomalies[2].reasons[0].contains("404 differs from the baseline's 200"));
    // Every request is in history, attributed to the actor.
    let ex = s.exchange_raw_request(&human(), results[2].exchange_id).unwrap();
    assert!(ex.starts_with("GET /api/orders/9999 "));
}

#[tokio::test]
async fn reflection_and_bad_attacks() {
    let (s, url) = setup().await;
    let r = s
        .fuzzer_run(
            &human(),
            FuzzerRequest {
                url: Some(url.clone()),
                raw: "GET /search?q=§hello§ HTTP/1.1\r\nHost: x\r\n\r\n".into(),
                payload_sets: vec![PayloadSet { builtin: Some("xss".into()), url_encode: true, ..list(&[]) }],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let FuzzerResult::Done { results, .. } = r else { panic!("{r:?}") };
    assert!(results.iter().all(|r| r.reflected), "VS-6 reflects every payload");

    let bad = |raw: &str, sets: Vec<PayloadSet>, mode: Mode| FuzzerRequest {
        url: Some(url.clone()),
        raw: raw.into(),
        payload_sets: sets,
        mode,
        ..Default::default()
    };
    for r in [
        bad("GET / HTTP/1.1\r\n\r\n", vec![list(&["a"])], Mode::OneAtATime),
        bad("GET /§a§/§b§ HTTP/1.1\r\n\r\n", vec![list(&["a"])], Mode::Paired),
        bad("GET /§a§ HTTP/1.1\r\n\r\n", vec![list(&[])], Mode::OneAtATime),
    ] {
        assert!(s.fuzzer_run(&human(), r).await.is_err());
    }
}

async fn wait_done(s: &Service, id: &str) -> pm_service::AttackView {
    for _ in 0..300 {
        let v = s.fuzzer_status(&human(), id, 0).unwrap();
        if !matches!(v.status, pm_service::AttackStatus::Running | pm_service::AttackStatus::Paused) {
            return v;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("attack {id} didn't finish");
}

#[tokio::test]
async fn background_attacks_with_extract_and_concurrency() {
    let (s, url) = setup().await;
    let req = FuzzerRequest {
        url: Some(url.clone()),
        raw: "GET /api/orders/§1001§ HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        payload_sets: vec![PayloadSet { numbers: Some("1001-1004".into()), ..Default::default() }],
        identity: Some("bob".into()),
        grep: vec!["\"owner\":\"ali\\w+\"".into()],
        grep_regex: true,
        extract: vec![pm_service::pm_fuzz::Extract { regex: Some(r#""owner":"(\w+)""#.into()), ..Default::default() }],
        concurrency: Some(3),
        ..Default::default()
    };
    let pm_service::FuzzerStart::Started { attack_id, total } = s.fuzzer_start(&human(), req).unwrap() else {
        panic!("not started")
    };
    assert_eq!(total, 4);
    let v = wait_done(&s, &attack_id).await;
    assert_eq!((v.status, v.done, v.total), (pm_service::AttackStatus::Done, 4, 4));
    let mut rows = v.rows.clone();
    rows.sort_by_key(|r| r.index);
    let owners: Vec<Option<String>> = rows.iter().map(|r| r.extracted[0].clone()).collect();
    assert_eq!(owners[0].as_deref(), Some("alice"), "{owners:?}");
    assert!(rows[0].matches.len() == 1 && rows[3].matches.is_empty());
    assert_eq!(v.extract_columns.len(), 1);
    // Polling from an offset returns only newer rows; the list shows the attack.
    assert!(s.fuzzer_status(&human(), &attack_id, 4).unwrap().rows.is_empty());
    assert_eq!(s.fuzzer_list(&human())[0].attack_id, attack_id);
    // Agents can't see other actors' attacks.
    assert!(s.fuzzer_status(&Actor::parse("agent:other").unwrap(), &attack_id, 0).is_err());
}

#[tokio::test]
async fn attacks_pause_resume_and_cancel() {
    let (s, url) = setup().await;
    let req = FuzzerRequest {
        url: Some(url.clone()),
        raw: "GET /api/products?x=§a§ HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        payload_sets: vec![PayloadSet { null_payloads: Some(200), ..Default::default() }],
        throttle_ms: Some(20),
        ..Default::default()
    };
    let pm_service::FuzzerStart::Started { attack_id, .. } = s.fuzzer_start(&human(), req).unwrap() else {
        panic!("not started")
    };
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(s.fuzzer_control(&human(), &attack_id, "pause").unwrap(), pm_service::AttackStatus::Paused);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let a = s.fuzzer_status(&human(), &attack_id, 0).unwrap().done;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let b = s.fuzzer_status(&human(), &attack_id, 0).unwrap().done;
    assert!(b <= a + 1, "paused: {a} → {b}");
    s.fuzzer_control(&human(), &attack_id, "resume").unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(s.fuzzer_control(&human(), &attack_id, "cancel").unwrap(), pm_service::AttackStatus::Cancelled);
    let v = wait_done(&s, &attack_id).await;
    assert_eq!(v.status, pm_service::AttackStatus::Cancelled);
    assert!(v.done > b && v.done < 200, "{} of 200", v.done);
    assert!(s.fuzzer_control(&human(), &attack_id, "fly").is_ok(), "finished attacks ignore controls");
}

#[tokio::test]
async fn payloads_cannot_walk_out_of_scope() {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/api/\"]\n  exclude: [\"{url}/api/admin/\"]\n");
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    let r = s
        .fuzzer_run(
            &human(),
            FuzzerRequest {
                url: Some(url.clone()),
                raw: "GET /api/products/§1§ HTTP/1.1\r\nHost: x\r\n\r\n".into(),
                payload_sets: vec![list(&["2", "../admin/users", "../../search?q=x"])],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let FuzzerResult::Done { results, .. } = r else { panic!("{r:?}") };
    assert!(results[0].status.is_some(), "in scope: sent");
    for row in &results[1..] {
        assert_eq!(row.status, None, "{row:?}");
        let ex = s.exchange_raw(row.exchange_id).unwrap();
        assert!(ex.response.is_none(), "never sent");
        assert!(ex.summary.error.as_deref().unwrap_or_default().contains("out of scope"), "{:?}", ex.summary.error);
    }
}
