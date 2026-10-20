//! Decoder, Comparer and Sequencer through the service.

use pm_demo::VulnShop;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{DecodeRequest, ReplayRequest, ReplayResult, SequencerRequest, SequencerResult, Service};

async fn setup() -> (Service, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    (Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap(), url)
}

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

async fn send(s: &Service, url: &str, raw: &str) -> i64 {
    match s
        .replay_send(&human(), ReplayRequest { url: Some(url.into()), raw: Some(raw.into()), ..Default::default() })
        .await
        .unwrap()
    {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn sequencer_finds_the_counter_and_hides_tokens() {
    let (s, url) = setup().await;
    let reset = send(&s, &url, "POST /api/password/reset HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n").await;
    let req = SequencerRequest {
        exchange_id: reset,
        locator: "json:/debug_code".into(),
        samples: Some(20),
        ..Default::default()
    };
    // POSTs repeated many times are intrusive: agents need approval.
    let agent = Actor::parse("agent:test").unwrap();
    assert!(matches!(s.sequencer_run(&agent, req.clone()).await.unwrap(), SequencerResult::PendingApproval { .. }));
    let SequencerResult::Done { found, analysis, .. } = s.sequencer_run(&human(), req).await.unwrap() else { panic!() };
    assert_eq!(found, 20);
    assert_eq!((analysis.rating, analysis.sequential_step), ("poor", Some(1)));
    let json = serde_json::to_string(&analysis).unwrap();
    assert!(!json.contains("400"), "statistics only, no tokens: {json}");

    let bad =
        SequencerRequest { exchange_id: reset, locator: "cookie:nope".into(), samples: Some(10), ..Default::default() };
    assert!(s.sequencer_run(&human(), bad).await.is_err(), "token not found");
    assert!(
        s.sequencer_run(&human(), SequencerRequest { exchange_id: reset, locator: "x".into(), ..Default::default() })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn compare_and_decode() {
    let (s, url) = setup().await;
    let a = send(&s, &url, "GET /api/products/search?q=Coffee HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let b = send(&s, &url, "GET /api/products/search?q=Tea HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let c = s.compare_exchanges(&human(), a, b).unwrap();
    assert_eq!(c["request_lines"]["added"], 1);
    assert_eq!(c["request_lines"]["removed"], 1);
    assert!(c["response_semantic"]["similarity"].as_f64().unwrap() < 1.0);
    assert!(s.compare_exchanges(&human(), a, 999).is_err());

    let d = s.decode(&DecodeRequest { input: "JTNDc2NyaXB0JTNF".into(), ops: vec![] }).unwrap();
    assert_eq!(d["steps"].as_array().unwrap().last().unwrap()["output"], "<script>");
    let d = s
        .decode(&DecodeRequest { input: "a b".into(), ops: vec!["url_encode".into(), "base64_encode".into()] })
        .unwrap();
    assert_eq!(d["steps"][1]["output"], "YSUyMGI=");
    assert!(s.decode(&DecodeRequest { input: "x".into(), ops: vec!["nope".into()] }).is_err());
    assert_eq!(s.sequencer_analyze(&["1".into(), "2".into(), "3".into()]).unwrap().sequential_step, Some(1));
}
