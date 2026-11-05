//! Race testing against VulnShop's gift card (VS-5).

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{RaceModeChoice, RaceRequest, RaceResult, Service};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn login(shop: u16, user: &str) -> String {
    let body = format!(r#"{{"username":"{user}","password":"{user}123"}}"#);
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", shop)).await.unwrap();
    let req = format!(
        "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    resp.split("\"token\":\"").nth(1).unwrap().split('"').next().unwrap().to_string()
}

fn service(shop: u16) -> Service {
    let roe = format!(
        "version: 1\nscope:\n  include: [\"http://127.0.0.1:{shop}/\"]\nlimits:\n  max_rps_per_host: 5\n  max_concurrency: 2\n"
    );
    Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap()
}

fn redeem(shop: u16, token: &str) -> String {
    let body = r#"{"code":"WELCOME10"}"#;
    format!(
        "POST /api/giftcard/redeem HTTP/1.1\r\nHost: 127.0.0.1:{shop}\r\nAuthorization: Bearer {token}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[tokio::test]
async fn a_race_redeems_a_one_time_gift_card_several_times() {
    let shop = pm_demo::VulnShop::start_local().await.unwrap().port();
    let svc = service(shop);
    let me = Actor::parse("human:tester").unwrap();
    let token = login(shop, "alice").await;
    let r = svc
        .race_send(
            &me,
            RaceRequest {
                url: Some(format!("http://127.0.0.1:{shop}")),
                raw: Some(redeem(shop, &token)),
                count: Some(8),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let RaceResult::Done { mode, count, successes, groups, exchange_ids, .. } = r else { panic!("{r:?}") };
    assert_eq!((count, exchange_ids.len()), (8, 8));
    assert_eq!(serde_json::to_value(mode).unwrap(), "last_byte", "VulnShop speaks HTTP/1.1 only");
    assert!(successes > 1, "the race condition shows: {successes} redemptions ({groups:?})");
    assert!(groups.iter().map(|g| g.count).sum::<usize>() == 8);
    let ex = svc.exchange_raw(exchange_ids[0]).unwrap();
    assert_eq!(ex.summary.source, "race");

    // Sent one at a time, only the first succeeds.
    let bob = login(shop, "bob").await;
    let mut ok = 0;
    for _ in 0..3 {
        let r = svc
            .replay_send(
                &me,
                pm_service::ReplayRequest {
                    url: Some(format!("http://127.0.0.1:{shop}")),
                    raw: Some(redeem(shop, &bob)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        if let pm_service::ReplayResult::Sent { view, .. } = r
            && serde_json::to_string(&view).unwrap().contains("\"status\":200")
        {
            ok += 1;
        }
    }
    assert_eq!(ok, 1, "without a race the card works once");
}

#[tokio::test]
async fn agents_need_approval_and_counts_are_bounded() {
    let shop = pm_demo::VulnShop::start_local().await.unwrap().port();
    let svc = service(shop);
    let agent = Actor::parse("agent:claude").unwrap();
    let req = RaceRequest {
        url: Some(format!("http://127.0.0.1:{shop}")),
        raw: Some(format!("GET /api/products HTTP/1.1\r\nHost: 127.0.0.1:{shop}\r\n\r\n")),
        count: Some(5),
        mode: RaceModeChoice::LastByte,
        ..Default::default()
    };
    // Even a GET race is active-intrusive: the default ROE asks a human.
    let r = svc.race_send(&agent, req.clone()).await.unwrap();
    let RaceResult::PendingApproval { summary, .. } = r else { panic!("{r:?}") };
    assert!(summary.starts_with("race ×5"), "{summary}");
    let me = Actor::parse("human:tester").unwrap();
    for bad in [0, 1, 51] {
        assert!(svc.race_send(&me, RaceRequest { count: Some(bad), ..req.clone() }).await.is_err());
    }
}

fn item(shop: u16, raw: String, name: &str) -> pm_service::GroupItem {
    pm_service::GroupItem {
        url: Some(format!("http://127.0.0.1:{shop}")),
        raw: Some(raw),
        name: Some(name.into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn groups_send_different_requests_in_sequence_or_together() {
    use pm_service::{GroupMode, GroupRequest, GroupResult};
    let shop = pm_demo::VulnShop::start_local().await.unwrap().port();
    let svc = service(shop);
    let me = Actor::parse("human:tester").unwrap();
    let me_req =
        |t: &str| format!("GET /api/me HTTP/1.1\r\nHost: 127.0.0.1:{shop}\r\nAuthorization: Bearer {t}\r\n\r\n");

    // In sequence, the second redemption sees the first: 200 then 409, and the profile last.
    let alice = login(shop, "alice").await;
    let r = svc
        .replay_group(
            &me,
            GroupRequest {
                requests: vec![
                    item(shop, redeem(shop, &alice), "first"),
                    item(shop, redeem(shop, &alice), "second"),
                    item(shop, me_req(&alice), "me"),
                ],
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let GroupResult::Done { mode, results, .. } = r else { panic!("{r:?}") };
    assert_eq!(mode, GroupMode::Sequence);
    let statuses: Vec<_> = results.iter().map(|x| x.status).collect();
    assert_eq!(statuses, vec![Some(200), Some(409), Some(200)]);
    assert_eq!(results[2].name.as_deref(), Some("me"));
    assert!(results.iter().all(|x| x.exchange_id.is_some()));

    // In parallel, different requests to the gift card race each other.
    let bob = login(shop, "bob").await;
    let tagged = |n: u8| redeem(shop, &bob).replacen("Content-Type", &format!("X-Try: {n}\r\nContent-Type"), 1);
    let r = svc
        .replay_group(
            &me,
            GroupRequest {
                requests: (1..=4).map(|n| item(shop, tagged(n), &format!("try {n}"))).collect(),
                mode: GroupMode::Parallel,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let GroupResult::Done { results, parallel, .. } = r else { panic!("{r:?}") };
    assert_eq!(serde_json::to_value(parallel).unwrap(), "last_byte");
    let wins = results.iter().filter(|x| x.status == Some(200)).count();
    assert!(wins > 1, "sent together, more than one redemption succeeds: {results:?}");
    let ex = svc.exchange_raw(results[2].exchange_id.unwrap()).unwrap();
    assert!(String::from_utf8_lossy(&ex.request).contains("X-Try: 3"), "each request is sent as written");

    // A group stays on one server.
    let dead = pm_service::GroupItem {
        url: Some("http://127.0.0.1:1".into()),
        raw: Some("GET / HTTP/1.1\r\nHost: x\r\n\r\n".into()),
        ..Default::default()
    };
    let err = svc
        .replay_group(&me, GroupRequest { requests: vec![dead, item(shop, me_req(&bob), "me")], ..Default::default() })
        .await;
    assert!(err.is_err() || matches!(err, Ok(GroupResult::Denied { .. })), "another server: {err:?}");

    // Limits: one request is not a group; agents need approval for a parallel group.
    let one = GroupRequest { requests: vec![item(shop, me_req(&bob), "me")], ..Default::default() };
    assert!(svc.replay_group(&me, one).await.is_err());
    let agent = Actor::parse("agent:claude").unwrap();
    let r = svc
        .replay_group(
            &agent,
            GroupRequest {
                requests: vec![item(shop, me_req(&bob), "a"), item(shop, me_req(&bob), "b")],
                mode: GroupMode::Parallel,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(r, GroupResult::PendingApproval { .. }), "{r:?}");
}
