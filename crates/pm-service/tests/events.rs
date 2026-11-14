//! ADR-0018 steps 1 and 4: the event bus, as the service layer publishes it.

use std::sync::Arc;

use futures_util::FutureExt;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_proxy::Recorder;
use pm_service::pm_store::{NewExchange, NewWsMessage, Store, WsTarget};
use pm_service::{Delivery, Event, NewFinding, Published, Service, Subscription, Topic};

const ROE: &str = "version: 1\nscope:\n  include: [\"https://**.example.com/\", \"https://shop.test/\"]\n";

fn exchange(host: &str, i: usize) -> NewExchange {
    NewExchange {
        ts_ms: i as i64,
        duration_ms: Some(1),
        source: "proxy".into(),
        actor_id: "human:local".into(),
        scheme: "https".into(),
        host: host.into(),
        port: 443,
        method: "GET".into(),
        path: format!("/r/{i}"),
        status: Some(200),
        request: format!("GET /r/{i} HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes(),
        response: Some(b"HTTP/1.1 200 OK\r\n\r\nok".to_vec()),
        error: None,
        identity: None,
        hypothesis_id: None,
    }
}

fn service() -> Service {
    Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap()
}

/// Everything already published to `sub`.
fn drain(sub: &mut Subscription) -> Vec<Published> {
    let mut out = Vec::new();
    while let Some(Some(d)) = sub.recv().now_or_never() {
        match d {
            Delivery::Event(p) => out.push(p),
            Delivery::Resync { .. } => panic!("unexpected resync"),
        }
    }
    out
}

fn file_project(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("pm-events-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    (dir.join("p.pmproj"), dir)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscriber_that_gets_the_event_can_read_the_row_at_once() {
    let (path, dir) = file_project("commit");
    let svc = Arc::new(Service::new(Store::open(&path).unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap());
    let mut sub = svc.subscribe();
    let reader = {
        let svc = svc.clone();
        tokio::spawn(async move {
            let Some(Delivery::Event(p)) = sub.recv().await else { panic!("expected an event") };
            let Event::ExchangeRecorded { id, host, method, status } = p.event else { panic!("{:?}", p.event) };
            // Reads on a pooled read-only connection: the row is there only if the transaction committed.
            let row = svc.exchange_raw(id).expect("the row is committed when the event arrives");
            assert_eq!((host.as_str(), method.as_str(), status), ("shop.test", "GET", Some(200)));
            assert_eq!(row.summary.host, "shop.test");
            id
        })
    };
    let id = svc.store_handle().write(|s| s.insert_exchange(&exchange("shop.test", 1))).unwrap();
    assert_eq!(reader.await.unwrap(), id);
    drop(svc);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_failed_write_publishes_nothing_and_seq_never_skips() {
    let svc = service();
    let mut sub = svc.subscribe();
    let handle = svc.store_handle();
    let bad_ws = NewWsMessage {
        exchange_id: 0,
        ts_ms: 1,
        from_client: true,
        opcode: 1,
        len: 1,
        payload: vec![1],
        truncated: false,
        compressed: false,
    };
    // The message points past the batch: the whole transaction rolls back, the exchange with it.
    let r = handle.write(|s| s.insert_batch(&[exchange("shop.test", 1)], &[(WsTarget::InBatch(5), bad_ws)]));
    assert!(r.is_err());
    assert_eq!(handle.read(|s| s.count_exchanges()).unwrap(), 0);
    assert!(drain(&mut sub).is_empty(), "a rolled-back write publishes nothing");

    let ids = handle.write(|s| s.insert_exchanges(&[exchange("shop.test", 2), exchange("shop.test", 3)])).unwrap();
    let got = drain(&mut sub);
    assert_eq!(got.iter().map(|p| p.seq).collect::<Vec<_>>(), [1, 2], "no sequence number was spent on the failure");
    let ev_ids: Vec<i64> = got
        .iter()
        .map(|p| match p.event {
            Event::ExchangeRecorded { id, .. } => id,
            ref e => panic!("{e:?}"),
        })
        .collect();
    assert_eq!(ev_ids, ids, "one event per row, in commit order");
    assert!(got.iter().all(|p| p.topic == Topic::Exchanges));
}

#[test]
fn recorder_batches_publish_one_event_per_row_in_order() {
    const N: usize = 400;
    let (path, dir) = file_project("recorder");
    let svc = Service::new(Store::open(&path).unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap();
    let mut sub = svc.subscribe();
    let (rec, join) = Recorder::spawn_shared(svc.store_handle());
    for i in 0..N {
        rec.record(exchange("shop.test", i));
    }
    drop(rec);
    join.join().unwrap();
    let got = drain(&mut sub);
    assert_eq!(got.len(), N, "one event per recorded row");
    for (i, p) in got.iter().enumerate() {
        assert_eq!(p.seq, i as u64 + 1, "seq strictly increasing, no gaps");
        match &p.event {
            Event::ExchangeRecorded { id, .. } => assert_eq!(*id, i as i64 + 1, "ids in commit order"),
            e => panic!("{e:?}"),
        }
    }
    drop(svc);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn findings_approvals_and_audit_publish_after_their_writes() {
    let svc = service();
    let me = Actor::parse("human:local").unwrap();
    let ex = svc.store_handle().write(|s| s.insert_exchange(&exchange("shop.test", 1))).unwrap();
    let mut sub = svc.subscribe();
    let f = svc
        .finding_create(
            &me,
            NewFinding {
                title: "t".into(),
                vuln_class: "idor".into(),
                severity: "low".into(),
                description: "d".into(),
                url: None,
                evidence: vec![ex],
                hypothesis_id: None,
            },
        )
        .unwrap();
    let id = f["id"].as_i64().unwrap();
    let got = drain(&mut sub);
    // The finding row is written first, then the audit record.
    assert!(matches!(&got[0].event, Event::FindingChanged { id: i, status } if *i == id && status == "suspected"));
    let Event::AuditAppended { seq } = got[1].event else { panic!("{:?}", got[1].event) };
    assert_eq!(svc.audit_verify().unwrap() as u64, seq, "the audit record exists when its event arrives");
    assert!(got.windows(2).all(|w| w[0].seq < w[1].seq));

    let req = pm_service::pm_policy::ActionRequest {
        actor: Actor::parse("agent:a").unwrap(),
        action: "replay_send".into(),
        tier: pm_service::pm_policy::Tier::ActiveIntrusive,
        target: Some(pm_service::pm_policy::Target::from_url("https://shop.test/x").unwrap()),
        summary: "s".into(),
    };
    let pm_service::Authorization::PendingApproval { approval_id, .. } =
        svc.authorize(req, &serde_json::json!({})).unwrap()
    else {
        panic!("expected a pending approval")
    };
    svc.decide_approval(&approval_id, &me, false).unwrap();
    let kinds: Vec<_> = drain(&mut sub).into_iter().map(|p| p.event).collect();
    assert!(kinds.contains(&Event::ApprovalRequested { id: approval_id.clone() }));
    assert!(kinds.contains(&Event::ApprovalDecided { id: approval_id.clone(), decision: "denied".into() }));
    // A decision that fails (already decided) publishes no ApprovalDecided.
    assert!(svc.decide_approval(&approval_id, &me, true).is_err());
    assert!(!drain(&mut sub).iter().any(|p| matches!(p.event, Event::ApprovalDecided { .. })));
}

#[test]
fn an_agent_only_sees_in_scope_events_and_redacted_hosts_a_human_sees_all() {
    let svc = service();
    let (human, agent) = (Actor::parse("human:h").unwrap(), Actor::parse("agent:a").unwrap());
    let mut sub = svc.subscribe();
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";
    let planted = format!("{jwt}.app.example.com");
    svc.store_handle()
        .write(|s| s.insert_exchanges(&[exchange("evil.test", 1), exchange(&planted, 2), exchange("shop.test", 3)]))
        .unwrap();
    let got = drain(&mut sub);
    assert_eq!(got.len(), 3);

    let seen_by = |a: &Actor| -> Vec<serde_json::Value> { got.iter().filter_map(|p| svc.event_for(a, p)).collect() };
    let human_view = seen_by(&human);
    assert_eq!(human_view.len(), 3, "a human sees every event");
    assert_eq!(human_view[1]["host"], planted.as_str(), "and the real host");
    assert_eq!(human_view[0]["type"], "exchange_recorded");
    assert_eq!((human_view[0]["seq"].as_u64(), human_view[0]["topic"].as_str()), (Some(1), Some("exchanges")));

    let agent_view = seen_by(&agent);
    assert_eq!(agent_view.len(), 2, "the out-of-scope host's event is dropped for an agent");
    assert!(agent_view.iter().all(|v| v["host"] != "evil.test"));
    let text = agent_view.iter().map(|v| v.to_string()).collect::<String>();
    assert!(!text.contains(jwt), "the secret in the host is replaced: {text}");
    assert_eq!(agent_view[1]["host"], "shop.test");

    assert!(!svc.may_read_topic(&agent, Topic::Intercept) && svc.may_read_topic(&agent, Topic::Findings));
}

#[test]
fn intercept_arrivals_and_releases_are_published_from_the_service() {
    use pm_service::pm_proxy::intercept::{Decision, Kind};
    use pm_service::pm_proxy::{InterceptQueue, InterceptSettings};
    let svc = service();
    let (human, agent) = (Actor::parse("human:h").unwrap(), Actor::parse("agent:a").unwrap());
    let q = Arc::new(InterceptQueue::new());
    svc.attach_intercept(q.clone());
    q.set_settings(InterceptSettings { enabled: true, in_scope_only: false, ..Default::default() });
    let mut sub = svc.subscribe();
    // One poll is enough to hold the message: it is queued, then waits for a decision.
    let mut held = Box::pin(q.hold(Kind::Request, "https", "shop.test", 443, "GET", "/", b"GET / HTTP/1.1\r\n\r\n"));
    assert!(held.as_mut().now_or_never().is_none());
    let id = q.held()[0].id;
    assert!(q.decide(id, Decision::Drop));
    let got = drain(&mut sub);
    assert_eq!(
        got.iter().map(|p| (p.topic, p.event.clone())).collect::<Vec<_>>(),
        [(Topic::Intercept, Event::InterceptQueued { id }), (Topic::Intercept, Event::InterceptResolved { id })]
    );
    assert!(svc.event_for(&human, &got[0]).is_some());
    assert!(svc.event_for(&agent, &got[0]).is_none(), "the intercept queue is for humans only");
}

#[test]
fn counters_from_cheap_queries_match_and_the_tracker_follows_events() {
    let svc = service();
    let me = Actor::parse("human:local").unwrap();
    let handle = svc.store_handle();
    handle.write(|s| s.insert_exchanges(&[exchange("shop.test", 1), exchange("shop.test", 2)])).unwrap();
    let start = svc.counters().unwrap();
    assert_eq!((start.exchanges, start.last_exchange_id, start.findings, start.audit_records), (2, 2, 0, 0));

    // Row 3 is committed after subscribing but before the tracker reads: its event must not count it twice.
    let mut sub = svc.subscribe();
    handle.write(|s| s.insert_exchange(&exchange("shop.test", 3))).unwrap();
    let mut tracker = svc.counter_tracker().unwrap();
    for p in drain(&mut sub) {
        assert!(tracker.apply(&p));
    }
    assert_eq!(tracker.snapshot(&svc).unwrap().exchanges, 3);

    handle.write(|s| s.insert_exchange(&exchange("shop.test", 4))).unwrap();
    svc.finding_create(
        &me,
        NewFinding {
            title: "t".into(),
            vuln_class: "idor".into(),
            severity: "low".into(),
            description: "d".into(),
            url: Some("https://shop.test/a".into()),
            evidence: vec![],
            hypothesis_id: None,
        },
    )
    .unwrap();
    assert!(drain(&mut sub).iter().all(|p| tracker.apply(p)), "every event published here changes a counter");
    let now = svc.counters().unwrap();
    assert_eq!((now.exchanges, now.last_exchange_id, now.findings, now.audit_records), (4, 4, 1, 1));
    assert_eq!(tracker.snapshot(&svc).unwrap(), now, "events and a fresh read agree");
}

#[test]
fn a_collaborator_callback_publishes_a_hit_with_its_row_id() {
    let svc = service();
    let mut sub = svc.subscribe();
    let hit = pm_service::pm_oast::Interaction {
        token: "tok1".into(),
        protocol: "http".into(),
        remote: "203.0.113.9:1".into(),
        method: "GET".into(),
        path: "/x".into(),
        ts_ms: 1,
        raw: String::new(),
    };
    svc.record_oast(&hit).unwrap();
    let got = drain(&mut sub);
    assert_eq!((got[0].topic, got[0].event.clone()), (Topic::Collaborator, Event::CollaboratorHit { id: 1 }));
}
