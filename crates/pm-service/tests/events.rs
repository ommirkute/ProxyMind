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

#[test]
fn ws_messages_publish_one_event_per_exchange_per_batch_with_scope_rules() {
    let svc = service();
    let (human, agent) = (Actor::parse("human:h").unwrap(), Actor::parse("agent:a").unwrap());
    let handle = svc.store_handle();
    let ids = handle.write(|s| s.insert_exchanges(&[exchange("shop.test", 1), exchange("evil.test", 2)])).unwrap();
    let msg = || NewWsMessage {
        exchange_id: 0,
        ts_ms: 1,
        from_client: true,
        opcode: 1,
        len: 1,
        payload: vec![b'x'],
        truncated: false,
        compressed: false,
    };
    let mut sub = svc.subscribe();
    // Five messages on three sockets (one in the same batch as its exchange): one event per exchange.
    let ws = [
        (WsTarget::Exchange(ids[0]), msg()),
        (WsTarget::Exchange(ids[0]), msg()),
        (WsTarget::Exchange(ids[1]), msg()),
        (WsTarget::Exchange(ids[0]), msg()),
        (WsTarget::InBatch(0), msg()),
    ];
    handle.write(|s| s.insert_batch(&[exchange("shop.test", 3)], &ws)).unwrap();
    let got = drain(&mut sub);
    let kinds: Vec<_> = got.iter().map(|p| (p.topic, p.event.clone())).collect();
    assert_eq!(kinds.len(), 4, "{kinds:?}");
    assert!(matches!(kinds[0].1, Event::ExchangeRecorded { .. }));
    assert_eq!(
        kinds[1..],
        [
            (Topic::Websockets, Event::WsMessageRecorded { exchange_id: ids[0] }),
            (Topic::Websockets, Event::WsMessageRecorded { exchange_id: ids[1] }),
            (Topic::Websockets, Event::WsMessageRecorded { exchange_id: ids[1] + 1 }),
        ]
    );
    // Humans see all; an agent loses the out-of-scope host's socket.
    let human_view: Vec<_> = got.iter().filter_map(|p| svc.event_for(&human, p)).collect();
    assert_eq!(human_view.len(), 4);
    assert_eq!(human_view[1]["type"], "ws_message_recorded");
    assert_eq!(
        (human_view[1]["topic"].as_str(), human_view[1]["exchange_id"].as_i64()),
        (Some("websockets"), Some(ids[0]))
    );
    let agent_ws: Vec<_> =
        got.iter().filter_map(|p| svc.event_for(&agent, p)).filter(|v| v["topic"] == "websockets").collect();
    assert_eq!(agent_ws.len(), 2, "the evil.test socket is dropped: {agent_ws:?}");
    assert!(agent_ws.iter().all(|v| v["exchange_id"] != ids[1]));
    assert!(svc.may_read_topic(&agent, Topic::Websockets));

    // A rolled-back batch publishes nothing.
    assert!(handle.write(|s| s.insert_batch(&[], &[(WsTarget::InBatch(0), msg())])).is_err());
    assert!(drain(&mut sub).is_empty());
}

// ---- ADR-0018 step 5: scan, fuzzer and AI-scan progress ----

use std::time::{Duration, Instant};

use pm_demo::VulnShop;
use pm_service::pm_fuzz::PayloadSet;
use pm_service::{AiScanRequest, AttackStatus, FuzzerRequest, FuzzerStart, ScanTaskRequest};

/// Receives events until `done` says so (it sees each one), failing after 30 s. Returns everything received.
async fn collect_until(sub: &mut Subscription, mut done: impl FnMut(&Event) -> bool) -> Vec<Published> {
    let mut out = Vec::new();
    loop {
        match tokio::time::timeout(Duration::from_secs(30), sub.recv()).await.expect("no event for 30 s") {
            Some(Delivery::Event(p)) => {
                let stop = done(&p.event);
                out.push(p);
                if stop {
                    return out;
                }
            }
            other => panic!("{other:?}"),
        }
    }
}

async fn shop_service() -> (Arc<Service>, String) {
    let addr = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", addr.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    (Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap()), url)
}

fn scan_states(got: &[Published], task: &str) -> Vec<String> {
    got.iter()
        .filter_map(|p| match &p.event {
            Event::ScanStateChanged { task: t, state } if t == task => Some(state.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_tasks_publish_every_state_change_and_a_final_progress() {
    let (svc, url) = shop_service().await;
    let human = Actor::parse("human:tester").unwrap();
    let mut sub = svc.subscribe();
    let req = ScanTaskRequest {
        url: format!("{url}/"),
        max_pages: Some(20),
        browser: Some(false),
        checks: vec!["reflected_input".into(), "sql_error".into()],
        ..Default::default()
    };
    let id = svc.scan_task_start(&human, req).unwrap().task_id;
    // Wait for the audit to be under way (an event, not a sleep), then cancel and resume it.
    let mut got = collect_until(&mut sub, |e| matches!(e, Event::ScanProgress { done, .. } if *done >= 2)).await;
    svc.scan_task_cancel(&human, &id).unwrap();
    got.extend(
        collect_until(&mut sub, |e| matches!(e, Event::ScanStateChanged { state, .. } if state == "cancelled")).await,
    );
    svc.scan_task_resume(&human, &id).unwrap();
    got.extend(
        collect_until(&mut sub, |e| matches!(e, Event::ScanStateChanged { state, .. } if state == "done")).await,
    );

    let states = scan_states(&got, &id);
    assert_eq!(states, ["crawling", "auditing", "cancelled", "auditing", "done"], "once per transition: {states:?}");
    // The final progress is sent whatever the rate limit says, and is the last progress event.
    let last = got.iter().rev().find_map(|p| match &p.event {
        Event::ScanProgress { done, total, .. } => Some((*done, *total)),
        _ => None,
    });
    let v = svc.scan_task_status(&human, &id).unwrap();
    assert_eq!(last, Some((v.targets_done, v.targets_total)), "{v:?}");
    assert!(got.iter().any(|p| p.topic == Topic::Scans && p.topic.as_str() == "scans"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_and_fuzzer_events_go_to_humans_and_the_run_s_owner_only() {
    let (svc, url) = shop_service().await;
    let (human, a, b) =
        (Actor::parse("human:h").unwrap(), Actor::parse("agent:a").unwrap(), Actor::parse("agent:b").unwrap());
    let mut sub = svc.subscribe();
    // Whatever the gate says for an agent (it may need an approval), the task's own events carry its owner.
    let id = svc
        .scan_task_start(&a, ScanTaskRequest { url: format!("{url}/"), browser: Some(false), ..Default::default() })
        .unwrap()
        .task_id;
    let got = collect_until(&mut sub, |e| {
        matches!(e, Event::ScanStateChanged { state, .. } if matches!(state.as_str(), "done" | "failed" | "cancelled"))
    })
    .await;
    // (The crawl and the audit also record exchanges and audit entries, on other topics.)
    let seen = |who: &Actor| got.iter().filter(|p| p.topic == Topic::Scans && svc.event_for(who, p).is_some()).count();
    assert!(seen(&a) >= 2, "the owner sees its task's events");
    assert_eq!(seen(&a), seen(&human), "a human sees every task's events");
    assert_eq!(seen(&b), 0, "another agent sees none, as it cannot read the task");
    assert!(svc.scan_task_status(&b, &id).is_err());
    for t in [Topic::Scans, Topic::Fuzzer, Topic::AiScan] {
        assert!(svc.may_read_topic(&a, t) && svc.may_read_topic(&human, t));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fuzzer_progress_is_rate_limited_and_state_changes_and_the_end_always_go_out() {
    let (svc, url) = shop_service().await;
    let human = Actor::parse("human:h").unwrap();
    let mut sub = svc.subscribe();
    let req = |n: usize, throttle: Option<u64>| FuzzerRequest {
        url: Some(url.clone()),
        raw: "GET /api/products?x=§a§ HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        payload_sets: vec![PayloadSet { null_payloads: Some(n), ..Default::default() }],
        throttle_ms: throttle,
        ..Default::default()
    };
    let FuzzerStart::Started { attack_id, total } = svc.fuzzer_start(&human, req(60, None)).unwrap() else {
        panic!("not started")
    };
    let started = Instant::now();
    let is_end = |e: &Event| matches!(e, Event::FuzzerProgress { state, .. } if state == "done");
    let got = collect_until(&mut sub, is_end).await;
    let took = started.elapsed();
    // (The attack also records exchanges and audit entries, on other topics.)
    let got: Vec<Published> = got.into_iter().filter(|p| p.topic == Topic::Fuzzer).collect();
    let prog: Vec<(usize, usize, String)> = got
        .iter()
        .filter_map(|p| match &p.event {
            Event::FuzzerProgress { attack, done, total, state } if *attack == attack_id => {
                Some((*done, *total, state.clone()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(prog.len(), got.len());
    assert_eq!(prog[0], (0, total, "running".into()), "the start is announced");
    assert_eq!(prog.last().unwrap(), &(60, 60, "done".into()), "the final count always goes out");
    assert!(prog.windows(2).all(|w| w[0].0 <= w[1].0), "done never goes back: {prog:?}");
    // Two always-sent updates (start, baseline), one per 250 ms window, the held one, and the end.
    let allowed = 4 + (took.as_millis() / 250) as usize;
    assert!(prog.len() <= allowed, "{} events in {took:?} (at most {allowed}): {prog:?}", prog.len());
    assert!(prog.len() < 60, "60 results did not make 60 events");

    // pause, resume and cancel are each announced at once, and the cancelled attack ends with its final count.
    let FuzzerStart::Started { attack_id: id2, .. } = svc.fuzzer_start(&human, req(200, Some(20))).unwrap() else {
        panic!("not started")
    };
    let state_of = |e: &Event| match e {
        Event::FuzzerProgress { attack, state, .. } if *attack == id2 => Some(state.clone()),
        _ => None,
    };
    collect_until(
        &mut sub,
        |e| matches!(e, Event::FuzzerProgress { attack, done, .. } if *attack == id2 && *done >= 2),
    )
    .await;
    for (action, want) in [("pause", "paused"), ("resume", "running"), ("cancel", "cancelled")] {
        svc.fuzzer_control(&human, &id2, action).unwrap();
        let got = collect_until(&mut sub, |e| state_of(e).as_deref() == Some(want)).await;
        assert!(got.iter().any(|p| state_of(&p.event).as_deref() == Some(want)), "{action}");
    }
    let v = svc.fuzzer_status(&human, &id2, 0).unwrap();
    assert_eq!(v.status, AttackStatus::Cancelled);
    // The attack stops after its in-flight request; the last event matches the status the page will fetch.
    let end = collect_until(&mut sub, |e| matches!(e, Event::FuzzerProgress { attack, done, .. } if *attack == id2 && *done == svc.fuzzer_status(&human, &id2, 0).unwrap().done)).await;
    assert!(!end.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ai_scan_changes_publish_ids_and_state_words_only_and_the_end_goes_out_at_once() {
    let svc = service();
    let (human, agent) = (Actor::parse("human:h").unwrap(), Actor::parse("agent:a").unwrap());
    let mut sub = svc.subscribe();
    let scan = svc.ai_scan_create(&human, &AiScanRequest::default(), "m").unwrap();
    let secret = "PLANTED-LOG-TEXT-from-the-target";
    for i in 0..20 {
        svc.ai_scan_log(scan.id, "note", &format!("{secret} {i}")).unwrap();
    }
    svc.ai_scan_set_phase(scan.id, "scanning", "gate met").unwrap();
    svc.ai_scan_usage(scan.id, 10, 5, 1000).unwrap();
    svc.ai_scan_finish(scan.id, "done", "").unwrap();
    // The end is sent at once: no waiting for a window.
    let t = Instant::now();
    let got = collect_until(&mut sub, |e| matches!(e, Event::AiScanChanged { state, .. } if state == "done")).await;
    assert!(t.elapsed() < Duration::from_millis(200), "{:?}", t.elapsed());
    let got: Vec<Published> = got.into_iter().filter(|p| p.topic == Topic::AiScan).collect();
    // 24 updates inside a few milliseconds made a handful of events (create, the first, the end).
    assert!(got.len() <= 4, "{} events", got.len());
    match &got.last().unwrap().event {
        Event::AiScanChanged { scan_id, state, phase } => {
            assert_eq!((*scan_id, state.as_str(), phase.as_str()), (scan.id, "done", "scanning"));
        }
        e => panic!("{e:?}"),
    }
    for who in [&human, &agent] {
        let shown: String = got.iter().filter_map(|p| svc.event_for(who, p)).map(|v| v.to_string()).collect();
        assert!(!shown.contains("PLANTED") && !shown.contains("gate met"), "no log text: {shown}");
        assert!(shown.contains("ai_scan_changed") && shown.contains("\"topic\":\"ai_scan\""), "{shown}");
    }
    // Held updates are not lost: a last quiet update still arrives within the window.
    let s2 = svc.ai_scan_create(&human, &AiScanRequest::default(), "m").unwrap();
    svc.ai_scan_set_phase(s2.id, "scanning", "").unwrap();
    let got = collect_until(
        &mut sub,
        |e| matches!(e, Event::AiScanChanged { scan_id, phase, .. } if *scan_id == s2.id && phase == "scanning"),
    )
    .await;
    assert!(!got.is_empty());
}
