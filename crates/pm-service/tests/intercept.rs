//! The intercept queue through the service: who may use it and how edits are applied.

use std::sync::Arc;
use std::time::Duration;

use pm_service::Service;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_proxy::intercept::{Decision, Kind};
use pm_service::pm_proxy::{InterceptQueue, InterceptSettings};
use pm_service::pm_store::Store;

fn service() -> Service {
    let roe = Roe::parse("version: 1\nscope:\n  include: [\"http://shop.test/\"]\n").unwrap();
    Service::new(Store::open_in_memory().unwrap(), Policy::new(roe)).unwrap()
}

#[tokio::test]
async fn needs_attached_queue_and_a_human() {
    let svc = service();
    let human = Actor::parse("human:tester").unwrap();
    let agent = Actor::parse("agent:claude").unwrap();
    assert!(!svc.intercept_state().attached);
    assert!(svc.intercept_settings(&human, InterceptSettings::default()).is_err(), "no queue attached");

    svc.attach_intercept(Arc::new(InterceptQueue::new()));
    assert!(svc.intercept_state().attached);
    let on = InterceptSettings { enabled: true, ..Default::default() };
    assert!(svc.intercept_settings(&agent, on.clone()).is_err(), "agents can't intercept");
    assert!(svc.intercept_settings(&human, on).unwrap().settings.enabled);
}

#[tokio::test]
async fn in_scope_edit_is_fixed_up_and_audited() {
    let svc = service();
    let q = Arc::new(InterceptQueue::new());
    svc.attach_intercept(q.clone());
    let human = Actor::parse("human:tester").unwrap();
    svc.intercept_settings(&human, InterceptSettings { enabled: true, ..Default::default() }).unwrap();

    // Out of scope: passes straight through.
    let out = q.hold(Kind::Request, "http", "other.test", 80, "GET", "/", b"GET / HTTP/1.1\r\n\r\n").await;
    assert!(matches!(out, Decision::Forward(None)));

    let raw = b"POST /a HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 2\r\n\r\nhi";
    let q2 = q.clone();
    let task = tokio::spawn(async move { q2.hold(Kind::Request, "http", "shop.test", 80, "POST", "/a", raw).await });
    for _ in 0..50 {
        if svc.intercept_held_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let held = svc.intercept_state().held;
    assert_eq!(held.len(), 1);
    // The UI sends LF line endings; the service restores CRLF and fixes Content-Length.
    let edited = "POST /b HTTP/1.1\nHost: shop.test\nContent-Length: 2\n\nhello";
    let agent = Actor::parse("agent:claude").unwrap();
    assert!(svc.intercept_forward(&agent, held[0].id, Some(edited.into()), true).is_err());
    svc.intercept_forward(&human, held[0].id, Some(edited.into()), true).unwrap();
    match task.await.unwrap() {
        Decision::Forward(Some(b)) => {
            assert_eq!(b, b"POST /b HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 5\r\n\r\nhello".to_vec())
        }
        other => panic!("expected an edited forward, got {other:?}"),
    }
    let audit = svc.audit_list(10).unwrap();
    assert!(audit.iter().any(|r| r.action == "intercept_edit" && r.actor == "human:tester"));
    assert!(svc.audit_verify().is_ok());
}
