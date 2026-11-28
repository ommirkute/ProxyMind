//! A token's tier cap at the service: the gate refuses above it, the refusal is audited, and an approved action is
//! checked against it again when it runs (ADR-0022 step 5).

use std::sync::{Arc, Mutex};

use pm_service::pm_policy::{Actor, Policy, Roe, Tier};
use pm_service::pm_store::Store;
use pm_service::{ReplayRequest, ReplayResult, Service};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn server(seen: Arc<Mutex<Vec<String>>>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = s.read(&mut buf).await.unwrap();
                seen.lock().unwrap().push(String::from_utf8_lossy(&buf[..n]).into_owned());
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await;
            });
        }
    });
    port
}

fn service() -> Service {
    let roe = Roe::parse("version: 1\nscope:\n  include: [\"http://127.0.0.1:*/\"]\n").unwrap();
    Service::new(Store::open_in_memory().unwrap(), Policy::new(roe)).unwrap()
}

fn get(port: u16) -> ReplayRequest {
    ReplayRequest {
        url: Some(format!("http://127.0.0.1:{port}")),
        raw: Some("GET / HTTP/1.1\r\nHost: x\r\n\r\n".into()),
        ..Default::default()
    }
}

fn post(port: u16) -> ReplayRequest {
    ReplayRequest {
        url: Some(format!("http://127.0.0.1:{port}")),
        raw: Some("POST /o HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n".into()),
        ..Default::default()
    }
}

#[tokio::test]
async fn above_the_cap_nothing_is_sent_and_the_denial_is_audited() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = server(seen.clone()).await;
    let s = service();
    let agent = Actor::parse("agent:claude").unwrap();
    s.policy().set_tier_cap(&agent, Some(Tier::Passive));
    let r = s.replay_send(&agent, get(port)).await.unwrap();
    let ReplayResult::Denied { reasons } = r else { panic!("expected a denial, got {r:?}") };
    assert!(reasons[0].contains("limited to passive"), "{reasons:?}");
    assert!(seen.lock().unwrap().is_empty(), "nothing reached the target");
    let log = s.audit_list(10).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(
        (log[0].actor.as_str(), log[0].action.as_str(), log[0].decision.as_str()),
        ("agent:claude", "replay_send", "deny")
    );
    assert!(log[0].detail.contains("limited to passive"), "{}", log[0].detail);
    s.audit_verify().unwrap();
    // At active_safe the same GET goes through; the POST (intrusive) is above the cap, with no approval offered.
    s.policy().set_tier_cap(&agent, Some(Tier::ActiveSafe));
    assert!(matches!(s.replay_send(&agent, get(port)).await.unwrap(), ReplayResult::Sent { .. }));
    assert!(matches!(s.replay_send(&agent, post(port)).await.unwrap(), ReplayResult::Denied { .. }));
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn an_approval_cannot_lift_a_cap_that_came_after_it() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let port = server(seen.clone()).await;
    let s = service();
    let agent = Actor::parse("agent:claude").unwrap();
    // No cap: the POST needs approval; a person approves it.
    let ReplayResult::PendingApproval { approval_id, .. } = s.replay_send(&agent, post(port)).await.unwrap() else {
        panic!("expected an approval to be asked for")
    };
    s.decide_approval(&approval_id, &Actor::parse("human:omkar").unwrap(), true).unwrap();
    // The agent's credential is now capped (a new token): the approved action is checked against the cap when it runs.
    s.policy().set_tier_cap(&agent, Some(Tier::ActiveSafe));
    let approved = ReplayRequest { approval_id: Some(approval_id), ..post(port) };
    let r = s.replay_send(&agent, approved).await.unwrap();
    assert!(matches!(r, ReplayResult::Denied { .. }), "{r:?}");
    assert!(seen.lock().unwrap().is_empty());
}
