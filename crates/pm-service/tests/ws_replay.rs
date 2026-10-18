//! WebSocket replay against VulnShop's support chat socket.

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{NewExchange, Store};
use pm_service::{Service, WsOut, WsReplayRequest, WsReplayResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn setup() -> (Service, i64) {
    let shop = pm_demo::VulnShop::start_local().await.unwrap().port();
    // Log in as alice over plain TCP to get a session token.
    let body = r#"{"username":"alice","password":"alice123"}"#;
    let mut s = tokio::net::TcpStream::connect(("127.0.0.1", shop)).await.unwrap();
    let req = format!(
        "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut resp = String::new();
    s.read_to_string(&mut resp).await.unwrap();
    let token = resp.split("\"token\":\"").nth(1).unwrap().split('"').next().unwrap().to_string();

    let mut store = Store::open_in_memory().unwrap();
    let mut ex = |path: &str, status: u16, request: String| {
        store
            .insert_exchange(&NewExchange {
                ts_ms: 1,
                duration_ms: None,
                source: "proxy".into(),
                actor_id: "human:local".into(),
                scheme: "http".into(),
                host: "127.0.0.1".into(),
                port: shop,
                method: "GET".into(),
                path: path.into(),
                status: Some(status),
                request: request.into_bytes(),
                response: Some(format!("HTTP/1.1 {status} X\r\n\r\n").into_bytes()),
                error: None,
                identity: None,
                hypothesis_id: None,
            })
            .unwrap()
    };
    ex("/", 200, format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{shop}\r\n\r\n"));
    // A WebSocket upgrade as the proxy would have recorded it.
    let id = ex(
        "/ws/support",
        101,
        format!(
            "GET /ws/support HTTP/1.1\r\nHost: 127.0.0.1:{shop}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Extensions: permessage-deflate\r\nCookie: session={token}\r\n\r\n"
        ),
    );
    let roe = format!(
        "version: 1\nscope:\n  include: [\"http://127.0.0.1:{shop}/\"]\ntiers:\n  agent:\n    read: allow\n    passive: allow\n    \
         active_safe: allow\n    active_intrusive: approve\n    destructive: deny\n"
    );
    (Service::new(store, Policy::new(Roe::parse(&roe).unwrap())).unwrap(), id)
}

fn text(t: &str) -> WsOut {
    WsOut { text: Some(t.into()), hex: None }
}

#[tokio::test]
async fn human_replay_sends_messages_and_records_the_session() {
    let (svc, id) = setup().await;
    let me = Actor::parse("human:tester").unwrap();
    let req = WsReplayRequest {
        exchange_id: id,
        messages: vec![text("where is my order?"), text("thanks")],
        wait_ms: Some(300),
        ..Default::default()
    };
    let r = svc.ws_replay(&me, req).await.unwrap();
    let WsReplayResult::Done { exchange_id, closed_by, messages, .. } = r else { panic!("{r:?}") };
    assert_ne!(exchange_id, id, "a new exchange");
    let seen: Vec<(&str, &str, String)> =
        messages.messages.iter().map(|m| (m.from, m.kind, m.text.clone().unwrap_or_default())).collect();
    assert_eq!(seen[0].0, "server");
    assert!(seen[0].2.contains("Hi alice"), "{seen:?}");
    assert_eq!((seen[1].0, seen[1].2.as_str()), ("client", "where is my order?"));
    assert!(seen[2].2.contains("we got: where is my order?"), "{seen:?}");
    assert_eq!((seen[3].0, seen[3].2.as_str()), ("client", "thanks"));
    assert!(seen[4].2.contains("we got: thanks"));
    assert_eq!(seen.last().unwrap().1, "close");
    assert!(closed_by == "proxymind" || closed_by == "server");

    let req = String::from_utf8(svc.exchange_raw(exchange_id).unwrap().request).unwrap();
    assert!(!req.contains("permessage-deflate") && !req.contains("dGhlIHNhbXBsZSBub25jZQ=="), "fresh key, no deflate");
    assert!(req.contains("Cookie: session="));
}

#[tokio::test]
async fn agents_need_approval_to_send_messages_but_not_to_open() {
    let (svc, id) = setup().await;
    let agent = Actor::parse("agent:claude").unwrap();
    let open_only = WsReplayRequest { exchange_id: id, wait_ms: Some(200), ..Default::default() };
    let r = svc.ws_replay(&agent, open_only).await.unwrap();
    let WsReplayResult::Done { messages, .. } = r else { panic!("{r:?}") };
    let hello = messages.messages[0].text.as_deref().unwrap();
    assert!(hello.starts_with("<untrusted_target_content>") && hello.contains("Hi alice"), "{hello}");

    let send = WsReplayRequest {
        exchange_id: id,
        messages: vec![text("hello from the agent")],
        wait_ms: Some(300),
        ..Default::default()
    };
    let r = svc.ws_replay(&agent, send.clone()).await.unwrap();
    let WsReplayResult::PendingApproval { approval_id, .. } = r else { panic!("{r:?}") };
    svc.decide_approval(&approval_id, &Actor::parse("human:lead").unwrap(), true).unwrap();

    // The approval covers exactly these messages.
    let other = WsReplayRequest {
        messages: vec![text("something else")],
        approval_id: Some(approval_id.clone()),
        ..send.clone()
    };
    assert!(svc.ws_replay(&agent, other).await.is_err());
    let r = svc
        .ws_replay(&agent, WsReplayRequest { approval_id: Some(approval_id.clone()), ..send.clone() })
        .await
        .unwrap();
    let WsReplayResult::Done { messages, .. } = r else { panic!("{r:?}") };
    assert!(
        messages.messages.iter().any(|m| m.text.as_deref().is_some_and(|t| t.contains("we got: hello from the agent")))
    );
    // Used once only.
    assert!(svc.ws_replay(&agent, WsReplayRequest { approval_id: Some(approval_id), ..send }).await.is_err());
}

#[tokio::test]
async fn bad_requests_are_refused() {
    let (svc, id) = setup().await;
    let me = Actor::parse("human:tester").unwrap();
    let both = WsReplayRequest {
        exchange_id: id,
        messages: vec![WsOut { text: Some("a".into()), hex: Some("00".into()) }],
        ..Default::default()
    };
    assert!(svc.ws_replay(&me, both).await.is_err());
    let not_ws = WsReplayRequest { exchange_id: id - 1, ..Default::default() };
    assert!(svc.ws_replay(&me, not_ws).await.unwrap_err().to_string().contains("not a WebSocket upgrade"));
    // Without the session cookie the server refuses the upgrade.
    let raw = String::from_utf8(svc.exchange_raw(id).unwrap().request).unwrap();
    let no_cookie: String = raw.lines().filter(|l| !l.starts_with("Cookie")).map(|l| format!("{l}\r\n")).collect();
    let r = svc
        .ws_replay(&me, WsReplayRequest { exchange_id: id, raw: Some(no_cookie), ..Default::default() })
        .await
        .unwrap();
    assert!(matches!(r, WsReplayResult::NotUpgraded { http_status: Some(401), .. }), "{r:?}");
}
