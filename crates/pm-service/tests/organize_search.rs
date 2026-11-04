//! Global search options (parts, inverted, scope, WebSockets), the Organizer
//! and the Replay request helpers.

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{HistoryFilter, NewExchange, NewWsMessage, Store};
use pm_service::{OrganizerUpdate, RequestTransform, SearchRequest, Service, WsSearchRequest};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

fn exchange(host: &str, path: &str, request: &str, response: &str) -> NewExchange {
    NewExchange {
        ts_ms: 1,
        duration_ms: None,
        source: "proxy".into(),
        actor_id: "human:local".into(),
        scheme: "http".into(),
        host: host.into(),
        port: 80,
        method: "GET".into(),
        path: path.into(),
        status: Some(200),
        request: request.as_bytes().to_vec(),
        response: Some(response.as_bytes().to_vec()),
        error: None,
        identity: None,
        hypothesis_id: None,
    }
}

fn service() -> (Service, Vec<i64>) {
    let mut store = Store::open_in_memory().unwrap();
    let ids = vec![
        store
            .insert_exchange(&exchange(
                "app.test",
                "/a",
                "GET /a HTTP/1.1\r\nHost: app.test\r\nX-Debug: needle\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            ))
            .unwrap(),
        store
            .insert_exchange(&exchange(
                "app.test",
                "/b",
                "GET /b HTTP/1.1\r\nHost: app.test\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nsome needle",
            ))
            .unwrap(),
        store
            .insert_exchange(&exchange(
                "other.test",
                "/c",
                "GET /c HTTP/1.1\r\nHost: other.test\r\n\r\n",
                "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nneedle",
            ))
            .unwrap(),
    ];
    for (from_client, text) in [(true, "subscribe needle"), (false, "price update"), (false, "needle reply")] {
        store
            .insert_ws_message(&NewWsMessage {
                exchange_id: ids[0],
                ts_ms: 2,
                from_client,
                opcode: 1,
                len: text.len() as u64,
                payload: text.as_bytes().to_vec(),
                truncated: false,
                compressed: false,
            })
            .unwrap();
    }
    let roe = Roe::parse("version: 1\nscope:\n  include: [\"http://app.test/\"]\n").unwrap();
    (Service::new(store, Policy::new(roe)).unwrap(), ids)
}

fn search(s: &Service, part: &str, invert: bool, in_scope: bool) -> Vec<(i64, &'static str)> {
    let r = s
        .history_search_text(
            &human(),
            &SearchRequest {
                query: "needle".into(),
                part: Some(part.into()),
                invert,
                filter: HistoryFilter { in_scope: in_scope.then_some(true), ..Default::default() },
                ..Default::default()
            },
        )
        .unwrap();
    let mut hits: Vec<_> = r.hits.iter().map(|h| (h.exchange.id, h.part)).collect();
    hits.sort();
    hits
}

#[test]
fn search_parts_inversion_and_scope() {
    let (s, ids) = service();
    let (a, b, c) = (ids[0], ids[1], ids[2]);
    assert_eq!(search(&s, "both", false, false), vec![(a, "request"), (b, "response"), (c, "response")]);
    assert_eq!(search(&s, "request_headers", false, false), vec![(a, "request")]);
    assert_eq!(search(&s, "request_body", false, false), vec![]);
    assert_eq!(search(&s, "response_body", false, false), vec![(b, "response"), (c, "response")]);
    assert_eq!(search(&s, "response_headers", false, false), vec![]);
    assert_eq!(search(&s, "both", false, true), vec![(a, "request"), (b, "response")], "other.test is out of scope");
    assert_eq!(search(&s, "response", true, false), vec![(a, "none")], "only /a has no needle in its response");
    let bad = SearchRequest { query: "x".into(), part: Some("cookies".into()), ..Default::default() };
    assert!(s.history_search_text(&human(), &bad).is_err());
}

#[test]
fn websocket_search() {
    let (s, _) = service();
    let ws = |direction: &str, invert: bool| {
        let r = s
            .ws_search_text(
                &human(),
                &WsSearchRequest {
                    query: "needle".into(),
                    direction: Some(direction.into()),
                    invert,
                    ..Default::default()
                },
            )
            .unwrap();
        r.hits.iter().map(|h| (h.from_client, h.snippets.first().map(|x| x.text.clone()))).collect::<Vec<_>>()
    };
    assert_eq!(ws("both", false).len(), 2);
    assert_eq!(ws("client", false), vec![(true, Some("subscribe needle".into()))]);
    assert_eq!(ws("server", true), vec![(false, None)], "the price update has no needle");
}

#[test]
fn organizer_items() {
    let (s, ids) = service();
    let agent = Actor::parse("agent:claude").unwrap();
    let item = s.organizer_add(&agent, ids[1], "check the debug flag").unwrap();
    assert_eq!((item.status.as_str(), item.exchange.as_ref().map(|e| e.path.as_str())), ("new", Some("/b")));
    s.organizer_add(&human(), ids[0], "").unwrap();
    assert!(s.organizer_add(&human(), 9999, "").is_err(), "unknown exchange");

    let u = OrganizerUpdate { status: Some("in_progress".into()), note: Some("looking".into()) };
    let changed = s.organizer_update(&human(), item.id, &u).unwrap();
    assert_eq!((changed.status.as_str(), changed.note.as_str()), ("in_progress", "looking"));
    let bad = OrganizerUpdate { status: Some("maybe".into()), note: None };
    assert!(s.organizer_update(&human(), item.id, &bad).is_err());

    assert_eq!(s.organizer_list(&human(), None).unwrap().len(), 2);
    let busy = s.organizer_list(&human(), Some("in_progress")).unwrap();
    assert_eq!(busy.iter().map(|i| i.id).collect::<Vec<_>>(), vec![item.id]);
    s.organizer_delete(&human(), item.id).unwrap();
    assert!(s.organizer_delete(&human(), item.id).is_err());
    assert_eq!(s.organizer_list(&human(), None).unwrap().len(), 1);
}

#[test]
fn request_transforms() {
    let (s, _) = service();
    let raw = "GET /s?q=1 HTTP/1.1\r\nHost: app.test\r\n\r\n".to_string();
    let post = s.request_transform(&RequestTransform::ChangeMethod { raw }).unwrap();
    let post = post["raw"].as_str().unwrap();
    assert!(post.starts_with("POST /s HTTP/1.1\r\n") && post.ends_with("\r\n\r\nq=1"), "{post}");
    let json = s
        .request_transform(&RequestTransform::ConvertBody {
            raw: post.into(),
            to: pm_service::pm_tools::reqedit::BodyEncoding::Json,
        })
        .unwrap();
    assert!(json["raw"].as_str().unwrap().ends_with("{\"q\":\"1\"}"));
}
