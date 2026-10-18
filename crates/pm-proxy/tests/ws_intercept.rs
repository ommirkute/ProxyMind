//! WebSocket messages held in the intercept queue: edited, dropped or
//! forwarded, in both directions.

use std::sync::Arc;
use std::time::Duration;

use pm_http::ws::{self, Decoder, WsMessage};
use pm_proxy::intercept::{Decision, Held, Kind};
use pm_proxy::{Hooks, InterceptQueue, InterceptSettings, Proxy, Recorder};
use pm_store::Store;
use pm_tls::CertAuthority;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn read_head(s: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.unwrap() == 0 {
            break;
        }
        head.push(b[0]);
    }
    String::from_utf8(head).unwrap()
}

/// Reads frames until one whole message arrives.
async fn next_message<R: AsyncRead + Unpin>(r: &mut R, d: &mut Decoder) -> Option<WsMessage> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), r.read(&mut buf)).await.ok()?.ok()?;
        if n == 0 {
            return None;
        }
        d.feed(&buf[..n], &mut out).unwrap();
        if !out.is_empty() {
            return Some(out.remove(0));
        }
    }
}

/// Echoes each text message as "echo: ..." until a close. Returns the
/// upgrade request head and the text messages received.
async fn echo_server() -> (u16, tokio::task::JoinHandle<(String, Vec<String>)>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let head = read_head(&mut s).await;
        s.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            .await
            .unwrap();
        let mut d = Decoder::new(1 << 20);
        let mut texts = Vec::new();
        while let Some(m) = next_message(&mut s, &mut d).await {
            match m.opcode {
                ws::TEXT => {
                    let t = String::from_utf8(m.payload).unwrap();
                    s.write_all(&ws::encode_frame(ws::TEXT, format!("echo: {t}").as_bytes(), None)).await.unwrap();
                    texts.push(t);
                }
                ws::PING => s.write_all(&ws::encode_frame(ws::PONG, &m.payload, None)).await.unwrap(),
                ws::CLOSE => {
                    let _ = s.write_all(&ws::encode_frame(ws::CLOSE, &m.payload, None)).await;
                    break;
                }
                _ => {}
            }
        }
        (head, texts)
    });
    (port, task)
}

async fn wait_held(q: &InterceptQueue) -> Held {
    for _ in 0..200 {
        if let Some(h) = q.held().into_iter().next() {
            return h;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("nothing was held");
}

fn masked(opcode: u8, text: &str) -> Vec<u8> {
    ws::encode_frame(opcode, text.as_bytes(), Some([0x11, 0x22, 0x33, 0x44]))
}

#[tokio::test]
async fn messages_are_held_edited_and_dropped_both_ways() {
    let dir = std::env::temp_dir().join(format!("pm-wsi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.pmproj");
    let ca = Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let q = Arc::new(InterceptQueue::new());
    q.set_settings(InterceptSettings {
        enabled: true,
        requests: false,
        websocket: true,
        in_scope_only: false,
        ..Default::default()
    });
    let hooks = Hooks { intercept: Some(q.clone()), ..Default::default() };
    let proxy = Proxy::with_hooks(ca, recorder, false, hooks).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));

    let (port, server) = echo_server().await;
    let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    c.write_all(
        format!(
            "GET http://127.0.0.1:{port}/chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    assert!(read_head(&mut c).await.starts_with("HTTP/1.1 101"));
    let mut d = Decoder::new(1 << 20);

    // Browser → server, edited.
    c.write_all(&masked(ws::TEXT, "one")).await.unwrap();
    let h = wait_held(&q).await;
    assert_eq!((h.kind, h.method.as_str(), h.path.as_str(), h.raw.as_str()), (Kind::WsToServer, "WS", "/chat", "one"));
    assert!(q.decide(h.id, Decision::Forward(Some(b"ONE (edited)".to_vec()))));
    // Server → browser, held too, forwarded unchanged.
    let h = wait_held(&q).await;
    assert_eq!((h.kind, h.raw.as_str()), (Kind::WsToClient, "echo: ONE (edited)"));
    assert!(q.decide(h.id, Decision::Forward(None)));
    let m = next_message(&mut c, &mut d).await.unwrap();
    assert_eq!(m.payload, b"echo: ONE (edited)");

    // Dropped: never reaches the server.
    c.write_all(&masked(ws::TEXT, "secret")).await.unwrap();
    let h = wait_held(&q).await;
    assert!(q.decide(h.id, Decision::Drop));

    // Control frames aren't held.
    c.write_all(&masked(ws::PING, "p")).await.unwrap();
    let m = next_message(&mut c, &mut d).await.unwrap();
    assert_eq!((m.opcode, m.payload.as_slice()), (ws::PONG, &b"p"[..]));

    // A fragmented message is held once, whole.
    let mut frag = ws::encode_frame(ws::TEXT, b"th", Some([1, 2, 3, 4]));
    frag[0] &= 0x7f; // not FIN
    let mut rest = ws::encode_frame(ws::CONTINUATION, b"ree", Some([5, 6, 7, 8]));
    frag.append(&mut rest);
    c.write_all(&frag).await.unwrap();
    let h = wait_held(&q).await;
    assert_eq!(h.raw, "three");
    q.decide(h.id, Decision::Forward(None));
    let h = wait_held(&q).await;
    q.decide(h.id, Decision::Forward(None));
    assert_eq!(next_message(&mut c, &mut d).await.unwrap().payload, b"echo: three");

    c.write_all(&ws::encode_frame(ws::CLOSE, &ws::close_payload(1000, ""), Some([9, 9, 9, 9]))).await.unwrap();
    let (head, texts) = tokio::time::timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
    assert!(!head.to_ascii_lowercase().contains("sec-websocket-extensions"), "opened without compression: {head}");
    assert_eq!(texts, ["ONE (edited)", "three"], "the edit arrived, the dropped message didn't");

    for _ in 0..100 {
        let s = Store::open(&project).unwrap();
        if let Some(e) = s.list_exchanges(1, None).unwrap().first() {
            let msgs = s.ws_messages(e.id, None, 50).unwrap();
            let texts: Vec<String> = msgs
                .iter()
                .filter(|m| m.opcode == ws::TEXT)
                .map(|m| String::from_utf8_lossy(&m.payload).into_owned())
                .collect();
            if texts.len() == 4 {
                assert_eq!(texts, ["ONE (edited)", "echo: ONE (edited)", "three", "echo: three"]);
                assert!(msgs.iter().any(|m| m.opcode == ws::PING) && msgs.iter().any(|m| m.opcode == ws::PONG));
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("messages were not recorded as delivered");
}
