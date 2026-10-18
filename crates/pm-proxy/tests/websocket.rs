//! WebSocket through the real proxy: bytes pass unchanged and each message
//! is logged, including permessage-deflate ones.

use std::time::Duration;

use flate2::{Compress, Compression, FlushCompress};
use pm_proxy::{Proxy, Recorder};
use pm_store::Store;
use pm_tls::CertAuthority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn deflated(text: &[u8]) -> Vec<u8> {
    let mut z = Compress::new(Compression::default(), false);
    let mut out = vec![0u8; text.len() + 64];
    z.compress(text, &mut out, FlushCompress::Sync).unwrap();
    out.truncate(z.total_out() as usize - 4); // drop the 00 00 FF FF tail
    out
}

/// What the server sends after the handshake.
fn server_frames() -> Vec<u8> {
    let data = deflated(b"hi from server");
    let mut v = vec![0xC1, data.len() as u8]; // FIN + RSV1 + text
    v.extend_from_slice(&data);
    v.extend_from_slice(&[0x88, 0x02, 0x03, 0xE8]); // close 1000
    v
}

async fn read_head(s: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await.unwrap() == 0 {
            break;
        }
        head.push(b[0]);
    }
    head
}

async fn ws_server() -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        read_head(&mut s).await;
        s.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
              Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover\r\n\r\n",
        )
        .await
        .unwrap();
        let mut got = vec![0u8; 11]; // masked "hello"
        s.read_exact(&mut got).await.unwrap();
        s.write_all(&server_frames()).await.unwrap();
        s.shutdown().await.unwrap();
        got
    });
    (port, task)
}

#[tokio::test]
async fn messages_are_relayed_unchanged_and_logged() {
    let dir = std::env::temp_dir().join(format!("pm-ws-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let project = dir.join("p.pmproj");
    let ca = std::sync::Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let proxy = Proxy::new(ca, recorder, false).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));

    let (port, server) = ws_server().await;
    let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    c.write_all(
        format!(
            "GET http://127.0.0.1:{port}/chat HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let head = read_head(&mut c).await;
    assert!(head.starts_with(b"HTTP/1.1 101"));
    let key = [0x37, 0xFA, 0x21, 0x3D];
    let mut hello = vec![0x81, 0x85];
    hello.extend_from_slice(&key);
    hello.extend(b"hello".iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    c.write_all(&hello).await.unwrap();
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut rest)).await.unwrap().unwrap();
    assert_eq!(rest, server_frames(), "server bytes reach the client unchanged");
    assert_eq!(server.await.unwrap(), hello, "client bytes reach the server unchanged");

    for _ in 0..100 {
        let s = Store::open(&project).unwrap();
        if let Some(e) = s.list_exchanges(1, None).unwrap().first()
            && s.ws_message_count(e.id).unwrap() == 3
        {
            let m = s.ws_messages(e.id, None, 10).unwrap();
            assert_eq!((m[0].from_client, m[0].opcode, m[0].payload.as_slice()), (true, 1, &b"hello"[..]));
            assert_eq!((m[1].from_client, m[1].payload.as_slice()), (false, &b"hi from server"[..]));
            assert!(!m[1].compressed, "inflated for the log");
            assert_eq!((m[2].opcode, m[2].payload.as_slice()), (8, &[0x03, 0xE8][..]));
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("WebSocket messages were not recorded");
}
