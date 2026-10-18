//! Requests written as HTTP/2 text: sent over HTTP/2 when the server speaks
//! it, downgraded to HTTP/1.1 when it doesn't.

use std::sync::Arc;

use bytes::Bytes;
use pm_replay::{Endpoint, Sender};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// Answers every stream with "METHOD path authority body".
async fn serve_h2<T: AsyncRead + AsyncWrite + Unpin>(io: T) {
    let mut conn = h2::server::handshake(io).await.unwrap();
    while let Some(Ok((req, mut respond))) = conn.accept().await {
        tokio::spawn(async move {
            let (parts, mut body) = req.into_parts();
            let mut data = Vec::new();
            while let Some(Ok(c)) = body.data().await {
                let _ = body.flow_control().release_capacity(c.len());
                data.extend_from_slice(&c);
            }
            let text = format!(
                "{} {} {} {}",
                parts.method,
                parts.uri.path_and_query().map(|p| p.as_str()).unwrap_or(""),
                parts.uri.authority().map(|a| a.as_str()).unwrap_or(""),
                String::from_utf8_lossy(&data)
            );
            let resp = http::Response::builder().status(201).header("x-proto", "h2").body(()).unwrap();
            let mut s = respond.send_response(resp, false).unwrap();
            s.send_data(Bytes::from(text), true).unwrap();
        });
    }
}

fn tls_acceptor(alpn: &[&[u8]]) -> pm_tls::TlsAcceptor {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    cfg.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    pm_tls::TlsAcceptor::from(Arc::new(cfg))
}

const REQ: &[u8] = b"POST /echo?x=1 HTTP/2\r\nhost: localhost\r\ncontent-type: text/plain\r\n\r\nhello";

#[tokio::test]
async fn http2_over_tls_with_alpn() {
    let acceptor = tls_acceptor(&[b"h2"]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (t, _) = l.accept().await.unwrap();
        serve_h2(acceptor.accept(t).await.unwrap()).await;
    });
    let r =
        Sender::new(false).unwrap().send(&Endpoint::new("https", "localhost", port), REQ, "POST", None).await.unwrap();
    let text = String::from_utf8(r.raw.clone()).unwrap();
    assert!(text.starts_with("HTTP/2 201\r\n") && text.contains("x-proto: h2\r\n"), "{text}");
    assert!(text.ends_with("POST /echo?x=1 localhost hello"), "{text}");
    assert_eq!(r.head.status, 201);
    assert!(r.sent.is_none());
}

#[tokio::test]
async fn h2c_with_prior_knowledge() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (t, _) = l.accept().await.unwrap();
        serve_h2(t).await;
    });
    let req = b"GET /plain HTTP/2\r\naccept: */*\r\n\r\n";
    let r =
        Sender::new(false).unwrap().send(&Endpoint::new("http", "127.0.0.1", port), req, "GET", None).await.unwrap();
    assert!(String::from_utf8_lossy(&r.raw).ends_with(&format!("GET /plain 127.0.0.1:{port} ")));
}

#[tokio::test]
async fn http1_only_servers_get_a_downgraded_request() {
    let acceptor = tls_acceptor(&[b"http/1.1"]);
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (t, _) = l.accept().await.unwrap();
        let mut t = acceptor.accept(t).await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = t.read(&mut buf).await.unwrap();
        t.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1").await.unwrap();
        buf.truncate(n);
        buf
    });
    let r =
        Sender::new(false).unwrap().send(&Endpoint::new("https", "localhost", port), REQ, "POST", None).await.unwrap();
    let expected =
        b"POST /echo?x=1 HTTP/1.1\r\nHost: localhost\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello";
    assert_eq!(server.await.unwrap(), expected);
    assert_eq!(r.sent.as_deref(), Some(&expected[..]), "the caller learns what was really sent");
    assert!(r.raw.ends_with(b"h1"));
}
