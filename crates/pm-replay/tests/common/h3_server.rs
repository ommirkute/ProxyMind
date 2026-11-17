//! An in-process HTTP/3 server for tests (quinn + h3, a self-signed certificate for `localhost`). Also built as the
//! `h3_server` example, which the browser test starts.
//!
//! Every request is answered `201` with `x-proto: h3`, `x-sni: <server name the client asked for>` and
//! `alt-svc: h3=":<port>"`, and a body `"<METHOD> <path> <authority> <request body>"`. Special paths:
//! `/big?n=BYTES` answers BYTES bytes of `x`, `/slow` waits 3 s first, `/trailers` ends with a trailer.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

pub struct H3Server {
    pub addr: SocketAddr,
    /// QUIC connections accepted so far.
    pub connections: Arc<AtomicUsize>,
    /// Requests answered so far.
    pub requests: Arc<AtomicUsize>,
    endpoint: quinn::Endpoint,
}

impl H3Server {
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"bye");
    }
}

/// Starts a server on `bind` (for example `127.0.0.1:0`) inside the current Tokio runtime.
pub fn start(bind: SocketAddr) -> H3Server {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
    let endpoint = quinn::Endpoint::server(quinn::ServerConfig::with_crypto(Arc::new(quic)), bind).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let (ep, conns, reqs, port) = (endpoint.clone(), connections.clone(), requests.clone(), addr.port());
    tokio::spawn(async move {
        while let Some(incoming) = ep.accept().await {
            let (conns, reqs) = (conns.clone(), reqs.clone());
            tokio::spawn(async move {
                let Ok(conn) = incoming.await else { return };
                conns.fetch_add(1, Ordering::SeqCst);
                let sni = conn
                    .handshake_data()
                    .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                    .and_then(|d| d.server_name.clone())
                    .unwrap_or_default();
                let Ok(mut h3) = h3::server::Connection::new(h3_quinn::Connection::new(conn)).await else { return };
                while let Ok(Some(resolver)) = h3.accept().await {
                    let (sni, reqs) = (sni.clone(), reqs.clone());
                    tokio::spawn(async move {
                        let Ok((req, mut stream)) = resolver.resolve_request().await else { return };
                        let mut body = Vec::new();
                        while let Ok(Some(mut c)) = stream.recv_data().await {
                            while c.has_remaining() {
                                let n = c.chunk().len();
                                body.extend_from_slice(c.chunk());
                                c.advance(n);
                            }
                        }
                        reqs.fetch_add(1, Ordering::SeqCst);
                        let path = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("").to_string();
                        let authority = req.uri().authority().map(|a| a.as_str()).unwrap_or("").to_string();
                        let payload: Vec<u8> = if let Some(n) = path.strip_prefix("/big?n=") {
                            vec![b'x'; n.parse().unwrap_or(0)]
                        } else {
                            let mut out = format!("{} {path} {authority} ", req.method()).into_bytes();
                            out.extend_from_slice(&body);
                            out
                        };
                        if path == "/slow" {
                            tokio::time::sleep(Duration::from_secs(3)).await;
                        }
                        let alt = format!("h3=\":{port}\"; ma=60");
                        let resp = http::Response::builder()
                            .status(201)
                            .header("x-proto", "h3")
                            .header("x-sni", sni)
                            .header("alt-svc", alt)
                            .body(())
                            .unwrap();
                        let _ = stream.send_response(resp).await;
                        let _ = stream.send_data(Bytes::from(payload)).await;
                        if path == "/trailers" {
                            let mut t = http::HeaderMap::new();
                            t.insert("x-trailer", "end".parse().unwrap());
                            let _ = stream.send_trailers(t).await;
                        }
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    H3Server { addr, connections, requests, endpoint }
}
