//! Helpers shared by the capture-mode tests (SOCKS5 and transparent mode).
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use pm_proxy::{Hooks, Proxy, Recorder};
use pm_replay::{NetConfig, Network};
use pm_store::Store;
use pm_tls::CertAuthority;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub struct Setup {
    pub proxy: Arc<Proxy>,
    pub ca: Arc<CertAuthority>,
    pub project: std::path::PathBuf,
}

pub async fn setup(name: &str, net: NetConfig) -> Setup {
    let dir = std::env::temp_dir().join(format!("pm-cap-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let project = dir.join("p.pmproj");
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let network = Network::new();
    network.set(net).unwrap();
    let hooks = Hooks { network: Some(network), ..Default::default() };
    let proxy = Proxy::with_hooks(ca.clone(), recorder, false, hooks).unwrap();
    Setup { proxy, ca, project }
}

pub async fn listener() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    (l, port)
}

/// The demo shop (VulnShop) on a local port.
pub async fn demo() -> u16 {
    pm_demo::VulnShop::start_local().await.unwrap().port()
}

/// A TLS front for `backend` (a plain TCP port on localhost) with a self-signed certificate for "localhost".
pub async fn tls_front(backend: u16) -> (u16, CertificateDer<'static>) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()]).unwrap().self_signed(&key).unwrap();
    let der = CertificateDer::from(cert.der().to_vec());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![der.clone()], PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())))
        .unwrap();
    let acceptor = pm_tls::TlsAcceptor::from(Arc::new(cfg));
    let (l, port) = listener().await;
    tokio::spawn(async move {
        while let Ok((t, _)) = l.accept().await {
            let a = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = a.accept(t).await else { return };
                let Ok(mut plain) = TcpStream::connect(("127.0.0.1", backend)).await else { return };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
            });
        }
    });
    (port, der)
}

/// A TLS client that trusts only these certificates, offering the name `sni`.
pub async fn tls_client<S: AsyncRead + AsyncWrite + Unpin>(
    io: S,
    sni: &str,
    trust: &[CertificateDer<'static>],
) -> std::io::Result<impl AsyncRead + AsyncWrite + Unpin + use<S>> {
    let mut roots = rustls::RootCertStore::empty();
    for c in trust {
        roots.add(c.clone()).unwrap();
    }
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(pm_tls::server_name(sni).unwrap(), io).await
}

pub fn ca_certs(ca: &CertAuthority) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(ca.ca_pem().as_bytes()).map(Result::unwrap).collect()
}

pub async fn read_all<S: AsyncRead + Unpin>(mut s: S) -> String {
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
    String::from_utf8_lossy(&out).into_owned()
}

/// Rows recorded so far, oldest first, once at least `n` exist.
pub async fn recorded(project: &std::path::Path, n: usize) -> Vec<pm_store::Exchange> {
    for _ in 0..100 {
        let store = Store::open(project).unwrap();
        let mut rows = store.list_exchanges(100, None).unwrap();
        if rows.len() >= n {
            rows.sort_by_key(|r| r.id);
            return rows.iter().map(|r| store.get_exchange(r.id).unwrap().unwrap()).collect();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("fewer than {n} exchanges recorded");
}

/// Nothing new is recorded within a moment.
pub async fn nothing_recorded(project: &std::path::Path) {
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(Store::open(project).unwrap().count_exchanges().unwrap(), 0, "nothing should be recorded");
}

/// Writes the request and reads the whole response.
pub async fn get<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, request: &str) -> String {
    s.write_all(request.as_bytes()).await.unwrap();
    read_all(s).await
}
