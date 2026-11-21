//! The setup page phones open: answered by the proxy itself, never forwarded, never recorded.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pm_proxy::{Proxy, Recorder};
use pm_store::Store;
use pm_tls::CertAuthority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Setup {
    proxy: u16,
    backend: u16,
    hits: Arc<AtomicUsize>,
    ca: Arc<CertAuthority>,
    project: std::path::PathBuf,
}

async fn start(name: &str) -> Setup {
    let hits = Arc::new(AtomicUsize::new(0));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = l.local_addr().unwrap().port();
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut t, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                let _ = t.read(&mut b).await;
                let _ = t.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await;
            });
        }
    });
    let dir = std::env::temp_dir().join(format!("pm-setup-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let project = dir.join("p.pmproj");
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let proxy = Proxy::new(ca.clone(), recorder, false).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));
    Setup { proxy: port, backend, hits, ca, project }
}

/// Sends raw bytes to the proxy and returns the whole response (the request asks for `Connection: close`).
async fn raw(proxy: u16, request: &str) -> Vec<u8> {
    let mut c = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    c.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await;
    out
}

fn split(resp: &[u8]) -> (String, Vec<u8>) {
    let end = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("a response head") + 4;
    (String::from_utf8_lossy(&resp[..end]).to_string(), resp[end..].to_vec())
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim()))
}

#[tokio::test]
async fn the_setup_host_is_answered_locally_never_forwarded_and_never_recorded() {
    let s = start("local").await;
    // Absolute-form, as a phone with its proxy set sends it.
    let page =
        raw(s.proxy, "GET http://proxymind.setup/ HTTP/1.1\r\nHost: proxymind.setup\r\nConnection: close\r\n\r\n")
            .await;
    let (head, body) = split(&page);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(header(&head, "content-type").unwrap().starts_with("text/html"));
    let html = String::from_utf8(body).unwrap();
    assert!(html.contains(&s.ca.ca_fingerprint()), "shows the fingerprint");
    assert!(html.contains("href=\"/ca.crt\"") && html.contains("href=\"/ca.pem\""));
    assert!(html.contains("Android") && html.contains("iPhone"));
    assert!(!html.to_ascii_lowercase().contains("<script"), "no scripts");
    assert!(header(&head, "content-security-policy").unwrap().contains("default-src 'none'"));
    assert!(!html.contains("pm2_") && !html.to_ascii_lowercase().contains("token"), "nothing secret");

    // The CA downloads: PEM as a file, DER as the type phones install from.
    let pem = raw(
        s.proxy,
        "GET http://proxymind.setup/ca.pem HTTP/1.1\r\nHost: proxymind.setup\r\nConnection: close\r\n\r\n",
    )
    .await;
    let (head, body) = split(&pem);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(header(&head, "content-type"), Some("application/x-pem-file"));
    assert!(header(&head, "content-disposition").unwrap().contains("proxymind-ca.pem"));
    assert_eq!(body, s.ca.ca_pem().as_bytes());
    let crt = raw(
        s.proxy,
        "GET http://proxymind.setup/ca.crt HTTP/1.1\r\nHost: proxymind.setup\r\nConnection: close\r\n\r\n",
    )
    .await;
    let (head, body) = split(&crt);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(header(&head, "content-type"), Some("application/x-x509-ca-cert"));
    assert_eq!(header(&head, "content-length"), Some(body.len().to_string().as_str()));
    assert_eq!(body, s.ca.ca_der(), "DER, not PEM");
    assert_eq!(body[0], 0x30, "an ASN.1 sequence");

    // Origin-form with a Host header (no proxy configured yet), a bare `proxymind`, a query, HEAD, and the
    // listener's own address all reach the same page.
    let by_host = raw(s.proxy, "GET /?x=1 HTTP/1.1\r\nHost: PROXYMIND.setup\r\nConnection: close\r\n\r\n").await;
    assert!(split(&by_host).0.starts_with("HTTP/1.1 200"));
    let bare =
        raw(s.proxy, "GET http://proxymind/ca.crt HTTP/1.1\r\nHost: proxymind\r\nConnection: close\r\n\r\n").await;
    assert_eq!(split(&bare).1, s.ca.ca_der());
    let own = format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n", s.proxy);
    let (head, body) = split(&raw(s.proxy, &own).await);
    assert!(head.starts_with("HTTP/1.1 200"), "the proxy's own address is not a request loop: {head}");
    assert!(String::from_utf8(body).unwrap().contains("ProxyMind setup"));
    let h = raw(
        s.proxy,
        "HEAD http://proxymind.setup/ca.pem HTTP/1.1\r\nHost: proxymind.setup\r\nConnection: close\r\n\r\n",
    )
    .await;
    let (head, body) = split(&h);
    assert!(head.starts_with("HTTP/1.1 200") && body.is_empty());
    assert_eq!(header(&head, "content-length"), Some(s.ca.ca_pem().len().to_string().as_str()));

    // Other paths and methods are answered here too (not forwarded to a host that does not exist).
    let nf = raw(
        s.proxy,
        "GET http://proxymind.setup/api/v1/anything HTTP/1.1\r\nHost: proxymind.setup\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(split(&nf).0.starts_with("HTTP/1.1 404"));
    let post = raw(s.proxy, "POST http://proxymind.setup/ca.pem HTTP/1.1\r\nHost: proxymind.setup\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc").await;
    let (head, _) = split(&post);
    assert!(head.starts_with("HTTP/1.1 405") && header(&head, "allow") == Some("GET, HEAD"), "{head}");

    // Inside a CONNECT tunnel (plain HTTP after the tunnel opens): still local, never a pass-through.
    let tunnel = "CONNECT proxymind.setup:80 HTTP/1.1\r\nHost: proxymind.setup:80\r\n\r\nGET /ca.crt HTTP/1.1\r\nHost: proxymind.setup\r\nConnection: close\r\n\r\n";
    let mut c = TcpStream::connect(("127.0.0.1", s.proxy)).await.unwrap();
    let (connect, rest) = tunnel.split_once("\r\n\r\n").unwrap();
    c.write_all(format!("{connect}\r\n\r\n").as_bytes()).await.unwrap();
    let mut est = vec![0u8; "HTTP/1.1 200 Connection Established\r\n\r\n".len()];
    c.read_exact(&mut est).await.unwrap();
    c.write_all(rest.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), c.read_to_end(&mut out)).await;
    assert_eq!(split(&out).1, s.ca.ca_der());

    // Nothing above reached the backend or the history; a normal request still does (and carries the client).
    assert_eq!(s.hits.load(Ordering::SeqCst), 0);
    let ok = raw(
        s.proxy,
        &format!("GET http://127.0.0.1:{}/real HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", s.backend),
    )
    .await;
    assert!(ok.ends_with(b"ok"));
    for _ in 0..100 {
        if !Store::open(&s.project).unwrap().list_exchanges(50, None).unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let rows = Store::open(&s.project).unwrap().list_exchanges(50, None).unwrap();
    assert_eq!(rows.len(), 1, "only the real request was recorded: {rows:?}");
    assert_eq!(rows[0].path, "/real");
    assert_eq!(rows[0].client_addr.as_deref(), Some("127.0.0.1"), "the peer address is recorded");
    assert_eq!(s.hits.load(Ordering::SeqCst), 1);
}
