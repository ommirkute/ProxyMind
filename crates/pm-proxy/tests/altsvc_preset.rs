//! The "Remove HTTP/3 advertisements" preset through the real proxy (ADR-0021): the client gets a response without
//! the h3 alternatives, other Alt-Svc values stay, and history keeps the server's original response next to the copy
//! that was delivered.

use std::sync::Arc;
use std::time::Duration;

use pm_proxy::{Hooks, Proxy, Recorder, Rewriter};
use pm_store::Store;
use pm_tls::CertAuthority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const ORIGINAL: &str = "HTTP/1.1 200 OK\r\nAlt-Svc: h3=\":443\"; ma=86400, h2=\"alt.example:8443\"; ma=60, h3-29=\":443\"\r\n\
                        Content-Length: 2\r\nConnection: close\r\n\r\nok";

async fn backend() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _ = s.read(&mut buf).await;
                let _ = s.write_all(ORIGINAL.as_bytes()).await;
            });
        }
    });
    port
}

async fn proxy_with(rules: Option<Vec<pm_proxy::RewriteRule>>) -> (u16, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("pm-altsvc-{}-{}", rules.is_some(), std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ca = Arc::new(CertAuthority::load_or_create(&dir).unwrap());
    let project = dir.join("p.pmproj");
    let (recorder, _w) = Recorder::spawn(Store::open(&project).unwrap());
    let rewrite = rules.map(|rules| {
        let rw = Arc::new(Rewriter::new());
        rw.set_rules(rules).unwrap();
        rw
    });
    let proxy = Proxy::with_hooks(ca, recorder, false, Hooks { rewrite, ..Default::default() }).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));
    (port, project)
}

async fn get(proxy: u16, backend: u16) -> String {
    let mut c = TcpStream::connect(("127.0.0.1", proxy)).await.unwrap();
    c.write_all(format!("GET http://127.0.0.1:{backend}/a HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
    let mut out = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), c.read_to_string(&mut out)).await;
    out
}

async fn recorded(project: &std::path::Path) -> pm_store::Exchange {
    for _ in 0..100 {
        let s = Store::open(project).unwrap();
        if let Some(e) = s.list_exchanges(1, None).unwrap().first() {
            return s.get_exchange(e.id).unwrap().unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not recorded");
}

#[tokio::test]
async fn the_preset_is_opt_in_and_the_original_is_recorded() {
    let backend = backend().await;

    // Nothing changes until a person adds the preset (ADR-0002): no rules, the bytes are the server's.
    let (plain, project) = proxy_with(None).await;
    let out = get(plain, backend).await;
    assert!(out.contains("h3=\":443\"") && out.contains("h3-29"), "{out}");
    let ex = recorded(&project).await;
    assert!(ex.response_delivered.is_none() && ex.changes.is_empty());

    // With the preset (made to apply to every host here): the client sees only the h2 alternative.
    let mut rules = pm_proxy::presets::presets().into_iter().find(|p| p.id == "no_http3").unwrap().rules;
    rules.iter_mut().for_each(|r| r.in_scope_only = false);
    let (proxy, project) = proxy_with(Some(rules)).await;
    let out = get(proxy, backend).await;
    assert!(out.contains("\r\nAlt-Svc: h2=\"alt.example:8443\"; ma=60\r\n"), "{out}");
    assert!(!out.contains("h3"), "no h3 alternative reaches the client: {out}");
    assert!(out.ends_with("\r\n\r\nok"));

    let ex = recorded(&project).await;
    let recorded_original = String::from_utf8(ex.response.clone().unwrap()).unwrap();
    assert!(
        recorded_original.contains("h3=\":443\"; ma=86400") && recorded_original.contains("h3-29"),
        "{recorded_original}"
    );
    let delivered = String::from_utf8(ex.response_delivered.clone().expect("delivered copy kept")).unwrap();
    assert!(!delivered.contains("h3") && delivered.contains("h2=\"alt.example:8443\""), "{delivered}");
    assert!(ex.changes.iter().any(|c| c.phase == "response" && c.by == "rule" && c.name.contains("Alt-Svc h3")));
    // History can tell the original offered HTTP/3.
    assert_eq!(pm_http::h3text::alt_svc_h3(&ex.response.unwrap()).unwrap().len(), 2);
}
