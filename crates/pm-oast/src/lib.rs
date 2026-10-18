//! Out-of-band (OAST) callback listener.
//!
//! Payloads carry a unique token in a URL such as
//! `http://oast.example.com:8085/<token>/…`. When the target fetches it
//! (SSRF, blind XXE, blind injection that triggers a lookup), this listener
//! records the interaction. Seeing the token proves the target made the
//! request: nothing else could know it.
//!
//! This first version listens for HTTP. DNS interactions (which need a
//! domain you control) come later.

use std::net::SocketAddr;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Interaction {
    pub token: String,
    pub protocol: String,
    pub remote: String,
    pub method: String,
    pub path: String,
    pub ts_ms: i64,
    /// First bytes of the request (headers), for evidence.
    pub raw: String,
}

/// A fresh token: 20 lowercase hex characters (safe in URLs and DNS labels).
pub fn new_token() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut x =
        (pm_core::now_ms() as u64) ^ (u64::from(std::process::id()) << 32) ^ n.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    // splitmix64 finaliser, twice, for 128 bits of spread.
    let mut mix = || {
        x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    };
    format!("{:016x}{:04x}", mix(), mix() & 0xffff)
}

/// Finds a token in a path (`/<token>/...`) or a Host header (`<token>.oast.example.com`).
pub fn extract_token(path: &str, host: Option<&str>) -> Option<String> {
    let is_token = |s: &str| s.len() == 20 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    path.trim_start_matches('/')
        .split(['/', '?'])
        .next()
        .filter(|s| is_token(s))
        .or_else(|| host.and_then(|h| h.split('.').next()).filter(|s| is_token(s)))
        .map(str::to_string)
}

/// Serves until the listener fails, calling `sink` for every request that
/// carries a token.
pub async fn serve<F>(listener: TcpListener, sink: F)
where
    F: Fn(Interaction) + Send + Sync + 'static,
{
    let sink = std::sync::Arc::new(sink);
    loop {
        let Ok((mut s, remote)) = listener.accept().await else { return };
        let sink = sink.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut len = 0;
            while len < buf.len() {
                let read = tokio::time::timeout(std::time::Duration::from_secs(5), s.read(&mut buf[len..])).await;
                match read {
                    Ok(Ok(0)) | Err(_) | Ok(Err(_)) => break,
                    Ok(Ok(n)) => len += n,
                }
                if matches!(pm_http::find_head_end(&buf[..len]), Ok(Some(_))) {
                    break;
                }
            }
            if let Some(i) = interaction(&buf[..len], remote) {
                sink(i);
            }
            let _ = s
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .await;
            let _ = s.shutdown().await;
        });
    }
}

fn interaction(raw: &[u8], remote: SocketAddr) -> Option<Interaction> {
    let end = pm_http::find_head_end(raw).ok().flatten().unwrap_or(raw.len());
    let head = pm_http::parse_request_head(&raw[..end]).ok()?;
    let host = pm_http::header(&head.headers, "host").map(|h| String::from_utf8_lossy(h).into_owned());
    let token = extract_token(&head.target, host.as_deref())?;
    Some(Interaction {
        token,
        protocol: "http".into(),
        remote: remote.to_string(),
        method: head.method,
        path: head.target,
        ts_ms: pm_core::now_ms(),
        raw: String::from_utf8_lossy(&raw[..end.min(2048)]).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn tokens_are_unique_and_extractable() {
        let (a, b) = (new_token(), new_token());
        assert_ne!(a, b);
        assert_eq!(a.len(), 20);
        assert_eq!(extract_token(&format!("/{a}/x?y=1"), None), Some(a.clone()));
        assert_eq!(extract_token("/", Some(&format!("{b}.oast.example.com"))), Some(b));
        assert_eq!(extract_token("/favicon.ico", Some("oast.example.com")), None);
    }

    #[tokio::test]
    async fn records_callbacks() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        tokio::spawn(serve(l, move |i| s2.lock().unwrap().push(i)));
        let token = new_token();
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(format!("GET /{token}/meta HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes()).await.unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).await.unwrap();
        assert!(out.ends_with("ok"));
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].token.as_str(), got[0].path.as_str()), (token.as_str(), format!("/{token}/meta").as_str()));
    }
}
