//! A minimal SMTP listener for out-of-band tests: a target that sends mail
//! to an address carrying a token (`pm@<token>.oast.example.com`, or
//! `<token>@…`) shows up as an interaction. It accepts every message and
//! delivers none. Commands, recipients and the message size are bounded,
//! and one deadline covers the whole session.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::{Interaction, is_token};

const MAX_LINE: usize = 1024;
const MAX_DATA: usize = 64 * 1024;
const MAX_RCPT: usize = 20;
const SESSION: Duration = Duration::from_secs(30);

/// Tokens in an address: any label of the domain, or the local part.
pub fn tokens_in(address: &str) -> Vec<String> {
    let a = address.trim().trim_start_matches('<').trim_end_matches('>').to_ascii_lowercase();
    let (local, domain) = a.rsplit_once('@').unwrap_or((&a, ""));
    std::iter::once(local).chain(domain.split('.')).filter(|s| is_token(s)).map(str::to_string).collect()
}

fn arg_after<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let upper = line.to_ascii_uppercase();
    upper.starts_with(prefix).then(|| line[prefix.len()..].trim().split_whitespace().next().unwrap_or(""))
}

/// Serves until the listener fails, calling `sink` once per token for every
/// message whose recipients carry one.
pub async fn serve<F>(listener: TcpListener, hostname: String, sink: F)
where
    F: Fn(Interaction) + Send + Sync + 'static,
{
    let sink = std::sync::Arc::new(sink);
    loop {
        let Ok((s, remote)) = listener.accept().await else { return };
        let (sink, host) = (sink.clone(), hostname.clone());
        tokio::spawn(async move {
            let _ = tokio::time::timeout(SESSION, session(s, remote, &host, &*sink)).await;
        });
    }
}

async fn session<F: Fn(Interaction)>(
    s: tokio::net::TcpStream,
    remote: SocketAddr,
    host: &str,
    sink: &F,
) -> std::io::Result<()> {
    let (r, mut w) = s.into_split();
    let mut r = BufReader::new(r);
    w.write_all(format!("220 {host} ESMTP ProxyMind OAST\r\n").as_bytes()).await?;
    let (mut from, mut rcpts) = (String::new(), Vec::<String>::new());
    loop {
        let mut line = String::new();
        let n = (&mut r).take(MAX_LINE as u64).read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        let line = line.trim_end().to_string();
        let upper = line.to_ascii_uppercase();
        let reply: String = if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            format!("250 {host}")
        } else if let Some(a) = arg_after(&line, "MAIL FROM:") {
            from = a.chars().take(200).collect();
            rcpts.clear();
            "250 OK".into()
        } else if let Some(a) = arg_after(&line, "RCPT TO:") {
            if rcpts.len() >= MAX_RCPT {
                "452 too many recipients".into()
            } else {
                rcpts.push(a.chars().take(200).collect());
                "250 OK".into()
            }
        } else if upper == "DATA" {
            if rcpts.is_empty() {
                "503 RCPT first".into()
            } else {
                w.write_all(b"354 end with <CRLF>.<CRLF>\r\n").await?;
                let mut data = Vec::new();
                loop {
                    let mut l = String::new();
                    let n = (&mut r).take(MAX_LINE as u64).read_line(&mut l).await?;
                    if n == 0 || l.trim_end() == "." {
                        break;
                    }
                    if data.len() < MAX_DATA {
                        data.extend_from_slice(l.as_bytes());
                    }
                }
                let message = String::from_utf8_lossy(&data[..data.len().min(2048)]).into_owned();
                let mut seen = Vec::new();
                for rc in &rcpts {
                    for t in tokens_in(rc) {
                        if seen.contains(&t) {
                            continue;
                        }
                        seen.push(t.clone());
                        sink(Interaction {
                            token: t,
                            protocol: "smtp".into(),
                            remote: remote.to_string(),
                            method: "MAIL".into(),
                            path: rc.clone(),
                            ts_ms: pm_core::now_ms(),
                            raw: format!("MAIL FROM:{from}\r\nRCPT TO:{}\r\n\r\n{message}", rcpts.join(", ")),
                        });
                    }
                }
                rcpts.clear();
                "250 OK: accepted".into()
            }
        } else if upper == "RSET" {
            rcpts.clear();
            "250 OK".into()
        } else if upper == "NOOP" {
            "250 OK".into()
        } else if upper == "QUIT" {
            w.write_all(b"221 bye\r\n").await?;
            return Ok(());
        } else {
            "502 not implemented".into()
        };
        w.write_all(format!("{reply}\r\n").as_bytes()).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;

    #[test]
    fn finds_tokens_in_addresses() {
        let t = crate::new_token();
        assert_eq!(tokens_in(&format!("<pm@{t}.oast.example.com>")), vec![t.clone()]);
        assert_eq!(tokens_in(&format!("{t}@example.com")), vec![t.clone()]);
        assert!(tokens_in("<someone@example.com>").is_empty());
    }

    #[tokio::test]
    async fn records_mail_to_a_token() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s2 = seen.clone();
        tokio::spawn(serve(l, "oast.test".into(), move |i| s2.lock().unwrap().push(i)));
        let t = crate::new_token();
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let script = format!(
            "EHLO target\r\nMAIL FROM:<app@shop.test>\r\nRCPT TO:<pm@{t}.oast.test>\r\nRCPT TO:<other@x.test>\r\nDATA\r\n\
             Subject: password reset\r\n\r\nclick here\r\n.\r\nQUIT\r\n"
        );
        c.write_all(script.as_bytes()).await.unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).await.unwrap();
        assert!(
            out.starts_with("220 oast.test") && out.contains("250 OK: accepted") && out.ends_with("221 bye\r\n"),
            "{out}"
        );
        let got = seen.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].token.as_str(), got[0].protocol.as_str()), (t.as_str(), "smtp"));
        assert!(got[0].raw.contains("Subject: password reset") && got[0].raw.contains("app@shop.test"));
    }
}
