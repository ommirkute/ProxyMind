//! The hook wire protocol (ADR-0020): one JSON object per line in each direction.
//!
//! ProxyMind to the hook: `{"v":2,"id":N,"phase":"request"|"response","exchange":{...},"raw":"<base64>"}`.
//! The hook back: `{"id":N,"action":"pass"}`, `{"id":N,"action":"replace","raw":"<base64>","note":"..."}` or
//! `{"id":N,"action":"drop"}` (requests only). What comes back is untrusted: it is validated here.

use serde::Deserialize;
use serde_json::json;

use crate::v2::HookKind;

/// Largest message a hook gets (bytes); bigger ones bypass hooks.
pub const MAX_MESSAGE: usize = 8 * 1024 * 1024;
/// Longest answer line read from a hook (a replacement of [`MAX_MESSAGE`] in base64, plus the envelope).
pub const MAX_LINE: usize = MAX_MESSAGE / 3 * 4 + 4096;
/// Longest note kept from a hook.
const MAX_NOTE: usize = 200;

/// The summary of the exchange a hook is shown (no bytes; those are `raw`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangeInfo {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub status: Option<u16>,
}

impl ExchangeInfo {
    pub fn url(&self) -> String {
        pm_core::url(&self.scheme, &self.host, self.port, &self.path)
    }
}

/// One call, as a line (with the trailing newline).
pub fn encode_call(id: u64, kind: HookKind, ex: &ExchangeInfo, raw: &[u8]) -> Vec<u8> {
    let mut exchange = json!({
        "method": ex.method, "url": ex.url(), "scheme": ex.scheme, "host": ex.host, "port": ex.port, "path": ex.path,
    });
    if let Some(s) = ex.status {
        exchange["status"] = json!(s);
    }
    let frame = json!({ "v": 2, "id": id, "phase": kind.as_str(), "exchange": exchange, "raw": pm_core::base64(raw) });
    let mut line = serde_json::to_vec(&frame).unwrap_or_default();
    line.push(b'\n');
    line
}

/// What a hook decided about one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Pass,
    Replace { raw: Vec<u8>, note: Option<String> },
    Drop,
}

/// Why an answer line is no good: with the id when it could be read (so the call it belongs to fails alone).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed {
    pub id: Option<u64>,
    pub why: String,
}

#[derive(Deserialize)]
struct RawAnswer {
    id: Option<u64>,
    action: Option<String>,
    raw: Option<String>,
    note: Option<String>,
}

/// Parses one answer line. `kind` is the phase of the call: `drop` is only valid for requests.
pub fn decode_answer(line: &[u8], kind: HookKind) -> Result<(u64, Answer), Malformed> {
    let bad = |id, why: &str| Malformed { id, why: why.to_string() };
    let a: RawAnswer = serde_json::from_slice(line).map_err(|_| bad(None, "the answer is not a JSON object"))?;
    let id = a.id.ok_or_else(|| bad(None, "the answer has no id"))?;
    let answer = match a.action.as_deref() {
        Some("pass") => Answer::Pass,
        Some("drop") if kind == HookKind::Request => Answer::Drop,
        Some("drop") => return Err(bad(Some(id), "a response hook can't drop (only request hooks can)")),
        Some("replace") => {
            let raw = a.raw.ok_or_else(|| bad(Some(id), "replace needs `raw`"))?;
            let raw = base64_decode(&raw).ok_or_else(|| bad(Some(id), "`raw` is not valid base64"))?;
            if raw.len() > MAX_MESSAGE {
                return Err(bad(Some(id), "the replacement is over 8 MB"));
            }
            let note = a.note.map(|n| clip(&n)).filter(|n| !n.is_empty());
            Answer::Replace { raw, note }
        }
        _ => return Err(bad(Some(id), "unknown action (use pass, replace or drop)")),
    };
    Ok((id, answer))
}

fn clip(s: &str) -> String {
    let s: String = s.chars().filter(|c| !c.is_control()).collect();
    if s.chars().count() <= MAX_NOTE { s } else { format!("{}…", s.chars().take(MAX_NOTE).collect::<String>()) }
}

/// Standard base64 (RFC 4648); padding optional, whitespace not allowed.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() / 4 * 3 + 3);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // Leftover bits must be zero and fewer than a byte-and-a-half (a length of 1 mod 4 is impossible).
    if s.len() % 4 == 1 || acc != 0 { None } else { Some(out) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> ExchangeInfo {
        ExchangeInfo {
            method: "POST".into(),
            scheme: "https".into(),
            host: "a.example.com".into(),
            port: 443,
            path: "/api/x?y=1".into(),
            status: None,
        }
    }

    #[test]
    fn calls_are_one_json_line() {
        let line = encode_call(7, HookKind::Request, &info(), b"POST /api/x HTTP/1.1\r\n\r\n");
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(line.iter().filter(|b| **b == b'\n').count(), 1);
        let v: serde_json::Value = serde_json::from_slice(&line).unwrap();
        assert_eq!((v["v"].as_u64(), v["id"].as_u64(), v["phase"].as_str()), (Some(2), Some(7), Some("request")));
        assert_eq!(v["exchange"]["url"], "https://a.example.com/api/x?y=1");
        assert!(v["exchange"].get("status").is_none());
        assert_eq!(base64_decode(v["raw"].as_str().unwrap()).unwrap(), b"POST /api/x HTTP/1.1\r\n\r\n");
        let mut i = info();
        i.status = Some(200);
        let v: serde_json::Value = serde_json::from_slice(&encode_call(1, HookKind::Response, &i, b"")).unwrap();
        assert_eq!((v["exchange"]["status"].as_u64(), v["phase"].as_str()), (Some(200), Some("response")));
    }

    #[test]
    fn base64_round_trips_binary() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 37 + 11) as u8).collect();
            assert_eq!(base64_decode(&pm_core::base64(&data)).unwrap(), data, "{n}");
        }
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
        assert_eq!(base64_decode("Zm8").unwrap(), b"fo", "padding is optional");
        assert!(base64_decode("Zm9v!").is_none() && base64_decode("Z").is_none() && base64_decode("Zm 9").is_none());
    }

    #[test]
    fn answers_are_decoded_and_checked() {
        let req = HookKind::Request;
        assert_eq!(decode_answer(br#"{"id":3,"action":"pass"}"#, req).unwrap(), (3, Answer::Pass));
        assert_eq!(decode_answer(br#"{"id":3,"action":"drop"}"#, req).unwrap(), (3, Answer::Drop));
        let (id, a) = decode_answer(br#"{"id":4,"action":"replace","raw":"aGk=","note":"signed\u0007"}"#, req).unwrap();
        assert_eq!((id, a), (4, Answer::Replace { raw: b"hi".to_vec(), note: Some("signed".into()) }));
        // Drop is for requests only.
        let e = decode_answer(br#"{"id":5,"action":"drop"}"#, HookKind::Response).unwrap_err();
        assert_eq!(e.id, Some(5));
        for bad in [
            &br#"{"id":1,"action":"explode"}"#[..],
            br#"{"id":1}"#,
            br#"{"id":1,"action":"replace"}"#,
            br#"{"id":1,"action":"replace","raw":"@@@"}"#,
        ] {
            assert_eq!(decode_answer(bad, req).unwrap_err().id, Some(1), "{}", String::from_utf8_lossy(bad));
        }
        for bad in [&b"garbage"[..], b"", br#"{"action":"pass"}"#, br#"[1]"#] {
            assert_eq!(decode_answer(bad, req).unwrap_err().id, None);
        }
    }
}
