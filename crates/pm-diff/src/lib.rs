//! Semantic diff of HTTP responses.
//!
//! Comparing raw bytes is useless for security testing: timestamps, CSRF
//! tokens and request ids change on every response. This crate compares
//! *meaning*:
//!
//! - JSON bodies are flattened to `path = value` pairs.
//! - HTML and text are compared by their visible words.
//! - A **noise mask**, learned by sending the same request twice, lists the
//!   parts that change on their own; they are ignored.
//!
//! The result is a similarity score (0–1) and a short summary a human or a
//! model can read.

use std::collections::{BTreeMap, BTreeSet};

use pm_ai::body::{self, Kind};
use serde::Serialize;
use serde_json::Value;

/// Parts of a response that change between identical requests.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NoiseMask {
    /// JSON paths whose values vary (e.g. `/timestamp`, `/items/0/requestId`).
    pub json_paths: BTreeSet<String>,
    /// Words that vary in text/HTML bodies.
    pub words: BTreeSet<String>,
    /// Response headers whose values vary.
    pub headers: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Diff {
    pub status: (u16, u16),
    /// 1.0 = same content (ignoring noise), 0.0 = nothing in common.
    pub similarity: f64,
    pub summary: String,
    /// Up to 20 JSON paths or words that differ (noise excluded).
    pub differences: Vec<String>,
}

/// A response broken into comparable features.
#[derive(Debug, Clone)]
pub struct Features {
    pub status: u16,
    pub kind: Kind,
    pub json: Option<BTreeMap<String, String>>,
    pub words: BTreeMap<String, usize>,
    pub headers: BTreeMap<String, String>,
    pub body_len: usize,
}

pub fn features(response: &[u8]) -> Features {
    let (head, body_raw) = pm_http::split_message(response);
    let parsed = pm_http::parse_response_head(head).ok();
    let status = parsed.as_ref().map_or(0, |h| h.status);
    let headers_list = parsed.map(|h| h.headers).unwrap_or_default();
    let decoded = body::decode(&headers_list, body_raw);
    let headers = headers_list
        .iter()
        .filter(|h| !h.name.eq_ignore_ascii_case("date") && !h.name.eq_ignore_ascii_case("content-length"))
        .map(|h| (h.name.to_ascii_lowercase(), String::from_utf8_lossy(&h.value).into_owned()))
        .collect();
    let text = String::from_utf8_lossy(&decoded.bytes);
    let json = (decoded.kind == Kind::Json).then(|| serde_json::from_str::<Value>(&text).ok()).flatten().map(|v| {
        let mut m = BTreeMap::new();
        flatten("", &v, &mut m);
        m
    });
    let visible = if decoded.kind == Kind::Html { strip_tags(&text) } else { text.into_owned() };
    let mut words = BTreeMap::new();
    if json.is_none() {
        for w in visible.split(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '-' && c != '_') {
            let w = w.trim_matches('.');
            if !w.is_empty() {
                *words.entry(w.to_string()).or_insert(0) += 1;
            }
        }
    }
    Features { status, kind: decoded.kind, json, words, headers, body_len: decoded.bytes.len() }
}

fn flatten(prefix: &str, v: &Value, out: &mut BTreeMap<String, String>) {
    match v {
        Value::Object(o) if !o.is_empty() => {
            for (k, x) in o {
                flatten(&format!("{prefix}/{}", k.replace('~', "~0").replace('/', "~1")), x, out);
            }
        }
        Value::Array(a) if !a.is_empty() => {
            for (i, x) in a.iter().enumerate() {
                flatten(&format!("{prefix}/{i}"), x, out);
            }
        }
        other => {
            out.insert(if prefix.is_empty() { "/".into() } else { prefix.to_string() }, other.to_string());
        }
    }
}

fn strip_tags(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let (mut in_tag, mut skip_until): (bool, Option<&str>) = (false, None);
    let lower = html.to_ascii_lowercase();
    let mut i = 0;
    let b = html.as_bytes();
    while i < b.len() {
        if let Some(end) = skip_until {
            match lower[i..].find(end) {
                Some(p) => {
                    i += p + end.len();
                    skip_until = None;
                    continue;
                }
                None => break,
            }
        }
        let c = b[i];
        if c == b'<' {
            if lower[i..].starts_with("<script") {
                skip_until = Some("</script>");
            } else if lower[i..].starts_with("<style") {
                skip_until = Some("</style>");
            }
            in_tag = true;
            out.push(' ');
        } else if c == b'>' && in_tag {
            in_tag = false;
        } else if !in_tag {
            let ch_len = html[i..].chars().next().map_or(1, char::len_utf8);
            out.push_str(&html[i..i + ch_len]);
            i += ch_len;
            continue;
        }
        i += 1;
    }
    out
}

/// Learns the noise mask from two responses to the *same* request.
pub fn learn_noise(a: &[u8], b: &[u8]) -> NoiseMask {
    let (fa, fb) = (features(a), features(b));
    let mut mask = NoiseMask::default();
    if let (Some(ja), Some(jb)) = (&fa.json, &fb.json) {
        for k in ja.keys().chain(jb.keys()) {
            if ja.get(k) != jb.get(k) {
                mask.json_paths.insert(k.clone());
            }
        }
    }
    for w in fa.words.keys().chain(fb.words.keys()) {
        if fa.words.get(w) != fb.words.get(w) {
            mask.words.insert(w.clone());
        }
    }
    for h in fa.headers.keys().chain(fb.headers.keys()) {
        if fa.headers.get(h) != fb.headers.get(h) {
            mask.headers.insert(h.clone());
        }
    }
    mask
}

/// Compares two responses, ignoring `noise`.
pub fn diff(a: &[u8], b: &[u8], noise: &NoiseMask) -> Diff {
    diff_features(&features(a), &features(b), noise)
}

pub fn diff_features(fa: &Features, fb: &Features, noise: &NoiseMask) -> Diff {
    let mut differences = Vec::new();
    let similarity = match (&fa.json, &fb.json) {
        (Some(ja), Some(jb)) => {
            let keys: BTreeSet<&String> =
                ja.keys().chain(jb.keys()).filter(|k| !noise.json_paths.contains(*k)).collect();
            let same = keys.iter().filter(|k| ja.get(**k) == jb.get(**k)).count();
            for k in keys.iter().filter(|k| ja.get(**k) != jb.get(**k)).take(20) {
                differences.push((*k).clone());
            }
            if keys.is_empty() { 1.0 } else { same as f64 / keys.len() as f64 }
        }
        (None, None) => {
            let words: BTreeSet<&String> =
                fa.words.keys().chain(fb.words.keys()).filter(|w| !noise.words.contains(*w)).collect();
            let (mut inter, mut union) = (0usize, 0usize);
            for w in &words {
                let (x, y) = (fa.words.get(*w).copied().unwrap_or(0), fb.words.get(*w).copied().unwrap_or(0));
                inter += x.min(y);
                union += x.max(y);
                if x != y && differences.len() < 20 {
                    differences.push((*w).clone());
                }
            }
            if union == 0 {
                if fa.body_len == 0 && fb.body_len == 0 { 1.0 } else { 0.0 }
            } else {
                inter as f64 / union as f64
            }
        }
        _ => {
            differences.push("body type differs (JSON vs non-JSON)".into());
            0.0
        }
    };
    let similarity = (similarity * 1000.0).round() / 1000.0;
    let status_part = if fa.status == fb.status {
        format!("same status {}", fa.status)
    } else {
        format!("status {} vs {}", fa.status, fb.status)
    };
    let noise_n = noise.json_paths.len() + noise.words.len();
    let summary = format!(
        "{status_part}; {:.0}% similar{}{}",
        similarity * 100.0,
        if differences.is_empty() {
            String::new()
        } else {
            format!("; differs at {}", differences.iter().take(5).cloned().collect::<Vec<_>>().join(", "))
        },
        if noise_n > 0 { format!(" ({noise_n} noisy fields ignored)") } else { String::new() }
    );
    Diff { status: (fa.status, fb.status), similarity, summary, differences }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(status: u16, body: &str) -> Vec<u8> {
        format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nDate: now\r\n\r\n{body}").into_bytes()
    }

    #[test]
    fn noise_is_learned_and_ignored() {
        let a1 = json(200, r#"{"id":7,"owner":"alice","email":"a@x","ts":1,"req":"r1"}"#);
        let a2 = json(200, r#"{"id":7,"owner":"alice","email":"a@x","ts":2,"req":"r2"}"#);
        let noise = learn_noise(&a1, &a2);
        assert_eq!(noise.json_paths, ["/req".to_string(), "/ts".to_string()].into());
        let other = json(200, r#"{"id":7,"owner":"alice","email":"a@x","ts":9,"req":"r9"}"#);
        assert_eq!(diff(&a1, &other, &noise).similarity, 1.0);
        let bob = json(200, r#"{"id":8,"owner":"bob","email":"b@x","ts":3,"req":"r3"}"#);
        let d = diff(&a1, &bob, &noise);
        assert!(d.similarity < 0.1, "{d:?}");
        assert!(d.differences.contains(&"/owner".to_string()));
    }

    #[test]
    fn html_compares_visible_words() {
        let page = |name: &str, csrf: &str| {
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><script>var x=1;</script>\
                 <h1>Order 42</h1><p>Customer: {name}</p><input name=csrf value={csrf}></html>"
            )
            .into_bytes()
        };
        let d = diff(&page("alice", "aaa"), &page("alice", "bbb"), &NoiseMask::default());
        assert_eq!(d.similarity, 1.0, "csrf token is in a tag, not visible text");
        let d = diff(&page("alice", "aaa"), &page("bob", "aaa"), &NoiseMask::default());
        assert!(d.similarity > 0.5 && d.similarity < 1.0, "{d:?}");
    }

    #[test]
    fn status_and_type_changes_show_up() {
        let d = diff(&json(200, "{}"), b"HTTP/1.1 403 Forbidden\r\n\r\nno", &NoiseMask::default());
        assert_eq!(d.status, (200, 403));
        assert_eq!(d.similarity, 0.0);
    }
}
