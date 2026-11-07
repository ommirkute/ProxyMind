//! Encoders, decoders and hashes for the Codec tool.

use std::io::Read;

use serde::Serialize;

/// Every operation, for UIs and validation.
pub const OPS: &[&str] = &[
    "base64_encode",
    "base64_decode",
    "base64url_encode",
    "base64url_decode",
    "url_encode",
    "url_encode_all",
    "url_decode",
    "html_encode",
    "html_decode",
    "hex_encode",
    "hex_decode",
    "unicode_escape",
    "unicode_unescape",
    "gzip_decode",
    "jwt_decode",
    "sha1",
    "sha256",
    "lowercase",
    "uppercase",
    "reverse",
];

/// Largest output kept (protects against gzip bombs).
pub const MAX_OUTPUT: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError(pub String);

impl std::fmt::Display for CodecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CodecError {}

fn err<T>(m: impl Into<String>) -> Result<T, CodecError> {
    Err(CodecError(m.into()))
}

pub fn base64_decode(s: &str, url: bool) -> Result<Vec<u8>, CodecError> {
    let mut vals = Vec::with_capacity(s.len());
    for c in s.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' if !url => 62,
            b'/' if !url => 63,
            b'-' if url => 62,
            b'_' if url => 63,
            // Be lenient: accept either alphabet.
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return err(format!("not base64: {:?}", c as char)),
        };
        vals.push(v);
    }
    if vals.len() % 4 == 1 {
        return err("not base64: bad length");
    }
    let mut out = Vec::with_capacity(vals.len() * 3 / 4);
    for chunk in vals.chunks(4) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, v)| acc | (u32::from(*v) << (18 - 6 * i)));
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..chunk.len() - 1]);
    }
    Ok(out)
}

fn url_encode(s: &[u8], all: bool) -> String {
    let mut out = String::new();
    for &b in s {
        if !all && (b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn url_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (b[i], b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b'+', ..) => {
                out.push(b' ');
                i += 1;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn html_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let tail = &rest[i..];
        let end = tail.find(';').filter(|&e| e <= 10);
        let decoded = end.and_then(|e| {
            let ent = &tail[1..e];
            let c = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some('\u{a0}'),
                _ if ent.starts_with("#x") || ent.starts_with("#X") => {
                    u32::from_str_radix(&ent[2..], 16).ok().and_then(char::from_u32)
                }
                _ if ent.starts_with('#') => ent[1..].parse().ok().and_then(char::from_u32),
                _ => None,
            };
            c.map(|c| (c, e + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &tail[len..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, CodecError> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let stripped = s.trim().trim_start_matches("0x");
    if stripped.chars().any(|c| !c.is_ascii_hexdigit() && !c.is_whitespace() && c != ':') || clean.len() % 2 == 1 {
        return err("not hex");
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|_| CodecError("not hex".into())))
        .collect()
}

fn unicode_unescape(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && matches!(chars.peek(), Some('u') | Some('x')) {
            let kind = chars.next().unwrap_or('u');
            let n = if kind == 'u' { 4 } else { 2 };
            let code: String = chars.clone().take(n).collect();
            if code.len() == n
                && let Some(ch) = u32::from_str_radix(&code, 16).ok().and_then(char::from_u32)
            {
                out.push(ch);
                for _ in 0..n {
                    chars.next();
                }
                continue;
            }
            out.push('\\');
            out.push(kind);
            continue;
        }
        out.push(c);
    }
    out
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// Applies one operation.
pub fn apply(op: &str, input: &str) -> Result<String, CodecError> {
    let out = match op {
        "base64_encode" => pm_core::base64(input.as_bytes()),
        "base64_decode" => text(&base64_decode(input.trim(), false)?),
        "base64url_encode" => {
            pm_core::base64(input.as_bytes()).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string()
        }
        "base64url_decode" => text(&base64_decode(input.trim(), true)?),
        "url_encode" => url_encode(input.as_bytes(), false),
        "url_encode_all" => url_encode(input.as_bytes(), true),
        "url_decode" => text(&url_decode(input)),
        "html_encode" => input
            .chars()
            .map(|c| match c {
                '&' => "&amp;".to_string(),
                '<' => "&lt;".into(),
                '>' => "&gt;".into(),
                '"' => "&quot;".into(),
                '\'' => "&#39;".into(),
                c => c.to_string(),
            })
            .collect(),
        "html_decode" => html_decode(input),
        "hex_encode" => input.bytes().map(|b| format!("{b:02x}")).collect(),
        "hex_decode" => text(&hex_decode(input)?),
        "unicode_escape" => input
            .chars()
            .map(|c| if c.is_ascii_graphic() || c == ' ' { c.to_string() } else { format!("\\u{:04x}", c as u32) })
            .collect(),
        "unicode_unescape" => unicode_unescape(input),
        "gzip_decode" => {
            let bytes = base64_decode(input.trim(), false).unwrap_or_else(|_| input.as_bytes().to_vec());
            let mut out = Vec::new();
            flate2::read::MultiGzDecoder::new(bytes.as_slice())
                .take(MAX_OUTPUT as u64)
                .read_to_end(&mut out)
                .map_err(|e| CodecError(format!("not gzip (give raw bytes or base64): {e}")))?;
            text(&out)
        }
        "jwt_decode" => jwt(input)?,
        "sha1" => hash(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, input),
        "sha256" => hash(&ring::digest::SHA256, input),
        "lowercase" => input.to_lowercase(),
        "uppercase" => input.to_uppercase(),
        "reverse" => input.chars().rev().collect(),
        other => return err(format!("unknown operation {other}; use one of {}", OPS.join(", "))),
    };
    if out.len() > MAX_OUTPUT {
        return err("output larger than 4 MB");
    }
    Ok(out)
}

fn hash(alg: &'static ring::digest::Algorithm, s: &str) -> String {
    ring::digest::digest(alg, s.as_bytes()).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn jwt(input: &str) -> Result<String, CodecError> {
    let token = input.trim().trim_start_matches("Bearer ").trim();
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return err("a JWT has three dot-separated parts");
    }
    let part = |p: &str| -> Result<serde_json::Value, CodecError> {
        serde_json::from_slice(&base64_decode(p, true)?).map_err(|e| CodecError(format!("not JSON: {e}")))
    };
    let out = serde_json::json!({ "header": part(parts[0])?, "payload": part(parts[1])?, "signature_bytes": base64_decode(parts[2], true).map(|s| s.len()).unwrap_or(0) });
    Ok(serde_json::to_string_pretty(&out).unwrap_or_default())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Step {
    pub op: String,
    pub output: String,
}

/// Applies operations in order; stops at the first error.
pub fn chain(ops: &[String], input: &str) -> Result<Vec<Step>, CodecError> {
    let mut cur = input.to_string();
    let mut steps = Vec::new();
    for op in ops.iter().take(20) {
        cur = apply(op, &cur).map_err(|e| CodecError(format!("{op}: {e}")))?;
        steps.push(Step { op: op.clone(), output: cur.clone() });
    }
    Ok(steps)
}

fn printable(s: &str) -> bool {
    !s.is_empty()
        && s.chars().filter(|c| c.is_control() && !c.is_whitespace()).count() * 20 <= s.chars().count()
        && !s.contains('\u{fffd}')
}

/// Peels common encodings while each step gives readable text: JWT, URL,
/// HTML entities, base64 (standard or URL-safe), hex, unicode escapes.
pub fn smart_decode(input: &str) -> Vec<Step> {
    let mut cur = input.trim().to_string();
    let mut steps = Vec::new();
    for _ in 0..8 {
        let looks_jwt = cur.matches('.').count() == 2 && cur.starts_with("eyJ");
        let candidates: &[&str] = if looks_jwt {
            &["jwt_decode"]
        } else if cur.contains('%') {
            &["url_decode"]
        } else if cur.contains('&') && cur.contains(';') {
            &["html_decode"]
        } else if cur.contains("\\u") || cur.contains("\\x") {
            &["unicode_unescape"]
        } else if cur.len() >= 8 && cur.len().is_multiple_of(2) && cur.chars().all(|c| c.is_ascii_hexdigit()) {
            &["hex_decode"]
        } else if cur.len() >= 8 && cur.chars().all(|c| c.is_ascii_alphanumeric() || "+/=-_".contains(c)) {
            &["base64_decode", "base64url_decode"]
        } else {
            &[]
        };
        let next = candidates
            .iter()
            .find_map(|op| apply(op, &cur).ok().filter(|o| printable(o) && *o != cur).map(|o| (*op, o)));
        match next {
            Some((op, out)) => {
                steps.push(Step { op: op.into(), output: out.clone() });
                if op == "jwt_decode" {
                    break;
                }
                cur = out;
            }
            None => break,
        }
    }
    steps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips() {
        for op in ["base64", "base64url", "hex"] {
            let enc = apply(&format!("{op}_encode"), "héllo wörld?/+").unwrap();
            assert_eq!(apply(&format!("{op}_decode"), &enc).unwrap(), "héllo wörld?/+", "{op}");
        }
        assert_eq!(apply("url_encode", "a b&c=d/é").unwrap(), "a%20b%26c%3Dd%2F%C3%A9");
        assert_eq!(apply("url_decode", "a%20b+c%zz").unwrap(), "a b c%zz");
        assert_eq!(apply("url_encode_all", "ab").unwrap(), "%61%62");
        assert_eq!(apply("html_encode", "<a href='x'>&</a>").unwrap(), "&lt;a href=&#39;x&#39;&gt;&amp;&lt;/a&gt;");
        assert_eq!(apply("html_decode", "&lt;b&gt;&#65;&#x42;&amp;&unknown; & x").unwrap(), "<b>AB&&unknown; & x");
        assert_eq!(apply("unicode_unescape", "\\u003cscript\\x3e\\uZZ").unwrap(), "<script>\\uZZ");
        assert_eq!(apply("unicode_escape", "a<é").unwrap(), "a<\\u00e9");
        assert_eq!(apply("sha256", "abc").unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert!(apply("base64_decode", "a").is_err());
        assert!(apply("hex_decode", "xyz").is_err());
        assert!(apply("nope", "x").is_err());
    }

    #[test]
    fn jwt_and_gzip() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2ln";
        let out = apply("jwt_decode", &format!("Bearer {jwt}")).unwrap();
        assert!(out.contains("\"alg\": \"HS256\"") && out.contains("\"sub\": \"alice\""));
        let mut gz = Vec::new();
        {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(&mut gz, flate2::Compression::default());
            e.write_all(b"compressed text").unwrap();
        }
        assert_eq!(apply("gzip_decode", &pm_core::base64(&gz)).unwrap(), "compressed text");
    }

    #[test]
    fn chains_and_smart_decode() {
        let steps = chain(&["url_encode".into(), "base64_encode".into()], "a b").unwrap();
        assert_eq!(steps[1].output, "YSUyMGI=");
        let peeled = smart_decode("JTNDc2NyaXB0JTNF"); // base64 of %3Cscript%3E
        let ops: Vec<&str> = peeled.iter().map(|s| s.op.as_str()).collect();
        assert_eq!(ops, vec!["base64_decode", "url_decode"]);
        assert_eq!(peeled.last().unwrap().output, "<script>");
        assert!(smart_decode("plain words here").is_empty());
        assert_eq!(smart_decode("eyJhbGciOiJub25lIn0.eyJhIjoxfQ.")[0].op, "jwt_decode");
    }
}
