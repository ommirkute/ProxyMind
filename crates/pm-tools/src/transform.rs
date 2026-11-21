//! Strict text transforms, the server-side twin of the editors' inline transforms (`ui/src/transforms.ts`, roadmap
//! 2.3). Workflows (2.2) use them on variables.
//!
//! Every operation works on text, treated as UTF-8 where bytes are involved, and fails with a message instead of
//! guessing (unlike the lenient [`crate::codec`], which backs the Codec page's "smart decode"). The operation ids,
//! the results and the failures are the same as the browser's: `testdata/transform_vectors.json` holds vectors that
//! both this module's tests and `ui/tests/transforms.test.mjs` run, so the two cannot drift apart.

use std::sync::OnceLock;

use regex::Regex;

/// Every operation id, in the order of the editor's menu.
pub const OPS: &[&str] = &[
    "url_encode",
    "url_decode",
    "url_encode_full",
    "url_decode_full",
    "base64_encode",
    "base64_decode",
    "base64url_encode",
    "base64url_decode",
    "html_encode",
    "html_decode",
    "hex_encode",
    "hex_decode",
    "unicode_encode",
    "unicode_encode_all",
    "unicode_decode",
    "json_escape",
    "json_unescape",
    "md5",
    "sha1",
    "sha256",
];

/// Why an operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransformError(pub String);

impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TransformError {}

fn fail<T>(m: impl Into<String>) -> Result<T, TransformError> {
    Err(TransformError(m.into()))
}

/// Largest input or output an operation handles (a workflow variable is far smaller).
pub const MAX_LEN: usize = 1 << 20;

/// Runs one operation by id. See [`OPS`].
pub fn apply(op: &str, input: &str) -> Result<String, TransformError> {
    if input.len() > MAX_LEN {
        return fail("the text is longer than 1 MB");
    }
    let out = match op {
        "url_encode" => url_encode(input, false),
        "url_encode_full" => url_encode(input, true),
        "url_decode" => url_decode(input, false)?,
        "url_decode_full" => url_decode(input, true)?,
        "base64_encode" => base64_encode(input.as_bytes(), false),
        "base64url_encode" => base64_encode(input.as_bytes(), true),
        "base64_decode" | "base64url_decode" => base64_decode(input)?,
        "html_encode" => html_encode(input),
        "html_decode" => html_decode(input)?,
        "hex_encode" => hex(input.as_bytes()),
        "hex_decode" => hex_decode(input)?,
        "unicode_encode" => unicode_escape(input, false),
        "unicode_encode_all" => unicode_escape(input, true),
        "unicode_decode" => unicode_unescape(input)?,
        "json_escape" => json_escape(input),
        "json_unescape" => json_unescape(input)?,
        "md5" => md5_hex(input.as_bytes()),
        "sha1" => digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, input),
        "sha256" => digest(&ring::digest::SHA256, input),
        other => return fail(format!("unknown operation {other}; use one of {}", OPS.join(", "))),
    };
    if out.len() > MAX_LEN {
        return fail("the result is longer than 1 MB");
    }
    Ok(out)
}

/// Applies operations in order and stops at the first failure (the message names the operation).
pub fn chain(ops: &[String], input: &str) -> Result<String, TransformError> {
    let mut cur = input.to_string();
    for op in ops {
        cur = apply(op, &cur).map_err(|e| TransformError(format!("{op}: {e}")))?;
    }
    Ok(cur)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest(alg: &'static ring::digest::Algorithm, s: &str) -> String {
    hex(ring::digest::digest(alg, s.as_bytes()).as_ref())
}

// ---------------------------------------------------------------- URL

/// What `encodeURIComponent` leaves alone; `encodeURI` also leaves `RESERVED`.
const UNRESERVED_MARKS: &[u8] = b"-_.!~*'()";
const RESERVED: &[u8] = b";,/?:@&=+$#";

fn url_encode(s: &str, full: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || UNRESERVED_MARKS.contains(&b) || (full && RESERVED.contains(&b)) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// `decodeURIComponent`, or with `full` `decodeURI`, which leaves escapes of reserved characters as written.
fn url_decode(s: &str, full: bool) -> Result<String, TransformError> {
    const BAD: &str =
        "Invalid percent-encoding (a % is not followed by two hex digits, or the bytes are not valid UTF-8).";
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'%' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        let byte = b
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .filter(|h| h.bytes().all(|c| c.is_ascii_hexdigit()))
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        let Some(byte) = byte else { return fail(BAD) };
        if full && byte.is_ascii() && RESERVED.contains(&byte) {
            out.extend_from_slice(&b[i..i + 3]);
        } else {
            out.push(byte);
        }
        i += 3;
    }
    String::from_utf8(out).or_else(|_| fail(BAD))
}

// ---------------------------------------------------------------- Base64

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(bytes: &[u8], url_safe: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else if !url_safe {
                out.push('=');
            }
        }
    }
    if url_safe { out.replace('+', "-").replace('/', "_") } else { out }
}

/// Accepts both alphabets, with or without padding, ignoring whitespace.
fn base64_decode(s: &str) -> Result<String, TransformError> {
    let clean: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    let clean = clean.trim_end_matches('=');
    if clean.is_empty() {
        return Ok(String::new());
    }
    if !clean.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/') {
        return fail("Not Base64: it has characters outside A-Z a-z 0-9 + / - _ =.");
    }
    if clean.len() % 4 == 1 {
        return fail("Not Base64: the length is impossible (one character too many or too few).");
    }
    let mut bytes = Vec::with_capacity(clean.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in clean.bytes() {
        let v = B64.iter().position(|&x| x == c).unwrap_or(0) as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    String::from_utf8(bytes).or_else(|_| {
        fail("The Base64 decodes to bytes that are not valid UTF-8 text (binary data), so it is left alone.")
    })
}

// ---------------------------------------------------------------- HTML

fn html_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn named_entity(name: &str) -> Option<&'static str> {
    Some(match name {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => "\u{a0}",
        "copy" => "\u{a9}",
        "reg" => "\u{ae}",
        "hellip" => "\u{2026}",
        "ndash" => "\u{2013}",
        "mdash" => "\u{2014}",
        "laquo" => "\u{ab}",
        "raquo" => "\u{bb}",
        _ => return None,
    })
}

/// Decodes numeric references and a short list of common named ones; other named entities stay as written.
fn html_decode(s: &str) -> Result<String, TransformError> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"&(?:#([0-9]{1,8})|#[xX]([0-9a-fA-F]{1,8})|([A-Za-z][A-Za-z0-9]{1,9}));").expect("valid regex")
    });
    let mut bad: Option<String> = None;
    let out = re.replace_all(s, |c: &regex::Captures| {
        if let Some(name) = c.get(3) {
            return named_entity(name.as_str()).map_or_else(|| c[0].to_string(), str::to_string);
        }
        let cp = match (c.get(1), c.get(2)) {
            (Some(d), _) => d.as_str().parse::<u32>().ok(),
            (_, Some(h)) => u32::from_str_radix(h.as_str(), 16).ok(),
            _ => None,
        };
        match cp.and_then(char::from_u32) {
            Some(ch) => ch.to_string(),
            None => {
                bad.get_or_insert_with(|| c[0].to_string());
                c[0].to_string()
            }
        }
    });
    match bad {
        Some(b) => fail(format!("{b} is not a valid character reference.")),
        None => Ok(out.into_owned()),
    }
}

// ---------------------------------------------------------------- hex

/// Accepts plain hex, with spaces, colons, commas or dashes between bytes, and 0x or \x prefixes.
fn hex_decode(s: &str) -> Result<String, TransformError> {
    static PREFIX: OnceLock<Regex> = OnceLock::new();
    static SEP: OnceLock<Regex> = OnceLock::new();
    let prefix = PREFIX.get_or_init(|| Regex::new(r"(?i)0x|\\x").expect("valid regex"));
    let sep = SEP.get_or_init(|| Regex::new(r"[\s:,\-]+").expect("valid regex"));
    let clean = sep.replace_all(&prefix.replace_all(s, ""), "").into_owned();
    if clean.is_empty() {
        return Ok(String::new());
    }
    if !clean.bytes().all(|c| c.is_ascii_hexdigit()) {
        return fail("Not hex: it has characters other than 0-9 a-f.");
    }
    if clean.len() % 2 == 1 {
        return fail("Not whole bytes: an odd number of hex digits.");
    }
    let bytes: Vec<u8> =
        (0..clean.len() / 2).map(|i| u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).unwrap_or(0)).collect();
    String::from_utf8(bytes)
        .or_else(|_| fail("The hex decodes to bytes that are not valid UTF-8 text (binary data), so it is left alone."))
}

// ---------------------------------------------------------------- Unicode

/// `\uXXXX` per UTF-16 code unit, so characters outside the BMP become a surrogate pair like JavaScript writes them.
fn unicode_escape(s: &str, all: bool) -> String {
    let mut out = String::with_capacity(s.len());
    let mut units = [0u16; 2];
    for c in s.chars() {
        for u in c.encode_utf16(&mut units) {
            if all || *u > 0x7f {
                out.push_str(&format!("\\u{u:04x}"));
            } else {
                out.push(*u as u8 as char);
            }
        }
    }
    out
}

fn unicode_unescape(s: &str) -> Result<String, TransformError> {
    let b: Vec<char> = s.chars().collect();
    let mut units: Vec<u16> = Vec::with_capacity(b.len());
    let mut i = 0;
    let hex_run =
        |from: usize, max: usize| b[from.min(b.len())..].iter().take(max).take_while(|c| c.is_ascii_hexdigit()).count();
    while i < b.len() {
        if b[i] != '\\' || b.get(i + 1) != Some(&'u') {
            let mut buf = [0u16; 2];
            units.extend_from_slice(b[i].encode_utf16(&mut buf));
            i += 1;
            continue;
        }
        let at = i;
        let (cp, len) = if b.get(i + 2) == Some(&'{') && {
            let n = hex_run(i + 3, 6);
            n >= 1 && b.get(i + 3 + n) == Some(&'}')
        } {
            let n = hex_run(i + 3, 6);
            let cp = u32::from_str_radix(&b[i + 3..i + 3 + n].iter().collect::<String>(), 16).unwrap_or(u32::MAX);
            (cp, n + 2)
        } else if hex_run(i + 2, 4) == 4 {
            (u32::from_str_radix(&b[i + 2..i + 6].iter().collect::<String>(), 16).unwrap_or(0), 4)
        } else {
            return fail(format!("Bad escape at position {at}: \\u needs four hex digits or {{hex}}."));
        };
        if cp > 0x10ffff {
            return fail("A code point is above U+10FFFF.");
        }
        match char::from_u32(cp) {
            Some(c) => {
                let mut buf = [0u16; 2];
                units.extend_from_slice(c.encode_utf16(&mut buf));
            }
            // A lone surrogate half: the matching second half joins it when both are in the text.
            None => units.push(cp as u16),
        }
        i += 2 + len;
    }
    String::from_utf16(&units).or_else(|_| fail("The text has an unpaired surrogate, which cannot be kept."))
}

// ---------------------------------------------------------------- JSON

fn json_escape(s: &str) -> String {
    let quoted = serde_json::to_string(s).unwrap_or_default();
    quoted.get(1..quoted.len().saturating_sub(1)).unwrap_or_default().to_string()
}

fn json_unescape(s: &str) -> Result<String, TransformError> {
    serde_json::from_str::<String>(&format!("\"{s}\"")).or_else(|_| {
        fail("Not a valid JSON string body: it has a raw quote, a raw line break or tab, or a bad backslash escape.")
    })
}

// ---------------------------------------------------------------- MD5

const MD5_SHIFT: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

/// MD5 of raw bytes as lowercase hex (RFC 1321). Only for matching values that use it, never for security.
pub fn md5_hex(data: &[u8]) -> String {
    let k: Vec<u32> = (0..64).map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32).collect();
    let blocks = ((data.len() + 8) >> 6) + 1;
    let mut words = vec![0u32; blocks * 16];
    for (i, &b) in data.iter().enumerate() {
        words[i >> 2] |= u32::from(b) << ((i & 3) * 8);
    }
    words[data.len() >> 2] |= 0x80 << ((data.len() & 3) * 8);
    let bits = (data.len() as u64) * 8;
    words[blocks * 16 - 2] = bits as u32;
    words[blocks * 16 - 1] = (bits >> 32) as u32;
    let (mut a0, mut b0, mut c0, mut d0) = (0x6745_2301u32, 0xefcd_ab89u32, 0x98ba_dcfeu32, 0x1032_5476u32);
    for blk in 0..blocks {
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64usize {
            let (f, g) = match i >> 4 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) & 15),
                2 => (b ^ c ^ d, (3 * i + 5) & 15),
                _ => (c ^ (b | !d), (7 * i) & 15),
            };
            let sum = a.wrapping_add(f).wrapping_add(k[i]).wrapping_add(words[blk * 16 + g]);
            let s = MD5_SHIFT[(i >> 4) * 4 + (i & 3)];
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(sum.rotate_left(s));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let mut out = Vec::with_capacity(16);
    for w in [a0, b0, c0, d0] {
        out.extend_from_slice(&w.to_le_bytes());
    }
    hex(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// The vectors the browser's tests run too (`ui/tests/transforms.test.mjs`).
    #[test]
    fn shared_vectors_agree_with_the_browser_transforms() {
        let vectors: Vec<Value> = serde_json::from_str(include_str!("../testdata/transform_vectors.json")).unwrap();
        assert!(vectors.len() >= 100, "the vector file shrank to {}", vectors.len());
        let mut ops_seen = std::collections::BTreeSet::new();
        for v in &vectors {
            let (op, input) = (v["op"].as_str().unwrap(), v["input"].as_str().unwrap());
            ops_seen.insert(op.to_string());
            let got = apply(op, input);
            if v["error"].as_bool() == Some(true) {
                assert!(got.is_err(), "{op}({input:?}) should fail, gave {got:?}");
            } else {
                assert_eq!(got.as_deref(), Ok(v["output"].as_str().unwrap()), "{op}({input:?})");
            }
        }
        for op in OPS {
            assert!(ops_seen.contains(*op), "no shared vector for {op}");
        }
    }

    #[test]
    fn md5_matches_rfc_1321_and_covers_padding_boundaries() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(md5_hex(b"message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
        assert_eq!(
            md5_hex(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
        // Lengths around the 56- and 64-byte padding boundaries (digests from the md5sum tool).
        assert_eq!(md5_hex("a".repeat(55).as_bytes()), "ef1772b6dff9a122358552954ad0df65");
        assert_eq!(md5_hex("a".repeat(56).as_bytes()), "3b0c8ac703f828b04c6c197006d17218");
        assert_eq!(md5_hex("a".repeat(64).as_bytes()), "014842d480b571495a4a0363793f7367");
    }

    #[test]
    fn chains_stop_at_the_first_failure_and_name_it() {
        let ops = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(chain(&ops(&["base64_encode", "url_encode"]), "a b").unwrap(), "YSBi");
        assert_eq!(chain(&ops(&["base64_encode", "url_encode"]), "hello?").unwrap(), "aGVsbG8%2F");
        let e = chain(&ops(&["hex_encode", "url_decode", "base64_decode"]), "x%").unwrap_err();
        assert!(e.0.starts_with("base64_decode") || e.0.starts_with("url_decode"), "{e}");
        assert!(apply("rot13", "x").unwrap_err().0.contains("unknown operation"));
    }

    #[test]
    fn unicode_pairs_join_and_lone_halves_are_refused() {
        assert_eq!(unicode_unescape("\\ud83d\\ude00").unwrap(), "\u{1F600}");
        assert_eq!(unicode_unescape("\\u{1F600}x").unwrap(), "\u{1F600}x");
        assert!(unicode_unescape("\\ud83d").is_err());
        assert!(unicode_unescape("\\u12").is_err());
    }
}
