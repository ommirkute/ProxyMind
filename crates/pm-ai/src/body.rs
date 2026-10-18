//! Decoding message bodies for display: chunked framing, compression and
//! content type. Raw bytes in the store are never changed.

use std::io::Read;

use pm_http::Header;

/// Decoded bodies larger than this are cut off (protects against zip bombs).
pub const MAX_DECODED: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Json,
    Html,
    Xml,
    Form,
    Text,
    Binary,
    Empty,
}

#[derive(Debug, Clone)]
pub struct Decoded {
    pub bytes: Vec<u8>,
    pub content_type: Option<String>,
    pub kind: Kind,
    /// Notes about decoding, e.g. "gzip decoded" or "unknown encoding br2".
    pub notes: Vec<String>,
}

pub fn decode(headers: &[Header], body: &[u8]) -> Decoded {
    let mut notes = Vec::new();
    let mut bytes = body.to_vec();
    let has_token = |name: &str, tok: &str| {
        headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .flat_map(|h| h.value.split(|&b| b == b','))
            .any(|t| t.trim_ascii().eq_ignore_ascii_case(tok.as_bytes()))
    };
    if has_token("transfer-encoding", "chunked") {
        match pm_http::decode_chunked(&bytes) {
            Some(d) => bytes = d,
            None => notes.push("chunked body is malformed; showing raw bytes".into()),
        }
    }
    if let Some(enc) = pm_http::header(headers, "content-encoding") {
        let enc = String::from_utf8_lossy(enc).trim().to_ascii_lowercase();
        let decoded = match enc.as_str() {
            "gzip" | "x-gzip" => read_capped(flate2::read::MultiGzDecoder::new(bytes.as_slice())),
            "deflate" => read_capped(flate2::read::ZlibDecoder::new(bytes.as_slice()))
                .or_else(|| read_capped(flate2::read::DeflateDecoder::new(bytes.as_slice()))),
            "br" => read_capped(brotli_decompressor::Decompressor::new(bytes.as_slice(), 4096)),
            "identity" | "" => Some(bytes.clone()),
            other => {
                notes.push(format!("unsupported content-encoding {other}; showing raw bytes"));
                None
            }
        };
        match decoded {
            Some(d) => {
                if enc != "identity" && !enc.is_empty() {
                    notes.push(format!("{enc} decoded"));
                }
                bytes = d;
            }
            None if !notes.iter().any(|n| n.starts_with("unsupported")) => {
                notes.push(format!("could not decode {enc} body; showing raw bytes"))
            }
            None => {}
        }
    }
    if bytes.len() > MAX_DECODED {
        bytes.truncate(MAX_DECODED);
        notes.push(format!("decoded body cut at {MAX_DECODED} bytes"));
    }
    let content_type = pm_http::header(headers, "content-type").map(|v| String::from_utf8_lossy(v).into_owned());
    let kind = classify(content_type.as_deref(), &bytes);
    Decoded { bytes, content_type, kind, notes }
}

fn read_capped(r: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    r.take(MAX_DECODED as u64 + 1).read_to_end(&mut out).ok()?;
    Some(out)
}

fn classify(ct: Option<&str>, bytes: &[u8]) -> Kind {
    if bytes.is_empty() {
        return Kind::Empty;
    }
    let ct = ct.unwrap_or("").to_ascii_lowercase();
    if ct.contains("json") {
        return Kind::Json;
    }
    if ct.contains("html") {
        return Kind::Html;
    }
    if ct.contains("xml") {
        return Kind::Xml;
    }
    if ct.contains("x-www-form-urlencoded") {
        return Kind::Form;
    }
    if ct.starts_with("text/") || ct.contains("javascript") || ct.contains("graphql") {
        return Kind::Text;
    }
    // Sniff when the type is missing or generic.
    let text = std::str::from_utf8(&bytes[..bytes.len().min(4096)]).is_ok()
        || bytes.iter().take(4096).filter(|b| b.is_ascii_graphic() || b.is_ascii_whitespace()).count() * 10
            > bytes.len().min(4096) * 9;
    if !text {
        return Kind::Binary;
    }
    let start = bytes.iter().find(|b| !b.is_ascii_whitespace()).copied().unwrap_or(b' ');
    match start {
        b'{' | b'[' if serde_json::from_slice::<serde_json::Value>(bytes).is_ok() => Kind::Json,
        b'<' if bytes.windows(5).take(2048).any(|w| w.eq_ignore_ascii_case(b"<html")) => Kind::Html,
        b'<' => Kind::Xml,
        _ => Kind::Text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn h(name: &str, value: &str) -> Header {
        Header { name: name.into(), value: value.as_bytes().to_vec() }
    }

    #[test]
    fn decodes_chunked_gzip_json() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(br#"{"user":"alice"}"#).unwrap();
        let gz = gz.finish().unwrap();
        let mut chunked = format!("{:x}\r\n", gz.len()).into_bytes();
        chunked.extend_from_slice(&gz);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let d = decode(
            &[h("Transfer-Encoding", "chunked"), h("Content-Encoding", "gzip"), h("Content-Type", "application/json")],
            &chunked,
        );
        assert_eq!(d.bytes, br#"{"user":"alice"}"#);
        assert_eq!(d.kind, Kind::Json);
    }

    #[test]
    fn sniffs_types_without_content_type() {
        assert_eq!(decode(&[], b" {\"a\":1}").kind, Kind::Json);
        assert_eq!(decode(&[], b"<!doctype html><html></html>").kind, Kind::Html);
        assert_eq!(decode(&[], &[0, 159, 146, 150, 0, 1, 2]).kind, Kind::Binary);
    }
}
