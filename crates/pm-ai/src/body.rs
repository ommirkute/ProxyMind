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

/// The body of a raw HTTP message as people read it: de-chunked and decompressed, all of it (up to
/// [`MAX_DECODED`]), with nothing stripped. `None` when there is no body or it is binary. Unlike the model views in
/// [`crate::view`], this is not cut to a token budget, HTML keeps its markup, and nothing is wrapped or redacted, so a
/// viewer can pretty-print JSON or render HTML from it.
pub fn decoded_text(raw: &[u8]) -> Option<String> {
    let (head, body) = pm_http::split_message(raw);
    if body.is_empty() {
        return None;
    }
    let headers = pm_http::parse_request_head(head)
        .map(|h| h.headers)
        .or_else(|_| pm_http::parse_response_head(head).map(|h| h.headers))
        .unwrap_or_default();
    let d = decode(&headers, body);
    match d.kind {
        Kind::Binary | Kind::Empty => None,
        _ => Some(String::from_utf8_lossy(&d.bytes).into_owned()),
    }
}

/// A gRPC or Protobuf message taken from raw HTTP text: the body as the application sees it (de-chunked and
/// decompressed at the HTTP level; per-message gRPC compression is still in it) and what the head says about it.
#[derive(Debug, Clone)]
pub struct ProtoMessage {
    pub kind: pm_http::protobuf::BodyKind,
    pub body: Vec<u8>,
    /// `grpc-encoding` (how single messages are compressed), lower-case.
    pub grpc_encoding: Option<String>,
    /// `grpc-status` / `grpc-message` from the head (a trailers-only response, or trailers kept in the head).
    pub grpc_status: Option<String>,
    pub grpc_message: Option<String>,
}

/// The gRPC/Protobuf message in raw HTTP text, if its content type says so and it has a body.
pub fn protobuf_message(raw: &[u8]) -> Option<ProtoMessage> {
    let (head, body) = pm_http::split_message(raw);
    if body.is_empty() {
        return None;
    }
    let headers = pm_http::parse_request_head(head)
        .map(|h| h.headers)
        .or_else(|_| pm_http::parse_response_head(head).map(|h| h.headers))
        .ok()?;
    let ct = pm_http::header(&headers, "content-type")?;
    let kind = pm_http::protobuf::BodyKind::from_content_type(&String::from_utf8_lossy(ct))?;
    let text = |name: &str| pm_http::header(&headers, name).map(|v| String::from_utf8_lossy(v).trim().to_string());
    Some(ProtoMessage {
        kind,
        body: decode(&headers, body).bytes,
        grpc_encoding: text("grpc-encoding").map(|e| e.to_ascii_lowercase()),
        grpc_status: text("grpc-status"),
        grpc_message: text("grpc-message"),
    })
}

/// Text of a gRPC/Protobuf body (see [`pm_http::protobuf::render_body`]); messages compressed with `gzip` or
/// `deflate` (`grpc_encoding`) are decompressed first.
pub fn protobuf_render(
    kind: pm_http::protobuf::BodyKind,
    body: &[u8],
    grpc_encoding: Option<&str>,
    annotate: bool,
) -> Result<pm_http::protobuf::Rendered, pm_http::protobuf::ProtoError> {
    let encoding = grpc_encoding.unwrap_or("identity").trim().to_ascii_lowercase();
    let decompress = |payload: &[u8]| match encoding.as_str() {
        "gzip" | "x-gzip" => read_capped(flate2::read::MultiGzDecoder::new(payload)),
        "deflate" => read_capped(flate2::read::ZlibDecoder::new(payload)),
        _ => None,
    };
    pm_http::protobuf::render_body(kind, body, &decompress, annotate)
}

/// The gRPC/Protobuf view of raw HTTP text: `None` when it is not one or nothing could be decoded. Status and
/// message found only in the head are added as comment lines to gRPC text.
pub fn protobuf_view(raw: &[u8], annotate: bool) -> Option<(pm_http::protobuf::BodyKind, pm_http::protobuf::Rendered)> {
    let m = protobuf_message(raw)?;
    let mut r = protobuf_render(m.kind, &m.body, m.grpc_encoding.as_deref(), annotate).ok()?;
    if m.kind.is_framed() {
        for (name, value, slot) in [
            ("grpc-status", &m.grpc_status, &mut r.grpc_status),
            ("grpc-message", &m.grpc_message, &mut r.grpc_message),
        ] {
            if let (None, Some(v)) = (&*slot, value) {
                r.text.push_str(&format!("# {name}: {v}\n"));
                *slot = Some(v.clone());
            }
        }
    }
    Some((m.kind, r))
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
    fn decoded_text_keeps_markup_and_all_of_the_body() {
        // HTML keeps its tags (the model view keeps only visible text) and is not cut to a token budget.
        let page = format!("<html><body><form action=\"/login\">{}</form></body></html>", "x".repeat(50_000));
        let raw = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{page}");
        assert_eq!(decoded_text(raw.as_bytes()).as_deref(), Some(page.as_str()));
        // Chunked and gzip are undone.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(br#"{"user":"alice"}"#).unwrap();
        let gz = gz.finish().unwrap();
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n\
                        Transfer-Encoding: chunked\r\n\r\n"
            .to_vec();
        raw.extend_from_slice(format!("{:x}\r\n", gz.len()).as_bytes());
        raw.extend_from_slice(&gz);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        assert_eq!(decoded_text(&raw).as_deref(), Some(r#"{"user":"alice"}"#));
        // Requests too; no body or a binary one gives nothing.
        let req = b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{\"a\":1}";
        assert_eq!(decoded_text(req).as_deref(), Some("{\"a\":1}"));
        assert_eq!(decoded_text(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"), None);
        assert_eq!(decoded_text(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG\0\x01\x02"), None);
    }

    #[test]
    fn protobuf_view_reads_grpc_messages_and_head_status() {
        use pm_http::protobuf::{BodyKind, frame_message};
        // A gzip-compressed gRPC message (flag 1) and a plain one, in a chunked HTTP/1.1 response.
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&[0x08, 0x07]).unwrap();
        let mut body = frame_message(1, &gz.finish().unwrap());
        body.extend(frame_message(0, &[0x12, 2, b'o', b'k']));
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/grpc\r\ngrpc-encoding: gzip\r\n\
                        grpc-status: 0\r\ngrpc-message: fine\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_vec();
        raw.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
        raw.extend_from_slice(&body);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        let (kind, r) = protobuf_view(&raw, false).unwrap();
        assert_eq!(kind, BodyKind::Grpc);
        assert_eq!(r.text, "@message\n1: 7\n@message\n2: \"ok\"\n# grpc-status: 0\n# grpc-message: fine\n");
        assert_eq!((r.grpc_status.as_deref(), r.grpc_message.as_deref()), (Some("0"), Some("fine")));
        assert!(!r.exact, "the compressed message is sent uncompressed after an edit");
        // Plain Protobuf in a request; other content types and empty bodies give nothing.
        let req = b"POST /a HTTP/2\r\ncontent-type: application/x-protobuf\r\n\r\n\x08\x96\x01";
        assert_eq!(protobuf_view(req, true).unwrap().1.text, "1: 150  # zigzag 75\n");
        assert!(protobuf_view(b"POST /a HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}", false).is_none());
        assert!(protobuf_view(b"POST /a HTTP/1.1\r\nContent-Type: application/grpc\r\n\r\n", false).is_none());
        // Garbage with a gRPC content type is not shown rather than guessed at.
        assert!(protobuf_view(b"POST /a HTTP/1.1\r\nContent-Type: application/grpc\r\n\r\nhello", false).is_none());
    }

    #[test]
    fn sniffs_types_without_content_type() {
        assert_eq!(decode(&[], b" {\"a\":1}").kind, Kind::Json);
        assert_eq!(decode(&[], b"<!doctype html><html></html>").kind, Kind::Html);
        assert_eq!(decode(&[], &[0, 159, 146, 150, 0, 1, 2]).kind, Kind::Binary);
    }
}
