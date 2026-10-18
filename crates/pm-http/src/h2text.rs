//! HTTP/2 messages as text. ProxyMind shows, edits and stores HTTP/2
//! requests and responses in HTTP/1-style text with `HTTP/2` as the
//! version, the `Host` header standing for `:authority`:
//!
//! ```text
//! GET /api/me HTTP/2
//! host: app.example.com
//! accept: application/json
//! ```
//!
//! These helpers convert between that text and the parts an HTTP/2 library
//! needs. No I/O.

use crate::{HttpError, Result, find_head_end, header, parse_request_head, parse_response_head, split_message};

/// Headers that mean something only to one HTTP/1.1 connection and are not
/// allowed in HTTP/2 (RFC 9113 section 8.2.2).
const CONNECTION_SPECIFIC: &[&str] = &["connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade"];

/// True when the request line's version is `HTTP/2`.
pub fn is_http2_request(raw: &[u8]) -> bool {
    let line = raw.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    line.rsplit(|&b| b == b' ').next().is_some_and(|v| v.eq_ignore_ascii_case(b"HTTP/2") || v == b"HTTP/2.0")
}

/// An HTTP/2 request taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Request {
    pub method: String,
    /// `:path`: origin-form target (`/a?b`), or `*`.
    pub path: String,
    /// `:authority`, from the `Host` header (None if absent).
    pub authority: Option<String>,
    /// Regular headers, lower-case names, without connection-specific ones.
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

/// Takes apart a request in HTTP/2 text form (or any HTTP/1.x text request).
/// Chunked bodies are decoded; `Content-Length` is kept only when it matches.
pub fn h2_request(raw: &[u8]) -> Result<H2Request> {
    let end = find_head_end(raw)?.ok_or(HttpError::BadHead("incomplete request head"))?;
    let head = parse_request_head(&raw[..end])?;
    let mut body = raw[end..].to_vec();
    let chunked = header(&head.headers, "transfer-encoding")
        .is_some_and(|v| String::from_utf8_lossy(v).to_ascii_lowercase().contains("chunked"));
    if chunked && let Some(decoded) = crate::decode_chunked(&body) {
        body = decoded;
    }
    let (path, authority_from_target) = match crate::split_absolute_target(&head.target) {
        Some((_, authority, path)) => (path.to_string(), Some(authority.to_string())),
        None => (head.target.clone(), None),
    };
    let mut authority = authority_from_target;
    let mut headers = Vec::with_capacity(head.headers.len());
    for h in &head.headers {
        let name = h.name.to_ascii_lowercase();
        if name == "host" {
            authority.get_or_insert_with(|| String::from_utf8_lossy(&h.value).trim().to_string());
            continue;
        }
        if CONNECTION_SPECIFIC.contains(&name.as_str()) || name.starts_with(':') {
            continue;
        }
        if name == "te" && !h.value.trim_ascii().eq_ignore_ascii_case(b"trailers") {
            continue;
        }
        if name == "content-length" && h.value.trim_ascii() != body.len().to_string().as_bytes() {
            continue;
        }
        headers.push((name, h.value.trim_ascii().to_vec()));
    }
    Ok(H2Request { method: head.method, path, authority, headers, body })
}

/// Joins split `cookie` headers into one, as RFC 9113 section 8.2.3 allows,
/// so tools that read or replace "the" Cookie header see all of them.
pub fn join_cookies(headers: &mut Vec<(String, Vec<u8>)>) {
    let Some(first) = headers.iter().position(|(n, _)| n == "cookie") else { return };
    let mut joined = Vec::new();
    headers.retain(|(n, v)| {
        if n != "cookie" {
            return true;
        }
        if !joined.is_empty() {
            joined.extend_from_slice(b"; ");
        }
        joined.extend_from_slice(v);
        false
    });
    headers.insert(first.min(headers.len()), ("cookie".to_string(), joined));
}

/// Renders a request in HTTP/2 text form.
pub fn render_h2_request(r: &H2Request) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/2\r\n", r.method, r.path).into_bytes();
    if let Some(a) = &r.authority {
        out.extend_from_slice(format!("host: {a}\r\n").as_bytes());
    }
    push_headers(&mut out, &r.headers);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&r.body);
    out
}

/// Renders a response in HTTP/2 text form.
pub fn render_h2_response(status: u16, headers: &[(String, Vec<u8>)], body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/2 {status}\r\n").into_bytes();
    push_headers(&mut out, headers);
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

fn push_headers(out: &mut Vec<u8>, headers: &[(String, Vec<u8>)]) {
    for (n, v) in headers {
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
}

/// The same request as HTTP/1.1 text, for servers that don't speak HTTP/2:
/// `Host` first, then the headers, and `Content-Length` when there is a body.
pub fn downgrade_request(r: &H2Request, default_authority: &str) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.1\r\n", r.method, r.path).into_bytes();
    out.extend_from_slice(format!("Host: {}\r\n", r.authority.as_deref().unwrap_or(default_authority)).as_bytes());
    let mut headers = r.headers.clone();
    join_cookies(&mut headers);
    let mut has_length = false;
    for (n, v) in &headers {
        has_length |= n == "content-length";
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    let bodyless = matches!(r.method.as_str(), "GET" | "HEAD" | "DELETE" | "OPTIONS" | "TRACE");
    if !has_length && (!r.body.is_empty() || !bodyless) {
        out.extend_from_slice(format!("content-length: {}\r\n", r.body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&r.body);
    out
}

/// A response (HTTP/1.x or HTTP/2 text) taken apart for sending over HTTP/2:
/// interim 1xx responses skipped, chunked bodies decoded, and
/// connection-specific headers removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H2Response {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}

pub fn h2_response(raw: &[u8]) -> Result<H2Response> {
    let mut rest = raw;
    loop {
        let end = find_head_end(rest)?.ok_or(HttpError::BadHead("incomplete response head"))?;
        let head = parse_response_head(&rest[..end])?;
        if (100..200).contains(&head.status) && head.status != 101 {
            rest = &rest[end..];
            continue;
        }
        let mut body = split_message(rest).1.to_vec();
        let chunked = header(&head.headers, "transfer-encoding")
            .is_some_and(|v| String::from_utf8_lossy(v).to_ascii_lowercase().contains("chunked"));
        if chunked && let Some(decoded) = crate::decode_chunked(&body) {
            body = decoded;
        }
        let headers = head
            .headers
            .iter()
            .map(|h| (h.name.to_ascii_lowercase(), h.value.trim_ascii().to_vec()))
            .filter(|(n, v)| {
                !CONNECTION_SPECIFIC.contains(&n.as_str())
                    && !n.starts_with(':')
                    && (n != "content-length" || v.as_slice() == body.len().to_string().as_bytes())
            })
            .collect();
        return Ok(H2Response { status: head.status, headers, body });
    }
}

/// True when a response's status line says `HTTP/2`.
pub fn is_http2_response(raw: &[u8]) -> bool {
    raw.starts_with(b"HTTP/2 ") || raw.starts_with(b"HTTP/2.0 ")
}

/// An HTTP/2 text response as HTTP/1.1, for an HTTP/1.1 client. None if it
/// can't be parsed.
pub fn to_http1_response(raw: &[u8]) -> Option<Vec<u8>> {
    let r = h2_response(raw).ok()?;
    let mut out = format!("HTTP/1.1 {} {}\r\n", r.status, crate::reason_phrase(r.status)).into_bytes();
    for (n, v) in r.headers.iter().filter(|(n, _)| n != "content-length") {
        out.extend_from_slice(n.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("content-length: {}\r\n\r\n", r.body.len()).as_bytes());
    out.extend_from_slice(&r.body);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_cookies_are_joined() {
        let mut h = vec![
            ("accept".to_string(), b"*/*".to_vec()),
            ("cookie".to_string(), b"a=1".to_vec()),
            ("x".to_string(), b"y".to_vec()),
            ("cookie".to_string(), b"b=2".to_vec()),
        ];
        join_cookies(&mut h);
        assert_eq!(h[1], ("cookie".to_string(), b"a=1; b=2".to_vec()));
        assert_eq!(h.len(), 3);
        let r = h2_request(b"GET / HTTP/2\r\nhost: h\r\ncookie: a=1\r\ncookie: b=2\r\n\r\n").unwrap();
        assert_eq!(downgrade_request(&r, "h"), b"GET / HTTP/1.1\r\nHost: h\r\ncookie: a=1; b=2\r\n\r\n");
    }

    #[test]
    fn http2_responses_for_http1_clients() {
        let raw = b"HTTP/2 404\r\nx-a: 1\r\ncontent-length: 3\r\n\r\nnah";
        assert!(is_http2_response(raw));
        assert_eq!(
            to_http1_response(raw).unwrap(),
            b"HTTP/1.1 404 Not Found\r\nx-a: 1\r\ncontent-length: 3\r\n\r\nnah"
        );
    }

    #[test]
    fn detects_http2_requests() {
        assert!(is_http2_request(b"GET / HTTP/2\r\nhost: a\r\n\r\n"));
        assert!(is_http2_request(b"GET / HTTP/2\nhost: a\n\n"));
        assert!(!is_http2_request(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!is_http2_request(b"GET /HTTP/2 HTTP/1.1\r\n\r\n"));
    }

    #[test]
    fn request_round_trip_and_cleanup() {
        let raw =
            b"POST /api?x=1 HTTP/2\r\nhost: app.test\r\nConnection: keep-alive\r\nContent-Type: application/json\r\n\
                    Content-Length: 99\r\nTE: gzip\r\n\r\n{\"a\":1}";
        let r = h2_request(raw).unwrap();
        assert_eq!(
            (r.method.as_str(), r.path.as_str(), r.authority.as_deref()),
            ("POST", "/api?x=1", Some("app.test"))
        );
        assert_eq!(
            r.headers,
            vec![("content-type".to_string(), b"application/json".to_vec())],
            "wrong CL, TE, Connection gone"
        );
        assert_eq!(r.body, b"{\"a\":1}");
        let text = render_h2_request(&r);
        assert_eq!(text, b"POST /api?x=1 HTTP/2\r\nhost: app.test\r\ncontent-type: application/json\r\n\r\n{\"a\":1}");
        assert_eq!(h2_request(&text).unwrap(), r);
    }

    #[test]
    fn downgrade_adds_host_and_length() {
        let r = h2_request(b"POST /a HTTP/2\r\nhost: app.test\r\n\r\nhello").unwrap();
        assert_eq!(downgrade_request(&r, "x"), b"POST /a HTTP/1.1\r\nHost: app.test\r\ncontent-length: 5\r\n\r\nhello");
        let g = h2_request(b"GET /b HTTP/2\r\naccept: */*\r\n\r\n").unwrap();
        assert_eq!(
            downgrade_request(&g, "fallback.test:8443"),
            b"GET /b HTTP/1.1\r\nHost: fallback.test:8443\r\naccept: */*\r\n\r\n"
        );
        let chunked =
            h2_request(b"POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
                .unwrap();
        assert_eq!(chunked.body, b"abc");
    }

    #[test]
    fn responses_skip_interim_and_dechunk() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\nX-A: 1\r\n\r\n2\r\nok\r\n0\r\n\r\n";
        let r = h2_response(raw).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        assert_eq!(r.headers, vec![("x-a".to_string(), b"1".to_vec())]);
        let text = render_h2_response(204, &[("server".into(), b"t".to_vec())], b"");
        assert_eq!(text, b"HTTP/2 204\r\nserver: t\r\n\r\n");
        assert_eq!(h2_response(&text).unwrap().status, 204);
    }
}
