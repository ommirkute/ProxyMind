//! HTTP/3 messages as text (ADR-0021), the same form as HTTP/2 (ADR-0009) with `HTTP/3` as the version:
//!
//! ```text
//! GET /api/me HTTP/3
//! host: app.example.com
//! accept: application/json
//! ```
//!
//! The `Host` header stands for `:authority`; header names are lower-case; connection-specific headers are not
//! used. Taking a request apart and rendering it share their code with HTTP/2 ([`crate::h2text`]), so rules,
//! Replay, identities and the other tools handle both alike. This module adds what is specific to HTTP/3: telling
//! the version, and reading `Alt-Svc` advertisements (RFC 7838) that offer it. No I/O.

use crate::h2text::{H2Request, h2_request, render_request, render_response};
use crate::{Result, find_head_end, parse_response_head};

/// The multiplexed protocol a request's request line names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Multiplexed {
    Http2,
    Http3,
}

/// Which text form a request is in: `HTTP/2`, `HTTP/3`, or `None` for HTTP/1.x (and anything else). One scan of the
/// request line, so the proxy's per-request check costs the same as before HTTP/3 existed.
pub fn request_protocol(raw: &[u8]) -> Option<Multiplexed> {
    let line = raw.split(|&b| b == b'\n').next().unwrap_or_default();
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let v = line.rsplit(|&b| b == b' ').next()?;
    if v.len() < 6 || !v[..5].eq_ignore_ascii_case(b"HTTP/") {
        return None;
    }
    match &v[5..] {
        b"2" | b"2.0" => Some(Multiplexed::Http2),
        b"3" | b"3.0" => Some(Multiplexed::Http3),
        _ => None,
    }
}

/// True when the request line's version is `HTTP/3`.
pub fn is_http3_request(raw: &[u8]) -> bool {
    request_protocol(raw) == Some(Multiplexed::Http3)
}

/// True when a response's status line says `HTTP/3`.
pub fn is_http3_response(raw: &[u8]) -> bool {
    raw.starts_with(b"HTTP/3 ") || raw.starts_with(b"HTTP/3.0 ")
}

/// True for a response in HTTP/2 or HTTP/3 text form (HTTP/1.1 clients and tools that want HTTP/1.1 text convert
/// these with [`crate::h2text::to_http1_response`]).
pub fn is_multiplexed_response(raw: &[u8]) -> bool {
    crate::h2text::is_http2_response(raw) || is_http3_response(raw)
}

/// True for a request in HTTP/2 or HTTP/3 text form.
pub fn is_multiplexed_request(raw: &[u8]) -> bool {
    request_protocol(raw).is_some()
}

/// Takes apart a request in HTTP/3 text form (or any HTTP/1.x text request): the same parts as HTTP/2.
pub fn h3_request(raw: &[u8]) -> Result<H2Request> {
    h2_request(raw)
}

/// Renders a request in HTTP/3 text form.
pub fn render_h3_request(r: &H2Request) -> Vec<u8> {
    render_request(r, "HTTP/3")
}

/// Renders a response in HTTP/3 text form.
pub fn render_h3_response(status: u16, headers: &[(String, Vec<u8>)], body: &[u8]) -> Vec<u8> {
    render_response("HTTP/3", status, headers, body)
}

/// One alternative service from an `Alt-Svc` header (RFC 7838).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltSvc {
    /// The protocol id: `h3`, `h3-29`, `h2`, ...
    pub protocol: String,
    /// The alternative authority: `:443` (same host) or `alt.example:8443`.
    pub authority: String,
    /// `ma` (max age in seconds), if given.
    pub max_age: Option<u64>,
}

impl AltSvc {
    /// An HTTP/3 alternative: `h3`, or a draft such as `h3-29`.
    pub fn is_h3(&self) -> bool {
        is_h3_protocol(&self.protocol)
    }
}

fn is_h3_protocol(id: &str) -> bool {
    id.eq_ignore_ascii_case("h3") || id.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("h3-"))
}

/// Splits `s` at `sep` outside double quotes.
fn split_outside_quotes(s: &str, sep: char) -> Vec<&str> {
    let (mut parts, mut start, mut quoted, mut escaped) = (Vec::new(), 0, false, false);
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            c if c == sep && !quoted => {
                parts.push(&s[start..i]);
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Parses the value of an `Alt-Svc` header. `clear` and entries that don't parse give nothing.
pub fn parse_alt_svc(value: &str) -> Vec<AltSvc> {
    let mut out = Vec::new();
    for item in split_outside_quotes(value, ',') {
        let mut params = split_outside_quotes(item, ';').into_iter();
        let Some((protocol, authority)) = params.next().and_then(|first| first.split_once('=')) else { continue };
        let authority = authority.trim().trim_matches('"');
        let protocol = protocol.trim();
        if protocol.is_empty() || authority.is_empty() {
            continue;
        }
        let max_age = params
            .filter_map(|p| p.split_once('='))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case("ma"))
            .and_then(|(_, v)| v.trim().trim_matches('"').parse().ok());
        out.push(AltSvc { protocol: protocol.to_string(), authority: authority.to_string(), max_age });
    }
    out
}

/// The HTTP/3 alternatives a response (HTTP/1.x, HTTP/2 or HTTP/3 text) advertises in its `Alt-Svc` headers.
/// Empty when it offers none; `None` when the head can't be read.
pub fn alt_svc_h3(raw_response: &[u8]) -> Option<Vec<AltSvc>> {
    let mut rest = raw_response;
    // Skip interim responses to the final head.
    let head = loop {
        let end = find_head_end(rest).ok()??;
        let head = parse_response_head(&rest[..end]).ok()?;
        if (100..200).contains(&head.status) && head.status != 101 {
            rest = &rest[end..];
            continue;
        }
        break head;
    };
    let mut found = Vec::new();
    // A server may send several Alt-Svc lines.
    for h in head.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("alt-svc")) {
        found.extend(parse_alt_svc(&String::from_utf8_lossy(&h.value)).into_iter().filter(AltSvc::is_h3));
    }
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2text::{h2_response, is_http2_request};

    #[test]
    fn detects_http3_text() {
        assert!(is_http3_request(b"GET / HTTP/3\r\nhost: a\r\n\r\n"));
        assert!(is_http3_request(b"GET / http/3\nhost: a\n\n"));
        assert!(!is_http3_request(b"GET / HTTP/2\r\n\r\n"));
        assert!(!is_http3_request(b"GET /HTTP/3 HTTP/1.1\r\n\r\n"));
        assert!(!is_http2_request(b"GET / HTTP/3\r\n\r\n"));
        assert_eq!(request_protocol(b"GET / HTTP/2\r\n\r\n"), Some(Multiplexed::Http2));
        assert_eq!(request_protocol(b"GET / HTTP/2.0\r\n\r\n"), Some(Multiplexed::Http2));
        assert_eq!(request_protocol(b"GET / http/3.0\r\n\r\n"), Some(Multiplexed::Http3));
        for other in [&b"GET / HTTP/1.1\r\n"[..], b"GET / HTTP/\r\n", b"GET / HTTP/3x\r\n", b"", b"GET / HTTP/20\r\n"] {
            assert_eq!(request_protocol(other), None, "{other:?}");
        }
        assert!(is_http3_response(b"HTTP/3 200\r\n\r\n") && !is_http3_response(b"HTTP/2 200\r\n\r\n"));
        assert!(is_multiplexed_response(b"HTTP/2 200\r\n\r\n") && is_multiplexed_response(b"HTTP/3 200\r\n\r\n"));
        assert!(!is_multiplexed_response(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(is_multiplexed_request(b"GET / HTTP/3\r\n\r\n") && !is_multiplexed_request(b"GET / HTTP/1.1\r\n\r\n"));
    }

    #[test]
    fn request_round_trip() {
        let raw = b"POST /api?x=1 HTTP/3\r\nhost: app.test\r\nConnection: close\r\nContent-Type: application/json\r\n\
                    Content-Length: 99\r\n\r\n{\"a\":1}";
        let r = h3_request(raw).unwrap();
        assert_eq!(
            (r.method.as_str(), r.path.as_str(), r.authority.as_deref()),
            ("POST", "/api?x=1", Some("app.test"))
        );
        assert_eq!(r.headers, vec![("content-type".to_string(), b"application/json".to_vec())]);
        let text = render_h3_request(&r);
        assert_eq!(text, b"POST /api?x=1 HTTP/3\r\nhost: app.test\r\ncontent-type: application/json\r\n\r\n{\"a\":1}");
        assert!(is_http3_request(&text));
        assert_eq!(h3_request(&text).unwrap(), r, "rendering and reading again changes nothing");
        // No authority: no host line, the version is still swapped.
        let bare = H2Request { method: "GET".into(), path: "/".into(), authority: None, headers: vec![], body: vec![] };
        assert_eq!(render_h3_request(&bare), b"GET / HTTP/3\r\n\r\n");
    }

    #[test]
    fn response_round_trip() {
        let text = render_h3_response(404, &[("server".into(), b"t".to_vec())], b"nope");
        assert_eq!(text, b"HTTP/3 404\r\nserver: t\r\n\r\nnope");
        let r = h2_response(&text).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (404, &b"nope"[..]));
        assert_eq!(
            crate::h2text::to_http1_response(&text).unwrap(),
            b"HTTP/1.1 404 Not Found\r\nserver: t\r\ncontent-length: 4\r\n\r\nnope"
        );
    }

    #[test]
    fn alt_svc_values() {
        let v = parse_alt_svc(r#"h3=":443"; ma=86400, h3-29=":8443"; ma=3600; persist=1, h2="alt.example:443", clear"#);
        assert_eq!(v.len(), 3, "clear isn't an alternative");
        assert_eq!((v[0].protocol.as_str(), v[0].authority.as_str(), v[0].max_age), ("h3", ":443", Some(86400)));
        assert!(v[0].is_h3() && v[1].is_h3() && !v[2].is_h3());
        assert_eq!((v[2].protocol.as_str(), v[2].authority.as_str(), v[2].max_age), ("h2", "alt.example:443", None));
        // A comma or semicolon inside quotes belongs to the value.
        let q = parse_alt_svc(r#"h3="a,b:443"; ma="60", quic=":1""#);
        assert_eq!((q[0].authority.as_str(), q[0].max_age, q.len()), ("a,b:443", Some(60), 2));
        assert!(parse_alt_svc("clear").is_empty() && parse_alt_svc("").is_empty() && parse_alt_svc("h3=").is_empty());
    }

    #[test]
    fn alt_svc_in_responses() {
        let h1 = b"HTTP/1.1 200 OK\r\nAlt-Svc: h3=\":443\"; ma=60\r\nalt-svc: h2=\":443\", h3-29=\":443\"\r\n\r\nbody";
        let found = alt_svc_h3(h1).unwrap();
        assert_eq!(found.iter().map(|a| a.protocol.as_str()).collect::<Vec<_>>(), ["h3", "h3-29"]);
        assert!(alt_svc_h3(b"HTTP/2 200\r\nalt-svc: h3=\":443\"\r\n\r\n").unwrap().len() == 1);
        assert!(
            alt_svc_h3(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nalt-svc: h3=\":1\"\r\n\r\n").unwrap().len()
                == 1
        );
        assert!(alt_svc_h3(b"HTTP/1.1 200 OK\r\nAlt-Svc: h2=\":443\"\r\n\r\n").unwrap().is_empty());
        assert!(alt_svc_h3(b"HTTP/1.1 200 OK\r\n\r\n").unwrap().is_empty());
        assert!(alt_svc_h3(b"garbage").is_none());
    }
}
