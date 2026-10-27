//! Raw HTTP/1.x parsing that keeps exact bytes.
//!
//! This crate does no I/O. Callers feed it bytes and it tells them where a
//! message head ends, what it contains, and how the body is framed. The
//! original bytes are never rewritten, so malformed or unusual messages
//! (the interesting ones in pentesting) pass through untouched.

pub mod h2text;
pub mod ws;

use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpError {
    #[error("message head is not valid: {0}")]
    BadHead(&'static str),
    #[error("chunked body is not valid: {0}")]
    BadChunk(&'static str),
    #[error("message head is larger than {0} bytes")]
    HeadTooLarge(usize),
}

pub type Result<T> = std::result::Result<T, HttpError>;

/// Largest head we accept before giving up (matches common server limits).
pub const MAX_HEAD_LEN: usize = 256 * 1024;

/// One header as it appeared on the wire. The name keeps its original case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub version: String,
    pub headers: Vec<Header>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<Header>,
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    None,
    ContentLength(u64),
    Chunked,
    /// Body runs until the connection closes (responses only).
    UntilClose,
}

/// Returns the length of the head (including the blank line) if `buf`
/// contains a complete one. Accepts both CRLF and bare LF line endings.
pub fn find_head_end(buf: &[u8]) -> Result<Option<usize>> {
    let mut i = 0;
    while let Some(pos) = memchr::memchr(b'\n', &buf[i..]) {
        let nl = i + pos;
        let rest = &buf[nl + 1..];
        if rest.starts_with(b"\r\n") {
            return Ok(Some(nl + 3));
        }
        if rest.starts_with(b"\n") {
            return Ok(Some(nl + 2));
        }
        i = nl + 1;
    }
    if buf.len() > MAX_HEAD_LEN {
        return Err(HttpError::HeadTooLarge(MAX_HEAD_LEN));
    }
    Ok(None)
}

fn lines(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l)).take_while(|l| !l.is_empty())
}

fn parse_headers<'a>(it: impl Iterator<Item = &'a [u8]>) -> Result<Vec<Header>> {
    let mut headers = Vec::new();
    for line in it {
        let colon = memchr::memchr(b':', line).ok_or(HttpError::BadHead("header without ':'"))?;
        let name = std::str::from_utf8(&line[..colon])
            .map_err(|_| HttpError::BadHead("header name is not UTF-8"))?
            .to_string();
        let value = line[colon + 1..].trim_ascii().to_vec();
        headers.push(Header { name, value });
    }
    Ok(headers)
}

fn utf8(b: &[u8], what: &'static str) -> Result<String> {
    std::str::from_utf8(b).map(str::to_string).map_err(|_| HttpError::BadHead(what))
}

/// Parses a request head. `head` is the bytes returned by [`find_head_end`].
pub fn parse_request_head(head: &[u8]) -> Result<RequestHead> {
    let mut it = lines(head);
    let first = it.next().ok_or(HttpError::BadHead("empty request"))?;
    let mut parts = first.splitn(3, |&b| b == b' ');
    let method = utf8(parts.next().unwrap_or_default(), "method is not UTF-8")?;
    let target = utf8(parts.next().ok_or(HttpError::BadHead("missing target"))?, "target is not UTF-8")?;
    let version = utf8(parts.next().ok_or(HttpError::BadHead("missing version"))?, "version is not UTF-8")?;
    if method.is_empty() || !version.starts_with("HTTP/") {
        return Err(HttpError::BadHead("bad request line"));
    }
    Ok(RequestHead { method, target, version, headers: parse_headers(it)? })
}

/// Parses a response head. `head` is the bytes returned by [`find_head_end`].
pub fn parse_response_head(head: &[u8]) -> Result<ResponseHead> {
    let mut it = lines(head);
    let first = it.next().ok_or(HttpError::BadHead("empty response"))?;
    let mut parts = first.splitn(3, |&b| b == b' ');
    let version = utf8(parts.next().unwrap_or_default(), "version is not UTF-8")?;
    let status = std::str::from_utf8(parts.next().ok_or(HttpError::BadHead("missing status"))?)
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(HttpError::BadHead("bad status code"))?;
    let reason = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    if !version.starts_with("HTTP/") {
        return Err(HttpError::BadHead("bad status line"));
    }
    Ok(ResponseHead { version, status, reason, headers: parse_headers(it)? })
}

/// First value of a header, matched case-insensitively.
pub fn header<'a>(headers: &'a [Header], name: &str) -> Option<&'a [u8]> {
    headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value.as_slice())
}

fn has_token(headers: &[Header], name: &str, token: &str) -> bool {
    headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case(name))
        .flat_map(|h| h.value.split(|&b| b == b','))
        .any(|t| t.trim_ascii().eq_ignore_ascii_case(token.as_bytes()))
}

fn is_chunked(headers: &[Header]) -> bool {
    // Per RFC 9112 only the final coding matters; checking any is the safe
    // framing choice for a proxy (avoids hanging on the body).
    has_token(headers, "transfer-encoding", "chunked")
}

fn content_length(headers: &[Header]) -> Result<Option<u64>> {
    match header(headers, "content-length") {
        None => Ok(None),
        Some(v) => std::str::from_utf8(v)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .map(Some)
            .ok_or(HttpError::BadHead("bad content-length")),
    }
}

impl RequestHead {
    pub fn body_kind(&self) -> Result<BodyKind> {
        if is_chunked(&self.headers) {
            return Ok(BodyKind::Chunked);
        }
        Ok(match content_length(&self.headers)? {
            Some(0) | None => BodyKind::None,
            Some(n) => BodyKind::ContentLength(n),
        })
    }

    /// Whether the client asked to close the connection after this request.
    pub fn wants_close(&self) -> bool {
        if self.version == "HTTP/1.0" {
            return !has_token(&self.headers, "connection", "keep-alive");
        }
        has_token(&self.headers, "connection", "close")
    }
}

impl ResponseHead {
    /// Body framing, given the method of the request this answers.
    pub fn body_kind(&self, request_method: &str) -> Result<BodyKind> {
        if request_method.eq_ignore_ascii_case("HEAD")
            || (100..200).contains(&self.status)
            || self.status == 204
            || self.status == 304
        {
            return Ok(BodyKind::None);
        }
        if is_chunked(&self.headers) {
            return Ok(BodyKind::Chunked);
        }
        Ok(match content_length(&self.headers)? {
            Some(0) => BodyKind::None,
            Some(n) => BodyKind::ContentLength(n),
            None => BodyKind::UntilClose,
        })
    }

    pub fn wants_close(&self) -> bool {
        if self.version == "HTTP/1.0" {
            return !has_token(&self.headers, "connection", "keep-alive");
        }
        has_token(&self.headers, "connection", "close")
    }
}

/// Incremental scanner for a chunked body. Feed it the body bytes seen so
/// far; it reports the total raw length once the final chunk and trailers
/// have arrived. Bytes are not decoded or changed.
#[derive(Debug, Default)]
pub struct ChunkedScanner {
    pos: usize,
    state: ChunkState,
}

#[derive(Debug, Default, Clone, Copy)]
enum ChunkState {
    #[default]
    Size,
    Data(u64),
    DataEnd,
    Trailers,
    Done,
}

impl ChunkedScanner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `Some(len)` when `buf[..len]` is the complete raw body.
    pub fn scan(&mut self, buf: &[u8]) -> Result<Option<usize>> {
        loop {
            match self.state {
                ChunkState::Done => return Ok(Some(self.pos)),
                ChunkState::Size => {
                    let Some(nl) = memchr::memchr(b'\n', &buf[self.pos..]) else {
                        if buf.len() - self.pos > 4096 {
                            return Err(HttpError::BadChunk("chunk size line too long"));
                        }
                        return Ok(None);
                    };
                    let line = &buf[self.pos..self.pos + nl];
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    let hex = line.split(|&b| b == b';').next().unwrap_or_default().trim_ascii();
                    let size = std::str::from_utf8(hex)
                        .ok()
                        .and_then(|s| u64::from_str_radix(s, 16).ok())
                        .ok_or(HttpError::BadChunk("bad chunk size"))?;
                    self.pos += nl + 1;
                    self.state = if size == 0 { ChunkState::Trailers } else { ChunkState::Data(size) };
                }
                ChunkState::Data(size) => {
                    let avail = (buf.len() - self.pos) as u64;
                    if avail < size {
                        return Ok(None);
                    }
                    self.pos += size as usize;
                    self.state = ChunkState::DataEnd;
                }
                ChunkState::DataEnd => {
                    let rest = &buf[self.pos..];
                    if rest.starts_with(b"\r\n") {
                        self.pos += 2;
                    } else if rest.starts_with(b"\n") {
                        self.pos += 1;
                    } else if rest.len() < 2 {
                        return Ok(None);
                    } else {
                        return Err(HttpError::BadChunk("missing CRLF after chunk data"));
                    }
                    self.state = ChunkState::Size;
                }
                ChunkState::Trailers => {
                    let Some(nl) = memchr::memchr(b'\n', &buf[self.pos..]) else {
                        return Ok(None);
                    };
                    let line = &buf[self.pos..self.pos + nl];
                    self.pos += nl + 1;
                    if line == b"\r" || line.is_empty() {
                        self.state = ChunkState::Done;
                    }
                }
            }
        }
    }
}

/// Splits an absolute-form target (`http://host:port/path`) into
/// `(scheme, authority, origin-form path)`. Returns `None` for other forms.
pub fn split_absolute_target(target: &str) -> Option<(&str, &str, &str)> {
    let (scheme, rest) = target.split_once("://")?;
    let slash = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, path) = rest.split_at(slash);
    Some((scheme, authority, if path.is_empty() { "/" } else { path }))
}

/// Splits `host:port`, using `default_port` when no port is given.
/// Handles bracketed IPv6 literals.
pub fn split_host_port(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => Some((h.to_string(), p.parse().ok()?)),
        None => Some((authority.to_string(), default_port)),
    }
}

/// Replaces the request target in the request line of `raw`, leaving every
/// other byte unchanged. Used to turn absolute-form into origin-form.
pub fn replace_request_target(raw: &[u8], new_target: &str) -> Option<Vec<u8>> {
    let first_sp = memchr::memchr(b' ', raw)?;
    let line_end = memchr::memchr(b'\n', raw)?;
    let second_sp = first_sp + 1 + memchr::memchr(b' ', &raw[first_sp + 1..line_end])?;
    let mut out = Vec::with_capacity(raw.len());
    out.extend_from_slice(&raw[..=first_sp]);
    out.extend_from_slice(new_target.as_bytes());
    out.extend_from_slice(&raw[second_sp..]);
    Some(out)
}

/// Splits a raw message into (head, body) at the blank line.
pub fn split_message(raw: &[u8]) -> (&[u8], &[u8]) {
    match find_head_end(raw) {
        Ok(Some(end)) => raw.split_at(end),
        _ => (raw, &[]),
    }
}

/// Decodes a chunked body into its payload, for display and analysis only.
/// Never use the result to forward traffic. Returns `None` if malformed.
pub fn decode_chunked(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let nl = memchr::memchr(b'\n', &body[i..])?;
        let line = &body[i..i + nl];
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let hex = line.split(|&b| b == b';').next()?.trim_ascii();
        let size = usize::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
        i += nl + 1;
        if size == 0 {
            return Some(out);
        }
        let end = i.checked_add(size)?;
        out.extend_from_slice(body.get(i..end)?);
        i = end;
        if body[i..].starts_with(b"\r\n") {
            i += 2;
        } else if body[i..].starts_with(b"\n") {
            i += 1;
        }
    }
}

/// Sets `Content-Length` to the actual body length (adding it if a body is
/// present and the header is missing). Leaves chunked messages and every
/// other byte untouched. Only call this when the user or agent asked for it.
pub fn fix_content_length(raw: &[u8]) -> Vec<u8> {
    let Ok(Some(end)) = find_head_end(raw) else { return raw.to_vec() };
    let (head, body) = raw.split_at(end);
    let Ok(parsed) = parse_request_head(head) else { return raw.to_vec() };
    if is_chunked(&parsed.headers) {
        return raw.to_vec();
    }
    let new_value = body.len().to_string();
    let mut out = Vec::with_capacity(raw.len() + 24);
    let mut replaced = false;
    let mut rest = head;
    while let Some(nl) = memchr::memchr(b'\n', rest) {
        let line = &rest[..=nl];
        rest = &rest[nl + 1..];
        let colon = memchr::memchr(b':', line);
        let is_cl = colon.is_some_and(|c| line[..c].trim_ascii().eq_ignore_ascii_case(b"content-length"));
        if is_cl && !replaced {
            let c = colon.unwrap_or(0);
            let eol: &[u8] = if line.ends_with(b"\r\n") { b"\r\n" } else { b"\n" };
            out.extend_from_slice(&line[..=c]);
            out.extend_from_slice(b" ");
            out.extend_from_slice(new_value.as_bytes());
            out.extend_from_slice(eol);
            replaced = true;
        } else if is_cl {
            // Drop duplicate Content-Length headers; they would conflict.
        } else if !replaced && !body.is_empty() && (line == b"\r\n" || line == b"\n") {
            out.extend_from_slice(format!("Content-Length: {new_value}\r\n").as_bytes());
            out.extend_from_slice(line);
            replaced = true;
        } else {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(rest);
    out.extend_from_slice(body);
    out
}

/// Removes every header with this name from a message's head; the rest
/// of the bytes (other headers, line endings, body) stay exactly as they were.
pub fn remove_header(raw: &[u8], name: &str) -> Vec<u8> {
    let Ok(Some(end)) = find_head_end(raw) else { return raw.to_vec() };
    let mut out = Vec::with_capacity(raw.len());
    let mut first = true;
    for line in raw[..end].split_inclusive(|&b| b == b'\n') {
        let is_match = !first
            && line
                .iter()
                .position(|&b| b == b':')
                .is_some_and(|c| line[..c].trim_ascii().eq_ignore_ascii_case(name.as_bytes()));
        first = false;
        if !is_match {
            out.extend_from_slice(line);
        }
    }
    out.extend_from_slice(&raw[end..]);
    out
}

/// The usual reason phrase for a status code ("" if unknown).
pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_head_end_crlf_and_lf() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nBODY").unwrap(), Some(27));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\nHost: a\n\nBODY").unwrap(), Some(24));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap(), None);
    }

    #[test]
    fn parses_request_and_keeps_header_case() {
        let raw = b"POST /a?b=1 HTTP/1.1\r\nHost: x\r\nX-Weird-CASE:  v \r\nContent-Length: 3\r\n\r\n";
        let h = parse_request_head(raw).unwrap();
        assert_eq!(h.method, "POST");
        assert_eq!(h.target, "/a?b=1");
        assert_eq!(h.headers[1].name, "X-Weird-CASE");
        assert_eq!(h.headers[1].value, b"v");
        assert_eq!(h.body_kind().unwrap(), BodyKind::ContentLength(3));
    }

    #[test]
    fn response_framing_rules() {
        let r = parse_response_head(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        assert_eq!(r.body_kind("GET").unwrap(), BodyKind::UntilClose);
        assert_eq!(r.body_kind("HEAD").unwrap(), BodyKind::None);
        let r = parse_response_head(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n").unwrap();
        assert_eq!(r.body_kind("GET").unwrap(), BodyKind::None);
        let r = parse_response_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n").unwrap();
        assert_eq!(r.body_kind("GET").unwrap(), BodyKind::Chunked);
    }

    #[test]
    fn chunked_scanner_handles_split_input() {
        let body = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: x\r\n\r\nNEXT";
        let mut s = ChunkedScanner::new();
        for end in 0..body.len() - 4 {
            assert_eq!(s.scan(&body[..end]).unwrap(), None, "end={end}");
        }
        assert_eq!(s.scan(body).unwrap(), Some(body.len() - 4));
    }

    #[test]
    fn rejects_bad_chunk_size() {
        assert!(ChunkedScanner::new().scan(b"zz\r\n").is_err());
    }

    #[test]
    fn absolute_targets_and_host_ports() {
        assert_eq!(split_absolute_target("http://a.com:81/x?y"), Some(("http", "a.com:81", "/x?y")));
        assert_eq!(split_absolute_target("http://a.com"), Some(("http", "a.com", "/")));
        assert_eq!(split_absolute_target("/x"), None);
        assert_eq!(split_host_port("a.com", 80), Some(("a.com".into(), 80)));
        assert_eq!(split_host_port("[::1]:8443", 443), Some(("::1".into(), 8443)));
    }

    #[test]
    fn decodes_chunked_for_display() {
        assert_eq!(decode_chunked(b"4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\n\r\n").unwrap(), b"Wikipedia");
        assert_eq!(decode_chunked(b"zz\r\n"), None);
        // Found by fuzzing: a size near usize::MAX overflowed the offset.
        assert_eq!(decode_chunked(b"ffffffffffffffff\n\n\nxx"), None);
    }

    #[test]
    fn fixes_content_length_only_where_needed() {
        let out = fix_content_length(b"POST / HTTP/1.1\r\nHost: a\r\ncontent-length: 1\r\n\r\nhello");
        assert_eq!(out, b"POST / HTTP/1.1\r\nHost: a\r\ncontent-length: 5\r\n\r\nhello");
        let out = fix_content_length(b"POST / HTTP/1.1\r\nHost: a\r\n\r\nhi");
        assert_eq!(out, b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nhi");
        let get = b"GET / HTTP/1.1\r\nHost: a\r\n\r\n";
        assert_eq!(fix_content_length(get), get);
        let chunked = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        assert_eq!(fix_content_length(chunked), chunked);
    }

    #[test]
    fn replaces_target_without_touching_rest() {
        let raw = b"GET http://a.com/x HTTP/1.1\r\nHost: a.com\r\n\r\n";
        let out = replace_request_target(raw, "/x").unwrap();
        assert_eq!(out, b"GET /x HTTP/1.1\r\nHost: a.com\r\n\r\n");
    }

    #[test]
    fn remove_header_keeps_everything_else() {
        let raw = b"GET /ws HTTP/1.1\r\nHost: a\r\nSec-WebSocket-Extensions: permessage-deflate\r\nX: 1\r\n\r\nbody";
        assert_eq!(remove_header(raw, "sec-websocket-extensions"), b"GET /ws HTTP/1.1\r\nHost: a\r\nX: 1\r\n\r\nbody");
        assert_eq!(remove_header(raw, "absent"), raw.to_vec());
        let lf = b"GET / HTTP/1.1\nA: 1\nB: 2\n\n";
        assert_eq!(remove_header(lf, "a"), b"GET / HTTP/1.1\nB: 2\n\n");
    }
}
