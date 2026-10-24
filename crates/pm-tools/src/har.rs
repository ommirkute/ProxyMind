//! HAR 1.2 import and export.
//!
//! HAR files keep decoded bodies, so imported exchanges are rebuilt rather
//! than replayed byte for byte: requests become HTTP/1.1 with a `Host`
//! header and a matching `Content-Length`; responses lose `Content-Encoding`
//! and `Transfer-Encoding` (the body is already decoded) and get a
//! `Content-Length`. Nothing here sends anything.

use std::io::Read;

use pm_http::{Header, find_head_end, header, parse_request_head, parse_response_head};
use serde_json::{Value, json};

/// Most entries read from one HAR file.
pub const MAX_ENTRIES: usize = 20_000;

/// One exchange rebuilt from a HAR entry or a cURL command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub ts_ms: i64,
    pub duration_ms: Option<i64>,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    /// Origin-form target (`/a?b`).
    pub path: String,
    pub status: Option<u16>,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
}

/// Parts of a URL that a request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlParts {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Origin-form target, at least `/`.
    pub target: String,
}

impl UrlParts {
    /// The `Host` header value (port only when not the default).
    pub fn authority(&self) -> String {
        pm_core::authority(&self.scheme, &self.host, self.port)
    }
}

/// Splits an absolute http(s) URL. A URL without a scheme is taken as http.
pub fn split_url(url: &str) -> Result<UrlParts, String> {
    let url = url.trim();
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("http".to_string(), url),
    };
    if scheme != "http" && scheme != "https" {
        return Err(format!("not an http(s) URL: {url}"));
    }
    let cut = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(cut);
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let (host, port) = pm_http::split_host_port(authority, pm_core::default_port(&scheme))
        .filter(|(h, _)| !h.is_empty())
        .ok_or_else(|| format!("bad host in URL: {url}"))?;
    let host_ok = |c: char| c.is_ascii_alphanumeric() || "-._~%!$&'()*+,;=:".contains(c);
    if !host.chars().all(host_ok) {
        return Err(format!("bad host in URL: {url}"));
    }
    let tail = tail.split('#').next().unwrap_or_default();
    // Spaces, control and non-ASCII characters are percent-encoded, as browsers do.
    let mut target = String::with_capacity(tail.len() + 1);
    if !tail.starts_with('/') {
        target.push('/');
    }
    for b in tail.bytes() {
        if b.is_ascii_graphic() {
            target.push(b as char);
        } else {
            target.push_str(&format!("%{b:02X}"));
        }
    }
    Ok(UrlParts { scheme, host, port, target })
}

/// Builds a request: request line, `Host` first unless given, the headers,
/// and a `Content-Length` for a body (an existing one is replaced, and
/// `Transfer-Encoding` dropped, since the body is given decoded).
/// True for an RFC 9110 token (method and header names).
pub fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Header values can't carry line breaks (they would forge more headers).
fn clean_value(v: &str) -> String {
    v.replace(['\r', '\n', '\0'], " ")
}

/// Builds a request: request line, `Host` first unless given, the headers,
/// and a `Content-Length` for a body (an existing one is replaced, and
/// `Transfer-Encoding` dropped, since the body is given decoded). Headers
/// with names that aren't tokens are left out; the caller checks the method.
pub fn build_request(method: &str, url: &UrlParts, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    debug_assert!(is_token(method));
    let mut out = format!("{method} {} HTTP/1.1\r\n", url.target).into_bytes();
    let has_host = headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("host"));
    if !has_host {
        out.extend_from_slice(format!("Host: {}\r\n", url.authority()).as_bytes());
    }
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if !is_token(name) || lower == "content-length" || lower == "transfer-encoding" {
            continue;
        }
        out.extend_from_slice(format!("{name}: {}\r\n", clean_value(value)).as_bytes());
    }
    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

fn build_response(status: u16, reason: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let bad = reason.is_empty() || reason.contains(['\r', '\n']);
    let reason = if bad { pm_http::reason_phrase(status) } else { reason };
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if !is_token(name) || matches!(lower.as_str(), "content-length" | "transfer-encoding" | "content-encoding") {
            continue;
        }
        out.extend_from_slice(format!("{name}: {}\r\n", clean_value(value)).as_bytes());
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    out.extend_from_slice(body);
    out
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn header_pairs(v: &Value) -> Vec<(String, String)> {
    v.get("headers")
        .and_then(Value::as_array)
        .map(|hs| {
            hs.iter()
                .filter_map(|h| {
                    let name = h.get("name")?.as_str()?.trim();
                    let value = h.get("value").and_then(Value::as_str).unwrap_or_default();
                    Some((name.to_string(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn form_encode(params: &[Value]) -> String {
    params
        .iter()
        .map(|p| format!("{}={}", percent_encode(str_field(p, "name")), percent_encode(str_field(p, "value"))))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Reads a HAR file. Returns the exchanges and a note for each entry skipped.
pub fn parse_har(text: &str, now_ms: i64) -> Result<(Vec<Imported>, Vec<String>), String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let entries = doc
        .get("log")
        .and_then(|l| l.get("entries"))
        .and_then(Value::as_array)
        .ok_or("not a HAR file: no log.entries")?;
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if out.len() >= MAX_ENTRIES {
            skipped.push(format!("stopped after {MAX_ENTRIES} entries"));
            break;
        }
        match har_entry(e, now_ms) {
            Ok(x) => out.push(x),
            Err(why) => skipped.push(format!("entry {i}: {why}")),
        }
    }
    Ok((out, skipped))
}

fn har_entry(e: &Value, now_ms: i64) -> Result<Imported, String> {
    let req = e.get("request").ok_or("no request")?;
    let method = str_field(req, "method").to_ascii_uppercase();
    if !is_token(&method) {
        return Err(format!("bad method {method:?}"));
    }
    let url = split_url(str_field(req, "url"))?;
    let headers = header_pairs(req);
    let body = match req.get("postData") {
        Some(pd) => match pd.get("text").and_then(Value::as_str) {
            Some(t) if str_field(pd, "encoding").eq_ignore_ascii_case("base64") => {
                crate::codec::base64_decode(t.trim(), false).map_err(|e| format!("request body: {e}"))?
            }
            Some(t) => t.as_bytes().to_vec(),
            None => form_encode(pd.get("params").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default())
                .into_bytes(),
        },
        None => Vec::new(),
    };
    let request = build_request(&method, &url, &headers, &body);

    let mut status = None;
    let mut response = None;
    if let Some(resp) = e.get("response") {
        let code = resp.get("status").and_then(Value::as_u64).unwrap_or(0);
        if (100..=999).contains(&code) {
            let content = resp.get("content").cloned().unwrap_or(Value::Null);
            let text = str_field(&content, "text");
            let body = if str_field(&content, "encoding").eq_ignore_ascii_case("base64") {
                crate::codec::base64_decode(text.trim(), false).map_err(|e| format!("response body: {e}"))?
            } else {
                text.as_bytes().to_vec()
            };
            let code = code as u16;
            response = Some(build_response(code, str_field(resp, "statusText"), &header_pairs(resp), &body));
            status = Some(code);
        }
    }
    let ts_ms = parse_iso8601(str_field(e, "startedDateTime")).unwrap_or(now_ms);
    let duration_ms = e.get("time").and_then(Value::as_f64).filter(|t| *t >= 0.0).map(|t| t.round() as i64);
    Ok(Imported {
        ts_ms,
        duration_ms,
        scheme: url.scheme,
        host: url.host,
        port: url.port,
        method,
        path: url.target,
        status,
        request,
        response,
    })
}

/// One exchange to write into a HAR file.
pub struct ExportItem {
    pub ts_ms: i64,
    pub duration_ms: Option<i64>,
    pub url: String,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
}

fn headers_json(hs: &[Header]) -> Value {
    Value::Array(hs.iter().map(|h| json!({ "name": h.name, "value": String::from_utf8_lossy(&h.value) })).collect())
}

fn content_type(hs: &[Header]) -> String {
    header(hs, "content-type").map(|v| String::from_utf8_lossy(v).into_owned()).unwrap_or_default()
}

/// Body as HAR text: UTF-8 as is, anything else as base64.
fn body_text(body: &[u8]) -> (String, Option<&'static str>) {
    match std::str::from_utf8(body) {
        Ok(s) => (s.to_string(), None),
        Err(_) => (pm_core::base64(body), Some("base64")),
    }
}

/// Undoes chunking and gzip/deflate so the HAR holds the content, as browsers write it.
fn decoded_body(hs: &[Header], body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    let te = header(hs, "transfer-encoding").map(|v| String::from_utf8_lossy(v).to_ascii_lowercase());
    if te.is_some_and(|t| t.contains("chunked"))
        && let Some(d) = pm_http::decode_chunked(&out)
    {
        out = d;
    }
    let ce = header(hs, "content-encoding").map(|v| String::from_utf8_lossy(v).trim().to_ascii_lowercase());
    let limit = 64 * 1024 * 1024;
    let inflated = match ce.as_deref() {
        Some("gzip" | "x-gzip") => read_limited(flate2::read::MultiGzDecoder::new(&out[..]), limit),
        Some("deflate") => read_limited(flate2::read::ZlibDecoder::new(&out[..]), limit)
            .or_else(|| read_limited(flate2::read::DeflateDecoder::new(&out[..]), limit)),
        _ => None,
    };
    inflated.unwrap_or(out)
}

fn read_limited(r: impl Read, limit: u64) -> Option<Vec<u8>> {
    let mut v = Vec::new();
    r.take(limit).read_to_end(&mut v).ok()?;
    Some(v)
}

fn query_string(url: &str) -> Value {
    let q = url.split_once('?').map(|(_, q)| q.split('#').next().unwrap_or_default()).unwrap_or_default();
    Value::Array(
        q.split('&')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let (n, v) = p.split_once('=').unwrap_or((p, ""));
                json!({ "name": n, "value": v })
            })
            .collect(),
    )
}

/// Writes exchanges as a HAR 1.2 document.
pub fn to_har(items: &[ExportItem], creator_version: &str) -> Value {
    let entries: Vec<Value> = items.iter().filter_map(export_entry).collect();
    json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "ProxyMind", "version": creator_version },
            "entries": entries,
        }
    })
}

fn export_entry(it: &ExportItem) -> Option<Value> {
    let end = find_head_end(&it.request).ok().flatten()?;
    let head = parse_request_head(&it.request[..end]).ok()?;
    let req_body = decoded_body(&head.headers, &it.request[end..]);
    let mut request = json!({
        "method": head.method,
        "url": it.url,
        "httpVersion": head.version,
        "cookies": [],
        "headers": headers_json(&head.headers),
        "queryString": query_string(&it.url),
        "headersSize": end,
        "bodySize": it.request.len() - end,
    });
    if !req_body.is_empty() {
        let (text, encoding) = body_text(&req_body);
        let mut pd = json!({ "mimeType": content_type(&head.headers), "text": text });
        if let Some(enc) = encoding {
            pd["encoding"] = json!(enc);
        }
        request["postData"] = pd;
    }
    let response = match it.response.as_deref().and_then(|r| {
        let end = find_head_end(r).ok().flatten()?;
        Some((end, parse_response_head(&r[..end]).ok()?, r))
    }) {
        Some((end, head, raw)) => {
            let body = decoded_body(&head.headers, &raw[end..]);
            let (text, encoding) = body_text(&body);
            let mut content = json!({ "size": body.len(), "mimeType": content_type(&head.headers), "text": text });
            if let Some(enc) = encoding {
                content["encoding"] = json!(enc);
            }
            let location = header(&head.headers, "location").map(|v| String::from_utf8_lossy(v).into_owned());
            json!({
                "status": head.status,
                "statusText": head.reason,
                "httpVersion": head.version,
                "cookies": [],
                "headers": headers_json(&head.headers),
                "content": content,
                "redirectURL": location.unwrap_or_default(),
                "headersSize": end,
                "bodySize": raw.len() - end,
            })
        }
        None => json!({
            "status": 0, "statusText": "", "httpVersion": "", "cookies": [], "headers": [],
            "content": { "size": 0, "mimeType": "" }, "redirectURL": "", "headersSize": -1, "bodySize": -1,
            "_error": "no response",
        }),
    };
    let time = it.duration_ms.unwrap_or(0).max(0);
    Some(json!({
        "startedDateTime": format_iso8601(it.ts_ms),
        "time": time,
        "request": request,
        "response": response,
        "cache": {},
        "timings": { "send": 0, "wait": time, "receive": 0 },
    }))
}

// Dates: days since 1970-01-01 for a civil date and back (H. Hinnant's algorithms).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { yoe + era * 400 + 1 } else { yoe + era * 400 }, m, d)
}

/// `2024-01-02T03:04:05.678Z` (or with a `+hh:mm` offset) as Unix milliseconds.
pub fn parse_iso8601(s: &str) -> Option<i64> {
    let b = s.trim().as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = b.get(r)?;
        part.iter().all(u8::is_ascii_digit).then(|| part.iter().fold(0i64, |a, d| a * 10 + i64::from(d - b'0')))
    };
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    let mut ms = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        let frac = &s[start..i];
        ms = format!("{frac:0<3}")[..3].parse().ok()?;
    }
    let offset_min = match b.get(i) {
        None | Some(b'Z' | b'z') => 0,
        Some(sign @ (b'+' | b'-')) => {
            let oh = num(i + 1..i + 3)?;
            let om = if b.get(i + 3) == Some(&b':') { num(i + 4..i + 6)? } else { num(i + 3..i + 5).unwrap_or(0) };
            let o = oh * 60 + om;
            if *sign == b'+' { o } else { -o }
        }
        _ => return None,
    };
    let days = days_from_civil(y, mo, d);
    Some(((days * 86_400 + h * 3600 + mi * 60 + sec - offset_min * 60) * 1000) + ms)
}

/// Unix milliseconds as `2024-01-02T03:04:05.678Z`.
pub fn format_iso8601(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, rem % 3600 / 60, rem % 60, ms.rem_euclid(1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HAR: &str = r#"{"log":{"version":"1.2","creator":{"name":"x","version":"1"},"entries":[
      {"startedDateTime":"2024-03-01T10:00:00.250+01:00","time":12.4,
       "request":{"method":"POST","url":"https://shop.test:8443/api/login?next=%2F#frag","httpVersion":"h2",
         "headers":[{"name":":authority","value":"shop.test:8443"},{"name":"content-type","value":"application/json"},
                    {"name":"content-length","value":"999"},{"name":"X-Evil","value":"a\r\nInjected: 1"}],
         "postData":{"mimeType":"application/json","text":"{\"u\":\"a\"}"}},
       "response":{"status":200,"statusText":"OK","httpVersion":"h2",
         "headers":[{"name":"content-encoding","value":"gzip"},{"name":"content-type","value":"text/plain"}],
         "content":{"size":2,"mimeType":"text/plain","text":"aGk=","encoding":"base64"}}},
      {"startedDateTime":"bad","time":-1,"request":{"method":"GET","url":"http://a.test/x"},
       "response":{"status":0,"content":{}}},
      {"request":{"method":"GET","url":"ftp://a.test/"}},
      {"request":{"method":"POST","url":"http://a.test/f","postData":{"params":[{"name":"a b","value":"1&2"}]}}}
    ]}}"#;

    #[test]
    fn imports_entries() {
        let (got, skipped) = parse_har(HAR, 42).unwrap();
        assert_eq!(got.len(), 3, "{skipped:?}");
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains("entry 2"));

        let a = &got[0];
        assert_eq!((a.scheme.as_str(), a.host.as_str(), a.port), ("https", "shop.test", 8443));
        assert_eq!(a.path, "/api/login?next=%2F");
        assert_eq!(a.ts_ms, parse_iso8601("2024-03-01T09:00:00.250Z").unwrap());
        assert_eq!(a.duration_ms, Some(12));
        let req = String::from_utf8(a.request.clone()).unwrap();
        assert_eq!(
            req,
            "POST /api/login?next=%2F HTTP/1.1\r\nHost: shop.test:8443\r\ncontent-type: application/json\r\n\
             X-Evil: a  Injected: 1\r\nContent-Length: 9\r\n\r\n{\"u\":\"a\"}"
        );
        let resp = String::from_utf8(a.response.clone().unwrap()).unwrap();
        assert_eq!(resp, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nContent-Length: 2\r\n\r\nhi");

        let b = &got[1];
        assert_eq!((b.ts_ms, b.duration_ms, b.status, b.response.is_none()), (42, None, None, true));
        assert_eq!(b.request, b"GET /x HTTP/1.1\r\nHost: a.test\r\n\r\n");

        assert!(String::from_utf8_lossy(&got[2].request).ends_with("Content-Length: 11\r\n\r\na%20b=1%262"));
    }

    #[test]
    fn rejects_non_har() {
        assert!(parse_har("{}", 0).is_err());
        assert!(parse_har("nope", 0).is_err());
    }

    #[test]
    fn exports_and_reimports() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"hello gzip").unwrap();
        let gz = gz.finish().unwrap();
        let mut resp = format!(
            "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            gz.len()
        )
        .into_bytes();
        resp.extend_from_slice(&gz);
        resp.extend_from_slice(b"\r\n0\r\n\r\n");
        let req = b"POST /p?a=1&b HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/octet-stream\r\nContent-Length: 2\r\n\r\n\xff\x00";
        let items = [
            ExportItem {
                ts_ms: 1_700_000_000_123,
                duration_ms: Some(5),
                url: "http://x.test/p?a=1&b".into(),
                request: req.to_vec(),
                response: Some(resp),
            },
            ExportItem {
                ts_ms: 0,
                duration_ms: None,
                url: "http://x.test/".into(),
                request: b"junk".to_vec(),
                response: None,
            },
        ];
        let har = to_har(&items, "0.0.1");
        let e = &har["log"]["entries"];
        assert_eq!(e.as_array().unwrap().len(), 1);
        assert_eq!(e[0]["startedDateTime"], "2023-11-14T22:13:20.123Z");
        assert_eq!(e[0]["request"]["queryString"][1]["name"], "b");
        assert_eq!(e[0]["request"]["postData"]["encoding"], "base64");
        assert_eq!(e[0]["response"]["content"]["text"], "hello gzip");
        assert_eq!(e[0]["response"]["redirectURL"], "/next");

        let (back, skipped) = parse_har(&har.to_string(), 0).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(back[0].ts_ms, 1_700_000_000_123);
        assert_eq!(back[0].status, Some(302));
        assert!(back[0].response.as_ref().unwrap().ends_with(b"Content-Length: 10\r\n\r\nhello gzip"));
        assert_eq!(&back[0].request[back[0].request.len() - 2..], b"\xff\x00");
    }

    #[test]
    fn dates_round_trip() {
        for ms in [0, 1, 951_782_400_000, 1_709_251_200_999, -86_400_000, 4_102_444_800_000] {
            assert_eq!(parse_iso8601(&format_iso8601(ms)), Some(ms), "{ms}");
        }
        assert_eq!(parse_iso8601("2024-02-29T00:00:00Z"), Some(1_709_164_800_000));
        assert_eq!(parse_iso8601("2024-02-29T01:30:00+0130"), Some(1_709_164_800_000));
        assert_eq!(parse_iso8601("2024-13-01T00:00:00Z"), None);
        assert_eq!(parse_iso8601("yesterday"), None);
    }

    #[test]
    fn splits_urls() {
        let u = split_url("HTTPS://user:pw@[::1]:8443?x=1#f").unwrap();
        assert_eq!((u.scheme.as_str(), u.host.as_str(), u.port, u.target.as_str()), ("https", "::1", 8443, "/?x=1"));
        assert_eq!(u.authority(), "[::1]:8443");
        assert_eq!(split_url("example.com/a").unwrap().authority(), "example.com");
        assert!(split_url("javascript:alert(1)").is_err());
        assert!(split_url("http:///x").is_err());
    }
}
