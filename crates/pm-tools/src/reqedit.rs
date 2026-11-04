//! Request helpers for the Replay editor: switch a request between GET and
//! POST, or re-encode its body (URL-encoded form, multipart, JSON), keeping
//! the parameters. Works on the editor's text; the line ending in use (CRLF
//! or LF) is kept, and Content-Length follows the new body.

use serde::Deserialize;

use crate::engage::{form_pairs, multipart_fields};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyEncoding {
    UrlEncoded,
    Multipart,
    Json,
}

struct Req {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    body: String,
    nl: &'static str,
}

fn parse(raw: &str) -> Result<Req, String> {
    let nl = if raw.contains("\r\n") { "\r\n" } else { "\n" };
    let (head, body) = raw.split_once(&format!("{nl}{nl}")).map_or((raw.trim_end_matches(nl), ""), |(h, b)| (h, b));
    let mut lines = head.split(nl);
    let first = lines.next().unwrap_or("");
    let mut parts = first.split(' ');
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Err("the first line must be METHOD TARGET VERSION".into());
    };
    if method.is_empty() || target.is_empty() {
        return Err("the first line must be METHOD TARGET VERSION".into());
    }
    let version = parts.collect::<Vec<_>>().join(" ");
    let headers = lines
        .filter(|l| !l.is_empty())
        .map(|l| match l.split_once(':') {
            Some((k, v)) => (k.to_string(), v.trim_start().to_string()),
            None => (l.to_string(), String::new()),
        })
        .collect();
    Ok(Req { method: method.to_string(), target: target.to_string(), version, headers, body: body.to_string(), nl })
}

impl Req {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn remove(&mut self, name: &str) {
        self.headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
    }

    fn set(&mut self, name: &str, value: &str) {
        match self.headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(name)) {
            Some(h) => h.1 = value.to_string(),
            None => self.headers.push((name.to_string(), value.to_string())),
        }
    }

    /// Sets the body with its type and length (no body: neither header).
    fn set_body(&mut self, body: String, content_type: Option<&str>) {
        self.remove("transfer-encoding");
        match content_type {
            Some(ct) => self.set("Content-Type", ct),
            None => self.remove("content-type"),
        }
        if body.is_empty() && content_type.is_none() {
            self.remove("content-length");
        } else {
            self.set("Content-Length", &body.len().to_string());
        }
        self.body = body;
    }

    fn build(&self) -> String {
        let nl = self.nl;
        let mut out = format!("{} {}", self.method, self.target);
        if !self.version.is_empty() {
            out.push(' ');
            out.push_str(&self.version);
        }
        out.push_str(nl);
        for (k, v) in &self.headers {
            out.push_str(&format!("{k}: {v}{nl}"));
        }
        out.push_str(nl);
        out.push_str(&self.body);
        out
    }

    /// The body's parameters, read by its content type.
    fn fields(&self) -> Result<Vec<(String, String)>, String> {
        let ct = self.header("content-type").unwrap_or("").to_ascii_lowercase();
        if self.body.trim().is_empty() {
            return Ok(vec![]);
        }
        if ct.contains("json") || ct.is_empty() && self.body.trim_start().starts_with('{') {
            let o: Ordered = serde_json::from_str(&self.body)
                .map_err(|e| format!("only a JSON object can be turned into parameters ({e})"))?;
            return Ok(o
                .0
                .into_iter()
                .map(|(k, v)| match v {
                    serde_json::Value::String(s) => (k, s),
                    other => (k, other.to_string()),
                })
                .collect());
        }
        if ct.contains("multipart/form-data") {
            let original = self.header("content-type").unwrap_or("");
            return Ok(multipart_fields(&self.body, original));
        }
        if ct.contains("x-www-form-urlencoded") || ct.is_empty() && self.body.contains('=') {
            return Ok(form_pairs(self.body.trim_end()));
        }
        Err(format!("a {ct} body can't be turned into parameters"))
    }
}

/// A JSON object's members in the order written.
struct Ordered(Vec<(String, serde_json::Value)>);

impl<'de> Deserialize<'de> for Ordered {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Ordered;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut m: A) -> Result<Ordered, A::Error> {
                let mut out = Vec::new();
                while let Some(kv) = m.next_entry()? {
                    out.push(kv);
                }
                Ok(Ordered(out))
            }
        }
        d.deserialize_map(V)
    }
}

/// Percent-encodes for a form or query (space as `+`).
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn urlencoded(fields: &[(String, String)]) -> String {
    fields.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&")
}

/// GET ⇄ POST: a GET's query string becomes a URL-encoded body; any other
/// method becomes a GET with the body's parameters in the query string.
pub fn change_method(raw: &str) -> Result<String, String> {
    let mut r = parse(raw)?;
    if r.method.eq_ignore_ascii_case("GET") {
        let (path, query) = match r.target.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (r.target.clone(), String::new()),
        };
        r.method = "POST".into();
        r.target = path;
        // The query moves as it was written: no re-encoding.
        r.set_body(query, Some("application/x-www-form-urlencoded"));
    } else {
        let ct = r.header("content-type").unwrap_or("").to_ascii_lowercase();
        let moved =
            if ct.contains("x-www-form-urlencoded") { r.body.trim_end().to_string() } else { urlencoded(&r.fields()?) };
        if !moved.is_empty() {
            let sep = if r.target.contains('?') { "&" } else { "?" };
            r.target = format!("{}{sep}{moved}", r.target);
        }
        r.method = "GET".into();
        r.set_body(String::new(), None);
    }
    Ok(r.build())
}

/// Re-encodes the body's parameters. JSON values become strings when
/// converting away from JSON and stay strings converting back.
pub fn convert_body(raw: &str, to: BodyEncoding) -> Result<String, String> {
    let mut r = parse(raw)?;
    let fields = r.fields()?;
    match to {
        BodyEncoding::UrlEncoded => r.set_body(urlencoded(&fields), Some("application/x-www-form-urlencoded")),
        BodyEncoding::Json => {
            let members: Vec<String> = fields
                .into_iter()
                .map(|(k, v)| format!("{}:{}", serde_json::Value::String(k), serde_json::Value::String(v)))
                .collect();
            r.set_body(format!("{{{}}}", members.join(",")), Some("application/json"));
        }
        BodyEncoding::Multipart => {
            let mut boundary = String::from("----ProxyMindFormBoundary");
            let mut n = 0u32;
            while fields.iter().any(|(k, v)| k.contains(&boundary) || v.contains(&boundary)) {
                n += 1;
                boundary = format!("----ProxyMindFormBoundary{n}");
            }
            let mut body = String::new();
            for (k, v) in &fields {
                let name = k.replace(['"', '\r', '\n'], "_");
                body.push_str(&format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{v}\r\n"
                ));
            }
            body.push_str(&format!("--{boundary}--\r\n"));
            r.set_body(body, Some(&format!("multipart/form-data; boundary={boundary}")));
        }
    }
    Ok(r.build())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GET: &str = "GET /search?q=a+b&page=2 HTTP/1.1\r\nHost: x.test\r\nCookie: s=1\r\n\r\n";

    #[test]
    fn get_and_post_round_trip() {
        let post = change_method(GET).unwrap();
        assert_eq!(
            post,
            "POST /search HTTP/1.1\r\nHost: x.test\r\nCookie: s=1\r\nContent-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 12\r\n\r\nq=a+b&page=2"
        );
        let back = change_method(&post).unwrap();
        assert_eq!(back, GET);
    }

    #[test]
    fn json_post_becomes_get_with_query() {
        let raw = "PUT /api?x=1 HTTP/1.1\nHost: x.test\nContent-Type: application/json\nContent-Length: 20\n\n{\"a\":\"b c\",\"n\":5}";
        let get = change_method(raw).unwrap();
        assert_eq!(get, "GET /api?x=1&a=b+c&n=5 HTTP/1.1\nHost: x.test\n\n");
    }

    #[test]
    fn body_encodings_convert_both_ways() {
        let form = "POST /login HTTP/1.1\r\nHost: x.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\
                    Content-Length: 22\r\n\r\nuser=al%40x&pass=p+w%26";
        let json = convert_body(form, BodyEncoding::Json).unwrap();
        assert!(json.ends_with("\r\n\r\n{\"user\":\"al@x\",\"pass\":\"p w&\"}"), "{json}");
        assert!(json.contains("Content-Type: application/json\r\n"));
        assert!(json.contains("Content-Length: 29\r\n"));
        let multi = convert_body(&json, BodyEncoding::Multipart).unwrap();
        assert!(multi.contains("Content-Type: multipart/form-data; boundary=----ProxyMindFormBoundary\r\n"));
        assert!(multi.contains("name=\"pass\"\r\n\r\np w&\r\n"));
        let again = convert_body(&multi, BodyEncoding::UrlEncoded).unwrap();
        assert!(again.ends_with("\r\n\r\nuser=al%40x&pass=p+w%26"), "{again}");
    }

    #[test]
    fn unreadable_bodies_are_refused() {
        let raw = "POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/octet-stream\r\n\r\n\x01\x02";
        assert!(convert_body(raw, BodyEncoding::Json).is_err());
        assert!(change_method("nonsense").is_err());
    }
}
