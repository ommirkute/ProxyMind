//! Custom checks: scan checks written as a short YAML file, so people can
//! add and share checks without writing a plugin. A check says which
//! requests to send (payloads at each insertion point, or a change to the
//! request) and what in the response counts as a hit. The service sends
//! the requests through the policy gate; this module only builds them and
//! judges the responses (no I/O).
//!
//! ```yaml
//! id: debug-switch
//! title: Debug mode switch
//! severity: medium
//! run: per_request
//! request:
//!   add_query: { debug: "true" }
//! match:
//!   body_contains: ["stack trace"]
//!   not_in_baseline: true
//! ```

use std::collections::BTreeMap;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::active::{self, PointKind};

/// Most requests one check builds for one request.
pub const MAX_PROBES: usize = 200;
/// Longest check file.
pub const MAX_YAML: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunOn {
    /// Each payload at each insertion point (query, form, JSON, path, cookie, header values).
    #[default]
    PerInsertionPoint,
    /// One changed copy of the request (see `request`).
    PerRequest,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadMode {
    /// The payload replaces the value.
    #[default]
    Replace,
    /// The payload goes after the value.
    Append,
}

/// Changes to the request (per_request checks; also applied before payloads).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RequestChange {
    pub method: Option<String>,
    /// A new path (and query), e.g. "/.git/config".
    pub path: Option<String>,
    pub add_query: BTreeMap<String, String>,
    pub add_headers: BTreeMap<String, String>,
    pub remove_headers: Vec<String>,
}

/// What makes a response a hit. Every condition given must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Match {
    /// The status is one of these.
    pub status: Vec<u16>,
    /// The status is none of these.
    pub status_not: Vec<u16>,
    /// The body contains all of these (case-insensitive).
    pub body_contains: Vec<String>,
    /// The body contains at least one of these (case-insensitive).
    pub body_contains_any: Vec<String>,
    /// The body matches this regex.
    pub body_regex: Option<String>,
    /// The response head contains each of these (case-insensitive), e.g. "access-control-allow-origin: *".
    pub header_contains: Vec<String>,
    /// The matched text is not in the baseline response (it came from the probe).
    pub not_in_baseline: bool,
    /// The status differs from the baseline's.
    pub status_differs: bool,
    /// The payload comes back unencoded.
    pub reflected: bool,
    /// The response took at least this long.
    pub min_time_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomCheck {
    /// Lower case letters, digits, '-' and '_' (1 to 40).
    pub id: String,
    pub title: String,
    /// info, low, medium or high.
    #[serde(default = "medium")]
    pub severity: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub run: RunOn,
    #[serde(default)]
    pub payloads: Vec<String>,
    #[serde(default)]
    pub payload_mode: PayloadMode,
    /// Insertion point kinds to use: query, form, json, path, cookie, header (default: all of them).
    #[serde(default)]
    pub points: Vec<String>,
    #[serde(default)]
    pub request: RequestChange,
    #[serde(rename = "match")]
    pub matcher: Match,
}

fn medium() -> String {
    "medium".into()
}

const POINT_KINDS: &[&str] = &["query", "form", "json", "path", "cookie", "header"];

/// Reads and checks a check file.
pub fn parse(yaml: &str) -> Result<CustomCheck, String> {
    if yaml.len() > MAX_YAML {
        return Err(format!("a check is at most {} KB", MAX_YAML / 1024));
    }
    let c: CustomCheck = serde_saphyr::from_str(yaml).map_err(|e| format!("not a valid check: {e}"))?;
    validate(&c)?;
    Ok(c)
}

pub fn validate(c: &CustomCheck) -> Result<(), String> {
    if c.id.is_empty()
        || c.id.len() > 40
        || !c.id.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_')
    {
        return Err("id: 1 to 40 lower case letters, digits, '-' or '_'".into());
    }
    if c.title.trim().is_empty() || c.title.len() > 200 {
        return Err("title: 1 to 200 characters".into());
    }
    if !["info", "low", "medium", "high"].contains(&c.severity.as_str()) {
        return Err("severity: info, low, medium or high".into());
    }
    if let Some(bad) = c.points.iter().find(|p| !POINT_KINDS.contains(&p.as_str())) {
        return Err(format!("points: {bad} is not one of {}", POINT_KINDS.join(", ")));
    }
    match c.run {
        RunOn::PerInsertionPoint if c.payloads.is_empty() => {
            return Err("per_insertion_point checks need at least one payload".into());
        }
        RunOn::PerRequest if c.request == RequestChange::default() => {
            return Err("per_request checks need a request change (method, path, add_query, add_headers…)".into());
        }
        _ => {}
    }
    if c.payloads.len() > 100 || c.payloads.iter().any(|p| p.len() > 4096) {
        return Err("payloads: at most 100, each at most 4 KB".into());
    }
    if let Some(m) = &c.request.method
        && (m.is_empty() || !m.chars().all(|ch| ch.is_ascii_uppercase()))
    {
        return Err("request.method: upper case letters, e.g. PUT".into());
    }
    if let Some(p) = &c.request.path
        && (!p.starts_with('/') || p.chars().any(|ch| ch.is_whitespace() || ch.is_control()))
    {
        return Err("request.path: starts with '/', no spaces".into());
    }
    let bad_text = |s: &String| s.chars().any(|ch| ch == '\r' || ch == '\n');
    if c.request.add_headers.iter().any(|(k, v)| bad_text(k) || bad_text(v) || k.contains(':') || k.trim().is_empty())
        || c.request.add_query.iter().any(|(k, v)| bad_text(k) || bad_text(v))
    {
        return Err("request: header and query names and values are single lines".into());
    }
    let m = &c.matcher;
    if m == &Match::default() || (m.not_in_baseline && !has_text_condition(m) && m.status.is_empty()) {
        return Err("match: give at least one condition (status, body_contains, body_regex…)".into());
    }
    if m.not_in_baseline && !has_text_condition(m) {
        return Err("match.not_in_baseline needs a body or header condition to compare".into());
    }
    if m.reflected && c.payloads.is_empty() {
        return Err("match.reflected needs payloads".into());
    }
    compile(m)?;
    Ok(())
}

fn has_text_condition(m: &Match) -> bool {
    !m.body_contains.is_empty()
        || !m.body_contains_any.is_empty()
        || m.body_regex.is_some()
        || !m.header_contains.is_empty()
}

fn compile(m: &Match) -> Result<Option<Regex>, String> {
    m.body_regex
        .as_deref()
        .map(|r| RegexBuilder::new(r).size_limit(1 << 20).build().map_err(|e| format!("match.body_regex: {e}")))
        .transpose()
}

/// A request a check sends.
#[derive(Debug, Clone, Serialize)]
pub struct CustomProbe {
    /// Where the payload went ("query q", "request").
    pub point: String,
    pub payload: Option<String>,
    #[serde(skip)]
    pub raw: Vec<u8>,
}

fn change_request(raw: &str, ch: &RequestChange) -> Option<String> {
    let (first, rest) = raw.split_once("\r\n").or_else(|| raw.split_once('\n'))?;
    let mut parts = first.splitn(3, ' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next().unwrap_or("HTTP/1.1"));
    let method = ch.method.as_deref().unwrap_or(method);
    let mut target = ch.path.clone().unwrap_or_else(|| target.to_string());
    for (k, v) in &ch.add_query {
        let sep = if target.contains('?') { '&' } else { '?' };
        target = format!("{target}{sep}{}={}", enc(k), enc(v));
    }
    let mut out = format!("{method} {target} {version}\r\n{rest}");
    if !ch.remove_headers.is_empty() {
        let (head, body) = out.split_once("\r\n\r\n").unwrap_or((&out, ""));
        let kept: Vec<&str> = head
            .split("\r\n")
            .enumerate()
            .filter(|(i, l)| {
                *i == 0
                    || !l
                        .split_once(':')
                        .is_some_and(|(k, _)| ch.remove_headers.iter().any(|h| h.eq_ignore_ascii_case(k.trim())))
            })
            .map(|(_, l)| l)
            .collect();
        out = format!("{}\r\n\r\n{body}", kept.join("\r\n"));
    }
    for (k, v) in &ch.add_headers {
        out = String::from_utf8(active::set_header(&out, k, v)?).ok()?;
    }
    Some(out)
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The requests `check` sends for the recorded request `raw`.
pub fn probes(check: &CustomCheck, raw: &str) -> Vec<CustomProbe> {
    let base = if check.request == RequestChange::default() {
        Some(raw.to_string())
    } else {
        change_request(raw, &check.request)
    };
    let Some(base) = base else { return Vec::new() };
    match check.run {
        RunOn::PerRequest => vec![CustomProbe { point: "request".into(), payload: None, raw: base.into_bytes() }],
        RunOn::PerInsertionPoint => {
            let want = |k: PointKind| {
                let name =
                    serde_json::to_value(k).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
                POINT_KINDS.contains(&name.as_str()) && (check.points.is_empty() || check.points.contains(&name))
            };
            let mut out = Vec::new();
            for pt in active::points(&base).into_iter().filter(|p| want(p.kind)) {
                for p in &check.payloads {
                    if out.len() >= MAX_PROBES {
                        return out;
                    }
                    let value = match check.payload_mode {
                        PayloadMode::Replace => p.clone(),
                        PayloadMode::Append => format!("{}{p}", pt.original),
                    };
                    if let Some(r) = active::inject(&base, &pt, &value) {
                        let kind = serde_json::to_value(pt.kind).ok().and_then(|v| v.as_str().map(str::to_string));
                        out.push(CustomProbe {
                            point: format!("{} {}", kind.unwrap_or_default(), pt.name),
                            payload: Some(p.clone()),
                            raw: r,
                        });
                    }
                }
            }
            out
        }
    }
}

/// A response, as the matcher sees it.
pub struct Seen<'a> {
    pub status: Option<u16>,
    /// Head as text.
    pub head: &'a str,
    /// Decoded body as text.
    pub body: &'a str,
    pub elapsed_ms: u64,
}

/// Whether `resp` is a hit, with the evidence (a short excerpt).
pub fn judge(check: &CustomCheck, baseline: Option<&Seen>, resp: &Seen, payload: Option<&str>) -> Option<String> {
    let m = &check.matcher;
    let re = compile(m).ok().flatten();
    let status = resp.status?;
    if !m.status.is_empty() && !m.status.contains(&status) {
        return None;
    }
    if m.status_not.contains(&status) {
        return None;
    }
    if m.status_differs && baseline.and_then(|b| b.status) == Some(status) {
        return None;
    }
    if m.min_time_ms.is_some_and(|t| resp.elapsed_ms < t) {
        return None;
    }
    let body_l = resp.body.to_lowercase();
    let head_l = resp.head.to_lowercase();
    let base_body = baseline.map(|b| b.body.to_lowercase()).unwrap_or_default();
    let base_head = baseline.map(|b| b.head.to_lowercase()).unwrap_or_default();
    let mut evidence: Vec<String> = vec![format!("status {status}")];
    // A text condition: present in the probe's response (and not the baseline's, when asked).
    let fresh =
        |hay: &str, base: &str, needle: &str| hay.contains(needle) && !(m.not_in_baseline && base.contains(needle));
    for t in &m.body_contains {
        let n = t.to_lowercase();
        if !fresh(&body_l, &base_body, &n) {
            return None;
        }
        evidence.push(excerpt(resp.body, &body_l, &n));
    }
    if !m.body_contains_any.is_empty() {
        let hit = m.body_contains_any.iter().map(|t| t.to_lowercase()).find(|n| fresh(&body_l, &base_body, n))?;
        evidence.push(excerpt(resp.body, &body_l, &hit));
    }
    if let Some(re) = &re {
        let found = re.find(resp.body)?;
        if m.not_in_baseline && baseline.is_some_and(|b| b.body.contains(found.as_str())) {
            return None;
        }
        evidence.push(found.as_str().chars().take(120).collect());
    }
    for h in &m.header_contains {
        let n = h.to_lowercase();
        if !fresh(&head_l, &base_head, &n) {
            return None;
        }
        evidence.push(h.clone());
    }
    if m.reflected {
        let p = payload?;
        if p.is_empty() || !resp.body.contains(p) {
            return None;
        }
        evidence.push(format!("payload reflected: {}", p.chars().take(80).collect::<String>()));
    }
    if m.min_time_ms.is_some() {
        evidence.push(format!("{} ms", resp.elapsed_ms));
    }
    Some(evidence.join(" · "))
}

fn excerpt(text: &str, lower: &str, needle: &str) -> String {
    let Some(at) = lower.find(needle) else { return needle.to_string() };
    // Lowercasing can shift byte offsets for non-ASCII text: fall back to the needle.
    let start = text.char_indices().map(|(i, _)| i).take_while(|&i| i + 40 <= at).last().unwrap_or(0);
    let s: String = text.get(start..).unwrap_or(needle).chars().take(needle.chars().count() + 80).collect();
    s.replace(['\r', '\n'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "GET /search?q=shoes&page=1 HTTP/1.1\r\nHost: shop\r\nCookie: s=abc\r\n\r\n";

    fn seen<'a>(status: u16, head: &'a str, body: &'a str) -> Seen<'a> {
        Seen { status: Some(status), head, body, elapsed_ms: 5 }
    }

    #[test]
    fn parses_and_validates() {
        let c = parse(
            "id: debug-switch\ntitle: Debug switch\nrun: per_request\nrequest:\n  add_query: { debug: \"true\" }\n\
             match:\n  body_contains: [stack trace]\n  not_in_baseline: true\n",
        )
        .unwrap();
        assert_eq!((c.severity.as_str(), c.run), ("medium", RunOn::PerRequest));
        assert!(parse("id: Bad Id\ntitle: x\npayloads: [a]\nmatch: {status: [200]}\n").is_err());
        assert!(parse("id: a\ntitle: x\nmatch: {status: [200]}\n").unwrap_err().contains("payload"));
        assert!(parse("id: a\ntitle: x\npayloads: [a]\nmatch: {}\n").unwrap_err().contains("condition"));
        assert!(parse("id: a\ntitle: x\npayloads: [a]\nmatch: {body_regex: \"(\"}\n").is_err());
        assert!(parse("id: a\ntitle: x\npayloads: [a]\nunknown: 1\nmatch: {status: [200]}\n").is_err());
        let smuggle = "id: a\ntitle: x\nrun: per_request\nrequest:\n  add_headers: { \"X-A\": \"1\\r\\nX-B: 2\" }\nmatch: {status: [200]}\n";
        assert!(parse(smuggle).is_err(), "no header injection through a check");
    }

    #[test]
    fn builds_probes() {
        let c =
            parse("id: a\ntitle: x\npayloads: [\"'\", \"<b>\"]\npoints: [query]\nmatch: {reflected: true}\n").unwrap();
        let ps = probes(&c, RAW);
        assert_eq!(ps.len(), 4, "two query values × two payloads");
        assert_eq!(ps[0].point, "query q");
        assert!(String::from_utf8_lossy(&ps[0].raw).starts_with("GET /search?q=%27&page=1 "));
        let c = parse(
            "id: a\ntitle: x\nrun: per_request\nrequest:\n  method: POST\n  path: /admin\n  add_query: {x: \"1 2\"}\n  \
             add_headers: {X-Debug: \"1\"}\n  remove_headers: [cookie]\nmatch: {status: [200]}\n",
        )
        .unwrap();
        let r = String::from_utf8(probes(&c, RAW).remove(0).raw).unwrap();
        assert!(r.starts_with("POST /admin?x=1%202 HTTP/1.1\r\n"), "{r}");
        assert!(r.contains("X-Debug: 1") && !r.to_lowercase().contains("cookie"), "{r}");
        let c = parse(
            "id: a\ntitle: x\npayloads: [\"--\"]\npayload_mode: append\npoints: [cookie]\nmatch: {status: [500]}\n",
        )
        .unwrap();
        assert!(String::from_utf8_lossy(&probes(&c, RAW)[0].raw).contains("Cookie: s=abc--"));
    }

    #[test]
    fn judges_responses() {
        let c = parse(
            "id: a\ntitle: x\nrun: per_request\nrequest: {add_query: {debug: \"1\"}}\nmatch:\n  status: [200]\n  \
             body_contains: [Traceback]\n  not_in_baseline: true\n",
        )
        .unwrap();
        let base = seen(200, "HTTP/1.1 200 OK", "<p>ok</p>");
        let hit = seen(200, "HTTP/1.1 200 OK", "<pre>Traceback (most recent call last)</pre>");
        assert!(judge(&c, Some(&base), &hit, None).unwrap().contains("Traceback"));
        assert!(judge(&c, Some(&hit), &hit, None).is_none(), "already in the baseline");
        assert!(judge(&c, Some(&base), &seen(500, "", "Traceback"), None).is_none(), "wrong status");

        let refl = parse("id: a\ntitle: x\npayloads: [\"<b>pm</b>\"]\nmatch: {reflected: true}\n").unwrap();
        assert!(judge(&refl, None, &seen(200, "", "hi <b>pm</b>"), Some("<b>pm</b>")).is_some());
        assert!(judge(&refl, None, &seen(200, "", "hi &lt;b&gt;pm"), Some("<b>pm</b>")).is_none());

        let cors = parse(
            "id: a\ntitle: x\nrun: per_request\nrequest: {add_headers: {Origin: \"https://evil.test\"}}\n\
             match: {header_contains: [\"access-control-allow-origin: https://evil.test\"]}\n",
        )
        .unwrap();
        let h = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: https://evil.test";
        assert!(judge(&cors, None, &seen(200, h, ""), None).is_some());
    }
}
