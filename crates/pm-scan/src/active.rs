//! Active checks: build probe requests from a recorded one, then compare
//! each probe's response with the baseline. No I/O here: the service layer
//! sends the probes through the policy gate.
//!
//! Insertion points are query parameters, form fields, JSON string and
//! number values, and numeric path segments. Checks:
//!
//! | check | payloads | flagged when |
//! |---|---|---|
//! | `sql_error` | `'`, `"`, `')` | a database error appears that the baseline didn't show |
//! | `reflected_input` | a unique marker with `<"'>` | the marker comes back with `<` and `"` unencoded in HTML |
//! | `open_redirect` | `https://pm-redirect.example/` (redirect-like parameters) | a 3xx points at that host |
//! | `path_traversal` | `../` sequences to `/etc/passwd` and `win.ini` (file-like parameters) | the file's content comes back |
//! | `ssti` | `{{7*191}}`, `${7*191}`, `<%= 7*191 %>` | `1337` appears and wasn't in the baseline |
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
}

pub const CHECKS: &[&str] = &["sql_error", "reflected_input", "open_redirect", "path_traversal", "ssti"];

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

fn percent_encode(s: &str) -> String {
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

struct Parsed<'a> {
    method: &'a str,
    target: &'a str,
    version: &'a str,
    rest_of_head: &'a str,
    body: &'a str,
    form: bool,
    json: bool,
}

fn parse(raw: &str) -> Option<Parsed<'_>> {
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
    })
}

fn rebuild(p: &Parsed, target: &str, body: &str) -> Vec<u8> {
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

/// Places where payloads can go in `raw`.
pub fn points(raw: &str) -> Vec<Point> {
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
        if !seg.is_empty() && seg.len() <= 20 && seg.chars().all(|c| c.is_ascii_digit()) {
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
    out
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

/// The probes for `checks` (all when empty), at most `limit`.
pub fn probes(raw: &str, checks: &[String], marker: &str, limit: usize) -> Vec<Probe> {
    let want = |c: &str| checks.is_empty() || checks.iter().any(|x| x == c);
    let mut out = Vec::new();
    for pt in points(raw) {
        let mut add = |check: &'static str, payload: String| {
            if out.len() < limit
                && let Some(r) = inject(raw, &pt, &payload)
            {
                out.push(Probe { check, point: pt.clone(), payload, raw: r });
            }
        };
        if want("sql_error") {
            for s in ["'", "\"", "')"] {
                add("sql_error", format!("{}{s}", pt.original));
            }
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
            for t in ["{{7*191}}", "${7*191}", "<%= 7*191 %>"] {
                add("ssti", t.into());
            }
        }
    }
    out
}

fn snippet(text: &str, at: usize, n: usize) -> String {
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
            let (what, sql, at) = crate::error_signature(&got.body)?;
            if !sql || crate::error_signature(&base.body).is_some_and(|b| b.1) {
                return None;
            }
            Some(issue(
                "Database error caused by a quote (likely SQL injection)",
                "high",
                format!("{what}: {}", snippet(&got.body, at, 140)),
                Some("proof_run oracle timing with a delay payload in this parameter".into()),
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
            Some(issue(
                "Template expression evaluated (server-side template injection)",
                "high",
                snippet(&got.body, at, 80),
                None,
            ))
        }
        _ => None,
    }
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
    fn probes_fit_the_parameter() {
        let ps = probes(GET, &[], "pmX", 1000);
        let for_point = |n: &str, c: &str| ps.iter().filter(|p| p.point.name == n && p.check == c).count();
        assert_eq!(for_point("next", "open_redirect"), 2);
        assert_eq!(for_point("q", "open_redirect"), 0);
        assert_eq!(for_point("file", "path_traversal"), 3);
        assert_eq!(for_point("q", "path_traversal"), 0);
        assert_eq!(for_point("path segment 3", "reflected_input"), 0);
        assert_eq!(probes(GET, &["ssti".into()], "pmX", 1000).len(), 9);
        assert_eq!(probes(GET, &[], "pmX", 5).len(), 5);
    }

    fn seen(status: u16, body: &str) -> Seen {
        Seen { status: Some(status), body: body.into(), content_type: Some("text/html".into()), location: None }
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
}
