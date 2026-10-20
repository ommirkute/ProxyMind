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
}

pub const CHECKS: &[&str] = &[
    "sql_error",
    "cmd_injection",
    "reflected_input",
    "open_redirect",
    "path_traversal",
    "ssti",
    "sql_boolean",
    "sql_time",
    "cmd_time",
];

/// Checks that take several rounds (run after the one-shot ones).
pub const MULTI_STEP: &[&str] = &["sql_boolean", "sql_time", "cmd_time"];

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

#[derive(Clone, Copy)]
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
    out
}

/// The head lines after the request line, with one header replaced.
fn replace_head_line(rest: &str, f: impl Fn(&str, &str) -> Option<String>) -> String {
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
                            (true, Some((n, _))) => format!("{n}={}", percent_encode(value)),
                            (true, None) => format!("{c}={}", percent_encode(value)),
                            _ => c.to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join("; ")
                })
            });
            Some(rebuild(&Parsed { rest_of_head: &rest, ..p }, p.target, p.body))
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
        _ => (
            "cmd_time",
            "OS command injection (time-based blind)",
            Some("proof_run oracle timing with this payload to measure it statistically".into()),
        ),
    };
    ActiveIssue {
        check,
        title,
        severity: "high",
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
    for pt in points_with(raw, id_segments) {
        let mut add = |check: &'static str, payload: String| {
            if out.len() < limit
                && let Some(r) = inject(raw, &pt, &payload)
            {
                out.push(Probe { check, point: pt.clone(), payload, raw: r });
            }
        };
        if want("sql_error") {
            for s in ["'", "\"", "')", "\\"] {
                add("sql_error", format!("{}{s}", pt.original));
            }
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
        assert!(ck.contains("\r\nCookie: sid=abc; theme=dark%27\r\nAccept: */*\r\n\r\n"), "{ck}");
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
}
