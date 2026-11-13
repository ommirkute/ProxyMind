//! Regression tests made from proven findings: a JSON file per finding that
//! a developer's CI runs against staging (`proxymind regress run`). A test
//! "fails" (the finding is still there) when the response still shows what
//! the proof showed. No I/O here: the format, filling in the placeholders,
//! and judging the responses.
//!
//! Placeholders in a test's requests:
//! - `{{auth:NAME}}` on a line of its own: replaced by the header lines in
//!   the environment variable `PM_AUTH_<NAME>` (e.g. `Cookie: sid=…`, several
//!   lines separated by `\n`). Credentials never go in the file.
//! - `{{xss}}`, `{{xss_url}}`, `{{token}}`: a fresh payload each run.
//! - `{{marker}}`: a fresh random value each run (open redirect, header injection).
//!
//! The Host header and Content-Length are set at run time.
//!
//! "Fixed" must mean fixed. A run can also fail to tell: the credentials are
//! no longer accepted (an expired token answers 401 whatever the bug), or the
//! server fails. Those are errors, never "fixed": see [`credentials_rejected`]
//! and [`AuthCheck`].

use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "proxymind-regression-1";
/// Tests that send several requests (`requests`) or a `{{marker}}`. A separate
/// format so a runner that doesn't know them refuses them instead of judging
/// the first request alone.
pub const FORMAT_2: &str = "proxymind-regression-2";

/// Whether this runner understands a test's format.
pub fn supported(format: &str) -> bool {
    format == FORMAT || format == FORMAT_2
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestFinding {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub vuln_class: String,
    pub url: String,
}

/// What the response looks like while the finding is still there (all set
/// conditions must hold).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VulnerableIf {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_min: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_max: Option<u16>,
    /// At least one of these appears in the body (e.g. the owner's email in
    /// another user's response).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub body_contains_any: Vec<String>,
    /// The payload comes back unencoded.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub reflects_payload: bool,
    /// The request is slower than the baseline by at least this many ms (median).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slower_by_ms: Option<f64>,
}

/// How this app answers when credentials are not accepted, beyond the usual
/// signs (401, a redirect to a login page). Any one part matching is enough.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggedOutLook {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub statuses: Vec<u16>,
    /// Text in a redirect's Location.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub location_contains: String,
    /// Text in the body.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub body_contains: String,
}

/// A request the test's identity is allowed to make. It is sent before a test
/// is called fixed: if it fails, the credentials stopped working and the test
/// can't tell (apps that answer 403 or a page for an expired session).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthCheck {
    pub request: String,
    /// Expected status (default: any 2xx).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_status: Option<u16>,
    /// Text the response must contain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_contains: Option<String>,
}

impl AuthCheck {
    pub fn passes(&self, status: u16, body: &str) -> bool {
        let status_ok = match self.expect_status {
            Some(s) => status == s,
            None => (200..300).contains(&status),
        };
        status_ok && self.expect_contains.as_deref().is_none_or(|t| body.contains(t))
    }
}

/// Whether a response says the credentials were not accepted: 401 (or 419,
/// 440), a redirect to a login page, or the look learned for this app. Such a
/// response says nothing about whether the finding is fixed.
pub fn credentials_rejected(status: u16, location: Option<&str>, body: &str, look: Option<&LoggedOutLook>) -> bool {
    if matches!(status, 401 | 419 | 440) {
        return true;
    }
    let redirect = (300..400).contains(&status);
    if redirect && let Some(loc) = location {
        let l = loc.to_ascii_lowercase();
        if ["login", "signin", "sign-in", "logon", "/auth", "sso"].iter().any(|w| l.contains(w)) {
            return true;
        }
    }
    look.is_some_and(|k| {
        k.statuses.contains(&status)
            || (redirect
                && !k.location_contains.is_empty()
                && location.is_some_and(|l| l.contains(&k.location_contains)))
            || (!k.body_contains.is_empty() && body.contains(&k.body_contains))
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegressionTest {
    pub format: String,
    pub finding: TestFinding,
    /// Where it was found (`scheme://host:port`); `--target` points it elsewhere.
    pub origin: String,
    /// The proof it comes from: differential_authz, reflection, timing,
    /// sql_error, boolean_injection, path_traversal or marker.
    pub oracle: String,
    /// The request that shows the finding (for tests with `requests`, the
    /// one carrying the payload, for people reading the file).
    pub request: String,
    /// The requests the proof sends, in its order: sql_error `[baseline,
    /// quote, second quote, benign change]`, boolean_injection `[baseline,
    /// true condition, false condition]`, path_traversal `[baseline, bogus
    /// name, file 1, …]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requests: Vec<String>,
    /// path_traversal: what shows each file request read its file.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub markers: Vec<String>,
    /// marker: redirect, crlf or host (where `{{marker}}` must not land).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker_kind: Option<String>,
    /// With `auth`: a request that shows the credentials still work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_check: Option<AuthCheck>,
    /// With `auth`: how this app answers when the credentials are not accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logged_out: Option<LoggedOutLook>,
    /// timing: the same request without the delay payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<String>,
    /// Identities whose credentials the requests need (`PM_AUTH_<NAME>`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub auth: Vec<String>,
    pub vulnerable_if: VulnerableIf,
    /// timing: how many times each request is sent.
    #[serde(default = "default_samples")]
    pub samples: usize,
}

fn default_samples() -> usize {
    1
}

impl RegressionTest {
    /// A one-request test in the first format; set the other fields as needed.
    pub fn new(finding: TestFinding, origin: String, oracle: &str, request: String) -> Self {
        Self {
            format: FORMAT.into(),
            finding,
            origin,
            oracle: oracle.into(),
            request,
            requests: Vec::new(),
            markers: Vec::new(),
            marker_kind: None,
            auth_check: None,
            logged_out: None,
            baseline: None,
            auth: Vec::new(),
            vulnerable_if: VulnerableIf::default(),
            samples: 1,
        }
    }
}

/// The environment variable that holds an identity's credentials.
pub fn auth_env(identity: &str) -> String {
    let name: String =
        identity.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect();
    format!("PM_AUTH_{name}")
}

fn split(raw: &str) -> (&str, &str) {
    raw.split_once("\r\n\r\n").or_else(|| raw.split_once("\n\n")).unwrap_or((raw, ""))
}

/// Removes these headers (case-insensitive) and puts `{{auth:identity}}`
/// after the request line.
pub fn strip_auth(raw: &str, headers: &[String], identity: &str) -> String {
    let (head, body) = split(raw);
    let mut lines = head.lines();
    let mut out = vec![lines.next().unwrap_or_default().to_string(), format!("{{{{auth:{identity}}}}}")];
    for l in lines {
        let name = l.split(':').next().unwrap_or_default().trim();
        if !headers.iter().any(|h| h.eq_ignore_ascii_case(name)) {
            out.push(l.trim_end_matches('\r').to_string());
        }
    }
    format!("{}\r\n\r\n{body}", out.join("\r\n"))
}

/// Fills a request template for one run: credentials from `env`, the Host
/// header for `authority`, the payload, and Content-Length for the body.
/// `Err` names what is missing.
pub fn fill(
    template: &str,
    authority: &str,
    payload: Option<(&str, &str)>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<String, String> {
    let mut t = template.to_string();
    if let Some((payload, token)) = payload {
        t = t
            .replace("{{xss_url}}", &crate::regress::percent_encode(payload))
            .replace("{{xss}}", payload)
            .replace("{{token}}", token);
    }
    let (head, body) = split(&t);
    let mut out: Vec<String> = Vec::new();
    for (i, l) in head.lines().enumerate() {
        let l = l.trim_end_matches('\r');
        if let Some(name) = l.trim().strip_prefix("{{auth:").and_then(|r| r.strip_suffix("}}")) {
            let var = auth_env(name);
            let v =
                env(&var).ok_or_else(|| format!("set {var} to {name}'s credentials (e.g. \"Cookie: session=…\")"))?;
            out.extend(v.replace("\\n", "\n").lines().map(str::trim).filter(|x| !x.is_empty()).map(str::to_string));
            continue;
        }
        let name = l.split(':').next().unwrap_or_default().trim().to_ascii_lowercase();
        if i > 0 && name == "host" {
            out.push(format!("Host: {authority}"));
        } else if i > 0 && name == "content-length" {
            continue;
        } else {
            out.push(l.to_string());
        }
    }
    if !body.is_empty() {
        out.push(format!("Content-Length: {}", body.len()));
    }
    Ok(format!("{}\r\n\r\n{body}", out.join("\r\n")))
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

/// Whether one response still shows the finding.
pub fn still_vulnerable(v: &VulnerableIf, status: u16, body: &str, payload: Option<&str>) -> bool {
    if v.status_min.is_some_and(|m| status < m) || v.status_max.is_some_and(|m| status > m) {
        return false;
    }
    if !v.body_contains_any.is_empty() && !v.body_contains_any.iter().any(|m| body.contains(m.as_str())) {
        return false;
    }
    if v.reflects_payload && !payload.is_some_and(|p| body.contains(p)) {
        return false;
    }
    true
}

fn median(xs: &[u64]) -> f64 {
    let mut v = xs.to_vec();
    v.sort_unstable();
    match v.len() {
        0 => 0.0,
        n if n % 2 == 1 => v[n / 2] as f64,
        n => (v[n / 2 - 1] + v[n / 2]) as f64 / 2.0,
    }
}

/// Whether the delayed request is still slower than the baseline by `min_ms` (medians).
pub fn still_slow(baseline_ms: &[u64], payload_ms: &[u64], min_ms: f64) -> bool {
    median(payload_ms) - median(baseline_ms) >= min_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_come_from_the_environment() {
        let raw = "GET /api/orders/1 HTTP/1.1\r\nHost: shop:8080\r\nCookie: sid=bob-secret\r\nAccept: */*\r\n\r\n";
        let t = strip_auth(raw, &["cookie".into()], "bob");
        assert!(!t.contains("bob-secret") && t.contains("{{auth:bob}}"), "{t}");
        let env = |k: &str| (k == "PM_AUTH_BOB").then(|| "Cookie: sid=new\\nX-Csrf: 1".to_string());
        let filled = fill(&t, "staging.test", None, &env).unwrap();
        assert_eq!(
            filled,
            "GET /api/orders/1 HTTP/1.1\r\nCookie: sid=new\r\nX-Csrf: 1\r\nHost: staging.test\r\nAccept: */*\r\n\r\n"
        );
        let missing = fill(&t, "s", None, &|_| None).unwrap_err();
        assert!(missing.contains("PM_AUTH_BOB"));
        assert_eq!(auth_env("qa-admin.2"), "PM_AUTH_QA_ADMIN_2");
    }

    #[test]
    fn payloads_and_content_length() {
        let t = "POST /c HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nq={{xss_url}}&r={{xss}}";
        let f = fill(t, "b", Some(("<i>", "tok")), &|_| None).unwrap();
        let body = "q=%3Ci%3E&r=<i>";
        assert!(f.ends_with(&format!("Content-Length: {}\r\n\r\n{body}", body.len())), "{f}");
        assert!(!f.contains("Content-Length: 3"));
    }

    #[test]
    fn judging() {
        let v = VulnerableIf {
            status_min: Some(200),
            status_max: Some(299),
            body_contains_any: vec!["alice@shop.test".into()],
            ..Default::default()
        };
        assert!(still_vulnerable(&v, 200, "{\"email\":\"alice@shop.test\"}", None));
        assert!(!still_vulnerable(&v, 403, "alice@shop.test", None));
        assert!(!still_vulnerable(&v, 200, "{}", None));
        let r = VulnerableIf { reflects_payload: true, ..Default::default() };
        assert!(still_vulnerable(&r, 200, "x<i>y", Some("<i>")));
        assert!(!still_vulnerable(&r, 200, "x&lt;i&gt;y", Some("<i>")));
        assert!(still_slow(&[10, 12, 11], &[3010, 3020, 15], 2000.0));
        assert!(!still_slow(&[10, 12, 11], &[30, 20, 15], 2000.0));
    }

    #[test]
    fn rejected_credentials_are_not_a_fix() {
        // The usual signs.
        assert!(credentials_rejected(401, None, "", None));
        assert!(credentials_rejected(302, Some("/Login?next=/orders"), "", None));
        assert!(credentials_rejected(303, Some("https://sso.corp.test/start"), "", None));
        // What a fix looks like: refused, gone, or a redirect elsewhere.
        for (status, loc) in [(403, None), (404, None), (302, Some("/orders")), (200, None)] {
            assert!(!credentials_rejected(status, loc, "{}", None), "{status} {loc:?}");
        }
        // An app that answers 200 with a sign-in page, or 403 for an expired token.
        let look = LoggedOutLook { statuses: vec![403], body_contains: "Please sign in".into(), ..Default::default() };
        assert!(credentials_rejected(200, None, "<h1>Please sign in</h1>", Some(&look)));
        assert!(credentials_rejected(403, None, "", Some(&look)));
        assert!(!credentials_rejected(200, None, "{\"orders\":[]}", Some(&look)));

        let check = AuthCheck { request: String::new(), expect_status: None, expect_contains: Some("bob@".into()) };
        assert!(check.passes(200, "{\"email\":\"bob@shop.test\"}"));
        assert!(!check.passes(200, "{}") && !check.passes(403, "bob@"));
    }

    #[test]
    fn formats() {
        assert!(supported(FORMAT) && supported(FORMAT_2) && !supported("proxymind-regression-3"));
        // A first-format test written before the new fields existed still loads.
        let old = r#"{"format":"proxymind-regression-1","finding":{"id":1,"title":"t","severity":"high","vuln_class":"idor","url":"u"},
            "origin":"http://a:80","oracle":"differential_authz","request":"GET / HTTP/1.1\r\n\r\n","vulnerable_if":{}}"#;
        let t: RegressionTest = serde_json::from_str(old).unwrap();
        assert!(t.requests.is_empty() && t.auth_check.is_none() && t.samples == 1);
        // And new fields stay out of files that don't use them.
        assert!(!serde_json::to_string(&t).unwrap().contains("requests"));
    }
}
