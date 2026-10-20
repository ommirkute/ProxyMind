//! Passive checks: look at recorded traffic, send nothing.
//!
//! Each check reads one exchange (request, response head, decoded body)
//! and reports issues: missing security headers, weak cookies, permissive
//! CORS, version disclosure, verbose errors, leaked secrets, directory
//! listings and passwords over plain HTTP. These are leads, not findings:
//! ProxyMind's rule is "no proof, no finding", and a human or agent decides
//! what to test or report.

pub mod active;

use pm_http::Header;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    /// Stable id of the check, e.g. `missing_csp`.
    pub check: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    /// What was seen. May contain target text (untrusted).
    pub evidence: String,
    /// Whether the issue belongs to the host (headers set site-wide) rather
    /// than to one path: used to group duplicates.
    pub host_wide: bool,
}

/// What a check gets to look at.
pub struct Exchange<'a> {
    pub scheme: &'a str,
    pub request: &'a [u8],
    pub status: u16,
    pub headers: &'a [Header],
    /// Body after de-chunking and decompression.
    pub body: &'a [u8],
}

impl Exchange<'_> {
    fn header(&self, name: &str) -> Option<String> {
        pm_http::header(self.headers, name).map(|v| String::from_utf8_lossy(v).into_owned())
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.headers
            .iter()
            .filter(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(&h.value).into_owned())
            .collect()
    }

    fn is_html(&self) -> bool {
        self.header("content-type").is_some_and(|c| c.to_ascii_lowercase().contains("text/html"))
    }

    fn request_header(&self, name: &str) -> Option<String> {
        let (head, _) = pm_http::split_message(self.request);
        let text = String::from_utf8_lossy(head);
        text.lines().skip(1).find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_string())
        })
    }
}

fn clip(s: &str, n: usize) -> String {
    if s.len() <= n {
        return s.to_string();
    }
    let mut end = n;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

fn issue(check: &'static str, title: &'static str, severity: Severity, evidence: String, host_wide: bool) -> Issue {
    Issue { check, title, severity, evidence: clip(&evidence, 300), host_wide }
}

/// Every passive check, on one exchange.
pub fn check(x: &Exchange) -> Vec<Issue> {
    let mut out = Vec::new();
    headers(x, &mut out);
    cookies(x, &mut out);
    cors(x, &mut out);
    disclosure(x, &mut out);
    body(x, &mut out);
    graphql(x, &mut out);
    out
}

/// A GraphQL server answering introspection hands out its whole schema,
/// including fields the UI never uses.
fn graphql(x: &Exchange, out: &mut Vec<Issue>) {
    if x.status != 200 || x.body.len() < 20 {
        return;
    }
    let head = &x.body[..x.body.len().min(4096)];
    let text = String::from_utf8_lossy(head);
    if text.contains("\"__schema\"") && (text.contains("\"queryType\"") || text.contains("\"types\"")) {
        out.push(issue(
            "graphql_introspection",
            "GraphQL introspection is enabled",
            Severity::Low,
            "the response is an introspection result (import it from History or the Model page)".into(),
            false,
        ));
    }
}

fn headers(x: &Exchange, out: &mut Vec<Issue>) {
    if !x.is_html() || !(200..300).contains(&x.status) {
        return;
    }
    let csp = x.header("content-security-policy");
    if csp.is_none() {
        out.push(issue(
            "missing_csp",
            "No Content-Security-Policy",
            Severity::Low,
            "HTML response without a CSP".into(),
            true,
        ));
    } else if let Some(c) = &csp {
        let l = c.to_ascii_lowercase();
        if l.contains("'unsafe-inline'") && l.contains("script-src") || l.contains("script-src *") {
            out.push(issue(
                "weak_csp",
                "Content-Security-Policy allows inline or any script",
                Severity::Low,
                c.clone(),
                true,
            ));
        }
    }
    let frame_ok = x.header("x-frame-options").is_some()
        || csp.as_deref().is_some_and(|c| c.to_ascii_lowercase().contains("frame-ancestors"));
    if !frame_ok {
        out.push(issue(
            "missing_clickjacking_protection",
            "Page can be framed (no X-Frame-Options or frame-ancestors)",
            Severity::Low,
            "HTML response without X-Frame-Options or CSP frame-ancestors".into(),
            true,
        ));
    }
    if x.header("x-content-type-options").is_none_or(|v| !v.eq_ignore_ascii_case("nosniff")) {
        out.push(issue(
            "missing_nosniff",
            "No X-Content-Type-Options: nosniff",
            Severity::Info,
            "HTML response".into(),
            true,
        ));
    }
    if x.scheme == "https" && x.header("strict-transport-security").is_none() {
        out.push(issue(
            "missing_hsts",
            "No Strict-Transport-Security on HTTPS",
            Severity::Low,
            "HTTPS response without HSTS".into(),
            true,
        ));
    }
}

fn cookies(x: &Exchange, out: &mut Vec<Issue>) {
    for c in x.all("set-cookie") {
        let name = c.split('=').next().unwrap_or("").trim().to_string();
        let attrs: Vec<String> = c.split(';').skip(1).map(|a| a.trim().to_ascii_lowercase()).collect();
        let has = |a: &str| attrs.iter().any(|x| x == a || x.starts_with(&format!("{a}=")));
        // Deleting a cookie (empty value or expired) isn't interesting.
        let value = c.split(';').next().unwrap_or("").split_once('=').map_or("", |(_, v)| v.trim());
        if value.is_empty() || attrs.iter().any(|a| a == "max-age=0") {
            continue;
        }
        let sessionish = {
            let n = name.to_ascii_lowercase();
            ["sess", "sid", "auth", "token", "jwt", "login", "remember"].iter().any(|k| n.contains(k))
                || value.len() >= 16
        };
        if !sessionish {
            continue;
        }
        let mut missing = Vec::new();
        if !has("httponly") {
            missing.push("HttpOnly");
        }
        if x.scheme == "https" && !has("secure") {
            missing.push("Secure");
        }
        if !has("samesite") {
            missing.push("SameSite");
        }
        if attrs.iter().any(|a| a == "samesite=none") && !has("secure") {
            missing.push("Secure (required with SameSite=None)");
        }
        if !missing.is_empty() {
            let sev = if missing.contains(&"HttpOnly") || missing.contains(&"Secure") {
                Severity::Medium
            } else {
                Severity::Low
            };
            out.push(issue(
                "weak_cookie",
                "Session-like cookie without protective attributes",
                sev,
                format!("cookie {name} lacks {}", missing.join(", ")),
                false,
            ));
        }
    }
}

fn cors(x: &Exchange, out: &mut Vec<Issue>) {
    let Some(acao) = x.header("access-control-allow-origin") else { return };
    let creds = x.header("access-control-allow-credentials").is_some_and(|v| v.eq_ignore_ascii_case("true"));
    let origin = x.request_header("origin");
    if acao.trim() == "null" {
        out.push(issue(
            "cors_null_origin",
            "CORS allows the null origin",
            Severity::Medium,
            "Access-Control-Allow-Origin: null".into(),
            false,
        ));
    } else if let Some(o) = origin.filter(|o| o == acao.trim() && creds) {
        out.push(issue(
            "cors_reflected_origin",
            "CORS reflects the request's Origin with credentials",
            Severity::High,
            format!("Origin {o} echoed with Access-Control-Allow-Credentials: true (test with an attacker origin to confirm)"),
            false,
        ));
    } else if acao.trim() == "*" && creds {
        out.push(issue(
            "cors_wildcard_credentials",
            "CORS wildcard with credentials",
            Severity::Low,
            "ACAO: * with credentials (browsers refuse it, but it shows intent)".into(),
            false,
        ));
    }
}

fn disclosure(x: &Exchange, out: &mut Vec<Issue>) {
    for h in ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"] {
        if let Some(v) = x.header(h)
            && v.chars().any(|c| c.is_ascii_digit())
        {
            out.push(issue(
                "version_disclosure",
                "Software version disclosed in a header",
                Severity::Info,
                format!("{h}: {v}"),
                true,
            ));
        }
    }
}

/// Error signatures: (needle, what it is).
const ERRORS: &[(&str, &str)] = &[
    ("you have an error in your sql syntax", "MySQL error"),
    ("warning: mysql", "MySQL error"),
    ("unclosed quotation mark after the character string", "SQL Server error"),
    ("quoted string not properly terminated", "Oracle error"),
    ("ora-0", "Oracle error"),
    ("pg::syntaxerror", "PostgreSQL error"),
    ("psqlexception", "PostgreSQL error"),
    ("sqlstate[", "SQL error (PDO)"),
    ("sqlite3::", "SQLite error"),
    ("sqlite3.operationalerror", "SQLite error"),
    ("sqlite3.databaseerror", "SQLite error"),
    ("sqlalchemy.exc.", "SQL error (SQLAlchemy)"),
    ("psycopg2.errors.", "PostgreSQL error"),
    ("syntax error at or near", "PostgreSQL error"),
    ("pymysql.err.", "MySQL error"),
    ("mysql.connector.errors", "MySQL error"),
    ("django.db.utils.", "SQL error (Django)"),
    ("sqlite_error", "SQLite error"),
    ("traceback (most recent call last)", "Python traceback"),
    ("at java.", "Java stack trace"),
    ("exception in thread", "Java stack trace"),
    ("system.nullreferenceexception", ".NET exception"),
    ("server error in '/' application", "ASP.NET error page"),
    ("stack trace:", "stack trace"),
    ("fatal error: uncaught", "PHP fatal error"),
    ("on line <b>", "PHP error"),
    ("panicked at", "Rust panic"),
    ("goroutine 1 [running]", "Go panic"),
    ("node_modules/", "Node.js stack trace"),
];

/// Secret signatures: (prefix, what it is, minimum token length after the prefix).
const SECRETS: &[(&str, &str, usize)] = &[
    ("akia", "AWS access key id", 16),
    ("-----begin rsa private key-----", "RSA private key", 0),
    ("-----begin private key-----", "private key", 0),
    ("-----begin openssh private key-----", "SSH private key", 0),
    ("-----begin ec private key-----", "EC private key", 0),
    ("ghp_", "GitHub token", 30),
    ("github_pat_", "GitHub token", 30),
    ("xoxb-", "Slack bot token", 20),
    ("xoxp-", "Slack user token", 20),
    ("sk_live_", "Stripe secret key", 20),
    ("aiza", "Google API key", 30),
];

/// The first error signature in `text` (lowercased search): what it is,
/// whether it's a database error, and where it starts.
pub fn error_signature(text: &str) -> Option<(&'static str, bool, usize)> {
    let lower = text.to_ascii_lowercase();
    ERRORS.iter().find_map(|(needle, what)| lower.find(needle).map(|at| (*what, what.contains("SQL"), at)))
}

fn body(x: &Exchange, out: &mut Vec<Issue>) {
    if x.body.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(&x.body[..x.body.len().min(2 * 1024 * 1024)]);
    let lower = text.to_ascii_lowercase();
    if let Some((needle, what)) = ERRORS.iter().find(|(n, _)| lower.contains(n)) {
        let at = lower.find(needle).unwrap_or(0);
        let snippet = snippet(&text, at, 120);
        let sql = what.contains("SQL");
        out.push(issue(
            if sql { "sql_error" } else { "verbose_error" },
            if sql { "Database error message in the response" } else { "Stack trace or verbose error in the response" },
            if sql { Severity::Medium } else { Severity::Low },
            format!("{what}: {snippet}"),
            false,
        ));
    }
    for (prefix, what, min) in SECRETS {
        let mut from = 0;
        while let Some(i) = lower[from..].find(prefix) {
            let at = from + i;
            from = at + prefix.len();
            let token: String =
                text[at..].chars().take_while(|c| c.is_ascii_alphanumeric() || "_-".contains(*c)).collect();
            if *min == 0 || token.len() >= prefix.len() + min - 4 && token.len() >= *min {
                // Boundary before the token, so "ghp_" inside a word doesn't count.
                let ok_before = at == 0 || !text.as_bytes()[at - 1].is_ascii_alphanumeric();
                if ok_before {
                    let shown = if *min == 0 { what.to_string() } else { format!("{}…", clip(&token, 8)) };
                    out.push(issue(
                        "secret_in_response",
                        "Secret or key in the response",
                        Severity::High,
                        format!("{what}: {shown}"),
                        false,
                    ));
                    break;
                }
            }
        }
    }
    if x.is_html() && lower.contains("<title>index of /") {
        out.push(issue(
            "directory_listing",
            "Directory listing",
            Severity::Low,
            "page titled \"Index of /…\"".into(),
            false,
        ));
    }
    if x.scheme == "http" && x.is_html() && lower.contains("type=\"password\"")
        || x.scheme == "http" && x.is_html() && lower.contains("type=password")
    {
        out.push(issue(
            "password_over_http",
            "Password field on a page served over plain HTTP",
            Severity::Medium,
            "<input type=password> on an http:// page".into(),
            false,
        ));
    }
}

fn snippet(text: &str, at: usize, n: usize) -> String {
    let mut start = at;
    while !text.is_char_boundary(start) {
        start -= 1;
    }
    let line: String = text[start..].chars().take(n).collect();
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(pairs: &[(&str, &str)]) -> Vec<Header> {
        pairs.iter().map(|(n, v)| Header { name: n.to_string(), value: v.as_bytes().to_vec() }).collect()
    }

    fn run(scheme: &str, req: &str, status: u16, headers: &[(&str, &str)], body: &str) -> Vec<&'static str> {
        let hs = h(headers);
        check(&Exchange { scheme, request: req.as_bytes(), status, headers: &hs, body: body.as_bytes() })
            .into_iter()
            .map(|i| i.check)
            .collect()
    }

    const GET: &str = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";

    #[test]
    fn security_headers_on_html_pages() {
        let bare = run("https", GET, 200, &[("Content-Type", "text/html")], "<p>hi</p>");
        assert_eq!(bare, vec!["missing_csp", "missing_clickjacking_protection", "missing_nosniff", "missing_hsts"]);
        let good = run(
            "https",
            GET,
            200,
            &[
                ("Content-Type", "text/html"),
                ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                ("X-Content-Type-Options", "nosniff"),
                ("Strict-Transport-Security", "max-age=31536000"),
            ],
            "<p>hi</p>",
        );
        assert!(good.is_empty(), "{good:?}");
        assert!(run("https", GET, 200, &[("Content-Type", "application/json")], "{}").is_empty(), "APIs aren't pages");
        assert!(run("https", GET, 404, &[("Content-Type", "text/html")], "").is_empty());
    }

    #[test]
    fn cookies() {
        let j = &[("Content-Type", "application/json")];
        let weak = |c: &str| run("https", GET, 200, &[j[0], ("Set-Cookie", c)], "");
        assert_eq!(weak("session=abcdef123456; Path=/"), vec!["weak_cookie"]);
        assert!(weak("session=abcdef123456; Path=/; HttpOnly; Secure; SameSite=Lax").is_empty());
        assert!(weak("theme=dark; Path=/").is_empty(), "not session-like");
        assert!(weak("session=; Max-Age=0").is_empty(), "deletion");
        let hs = h(&[("Set-Cookie", "sid=0123456789abcdef; HttpOnly")]);
        let i = check(&Exchange { scheme: "https", request: GET.as_bytes(), status: 200, headers: &hs, body: b"" });
        assert_eq!(i[0].evidence, "cookie sid lacks Secure, SameSite");
        assert_eq!(i[0].severity, Severity::Medium);
    }

    #[test]
    fn cors() {
        let req = "GET /api HTTP/1.1\r\nHost: x\r\nOrigin: https://evil.test\r\n\r\n";
        let reflected = run(
            "https",
            req,
            200,
            &[("Access-Control-Allow-Origin", "https://evil.test"), ("Access-Control-Allow-Credentials", "true")],
            "",
        );
        assert_eq!(reflected, vec!["cors_reflected_origin"]);
        assert_eq!(run("https", req, 200, &[("Access-Control-Allow-Origin", "null")], ""), vec!["cors_null_origin"]);
        assert!(run("https", req, 200, &[("Access-Control-Allow-Origin", "https://app.test")], "").is_empty());
    }

    #[test]
    fn bodies_and_disclosure() {
        let j = &[("Content-Type", "text/plain"), ("Server", "Apache/2.4.49 (Unix)")];
        assert_eq!(
            run("https", GET, 500, j, "You have an error in your SQL syntax near ''x''"),
            vec!["version_disclosure", "sql_error"]
        );
        assert_eq!(run("https", GET, 500, &[], "Traceback (most recent call last):\n  File"), vec!["verbose_error"]);
        let flask = "<title>sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) unrecognized token</title>";
        assert_eq!(run("https", GET, 500, &[], flask), vec!["sql_error"]);
        assert_eq!(run("https", GET, 200, &[], "{\"key\":\"AKIAABCDEFGHIJKLMNOP\"}"), vec!["secret_in_response"]);
        assert!(run("https", GET, 200, &[], "{\"word\":\"MAKIAVELLI\"}").is_empty(), "inside a word");
        assert_eq!(run("https", GET, 200, &[], "-----BEGIN PRIVATE KEY-----\nMII"), vec!["secret_in_response"]);
        assert!(run("https", GET, 200, &[("Server", "nginx")], "ok").is_empty(), "no version, no issue");
        let html = &[
            ("Content-Type", "text/html"),
            ("Content-Security-Policy", "frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"),
        ];
        assert_eq!(run("http", GET, 200, html, "<input type=\"password\" name=p>"), vec!["password_over_http"]);
        assert_eq!(run("http", GET, 200, html, "<title>Index of /backup</title>"), vec!["directory_listing"]);
        let gql = r#"{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}"#;
        assert_eq!(run("https", GET, 200, &[], gql), vec!["graphql_introspection"]);
        assert!(run("https", GET, 200, &[], r#"{"doc":"__schema is a word"}"#).is_empty());
    }
}
