//! Test identities: the credentials of one user or role, and how to put
//! them into any request.
//!
//! An identity holds cookies and auth headers. [`apply`] rewrites a raw
//! request so it is sent *as* that identity: auth-carrying headers from the
//! original request are removed and the identity's own are added. Every
//! other byte of the request is left as it was.
//!
//! Optional extras keep sessions usable without a human:
//! - a **health check** says how to tell the session is still logged in;
//! - a **login recipe** says how to log in again when it isn't.

use serde::{Deserialize, Serialize};

/// The name used for "no credentials at all".
pub const ANONYMOUS: &str = "anonymous";

/// Headers that carry authentication and are replaced when switching identity.
pub const AUTH_HEADERS: &[&str] = &[
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "x-session-token",
    "x-csrf-token",
    "x-xsrf-token",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthMaterial {
    /// Cookie name → value.
    #[serde(default)]
    pub cookies: Vec<(String, String)>,
    /// Extra headers, e.g. ("Authorization", "Bearer …").
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

impl AuthMaterial {
    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty() && self.headers.is_empty()
    }

    /// Merges `Set-Cookie` headers from a response (new values win;
    /// cookies set to empty or expired are removed).
    pub fn absorb_set_cookies(&mut self, response: &[u8]) -> usize {
        let (head, _) = pm_http::split_message(response);
        let Ok(parsed) = pm_http::parse_response_head(head) else { return 0 };
        let mut changed = 0;
        for h in parsed.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("set-cookie")) {
            let v = String::from_utf8_lossy(&h.value);
            let first = v.split(';').next().unwrap_or_default();
            let Some((name, value)) = first.split_once('=') else { continue };
            let (name, value) = (name.trim().to_string(), value.trim().to_string());
            let lower = v.to_ascii_lowercase();
            let expired = value.is_empty() || lower.contains("max-age=0") || lower.contains("expires=thu, 01 jan 1970");
            self.cookies.retain(|(n, _)| n != &name);
            if !expired {
                self.cookies.push((name, value));
            }
            changed += 1;
        }
        changed
    }
}

/// How to check that a session is still valid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Where to send it: scheme://host[:port]
    pub url: String,
    /// Raw request to send (the identity's credentials are applied to it).
    pub request: String,
    /// Expected status code (default: any 2xx).
    #[serde(default)]
    pub expect_status: Option<u16>,
    /// Text the response must contain, e.g. the user's email.
    #[serde(default)]
    pub expect_contains: Option<String>,
}

impl HealthCheck {
    pub fn passes(&self, response: &[u8]) -> bool {
        let (head, body) = pm_http::split_message(response);
        let Ok(h) = pm_http::parse_response_head(head) else { return false };
        let status_ok = match self.expect_status {
            Some(s) => h.status == s,
            None => (200..300).contains(&h.status),
        };
        let body_ok = match &self.expect_contains {
            Some(t) => {
                let decoded = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
                String::from_utf8_lossy(&decoded).contains(t.as_str())
            }
            None => true,
        };
        status_ok && body_ok
    }
}

/// How to log in again. Each step is sent in order; cookies set by any step
/// are kept, and `token` extraction can turn a JSON login response into an
/// Authorization header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRecipe {
    pub steps: Vec<LoginStep>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStep {
    /// Where to send it: scheme://host[:port]
    pub url: String,
    /// Raw request (e.g. the recorded login POST, with the password).
    pub request: String,
    /// Optional: read a token from the JSON response body at this JSON
    /// pointer (e.g. `/token` or `/data/accessToken`) …
    #[serde(default)]
    pub token_json_pointer: Option<String>,
    /// … and store it in this header with this prefix
    /// (default `Authorization: Bearer `).
    #[serde(default)]
    pub token_header: Option<String>,
    #[serde(default)]
    pub token_prefix: Option<String>,
    /// Values to read from this step's response (e.g. a CSRF token), used
    /// as `{{name}}` in later steps and in `set_headers`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extract: Vec<LoginExtract>,
    /// Headers the identity carries after logging in, e.g.
    /// ("Authorization", "Bearer {{v1}}").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_headers: Vec<(String, String)>,
}

/// A value read from a login response with a regex (its first group).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginExtract {
    pub name: String,
    pub regex: String,
}

impl LoginExtract {
    /// The value in `response` (head and decoded body), if the regex matches.
    pub fn find(&self, response: &[u8]) -> Option<String> {
        let re = regex::Regex::new(&self.regex).ok()?;
        let text = response_text(response);
        let c = re.captures(&text)?;
        Some(c.get(1).or_else(|| c.get(0))?.as_str().to_string())
    }
}

/// A response's head and (de-chunked) body as text.
pub fn response_text(response: &[u8]) -> String {
    let (head, body) = pm_http::split_message(response);
    let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
    let mut t = String::from_utf8_lossy(head).into_owned();
    t.push_str(&String::from_utf8_lossy(&body));
    t
}

/// What a logged-out response looks like for one app, learned by sending a
/// request with and without credentials. Any one part matching is enough.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggedOut {
    pub statuses: Vec<u16>,
    /// Text in a redirect's Location.
    pub location_contains: String,
    /// Text in the body.
    pub body_contains: String,
}

impl LoggedOut {
    pub fn matches(&self, response: &[u8]) -> bool {
        let (head, body) = pm_http::split_message(response);
        let Ok(h) = pm_http::parse_response_head(head) else { return false };
        if self.statuses.contains(&h.status) {
            return true;
        }
        if !self.location_contains.is_empty()
            && (300..400).contains(&h.status)
            && pm_http::header(&h.headers, "location")
                .is_some_and(|l| String::from_utf8_lossy(l).contains(&self.location_contains))
        {
            return true;
        }
        if !self.body_contains.is_empty() {
            let decoded = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
            return String::from_utf8_lossy(&decoded).contains(&self.body_contains);
        }
        false
    }
}

impl LoginStep {
    /// Applies a login response to the auth material. Returns a description
    /// of what was learned.
    pub fn absorb(&self, auth: &mut AuthMaterial, response: &[u8]) -> Vec<String> {
        let mut learned = Vec::new();
        let n = auth.absorb_set_cookies(response);
        if n > 0 {
            learned.push(format!("{n} cookie(s)"));
        }
        if let Some(ptr) = &self.token_json_pointer {
            let (_, body) = pm_http::split_message(response);
            let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body)
                && let Some(tok) = v.pointer(ptr).and_then(|t| t.as_str())
            {
                let header = self.token_header.clone().unwrap_or_else(|| "Authorization".into());
                let prefix = self.token_prefix.clone().unwrap_or_else(|| "Bearer ".into());
                auth.headers.retain(|(h, _)| !h.eq_ignore_ascii_case(&header));
                auth.headers.push((header.clone(), format!("{prefix}{tok}")));
                learned.push(format!("token into {header}"));
            }
        }
        learned
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    /// Short name such as `alice` or `admin`.
    pub name: String,
    /// Free-form role, e.g. `user`, `admin`, `guest`.
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub auth: AuthMaterial,
    #[serde(default)]
    pub health: Option<HealthCheck>,
    #[serde(default)]
    pub login: Option<LoginRecipe>,
    /// How this app answers when the session is gone (beyond the usual 401
    /// or redirect to a login page).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logged_out: Option<LoggedOut>,
}

impl Identity {
    pub fn anonymous() -> Self {
        Self {
            name: ANONYMOUS.into(),
            role: "anonymous".into(),
            auth: AuthMaterial::default(),
            health: None,
            login: None,
            logged_out: None,
        }
    }

    /// Whether `response` means this identity's session has expired.
    pub fn looks_logged_out(&self, response: &[u8]) -> bool {
        looks_logged_out(response) || self.logged_out.as_ref().is_some_and(|l| l.matches(response))
    }
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// Takes the auth-carrying headers of a recorded request as an identity's
/// credentials.
pub fn auth_from_request(raw: &[u8]) -> AuthMaterial {
    let (head, _) = pm_http::split_message(raw);
    let Ok(parsed) = pm_http::parse_request_head(head) else { return AuthMaterial::default() };
    let mut auth = AuthMaterial::default();
    for h in &parsed.headers {
        let name = h.name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(&h.value).into_owned();
        if name == "cookie" {
            for pair in value.split(';') {
                if let Some((k, v)) = pair.split_once('=') {
                    auth.cookies.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
        } else if AUTH_HEADERS.contains(&name.as_str()) && name != "proxy-authorization" {
            auth.headers.push((h.name.clone(), value));
        }
    }
    auth
}

/// Whether a response suggests the session has expired: 401, or a redirect
/// to a login page.
pub fn looks_logged_out(response: &[u8]) -> bool {
    let (head, _) = pm_http::split_message(response);
    let Ok(h) = pm_http::parse_response_head(head) else { return false };
    if h.status == 401 || h.status == 419 || h.status == 440 {
        return true;
    }
    if (300..400).contains(&h.status)
        && let Some(loc) = pm_http::header(&h.headers, "location")
    {
        let loc = String::from_utf8_lossy(loc).to_ascii_lowercase();
        return ["login", "signin", "sign-in", "logon", "/auth", "sso"].iter().any(|w| loc.contains(w));
    }
    false
}

/// Rewrites `raw` to carry `auth` instead of its own credentials.
/// Non-auth cookies in the original (e.g. `theme=dark`) are kept unless the
/// identity has its own cookie with the same name.
pub fn apply(raw: &[u8], auth: &AuthMaterial) -> Vec<u8> {
    let Ok(Some(end)) = pm_http::find_head_end(raw) else { return raw.to_vec() };
    let (head, body) = raw.split_at(end);
    let crlf = head.windows(2).any(|w| w == b"\r\n");
    let eol: &[u8] = if crlf { b"\r\n" } else { b"\n" };

    let mut lines: Vec<&[u8]> = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l)).collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let mut out: Vec<u8> = Vec::with_capacity(raw.len() + 256);
    let mut kept_cookies: Vec<String> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            let colon = line.iter().position(|&b| b == b':');
            let name = colon.map(|c| String::from_utf8_lossy(&line[..c]).trim().to_ascii_lowercase());
            if let Some(name) = name {
                if name == "cookie" {
                    // Keep only cookies that look like preferences, i.e. ones
                    // the identity doesn't define and that aren't session-like.
                    let v = String::from_utf8_lossy(&line[colon.unwrap_or(0) + 1..]).into_owned();
                    for pair in v.split(';') {
                        let Some((k, _)) = pair.split_once('=') else { continue };
                        let k = k.trim();
                        let ours = auth.cookies.iter().any(|(n, _)| n == k);
                        if !ours && !looks_like_session_cookie(k) {
                            kept_cookies.push(pair.trim().to_string());
                        }
                    }
                    continue;
                }
                let replaced_by_identity = auth.headers.iter().any(|(h, _)| h.eq_ignore_ascii_case(&name));
                if AUTH_HEADERS.contains(&name.as_str()) || replaced_by_identity {
                    continue;
                }
            }
        }
        out.extend_from_slice(line);
        out.extend_from_slice(eol);
    }
    let mut cookies: Vec<String> = auth.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect();
    cookies.extend(kept_cookies);
    if !cookies.is_empty() {
        out.extend_from_slice(format!("Cookie: {}", cookies.join("; ")).as_bytes());
        out.extend_from_slice(eol);
    }
    for (h, v) in &auth.headers {
        out.extend_from_slice(format!("{h}: {v}").as_bytes());
        out.extend_from_slice(eol);
    }
    out.extend_from_slice(eol);
    out.extend_from_slice(body);
    out
}

pub fn looks_like_session_cookie(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["sess", "sid", "auth", "token", "jwt", "login", "user", "remember", "csrf", "xsrf", "id"]
        .iter()
        .any(|p| n.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: &[u8] = b"GET /api/orders/7 HTTP/1.1\r\nHost: shop\r\nCookie: session=ALICE; theme=dark\r\n\
Authorization: Bearer alice-token\r\nAccept: */*\r\n\r\n";

    #[test]
    fn captures_credentials_from_a_request() {
        let a = auth_from_request(REQ);
        assert_eq!(a.cookies, vec![("session".into(), "ALICE".into()), ("theme".into(), "dark".into())]);
        assert_eq!(a.headers, vec![("Authorization".into(), "Bearer alice-token".into())]);
    }

    #[test]
    fn applies_another_identity_and_keeps_everything_else() {
        let bob = AuthMaterial {
            cookies: vec![("session".into(), "BOB".into())],
            headers: vec![("Authorization".into(), "Bearer bob-token".into())],
        };
        let out = String::from_utf8(apply(REQ, &bob)).unwrap();
        assert_eq!(
            out,
            "GET /api/orders/7 HTTP/1.1\r\nHost: shop\r\nAccept: */*\r\nCookie: session=BOB; theme=dark\r\n\
Authorization: Bearer bob-token\r\n\r\n"
        );
        let anon = String::from_utf8(apply(REQ, &AuthMaterial::default())).unwrap();
        assert!(!anon.contains("ALICE") && !anon.contains("alice-token"), "{anon}");
        assert!(anon.contains("Cookie: theme=dark"));
    }

    #[test]
    fn body_is_untouched() {
        let req = b"POST /x HTTP/1.1\r\nCookie: sid=1\r\nContent-Length: 11\r\n\r\nCookie: x=1";
        let out = apply(req, &AuthMaterial::default());
        assert!(out.ends_with(b"\r\n\r\nCookie: x=1"));
    }

    #[test]
    fn learns_cookies_and_tokens_from_login() {
        let mut a = AuthMaterial { cookies: vec![("session".into(), "old".into())], headers: vec![] };
        let step = LoginStep {
            url: String::new(),
            request: String::new(),
            token_json_pointer: Some("/data/token".into()),
            token_header: None,
            token_prefix: None,
            ..Default::default()
        };
        let resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=new; Path=/\r\nSet-Cookie: gone=; Max-Age=0\r\n\r\n{\"data\":{\"token\":\"T1\"}}";
        let learned = step.absorb(&mut a, resp);
        assert_eq!(a.cookies, vec![("session".into(), "new".into())]);
        assert_eq!(a.headers, vec![("Authorization".into(), "Bearer T1".into())]);
        assert_eq!(learned.len(), 2);
    }

    #[test]
    fn health_checks() {
        let h = HealthCheck {
            url: String::new(),
            request: String::new(),
            expect_status: None,
            expect_contains: Some("alice@".into()),
        };
        assert!(h.passes(b"HTTP/1.1 200 OK\r\n\r\n{\"email\":\"alice@x\"}"));
        assert!(!h.passes(b"HTTP/1.1 200 OK\r\n\r\n{\"email\":\"bob@x\"}"));
        assert!(!h.passes(b"HTTP/1.1 401 Unauthorized\r\n\r\nalice@"));
    }
}
