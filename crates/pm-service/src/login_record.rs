//! Recorded logins: turns a login done by hand in the browser into an
//! identity's login recipe, and learns what a logged-out response looks like
//! so expired sessions are noticed during scans.
//!
//! Recording reads history between two marks. The last request in it that
//! carries credentials is the logged-in state; working backwards, the steps
//! kept are the ones whose responses set those cookies or return those
//! tokens, then the steps those depend on (e.g. the login form that holds
//! the CSRF token the login POST sends). Values passed from one step's
//! response to a later request become `{{variables}}`, so each login run
//! uses fresh ones.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use pm_identity::{AuthMaterial, HealthCheck, Identity, LoggedOut, LoginExtract, LoginRecipe, LoginStep};
use pm_policy::{Actor, ActorKind, Target, Tier};
use serde::Serialize;
use serde_json::json;

use crate::replay::parse_url_endpoint;
use crate::{Authorization, Result, Service, ServiceError};

/// At most this many exchanges are read from one recording.
const MAX_WINDOW: usize = 3000;
/// At most this many steps in a recorded login.
const MAX_STEPS: usize = 20;

#[derive(Debug, Clone, Serialize)]
pub struct RecordedStep {
    pub exchange_id: i64,
    pub method: String,
    pub url: String,
    /// Variables read from this step's response.
    pub extracts: Vec<String>,
    /// Variables this step's request uses.
    pub uses: Vec<String>,
}

/// What a recording produced (names only; values stay in the identity).
#[derive(Debug, Clone, Serialize)]
pub struct LoginRecording {
    pub name: String,
    pub steps: Vec<RecordedStep>,
    pub cookies: Vec<String>,
    pub headers: Vec<String>,
    /// Exchange used as the health check, when one was set.
    pub health_check: Option<i64>,
    pub notes: Vec<String>,
}

/// What learning the logged-out look found.
#[derive(Debug, Clone, Serialize)]
pub struct LoggedOutLearned {
    pub name: String,
    pub logged_out: LoggedOut,
    /// Text a logged-in health check response must contain, when one was added.
    pub health_contains: Option<String>,
    pub exchange_ids: Vec<i64>,
}

/// One recorded exchange.
struct Rec {
    id: i64,
    method: String,
    origin: String,
    url: String,
    request: String,
    response: Vec<u8>,
    text: String,
    status: u16,
}

fn token_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"[A-Za-z0-9._~+-]{8,}").expect("valid regex"))
}

/// Values in `text` that look generated (session ids, CSRF tokens, JWTs):
/// at least 8 characters with both letters and digits.
pub fn tokens(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for m in token_re().find_iter(text) {
        let t = m.as_str().trim_matches(['.', '-', '~', '+']);
        if t.len() >= 8
            && t.chars().any(|c| c.is_ascii_digit())
            && t.chars().any(|c| c.is_ascii_alphabetic())
            && !out.iter().any(|o| o == t)
        {
            out.push(t.to_string());
        }
    }
    out
}

/// A request's text without its Cookie header (cookies are carried by name).
fn without_cookie_line(request: &str) -> String {
    request.split('\n').filter(|l| !l.to_ascii_lowercase().starts_with("cookie:")).collect::<Vec<_>>().join("\n")
}

/// A regex whose first group finds `value` in `text`: the text just before
/// it, then the token's characters. None when no short context is unique
/// enough to find this value first.
pub fn extraction_regex(text: &str, value: &str) -> Option<String> {
    let at = text.find(value)?;
    let line_start = text[..at].rfind('\n').map(|i| i + 1).unwrap_or(0);
    for len in [12usize, 24, 48, 96] {
        let mut from = at.saturating_sub(len).max(line_start);
        while !text.is_char_boundary(from) {
            from += 1;
        }
        let before = &text[from..at];
        if before.trim().is_empty() {
            continue;
        }
        let re = format!("{}([A-Za-z0-9._~+-]+)", regex::escape(before));
        let ok = regex::Regex::new(&re)
            .ok()
            .and_then(|r| r.captures(text).and_then(|c| c.get(1).map(|m| m.as_str() == value)))
            .unwrap_or(false);
        if ok {
            return Some(re);
        }
        if from == line_start {
            break;
        }
    }
    None
}

/// Cookie names a request sends.
fn cookie_names(request: &str) -> Vec<String> {
    pm_identity::auth_from_request(request.as_bytes()).cookies.into_iter().map(|(k, _)| k).collect()
}

/// Cookie names a response sets.
fn set_cookie_names(response: &[u8]) -> Vec<String> {
    let mut a = AuthMaterial::default();
    a.absorb_set_cookies(response);
    a.cookies.into_iter().map(|(k, _)| k).collect()
}

fn static_path(path: &str) -> bool {
    let p = path.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
    [
        ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map",
        ".webp", ".mp4", ".webm",
    ]
    .iter()
    .any(|e| p.ends_with(e))
}

fn static_type(response: &[u8]) -> bool {
    let Ok(h) = pm_http::parse_response_head(pm_http::split_message(response).0) else { return false };
    let ct = pm_http::header(&h.headers, "content-type")
        .map(|v| String::from_utf8_lossy(v).to_ascii_lowercase())
        .unwrap_or_default();
    ["image/", "font/", "text/css", "javascript", "video/", "audio/"].iter().any(|t| ct.contains(t))
}

/// Short pieces of text in a body, for telling two responses apart.
fn fragments(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for f in body.split(['<', '>', '\n', '{', '}', '[', ']', ',', '"']) {
        let f = f.trim();
        if (4..=60).contains(&f.len()) && !out.iter().any(|o| o == f) {
            out.push(f.to_string());
        }
    }
    out
}

const LOGGED_OUT_WORDS: &[&str] = &[
    "log in",
    "login",
    "sign in",
    "signin",
    "sign-in",
    "log on",
    "logged out",
    "session expired",
    "session has expired",
    "unauthorized",
    "unauthenticated",
    "not authenticated",
];

/// A fragment of `bad` that `good` doesn't have, preferring login wording.
pub fn logged_out_marker(bad: &str, good: &str) -> Option<String> {
    let score = |f: &str| {
        let l = f.to_ascii_lowercase();
        let worded = LOGGED_OUT_WORDS.iter().any(|w| l.contains(w));
        let prose = !f.contains(['=', '/', ':']);
        (worded as u8) * 2 + prose as u8
    };
    fragments(bad)
        .into_iter()
        .filter(|f| !good.contains(f.as_str()) && f.chars().any(|c| c.is_alphabetic()))
        .max_by_key(|f| (score(f), f.len().min(30)))
        .filter(|f| score(f) >= 2)
}

/// A fragment of `good` that `bad` lacks: proof of being logged in.
fn logged_in_marker(good: &str, bad: &str) -> Option<String> {
    fragments(good)
        .into_iter()
        .filter(|f| {
            !bad.contains(f.as_str())
                && f.chars().filter(|c| c.is_ascii_digit()).count() * 3 < f.len()
                && f.chars().any(|c| c.is_alphabetic())
        })
        .max_by_key(|f| f.len())
}

fn body_text(response: &[u8]) -> String {
    let (_, body) = pm_http::split_message(response);
    let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
    String::from_utf8_lossy(&body).into_owned()
}

impl Service {
    /// The newest exchange id: where a recording starts.
    pub fn history_mark(&self) -> Result<i64> {
        Ok(self.store.read(|db| db.max_exchange_id())?)
    }

    fn recorded_window(&self, from: i64, to: i64) -> Result<Vec<Rec>> {
        self.store.read(|store| -> Result<Vec<Rec>> {
            let mut after = from;
            let mut out = Vec::new();
            let mut read = 0;
            'outer: loop {
                let ids = store.exchange_ids_after(after, 500)?;
                let Some(&last) = ids.last() else { break };
                for id in ids {
                    if id > to || read >= MAX_WINDOW {
                        break 'outer;
                    }
                    read += 1;
                    let Some(ex) = store.get_exchange(id)? else { continue };
                    let s = &ex.summary;
                    let Some(response) = ex.response else { continue };
                    if s.identity.is_some() || s.source != "proxy" || static_path(&s.path) || static_type(&response) {
                        continue;
                    }
                    let origin = pm_core::url(&s.scheme, &s.host, s.port, "");
                    let url = format!("{origin}{}", s.path);
                    if Target::from_url(&url).map(|t| self.policy.scope_check(&t).is_err()).unwrap_or(true) {
                        continue;
                    }
                    let status = s.status.unwrap_or(0);
                    let text = pm_identity::response_text(&response);
                    out.push(Rec {
                        id,
                        method: s.method.clone(),
                        origin,
                        url,
                        request: String::from_utf8_lossy(&ex.request).into_owned(),
                        response,
                        text,
                        status,
                    });
                }
                after = last;
            }
            Ok(out)
        })
    }

    /// Builds `name`'s login recipe from what the browser sent between
    /// exchange `from` (exclusive) and `to` (inclusive; default: now), and
    /// takes the logged-in credentials from the last request that had them.
    /// Humans only: the recipe holds the password.
    pub fn identity_record_login(
        &self,
        actor: &Actor,
        name: &str,
        role: &str,
        from: i64,
        to: Option<i64>,
    ) -> Result<LoginRecording> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can record logins (they contain passwords)".into()));
        }
        if !pm_identity::valid_name(name) || name == pm_identity::ANONYMOUS {
            return Err(ServiceError::Invalid(format!("bad identity name {name:?}")));
        }
        let to = match to {
            Some(t) => t,
            None => self.history_mark()?,
        };
        let recs = self.recorded_window(from, to)?;
        let has_auth = |r: &Rec| {
            let a = pm_identity::auth_from_request(r.request.as_bytes());
            !a.headers.is_empty() || a.cookies.iter().any(|(k, _)| pm_identity::looks_like_session_cookie(k))
        };
        let Some(last) = recs.iter().rposition(has_auth) else {
            return Err(ServiceError::Invalid(
                "the recording has no request with credentials: log in, then open a page that needs the login \
                 before stopping"
                    .into(),
            ));
        };
        let auth = pm_identity::auth_from_request(recs[last].request.as_bytes());

        // Work backwards from the logged-in request to the steps it needs.
        let mut want_cookies: HashSet<String> = auth.cookies.iter().map(|(k, _)| k.clone()).collect();
        let mut want_tokens: HashSet<String> = auth.headers.iter().flat_map(|(_, v)| tokens(v)).collect();
        let mut needed: Vec<usize> = Vec::new();
        for i in (0..last).rev() {
            let r = &recs[i];
            let sets = set_cookie_names(&r.response);
            let gives_cookie: Vec<String> = want_cookies.iter().filter(|c| sets.contains(c)).cloned().collect();
            let gives_token: Vec<String> =
                want_tokens.iter().filter(|t| r.text.contains(t.as_str())).cloned().collect();
            if gives_cookie.is_empty() && gives_token.is_empty() {
                continue;
            }
            for c in &gives_cookie {
                want_cookies.remove(c);
            }
            for t in &gives_token {
                want_tokens.remove(t);
            }
            needed.push(i);
            want_cookies.extend(cookie_names(&r.request));
            want_tokens.extend(tokens(&without_cookie_line(&r.request)));
        }
        needed.reverse();
        if needed.is_empty() {
            return Err(ServiceError::Invalid(
                "couldn't find the login in the recording: no response in it sets the cookies or returns the token \
                 that the logged-in requests use"
                    .into(),
            ));
        }
        if needed.len() > MAX_STEPS {
            return Err(ServiceError::Invalid(format!(
                "the login needs {} steps; at most {MAX_STEPS} are supported (record just the login)",
                needed.len()
            )));
        }

        // Turn values passed between steps into variables.
        let mut steps: Vec<LoginStep> = Vec::new();
        let mut info: Vec<RecordedStep> = Vec::new();
        let mut vars: HashMap<String, String> = HashMap::new(); // value → variable
        let mut notes = Vec::new();
        let var_for = |value: &str,
                       upto: usize,
                       steps: &mut Vec<LoginStep>,
                       info: &mut Vec<RecordedStep>,
                       vars: &mut HashMap<String, String>|
         -> Option<String> {
            if let Some(v) = vars.get(value) {
                return Some(v.clone());
            }
            let k = (0..upto).rev().find(|&k| recs[needed[k]].text.contains(value))?;
            let regex = extraction_regex(&recs[needed[k]].text, value)?;
            let var = format!("v{}", vars.len() + 1);
            vars.insert(value.to_string(), var.clone());
            steps[k].extract.push(LoginExtract { name: var.clone(), regex });
            info[k].extracts.push(var.clone());
            Some(var)
        };
        for (n, &i) in needed.iter().enumerate() {
            let r = &recs[i];
            steps.push(LoginStep { url: r.origin.clone(), request: r.request.clone(), ..Default::default() });
            info.push(RecordedStep {
                exchange_id: r.id,
                method: r.method.clone(),
                url: r.url.clone(),
                extracts: vec![],
                uses: vec![],
            });
            let mut request = r.request.clone();
            for t in tokens(&without_cookie_line(&r.request)) {
                if let Some(var) = var_for(&t, n, &mut steps, &mut info, &mut vars) {
                    request = request.replace(&t, &format!("{{{{{var}}}}}"));
                    info[n].uses.push(var);
                }
            }
            steps[n].request = request;
        }
        let n = steps.len();
        for (h, value) in &auth.headers {
            let mut template = value.clone();
            let mut found = false;
            for t in tokens(value) {
                if let Some(var) = var_for(&t, n, &mut steps, &mut info, &mut vars) {
                    template = template.replace(&t, &format!("{{{{{var}}}}}"));
                    found = true;
                }
            }
            if found {
                steps[n - 1].set_headers.push((h.clone(), template));
            } else {
                notes.push(format!("{h} isn't returned by the login; its recorded value is kept"));
            }
        }

        // A GET after the login that worked becomes the health check.
        let mut ident = match self.load_identity(name) {
            Ok(i) => i,
            Err(ServiceError::NotFound(_)) => Identity { name: name.into(), role: role.into(), ..Default::default() },
            Err(e) => return Err(e),
        };
        let mut health_check = None;
        if ident.health.is_none()
            && let Some(h) = recs[needed[n - 1] + 1..].iter().rev().find(|r| {
                Tier::for_http_method(&r.method) == Tier::ActiveSafe && (200..300).contains(&r.status) && has_auth(r)
            })
        {
            ident.health = Some(HealthCheck {
                url: h.origin.clone(),
                request: h.request.clone(),
                expect_status: Some(h.status),
                expect_contains: None,
            });
            health_check = Some(h.id);
            notes.push(format!("health check: {} {}", h.method, h.url));
        }
        ident.auth = auth.clone();
        ident.login = Some(LoginRecipe { steps });
        let created_by =
            self.store.read(|db| db.get_identity(name))?.map(|r| r.created_by).unwrap_or_else(|| actor.id());
        self.save_identity(&ident, &created_by, "unknown")?;
        let ids: Vec<i64> = info.iter().map(|s| s.exchange_id).collect();
        self.audit(
            &actor.id(),
            "identity_record_login",
            json!({ "name": name, "from": from, "to": to, "steps": ids }),
            "allow",
        )?;
        Ok(LoginRecording {
            name: name.into(),
            steps: info,
            cookies: auth.cookies.iter().map(|(k, _)| k.clone()).collect(),
            headers: auth.headers.iter().map(|(k, _)| k.clone()).collect(),
            health_check,
            notes,
        })
    }

    /// Learns how this app answers a request whose session is gone: logs
    /// `name` in, sends its health check with and without credentials, and
    /// keeps what tells them apart. Scans then notice expired sessions that
    /// don't show up as a 401 or a redirect to a login page.
    pub async fn identity_learn_logged_out(&self, actor: &Actor, name: &str) -> Result<LoggedOutLearned> {
        let mut ident = self.load_identity(name)?;
        let health = ident.health.clone().ok_or_else(|| {
            ServiceError::Invalid(format!("{name} needs a health check first (record a login, or set one)"))
        })?;
        let out = self.outgoing(parse_url_endpoint(&health.url)?, health.request.as_bytes(), true)?;
        if Tier::for_http_method(&out.method) != Tier::ActiveSafe {
            return Err(ServiceError::Invalid("health checks must use GET, HEAD or OPTIONS".into()));
        }
        match self.gate_send(actor, "identity_learn_logged_out", &out, Some(name), true, None)? {
            Authorization::Allowed { .. } => {}
            other => return Err(ServiceError::Invalid(format!("not allowed: {other:?}"))),
        }
        if ident.login.is_some() {
            self.identity_login(name).await?;
            ident = self.load_identity(name)?;
        }
        let good = self.send_now(actor, &out, Some(&ident), true, "health").await?;
        let bad = self.send_now(actor, &out, Some(&Identity::anonymous()), true, "health").await?;
        let ids = vec![good.exchange_id, bad.exchange_id];
        let (Some(g), Some(b)) = (good.response, bad.response) else {
            return Err(ServiceError::Invalid("the health check got no response".into()));
        };
        if !health.passes(&g) {
            return Err(ServiceError::Invalid(format!(
                "{name}'s health check fails even after logging in; check the login first"
            )));
        }
        let status = |r: &[u8]| pm_http::parse_response_head(pm_http::split_message(r).0).map(|h| h.status).ok();
        let (gs, bs) = (status(&g), status(&b));
        let mut lo = LoggedOut::default();
        if gs != bs
            && let Some(bs) = bs
        {
            if (300..400).contains(&bs) {
                let head = pm_http::parse_response_head(pm_http::split_message(&b).0).ok();
                let loc = head
                    .as_ref()
                    .and_then(|h| pm_http::header(&h.headers, "location"))
                    .map(|l| String::from_utf8_lossy(l).into_owned())
                    .unwrap_or_default();
                let path = loc.split(['?', '#']).next().unwrap_or("").to_string();
                let path = match path.find("://") {
                    Some(i) => path[i + 3..].find('/').map(|j| path[i + 3 + j..].to_string()).unwrap_or_default(),
                    None => path,
                };
                if path.len() > 1 {
                    lo.location_contains = path;
                }
            } else if [401, 419, 440].contains(&bs) {
                lo.statuses.push(bs);
            }
        }
        let (gt, bt) = (body_text(&g), body_text(&b));
        if lo.location_contains.is_empty()
            && lo.statuses.is_empty()
            && let Some(m) = logged_out_marker(&bt, &gt)
        {
            lo.body_contains = m;
        }
        if lo == LoggedOut::default() && !pm_identity::looks_logged_out(&b) {
            return Err(ServiceError::Invalid(
                "a request without credentials gets an answer that can't be told apart from a logged-in one; \
                 use a health check that needs the login"
                    .into(),
            ));
        }
        // A health check that also passes when logged out proves nothing.
        let mut health_contains = None;
        if health.passes(&b)
            && let Some(m) = logged_in_marker(&gt, &bt)
        {
            let mut h = health.clone();
            h.expect_contains = Some(m.clone());
            ident.health = Some(h);
            health_contains = Some(m);
        }
        ident.logged_out = (lo != LoggedOut::default()).then(|| lo.clone());
        let created_by =
            self.store.read(|db| db.get_identity(name))?.map(|r| r.created_by).unwrap_or_else(|| actor.id());
        self.save_identity(&ident, &created_by, "ok")?;
        self.audit(&actor.id(), "identity_learn_logged_out", json!({ "name": name, "logged_out": lo }), "allow")?;
        Ok(LoggedOutLearned { name: name.into(), logged_out: lo, health_contains, exchange_ids: ids })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_generated_values() {
        assert_eq!(tokens("csrf=c0ffee11aa22&user=alice&pass=secret"), vec!["c0ffee11aa22"]);
        assert_eq!(
            tokens("Authorization: Bearer eyJhbGciOi.eyJzdWIi0.sig123abc"),
            vec!["eyJhbGciOi.eyJzdWIi0.sig123abc"]
        );
        assert!(tokens("Content-Type: application/x-www-form-urlencoded").is_empty());
    }

    #[test]
    fn regexes_find_the_value_again() {
        let html = "<form><input type=hidden name=csrf value=\"c0ffee11aa22\"><input name=x value=\"zz\"></form>";
        let re = extraction_regex(html, "c0ffee11aa22").unwrap();
        let other = html.replace("c0ffee11aa22", "beef99887766");
        let x = LoginExtract { name: "v".into(), regex: re };
        assert_eq!(x.find(format!("HTTP/1.1 200 OK\r\n\r\n{other}").as_bytes()).as_deref(), Some("beef99887766"));
        let json = "{\"token\":\"tok0a1b2c3d4\",\"user\":{\"id\":1}}";
        let re = extraction_regex(json, "tok0a1b2c3d4").unwrap();
        assert!(re.contains("token"), "{re}");
    }

    #[test]
    fn markers_tell_logged_out_from_logged_in() {
        let bad = "<html><a href=/login>Please sign in</a></html>";
        let good = "{\"email\":\"alice@x.test\",\"id\":7}";
        assert_eq!(logged_out_marker(bad, good).as_deref(), Some("Please sign in"));
        assert_eq!(logged_in_marker(good, bad).as_deref(), Some("alice@x.test"));
        assert_eq!(logged_out_marker("<p>Welcome</p>", "<p>Hello</p>"), None);
    }
}
