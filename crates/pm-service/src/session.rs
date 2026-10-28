//! Session handling: keeps tool traffic logged in without a human.
//!
//! - A **cookie jar** follows `Set-Cookie` in every recorded response
//!   (proxy, tools, macros) that wasn't sent as a test identity.
//! - **Macros** are recorded request sequences (a login, or the page that
//!   holds a CSRF token). Each step can extract values into variables.
//! - **Rules** say which tools and hosts they cover and what to do: run a
//!   macro before each request or only when the session looks invalid
//!   (then the request is sent once more), put jar cookies into requests,
//!   and set headers, cookies or parameters from variables.
//!
//! Rules apply to requests sent as recorded (no test identity: identities
//! have their own login recipes). Macro steps go through the policy gate as
//! the human who saved the rules, like identity logins, and are recorded
//! as `macro` exchanges. Only humans can read or change the settings: macro
//! requests usually contain passwords.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Instant;

use pm_policy::{Actor, ActorKind};
use pm_replay::net::host_matches;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::replay::{Outgoing, Sent, parse_url_endpoint};
use crate::{Authorization, Result, Service, ServiceError};

/// Project setting that holds the session handling settings as JSON.
pub const SESSION_SETTING: &str = "session_handling";

/// Sources whose requests never get session rules (they *are* the session
/// machinery, or they're how identities stay logged in).
const EXEMPT: &[&str] = &["macro", "login", "health"];

/// How many recent exchanges seed the cookie jar when a project opens.
const JAR_SEED: i64 = 2000;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    pub macros: Vec<Macro>,
    pub rules: Vec<SessionRule>,
    /// Who saved these settings (macro steps run as them). Set by the service.
    pub saved_by: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Macro {
    pub name: String,
    pub steps: Vec<MacroStep>,
    /// Start with the cookie jar's cookies (otherwise only cookies set by
    /// earlier steps of this macro are sent).
    pub use_cookie_jar: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MacroStep {
    /// scheme://host[:port]
    pub url: String,
    /// Raw request; `{{name}}` is replaced by a variable from an earlier step.
    pub request: String,
    pub extract: Vec<Extraction>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractKind {
    /// First capture group (or the whole match) of a regex over head and body.
    #[default]
    Regex,
    /// A JSON pointer into the body, e.g. `/data/token`.
    Json,
    /// A response header's value.
    Header,
    /// A cookie the response sets.
    Cookie,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Extraction {
    /// Variable name: letters, digits and `_`.
    pub name: String,
    pub kind: ExtractKind,
    pub expr: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunWhen {
    /// Before every request the rule covers (e.g. a fresh CSRF token).
    Always,
    /// Only when a response looks logged out; the request is then sent again.
    #[default]
    WhenInvalid,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetWhere {
    #[default]
    Header,
    Cookie,
    /// A query, form or top-level JSON parameter that's already in the request.
    Param,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SetValue {
    #[serde(rename = "where")]
    pub location: SetWhere,
    pub name: String,
    /// May contain `{{variable}}`.
    pub value: String,
}

/// When a response means the session is gone. Empty: 401, 419, 440 or a
/// redirect to a login page.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Validity {
    pub statuses: Vec<u16>,
    /// Text in the response (head or body) that means logged out.
    pub contains: String,
}

/// A tool (exchange source) name, lowercased, with the names used before
/// the 2026-10-28 rename mapped to the current ones.
fn canonical_tool(name: &str) -> String {
    let n = name.trim().to_ascii_lowercase();
    match n.as_str() {
        "repeater" => "replay".into(),
        "intruder" => "fuzzer".into(),
        "sequencer" => "token_analyzer".into(),
        _ => n,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SessionRule {
    pub name: String,
    pub enabled: bool,
    /// Tools (exchange sources) covered: replay, fuzzer, scan, crawl,
    /// discover, token_analyzer, proof, authz, graphql, openapi. Empty: all.
    /// Older names (repeater, intruder, sequencer) still match.
    pub tools: Vec<String>,
    /// Host patterns (`api.example.com`, `*.example.com`). Empty: all.
    pub hosts: Vec<String>,
    pub use_cookie_jar: bool,
    /// Name of a macro to run (empty: none).
    #[serde(rename = "macro")]
    pub macro_name: String,
    pub run: RunWhen,
    pub invalid: Validity,
    pub set: Vec<SetValue>,
}

impl Default for SessionRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            enabled: true,
            tools: vec![],
            hosts: vec![],
            use_cookie_jar: true,
            macro_name: String::new(),
            run: RunWhen::WhenInvalid,
            invalid: Validity::default(),
            set: vec![],
        }
    }
}

impl SessionRule {
    fn covers(&self, source: &str, host: &str) -> bool {
        self.enabled
            && (self.tools.is_empty() || self.tools.iter().any(|t| canonical_tool(t) == canonical_tool(source)))
            && (self.hosts.is_empty() || self.hosts.iter().any(|h| host_matches(h, host)))
    }
}

fn valid_var(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

impl SessionConfig {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.macros.len() > 50 || self.rules.len() > 50 {
            return Err("at most 50 macros and 50 rules".into());
        }
        let mut names = std::collections::HashSet::new();
        for m in &self.macros {
            if m.name.trim().is_empty() || !names.insert(m.name.as_str()) {
                return Err(format!("each macro needs a unique name ({:?})", m.name));
            }
            if m.steps.is_empty() || m.steps.len() > 20 {
                return Err(format!("macro {}: 1 to 20 steps", m.name));
            }
            for (i, s) in m.steps.iter().enumerate() {
                parse_url_endpoint(&s.url).map_err(|e| format!("macro {} step {}: {e}", m.name, i + 1))?;
                if pm_http::parse_request_head(pm_http::split_message(s.request.as_bytes()).0).is_err() {
                    return Err(format!("macro {} step {}: the request isn't valid HTTP", m.name, i + 1));
                }
                for x in &s.extract {
                    if !valid_var(&x.name) {
                        return Err(format!("macro {}: bad variable name {:?}", m.name, x.name));
                    }
                    if x.kind == ExtractKind::Regex
                        && let Err(e) = regex::Regex::new(&x.expr)
                    {
                        return Err(format!("macro {}: bad regex for {}: {e}", m.name, x.name));
                    }
                    if x.kind == ExtractKind::Json && !(x.expr.is_empty() || x.expr.starts_with('/')) {
                        return Err(format!("macro {}: JSON pointers start with / ({})", m.name, x.name));
                    }
                }
            }
        }
        for r in &self.rules {
            if !r.macro_name.is_empty() && !names.contains(r.macro_name.as_str()) {
                return Err(format!("rule {:?} uses an unknown macro {:?}", r.name, r.macro_name));
            }
            for v in &r.set {
                let bad = v.name.trim().is_empty()
                    || v.name.contains([':', '\r', '\n', ';', '=', '&'])
                    || v.value.contains(['\r', '\n']);
                if bad {
                    return Err(format!("rule {:?}: bad name or value to set ({:?})", r.name, v.name));
                }
            }
        }
        Ok(())
    }

    /// The settings with every macro request replaced by its request line,
    /// for the audit log (requests hold passwords).
    fn for_audit(&self) -> serde_json::Value {
        let mut c = self.clone();
        for m in &mut c.macros {
            for s in &mut m.steps {
                s.request = s.request.lines().next().unwrap_or_default().to_string();
            }
        }
        json!(c)
    }
}

// ---- cookie jar -----------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JarCookie {
    pub domain: String,
    /// Sent only to `domain` itself (no Domain attribute was given).
    pub host_only: bool,
    pub name: String,
    pub value: String,
}

impl JarCookie {
    fn applies_to(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        host == self.domain || (!self.host_only && host.ends_with(&format!(".{}", self.domain)))
    }
}

#[derive(Debug, Default)]
pub(crate) struct Jar {
    seen_up_to: Option<i64>,
    cookies: Vec<JarCookie>,
}

impl Jar {
    /// Applies a response's `Set-Cookie` headers, as received from `host`.
    pub(crate) fn absorb(&mut self, host: &str, response: &[u8]) {
        let (head, _) = pm_http::split_message(response);
        let Ok(parsed) = pm_http::parse_response_head(head) else { return };
        let host = host.to_ascii_lowercase();
        for h in parsed.headers.iter().filter(|h| h.name.eq_ignore_ascii_case("set-cookie")) {
            let v = String::from_utf8_lossy(&h.value);
            let mut parts = v.split(';');
            let Some((name, value)) = parts.next().and_then(|p| p.split_once('=')) else { continue };
            let (name, value) = (name.trim().to_string(), value.trim().to_string());
            if name.is_empty() {
                continue;
            }
            let mut domain = None;
            let mut expired = false;
            for attr in parts {
                let (k, val) = attr.split_once('=').unwrap_or((attr, ""));
                match k.trim().to_ascii_lowercase().as_str() {
                    "domain" => domain = Some(val.trim().trim_start_matches('.').to_ascii_lowercase()),
                    "max-age" => expired |= val.trim().parse::<i64>().is_ok_and(|n| n <= 0),
                    "expires" => expired |= val.contains("1970"),
                    _ => {}
                }
            }
            // A Domain must cover the host that set it (no cross-site cookies).
            let (domain, host_only) = match domain.filter(|d| !d.is_empty()) {
                Some(d) if host == d || host.ends_with(&format!(".{d}")) => (d, false),
                Some(_) => continue,
                None => (host.clone(), true),
            };
            self.cookies.retain(|c| !(c.domain == domain && c.name == name));
            // Targets choose what they set: keep the jar (and the Cookie
            // headers built from it) bounded, like browsers do.
            let too_big = name.len() + value.len() > 4096;
            if !expired && !value.is_empty() && !too_big {
                if self.cookies.iter().filter(|c| c.domain == domain).count() >= 180
                    && let Some(i) = self.cookies.iter().position(|c| c.domain == domain)
                {
                    self.cookies.remove(i); // the oldest for this domain
                }
                if self.cookies.len() >= 3000 {
                    self.cookies.remove(0);
                }
                self.cookies.push(JarCookie { domain, host_only, name, value });
            }
        }
    }

    pub(crate) fn for_host(&self, host: &str) -> Vec<(String, String)> {
        self.cookies.iter().filter(|c| c.applies_to(host)).map(|c| (c.name.clone(), c.value.clone())).collect()
    }
}

/// What the rules covering one request want.
#[derive(Debug, Default)]
struct Plan {
    use_jar: bool,
    always: Vec<String>,
    when_invalid: Vec<(String, Validity)>,
    set: Vec<SetValue>,
}

/// Live session state: jar, variables and when each macro last ran.
#[derive(Default)]
pub(crate) struct SessionState {
    jar: Jar,
    vars: HashMap<String, String>,
    last_run: HashMap<String, Instant>,
}

/// What a macro run produced.
#[derive(Debug, Clone, Serialize)]
pub struct MacroRun {
    pub name: String,
    pub exchange_ids: Vec<i64>,
    /// Variables set by this run (values shown to humans only).
    pub variables: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    #[serde(flatten)]
    pub config: SessionConfig,
    /// Current variable values from macro runs.
    pub variables: HashMap<String, String>,
}

// ---- request editing (pure; only the named parts change) -------------------

fn var_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\{\{([A-Za-z_][A-Za-z0-9_]{0,63})\}\}").expect("valid regex"))
}

/// Replaces `{{name}}` with known variables; unknown ones stay as written.
pub fn substitute(text: &str, vars: &HashMap<String, String>) -> String {
    var_re()
        .replace_all(text, |c: &regex::Captures| vars.get(&c[1]).cloned().unwrap_or_else(|| c[0].to_string()))
        .into_owned()
}

/// Head lines (without line endings), the line ending, and the body.
type Split<'a> = (Vec<Vec<u8>>, &'static [u8], &'a [u8]);

fn split_lines(raw: &[u8]) -> Option<Split<'_>> {
    let end = pm_http::find_head_end(raw).ok().flatten()?;
    let (head, body) = raw.split_at(end);
    let eol: &'static [u8] = if head.windows(2).any(|w| w == b"\r\n") { b"\r\n" } else { b"\n" };
    let mut lines: Vec<Vec<u8>> =
        head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l).to_vec()).collect();
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    Some((lines, eol, body))
}

fn join_lines(lines: &[Vec<u8>], eol: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + lines.iter().map(|l| l.len() + 2).sum::<usize>() + 2);
    for l in lines {
        out.extend_from_slice(l);
        out.extend_from_slice(eol);
    }
    out.extend_from_slice(eol);
    out.extend_from_slice(body);
    out
}

fn header_name(line: &[u8]) -> Option<&[u8]> {
    let c = line.iter().position(|&b| b == b':')?;
    Some(line[..c].trim_ascii())
}

/// Whether a value can go into a header line as is. Values extracted from
/// responses are target content: a line break would add headers or a whole
/// second request.
pub(crate) fn header_safe(s: &str) -> bool {
    !s.contains(['\r', '\n', '\0'])
}

/// Sets a header: replaces the first one with that name, or adds it.
/// Names or values with line breaks are refused (the request is unchanged).
pub fn set_header(raw: &[u8], name: &str, value: &str) -> Vec<u8> {
    if !header_safe(name) || !header_safe(value) || name.contains(':') {
        return raw.to_vec();
    }
    let Some((mut lines, eol, body)) = split_lines(raw) else { return raw.to_vec() };
    let line = format!("{name}: {value}").into_bytes();
    match lines.iter().skip(1).position(|l| header_name(l).is_some_and(|n| n.eq_ignore_ascii_case(name.as_bytes()))) {
        Some(i) => lines[i + 1] = line,
        None => lines.push(line),
    }
    join_lines(&lines, eol, body)
}

/// Sets cookies: replaces values of cookies already sent and adds the rest,
/// in the first Cookie header (one is added if there is none).
pub fn set_cookies(raw: &[u8], cookies: &[(String, String)]) -> Vec<u8> {
    if cookies.is_empty() {
        return raw.to_vec();
    }
    let Some((mut lines, eol, body)) = split_lines(raw) else { return raw.to_vec() };
    let at = lines.iter().skip(1).position(|l| header_name(l).is_some_and(|n| n.eq_ignore_ascii_case(b"cookie")));
    let current = at.map(|i| {
        let l = &lines[i + 1];
        let c = l.iter().position(|&b| b == b':').unwrap_or(l.len());
        String::from_utf8_lossy(&l[(c + 1).min(l.len())..]).trim().to_string()
    });
    let mut pairs: Vec<(String, String)> = current
        .as_deref()
        .unwrap_or_default()
        .split(';')
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (k.trim().to_string(), v.trim().to_string())
        })
        .collect();
    for (k, v) in cookies.iter().filter(|(k, v)| header_safe(k) && header_safe(v) && !k.contains([';', '='])) {
        match pairs.iter_mut().find(|(n, _)| n == k) {
            Some(p) => p.1.clone_from(v),
            None => pairs.push((k.clone(), v.clone())),
        }
    }
    let value = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; ");
    let line = format!("Cookie: {value}").into_bytes();
    match at {
        Some(i) => lines[i + 1] = line,
        None => lines.push(line),
    }
    join_lines(&lines, eol, body)
}

fn form_encode(v: &str) -> String {
    url::form_urlencoded::byte_serialize(v.as_bytes()).collect()
}

/// Replaces `name=…` pairs in an `a=1&b=2` string. Returns None if absent.
fn replace_pairs(s: &str, name: &str, value: &str) -> Option<String> {
    let mut hit = false;
    let out = s
        .split('&')
        .map(|kv| match kv.split_once('=') {
            Some((k, _)) if k == name || crate::session::decode(k) == name => {
                hit = true;
                format!("{k}={}", form_encode(value))
            }
            _ => kv.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");
    hit.then_some(out)
}

fn decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={s}").as_bytes()).next().map(|(_, v)| v.into_owned()).unwrap_or_default()
}

/// Sets a parameter that's already in the request: in the query string, a
/// URL-encoded form body, or a JSON body (`"name": "…"` string values).
/// Returns the request and whether the body changed.
pub fn set_param(raw: &[u8], name: &str, value: &str) -> (Vec<u8>, bool) {
    let Some((mut lines, eol, body)) = split_lines(raw) else { return (raw.to_vec(), false) };
    let mut changed_body = None;
    // Query string, in the request line.
    let first = String::from_utf8_lossy(&lines[0]).into_owned();
    let parts: Vec<&str> = first.split(' ').collect();
    if parts.len() >= 3 {
        let target = parts[1..parts.len() - 1].join(" ");
        if let Some((path, q)) = target.split_once('?')
            && let Some(nq) = replace_pairs(q, name, value)
        {
            lines[0] = format!("{} {path}?{nq} {}", parts[0], parts[parts.len() - 1]).into_bytes();
        }
    }
    let ctype = lines
        .iter()
        .skip(1)
        .find(|l| header_name(l).is_some_and(|n| n.eq_ignore_ascii_case(b"content-type")))
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .unwrap_or_default();
    if let Ok(text) = std::str::from_utf8(body) {
        if ctype.contains("x-www-form-urlencoded") {
            changed_body = replace_pairs(text, name, value);
        } else if ctype.contains("json") {
            let key = serde_json::to_string(name).unwrap_or_default();
            let re = regex::Regex::new(&format!(r#"({}\s*:\s*)"(?:[^"\\]|\\.)*""#, regex::escape(&key))).ok();
            if let Some(re) = re
                && re.is_match(text)
            {
                let v = serde_json::to_string(value).unwrap_or_default();
                changed_body = Some(re.replace_all(text, |c: &regex::Captures| format!("{}{v}", &c[1])).into_owned());
            }
        }
    }
    match changed_body {
        Some(b) => (pm_http::fix_content_length(&join_lines(&lines, eol, b.as_bytes())), true),
        None => (join_lines(&lines, eol, body), false),
    }
}

fn response_text(response: &[u8]) -> (String, Vec<u8>) {
    let (head, body) = pm_http::split_message(response);
    let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
    (String::from_utf8_lossy(head).into_owned(), body)
}

/// Reads one value out of a response.
pub fn extract(x: &Extraction, response: &[u8]) -> Option<String> {
    let (head, body) = response_text(response);
    match x.kind {
        ExtractKind::Regex => {
            let re = regex::Regex::new(&x.expr).ok()?;
            let text = format!("{head}{}", String::from_utf8_lossy(&body));
            let c = re.captures(&text)?;
            Some(c.get(1).or_else(|| c.get(0))?.as_str().to_string())
        }
        ExtractKind::Json => {
            let v: serde_json::Value = serde_json::from_slice(&body).ok()?;
            match v.pointer(&x.expr)? {
                serde_json::Value::String(s) => Some(s.clone()),
                other => Some(other.to_string()),
            }
        }
        ExtractKind::Header => {
            let parsed = pm_http::parse_response_head(pm_http::split_message(response).0).ok()?;
            pm_http::header(&parsed.headers, &x.expr).map(|v| String::from_utf8_lossy(v).trim().to_string())
        }
        ExtractKind::Cookie => {
            let mut jar = Jar::default();
            jar.absorb("x", response);
            jar.cookies.into_iter().find(|c| c.name == x.expr).map(|c| c.value)
        }
    }
}

/// Whether a response means the session is gone.
pub fn is_invalid(v: &Validity, response: &[u8]) -> bool {
    if v.statuses.is_empty() && v.contains.is_empty() {
        return pm_identity::looks_logged_out(response);
    }
    let (head, body) = response_text(response);
    let status = pm_http::parse_response_head(pm_http::split_message(response).0).map(|h| h.status).ok();
    status.is_some_and(|s| v.statuses.contains(&s))
        || (!v.contains.is_empty()
            && (head.contains(&v.contains) || String::from_utf8_lossy(&body).contains(&v.contains)))
}

// ---- service --------------------------------------------------------------

fn load(store: &pm_store::Store) -> Result<SessionConfig> {
    match store.get_setting(SESSION_SETTING)? {
        Some(t) => serde_json::from_str(&t)
            .map_err(|e| ServiceError::Invalid(format!("saved session handling settings are unreadable: {e}"))),
        None => Ok(SessionConfig::default()),
    }
}

fn humans_only(actor: &Actor) -> Result<()> {
    if actor.kind != ActorKind::Human {
        return Err(ServiceError::Invalid(
            "only humans can see or change session handling (macros hold passwords)".into(),
        ));
    }
    Ok(())
}

impl Service {
    pub fn session_get(&self, actor: &Actor) -> Result<SessionView> {
        humans_only(actor)?;
        let config = load(&self.store.lock())?;
        Ok(SessionView { config, variables: self.session.lock().vars.clone() })
    }

    pub fn session_set(&self, actor: &Actor, mut cfg: SessionConfig) -> Result<SessionView> {
        humans_only(actor)?;
        cfg.validate().map_err(ServiceError::Invalid)?;
        cfg.saved_by = actor.id();
        let text = serde_json::to_string(&cfg).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.lock().set_setting(SESSION_SETTING, &text)?;
        self.audit(&actor.id(), "session_handling", cfg.for_audit(), "allow")?;
        self.session_get(actor)
    }

    /// The cookie jar, brought up to date with history.
    pub fn session_jar(&self, actor: &Actor) -> Result<Vec<JarCookie>> {
        humans_only(actor)?;
        self.refresh_jar()?;
        Ok(self.session.lock().jar.cookies.clone())
    }

    /// Empties the jar; it fills again from responses recorded from now on.
    pub fn session_jar_clear(&self, actor: &Actor) -> Result<()> {
        humans_only(actor)?;
        self.refresh_jar()?;
        self.session.lock().jar.cookies.clear();
        self.audit(&actor.id(), "session_jar_clear", json!({}), "allow")?;
        Ok(())
    }

    /// Runs a macro now (to test it). Humans only.
    pub async fn session_macro_run(&self, actor: &Actor, name: &str) -> Result<MacroRun> {
        humans_only(actor)?;
        let cfg = load(&self.store.lock())?;
        let m = cfg
            .macros
            .iter()
            .find(|m| m.name == name)
            .ok_or_else(|| ServiceError::NotFound(format!("macro {name}")))?;
        self.run_macro(&cfg, m, &actor.id()).await
    }

    /// Reads responses recorded since the last look into the jar.
    fn refresh_jar(&self) -> Result<()> {
        let from = self.session.lock().jar.seen_up_to;
        let store = self.store.lock();
        let mut after = match from {
            Some(id) => id,
            None => (store.max_exchange_id()? - JAR_SEED).max(0),
        };
        let mut fresh = Vec::new();
        loop {
            let ids = store.exchange_ids_after(after, 500)?;
            let Some(&last) = ids.last() else { break };
            for id in ids {
                if let Some(ex) = store.get_exchange(id)?
                    && ex.summary.identity.is_none()
                    && let Some(resp) = ex.response
                {
                    fresh.push((ex.summary.host, resp));
                }
            }
            after = last;
        }
        drop(store);
        let mut st = self.session.lock();
        for (host, resp) in fresh {
            st.jar.absorb(&host, &resp);
        }
        st.jar.seen_up_to = Some(after.max(st.jar.seen_up_to.unwrap_or(0)));
        Ok(())
    }

    fn session_plan(&self, cfg: &SessionConfig, source: &str, host: &str) -> Option<Plan> {
        let rules: Vec<&SessionRule> = cfg.rules.iter().filter(|r| r.covers(source, host)).collect();
        if rules.is_empty() {
            return None;
        }
        let mut plan = Plan::default();
        for r in rules {
            plan.use_jar |= r.use_cookie_jar;
            if !r.macro_name.is_empty() {
                match r.run {
                    RunWhen::Always => plan.always.push(r.macro_name.clone()),
                    RunWhen::WhenInvalid => plan.when_invalid.push((r.macro_name.clone(), r.invalid.clone())),
                }
            }
            plan.set.extend(r.set.iter().cloned());
        }
        Some(plan)
    }

    /// The request with jar cookies and rule values put in.
    fn session_apply(&self, plan: &Plan, wire: &[u8], host: &str) -> Result<Vec<u8>> {
        let mut out = wire.to_vec();
        if plan.use_jar {
            self.refresh_jar()?;
            let cookies = self.session.lock().jar.for_host(host);
            out = set_cookies(&out, &cookies);
        }
        let vars = self.session.lock().vars.clone();
        for v in &plan.set {
            let value = substitute(&v.value, &vars);
            out = match v.location {
                SetWhere::Header => set_header(&out, &v.name, &value),
                SetWhere::Cookie => set_cookies(&out, &[(v.name.clone(), value)]),
                SetWhere::Param => set_param(&out, &v.name, &value).0,
            };
        }
        Ok(out)
    }

    /// Runs one macro as the human who saved the rules.
    async fn run_macro(&self, cfg: &SessionConfig, m: &Macro, triggered_by: &str) -> Result<MacroRun> {
        let owner = Actor::parse(if cfg.saved_by.is_empty() { "human:local" } else { &cfg.saved_by })
            .map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let mut local = Jar::default();
        let mut run = MacroRun { name: m.name.clone(), exchange_ids: vec![], variables: HashMap::new() };
        for (i, step) in m.steps.iter().enumerate() {
            let vars = self.session.lock().vars.clone();
            let endpoint = parse_url_endpoint(&step.url)?;
            let raw = substitute(&step.request, &vars);
            let out = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
            match self.gate_send(&owner, "session_macro", &out, None, true, None)? {
                Authorization::Allowed { .. } => {}
                other => {
                    return Err(ServiceError::Invalid(format!(
                        "macro {} step {} not allowed: {other:?}",
                        m.name,
                        i + 1
                    )));
                }
            }
            let mut cookies = if m.use_cookie_jar {
                self.refresh_jar()?;
                self.session.lock().jar.for_host(&endpoint.host)
            } else {
                vec![]
            };
            for (k, v) in local.for_host(&endpoint.host) {
                cookies.retain(|(n, _)| n != &k);
                cookies.push((k, v));
            }
            let wire = set_cookies(&self.redactor.unredact(&out.raw), &cookies);
            let sent = self.transmit(&owner, &out, wire, None, true, "macro").await?;
            run.exchange_ids.push(sent.exchange_id);
            let resp = sent.response.ok_or_else(|| {
                ServiceError::Invalid(format!(
                    "macro {} step {} failed: {}",
                    m.name,
                    i + 1,
                    sent.error.unwrap_or_default()
                ))
            })?;
            local.absorb(&endpoint.host, &resp);
            let mut st = self.session.lock();
            for x in &step.extract {
                if let Some(v) = extract(x, &resp).filter(|v| header_safe(v)) {
                    st.vars.insert(x.name.clone(), v.clone());
                    run.variables.insert(x.name.clone(), v);
                }
            }
            st.last_run.insert(m.name.clone(), Instant::now());
        }
        let learned: Vec<&String> = run.variables.keys().collect();
        self.audit(
            &owner.id(),
            "session_macro",
            json!({ "macro": m.name, "triggered_by": triggered_by, "exchanges": run.exchange_ids, "variables": learned }),
            "allow",
        )?;
        Ok(run)
    }

    /// Runs the macros a plan needs, once even when many requests ask at
    /// the same time (`since`: skip a macro that already ran after this).
    async fn run_macros(&self, cfg: &SessionConfig, names: &[String], since: Option<Instant>, actor: &Actor) {
        let _one_at_a_time = self.session_lock.lock().await;
        for name in names {
            if let Some(t) = since
                && self.session.lock().last_run.get(name).is_some_and(|r| *r > t)
            {
                continue;
            }
            let Some(m) = cfg.macros.iter().find(|m| &m.name == name) else { continue };
            if let Err(e) = self.run_macro(cfg, m, &actor.id()).await {
                tracing::warn!(macro_name = %name, error = %e, "session macro failed");
            }
        }
    }

    /// Sends with session rules, when any cover this request. None: no
    /// rule applies and the caller sends as usual.
    pub(crate) async fn send_with_session(
        &self,
        actor: &Actor,
        out: &Outgoing,
        fix_cl: bool,
        source: &str,
    ) -> Result<Option<Sent>> {
        if EXEMPT.contains(&source) {
            return Ok(None);
        }
        let cfg = load(&self.store.lock())?;
        if cfg.rules.is_empty() {
            return Ok(None);
        }
        let Some(plan) = self.session_plan(&cfg, source, &out.endpoint.host) else { return Ok(None) };
        if !plan.always.is_empty() {
            self.run_macros(&cfg, &plan.always, None, actor).await;
        }
        let base = self.redactor.unredact(&out.raw);
        let prepare = |wire: Vec<u8>| if fix_cl { pm_http::fix_content_length(&wire) } else { wire };
        let started = Instant::now();
        let wire = prepare(self.session_apply(&plan, &base, &out.endpoint.host)?);
        let sent = self.transmit(actor, out, wire, None, false, source).await?;
        let invalid: Vec<String> = match &sent.response {
            Some(r) => plan.when_invalid.iter().filter(|(_, v)| is_invalid(v, r)).map(|(m, _)| m.clone()).collect(),
            None => vec![],
        };
        if invalid.is_empty() {
            return Ok(Some(sent));
        }
        self.run_macros(&cfg, &invalid, Some(started), actor).await;
        // Values from per-request macros (e.g. CSRF tokens) belong to the
        // old session: fetch them again.
        if !plan.always.is_empty() {
            self.run_macros(&cfg, &plan.always, None, actor).await;
        }
        let wire = prepare(self.session_apply(&plan, &base, &out.endpoint.host)?);
        Ok(Some(self.transmit(actor, out, wire, None, false, source).await?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ: &[u8] = b"POST /api/cart?id=7&csrf=old HTTP/1.1\r\nHost: shop\r\nCookie: session=A; theme=dark\r\n\
Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 18\r\n\r\nqty=1&csrf=oldtok1";

    #[test]
    fn headers_and_cookies_change_in_place() {
        let r = set_header(REQ, "x-csrf-token", "T1");
        assert!(String::from_utf8_lossy(&r).contains("Content-Length: 18\r\nx-csrf-token: T1\r\n\r\nqty="));
        let r = set_header(&r, "X-CSRF-Token", "T2");
        assert!(String::from_utf8_lossy(&r).contains("\r\nX-CSRF-Token: T2\r\n\r\n"));
        assert!(!String::from_utf8_lossy(&r).contains("T1"));
        let r = set_cookies(REQ, &[("session".into(), "B".into()), ("new".into(), "1".into())]);
        assert!(String::from_utf8_lossy(&r).contains("\r\nCookie: session=B; theme=dark; new=1\r\n"));
        let bare = b"GET / HTTP/1.1\nHost: x\n\n";
        assert_eq!(set_cookies(bare, &[("a".into(), "1".into())]), b"GET / HTTP/1.1\nHost: x\nCookie: a=1\n\n");
        assert_eq!(set_cookies(bare, &[]), bare);
    }

    #[test]
    fn params_in_query_form_and_json() {
        let (r, body) = set_param(REQ, "csrf", "new tok!");
        let t = String::from_utf8_lossy(&r);
        assert!(body && t.starts_with("POST /api/cart?id=7&csrf=new+tok%21 HTTP/1.1\r\n"), "{t}");
        assert!(t.ends_with("\r\nContent-Length: 21\r\n\r\nqty=1&csrf=new+tok%21"), "{t}");
        let (same, changed) = set_param(REQ, "absent", "x");
        assert!(!changed && same == REQ);
        let json = b"POST /a HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"csrf\": \"old\", \"n\": \"csrf\"}";
        let (r, changed) = set_param(json, "csrf", "a\"b");
        assert!(changed);
        assert!(String::from_utf8_lossy(&r).ends_with("{\"csrf\": \"a\\\"b\", \"n\": \"csrf\"}"));
    }

    #[test]
    fn variables() {
        let vars = HashMap::from([("csrf".to_string(), "T".to_string())]);
        assert_eq!(substitute("a={{csrf}}&b={{other}}&s={{secret:1}}", &vars), "a=T&b={{other}}&s={{secret:1}}");
    }

    #[test]
    fn jar_follows_domains_and_expiry() {
        let mut jar = Jar::default();
        jar.absorb(
            "app.shop.test",
            b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=1; Path=/; HttpOnly\r\nSet-Cookie: wide=2; Domain=.shop.test\r\n\
Set-Cookie: evil=3; Domain=other.test\r\n\r\n",
        );
        assert_eq!(jar.for_host("app.shop.test"), vec![("sid".into(), "1".into()), ("wide".into(), "2".into())]);
        assert_eq!(jar.for_host("api.shop.test"), vec![("wide".into(), "2".into())]);
        assert!(jar.for_host("other.test").is_empty(), "cookies for other sites are ignored");
        jar.absorb("app.shop.test", b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=; Max-Age=0\r\n\r\n");
        assert_eq!(jar.for_host("app.shop.test"), vec![("wide".into(), "2".into())]);
    }

    #[test]
    fn the_jar_is_bounded() {
        let mut jar = Jar::default();
        let mut resp = String::from("HTTP/1.1 200 OK\r\n");
        for i in 0..400 {
            resp.push_str(&format!("Set-Cookie: c{i}=v\r\n"));
        }
        resp.push_str(&format!("Set-Cookie: big={}\r\n\r\n", "x".repeat(5000)));
        jar.absorb("shop.test", resp.as_bytes());
        let sent = jar.for_host("shop.test");
        assert_eq!(sent.len(), 180);
        assert_eq!(sent.last().unwrap().0, "c399", "the newest are kept");
    }

    #[test]
    fn extracted_line_breaks_never_reach_the_request() {
        let raw = b"GET / HTTP/1.1\r\nHost: shop\r\n\r\n";
        assert_eq!(set_header(raw, "X-Csrf", "t\r\n\r\nDELETE /x HTTP/1.1"), raw.to_vec());
        assert_eq!(set_header(raw, "X-Csrf", "tok"), b"GET / HTTP/1.1\r\nHost: shop\r\nX-Csrf: tok\r\n\r\n".to_vec());
        let jar = vec![("a".to_string(), "1\r\nX: y".to_string()), ("b".to_string(), "2".to_string())];
        assert_eq!(set_cookies(raw, &jar), b"GET / HTTP/1.1\r\nHost: shop\r\nCookie: b=2\r\n\r\n".to_vec());
    }

    #[test]
    fn extraction_and_validity() {
        let resp = b"HTTP/1.1 200 OK\r\nX-Token: H1\r\nSet-Cookie: s=C1\r\nContent-Type: application/json\r\n\r\n\
{\"data\":{\"token\":\"J1\",\"n\":5},\"html\":\"<input name=csrf value=R1>\"}";
        let x = |kind, expr: &str| extract(&Extraction { name: "v".into(), kind, expr: expr.into() }, resp);
        assert_eq!(x(ExtractKind::Json, "/data/token").as_deref(), Some("J1"));
        assert_eq!(x(ExtractKind::Json, "/data/n").as_deref(), Some("5"));
        assert_eq!(x(ExtractKind::Header, "x-token").as_deref(), Some("H1"));
        assert_eq!(x(ExtractKind::Cookie, "s").as_deref(), Some("C1"));
        assert_eq!(x(ExtractKind::Regex, r"name=csrf value=(\w+)").as_deref(), Some("R1"));
        assert_eq!(x(ExtractKind::Regex, "absent"), None);
        let login = b"HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n";
        assert!(is_invalid(&Validity::default(), login));
        assert!(!is_invalid(&Validity::default(), resp));
        let custom = Validity { statuses: vec![403], contains: "Please sign in".into() };
        assert!(is_invalid(&custom, b"HTTP/1.1 200 OK\r\n\r\n<p>Please sign in</p>"));
        assert!(is_invalid(&custom, b"HTTP/1.1 403 Forbidden\r\n\r\n"));
        assert!(!is_invalid(&custom, login));
    }

    #[test]
    fn validation() {
        let step = MacroStep {
            url: "http://shop:80".into(),
            request: "GET / HTTP/1.1\r\nHost: shop\r\n\r\n".into(),
            extract: vec![],
        };
        let m = Macro { name: "login".into(), steps: vec![step.clone()], use_cookie_jar: false };
        let ok = SessionConfig {
            macros: vec![m.clone()],
            rules: vec![SessionRule { macro_name: "login".into(), ..Default::default() }],
            ..Default::default()
        };
        assert!(ok.validate().is_ok());
        let unknown = SessionConfig {
            rules: vec![SessionRule { macro_name: "nope".into(), ..Default::default() }],
            ..ok.clone()
        };
        assert!(unknown.validate().is_err());
        let bad_var = Macro {
            steps: vec![MacroStep { extract: vec![Extraction { name: "1x".into(), ..Default::default() }], ..step }],
            ..m
        };
        assert!(SessionConfig { macros: vec![bad_var], ..Default::default() }.validate().is_err());
        let smuggle = SessionRule {
            set: vec![SetValue { location: SetWhere::Header, name: "X".into(), value: "a\r\nB: 1".into() }],
            ..Default::default()
        };
        assert!(SessionConfig { rules: vec![smuggle], ..Default::default() }.validate().is_err());
    }
}
