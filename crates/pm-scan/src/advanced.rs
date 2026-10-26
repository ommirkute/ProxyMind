//! Scanner step 4 checks: JWT handling, GraphQL hardening, web cache
//! poisoning and deception, mass assignment and server-side prototype
//! pollution. Payload builders and verdicts only; the service sends.

use serde_json::Value;

use crate::active::{Seen, parse, percent_encode, rebuild, set_header, similarity, without_header};

// ------------------------------------------------------------------ JWT --

/// A decoded JSON Web Token.
#[derive(Debug, Clone, PartialEq)]
pub struct Jwt {
    pub token: String,
    pub header: Value,
    pub payload: Value,
    pub alg: String,
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut bits, mut n) = (0u32, 0);
    for c in s.trim_end_matches('=').bytes() {
        let x = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' | b'+' => 62,
            b'_' | b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(x);
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
            bits &= (1 << n) - 1;
        }
    }
    Some(out)
}

fn b64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// JWTs anywhere in a request (headers, cookies, parameters, body), each once.
pub fn find_jwts(raw: &str) -> Vec<Jwt> {
    let mut out: Vec<Jwt> = Vec::new();
    let mut from = 0;
    while let Some(at) = raw[from..].find("eyJ").map(|i| i + from) {
        let end = raw[at..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
            .map_or(raw.len(), |e| at + e);
        from = end.max(at + 3);
        if let Some(j) = parse_jwt(&raw[at..end])
            && !out.iter().any(|x| x.token == j.token)
        {
            out.push(j);
        }
    }
    out
}

pub fn parse_jwt(token: &str) -> Option<Jwt> {
    let mut parts = token.split('.');
    let (h, p, _sig) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let header: Value = serde_json::from_slice(&b64url_decode(h)?).ok()?;
    let payload: Value = serde_json::from_slice(&b64url_decode(p)?).ok()?;
    let alg = header.get("alg")?.as_str()?.to_string();
    Some(Jwt { token: token.to_string(), header, payload, alg })
}

impl Jwt {
    fn parts(&self) -> (&str, &str, &str) {
        let mut it = self.token.splitn(3, '.');
        (it.next().unwrap_or(""), it.next().unwrap_or(""), it.next().unwrap_or(""))
    }

    /// The same token with one signature character changed: a verifying
    /// server must refuse it.
    pub fn tampered(&self) -> String {
        let (h, p, s) = self.parts();
        let mut sig: Vec<char> = s.chars().collect();
        match sig.first_mut() {
            Some(c) => *c = if *c == 'A' { 'B' } else { 'A' },
            None => sig.push('A'),
        }
        format!("{h}.{p}.{}", sig.into_iter().collect::<String>())
    }

    /// Forged versions that a careless verifier accepts: `alg: none` (three
    /// spellings) and the signature left out.
    pub fn forgeries(&self) -> Vec<(String, String)> {
        let (h, p, _) = self.parts();
        let mut out = Vec::new();
        for none in ["none", "None", "NONE"] {
            let mut header = self.header.clone();
            header["alg"] = Value::String(none.into());
            let enc = b64url(header.to_string().as_bytes());
            out.push((format!("alg: {none}, no signature"), format!("{enc}.{p}.")));
        }
        out.push(("signature removed".into(), format!("{h}.{p}.")));
        out
    }

    /// The HMAC secret, if it is a common one (checked offline, nothing sent).
    pub fn weak_secret(&self) -> Option<&'static str> {
        use ring::hmac;
        let algo = match self.alg.as_str() {
            "HS256" => hmac::HMAC_SHA256,
            "HS384" => hmac::HMAC_SHA384,
            "HS512" => hmac::HMAC_SHA512,
            _ => return None,
        };
        let (h, p, s) = self.parts();
        let sig = b64url_decode(s)?;
        let input = format!("{h}.{p}");
        JWT_SECRETS.iter().copied().find(|secret| {
            let key = hmac::Key::new(algo, secret.as_bytes());
            hmac::verify(&key, input.as_bytes(), &sig).is_ok()
        })
    }
}

/// Signs `header.payload` with HS256 (tests and demos).
pub fn sign_hs256(header: &Value, payload: &Value, secret: &str) -> String {
    let input = format!("{}.{}", b64url(header.to_string().as_bytes()), b64url(payload.to_string().as_bytes()));
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let sig = ring::hmac::sign(&key, input.as_bytes());
    format!("{input}.{}", b64url(sig.as_ref()))
}

/// HMAC secrets seen in tutorials, defaults and leaks.
pub const JWT_SECRETS: &[&str] = &[
    "secret",
    "secret1",
    "secret123",
    "secretkey",
    "secret-key",
    "secret_key",
    "mysecret",
    "my_secret",
    "jwt",
    "jwtsecret",
    "jwt_secret",
    "jwt-secret",
    "JWT_SECRET",
    "your-256-bit-secret",
    "your-secret-key",
    "your_jwt_secret",
    "supersecret",
    "super-secret",
    "changeme",
    "change-me",
    "password",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "admin",
    "key",
    "private",
    "default",
    "test",
    "dev",
    "development",
    "token",
    "auth",
    "hello",
    "s3cr3t",
    "shhhhh",
    "keyboard cat",
    "random",
    "abc123",
];

/// A forged request was accepted like the real one.
pub fn accepted(base: &Seen, got: &Seen) -> bool {
    base.status.is_some_and(|s| (200..400).contains(&s))
        && got.status == base.status
        && similarity(&base.body, &got.body) >= 0.8
}

// -------------------------------------------------------------- GraphQL --

/// GraphQL probes for a request whose JSON body has a `query`: (what, request).
pub fn graphql_probes(raw: &str) -> Vec<(&'static str, Vec<u8>)> {
    let Some(p) = parse(raw) else { return Vec::new() };
    let Ok(body) = serde_json::from_str::<Value>(p.body) else { return Vec::new() };
    let Some(query) = body.get("query").and_then(Value::as_str) else { return Vec::new() };
    let one = |q: &str| serde_json::json!({ "query": q }).to_string();
    let mut out = vec![
        ("introspection", rebuild(&p, p.target, &one("query { __schema { queryType { name } } }"))),
        ("batching", rebuild(&p, p.target, &serde_json::json!([body, body]).to_string())),
        ("suggestions", rebuild(&p, p.target, &one("query { __typenam }"))),
    ];
    if p.method.eq_ignore_ascii_case("POST") {
        let path = p.target.split('?').next().unwrap_or(p.target);
        let get = format!("{path}?query={}", percent_encode(query));
        if let Some(r) = without_header(&String::from_utf8_lossy(&rebuild(&p, &get, "")), "content-type")
            && let Some(r) = without_header(&String::from_utf8_lossy(&r), "content-length")
        {
            let s = String::from_utf8_lossy(&r).replacen(p.method, "GET", 1);
            out.push(("get", s.into_bytes()));
        }
    }
    out
}

/// Whether a GraphQL probe's response shows what it looks for.
pub fn graphql_verdict(what: &str, base: &Seen, got: &Seen) -> Option<(&'static str, &'static str, String)> {
    let json: Option<Value> = serde_json::from_str(&got.body).ok();
    match what {
        "introspection" => json.as_ref().and_then(|j| j.pointer("/data/__schema")).filter(|s| !s.is_null()).map(|_| {
            ("low", "GraphQL introspection is enabled", "the schema query answered with data.__schema".into())
        }),
        "batching" => json
            .as_ref()
            .and_then(Value::as_array)
            .filter(|a| a.len() >= 2 && a.iter().all(|x| x.get("data").is_some() || x.get("errors").is_some()))
            .map(|_| {
                (
                    "low",
                    "GraphQL batching is accepted (one request runs many operations: rate limits can be bypassed)",
                    "an array of two operations got an array of two results".into(),
                )
            }),
        "suggestions" => got.body.contains("Did you mean").then(|| {
            (
                "info",
                "GraphQL field suggestions are on (the schema leaks even without introspection)",
                "\"Did you mean\" in the error".into(),
            )
        }),
        "get" => (got.status.is_some_and(|s| (200..300).contains(&s))
            && json.as_ref().and_then(|j| j.get("data")).is_some_and(|d| !d.is_null())
            && similarity(&base.body, &got.body) >= 0.8)
            .then(|| {
                (
                    "medium",
                    "GraphQL queries run over GET (cross-site requests can run them with the user's cookies)",
                    "the same query as a GET parameter got the same data".into(),
                )
            }),
        _ => None,
    }
}

// ---------------------------------------------------------- web caches --

/// Headers that caches often leave out of the key but apps use.
pub const UNKEYED_HEADERS: &[&str] =
    &["X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Original-Host", "X-Forwarded-Scheme"];

/// `raw` with a cache-buster parameter, so probes never touch the cache
/// entry real users get.
pub fn with_cache_buster(raw: &str, buster: &str) -> Option<Vec<u8>> {
    let p = parse(raw)?;
    let sep = if p.target.contains('?') { '&' } else { '?' };
    Some(rebuild(&p, &format!("{}{sep}pmcb={buster}", p.target), p.body))
}

/// Requests for a cache poisoning test of one header: (header, poisoned
/// request, the same URL without the header).
pub fn cache_poison_probes(raw: &str, marker: &str) -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    UNKEYED_HEADERS
        .iter()
        .enumerate()
        .filter_map(|(i, h)| {
            // The buster must not contain the marker: pages that echo the URL would look poisoned.
            let busted = with_cache_buster(raw, &buster_for(marker, i))?;
            let busted = String::from_utf8_lossy(&busted).into_owned();
            let value = if *h == "X-Forwarded-Scheme" { "http".to_string() } else { format!("{marker}.example") };
            Some((*h, set_header(&busted, h, &value)?, busted.into_bytes()))
        })
        .collect()
}

/// Whether a response shows the injected header value (or, for
/// X-Forwarded-Scheme, a redirect the original didn't have).
pub fn shows_injection(header: &str, base: &Seen, got: &Seen, marker: &str) -> bool {
    if header == "X-Forwarded-Scheme" {
        return got.status.is_some_and(|s| (300..400).contains(&s)) && base.status != got.status;
    }
    let host = format!("{marker}.example");
    got.body.contains(&host) || got.location.as_deref().is_some_and(|l| l.contains(&host))
}

/// A cache-buster value for probe `i` that doesn't contain `marker`.
pub fn buster_for(marker: &str, i: usize) -> String {
    format!("cb{i}{}", marker.trim_start_matches("pm"))
}

/// Cache deception paths for an authenticated GET: (trick, request) with
/// a static-looking suffix the app may ignore and a cache may store.
pub fn cache_deception_probes(raw: &str, marker: &str) -> Vec<(&'static str, Vec<u8>)> {
    let Some(p) = parse(raw) else { return Vec::new() };
    let (path, query) = p.target.split_once('?').map_or((p.target, String::new()), |(a, q)| (a, format!("?{q}")));
    if path.len() < 2 {
        return Vec::new();
    }
    let path = path.trim_end_matches('/');
    [("/x.css", format!("{path}/pm{marker}.css")), (";x.css", format!("{path};pm{marker}.css"))]
        .into_iter()
        .map(|(what, t)| (what, rebuild(&p, &format!("{t}{query}"), p.body)))
        .collect()
}

/// `raw` without its credentials (cookies and Authorization).
pub fn anonymous(raw: &str) -> Option<Vec<u8>> {
    let r = without_header(raw, "cookie")?;
    without_header(&String::from_utf8_lossy(&r), "authorization")
}

/// Whether a request carries credentials.
pub fn has_credentials(raw: &str) -> bool {
    parse(raw).is_some_and(|p| {
        p.rest_of_head.lines().any(|l| {
            let k = l.split(':').next().unwrap_or("").trim();
            k.eq_ignore_ascii_case("cookie") || k.eq_ignore_ascii_case("authorization")
        })
    })
}

// ------------------------------------------------------ mass assignment --

/// Privileged fields people forget to filter out.
pub const PRIVILEGED_FIELDS: &[(&str, &str)] =
    &[("role", "admin"), ("isAdmin", "true"), ("is_admin", "true"), ("admin", "true"), ("verified", "true")];

/// The submission with the privileged fields added (JSON object or form),
/// plus a made-up field `pm<marker>` as a control: an endpoint that echoes
/// any field proves nothing.
pub fn with_privileged_fields(raw: &str, marker: &str) -> Option<Vec<u8>> {
    let control = format!("pm{marker}");
    let p = parse(raw)?;
    if p.json {
        let mut v: Value = serde_json::from_str(p.body).ok()?;
        let o = v.as_object_mut()?;
        // A sign-up re-sent as is fails on "already taken": make it a new account.
        for (k, val) in o.iter_mut() {
            if let Value::String(s) = val
                && is_account_field(k)
            {
                *s = unique_value(s, marker);
            }
        }
        for (k, val) in PRIVILEGED_FIELDS {
            if !o.contains_key(*k) {
                let x = if *val == "true" { Value::Bool(true) } else { Value::String((*val).into()) };
                o.insert((*k).to_string(), x);
            }
        }
        o.insert(control, Value::String("1".into()));
        Some(rebuild(&p, p.target, &v.to_string()))
    } else if p.form {
        let body: String = p
            .body
            .trim()
            .split('&')
            .map(|kv| match kv.split_once('=') {
                Some((k, v)) if is_account_field(k) => format!("{k}={}", unique_value(v, marker)),
                _ => kv.to_string(),
            })
            .collect::<Vec<_>>()
            .join("&");
        let p = crate::active::Parsed { body: &body, ..p };
        let mut extra: Vec<String> = PRIVILEGED_FIELDS
            .iter()
            .filter(|(k, _)| !p.body.split('&').any(|kv| kv.split('=').next() == Some(*k)))
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        extra.push(format!("{control}=1"));
        let body = p.body.trim();
        let sep = if body.is_empty() { "" } else { "&" };
        Some(rebuild(&p, p.target, &format!("{body}{sep}{}", extra.join("&"))))
    } else {
        None
    }
}

/// Fields that name an account and must be unique (email, username…).
fn is_account_field(k: &str) -> bool {
    matches!(
        k.to_ascii_lowercase().replace(['_', '-'], "").as_str(),
        "email" | "mail" | "emailaddress" | "username" | "user" | "login" | "loginname" | "name" | "nickname"
    )
}

/// `value` made unique with the marker, keeping an email an email.
fn unique_value(value: &str, marker: &str) -> String {
    match value.split_once('@').or_else(|| value.split_once("%40")) {
        Some((local, domain)) => {
            let at = if value.contains('@') { "@" } else { "%40" };
            format!("{local}{marker}{at}{domain}")
        }
        None => format!("{value}{marker}"),
    }
}

fn json_pairs(v: &Value, out: &mut Vec<(String, String)>) {
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                match x {
                    Value::String(s) => out.push((k.to_ascii_lowercase(), s.to_ascii_lowercase())),
                    Value::Bool(b) => out.push((k.to_ascii_lowercase(), b.to_string())),
                    _ => json_pairs(x, out),
                }
            }
        }
        Value::Array(a) => a.iter().for_each(|x| json_pairs(x, out)),
        _ => {}
    }
}

/// Privileged fields the response shows with our value, unlike the original
/// (none if the made-up control field came back too).
pub fn mass_assigned(base: &Seen, got: &Seen, marker: &str) -> Vec<String> {
    let pairs = |s: &Seen| {
        let mut out = Vec::new();
        if let Ok(v) = serde_json::from_str::<Value>(&s.body) {
            json_pairs(&v, &mut out);
        }
        out
    };
    let (b, g) = (pairs(base), pairs(got));
    let control = format!("pm{marker}").to_ascii_lowercase();
    if g.iter().any(|(k, _)| *k == control) {
        return Vec::new();
    }
    PRIVILEGED_FIELDS
        .iter()
        .filter(|(k, v)| {
            let kv = (k.to_ascii_lowercase(), v.to_string());
            g.contains(&kv) && !b.contains(&kv)
        })
        .map(|(k, v)| format!("{k}={v}"))
        .collect()
}

// ------------------------------------------------------------ logins --

const USER_FIELDS: &[&str] = &["username", "user", "email", "login", "user_name", "username_or_email", "mail"];
const PASSWORD_FIELDS: &[&str] = &["password", "pass", "passwd", "pwd"];

/// Requests for telling whether a login reveals which accounts exist: the
/// recorded user with a wrong password (twice: the second is a control for
/// noise) and an account that doesn't exist with the same wrong password.
#[derive(Debug, Clone)]
pub struct EnumProbes {
    pub wrong_password: Vec<u8>,
    pub unknown_user: Vec<u8>,
    /// The recorded user and the made-up one (removed before comparing).
    pub user: String,
    pub fake_user: String,
}

fn field_of<'a>(keys: impl Iterator<Item = &'a str>, wanted: &[&str]) -> Option<&'a str> {
    keys.into_iter().find(|k| wanted.iter().any(|w| k.eq_ignore_ascii_case(w)))
}

/// Probes for a login submission (JSON or form with a user and a password
/// field); None for anything else.
pub fn enum_probes(raw: &str, marker: &str) -> Option<EnumProbes> {
    let p = parse(raw)?;
    let wrong = format!("Pm{marker}-Wrong-1");
    if p.json {
        let v: Value = serde_json::from_str(p.body).ok()?;
        let o = v.as_object()?;
        let uk = field_of(o.keys().map(String::as_str), USER_FIELDS)?.to_string();
        let pk = field_of(o.keys().map(String::as_str), PASSWORD_FIELDS)?.to_string();
        let user = o.get(&uk)?.as_str()?.to_string();
        o.get(&pk)?.as_str()?;
        let fake = if user.contains('@') { format!("pm{marker}@example.invalid") } else { format!("pm{marker}nouser") };
        let with = |u: &str| {
            let mut x = v.clone();
            x[&uk] = Value::String(u.into());
            x[&pk] = Value::String(wrong.clone());
            rebuild(&p, p.target, &x.to_string())
        };
        return Some(EnumProbes { wrong_password: with(&user), unknown_user: with(&fake), user, fake_user: fake });
    }
    if p.form {
        let pairs: Vec<(&str, &str)> = p.body.trim().split('&').filter_map(|kv| kv.split_once('=')).collect();
        let uk = field_of(pairs.iter().map(|(k, _)| *k), USER_FIELDS)?;
        let pk = field_of(pairs.iter().map(|(k, _)| *k), PASSWORD_FIELDS)?;
        let user = pairs.iter().find(|(k, _)| *k == uk)?.1.to_string();
        let fake = if user.contains('@') || user.contains("%40") {
            format!("pm{marker}%40example.invalid")
        } else {
            format!("pm{marker}nouser")
        };
        let with = |u: &str| {
            let body: Vec<String> = pairs
                .iter()
                .map(|(k, v)| {
                    if *k == uk {
                        format!("{k}={u}")
                    } else if *k == pk {
                        format!("{k}={wrong}")
                    } else {
                        format!("{k}={v}")
                    }
                })
                .collect();
            rebuild(&p, p.target, &body.join("&"))
        };
        let user_shown = user.replace("%40", "@");
        let fake_shown = fake.replace("%40", "@");
        return Some(EnumProbes {
            wrong_password: with(&user),
            unknown_user: with(&fake),
            user: user_shown,
            fake_user: fake_shown,
        });
    }
    None
}

fn without_names(s: &Seen, names: &[&str]) -> String {
    let mut b = s.body.clone();
    for n in names.iter().filter(|n| !n.is_empty()) {
        b = b.replace(n, "<user>");
    }
    b
}

/// What gives away that an account exists, if anything: a different status
/// or message for an unknown account than for a wrong password (the wrong
/// password sent twice must answer the same, or the page is too noisy).
pub fn enumerates(probes: &EnumProbes, wrong: &Seen, again: &Seen, unknown: &Seen) -> Option<String> {
    let names = [probes.user.as_str(), probes.fake_user.as_str()];
    let (w, a, u) = (without_names(wrong, &names), without_names(again, &names), without_names(unknown, &names));
    if wrong.status.is_some_and(|s| (200..300).contains(&s)) && w.contains("token") {
        return None; // the "wrong" password worked: not a login we understand
    }
    if wrong.status != again.status || w != a {
        return None;
    }
    let clip = |s: &str| s.chars().take(120).collect::<String>();
    if wrong.status != unknown.status {
        return Some(format!(
            "a wrong password gets status {}, an unknown account gets {}",
            wrong.status.unwrap_or(0),
            unknown.status.unwrap_or(0)
        ));
    }
    (w != u).then(|| format!("a wrong password answers {:?}; an unknown account answers {:?}", clip(&w), clip(&u)))
}

/// A password change that asks for the current password, without it:
/// (the request without the field, the field's name). The new password
/// stays the one recorded, so re-sending it changes nothing.
pub fn without_current_password(raw: &str) -> Option<(Vec<u8>, String)> {
    const CURRENT: &[&str] =
        &["current", "currentpassword", "current_password", "oldpassword", "old_password", "old", "oldpass"];
    let is_current = |k: &str| CURRENT.iter().any(|c| k.eq_ignore_ascii_case(c));
    let p = parse(raw)?;
    let lower = p.target.to_ascii_lowercase();
    // Query string (Juice Shop's GET /rest/user/change-password?current=…&new=…).
    if let Some((path, q)) = p.target.split_once('?')
        && lower.contains("password")
    {
        let parts: Vec<&str> = q.split('&').collect();
        let name = parts.iter().filter_map(|kv| kv.split('=').next()).find(|k| is_current(k))?.to_string();
        let rest: Vec<&str> = parts.into_iter().filter(|kv| kv.split('=').next() != Some(name.as_str())).collect();
        let target = if rest.is_empty() { path.to_string() } else { format!("{path}?{}", rest.join("&")) };
        return Some((rebuild(&p, &target, p.body), name));
    }
    if p.json {
        let mut v: Value = serde_json::from_str(p.body).ok()?;
        let o = v.as_object_mut()?;
        let has_new = o.keys().any(|k| {
            let k = k.to_ascii_lowercase();
            k.contains("new") || k.contains("repeat") || k.contains("confirm")
        });
        let name = o.keys().find(|k| is_current(k)).cloned()?;
        if !has_new {
            return None;
        }
        o.remove(&name);
        return Some((rebuild(&p, p.target, &v.to_string()), name));
    }
    None
}

// ---------------------------------------------------------- exposure --

/// Keys in a JSON response that hold credentials (with a non-empty value).
pub fn credential_keys(body: &str) -> Vec<String> {
    const KEYS: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "password_hash",
        "passwordhash",
        "hash",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "totp_secret",
        "totpsecret",
    ];
    fn walk(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(o) => {
                for (k, x) in o {
                    let filled = matches!(x, Value::String(s) if s.len() >= 3);
                    if filled && KEYS.contains(&k.to_ascii_lowercase().as_str()) && !out.contains(k) {
                        out.push(k.clone());
                    }
                    walk(x, out);
                }
            }
            Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<Value>(body) {
        walk(&v, &mut out);
    }
    out
}

/// Email addresses in a text, lower-cased.
pub fn emails(text: &str) -> std::collections::BTreeSet<String> {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+").expect("valid regex")
    });
    re.find_iter(text).map(|m| m.as_str().to_ascii_lowercase()).collect()
}

/// Files a directory listing links to that look confidential (documents,
/// backups, key stores, configuration, compiled code): names, not folders.
pub fn sensitive_listed_files(html: &str) -> Vec<String> {
    const EXT: &[&str] = &[
        ".md", ".bak", ".old", ".kdbx", ".key", ".pem", ".sql", ".db", ".sqlite", ".yml", ".yaml", ".env", ".log",
        ".pyc", ".zip", ".tar", ".gz", ".7z", ".csv", ".xlsx", ".docx", ".pdf", ".conf", ".ini", ".json", ".txt",
    ];
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| regex::Regex::new(r#"(?i)href\s*=\s*["']([^"'?#]+)["']"#).expect("valid regex"));
    let mut out: Vec<String> = Vec::new();
    for c in re.captures_iter(html) {
        let href = c[1].to_string();
        let name = href.rsplit('/').next().unwrap_or("").to_ascii_lowercase();
        if name.is_empty() || href.starts_with("http") || href.starts_with("//") || href.contains("..") {
            continue;
        }
        if EXT.iter().any(|e| name.ends_with(e)) && !out.contains(&href) {
            out.push(href);
        }
    }
    // The most telling first: key stores and backups, then documents.
    let rank = |h: &String| {
        let n = h.to_ascii_lowercase();
        if [".kdbx", ".key", ".pem", ".bak", ".sql", ".env", ".db"].iter().any(|e| n.ends_with(e)) {
            0
        } else if n.ends_with(".md") || n.ends_with(".pdf") || n.ends_with(".docx") {
            1
        } else {
            2
        }
    };
    out.sort_by_key(rank);
    out
}

// ------------------------------------------------- prototype pollution --

/// JSON submissions with `__proto__` and `constructor.prototype` carrying a
/// marker property: (how, request).
pub fn proto_probes(raw: &str, marker: &str) -> Vec<(&'static str, Vec<u8>)> {
    let Some(p) = parse(raw) else { return Vec::new() };
    if !p.json {
        return Vec::new();
    }
    let Ok(Value::Object(base)) = serde_json::from_str::<Value>(p.body) else { return Vec::new() };
    let prop = format!("pm{marker}");
    let mut out = Vec::new();
    for (how, extra) in [
        ("__proto__", serde_json::json!({ "__proto__": { prop.clone(): "polluted" } })),
        ("constructor.prototype", serde_json::json!({ "constructor": { "prototype": { prop.clone(): "polluted" } } })),
    ] {
        let mut o = base.clone();
        if let Value::Object(e) = extra {
            o.extend(e);
        }
        out.push((how, rebuild(&p, p.target, &Value::Object(o).to_string())));
    }
    out
}

/// Whether the marker property shows up outside the `__proto__` /
/// `constructor` objects we sent (it was merged into a prototype).
pub fn polluted(got: &Seen, marker: &str) -> bool {
    fn walk(v: &Value, prop: &str) -> bool {
        match v {
            Value::Object(o) => o.iter().any(|(k, x)| {
                if k == "__proto__" || k == "constructor" {
                    return false;
                }
                k == prop || walk(x, prop)
            }),
            Value::Array(a) => a.iter().any(|x| walk(x, prop)),
            _ => false,
        }
    }
    serde_json::from_str::<Value>(&got.body).is_ok_and(|v| walk(&v, &format!("pm{marker}")))
}

// ----------------------------------------------- request smuggling (4b) --

/// Timing probes for HTTP/1.1 request smuggling: a front end and back end
/// that disagree on framing make the back end wait for bytes that never
/// come. Built from the request's head as a POST.
pub struct SmugglingProbes {
    /// A complete chunked body, but Content-Length says 4: a CL front end
    /// forwards `1\r\nA` and a TE back end waits for the next chunk. (A lone
    /// server reads either framing to the end and answers at once.)
    pub cl_te: Vec<u8>,
    /// Chunked ends after 5 bytes, Content-Length says 6: a CL back end waits.
    pub te_cl: Vec<u8>,
    /// Both framings agree: must be fast.
    pub control: Vec<u8>,
}

pub fn smuggling_probes(raw: &str) -> Option<SmugglingProbes> {
    let p = parse(raw)?;
    if !p.version.starts_with("HTTP/1") {
        return None;
    }
    let skip = ["content-length", "transfer-encoding", "content-type", "connection"];
    let head: Vec<&str> = p
        .rest_of_head
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| {
            !l.is_empty() && !skip.contains(&l.split(':').next().unwrap_or("").trim().to_ascii_lowercase().as_str())
        })
        .collect();
    let build = |cl: usize, body: &str| {
        format!(
            "POST {} {}\r\n{}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {cl}\r\n\
             Transfer-Encoding: chunked\r\n\r\n{body}",
            p.target,
            p.version,
            head.join("\r\n")
        )
        .into_bytes()
    };
    Some(SmugglingProbes {
        cl_te: build(4, "1\r\nA\r\n0\r\n\r\n"),
        te_cl: build(6, "0\r\n\r\nX"),
        control: build(5, "0\r\n\r\n"),
    })
}

/// A probe hung well past the baseline (the server waited for more body).
pub fn hung(base_ms: &[u64], ms: u64) -> bool {
    let max = base_ms.iter().copied().max().unwrap_or(0);
    ms >= max + 4000
}

// -------------------------------------------------------------- OAuth --

/// For an authorization request (a `redirect_uri` parameter): the request
/// with redirect_uri pointing elsewhere, (trick, request).
pub fn oauth_probes(raw: &str, marker: &str) -> Vec<(&'static str, Vec<u8>)> {
    let Some(p) = parse(raw) else { return Vec::new() };
    let Some((path, query)) = p.target.split_once('?') else { return Vec::new() };
    let pairs: Vec<(String, String)> = query
        .split('&')
        .map(|kv| kv.split_once('=').map_or((kv.to_string(), String::new()), |(k, v)| (k.to_string(), v.to_string())))
        .collect();
    let Some(orig) = pairs.iter().find(|(k, _)| k == "redirect_uri").map(|(_, v)| crate::active::percent_decode(v))
    else {
        return Vec::new();
    };
    let evil = format!("pm{marker}.example");
    let host = url_host(&orig).unwrap_or_default();
    let mut tricks = vec![("another site", format!("https://{evil}/callback"))];
    if !host.is_empty() {
        tricks.push(("registered host as a prefix", format!("https://{host}.{evil}/callback")));
        tricks.push(("registered host as user info", format!("https://{host}@{evil}/callback")));
    }
    tricks
        .into_iter()
        .map(|(what, uri)| {
            let q: Vec<String> = pairs
                .iter()
                .map(
                    |(k, v)| {
                        if k == "redirect_uri" { format!("{k}={}", percent_encode(&uri)) } else { format!("{k}={v}") }
                    },
                )
                .collect();
            (what, rebuild(&p, &format!("{path}?{}", q.join("&")), p.body))
        })
        .collect()
}

fn url_host(u: &str) -> Option<String> {
    let rest = u.split_once("://")?.1;
    let auth = rest.split(['/', '?', '#']).next()?;
    let host = auth.rsplit('@').next()?;
    Some(host.to_ascii_lowercase())
}

/// The request without query parameter `name`.
pub fn without_query_param(raw: &str, name: &str) -> Option<Vec<u8>> {
    let p = parse(raw)?;
    let (path, query) = p.target.split_once('?')?;
    let kept: Vec<&str> = query.split('&').filter(|kv| kv.split('=').next() != Some(name)).collect();
    if kept.len() == query.split('&').count() {
        return None;
    }
    let target = if kept.is_empty() { path.to_string() } else { format!("{path}?{}", kept.join("&")) };
    Some(rebuild(&p, &target, p.body))
}

/// The response sends the user (with a code or token) to our host.
pub fn oauth_leaks(got: &Seen, marker: &str) -> bool {
    let evil = format!("pm{marker}.example").to_ascii_lowercase();
    got.location.as_deref().and_then(url_host).is_some_and(|h| h == evil || h.ends_with(&format!(".{evil}")))
}

/// A code or token issued for a request without `state` (login CSRF).
pub fn oauth_without_state(raw: &str, got: &Seen) -> bool {
    let has_state = parse(raw)
        .and_then(|p| p.target.split_once('?').map(|(_, q)| q.split('&').any(|kv| kv.starts_with("state="))))
        .unwrap_or(false);
    let issued = got.location.as_deref().is_some_and(|l| l.contains("code=") || l.contains("access_token="));
    !has_state && issued
}

// --------------------------------------------------- deserialization --

/// What a value holds: (format, corrupted copy). Base64 values stay base64.
pub fn deser_probe(value: &str) -> Option<(&'static str, String)> {
    let php = |t: &str| {
        let b = t.as_bytes();
        b.len() > 4
            && matches!(b[0], b'a' | b'O' | b's' | b'i' | b'b' | b'C')
            && b[1] == b':'
            && t[2..].starts_with(|c: char| c.is_ascii_digit())
    };
    if php(value) {
        return Some(("PHP", corrupt_php(value)?));
    }
    let bytes = b64_any(value)?;
    let kind = if bytes.starts_with(&[0xAC, 0xED, 0x00, 0x05]) {
        "Java"
    } else if bytes.len() > 2 && bytes[0] == 0x80 && (2..=5).contains(&bytes[1]) {
        "Python pickle"
    } else if bytes.starts_with(&[0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]) {
        ".NET BinaryFormatter"
    } else if bytes.starts_with(&[0x04, 0x08]) {
        "Ruby Marshal"
    } else if std::str::from_utf8(&bytes).is_ok_and(php) {
        let t = corrupt_php(std::str::from_utf8(&bytes).ok()?)?;
        return Some(("PHP", b64_std(t.as_bytes())));
    } else {
        return None;
    };
    // Cut the stream short and end it with junk: a deserializer fails loudly.
    let mut cut = bytes[..bytes.len() * 2 / 3].to_vec();
    cut.extend_from_slice(&[0xFF, 0xFE, 0x7F]);
    Some((kind, b64_std(&cut)))
}

fn corrupt_php(t: &str) -> Option<String> {
    // Make the first declared string length wrong: `s:6:"Coffee"` → `s:13:"Coffee"`.
    let at = t.find("s:")?;
    let digits: String = t[at + 2..].chars().take_while(char::is_ascii_digit).collect();
    let n: usize = digits.parse().ok()?;
    Some(format!("{}s:{}{}", &t[..at], n + 7, &t[at + 2 + digits.len()..]))
}

fn b64_any(v: &str) -> Option<Vec<u8>> {
    let v = v.trim();
    if v.len() < 8 || !v.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/' | b'=' | b'-' | b'_')) {
        return None;
    }
    b64url_decode(v)
}

fn b64_std(data: &[u8]) -> String {
    let mut out = b64url(data).replace('-', "+").replace('_', "/");
    while !out.len().is_multiple_of(4) {
        out.push('=');
    }
    out
}

/// Error text that shows the server deserialized our corrupted object.
pub const DESER_ERRORS: &[(&str, &str)] = &[
    ("java.io.StreamCorruptedException", "Java"),
    ("java.io.EOFException", "Java"),
    ("java.io.InvalidClassException", "Java"),
    ("invalid stream header", "Java"),
    ("ObjectInputStream", "Java"),
    ("unserialize()", "PHP"),
    ("__PHP_Incomplete_Class", "PHP"),
    ("UnpicklingError", "Python"),
    ("pickle data was truncated", "Python"),
    ("_pickle.", "Python"),
    ("SerializationException", ".NET"),
    ("BinaryFormatter", ".NET"),
    ("marshal data too short", "Ruby"),
];

/// The deserialization error in `got` that `base` doesn't have.
pub fn deser_error(base: &Seen, got: &Seen) -> Option<&'static str> {
    DESER_ERRORS.iter().find(|(e, _)| got.body.contains(e) && !base.body.contains(e)).map(|(e, _)| *e)
}

// -------------------------------------------------------- file upload --

/// What an upload probe checks once the file is fetched back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadKind {
    Html,
    Svg,
    Php,
}

impl UploadKind {
    pub fn file_name(self, marker: &str) -> String {
        let ext = match self {
            UploadKind::Html => "html",
            UploadKind::Svg => "svg",
            UploadKind::Php => "php",
        };
        format!("pm{marker}.{ext}")
    }

    fn content(self, marker: &str) -> (&'static str, String) {
        match self {
            UploadKind::Html => {
                ("text/html", format!("<html><body><pmx-{marker}>pm{marker}</pmx-{marker}></body></html>"))
            }
            UploadKind::Svg => (
                "image/svg+xml",
                format!("<svg xmlns=\"http://www.w3.org/2000/svg\"><script>/*pm{marker}*/</script></svg>"),
            ),
            // Harmless: prints a string only if PHP runs it.
            UploadKind::Php => ("image/png", format!("<?php echo 'pm' . '{marker}' . 'run'; ?>")),
        }
    }

    /// Whether the fetched file shows the risk.
    pub fn verdict(self, got: &Seen, marker: &str) -> bool {
        let ct = got.content_type.as_deref().or(got.header("content-type")).unwrap_or("").to_ascii_lowercase();
        match self {
            UploadKind::Html => ct.contains("html") && got.body.contains(&format!("<pmx-{marker}>")),
            UploadKind::Svg => ct.contains("svg") && got.body.contains(&format!("<script>/*pm{marker}*/")),
            UploadKind::Php => got.body.contains(&format!("pm{marker}run")) && !got.body.contains("<?php"),
        }
    }
}

/// Multipart uploads with the file part replaced: (kind, request).
pub fn upload_probes(raw: &str, marker: &str) -> Vec<(UploadKind, Vec<u8>)> {
    let Some(p) = parse(raw) else { return Vec::new() };
    let ct = p
        .rest_of_head
        .lines()
        .find_map(|l| {
            l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-type")).map(|(_, v)| v.trim())
        })
        .unwrap_or("");
    if !ct.to_ascii_lowercase().starts_with("multipart/form-data") {
        return Vec::new();
    }
    let Some(boundary) = ct.split(';').find_map(|x| x.trim().strip_prefix("boundary=")).map(|b| b.trim_matches('"'))
    else {
        return Vec::new();
    };
    let delim = format!("--{boundary}");
    let parts: Vec<&str> = p.body.split(delim.as_str()).collect();
    let Some(file_idx) = parts.iter().position(|x| x.contains("filename=")) else { return Vec::new() };
    let field = parts[file_idx].split("name=\"").nth(1).and_then(|x| x.split('"').next()).unwrap_or("file").to_string();
    [UploadKind::Html, UploadKind::Svg, UploadKind::Php]
        .into_iter()
        .map(|k| {
            let (ctype, data) = k.content(marker);
            let part = format!(
                "\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{}\"\r\nContent-Type: {ctype}\r\n\r\n{data}\r\n",
                k.file_name(marker)
            );
            let mut new_parts: Vec<String> = parts.iter().map(|x| x.to_string()).collect();
            new_parts[file_idx] = part;
            let body = new_parts.join(delim.as_str());
            (k, rebuild(&p, p.target, &body))
        })
        .collect()
}

/// Where the upload response says the file went (paths and URLs that end
/// in the file name), then the usual folders. At most 4, as origin-form paths.
pub fn upload_locations(body: &str, file_name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (at, _) in body.match_indices(file_name) {
        let start = body[..at]
            .rfind(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | '=' | ','))
            .map_or(0, |i| i + 1);
        let found = &body[start..at + file_name.len()];
        let path = match found.split_once("://") {
            Some((_, rest)) => rest.find('/').map(|i| rest[i..].to_string()),
            None if found.starts_with('/') => Some(found.to_string()),
            None => None,
        };
        if let Some(path) = path.filter(|x| !out.contains(x)) {
            out.push(path);
        }
    }
    for dir in ["/uploads/", "/files/", "/static/uploads/", "/images/"] {
        let p = format!("{dir}{file_name}");
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out.truncate(4);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn seen(status: u16, body: &str) -> Seen {
        Seen { status: Some(status), body: body.into(), ..Default::default() }
    }

    #[test]
    fn jwts_are_found_forged_and_cracked() {
        let t = sign_hs256(&json!({"alg": "HS256", "typ": "JWT"}), &json!({"sub": "alice"}), "secret");
        let raw = format!("GET /p HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {t}\r\nCookie: a=1; jwt={t}\r\n\r\n");
        let found = find_jwts(&raw);
        assert_eq!(found.len(), 1);
        let j = &found[0];
        assert_eq!((j.alg.as_str(), j.payload["sub"].as_str()), ("HS256", Some("alice")));
        assert_eq!(j.weak_secret(), Some("secret"));
        let strong = sign_hs256(&j.header, &j.payload, "a long random secret nobody guesses 7f3a9c");
        assert_eq!(parse_jwt(&strong).unwrap().weak_secret(), None);
        let f = j.forgeries();
        assert_eq!(f.len(), 4);
        let none = parse_jwt(&f[0].1).unwrap();
        assert_eq!((none.alg.as_str(), none.payload["sub"].as_str()), ("none", Some("alice")));
        assert!(f[0].1.ends_with('.'));
        assert_ne!(j.tampered(), j.token);
        assert!(parse_jwt("eyJhbGciOiJIUzI1NiJ9.notjson.x").is_none());
    }

    #[test]
    fn graphql_probes_and_verdicts() {
        let raw = "POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n\
                   {\"query\":\"{ me { id } }\"}";
        let p = graphql_probes(raw);
        assert_eq!(p.iter().map(|x| x.0).collect::<Vec<_>>(), ["introspection", "batching", "suggestions", "get"]);
        let get = String::from_utf8(p[3].1.clone()).unwrap();
        assert!(get.starts_with("GET /graphql?query=%7B%20me%20%7B%20id%20%7D%20%7D HTTP/1.1\r\n"), "{get}");
        assert!(!get.contains("Content-Type") && !get.contains("Content-Length"));
        let base = seen(200, r#"{"data":{"me":{"id":"1"}}}"#);
        assert!(
            graphql_verdict("introspection", &base, &seen(200, r#"{"data":{"__schema":{"queryType":{}}}}"#)).is_some()
        );
        assert!(graphql_verdict("introspection", &base, &seen(200, r#"{"errors":[{"message":"off"}]}"#)).is_none());
        assert!(graphql_verdict("batching", &base, &seen(200, r#"[{"data":{}},{"data":{}}]"#)).is_some());
        assert!(graphql_verdict("batching", &base, &seen(400, r#"{"errors":[]}"#)).is_none());
        assert!(graphql_verdict("get", &base, &base.clone()).is_some());
        assert!(graphql_probes("POST /x HTTP/1.1\r\nHost: x\r\n\r\n{\"a\":1}").is_empty());
    }

    #[test]
    fn cache_probes_use_a_buster() {
        let raw = "GET /banner?lang=en HTTP/1.1\r\nHost: x\r\n\r\n";
        let p = cache_poison_probes(raw, "pmK");
        assert_eq!(p.len(), UNKEYED_HEADERS.len());
        let (h, poisoned, clean) = &p[0];
        assert_eq!(*h, "X-Forwarded-Host");
        let (poisoned, clean) = (String::from_utf8_lossy(poisoned), String::from_utf8_lossy(clean));
        assert!(
            poisoned.starts_with("GET /banner?lang=en&pmcb=cb0K ")
                && poisoned.contains("X-Forwarded-Host: pmK.example")
        );
        assert!(clean.starts_with("GET /banner?lang=en&pmcb=cb0K ") && !clean.contains("X-Forwarded-Host"));
        let base = seen(200, "<script src=//x/b.js>");
        assert!(shows_injection("X-Forwarded-Host", &base, &seen(200, "<script src=//pmK.example/b.js>"), "pmK"));
        assert!(!shows_injection("X-Forwarded-Host", &base, &base.clone(), "pmK"));
        // An echoed URL (with the buster) is not the injected host.
        assert!(!shows_injection("X-Forwarded-Host", &base, &seen(301, "Redirecting to /banner?pmcb=cb0K"), "pmK"));

        let authed = "GET /api/account HTTP/1.1\r\nHost: x\r\nCookie: s=1\r\n\r\n";
        let d = cache_deception_probes(authed, "pmK");
        assert!(String::from_utf8_lossy(&d[0].1).starts_with("GET /api/account/pmpmK.css "));
        assert!(String::from_utf8_lossy(&d[1].1).starts_with("GET /api/account;pmpmK.css "));
        assert!(has_credentials(authed) && !has_credentials(raw));
        assert!(!String::from_utf8_lossy(&anonymous(authed).unwrap()).contains("Cookie"));
    }

    #[test]
    fn mass_assignment_and_prototype_pollution() {
        let json = "POST /r HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{\"username\":\"u\"}";
        let r = String::from_utf8(with_privileged_fields(json, "M").unwrap()).unwrap();
        assert!(r.contains("\"role\":\"admin\"") && r.contains("\"isAdmin\":true"));
        assert!(r.contains("\"username\":\"uM\""), "a new account each time: {r}");
        assert!(r.contains("\"pmM\":\"1\""));
        let form = "POST /r HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=u&role=user";
        let r = String::from_utf8(with_privileged_fields(form, "M").unwrap()).unwrap();
        assert!(r.ends_with("username=uM&role=user&isAdmin=true&is_admin=true&admin=true&verified=true&pmM=1"), "{r}");
        let signup = "POST /api/Users HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"email\":\"a@b.test\",\"password\":\"p\"}";
        let r = String::from_utf8(with_privileged_fields(signup, "M").unwrap()).unwrap();
        assert!(r.contains("\"email\":\"aM@b.test\"") && r.contains("\"password\":\"p\""), "{r}");
        let base = seen(201, r#"{"user":{"username":"u","role":"user"}}"#);
        assert_eq!(
            mass_assigned(&base, &seen(201, r#"{"user":{"username":"u","role":"admin"}}"#), "M"),
            ["role=admin"]
        );
        assert!(mass_assigned(&base, &base.clone(), "M").is_empty());
        let echo = seen(200, r#"{"prefs":{"role":"admin","pmM":"1"}}"#);
        assert!(mass_assigned(&base, &echo, "M").is_empty(), "an endpoint that keeps any field proves nothing");

        let p = proto_probes(json, "pmP");
        assert_eq!(p.len(), 2);
        assert!(String::from_utf8_lossy(&p[0].1).contains(r#""__proto__":{"pmpmP":"polluted"}"#));
        assert!(polluted(&seen(200, r#"{"theme":"dark","pmpmP":"polluted"}"#), "pmP"));
        assert!(!polluted(&seen(200, r#"{"__proto__":{"pmpmP":"polluted"}}"#), "pmP"), "an echo is not pollution");
        assert!(proto_probes(form, "pmP").is_empty());
    }

    #[test]
    fn smuggling_probes_disagree_on_framing() {
        let raw = "GET /legacy/status HTTP/1.1\r\nHost: x\r\nCookie: a=1\r\nContent-Length: 0\r\n\r\n";
        let p = smuggling_probes(raw).unwrap();
        let te_cl = String::from_utf8(p.te_cl).unwrap();
        assert!(te_cl.starts_with("POST /legacy/status HTTP/1.1\r\nHost: x\r\nCookie: a=1\r\n"), "{te_cl}");
        assert!(te_cl.contains("Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX"));
        assert_eq!(te_cl.matches("Content-Length").count(), 1);
        assert!(
            String::from_utf8(p.cl_te)
                .unwrap()
                .ends_with("Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n\r\n")
        );
        assert!(
            String::from_utf8(p.control)
                .unwrap()
                .ends_with("Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        );
        assert!(hung(&[20, 30], 6000) && !hung(&[20, 30], 900));
        assert!(smuggling_probes("GET / HTTP/2\r\nhost: x\r\n\r\n").is_none());
    }

    #[test]
    fn oauth_redirect_uri_tricks() {
        let raw = "GET /oauth/authorize?response_type=code&client_id=c&redirect_uri=http%3A%2F%2Fshop.test%2Fcb&state=s HTTP/1.1\r\nHost: x\r\n\r\n";
        let p = oauth_probes(raw, "Q");
        assert_eq!(p.len(), 3);
        let first = String::from_utf8_lossy(&p[0].1);
        assert!(first.contains("redirect_uri=https%3A%2F%2FpmQ.example%2Fcallback&state=s"), "{first}");
        assert!(String::from_utf8_lossy(&p[2].1).contains("shop.test%40pmQ.example"));
        let to = |l: &str| Seen { status: Some(302), location: Some(l.into()), ..Default::default() };
        assert!(oauth_leaks(&to("https://pmQ.example/callback?code=1"), "Q"));
        assert!(oauth_leaks(&to("https://shop.test.pmQ.example/callback?code=1"), "Q"));
        assert!(!oauth_leaks(&to("http://shop.test/cb?error=bad_redirect&x=pmQ.example"), "Q"));
        assert!(!oauth_without_state(raw, &to("http://shop.test/cb?code=1")));
        assert!(oauth_without_state(&raw.replace("&state=s", ""), &to("http://shop.test/cb?code=1")));
        assert!(oauth_probes("GET /x?a=1 HTTP/1.1\r\nHost: x\r\n\r\n", "Q").is_empty());
        let no_state = String::from_utf8(without_query_param(raw, "state").unwrap()).unwrap();
        assert!(no_state.starts_with(
            "GET /oauth/authorize?response_type=code&client_id=c&redirect_uri=http%3A%2F%2Fshop.test%2Fcb HTTP/1.1"
        ));
        assert!(without_query_param(&no_state, "state").is_none());
    }

    #[test]
    fn serialized_values_are_recognised_and_corrupted() {
        let php = r#"a:1:{s:4:"item";s:6:"Coffee";}"#;
        assert_eq!(deser_probe(php).unwrap(), ("PHP", r#"a:1:{s:11:"item";s:6:"Coffee";}"#.to_string()));
        let (kind, c) = deser_probe(&b64_std(php.as_bytes())).unwrap();
        assert_eq!(kind, "PHP");
        assert_eq!(String::from_utf8(b64url_decode(&c).unwrap()).unwrap(), r#"a:1:{s:11:"item";s:6:"Coffee";}"#);
        let java = b64_std(&[0xAC, 0xED, 0x00, 0x05, 0x73, 0x72, 0x00, 0x04, 0x55, 0x73, 0x65, 0x72]);
        assert_eq!(deser_probe(&java).unwrap().0, "Java");
        assert_eq!(deser_probe(&b64_std(&[0x80, 0x04, 0x95, 0x10, 0, 0, 0, 0, 0])).unwrap().0, "Python pickle");
        for plain in ["coffee", "12345678", "aGVsbG8gd29ybGQ=", "a:b"] {
            assert!(deser_probe(plain).is_none(), "{plain}");
        }
        let base = Seen { status: Some(200), body: "ok".into(), ..Default::default() };
        let err = Seen {
            status: Some(500),
            body: "unserialize(): Error at offset 9 of 30 bytes".into(),
            ..Default::default()
        };
        assert_eq!(deser_error(&base, &err), Some("unserialize()"));
        assert_eq!(deser_error(&err, &err.clone()), None);
    }

    #[test]
    fn upload_probes_and_locations() {
        let raw = "POST /api/avatar HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=XyZ\r\n\r\n\
                   --XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhi\r\n\
                   --XyZ\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"me.png\"\r\nContent-Type: image/png\r\n\r\nPNGDATA\r\n\
                   --XyZ--\r\n";
        let p = upload_probes(raw, "U");
        assert_eq!(p.iter().map(|x| x.0).collect::<Vec<_>>(), [UploadKind::Html, UploadKind::Svg, UploadKind::Php]);
        let html = String::from_utf8(p[0].1.clone()).unwrap();
        assert!(html.contains("name=\"note\"\r\n\r\nhi\r\n--XyZ\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"pmU.html\"\r\nContent-Type: text/html\r\n\r\n<html>"), "{html}");
        assert!(html.ends_with("</html>\r\n--XyZ--\r\n") && !html.contains("PNGDATA"));
        assert_eq!(
            upload_locations(r#"{"url":"http://x/uploads/pmU.html","path":"/media/pmU.html"}"#, "pmU.html"),
            ["/uploads/pmU.html", "/media/pmU.html", "/files/pmU.html", "/static/uploads/pmU.html"]
        );
        let served = |ct: &str, body: &str| Seen {
            status: Some(200),
            content_type: Some(ct.into()),
            body: body.into(),
            ..Default::default()
        };
        assert!(UploadKind::Html.verdict(&served("text/html", "<html><body><pmx-U>pmU</pmx-U>"), "U"));
        assert!(!UploadKind::Html.verdict(&served("text/plain", "<html><body><pmx-U>pmU</pmx-U>"), "U"));
        assert!(UploadKind::Php.verdict(&served("text/html", "pmUrun"), "U"));
        assert!(!UploadKind::Php.verdict(&served("image/png", "<?php echo 'pm' . 'U' . 'run'; ?>"), "U"));
        assert!(
            upload_probes("POST /x HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{}", "U").is_empty()
        );
    }

    #[test]
    fn login_enumeration_probes_and_verdict() {
        let login = "POST /users/v1/login HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"username\":\"name1\",\"password\":\"pass1\"}";
        let p = enum_probes(login, "K").unwrap();
        let w = String::from_utf8_lossy(&p.wrong_password).to_string();
        let u = String::from_utf8_lossy(&p.unknown_user).to_string();
        assert!(w.contains("\"username\":\"name1\"") && w.contains("PmK-Wrong-1") && !w.contains("pass1"), "{w}");
        assert!(u.contains("\"username\":\"pmKnouser\""), "{u}");
        let wrong = seen(401, r#"{"message":"Password is not correct for the given username."}"#);
        let unknown = seen(401, r#"{"message":"Username does not exist"}"#);
        assert!(enumerates(&p, &wrong, &wrong.clone(), &unknown).is_some());
        // Same message for both: nothing given away (the echoed name doesn't count).
        let a = seen(401, r#"{"error":"Invalid login for name1"}"#);
        let b = seen(401, r#"{"error":"Invalid login for pmKnouser"}"#);
        assert!(enumerates(&p, &a, &a.clone(), &b).is_none());
        // Noisy pages (the same wrong password answers differently) prove nothing.
        assert!(enumerates(&p, &wrong, &seen(401, "{\"t\":2}"), &unknown).is_none());
        let form = "POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nemail=a%40b.test&password=x";
        let f = enum_probes(form, "K").unwrap();
        assert!(String::from_utf8_lossy(&f.unknown_user).contains("email=pmK%40example.invalid"));
        assert_eq!(f.user, "a@b.test");
        assert!(enum_probes("POST /x HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"q\":1}", "K").is_none());
    }

    #[test]
    fn password_change_without_current() {
        let get = "GET /rest/user/change-password?current=old&new=n1&repeat=n1 HTTP/1.1\r\nHost: x\r\n\r\n";
        let (r, f) = without_current_password(get).unwrap();
        assert_eq!(f, "current");
        assert!(String::from_utf8_lossy(&r).starts_with("GET /rest/user/change-password?new=n1&repeat=n1 HTTP/1.1"));
        let json = "PUT /me/password HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"oldPassword\":\"a\",\"newPassword\":\"b\"}";
        let (r, f) = without_current_password(json).unwrap();
        assert_eq!(f, "oldPassword");
        assert!(!String::from_utf8_lossy(&r).contains("oldPassword"));
        assert!(without_current_password("GET /search?current=1 HTTP/1.1\r\n\r\n").is_none(), "not a password change");
    }

    #[test]
    fn exposure_helpers() {
        let debug = r#"{"users":[{"username":"name1","password":"pass1","admin":false}]}"#;
        assert_eq!(credential_keys(debug), vec!["password"]);
        assert!(credential_keys(r#"{"users":[{"username":"name1","password":""}]}"#).is_empty());
        let listing = r#"<a href="/ftp/quarantine">quarantine</a><a href="/ftp/legal.md">legal.md</a>
            <a href="/ftp/incident-support.kdbx">x</a><a href="https://other/x.md">y</a><a href="/ftp/eastere.gg">z</a>"#;
        assert_eq!(sensitive_listed_files(listing), vec!["/ftp/incident-support.kdbx", "/ftp/legal.md"]);
        assert_eq!(emails("a: Bob@Shop.test, b: x@y").into_iter().collect::<Vec<_>>(), vec!["bob@shop.test"]);
    }
}
