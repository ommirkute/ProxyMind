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
        for (k, val) in PRIVILEGED_FIELDS {
            if !o.contains_key(*k) {
                let x = if *val == "true" { Value::Bool(true) } else { Value::String((*val).into()) };
                o.insert((*k).to_string(), x);
            }
        }
        o.insert(control, Value::String("1".into()));
        Some(rebuild(&p, p.target, &v.to_string()))
    } else if p.form {
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
        assert!(r.contains("\"role\":\"admin\"") && r.contains("\"isAdmin\":true") && r.contains("\"username\":\"u\""));
        assert!(r.contains("\"pmM\":\"1\""));
        let form = "POST /r HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=u&role=user";
        let r = String::from_utf8(with_privileged_fields(form, "M").unwrap()).unwrap();
        assert!(r.ends_with("username=u&role=user&isAdmin=true&is_admin=true&admin=true&verified=true&pmM=1"), "{r}");
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
}
