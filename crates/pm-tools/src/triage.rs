//! Traffic triage: what in a recorded exchange is worth testing, and how.
//! Cheap heuristics over the request and response (no model, no I/O), so a
//! person or an agent can start from the promising requests instead of the
//! whole history.

use serde::Serialize;

use crate::codec::base64_decode;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hint {
    /// idor, ssrf, traversal, command, injection, xss, jwt, upload, graphql, unauthenticated, admin, error, debug
    pub kind: &'static str,
    /// What was seen.
    pub why: String,
    /// What to try, with ProxyMind's tools.
    pub suggest: &'static str,
    /// 1 (worth a look) to 5 (test first).
    pub weight: u8,
}

/// The parts of an exchange triage looks at.
pub struct Exchange<'a> {
    pub method: &'a str,
    /// Path with query.
    pub path: &'a str,
    /// The raw request (head and body).
    pub request: &'a [u8],
    pub status: Option<u16>,
    pub content_type: &'a str,
    /// The decoded response body.
    pub body: &'a [u8],
}

const PARAM_RULES: &[(&str, &[&str], &str, u8)] = &[
    (
        "ssrf",
        &[
            "url",
            "uri",
            "link",
            "src",
            "dest",
            "destination",
            "redirect",
            "redirecturi",
            "redirecturl",
            "return",
            "returnto",
            "returnurl",
            "next",
            "callback",
            "webhook",
            "feed",
            "imageurl",
            "imgurl",
            "proxy",
            "target",
            "continue",
        ],
        "scan_active with ssrf_oob and open_redirect (Collaborator shows server-side fetches)",
        4,
    ),
    (
        "traversal",
        &[
            "file",
            "filename",
            "path",
            "filepath",
            "template",
            "page",
            "include",
            "doc",
            "document",
            "folder",
            "dir",
            "download",
            "view",
            "lang",
            "locale",
            "attachment",
        ],
        "scan_active with path_traversal; try ../ sequences and absolute paths",
        4,
    ),
    (
        "command",
        &["cmd", "exec", "command", "run", "ping", "ip", "hostname", "daemon", "process", "shell"],
        "scan_active with cmd_injection, cmd_time and cmd_oob",
        4,
    ),
    (
        "injection",
        &[
            "q", "search", "query", "filter", "sort", "order", "orderby", "sortby", "where", "column", "field",
            "keyword",
        ],
        "scan_active (SQL/NoSQL checks: sql_error, sql_boolean, sql_time, nosql_operator)",
        2,
    ),
    (
        "debug",
        &["debug", "test", "verbose", "trace", "admin", "internal", "dev"],
        "try true/1 and compare responses",
        2,
    ),
];

fn norm(name: &str) -> String {
    name.to_ascii_lowercase().chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

fn split(raw: &[u8]) -> (String, &[u8]) {
    match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => (String::from_utf8_lossy(&raw[..i]).into_owned(), &raw[i + 4..]),
        None => (String::from_utf8_lossy(raw).into_owned(), &[]),
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Parameters (name, value) from the query, a form body or a JSON body's top level.
fn params(path: &str, head: &str, body: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut form = |s: &str| {
        for pair in s.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            out.push((k.to_string(), v.to_string()));
        }
    };
    if let Some((_, q)) = path.split_once('?') {
        form(q);
    }
    let ct = header(head, "content-type").unwrap_or("").to_ascii_lowercase();
    if ct.contains("x-www-form-urlencoded") {
        form(&String::from_utf8_lossy(body));
    } else if ct.contains("json")
        && let Ok(serde_json::Value::Object(o)) = serde_json::from_slice::<serde_json::Value>(body)
    {
        for (k, v) in o {
            let v = match v {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            out.push((k, v));
        }
    }
    out
}

/// Ids in the path: numeric segments and UUIDs.
fn path_ids(path: &str) -> (usize, usize) {
    let p = path.split(['?', '#']).next().unwrap_or("");
    let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    let numeric = segs.iter().filter(|s| s.len() <= 12 && s.bytes().all(|b| b.is_ascii_digit())).count();
    let uuid = segs
        .iter()
        .filter(|s| {
            s.len() == 36
                && s.bytes()
                    .enumerate()
                    .all(|(i, b)| if [8, 13, 18, 23].contains(&i) { b == b'-' } else { b.is_ascii_hexdigit() })
        })
        .count();
    (numeric, uuid)
}

/// JWTs in the Authorization header or cookies, with their header JSON.
fn jwts(head: &str) -> Vec<serde_json::Value> {
    let mut found = Vec::new();
    let sources = [header(head, "authorization").unwrap_or(""), header(head, "cookie").unwrap_or("")];
    for src in sources {
        for word in src.split([' ', ';', '=', ',']) {
            let parts: Vec<&str> = word.trim().split('.').collect();
            if parts.len() == 3
                && parts[0].starts_with("eyJ")
                && parts[1].starts_with("eyJ")
                && let Ok(h) = base64_decode(parts[0], true)
                && let Ok(v) = serde_json::from_slice::<serde_json::Value>(&h)
            {
                found.push(v);
            }
        }
    }
    found
}

const ERRORS: &[&str] = &[
    "Traceback (most recent call last)",
    "SQLSTATE[",
    "ORA-0",
    "Exception in thread",
    "at java.",
    "System.NullReferenceException",
    "Fatal error:</b>",
    "You have an error in your SQL syntax",
    "Microsoft OLE DB",
    "Stack trace:",
];

/// What in `x` is worth testing, most promising first.
pub fn hints(x: &Exchange<'_>) -> Vec<Hint> {
    let (head, req_body) = split(x.request);
    let mut out: Vec<Hint> = Vec::new();
    let json = x.content_type.contains("json");
    let path_only = x.path.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();

    let (numeric, uuid) = path_ids(x.path);
    if numeric > 0 && (json || x.content_type.contains("html")) && x.status.is_some_and(|s| s < 400) {
        out.push(Hint {
            kind: "idor",
            why: "numeric object id in the path".into(),
            suggest: "authz_check with another identity, and nearby ids with replay_send (IDOR/BOLA)",
            weight: 4,
        });
    } else if uuid > 0 && x.status.is_some_and(|s| s < 400) {
        out.push(Hint {
            kind: "idor",
            why: "UUID in the path (hard to guess, but check whether other users' ids leak elsewhere)".into(),
            suggest: "authz_check with another identity",
            weight: 2,
        });
    }

    let ps = params(x.path, &head, req_body);
    for (kind, names, suggest, weight) in PARAM_RULES {
        let hit: Vec<&str> =
            ps.iter().filter(|(k, _)| names.contains(&norm(k).as_str())).map(|(k, _)| k.as_str()).collect();
        if !hit.is_empty() {
            out.push(Hint { kind, why: format!("parameter {}", hit.join(", ")), suggest, weight: *weight });
        }
    }
    let url_value = ps.iter().find(|(k, v)| {
        let v = v.to_ascii_lowercase();
        (v.starts_with("http%3a") || v.starts_with("http://") || v.starts_with("https"))
            && !out.iter().any(|h| h.why.contains(k.as_str()))
    });
    if let Some((k, _)) = url_value {
        out.push(Hint {
            kind: "ssrf",
            why: format!("parameter {k} carries a URL"),
            suggest: "scan_active with ssrf_oob and open_redirect",
            weight: 4,
        });
    }

    if x.content_type.contains("html") {
        let body = String::from_utf8_lossy(x.body);
        let reflected: Vec<&str> = ps
            .iter()
            .filter(|(_, v)| v.len() >= 4 && v.bytes().any(|b| b.is_ascii_alphabetic()) && body.contains(v.as_str()))
            .map(|(k, _)| k.as_str())
            .collect();
        if !reflected.is_empty() {
            out.push(Hint {
                kind: "xss",
                why: format!("value of {} appears in the HTML response", reflected.join(", ")),
                suggest: "scan_active with reflected_input and dom_xss; proof_run with the reflection oracle",
                weight: 3,
            });
        }
    }

    for h in jwts(&head) {
        let alg = h["alg"].as_str().unwrap_or("").to_ascii_lowercase();
        if alg == "none" {
            out.push(Hint {
                kind: "jwt",
                why: "JWT with alg none".into(),
                suggest: "scan_active with jwt: a token the server should reject",
                weight: 5,
            });
        } else if alg.starts_with("hs") {
            out.push(Hint {
                kind: "jwt",
                why: format!("JWT signed with {} (a shared secret)", alg.to_uppercase()),
                suggest: "scan_active with jwt (alg confusion, weak secrets, unverified signatures)",
                weight: 3,
            });
        } else if !alg.is_empty() {
            out.push(Hint { kind: "jwt", why: format!("JWT ({alg})"), suggest: "scan_active with jwt", weight: 2 });
        }
        for k in ["kid", "jku", "x5u"] {
            if h.get(k).is_some() {
                out.push(Hint {
                    kind: "jwt",
                    why: format!("JWT header has {k}"),
                    suggest: "scan_active with jwt: header injection (kid path traversal, jku/x5u pointing elsewhere)",
                    weight: 3,
                });
            }
        }
    }

    let ct = header(&head, "content-type").unwrap_or("").to_ascii_lowercase();
    if ct.contains("multipart/form-data") && String::from_utf8_lossy(req_body).contains("filename=") {
        out.push(Hint {
            kind: "upload",
            why: "file upload".into(),
            suggest: "scan_active with file_upload (needs approval); follow the file_upload skill",
            weight: 4,
        });
    }
    if path_only.contains("graphql") {
        out.push(Hint {
            kind: "graphql",
            why: "GraphQL endpoint".into(),
            suggest: "graphql_import, then authz checks per field and scan_active with graphql checks",
            weight: 3,
        });
    }
    let authed = header(&head, "authorization").is_some() || header(&head, "cookie").is_some();
    if !authed && json && x.status == Some(200) && path_only.contains("/api") {
        out.push(Hint {
            kind: "unauthenticated",
            why: "API answered with JSON without any credentials".into(),
            suggest: "check whether the data should be public (excessive data exposure)",
            weight: 2,
        });
    }
    if ["/admin", "/debug", "/internal", "/actuator", "/console", "/manage"].iter().any(|p| path_only.contains(p)) {
        out.push(Hint {
            kind: "admin",
            why: "administrative or debug path".into(),
            suggest: "authz_check as a normal user and anonymously; scan_active with auth_bypass",
            weight: 3,
        });
    }
    let body = String::from_utf8_lossy(&x.body[..x.body.len().min(200_000)]);
    if let Some(e) = ERRORS.iter().find(|e| body.contains(*e)) {
        out.push(Hint {
            kind: "error",
            why: format!("error details in the response ({})", e.trim_end_matches(['[', ':'])),
            suggest: "scan_issues; the input that caused it is a strong injection candidate",
            weight: 3,
        });
    }
    out.sort_by_key(|h| std::cmp::Reverse(h.weight));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex<'a>(method: &'a str, path: &'a str, request: &'a [u8], ct: &'a str, body: &'a [u8]) -> Exchange<'a> {
        Exchange { method, path, request, status: Some(200), content_type: ct, body }
    }

    fn kinds(h: &[Hint]) -> Vec<&str> {
        h.iter().map(|h| h.kind).collect()
    }

    #[test]
    fn finds_what_is_worth_testing() {
        // {"alg":"none","typ":"JWT"} . {"sub":"1"} .
        let req = b"GET /api/orders/1001?redirect=https://x.test/&q=shoes HTTP/1.1\r\nHost: s\r\nAuthorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.\r\n\r\n";
        let h = hints(&ex("GET", "/api/orders/1001?redirect=https://x.test/&q=shoes", req, "application/json", b"{}"));
        assert_eq!(h[0].kind, "jwt", "{h:?}");
        assert_eq!(h[0].weight, 5);
        for k in ["idor", "ssrf", "injection"] {
            assert!(kinds(&h).contains(&k), "{k} in {h:?}");
        }
    }

    #[test]
    fn reflection_uploads_errors_and_anonymous_apis() {
        let req = b"GET /search?term=zebra42 HTTP/1.1\r\nHost: s\r\n\r\n";
        let h = hints(&ex("GET", "/search?term=zebra42", req, "text/html", b"<p>No results for zebra42</p>"));
        assert_eq!(kinds(&h), ["xss"]);

        let up = b"POST /profile/avatar HTTP/1.1\r\nHost: s\r\nCookie: s=1\r\nContent-Type: multipart/form-data; boundary=b\r\n\r\n--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.png\"\r\n\r\nx\r\n--b--";
        assert_eq!(kinds(&hints(&ex("POST", "/profile/avatar", up, "text/html", b"ok"))), ["upload"]);

        let api = b"GET /api/users HTTP/1.1\r\nHost: s\r\n\r\n";
        let body = b"Traceback (most recent call last):\n  File x";
        let h = hints(&ex("GET", "/api/users", api, "application/json", body));
        assert_eq!(kinds(&h), ["error", "unauthenticated"]);

        let boring = b"GET /about HTTP/1.1\r\nHost: s\r\nCookie: s=1\r\n\r\n";
        assert!(hints(&ex("GET", "/about", boring, "text/html", b"<h1>About</h1>")).is_empty());
    }

    #[test]
    fn json_bodies_and_jwt_headers() {
        let req = b"POST /api/fetch HTTP/1.1\r\nHost: s\r\nContent-Type: application/json\r\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uL2tleSJ9.eyJzdWIiOiIxIn0.c2ln\r\n\r\n{\"webhook\":\"http://a.test/\",\"template\":\"x\"}";
        let h = hints(&ex("POST", "/api/fetch", req, "application/json", b"{}"));
        let k = kinds(&h);
        for want in ["ssrf", "traversal", "jwt"] {
            assert!(k.contains(&want), "{want} in {h:?}");
        }
        assert!(h.iter().any(|x| x.why.contains("kid")), "{h:?}");
    }
}
