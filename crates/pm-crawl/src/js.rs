//! Endpoints mentioned in JavaScript: string literals that look like URL
//! paths (`"/api/orders"`, `` `/rest/track-order/${id}` ``, `'https://…'`),
//! with query parameter names and a method when the call site shows one
//! (`.post("/api/x")`, `method: "PUT"`). Front-end bundles list most of an
//! app's API routes, including ones no page links to.
//!
//! The script is the target's and untrusted: this is a small tolerant
//! scanner over quoted strings. It never runs anything and never panics.

use serde::Serialize;

/// Most endpoints read from one script.
pub const MAX_ENDPOINTS: usize = 2000;
/// Longest string literal considered.
const MAX_LITERAL: usize = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct JsEndpoint {
    /// A path (`/api/orders/{id}`) or an absolute URL. `{param}` marks a
    /// value the script fills in.
    pub path: String,
    /// Query parameter names seen with it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    /// GET, POST, PUT, PATCH or DELETE, when the call site says.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'static str>,
    /// Another script (`/main.js`), worth reading in turn.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub script: bool,
}

/// Files that are never API endpoints.
const STATIC: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp", ".css", ".scss", ".less", ".woff",
    ".woff2", ".ttf", ".otf", ".eot", ".map", ".mp4", ".webm", ".mp3", ".wav", ".pdf",
];
/// Hosts of namespaces and specs that show up in every bundle.
const NOISE_HOSTS: &[&str] = &["www.w3.org", "w3.org", "schemas.", "xmlns.", "reactjs.org", "angular.io", "github.com"];

/// Reads the endpoints out of a script (or the inline scripts of a page).
pub fn js_endpoints(script: &str) -> Vec<JsEndpoint> {
    let b = script.as_bytes();
    let mut out: Vec<JsEndpoint> = Vec::new();
    let mut i = 0;
    while i < b.len() && out.len() < MAX_ENDPOINTS {
        let q = b[i];
        if q != b'"' && q != b'\'' && q != b'`' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut j = start;
        let mut closed = false;
        while j < b.len() && j - start <= MAX_LITERAL {
            match b[j] {
                b'\\' => j += 2,
                b'\n' if q != b'`' => break,
                c if c == q => {
                    closed = true;
                    break;
                }
                _ => j += 1,
            }
        }
        if !closed || j > b.len() {
            // Not a string (an apostrophe in a comment, say): move on by one byte.
            i += 1;
            continue;
        }
        let literal = &script[start..j];
        if let Some(mut e) = candidate(literal, q == b'`') {
            e.method = method_hint(&script[..i], &script[j + 1..]);
            merge(&mut out, e);
        }
        i = j + 1;
    }
    out
}

fn merge(out: &mut Vec<JsEndpoint>, e: JsEndpoint) {
    match out.iter_mut().find(|o| o.path == e.path && o.method == e.method) {
        Some(o) => {
            for p in e.params {
                if !o.params.contains(&p) {
                    o.params.push(p);
                }
            }
        }
        None => out.push(e),
    }
}

/// The endpoint a literal names, if it looks like one.
fn candidate(literal: &str, template: bool) -> Option<JsEndpoint> {
    let s = literal.trim();
    // `${expr}` in a template literal is a value the script fills in.
    let s = if template { fill_template(s)? } else { s.to_string() };
    if s.len() < 2 || s.len() > 200 || !s.bytes().any(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let url_char = |c: char| c.is_ascii_alphanumeric() || "-._~:/?#[]@!$&()*+,;=%{}".contains(c);
    if !s.chars().all(url_char) {
        return None;
    }
    let absolute = s.starts_with("http://") || s.starts_with("https://");
    let rooted = s.starts_with('/') && !s.starts_with("//");
    let relative_api = ["api/", "rest/", "graphql", "v1/", "v2/", "v3/"].iter().any(|p| s.starts_with(p));
    if !(absolute || rooted || relative_api) {
        return None;
    }
    if absolute {
        let host = s.split("://").nth(1).unwrap_or_default().split(['/', '?', '#']).next().unwrap_or_default();
        if host.is_empty() || NOISE_HOSTS.iter().any(|n| host.starts_with(n) || host == n.trim_end_matches('.')) {
            return None;
        }
    }
    let s = s.split('#').next().unwrap_or_default();
    let (path, query) = match s.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (s, None),
    };
    let path = if relative_api { format!("/{path}") } else { path.to_string() };
    // Paths of one character (`/`), wildcards and things like `/*/` are not endpoints.
    let tail = path.split("://").last().unwrap_or_default();
    if tail.trim_matches('/').is_empty() || path.contains('*') || path.contains("..") {
        return None;
    }
    let lower = path.to_ascii_lowercase();
    if STATIC.iter().any(|e| lower.ends_with(e)) {
        return None;
    }
    let script = lower.ends_with(".js") || lower.ends_with(".mjs");
    let params = query
        .map(|q| {
            q.split('&')
                .filter_map(|kv| {
                    let k = kv.split('=').next().unwrap_or_default();
                    (!k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || "_-.[]".contains(c)))
                        .then(|| k.to_string())
                })
                .collect()
        })
        .unwrap_or_default();
    Some(JsEndpoint { path, params, method: None, script })
}

/// `/rest/track-order/${id}` → `/rest/track-order/{id}`; `None` when the
/// template is mostly expressions (`${base}${path}`).
fn fill_template(s: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(at) = rest.find("${") {
        out.push_str(&rest[..at]);
        let end = rest[at..].find('}')? + at;
        let expr = &rest[at + 2..end];
        let name: String = expr
            .rsplit(['.', ' ', '(', '['])
            .next()
            .unwrap_or_default()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        out.push('{');
        out.push_str(if name.is_empty() { "param" } else { &name });
        out.push('}');
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    // A template that starts with an expression has no fixed path to go on.
    if out.starts_with('{') { None } else { Some(out) }
}

/// The method the call site shows: `.post(` just before the literal, or a
/// `method: "PUT"` option just after it.
fn method_hint(before: &str, after: &str) -> Option<&'static str> {
    const METHODS: [(&str, &str); 5] =
        [("get", "GET"), ("post", "POST"), ("put", "PUT"), ("patch", "PATCH"), ("delete", "DELETE")];
    let tail: String = before.chars().rev().take(24).collect::<Vec<_>>().into_iter().rev().collect();
    let tail = tail.to_ascii_lowercase();
    let tail = tail.trim_end_matches([' ', '(']);
    for (word, m) in METHODS {
        if tail.ends_with(&format!(".{word}")) {
            return Some(m);
        }
    }
    let head: String = after.chars().take(120).collect::<String>().to_ascii_lowercase();
    if let Some(at) = head.find("method") {
        let v = head[at + 6..].trim_start_matches([' ', ':', '=', '"', '\'']);
        for (word, m) in METHODS {
            if v.starts_with(word) {
                return Some(m);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(js: &str) -> Vec<String> {
        js_endpoints(js).into_iter().map(|e| e.path).collect()
    }

    #[test]
    fn finds_paths_urls_and_templates() {
        let js = r#"
            const a = "/api/Products";  fetch('/rest/user/whoami');
            this.http.get(`/rest/track-order/${encodeURIComponent(id)}`);
            const u = "https://api.shop.test/v2/orders?status=open&page=1";
            axios.post("api/feedback", data); // don't break on this apostrophe
            const logo = "/assets/logo.png"; const ns = "http://www.w3.org/2000/svg";
            const t = "text/html"; const d = "MM/dd/yyyy"; const root = "/"; const glob = "/*";
            import("/chunks/main.js");
        "#;
        assert_eq!(
            paths(js),
            [
                "/api/Products",
                "/rest/user/whoami",
                "/rest/track-order/{id}",
                "https://api.shop.test/v2/orders",
                "/api/feedback",
                "/chunks/main.js"
            ]
        );
        let all = js_endpoints(js);
        assert_eq!(all[2].method, Some("GET"));
        assert_eq!(all[3].params, ["status", "page"]);
        assert_eq!(all[4].method, Some("POST"));
        assert!(all[5].script);
    }

    #[test]
    fn method_options_and_merging() {
        let js =
            r#"fetch("/api/orders", { method: "DELETE" }); fetch("/api/orders?id=1"); fetch("/api/orders?sort=a")"#;
        let e = js_endpoints(js);
        assert_eq!(e.len(), 2);
        assert_eq!(e[0].method, Some("DELETE"));
        assert_eq!(e[1].params, ["id", "sort"]);
        // A template that is all expressions names no endpoint.
        assert!(js_endpoints("x = `${base}${path}`;").is_empty());
    }

    #[test]
    fn hostile_input_does_not_panic() {
        for s in ["\"", "'\\", "`${", "`/a/${", "\"/a\\\"", "'/é'", "\"/\u{1F600}\"", &"\"/a".repeat(10_000)] {
            let _ = js_endpoints(s);
        }
    }
}
