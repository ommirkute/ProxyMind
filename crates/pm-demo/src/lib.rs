//! VulnShop: a small, deliberately vulnerable shop API for demos, tests and
//! benchmarks. **It is insecure on purpose. Bind it to 127.0.0.1 only.**
//!
//! Users: `alice/alice123`, `bob/bob123` (role user), `admin/admin123` (admin).
//! Log in with `POST /api/login` (JSON or form: username, password); use the
//! `session` cookie or `Authorization: Bearer <token>`.
//!
//! The planted vulnerabilities are listed in [`GROUND_TRUTH`]. Some endpoints
//! are deliberately *secure* so tools can be scored on false positives too.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A planted vulnerability, for scoring tools against this app.
#[derive(Debug, Clone, Copy)]
pub struct Vuln {
    pub id: &'static str,
    pub class: &'static str,
    pub method: &'static str,
    /// Path with `{id}` for the object id.
    pub path: &'static str,
    pub description: &'static str,
}

pub const GROUND_TRUTH: &[Vuln] = &[
    Vuln {
        id: "VS-1",
        class: "idor",
        method: "GET",
        path: "/api/orders/{id}",
        description: "Any logged-in user can read any order (no ownership check).",
    },
    Vuln {
        id: "VS-2",
        class: "broken_function_level_authz",
        method: "GET",
        path: "/api/admin/users",
        description: "Admin user list only checks that you are logged in, not that you are an admin.",
    },
    Vuln {
        id: "VS-3",
        class: "sqli_blind",
        method: "GET",
        path: "/api/products/search",
        description: "The q parameter is concatenated into a real SQLite query; errors are hidden, but true/false \
                      conditions change the results and SLEEP(n) delays the response (blind SQL injection).",
    },
    Vuln {
        id: "VS-4",
        class: "ssrf",
        method: "GET",
        path: "/api/fetch",
        description: "The url parameter is fetched server-side without any allow-list.",
    },
    Vuln {
        id: "VS-5",
        class: "race_condition",
        method: "POST",
        path: "/api/giftcard/redeem",
        description: "A one-per-user gift card is checked, then credited after a pause, without a lock: \
                      requests sent together are all credited.",
    },
    Vuln {
        id: "VS-6",
        class: "xss_reflected",
        method: "GET",
        path: "/search",
        description: "The q parameter is written into the HTML results page without encoding (reflected XSS).",
    },
    Vuln {
        id: "VS-7",
        class: "sqli_error_based",
        method: "GET",
        path: "/api/reviews",
        description: "A quote in product breaks the SQL query and the database error is returned.",
    },
    Vuln {
        id: "VS-8",
        class: "open_redirect",
        method: "GET",
        path: "/go",
        description: "Redirects to any url, including other sites.",
    },
    Vuln {
        id: "VS-9",
        class: "path_traversal",
        method: "GET",
        path: "/download",
        description: "file is joined to the downloads folder without normalising, so ../ reaches /etc/passwd.",
    },
    Vuln {
        id: "VS-10",
        class: "ssti",
        method: "GET",
        path: "/greet",
        description: "name is rendered as a template: {{7*191}} becomes 1337.",
    },
    Vuln {
        id: "VS-11",
        class: "weak_token",
        method: "POST",
        path: "/api/password/reset",
        description: "Password-reset codes are a counter: each one is the previous plus one.",
    },
    Vuln {
        id: "VS-12",
        class: "idor",
        method: "POST",
        path: "/graphql",
        description: "The GraphQL invoice(id) resolver returns any user's invoice; the REST endpoint checks ownership.",
    },
    Vuln {
        id: "VS-13",
        class: "exposure",
        method: "GET",
        path: "/.git/config",
        description: "The git metadata folder is served; its config holds a deploy token in the remote URL.",
    },
    Vuln {
        id: "VS-14",
        class: "command_injection",
        method: "GET",
        path: "/api/tools/ping",
        description: "The host parameter is put into a shell command line (simulated shell: echo, sleep and \
                      $((a*b)) are emulated, nothing is executed).",
    },
    Vuln {
        id: "VS-15",
        class: "sqli_blind",
        method: "GET",
        path: "/api/products",
        description: "The User-Agent header is looked up in a visit log with string concatenation (time-based \
                      blind SQL injection in a header).",
    },
    Vuln {
        id: "VS-16",
        class: "xxe",
        method: "POST",
        path: "/api/import",
        description: "Product imports are XML; the parser resolves external entities and fetches their http:// URLs \
                      (blind XXE, seen out of band).",
    },
    Vuln {
        id: "VS-17",
        class: "auth_bypass",
        method: "GET",
        path: "/api/internal/config",
        description: "Internal-only config is denied (403) unless X-Forwarded-For says 127.0.0.1, which any client \
                      can send.",
    },
    Vuln {
        id: "VS-18",
        class: "crlf",
        method: "GET",
        path: "/api/lang",
        description: "The set parameter goes into a Set-Cookie header undecoded-safe: CR LF adds headers.",
    },
    Vuln {
        id: "VS-19",
        class: "host_header_injection",
        method: "GET",
        path: "/api/share",
        description: "Share links are built from the Host header, so a forged Host poisons them.",
    },
    Vuln {
        id: "VS-20",
        class: "cors",
        method: "GET",
        path: "/api/me",
        description: "Any Origin is echoed back with Access-Control-Allow-Credentials: true.",
    },
    Vuln {
        id: "VS-21",
        class: "nosqli",
        method: "POST",
        path: "/api/v2/login",
        description: "A MongoDB-style login: {\"$ne\": …} as the password logs in as anyone.",
    },
    Vuln {
        id: "VS-22",
        class: "exposure",
        method: "GET",
        path: "/api/products",
        description: "A hidden debug parameter adds internal settings (with a database password) to the product list.",
    },
    Vuln {
        id: "VS-23",
        class: "stored_xss",
        method: "POST",
        path: "/api/guestbook",
        description: "Guestbook messages are stored and shown on /guestbook without encoding (the name is encoded).",
    },
    Vuln {
        id: "VS-24",
        class: "csrf",
        method: "POST",
        path: "/api/profile",
        description: "Changing the profile email needs only the session cookie: no CSRF token, no Origin check.",
    },
    Vuln {
        id: "VS-25",
        class: "dom_xss",
        method: "GET",
        path: "/welcome",
        description: "welcome.js writes the name URL parameter into the page with innerHTML.",
    },
    Vuln {
        id: "VS-26",
        class: "sqli",
        method: "GET",
        path: "/api/recommend",
        description: "ctx is base64 of a JSON object; its category goes into SQL unescaped (error-based).",
    },
    Vuln {
        id: "VS-27",
        class: "jwt",
        method: "GET",
        path: "/api/v3/profile",
        description: "Login JWTs are signed with the secret \"secret\", and alg: none tokens are accepted.",
    },
    Vuln {
        id: "VS-28",
        class: "graphql",
        method: "POST",
        path: "/graphql",
        description: "Introspection is on and batched operations are run (one request, many guesses).",
    },
    Vuln {
        id: "VS-29",
        class: "cache_poisoning",
        method: "GET",
        path: "/api/banner",
        description: "The banner's script URL comes from X-Forwarded-Host, which the cache doesn't key on.",
    },
    Vuln {
        id: "VS-30",
        class: "cache_deception",
        method: "GET",
        path: "/api/account/settings",
        description: "Any suffix after /settings is ignored, and the cache stores everything ending in .css.",
    },
    Vuln {
        id: "VS-31",
        class: "mass_assignment",
        method: "POST",
        path: "/api/register",
        description: "Registration takes a role field from the request (role=admin works).",
    },
    Vuln {
        id: "VS-32",
        class: "prototype_pollution",
        method: "POST",
        path: "/api/preferences",
        description: "Preferences are deep-merged without skipping __proto__ or constructor.prototype.",
    },
    Vuln {
        id: "VS-33",
        class: "csrf",
        method: "POST",
        path: "/graphql",
        description: "GraphQL runs cross-site requests with the session cookie: no token, any content type.",
    },
    Vuln {
        id: "VS-34",
        class: "request_smuggling",
        method: "GET",
        path: "/legacy/status",
        description: "The /legacy front end honours Transfer-Encoding but passes Content-Length on to a back end that \
                      trusts it (TE.CL desync).",
    },
    Vuln {
        id: "VS-35",
        class: "oauth",
        method: "GET",
        path: "/oauth/authorize",
        description: "Any redirect_uri is accepted, and codes are issued without state.",
    },
    Vuln {
        id: "VS-36",
        class: "deserialization",
        method: "GET",
        path: "/api/cart",
        description: "The cart cookie is a base64 PHP-serialized array that the server unserializes.",
    },
    Vuln {
        id: "VS-37",
        class: "file_upload",
        method: "POST",
        path: "/api/avatar",
        description: "Avatars of any type are stored and served from /uploads with a type from the extension (HTML runs).",
    },
    Vuln {
        id: "VS-38",
        class: "sqli",
        method: "GET",
        path: "/api/spa/catalog",
        description: "The single-page app at /spa calls this API from JavaScript only; category goes into SQL \
                      (error-based). Only a crawler that runs the app finds it.",
    },
];

/// Endpoints that look similar but are correctly protected (false-positive traps).
pub const SECURE_ENDPOINTS: &[&str] = &[
    "GET /api/invoices/{id}",
    "GET /api/admin/stats",
    "GET /api/orders",
    "GET /help",
    "GET /out",
    "GET /docs",
    "POST /api/settings",
    "GET /hello",
    "GET /api/notice",
    "GET /api/account/keys",
    "POST /api/signup",
    "GET /oauth2/authorize",
];

struct User {
    id: u32,
    name: &'static str,
    password: &'static str,
    role: &'static str,
}

const USERS: &[User] = &[
    User { id: 1, name: "alice", password: "alice123", role: "user" },
    User { id: 2, name: "bob", password: "bob123", role: "user" },
    User { id: 3, name: "admin", password: "admin123", role: "admin" },
];

#[derive(Clone)]
struct Order {
    id: u32,
    owner: u32,
    product: u32,
    qty: u32,
}

struct State {
    sessions: HashMap<String, u32>,
    orders: Vec<Order>,
    invoices: Vec<(u32, u32, f64)>,
    next_order: u32,
    /// Users who redeemed the WELCOME10 gift card, and their store credit.
    redeemed: std::collections::HashSet<u32>,
    credit: HashMap<u32, u32>,
    /// VS-23: guestbook entries (name, message), newest last.
    guestbook: Vec<(String, String)>,
    /// VS-24: profile emails by user id.
    emails: HashMap<u32, String>,
    /// VS-29/VS-30: a shared response cache keyed on the request target only.
    cache: HashMap<String, (std::time::Instant, Response)>,
    /// VS-31: registered accounts (name, role).
    registered: Vec<(String, String)>,
    /// VS-32: what got merged into "Object.prototype".
    proto: serde_json::Map<String, Value>,
    /// VS-37: uploaded files by name.
    uploads: HashMap<String, Vec<u8>>,
}

#[derive(Clone)]
pub struct VulnShop {
    state: Arc<Mutex<State>>,
    counter: Arc<AtomicU64>,
    /// VS-11: password-reset codes.
    reset_codes: Arc<AtomicU64>,
}

impl Default for VulnShop {
    fn default() -> Self {
        Self::new()
    }
}

struct Request {
    method: String,
    path: String,
    /// Path and query as sent (the cache key).
    target: String,
    query: HashMap<String, String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn cookie(&self, name: &str) -> Option<String> {
        self.header("cookie")?
            .split(';')
            .filter_map(|p| p.split_once('='))
            .find(|(k, _)| k.trim() == name)
            .map(|(_, v)| v.trim().to_string())
    }

    fn token(&self) -> Option<String> {
        self.header("authorization")
            .and_then(|a| a.strip_prefix("Bearer ").map(str::to_string))
            .or_else(|| self.cookie("session"))
    }

    fn params(&self) -> HashMap<String, String> {
        if let Ok(Value::Object(o)) = serde_json::from_slice::<Value>(&self.body) {
            return o
                .into_iter()
                .map(|(k, v)| (k, v.as_str().map(String::from).unwrap_or_else(|| v.to_string())))
                .collect();
        }
        parse_query(&String::from_utf8_lossy(&self.body))
    }
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                match std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A pretend filesystem: resolves `..` the way a naive server would.
fn fake_file(path: &str) -> Response {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split(['/', '\\']) {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let resolved = format!("/{}", parts.join("/"));
    let body = match resolved.as_str() {
        "/etc/passwd" => "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        "/srv/downloads/report.pdf" => "%PDF-1.4 VulnShop annual report",
        "/srv/downloads/menu.txt" => "Coffee, Tea, Cake",
        _ => return json_resp(404, json!({"error": "no such file"})),
    };
    Response { status: 200, headers: vec![], body: body.into(), content_type: "text/plain" }
}

/// Replaces `{{a*b}}` (integers) with the product, like a template engine would.
fn render_template(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("{{") {
        out.push_str(&rest[..i]);
        let Some(j) = rest[i..].find("}}") else {
            out.push_str(&rest[i..]);
            return out;
        };
        let expr = rest[i + 2..i + j].trim();
        let value = expr
            .split_once('*')
            .and_then(|(a, b)| {
                Some(a.trim().parse::<i64>().ok()?.checked_mul(b.trim().parse::<i64>().ok()?)?.to_string())
            })
            .unwrap_or_default();
        out.push_str(&value);
        rest = &rest[i + j + 2..];
    }
    out.push_str(rest);
    out
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&').filter_map(|p| p.split_once('=')).map(|(k, v)| (url_decode(k), url_decode(v))).collect()
}

#[derive(Clone)]
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
    content_type: &'static str,
}

fn json_resp(status: u16, v: Value) -> Response {
    Response { status, headers: vec![], body: v.to_string(), content_type: "application/json" }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        502 => "Bad Gateway",
        _ => "Unknown",
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// VS-38: the single-page app's script. Navigation is buttons and
/// `history.pushState`; the catalog API's path is assembled at run time.
const SPA_JS: &str = r#"const pages = [['/spa', 'Home'], ['/spa/catalog', 'Catalog'], ['/spa/account', 'Account']];
const nav = document.getElementById('nav');
for (const [path, label] of pages) {
  const b = document.createElement('button');
  b.textContent = label;
  b.onclick = () => { history.pushState({}, '', path); render(); };
  nav.appendChild(b);
}
async function render() {
  const view = document.getElementById('view');
  if (location.pathname === '/spa/catalog') {
    const r = await fetch(['/api', 'spa', 'catalog'].join('/') + '?category=' + 'tea');
    view.textContent = (await r.json()).items.join(', ');
  } else if (location.pathname === '/spa/account') {
    const r = await fetch('/api/me');
    view.textContent = r.status === 200 ? 'Signed in' : 'Please sign in';
  } else {
    view.textContent = 'Welcome to the VulnShop app';
  }
}
render();
"#;

/// VS-36: checks a PHP-serialized value the way unserialize() would fail:
/// declared string lengths must match. Returns the strings, or the offset
/// of the first error.
fn php_unserialize_check(text: &str) -> Result<Vec<String>, usize> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(at) = text[i..].find("s:").map(|x| x + i) {
        let digits: String = text[at + 2..].chars().take_while(char::is_ascii_digit).collect();
        let n: usize = digits.parse().map_err(|_| at)?;
        let start = at + 2 + digits.len() + 2; // past `:"`
        let end = start + n;
        if b.get(start - 2..start) != Some(b":\"") || b.get(end) != Some(&b'"') {
            return Err(at);
        }
        out.push(text[start..end].to_string());
        i = end;
    }
    Ok(out)
}

/// The first file in a multipart/form-data body: (file name, bytes).
fn multipart_file(req: &Request) -> Option<(String, Vec<u8>)> {
    let ct = req.header("content-type")?;
    let boundary = ct.split(';').find_map(|x| x.trim().strip_prefix("boundary="))?.trim_matches('"');
    let delim = format!("--{boundary}");
    let body = String::from_utf8_lossy(&req.body).into_owned();
    for part in body.split(delim.as_str()) {
        let Some((head, data)) = part.split_once("\r\n\r\n") else { continue };
        let Some(name) = head.split("filename=\"").nth(1).and_then(|x| x.split('"').next()) else { continue };
        let data = data.strip_suffix("\r\n").unwrap_or(data);
        return Some((name.to_string(), data.as_bytes().to_vec()));
    }
    None
}

/// VS-27: the HMAC key for login JWTs (a guessable one).
const JWT_SECRET: &str = "secret";

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

fn sign_jwt(claims: &Value, secret: &str) -> String {
    let input = format!("{}.{}", b64url(br#"{"alg":"HS256","typ":"JWT"}"#), b64url(claims.to_string().as_bytes()));
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    format!("{input}.{}", b64url(ring::hmac::sign(&key, input.as_bytes()).as_ref()))
}

/// The claims of a valid token; `trust_none` accepts `alg: none` unsigned.
fn verify_jwt(token: &str, trust_none: bool) -> Option<Value> {
    let mut parts = token.split('.');
    let (h, p, sig) = (parts.next()?, parts.next()?, parts.next()?);
    let unb64 = |x: &str| b64_decode(&x.replace('-', "+").replace('_', "/"));
    let header: Value = serde_json::from_slice(&unb64(h)?).ok()?;
    let claims: Value = serde_json::from_slice(&unb64(p)?).ok()?;
    let alg = header["alg"].as_str()?;
    if alg.eq_ignore_ascii_case("none") {
        return trust_none.then_some(claims);
    }
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, JWT_SECRET.as_bytes());
    ring::hmac::verify(&key, format!("{h}.{p}").as_bytes(), &unb64(sig)?).ok()?;
    Some(claims)
}

/// Standard base64 (padding optional).
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let (mut bits, mut n) = (0u32, 0);
    for c in s.trim_end_matches('=').bytes() {
        let x = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
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

/// VulnShop's API description (served at /openapi.json).
const OPENAPI: &str = r##"{
  "openapi": "3.0.3",
  "info": {"title": "VulnShop API", "version": "1.0"},
  "servers": [{"url": "/"}],
  "components": {
    "securitySchemes": {"session": {"type": "apiKey", "in": "cookie", "name": "session"}},
    "schemas": {"Login": {"type": "object", "properties": {"username": {"type": "string", "example": "alice"}, "password": {"type": "string", "example": "alice123"}}}}
  },
  "security": [{"session": []}],
  "paths": {
    "/api/login": {"post": {"summary": "Log in", "security": [], "requestBody": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Login"}}}}}},
    "/api/me": {"get": {"summary": "Current user"}},
    "/api/products": {"get": {"summary": "List products", "security": []}},
    "/api/import": {"post": {"summary": "Import products (XML)", "security": [], "requestBody": {"content": {"application/xml": {"example": "<?xml version=\"1.0\"?><items><item>Coffee</item></items>"}}}}},
    "/api/products/search": {"get": {"summary": "Search products", "security": [], "parameters": [{"name": "q", "in": "query", "required": true, "schema": {"type": "string", "example": "Coffee"}}]}},
    "/api/orders": {"get": {"summary": "Your orders"}, "post": {"summary": "Place an order"}},
    "/api/orders/{id}": {"get": {"summary": "One order", "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "integer", "example": 1001}}]}},
    "/api/reviews": {"get": {"summary": "Product reviews", "security": [], "parameters": [{"name": "product", "in": "query", "required": true, "schema": {"type": "integer", "example": 1}}]}},
    "/api/giftcard/redeem": {"post": {"summary": "Redeem the welcome gift card"}},
    "/api/guestbook": {"post": {"summary": "Sign the guestbook", "security": [], "requestBody": {"content": {"application/x-www-form-urlencoded": {"schema": {"type": "object", "properties": {"name": {"type": "string", "example": "carol"}, "message": {"type": "string", "example": "Nice shop"}}}}}}}},
    "/api/register": {"post": {"summary": "Create an account", "security": [], "requestBody": {"content": {"application/json": {"schema": {"type": "object", "properties": {"username": {"type": "string", "example": "carol"}, "password": {"type": "string", "example": "carol123"}}}}}}}},
    "/api/profile": {"post": {"summary": "Change your email", "requestBody": {"content": {"application/x-www-form-urlencoded": {"schema": {"type": "object", "properties": {"email": {"type": "string", "example": "alice@example.org"}}}}}}}}
  }
}"##;

const HOME: &str = "<!doctype html><html><head><title>VulnShop</title></head><body>\
<h1>VulnShop</h1><p>A deliberately vulnerable demo shop. Do not expose it to a network.</p>\
<form method=post action=/api/login><input name=username><input type=password name=password>\
<button>Log in</button></form><a href=/api/products>Products</a> \
<form action=/search><input name=q><button>Search</button></form> <a href=\"/search?q=coffee\">Coffee</a> \
<a href='/help?topic=orders'>Help</a> <a href=/guestbook>Guestbook</a> <a href='/welcome?name=guest'>Welcome</a> <a href='/hello?name=guest'>Hello</a> <a href=/spa>App</a> <a href='/api/recommend?ctx=eyJjYXRlZ29yeSI6ImNvZmZlZSJ9'>For you</a> <a href='/api/tools/ping?host=127.0.0.1'>Network check</a> <a href='/api/lang?set=en'>English</a> <a href='/api/share?product=1'>Share</a> <a href=/api/logout>Log out</a> <a href=https://example.org/>Elsewhere</a> \
<script src=/static/app.js></script></body></html>";

/// An in-memory SQLite database for the SQL injection demos, with MySQL's
/// `SLEEP(n)` (at most 10 s) so time-based payloads behave as on MySQL.
fn demo_db() -> rusqlite::Result<rusqlite::Connection> {
    use rusqlite::functions::FunctionFlags;
    let c = rusqlite::Connection::open_in_memory()?;
    c.create_scalar_function("sleep", 1, FunctionFlags::SQLITE_UTF8, |ctx| {
        let secs = ctx.get::<f64>(0).unwrap_or(0.0).clamp(0.0, 10.0);
        std::thread::sleep(Duration::from_secs_f64(secs));
        Ok(0i64)
    })?;
    c.execute_batch(
        "CREATE TABLE products(id INTEGER, name TEXT);
         INSERT INTO products VALUES (1, 'Coffee'), (2, 'Tea'), (3, 'Cake');
         CREATE TABLE visits(ua TEXT);
         INSERT INTO visits VALUES ('Mozilla/5.0');",
    )?;
    Ok(c)
}

/// Runs SQL built from user input (deliberately) and returns the first
/// column of each row. Errors give no rows: the injection is blind.
async fn demo_query(sql: String) -> Vec<String> {
    tokio::task::spawn_blocking(move || {
        let Ok(c) = demo_db() else { return Vec::new() };
        let Ok(mut st) = c.prepare(&sql) else { return Vec::new() };
        let Ok(rows) = st.query_map([], |r| r.get::<_, rusqlite::types::Value>(0)) else { return Vec::new() };
        rows.filter_map(Result::ok)
            .map(|v| match v {
                rusqlite::types::Value::Text(s) => s,
                rusqlite::types::Value::Integer(i) => i.to_string(),
                _ => String::new(),
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

/// A pretend `sh -c` for VS-14: understands `;`, `|`, `&&`, `||`, new
/// lines, `$(…)` and backticks, and the commands ping, echo (with
/// `$((a*b))`) and sleep (at most 10 s in all). Nothing is executed.
async fn fake_shell(line: &str) -> String {
    let mut line = line.to_string();
    let mut slept = 0.0;
    let mut fetches = Vec::new();
    // Command substitution first: $(cmd) and `cmd` (but not $((…)) arithmetic).
    for _ in 0..5 {
        let found = match (line.find("$("), line.find('`')) {
            (Some(i), _) if !line[i + 2..].starts_with('(') => {
                // The matching `)`, skipping nested ones such as $((…)).
                let mut depth = 0usize;
                line[i + 1..]
                    .char_indices()
                    .find_map(|(k, c)| {
                        match c {
                            '(' => depth += 1,
                            ')' => depth -= 1,
                            _ => {}
                        }
                        (depth == 0).then_some(i + 1 + k)
                    })
                    .map(|close| (i, close + 1, i + 2, close))
            }
            (_, Some(i)) => line[i + 1..].find('`').map(|j| (i, i + j + 2, i + 1, i + 1 + j)),
            _ => None,
        };
        let Some((start, end, a, b)) = found else { break };
        let (out, s, f) = shell_commands(&line[a..b]);
        slept += s;
        fetches.extend(f);
        line.replace_range(start..end, out.trim());
    }
    let (out, s, f) = shell_commands(&line);
    slept += s;
    fetches.extend(f);
    tokio::time::sleep(Duration::from_secs_f64(f64::min(slept, 10.0))).await;
    // curl and wget (run as commands) really fetch, http:// only like VS-4,
    // so out-of-band payloads can be seen; a few at most.
    for url in fetches.iter().take(3) {
        let _ = fetch(url).await;
    }
    out
}

/// A MongoDB-style match of one field: a plain value, or an operator object.
fn mongo_match(cond: &Value, actual: &str) -> bool {
    match cond {
        Value::String(s) => s == actual,
        Value::Object(o) => o.iter().all(|(op, v)| {
            let s = v.as_str().unwrap_or_default();
            match op.as_str() {
                "$eq" => s == actual,
                "$ne" => s != actual,
                "$gt" => actual > s,
                "$lt" => actual < s,
                "$in" => v.as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == Some(actual))),
                "$nin" => v.as_array().is_some_and(|a| !a.iter().any(|x| x.as_str() == Some(actual))),
                // Only the patterns the demo needs: anything, or an exact anchored string.
                "$regex" => s == ".*" || s.strip_prefix('^').and_then(|x| x.strip_suffix('$')) == Some(actual),
                _ => false,
            }
        }),
        _ => false,
    }
}

/// URLs of external entities an XML document declares and uses.
fn external_entities(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<!ENTITY") {
        rest = &rest[i + 8..];
        let decl = &rest[..rest.find('>').unwrap_or(rest.len())];
        let words: Vec<&str> = decl.split_whitespace().collect();
        let (param, name) = match words.as_slice() {
            ["%", n, ..] => (true, *n),
            [n, ..] => (false, *n),
            _ => continue,
        };
        let Some(url) = decl.split('"').nth(1).filter(|u| decl.contains("SYSTEM") && u.starts_with("http://")) else {
            continue;
        };
        let used = if param { xml.contains(&format!("%{name};")) } else { xml.contains(&format!("&{name};")) };
        if used && out.len() < 3 {
            out.push(url.to_string());
        }
    }
    out
}

/// Output, seconds slept, and URLs that curl/wget fetched.
fn shell_commands(line: &str) -> (String, f64, Vec<String>) {
    let mut cmds = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        let two = |n: char, chars: &mut std::iter::Peekable<std::str::Chars>| chars.next_if_eq(&n).is_some();
        let split = match c {
            ';' | '\n' => true,
            '|' => {
                two('|', &mut chars);
                true
            }
            '&' if two('&', &mut chars) => true,
            _ => false,
        };
        if split {
            cmds.push(std::mem::take(&mut cur));
        } else {
            cur.push(c);
        }
    }
    cmds.push(cur);
    let (mut out, mut slept, mut fetches) = (String::new(), 0.0, Vec::new());
    for cmd in cmds {
        let words: Vec<&str> = cmd.split_whitespace().collect();
        match words.first().copied() {
            None => {}
            Some("ping") => {
                out.push_str(&format!("PING {}: 1 packets transmitted, 1 received\n", words.last().unwrap_or(&"")))
            }
            Some("echo") => {
                let mut text = words[1..].join(" ");
                while let Some(i) = text.find("$((") {
                    let Some(j) = text[i..].find("))") else { break };
                    let expr = &text[i + 3..i + j];
                    let v = expr
                        .split_once('*')
                        .and_then(|(a, b)| Some(a.trim().parse::<i64>().ok()? * b.trim().parse::<i64>().ok()?));
                    text.replace_range(i..i + j + 2, &v.map(|v| v.to_string()).unwrap_or_default());
                }
                out.push_str(&text);
                out.push('\n');
            }
            Some("sleep") => slept += words.get(1).and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0),
            Some("curl" | "wget") => {
                fetches.extend(words.iter().filter(|w| w.starts_with("http://")).map(|w| w.to_string()));
                out.push_str("<html>ok</html>\n");
            }
            Some("nslookup") => out.push_str("Server: 127.0.0.53\n"),
            Some(other) => out.push_str(&format!("sh: {other}: not found\n")),
        }
    }
    (out, slept, fetches)
}

/// The introspection result for VulnShop's GraphQL schema.
fn graphql_schema() -> Value {
    let named = |kind: &str, name: &str| json!({"kind": kind, "name": name, "ofType": null});
    let non_null = |t: Value| json!({"kind": "NON_NULL", "name": null, "ofType": t});
    let list = |t: Value| json!({"kind": "LIST", "name": null, "ofType": t});
    let field =
        |name: &str, args: Value, ty: Value| json!({"name": name, "description": null, "args": args, "type": ty});
    let scalar = |n: &str| named("SCALAR", n);
    let id_arg = json!([{"name": "id", "type": non_null(scalar("ID")), "defaultValue": null}]);
    json!({
        "queryType": {"name": "Query"}, "mutationType": null, "subscriptionType": null,
        "types": [
            {"kind": "OBJECT", "name": "Query", "fields": [
                field("me", json!([]), named("OBJECT", "User")),
                field("invoice", id_arg, named("OBJECT", "Invoice")),
                field("products", json!([]), non_null(list(non_null(named("OBJECT", "Product"))))),
            ]},
            {"kind": "OBJECT", "name": "User", "fields": [
                field("id", json!([]), non_null(scalar("ID"))), field("username", json!([]), scalar("String")),
                field("email", json!([]), scalar("String")), field("role", json!([]), scalar("String")),
            ]},
            {"kind": "OBJECT", "name": "Invoice", "fields": [
                field("id", json!([]), non_null(scalar("ID"))), field("total", json!([]), scalar("Float")),
                field("owner", json!([]), named("OBJECT", "User")),
            ]},
            {"kind": "OBJECT", "name": "Product", "fields": [
                field("id", json!([]), non_null(scalar("ID"))), field("name", json!([]), scalar("String")),
                field("price", json!([]), scalar("Float")),
            ]},
            scalar("ID"), scalar("String"), scalar("Float"), scalar("Boolean"),
        ]
    })
}

impl VulnShop {
    pub fn new() -> Self {
        let orders = vec![
            Order { id: 1001, owner: 1, product: 1, qty: 2 },
            Order { id: 1002, owner: 1, product: 3, qty: 1 },
            Order { id: 2001, owner: 2, product: 2, qty: 5 },
        ];
        Self {
            state: Arc::new(Mutex::new(State {
                sessions: HashMap::new(),
                orders,
                invoices: vec![(5001, 1, 49.90), (6001, 2, 120.00)],
                next_order: 3000,
                redeemed: Default::default(),
                credit: HashMap::new(),
                guestbook: vec![("alice".into(), "Lovely coffee!".into())],
                emails: HashMap::new(),
                cache: HashMap::new(),
                registered: Vec::new(),
                proto: serde_json::Map::new(),
                uploads: HashMap::new(),
            })),
            counter: Arc::new(AtomicU64::new(0)),
            reset_codes: Arc::new(AtomicU64::new(400_000)),
        }
    }

    /// Serves until the listener fails.
    pub async fn serve(self, listener: TcpListener) {
        loop {
            let Ok((s, _)) = listener.accept().await else { return };
            let shop = self.clone();
            tokio::spawn(async move {
                let _ = shop.handle(s).await;
            });
        }
    }

    /// Starts on a random local port and returns its address.
    pub async fn start_local() -> std::io::Result<SocketAddr> {
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        tokio::spawn(VulnShop::new().serve(l));
        Ok(addr)
    }

    async fn handle(&self, mut s: TcpStream) -> std::io::Result<()> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 8192];
        let head_end = loop {
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                return Ok(());
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Ok(Some(end)) = pm_http::find_head_end(&buf) {
                break end;
            }
            if buf.len() > 64 * 1024 {
                return Ok(());
            }
        };
        let Ok(head) = pm_http::parse_request_head(&buf[..head_end]) else { return Ok(()) };
        let wants_ws = pm_http::header(&head.headers, "upgrade").is_some_and(|v| v.eq_ignore_ascii_case(b"websocket"));
        let len = pm_http::header(&head.headers, "content-length")
            .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse::<usize>().ok())
            .unwrap_or(0)
            .min(1024 * 1024);
        while buf.len() < head_end + len {
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let (path, query) = head.target.split_once('?').unwrap_or((head.target.as_str(), ""));
        let req = Request {
            method: head.method.to_ascii_uppercase(),
            path: path.to_string(),
            target: head.target.clone(),
            query: parse_query(query),
            headers: head
                .headers
                .iter()
                .map(|h| (h.name.clone(), String::from_utf8_lossy(&h.value).into_owned()))
                .collect(),
            body: buf[head_end..(head_end + len).min(buf.len())].to_vec(),
        };
        if wants_ws && req.method == "GET" && req.path == "/ws/support" {
            return self.support_socket(s, &req, buf[head_end..].to_vec()).await;
        }
        let resp = match self.legacy_front_end(&req).await {
            Some(r) => r,
            None => self.cached(&req).await,
        };
        let mut out = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nX-Request-Id: {}\r\nConnection: close\r\n",
            resp.status,
            reason(resp.status),
            resp.content_type,
            resp.body.len(),
            self.counter.fetch_add(1, Ordering::Relaxed)
        );
        for (k, v) in &resp.headers {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        out.push_str(&resp.body);
        s.write_all(out.as_bytes()).await?;
        let _ = s.shutdown().await;
        Ok(())
    }

    /// A WebSocket support chat for logged-in users: it greets you and
    /// answers each message.
    async fn support_socket(&self, mut s: TcpStream, req: &Request, mut pending: Vec<u8>) -> std::io::Result<()> {
        let (Some(user), Some(key)) = (self.user(req), req.header("sec-websocket-key")) else {
            let body = r#"{"error":"login required"}"#;
            let out = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            s.write_all(out.as_bytes()).await?;
            return Ok(());
        };
        let accept = ws_accept(key.trim());
        s.write_all(
            format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n")
                .as_bytes(),
        )
        .await?;
        let hello = json!({"from": "support", "text": format!("Hi {}, how can we help?", user.name)}).to_string();
        s.write_all(&ws_frame(pm_http::ws::TEXT, hello.as_bytes())).await?;
        let mut decoder = pm_http::ws::Decoder::new(64 * 1024);
        let mut tmp = [0u8; 8192];
        loop {
            let mut msgs = Vec::new();
            if decoder.feed(&pending, &mut msgs).is_err() {
                return Ok(());
            }
            pending.clear();
            for m in msgs {
                match m.opcode {
                    pm_http::ws::TEXT => {
                        let text = String::from_utf8_lossy(&m.payload);
                        let reply = json!({"from": "support", "text": format!("Thanks {}, we got: {text}", user.name)});
                        s.write_all(&ws_frame(pm_http::ws::TEXT, reply.to_string().as_bytes())).await?;
                    }
                    pm_http::ws::PING => s.write_all(&ws_frame(pm_http::ws::PONG, &m.payload)).await?,
                    pm_http::ws::CLOSE => {
                        s.write_all(&ws_frame(pm_http::ws::CLOSE, &m.payload)).await?;
                        let _ = s.shutdown().await;
                        return Ok(());
                    }
                    _ => {}
                }
            }
            let n = s.read(&mut tmp).await?;
            if n == 0 {
                return Ok(());
            }
            pending.extend_from_slice(&tmp[..n]);
        }
    }

    /// A tiny GraphQL endpoint: introspection is on (as on many real servers)
    /// and the root fields me, invoice(id) and products are answered.
    fn graphql(&self, req: &Request) -> Response {
        let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
            return json_resp(400, json!({"errors": [{"message": "expected a JSON body"}]}));
        };
        // VS-28: batches run every operation.
        if let Value::Array(ops) = &body {
            let results: Vec<Value> = ops
                .iter()
                .take(100)
                .map(|op| {
                    let one = Request {
                        method: req.method.clone(),
                        path: req.path.clone(),
                        target: req.target.clone(),
                        query: req.query.clone(),
                        headers: req.headers.clone(),
                        body: op.to_string().into_bytes(),
                    };
                    serde_json::from_str(&self.graphql(&one).body).unwrap_or(Value::Null)
                })
                .collect();
            return json_resp(200, Value::Array(results));
        }
        let query = body["query"].as_str().unwrap_or_default();
        if query.contains("__schema") {
            return json_resp(200, json!({"data": {"__schema": graphql_schema()}}));
        }
        let Some(user) = self.user(req) else {
            return json_resp(200, json!({"errors": [{"message": "not logged in"}], "data": null}));
        };
        // The first field inside the first selection set is the root field.
        let after = query.split_once('{').map(|(_, r)| r.trim_start()).unwrap_or_default();
        let field: String = after.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        let user_json = |u: &User| json!({"id": u.id.to_string(), "username": u.name, "email": format!("{}@vulnshop.test", u.name), "role": u.role});
        let data = match field.as_str() {
            "me" => json!({"me": user_json(user)}),
            "products" => json!({"products": [
                {"id": "1", "name": "Coffee", "price": 3.5}, {"id": "2", "name": "Tea", "price": 2.0},
                {"id": "3", "name": "Cake", "price": 4.25}]}),
            "invoice" => {
                // VS-12: no ownership check here, unlike GET /api/invoices/{id}.
                let id = body["variables"]["id"]
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| body["variables"]["id"].as_u64().map(|n| n.to_string()))
                    .or_else(|| {
                        let rest = after.split_once("id:")?.1.trim_start().trim_start_matches('"');
                        Some(rest.chars().take_while(char::is_ascii_digit).collect())
                    })
                    .unwrap_or_default();
                let st = self.state.lock().expect("state");
                match id.parse::<u32>().ok().and_then(|id| st.invoices.iter().find(|i| i.0 == id)) {
                    Some(inv) => {
                        let owner = USERS.iter().find(|u| u.id == inv.1).expect("owner");
                        json!({"invoice": {"id": inv.0.to_string(), "total": inv.2, "owner": user_json(owner)}})
                    }
                    None => json!({"invoice": null}),
                }
            }
            other => {
                return json_resp(
                    200,
                    json!({"errors": [{"message": format!("Cannot query field \"{other}\" on type \"Query\".")}]}),
                );
            }
        };
        json_resp(200, json!({"data": data}))
    }

    fn user(&self, req: &Request) -> Option<&'static User> {
        let tok = req.token()?;
        let id = *self.state.lock().ok()?.sessions.get(&tok)?;
        USERS.iter().find(|u| u.id == id)
    }

    /// Fields that change on every response (noise for diffing tools).
    fn meta(&self) -> Value {
        json!({ "generated_at": now_ms() as u64, "request_id": self.counter.load(Ordering::Relaxed) })
    }

    /// VS-34: /legacy sits behind a front end that reads chunked bodies but
    /// forwards Content-Length unchanged to a back end that trusts it. When
    /// the two disagree, the back end waits for bytes that never come.
    async fn legacy_front_end(&self, req: &Request) -> Option<Response> {
        let chunked = req.header("transfer-encoding").is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        if !req.path.starts_with("/legacy") || !chunked {
            return None;
        }
        let declared: usize = req.header("content-length").and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        let Some(end) = req.body.windows(5).position(|w| w == b"0\r\n\r\n").map(|i| i + 5) else {
            return Some(json_resp(400, json!({"error": "bad chunked body"})));
        };
        if declared > end {
            tokio::time::sleep(Duration::from_secs(6)).await;
            return Some(json_resp(504, json!({"error": "upstream timed out"})));
        }
        None
    }

    /// A shared cache in front of the app (VS-29, VS-30): static-looking
    /// paths and the banner/notice pages, keyed on the target only, 30 s.
    async fn cached(&self, req: &Request) -> Response {
        let static_ext = [".css", ".js", ".png", ".ico"].iter().any(|e| req.path.ends_with(e));
        let cacheable = req.method == "GET" && (static_ext || req.path == "/api/banner" || req.path == "/api/notice");
        if !cacheable {
            return self.route(req).await;
        }
        let ttl = Duration::from_secs(30);
        let hit = self.state.lock().ok().and_then(|st| {
            st.cache.get(&req.target).filter(|(at, _)| at.elapsed() < ttl).map(|(at, r)| (at.elapsed(), r.clone()))
        });
        if let Some((age, mut r)) = hit {
            r.headers.push(("X-Cache".into(), "hit".into()));
            r.headers.push(("Age".into(), age.as_secs().to_string()));
            return r;
        }
        let mut r = self.route(req).await;
        r.headers.push(("Cache-Control".into(), "public, max-age=30".into()));
        if r.status == 200
            && let Ok(mut st) = self.state.lock()
        {
            if st.cache.len() > 500 {
                st.cache.clear();
            }
            st.cache.insert(req.target.clone(), (std::time::Instant::now(), r.clone()));
        }
        r.headers.push(("X-Cache".into(), "miss".into()));
        r
    }

    async fn route(&self, req: &Request) -> Response {
        let unauthorized = || json_resp(401, json!({"error": "login required"}));
        let segs: Vec<&str> = req.path.trim_matches('/').split('/').collect();
        match (req.method.as_str(), segs.as_slice()) {
            ("GET", [""]) => Response { status: 200, headers: vec![], body: HOME.into(), content_type: "text/html" },
            ("GET", ["search"]) => {
                // VS-6: reflected XSS, q is written into the page as is.
                let q = req.query.get("q").cloned().unwrap_or_default();
                let body = format!(
                    "<!doctype html><html><head><title>Search</title></head><body><h1>Search</h1>\
                     <p>Results for {q}</p><ul><li>Coffee</li></ul></body></html>"
                );
                Response { status: 200, headers: vec![], body, content_type: "text/html; charset=utf-8" }
            }
            ("GET", ["api", "reviews"]) => {
                // VS-7: error-based SQL injection.
                let product = req.query.get("product").cloned().unwrap_or_default();
                if product.contains('\'') || product.contains('"') {
                    return Response {
                        status: 500,
                        headers: vec![],
                        body: format!(
                            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL \
                             server version for the right syntax to use near '{product}' at line 1"
                        ),
                        content_type: "text/plain",
                    };
                }
                json_resp(200, json!({"product": product, "reviews": [{"stars": 5, "text": "Great"}]}))
            }
            ("POST", ["api", "password", "reset"]) => {
                // VS-11: predictable reset codes (a counter).
                let code = self.reset_codes.fetch_add(1, Ordering::Relaxed);
                json_resp(200, json!({"sent": true, "debug_code": code.to_string()}))
            }
            ("GET", ["go"]) => {
                // VS-8: open redirect.
                let url = req.query.get("url").cloned().unwrap_or_else(|| "/".into());
                Response {
                    status: 302,
                    headers: vec![("Location".into(), url)],
                    body: String::new(),
                    content_type: "text/plain",
                }
            }
            ("GET", ["out"]) => {
                // Secure look-alike: only same-site paths.
                let url = req.query.get("url").cloned().unwrap_or_else(|| "/".into());
                // (Control characters too: a CR LF here would split the header.)
                if url.starts_with('/')
                    && !url.starts_with("//")
                    && !url.contains('\\')
                    && !url.contains(char::is_control)
                {
                    Response {
                        status: 302,
                        headers: vec![("Location".into(), url)],
                        body: String::new(),
                        content_type: "text/plain",
                    }
                } else {
                    json_resp(400, json!({"error": "only paths on this site"}))
                }
            }
            ("GET", ["download"]) => {
                // VS-9: path traversal (simulated files; nothing is read from disk).
                let file = req.query.get("file").cloned().unwrap_or_default();
                fake_file(&format!("/srv/downloads/{file}"))
            }
            ("GET", ["docs"]) => {
                // Secure look-alike: only the base name is used.
                let file = req.query.get("file").cloned().unwrap_or_default();
                let base = file.rsplit(['/', '\\']).next().unwrap_or("");
                fake_file(&format!("/srv/downloads/{base}"))
            }
            ("GET", ["greet"]) => {
                // VS-10: server-side template injection ({{a*b}} is evaluated).
                let name = req.query.get("name").cloned().unwrap_or_else(|| "friend".into());
                let rendered = render_template(&name);
                Response {
                    status: 200,
                    headers: vec![],
                    body: format!("<!doctype html><p>Hello {}</p>", html_escape(&rendered)),
                    content_type: "text/html; charset=utf-8",
                }
            }
            ("POST", ["graphql"]) => self.graphql(req),
            ("GET", ["openapi.json"]) => {
                Response { status: 200, headers: vec![], body: OPENAPI.into(), content_type: "application/json" }
            }
            ("GET", ["robots.txt"]) => Response {
                status: 200,
                headers: vec![],
                body: "User-agent: *\nDisallow: /api/admin/\nDisallow: /api/internal/\nDisallow: /*.bak$\n".into(),
                content_type: "text/plain",
            },
            ("GET", ["api", "recommend"]) => {
                // VS-26: SQL injection inside base64-encoded JSON.
                let ctx = req.query.get("ctx").cloned().unwrap_or_default();
                let Some(v) = b64_decode(&ctx).and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else {
                    return json_resp(400, json!({"error": "bad ctx"}));
                };
                let category = v["category"].as_str().unwrap_or("");
                if category.contains('\'') {
                    return Response {
                        status: 500,
                        headers: vec![],
                        body: format!(
                            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL \
                             server version for the right syntax to use near '{category}' at line 1"
                        ),
                        content_type: "text/plain",
                    };
                }
                json_resp(200, json!({"category": category, "products": ["Coffee"]}))
            }
            ("GET", ["guestbook"]) => {
                // VS-23: messages are shown as stored (names are encoded).
                let entries = self.state.lock().map(|st| st.guestbook.clone()).unwrap_or_default();
                let items: String =
                    entries.iter().map(|(n, m)| format!("<li><b>{}</b>: {m}</li>", html_escape(n))).collect();
                let body = format!(
                    "<!doctype html><html><head><title>Guestbook</title></head><body><h1>Guestbook</h1>\
                     <ul>{items}</ul><form method=post action=/api/guestbook><input name=name>\
                     <input name=message><button>Sign</button></form></body></html>"
                );
                Response { status: 200, headers: vec![], body, content_type: "text/html; charset=utf-8" }
            }
            ("POST", ["api", "guestbook"]) => {
                let p = req.params();
                let (n, m) =
                    (p.get("name").cloned().unwrap_or_default(), p.get("message").cloned().unwrap_or_default());
                if m.is_empty() {
                    return json_resp(400, json!({"error": "message required"}));
                }
                if let Ok(mut st) = self.state.lock() {
                    st.guestbook.push((n.chars().take(100).collect(), m.chars().take(500).collect()));
                    let excess = st.guestbook.len().saturating_sub(50);
                    st.guestbook.drain(..excess);
                }
                json_resp(201, json!({"ok": true}))
            }
            ("POST", ["api", "profile"]) => {
                // VS-24: the session cookie is all it takes (CSRF).
                let Some(u) = self.user(req) else { return unauthorized() };
                let email = req.params().get("email").cloned().unwrap_or_default();
                if let Ok(mut st) = self.state.lock() {
                    st.emails.insert(u.id, email.chars().take(100).collect());
                }
                json_resp(200, json!({"ok": true, "user": u.name}))
            }
            ("POST", ["api", "settings"]) => {
                // Secure look-alike: a cross-site Origin or Referer is refused.
                let Some(u) = self.user(req) else { return unauthorized() };
                let host = req.header("host").unwrap_or("");
                let foreign = |v: Option<&str>| {
                    v.is_some_and(|v| v.split("://").nth(1).and_then(|r| r.split('/').next()) != Some(host))
                };
                if foreign(req.header("origin")) || foreign(req.header("referer")) {
                    return json_resp(403, json!({"error": "cross-site request refused"}));
                }
                json_resp(200, json!({"ok": true, "user": u.name}))
            }
            ("GET", ["welcome"]) => Response {
                status: 200,
                headers: vec![],
                body: "<!doctype html><html><head><title>Welcome</title></head><body><h1>Welcome</h1>\
                       <p id=msg></p><script src=/static/welcome.js></script></body></html>"
                    .into(),
                content_type: "text/html; charset=utf-8",
            },
            ("GET", ["hello"]) => Response {
                status: 200,
                headers: vec![],
                body: "<!doctype html><html><head><title>Hello</title></head><body><h1>Hello</h1>\
                       <p id=msg></p><script src=/static/hello.js></script></body></html>"
                    .into(),
                content_type: "text/html; charset=utf-8",
            },
            ("GET", ["static", "welcome.js"]) => Response {
                // VS-25: DOM XSS, the name parameter goes to innerHTML.
                status: 200,
                headers: vec![],
                body: "const n = new URLSearchParams(location.search).get('name') || 'guest';\n\
                       document.getElementById('msg').innerHTML = 'Welcome back, ' + n + '!';\n"
                    .into(),
                content_type: "application/javascript",
            },
            ("GET", ["static", "hello.js"]) => Response {
                // Secure look-alike: textContent.
                status: 200,
                headers: vec![],
                body: "const n = new URLSearchParams(location.search).get('name') || 'guest';\n\
                       document.getElementById('msg').textContent = 'Hello, ' + n + '!';\n"
                    .into(),
                content_type: "application/javascript",
            },
            ("GET", ["api", "v3", "profile"]) => {
                // VS-27: weak secret, and alg none is trusted.
                let tok = req.header("authorization").and_then(|a| a.strip_prefix("Bearer ")).unwrap_or("");
                match verify_jwt(tok, true) {
                    Some(c) => {
                        json_resp(200, json!({"profile": {"username": c["sub"], "role": c["role"], "plan": "gold"}}))
                    }
                    None => json_resp(401, json!({"error": "invalid token"})),
                }
            }
            ("GET", ["api", "banner"]) => {
                // VS-29: the script host comes from X-Forwarded-Host (unkeyed by the cache).
                let host = req.header("x-forwarded-host").or(req.header("host")).unwrap_or("localhost");
                let lang = html_escape(&req.query.get("lang").cloned().unwrap_or_else(|| "en".into()));
                let body = format!(
                    "<!doctype html><div class=banner lang={lang}>Spring sale!</div>\
                     <script src=\"//{host}/static/banner.js\"></script>"
                );
                Response { status: 200, headers: vec![], body, content_type: "text/html; charset=utf-8" }
            }
            ("GET", ["api", "notice"]) => {
                // Secure look-alike: cached too, but no request header goes into it.
                let lang = html_escape(&req.query.get("lang").cloned().unwrap_or_else(|| "en".into()));
                let body = format!(
                    "<!doctype html><div class=notice lang={lang}>Opening hours 9-5</div>\
                     <script src=\"/static/notice.js\"></script>"
                );
                Response { status: 200, headers: vec![], body, content_type: "text/html; charset=utf-8" }
            }
            ("GET", ["api", "account", s, ..]) if s.starts_with("settings") => {
                // VS-30: /settings/anything.css and /settings;x.css get the same page (and get cached).
                let Some(u) = self.user(req) else { return unauthorized() };
                json_resp(
                    200,
                    json!({"username": u.name, "email": format!("{}@vulnshop.test", u.name), "api_key": format!("vs-{}-{:08x}", u.name, u.id * 7919)}),
                )
            }
            ("GET", ["api", "account", "keys"]) => {
                // Secure look-alike: exact path only.
                let Some(u) = self.user(req) else { return unauthorized() };
                json_resp(200, json!({"keys": [format!("vs-{}-key", u.name)]}))
            }
            ("POST", ["api", "register"]) => {
                // VS-31: role comes from the request.
                let p = req.params();
                let name = p.get("username").cloned().unwrap_or_default();
                if name.is_empty() {
                    return json_resp(400, json!({"error": "username required"}));
                }
                let role = p.get("role").cloned().unwrap_or_else(|| "user".into());
                if let Ok(mut st) = self.state.lock()
                    && st.registered.len() < 1000
                {
                    st.registered.push((name.clone(), role.clone()));
                }
                json_resp(201, json!({"user": {"username": name, "role": role}}))
            }
            ("POST", ["api", "signup"]) => {
                // Secure look-alike: only known fields are used.
                let p = req.params();
                let name = p.get("username").cloned().unwrap_or_default();
                if name.is_empty() {
                    return json_resp(400, json!({"error": "username required"}));
                }
                json_resp(201, json!({"user": {"username": name, "role": "user"}}))
            }
            ("POST", ["api", "preferences"]) => {
                // VS-32: a naive deep merge; __proto__ lands in the shared prototype.
                let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(&req.body) else {
                    return json_resp(400, json!({"error": "expected a JSON object"}));
                };
                let mut prefs = serde_json::Map::new();
                prefs.insert("theme".into(), json!("light"));
                let Ok(mut st) = self.state.lock() else { return json_resp(500, json!({})) };
                for (k, v) in body {
                    match (k.as_str(), v) {
                        ("__proto__", Value::Object(o)) => st.proto.extend(o),
                        ("constructor", Value::Object(o)) => {
                            if let Some(Value::Object(p)) = o.get("prototype") {
                                st.proto.extend(p.clone());
                            }
                        }
                        (_, v) => {
                            prefs.insert(k, v);
                        }
                    }
                }
                // Inherited properties show up when the object is serialised by key.
                let mut out = st.proto.clone();
                out.extend(prefs);
                json_resp(200, json!({"preferences": out}))
            }
            ("GET" | "POST", ["legacy", "status"]) => json_resp(200, json!({"status": "ok", "backend": "legacy-1.0"})),
            ("GET", ["oauth", "authorize"]) => {
                // VS-35: any redirect_uri, and no state needed.
                let uri = req.query.get("redirect_uri").cloned().unwrap_or_default();
                let clean = |v: &str| !v.contains(char::is_control);
                let state_ok = req.query.get("state").is_none_or(|s| clean(s));
                if !uri.starts_with("http")
                    || !clean(&uri)
                    || !state_ok
                    || req.query.get("client_id").map(String::as_str) != Some("shop-web")
                {
                    return json_resp(400, json!({"error": "invalid_request"}));
                }
                let code = format!("c{:x}", self.counter.fetch_add(1, Ordering::Relaxed) * 7919);
                let state = req.query.get("state").map(|s| format!("&state={s}")).unwrap_or_default();
                let sep = if uri.contains('?') { '&' } else { '?' };
                Response {
                    status: 302,
                    headers: vec![("Location".into(), format!("{uri}{sep}code={code}{state}"))],
                    body: String::new(),
                    content_type: "text/plain",
                }
            }
            ("GET", ["oauth2", "authorize"]) => {
                // Secure look-alike: the registered redirect_uri only, and state required.
                let host = req.header("host").unwrap_or("");
                let uri = req.query.get("redirect_uri").cloned().unwrap_or_default();
                let state = req.query.get("state").cloned().unwrap_or_default();
                if uri != format!("http://{host}/oauth/callback")
                    || state.is_empty()
                    || !state.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
                {
                    return json_resp(400, json!({"error": "invalid_request"}));
                }
                Response {
                    status: 302,
                    headers: vec![("Location".into(), format!("{uri}?code=c2&state={state}"))],
                    body: String::new(),
                    content_type: "text/plain",
                }
            }
            ("GET", ["oauth", "callback"]) => Response {
                status: 200,
                headers: vec![],
                body: "<!doctype html><p>Signed in.</p>".into(),
                content_type: "text/html; charset=utf-8",
            },
            ("GET", ["api", "cart"]) => {
                // VS-36: unserialize() on a cookie.
                let cookie = req.cookie("cart").unwrap_or_else(|| "YToxOntzOjQ6Iml0ZW0iO3M6NjoiQ29mZmVlIjt9".into());
                let Some(text) = b64_decode(&cookie).and_then(|b| String::from_utf8(b).ok()) else {
                    return json_resp(400, json!({"error": "bad cart"}));
                };
                match php_unserialize_check(&text) {
                    Ok(items) => json_resp(200, json!({"cart": items})),
                    Err(at) => Response {
                        status: 500,
                        headers: vec![],
                        body: format!(
                            "<b>Notice</b>: unserialize(): Error at offset {at} of {} bytes in /var/www/cart.php on line 12",
                            text.len()
                        ),
                        content_type: "text/html",
                    },
                }
            }
            ("POST", ["api", "avatar"]) => {
                // VS-37: any file type, served back with a type from its extension.
                let Some((name, data)) = multipart_file(req) else {
                    return json_resp(400, json!({"error": "no file"}));
                };
                let name: String =
                    name.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')).collect();
                if name.is_empty() || data.len() > 256 * 1024 {
                    return json_resp(400, json!({"error": "bad file"}));
                }
                if let Ok(mut st) = self.state.lock() {
                    if st.uploads.len() > 100 {
                        st.uploads.clear();
                    }
                    st.uploads.insert(name.clone(), data);
                }
                json_resp(201, json!({"url": format!("/uploads/{name}")}))
            }
            ("GET", ["uploads", name]) => {
                let data = self.state.lock().ok().and_then(|st| st.uploads.get(*name).cloned());
                let Some(data) = data else { return json_resp(404, json!({"error": "no such file"})) };
                let content_type = match name.rsplit('.').next().unwrap_or("") {
                    "html" | "htm" => "text/html",
                    "svg" => "image/svg+xml",
                    "png" => "image/png",
                    "jpg" | "jpeg" => "image/jpeg",
                    _ => "application/octet-stream",
                };
                Response {
                    status: 200,
                    headers: vec![],
                    body: String::from_utf8_lossy(&data).into_owned(),
                    content_type,
                }
            }
            ("GET", ["spa", ..]) => Response {
                // A single-page app: buttons, History API routes, and an API only its script knows.
                status: 200,
                headers: vec![],
                body: "<!doctype html><html><head><title>VulnShop app</title></head><body><nav id=nav></nav>\
                       <main id=view>Loading…</main><script src=/static/spa.js></script></body></html>"
                    .into(),
                content_type: "text/html; charset=utf-8",
            },
            ("GET", ["static", "spa.js"]) => {
                Response { status: 200, headers: vec![], body: SPA_JS.into(), content_type: "application/javascript" }
            }
            ("GET", ["api", "spa", "catalog"]) => {
                // VS-38: SQL injection in an API only the app's script calls.
                let category = req.query.get("category").cloned().unwrap_or_default();
                if category.contains('\'') {
                    return Response {
                        status: 500,
                        headers: vec![],
                        body: format!(
                            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL \
                             server version for the right syntax to use near '{category}' at line 1"
                        ),
                        content_type: "text/plain",
                    };
                }
                let items = if category == "tea" { vec!["Green tea", "Black tea"] } else { vec!["Coffee"] };
                json_resp(200, json!({"category": category, "items": items}))
            }
            ("GET", ["help"]) => {
                // Secure look-alike: the topic is HTML-encoded.
                let topic = html_escape(&req.query.get("topic").cloned().unwrap_or_default());
                let body = format!(
                    "<!doctype html><html><head><title>Help</title></head><body><h1>Help</h1>\
                     <p>No help found for {topic}</p></body></html>"
                );
                Response { status: 200, headers: vec![], body, content_type: "text/html; charset=utf-8" }
            }
            ("POST", ["api", "login"]) => {
                let p = req.params();
                let (u, pw) =
                    (p.get("username").cloned().unwrap_or_default(), p.get("password").cloned().unwrap_or_default());
                match USERS.iter().find(|x| x.name == u && x.password == pw) {
                    Some(user) => {
                        let n = u128::from(self.counter.fetch_add(1, Ordering::Relaxed));
                        let token =
                            format!("{:x}", now_ms() ^ (u128::from(user.id) << 64) ^ (n * 0x9e37_79b9_7f4a_7c15));
                        if let Ok(mut st) = self.state.lock() {
                            st.sessions.insert(token.clone(), user.id);
                        }
                        let claims = json!({"sub": user.name, "role": user.role, "iat": (now_ms() / 1000) as u64});
                        let jwt = sign_jwt(&claims, JWT_SECRET);
                        let mut r = json_resp(200, json!({"token": token, "user": user.name, "jwt": jwt}));
                        r.headers.push(("Set-Cookie".into(), format!("session={token}; Path=/; HttpOnly")));
                        r
                    }
                    None => json_resp(401, json!({"error": "bad credentials"})),
                }
            }
            ("POST", ["api", "logout"]) => {
                if let (Some(t), Ok(mut st)) = (req.token(), self.state.lock()) {
                    st.sessions.remove(&t);
                }
                json_resp(200, json!({"ok": true}))
            }
            ("GET", ["api", "me"]) => {
                let mut r = match self.user(req) {
                    Some(u) => json_resp(
                        200,
                        json!({"id": u.id, "username": u.name, "email": format!("{}@vulnshop.test", u.name), "role": u.role, "meta": self.meta()}),
                    ),
                    None => unauthorized(),
                };
                // VS-20: any Origin is trusted, with cookies.
                if let Some(o) = req.header("origin") {
                    r.headers.push(("Access-Control-Allow-Origin".into(), o.to_string()));
                    r.headers.push(("Access-Control-Allow-Credentials".into(), "true".into()));
                }
                r
            }
            ("GET", ["api", "internal", "config"]) => {
                // VS-17: "internal only", judged by a header any client can set.
                if req.header("x-forwarded-for").is_some_and(|v| v.trim() == "127.0.0.1") {
                    json_resp(
                        200,
                        json!({"database": "postgres://shop:s3cret@db/shop", "debug": true, "feature_flags": ["beta"]}),
                    )
                } else {
                    json_resp(403, json!({"error": "internal only"}))
                }
            }
            ("GET", ["api", "lang"]) => {
                // VS-18: the value goes into a header as is (CR LF splits it).
                let lang = req.query.get("set").cloned().unwrap_or_else(|| "en".into());
                Response {
                    status: 302,
                    headers: vec![
                        ("Location".into(), "/".into()),
                        ("Set-Cookie".into(), format!("lang={lang}; Path=/")),
                    ],
                    body: String::new(),
                    content_type: "text/plain",
                }
            }
            ("GET", ["api", "share"]) => {
                // VS-19: links built from the Host header.
                let host = req.header("host").unwrap_or("localhost").to_string();
                let id = req.query.get("product").cloned().unwrap_or_else(|| "1".into());
                json_resp(200, json!({"link": format!("http://{host}/products/{id}")}))
            }
            ("POST", ["api", "v2", "login"]) => {
                // VS-21: a MongoDB-style match: operators in the JSON are run.
                let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
                    return json_resp(400, json!({"error": "send JSON"}));
                };
                let user = USERS
                    .iter()
                    .find(|u| mongo_match(&body["username"], u.name) && mongo_match(&body["password"], u.password));
                match user {
                    Some(u) => json_resp(200, json!({"token": format!("v2-{}", u.id), "user": u.name})),
                    None => json_resp(401, json!({"error": "invalid username or password"})),
                }
            }
            ("GET", ["api", "products"]) => {
                // VS-15: the User-Agent goes into a visit-log lookup as is (blind; the result isn't shown).
                let ua = req.header("user-agent").unwrap_or_default().to_string();
                let _ = demo_query(format!("SELECT count(*) FROM visits WHERE ua = '{ua}'")).await;
                let mut body = json!({"products": [
                    {"id": 1, "name": "Coffee", "price": 4.5}, {"id": 2, "name": "Tea", "price": 3.0}, {"id": 3, "name": "Cake", "price": 6.25}
                ]});
                // VS-22: an undocumented debug switch.
                if req.query.contains_key("debug") {
                    body["internal"] =
                        json!({"db_password": "s3cret", "cache": "redis://10.0.0.7:6379", "build": "4.2.1-dev"});
                }
                json_resp(200, body)
            }
            ("POST", ["api", "import"]) => {
                // VS-16: an XML parser that resolves external entities (http:// only).
                let xml = String::from_utf8_lossy(&req.body).into_owned();
                for url in external_entities(&xml) {
                    let _ = fetch(&url).await;
                }
                let items = xml.matches("<item>").count();
                json_resp(200, json!({"imported": items}))
            }
            ("GET", ["api", "tools", "ping"]) => {
                // VS-14: OS command injection into a simulated shell (nothing is executed).
                let host = req.query.get("host").cloned().unwrap_or_default();
                let out = fake_shell(&format!("ping -c 1 {host}")).await;
                Response { status: 200, headers: vec![], body: out, content_type: "text/plain" }
            }
            ("GET", ["api", "products", "search"]) => {
                // VS-3: blind SQL injection: q goes into a real query as is; errors are hidden.
                let q = req.query.get("q").cloned().unwrap_or_default();
                let results =
                    demo_query(format!("SELECT name FROM products WHERE name LIKE '%{q}%' ORDER BY id")).await;
                json_resp(200, json!({"results": results}))
            }
            ("GET", ["api", "orders"]) => match self.user(req) {
                Some(u) => {
                    let st = self.state.lock().expect("state");
                    let mine: Vec<Value> = st
                        .orders
                        .iter()
                        .filter(|o| o.owner == u.id)
                        .map(|o| json!({"id": o.id, "product": o.product, "qty": o.qty}))
                        .collect();
                    json_resp(200, json!({"orders": mine, "meta": self.meta()}))
                }
                None => unauthorized(),
            },
            ("POST", ["api", "orders"]) => match self.user(req) {
                Some(u) => {
                    let p = req.params();
                    let mut st = self.state.lock().expect("state");
                    st.next_order += 1;
                    let id = st.next_order;
                    let order = Order {
                        id,
                        owner: u.id,
                        product: p.get("product_id").and_then(|x| x.parse().ok()).unwrap_or(1),
                        qty: p.get("qty").and_then(|x| x.parse().ok()).unwrap_or(1),
                    };
                    st.orders.push(order);
                    json_resp(201, json!({"id": id, "owner": u.name}))
                }
                None => unauthorized(),
            },
            ("GET", ["api", "orders", id]) => {
                // VS-1: IDOR. Logged in is checked; ownership is not.
                let Some(_) = self.user(req) else { return unauthorized() };
                let st = self.state.lock().expect("state");
                let order = id.parse::<u32>().ok().and_then(|id| st.orders.iter().find(|o| o.id == id).cloned());
                match order {
                    Some(o) => {
                        let owner = USERS.iter().find(|u| u.id == o.owner).map(|u| u.name).unwrap_or("?");
                        json_resp(
                            200,
                            json!({"id": o.id, "owner": owner, "email": format!("{owner}@vulnshop.test"),
                            "address": format!("{} Example Street", o.owner * 10), "product": o.product, "qty": o.qty, "meta": self.meta()}),
                        )
                    }
                    None => json_resp(404, json!({"error": "not found"})),
                }
            }
            ("GET", ["api", "invoices", id]) => {
                // Secure: owner or admin only.
                let Some(u) = self.user(req) else { return unauthorized() };
                let st = self.state.lock().expect("state");
                match id.parse::<u32>().ok().and_then(|id| st.invoices.iter().find(|i| i.0 == id)) {
                    Some(inv) if inv.1 == u.id || u.role == "admin" => {
                        json_resp(200, json!({"id": inv.0, "amount": inv.2, "meta": self.meta()}))
                    }
                    Some(_) => json_resp(403, json!({"error": "forbidden"})),
                    None => json_resp(404, json!({"error": "not found"})),
                }
            }
            ("GET", ["api", "admin", "users"]) => {
                // VS-2: no role check.
                match self.user(req) {
                    Some(_) => json_resp(
                        200,
                        json!({"users": USERS.iter().map(|u| json!({"id": u.id, "username": u.name, "role": u.role})).collect::<Vec<_>>(), "meta": self.meta()}),
                    ),
                    None => unauthorized(),
                }
            }
            ("GET", ["api", "admin", "stats"]) => match self.user(req) {
                Some(u) if u.role == "admin" => json_resp(
                    200,
                    json!({"orders": self.state.lock().map(|s| s.orders.len()).unwrap_or(0), "meta": self.meta()}),
                ),
                Some(_) => json_resp(403, json!({"error": "admins only"})),
                None => unauthorized(),
            },
            ("POST", ["api", "giftcard", "redeem"]) => {
                let Some(user) = self.user(req) else { return unauthorized() };
                if req.params().get("code").map(String::as_str) != Some("WELCOME10") {
                    return json_resp(404, json!({"error": "unknown gift card"}));
                }
                // VS-5: race condition. Check, pause (a slow payment call), then
                // write, with no lock held across the gap.
                let used = self.state.lock().map(|s| s.redeemed.contains(&user.id)).unwrap_or(true);
                if used {
                    return json_resp(409, json!({"error": "gift card already redeemed"}));
                }
                tokio::time::sleep(Duration::from_millis(150)).await;
                let credit = self
                    .state
                    .lock()
                    .map(|mut s| {
                        s.redeemed.insert(user.id);
                        let c = s.credit.entry(user.id).or_default();
                        *c += 10;
                        *c
                    })
                    .unwrap_or(0);
                json_resp(200, json!({"redeemed": "WELCOME10", "credit": credit, "meta": self.meta()}))
            }
            ("GET", ["api", "fetch"]) => {
                // VS-4: SSRF. Fetches any http:// URL.
                let url = req.query.get("url").cloned().unwrap_or_default();
                match fetch(&url).await {
                    Ok(status) => json_resp(200, json!({"fetched": url, "status_line": status})),
                    Err(e) => json_resp(502, json!({"error": e})),
                }
            }
            ("GET", [".git", "config"]) => {
                // VS-13: source control metadata left on the server, with a credential.
                Response {
                    status: 200,
                    headers: vec![],
                    body: "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = \
                           https://deploy:vs13-deploy-token-0f9a@git.vulnshop.test/shop.git\n"
                        .into(),
                    content_type: "text/plain",
                }
            }
            ("GET", [".git", "HEAD"]) => Response {
                status: 200,
                headers: vec![],
                body: "ref: refs/heads/main\n".into(),
                content_type: "text/plain",
            },
            ("GET", ["app", "config.json"]) => json_resp(200, json!({"apiBase": "/api", "features": ["cart"]})),
            ("GET", ["app", ..]) => {
                // A single-page app: every other path gets the same shell with
                // status 200 (a soft 404, a trap for content discovery).
                Response {
                    status: 200,
                    headers: vec![],
                    body: format!(
                        "<!doctype html><title>VulnShop</title><div id=app data-path=\"{}\"></div>",
                        html_escape(&req.path)
                    ),
                    content_type: "text/html; charset=utf-8",
                }
            }
            _ => json_resp(404, json!({"error": "not found"})),
        }
    }
}

/// Minimal HTTP GET used by the SSRF endpoint (http only, 3 s timeout).
async fn fetch(url: &str) -> Result<String, String> {
    let rest = url.strip_prefix("http://").ok_or("only http:// URLs are fetched")?;
    let (authority, path) = rest.split_once('/').map(|(a, p)| (a, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let (host, port) = pm_http::split_host_port(authority, 80).ok_or("bad host")?;
    let fut = async {
        let mut s = TcpStream::connect((host.as_str(), port)).await.map_err(|e| e.to_string())?;
        s.write_all(format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 1024];
        let n = s.read(&mut buf).await.map_err(|e| e.to_string())?;
        Ok(String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or_default().to_string())
    };
    tokio::time::timeout(Duration::from_secs(3), fut).await.map_err(|_| "timeout".to_string())?
}

/// An unmasked server frame.
fn ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => v.push(n as u8),
        n if n <= 0xFFFF => {
            v.push(126);
            v.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            v.push(127);
            v.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    v.extend_from_slice(payload);
    v
}

/// `Sec-WebSocket-Accept` for a client key (RFC 6455 section 4.2.2).
fn ws_accept(key: &str) -> String {
    let digest = sha1_smol::Sha1::from(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11")).digest().bytes();
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in digest.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn websocket_accept_matches_the_rfc_example() {
        assert_eq!(super::ws_accept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    use super::*;

    async fn call(addr: SocketAddr, raw: String) -> String {
        let mut s = TcpStream::connect(addr).await.unwrap();
        s.write_all(raw.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    async fn login(addr: SocketAddr, user: &str) -> String {
        let body = format!("{{\"username\":\"{user}\",\"password\":\"{user}123\"}}");
        let r = call(addr, format!("POST /api/login HTTP/1.1\r\nContent-Length: {}\r\n\r\n{body}", body.len())).await;
        r.split("session=").nth(1).unwrap().split(';').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn planted_bugs_and_secure_endpoints_behave() {
        let addr = VulnShop::start_local().await.unwrap();
        let bob = login(addr, "bob").await;
        let get = |path: &str, tok: &str| format!("GET {path} HTTP/1.1\r\nCookie: session={tok}\r\n\r\n");
        assert!(call(addr, get("/api/orders/1001", &bob)).await.contains("\"owner\":\"alice\""), "IDOR");
        assert!(call(addr, get("/api/invoices/5001", &bob)).await.starts_with("HTTP/1.1 403"), "invoice secure");
        assert!(call(addr, get("/api/admin/users", &bob)).await.starts_with("HTTP/1.1 200"), "admin list open");
        assert!(call(addr, get("/api/admin/stats", &bob)).await.starts_with("HTTP/1.1 403"), "stats secure");
        assert!(call(addr, "GET /api/orders/1001 HTTP/1.1\r\n\r\n".into()).await.starts_with("HTTP/1.1 401"));
        // VS-3: a real query: delays and true/false conditions, errors hidden.
        let search = |q: &str| call(addr, format!("GET /api/products/search?q={q} HTTP/1.1\r\n\r\n"));
        let t = std::time::Instant::now();
        search("Coffee%27%20AND%20SLEEP(1)--%20").await;
        assert!(t.elapsed() >= Duration::from_millis(1000));
        assert!(search("Coffee%27%20AND%201=1--").await.contains("[\"Coffee\"]"));
        assert!(search("Coffee%27%20AND%201=2--").await.contains("\"results\":[]"));
        assert!(search("%27").await.contains("\"results\":[]"), "errors are hidden");
        // VS-15: the User-Agent goes into SQL.
        let t = std::time::Instant::now();
        call(addr, "GET /api/products HTTP/1.1\r\nUser-Agent: x'||SLEEP(1)||'\r\n\r\n".into()).await;
        assert!(t.elapsed() >= Duration::from_millis(1000));
        // VS-14: a simulated shell.
        let ping = |h: &str| call(addr, format!("GET /api/tools/ping?host={h} HTTP/1.1\r\n\r\n"));
        assert!(ping("127.0.0.1").await.contains("PING 127.0.0.1: 1 packets"));
        assert!(ping("x;echo%20M$((7*191))").await.contains("\nM1337"));
        assert!(ping("x$(echo%20M$((7*191)))").await.contains("PING xM1337"));
        assert!(ping("x;cat%20/etc/passwd").await.contains("sh: cat: not found"));
        let t = std::time::Instant::now();
        ping("x|sleep%201").await;
        assert!(t.elapsed() >= Duration::from_millis(1000));
    }
}
