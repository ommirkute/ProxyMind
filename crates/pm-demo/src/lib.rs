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
];

/// Endpoints that look similar but are correctly protected (false-positive traps).
pub const SECURE_ENDPOINTS: &[&str] =
    &["GET /api/invoices/{id}", "GET /api/admin/stats", "GET /api/orders", "GET /help", "GET /out", "GET /docs"];

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
    "/api/giftcard/redeem": {"post": {"summary": "Redeem the welcome gift card"}}
  }
}"##;

const HOME: &str = "<!doctype html><html><head><title>VulnShop</title></head><body>\
<h1>VulnShop</h1><p>A deliberately vulnerable demo shop. Do not expose it to a network.</p>\
<form method=post action=/api/login><input name=username><input type=password name=password>\
<button>Log in</button></form><a href=/api/products>Products</a> \
<form action=/search><input name=q><button>Search</button></form> <a href=\"/search?q=coffee\">Coffee</a> \
<a href='/help?topic=orders'>Help</a> <a href='/api/tools/ping?host=127.0.0.1'>Network check</a> <a href=/api/logout>Log out</a> <a href=https://example.org/>Elsewhere</a> \
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
        let resp = self.route(&req).await;
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
                if url.starts_with('/') && !url.starts_with("//") && !url.contains('\\') {
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
                body: "User-agent: *\nDisallow: /api/admin/\nDisallow: /*.bak$\n".into(),
                content_type: "text/plain",
            },
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
                        let mut r = json_resp(200, json!({"token": token, "user": user.name}));
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
            ("GET", ["api", "me"]) => match self.user(req) {
                Some(u) => json_resp(
                    200,
                    json!({"id": u.id, "username": u.name, "email": format!("{}@vulnshop.test", u.name), "role": u.role, "meta": self.meta()}),
                ),
                None => unauthorized(),
            },
            ("GET", ["api", "products"]) => {
                // VS-15: the User-Agent goes into a visit-log lookup as is (blind; the result isn't shown).
                let ua = req.header("user-agent").unwrap_or_default().to_string();
                let _ = demo_query(format!("SELECT count(*) FROM visits WHERE ua = '{ua}'")).await;
                json_resp(
                    200,
                    json!({"products": [
                        {"id": 1, "name": "Coffee", "price": 4.5}, {"id": 2, "name": "Tea", "price": 3.0}, {"id": 3, "name": "Cake", "price": 6.25}
                    ]}),
                )
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
