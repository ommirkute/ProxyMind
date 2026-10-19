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
        class: "sqli_time_based",
        method: "GET",
        path: "/api/products/search",
        description: "The q parameter is concatenated into a query; SLEEP() payloads delay the response.",
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
];

/// Endpoints that look similar but are correctly protected (false-positive traps).
pub const SECURE_ENDPOINTS: &[&str] =
    &["GET /api/invoices/{id}", "GET /api/admin/stats", "GET /api/orders", "GET /help"];

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

const HOME: &str = "<!doctype html><html><head><title>VulnShop</title></head><body>\
<h1>VulnShop</h1><p>A deliberately vulnerable demo shop. Do not expose it to a network.</p>\
<form method=post action=/api/login><input name=username><input type=password name=password>\
<button>Log in</button></form><a href=/api/products>Products</a></body></html>";

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
            ("GET", ["api", "products"]) => json_resp(
                200,
                json!({"products": [
                    {"id": 1, "name": "Coffee", "price": 4.5}, {"id": 2, "name": "Tea", "price": 3.0}, {"id": 3, "name": "Cake", "price": 6.25}
                ]}),
            ),
            ("GET", ["api", "products", "search"]) => {
                // VS-3: fake time-based SQL injection.
                let q = req.query.get("q").cloned().unwrap_or_default();
                if q.to_ascii_lowercase().contains("sleep(") {
                    tokio::time::sleep(Duration::from_millis(1200)).await;
                }
                if q.contains('\'') && !q.to_ascii_lowercase().contains("sleep(") {
                    return json_resp(200, json!({"results": [], "note": "no results"}));
                }
                let results: Vec<&str> = ["Coffee", "Tea", "Cake"]
                    .into_iter()
                    .filter(|n| n.to_lowercase().contains(&q.to_lowercase()))
                    .collect();
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
        let t = std::time::Instant::now();
        call(addr, "GET /api/products/search?q=x%27%20AND%20SLEEP(1)--%20 HTTP/1.1\r\n\r\n".into()).await;
        assert!(t.elapsed() >= Duration::from_millis(1100));
    }
}
