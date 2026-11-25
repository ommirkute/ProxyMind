//! Server mode (ADR-0022 step 4) over real sockets: sessions, cookies, CSRF, setup, invites, TLS and pinning.
//!
//! Time is a manual clock and Argon2 runs at test cost, so nothing here sleeps or hashes for long.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use pm_accounts::{Accounts, Clock, Config, ManualClock, ServerKey, totp};
use pm_api::listen::{ListenInput, TlsKind, plan, serve_app};
use pm_api::{AppState, ServerMode};
use pm_service::Service;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_tls::server::{Pin, ServerTls, pin_client_config};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PW: &str = "correct horse battery staple";
const PW2: &str = "another long passphrase here";
const T0: i64 = 1_700_000_000;

// ---- captured log lines (the secrets test greps them) ------------------------------------------------------------

fn captured() -> &'static Arc<Mutex<Vec<String>>> {
    static LINES: OnceLock<Arc<Mutex<Vec<String>>>> = OnceLock::new();
    LINES.get_or_init(|| {
        struct Capture(Arc<Mutex<Vec<String>>>);
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={v:?} ", f.name()));
            }
        }
        impl tracing::Subscriber for Capture {
            fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                tracing::span::Id::from_u64(1)
            }
            fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
            fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
            fn event(&self, e: &tracing::Event<'_>) {
                let mut f = Fields(String::new());
                e.record(&mut f);
                self.0.lock().unwrap().push(format!("{} {}", e.metadata().target(), f.0));
            }
            fn enter(&self, _: &tracing::span::Id) {}
            fn exit(&self, _: &tracing::span::Id) {}
        }
        let lines = Arc::new(Mutex::new(Vec::new()));
        let _ = tracing::subscriber::set_global_default(Capture(lines.clone()));
        lines
    })
}

// ---- a tiny HTTP/1.1 client --------------------------------------------------------------------------------------

#[derive(Debug)]
struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn all(&self, name: &str) -> Vec<&str> {
        self.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).collect()
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.all(name).into_iter().next()
    }
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }
    fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_string()
    }
    /// The whole `Set-Cookie` line for `name`, and its value.
    fn set_cookie(&self, name: &str) -> Option<(String, String)> {
        self.all("set-cookie").into_iter().find_map(|line| {
            let (pair, _) = line.split_once(';').unwrap_or((line, ""));
            let (k, v) = pair.split_once('=')?;
            (k == name).then(|| (line.to_string(), v.to_string()))
        })
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(mut s: S, req: String) -> Resp {
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let status = lines.next().and_then(|l| l.split(' ').nth(1)).and_then(|s| s.parse().ok()).unwrap_or(0);
    let headers =
        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
    Resp { status, headers, body: body.to_string() }
}

fn b32_decode(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buf, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.bytes() {
        buf = (buf << 5) | A.iter().position(|a| *a == c).unwrap() as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

// ---- the server under test ---------------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Plain,
    SelfSigned,
    OwnCert,
    /// Behind a proxy that is `127.0.0.1` (this test's client).
    Proxy,
    /// Behind a proxy that is some other machine: the test client is not it.
    ProxyOther,
}

struct Harness {
    port: u16,
    kind: Kind,
    host: String,
    origin: String,
    accounts: Arc<Accounts>,
    clock: Arc<ManualClock>,
    project: String,
    pin: Option<Pin>,
    dir: PathBuf,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn cheap_config() -> Config {
    Config::insecure_for_tests()
}

impl Harness {
    async fn start(kind: Kind) -> Self {
        Self::start_with(kind, cheap_config()).await
    }

    async fn start_with(kind: Kind, cfg: Config) -> Self {
        let clock = Arc::new(ManualClock::new(T0));
        let accounts = Arc::new(Accounts::open_in_memory(ServerKey::from_bytes([7; 32]), cfg, clock.clone()).unwrap());
        let svc = Service::new(
            Store::open_in_memory().unwrap(),
            Policy::new(Roe::parse("version: 1\nscope:\n  include: [\"http://127.0.0.1:9/\"]\n").unwrap()),
        )
        .unwrap();
        let project = svc.project_id().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let dir = std::env::temp_dir().join(format!("pm-api-server-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let public = match kind {
            Kind::Plain => None,
            Kind::SelfSigned | Kind::OwnCert => Some(format!("https://localhost:{port}")),
            Kind::Proxy | Kind::ProxyOther => Some("https://pm.test".to_string()),
        };
        let trusted: Vec<IpAddr> = match kind {
            Kind::Proxy => vec!["127.0.0.1".parse().unwrap()],
            Kind::ProxyOther => vec!["10.9.9.9".parse().unwrap()],
            _ => vec![],
        };
        let tls_kind = match kind {
            Kind::SelfSigned => TlsKind::SelfSigned,
            Kind::OwnCert => TlsKind::Own,
            _ => TlsKind::None,
        };
        let listen: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let plan = plan(&ListenInput {
            listen,
            tls: tls_kind,
            behind_proxy: matches!(kind, Kind::Proxy | Kind::ProxyOther),
            trusted_proxies: &trusted,
            public_url: public.as_deref(),
            extra_hosts: &[],
        })
        .unwrap();
        let (host, origin) = match &public {
            Some(u) if matches!(kind, Kind::Proxy | Kind::ProxyOther) => ("pm.test".to_string(), u.clone()),
            Some(u) => (format!("localhost:{port}"), u.clone()),
            None => (format!("127.0.0.1:{port}"), format!("http://127.0.0.1:{port}")),
        };
        let (tls_config, pin) = match tls_kind {
            TlsKind::None => (None, None),
            TlsKind::SelfSigned => {
                let (tls, made) = ServerTls::self_signed(&dir, &plan.certificate_names(listen)).unwrap();
                (Some(tls.config), Some(made.pin))
            }
            TlsKind::Own => {
                // An operator's certificate: files made elsewhere, loaded as PEM.
                let made = pm_tls::server::SelfSigned::load_or_create(&dir, &plan.certificate_names(listen)).unwrap();
                let tls = ServerTls::from_files(&made.cert_path, &made.key_path).unwrap();
                assert!(!tls.self_signed);
                (Some(tls.config), Some(made.pin))
            }
        };
        let sm = ServerMode::new(accounts.clone(), clock.clone() as Arc<dyn Clock>, project.clone(), plan);
        let state = AppState::new(
            Arc::new(svc),
            Actor::parse("human:unused").unwrap(),
            "install-token-that-server-mode-must-refuse".into(),
            "test.pmproj".into(),
        )
        .unwrap()
        .with_server_mode(sm);
        tokio::spawn(async move { serve_app(listener, pm_api::router(state), tls_config).await.unwrap() });
        Self { port, kind, host, origin, accounts, clock, project, pin, dir }
    }

    fn secure(&self) -> bool {
        self.kind != Kind::Plain
    }

    fn cookie_name(&self) -> &'static str {
        if self.secure() { "__Host-pm_session" } else { "pm_session" }
    }

    async fn connect_tls(&self, pin: Pin) -> std::io::Result<pm_tls::server::ClientTlsStream<TcpStream>> {
        let tcp = TcpStream::connect(("127.0.0.1", self.port)).await?;
        let cfg = pin_client_config(pin, &[b"http/1.1"]).unwrap();
        pm_tls::TlsConnector::from(cfg).connect(pm_tls::server_name("localhost").unwrap(), tcp).await
    }

    /// Sends exactly these headers (plus Host and the framing ones) and reads the answer.
    async fn raw(&self, method: &str, path: &str, headers: &[(&str, String)], body: Option<Value>) -> Resp {
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let mut req = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
        if !headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("host")) {
            req.push_str(&format!("Host: {}\r\n", self.host));
        }
        if !body.is_empty() {
            req.push_str("Content-Type: application/json\r\n");
        }
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(&body);
        match (self.pin, self.kind) {
            (Some(pin), Kind::SelfSigned | Kind::OwnCert) => exchange(self.connect_tls(pin).await.unwrap(), req).await,
            _ => exchange(TcpStream::connect(("127.0.0.1", self.port)).await.unwrap(), req).await,
        }
    }

    /// What a browser's script on the right origin sends (and what a reverse proxy adds).
    fn browser(&self) -> Vec<(&'static str, String)> {
        let mut h = vec![("X-ProxyMind", "1".to_string()), ("Origin", self.origin.clone())];
        if matches!(self.kind, Kind::Proxy | Kind::ProxyOther) {
            h.push(("X-Forwarded-Proto", "https".into()));
            h.push(("X-Forwarded-For", "198.51.100.7".into()));
        }
        h
    }

    /// A same-origin API call, with the session cookie when there is one.
    async fn api(&self, cookie: Option<&str>, method: &str, path: &str, body: Option<Value>) -> Resp {
        let mut h = self.browser();
        if let Some(c) = cookie {
            h.push(("Cookie", format!("{}={c}", self.cookie_name())));
        }
        self.raw(method, path, &h, body).await
    }

    fn code(&self, secret_b32: &str) -> String {
        format!("{:06}", totp(&b32_decode(secret_b32), self.clock.now() as u64, 30, 6))
    }

    /// Setup as the CLI would offer it: a one-time token, then the account, then the first enrolment.
    async fn setup_owner(&self) -> Signed {
        let tok = self.accounts.create_setup_token().unwrap();
        let r = self
            .api(
                None,
                "POST",
                "/api/v1/auth/setup",
                Some(json!({"setup_token": tok.token.expose(), "username": "owner", "display_name": "Owner", "password": PW})),
            )
            .await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.json()["step"], "enrolment_required");
        let pending = r.json()["pending"].as_str().unwrap().to_string();
        self.finish_enrolment(&pending, "owner").await
    }

    async fn finish_enrolment(&self, pending: &str, username: &str) -> Signed {
        let r = self.api(None, "POST", "/api/v1/auth/login/enrol", Some(json!({ "pending": pending }))).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let secret = r.json()["secret_base32"].as_str().unwrap().to_string();
        assert!(r.json()["otpauth_uri"].as_str().unwrap().starts_with("otpauth://totp/"));
        let qr = r.json()["qr_svg"].as_str().unwrap().to_string();
        assert!(qr.starts_with("<svg ") && !qr.contains("<script"), "a self-contained QR code of the URI");
        let code = self.code(&secret);
        let r = self
            .api(None, "POST", "/api/v1/auth/login/enrol/confirm", Some(json!({ "pending": pending, "code": code })))
            .await;
        assert_eq!(r.status, 200, "{}", r.body);
        let v = r.json();
        assert_eq!(v["step"], "authenticated");
        let codes: Vec<String> =
            v["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().into()).collect();
        assert_eq!(codes.len(), 10);
        let (_, cookie) = r.set_cookie(self.cookie_name()).expect("a session cookie");
        Signed { username: username.into(), cookie, secret, codes, user_id: v["user"]["id"].as_str().unwrap().into() }
    }

    /// Password step plus TOTP; the clock moves to a new 30-second step first (a used step is never accepted twice).
    async fn login(&self, who: &Signed, password: &str) -> Resp {
        self.clock.advance(31);
        let r = self
            .api(None, "POST", "/api/v1/auth/login", Some(json!({"username": who.username, "password": password})))
            .await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.json()["step"], "second_factor_required", "{}", r.body);
        let pending = r.json()["pending"].as_str().unwrap().to_string();
        self.api(
            None,
            "POST",
            "/api/v1/auth/login/second-factor",
            Some(json!({"pending": pending, "code": self.code(&who.secret)})),
        )
        .await
    }

    async fn relogin(&self, who: &mut Signed) -> String {
        let r = self.login(who, PW).await;
        assert_eq!(r.status, 200, "{}", r.body);
        who.cookie = r.set_cookie(self.cookie_name()).unwrap().1;
        who.cookie.clone()
    }

    /// An invite for `role` on this project, accepted and enrolled: a signed-in second user.
    async fn invited_user(&self, owner: &Signed, name: &str, role: &str) -> Signed {
        let r = self.api(Some(&owner.cookie), "POST", "/api/v1/auth/invites", Some(json!({"role": role}))).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let token = r.json()["token"].as_str().unwrap().to_string();
        let r = self
            .api(
                None,
                "POST",
                "/api/v1/auth/invite/accept",
                Some(json!({"invite": token, "username": name, "password": PW})),
            )
            .await;
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(r.json()["step"], "enrolment_required");
        self.finish_enrolment(r.json()["pending"].as_str().unwrap(), name).await
    }
}

struct Signed {
    username: String,
    cookie: String,
    secret: String,
    codes: Vec<String>,
    user_id: String,
}

// ---- the route matrix ----------------------------------------------------------------------------------------------

/// The auth endpoints that work without a session. Every other route must be 401 without one.
const PUBLIC: [(&str, &str); 7] = [
    ("get", "/api/v1/auth/state"),
    ("post", "/api/v1/auth/setup"),
    ("post", "/api/v1/auth/login"),
    ("post", "/api/v1/auth/login/second-factor"),
    ("post", "/api/v1/auth/login/enrol"),
    ("post", "/api/v1/auth/login/enrol/confirm"),
    ("post", "/api/v1/auth/invite/accept"),
];

fn concrete(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(i) = rest.find('{') {
        out.push_str(&rest[..i]);
        out.push('1');
        rest = &rest[rest.find('}').unwrap() + 1..];
    }
    out.push_str(rest);
    out
}

#[tokio::test]
async fn every_route_but_the_sign_in_ones_is_401_without_a_session() {
    let h = Harness::start(Kind::Plain).await;
    h.setup_owner().await;
    let ops = pm_api::contracts::operations();
    assert!(ops.len() > 180, "the walker found only {} operations", ops.len());
    let mut checked = 0;
    for op in &ops {
        let path = concrete(&op.path);
        let body = (op.method != "get" && op.method != "delete").then(|| json!({}));
        let public = PUBLIC.contains(&(op.method, op.path.as_str()));
        // A page's script on the right origin, with no cookie.
        let r = h.api(None, &op.method.to_uppercase(), &path, body.clone()).await;
        if public {
            assert!(
                r.status != 401 || r.code() == "invalid_pending",
                "{} {} is public: {} {}",
                op.method,
                op.path,
                r.status,
                r.body
            );
        } else {
            assert_eq!(r.status, 401, "{} {} answered {} {}", op.method, op.path, r.status, r.body);
            assert_eq!(r.code(), "unauthenticated", "{} {}", op.method, op.path);
            checked += 1;
        }
        // The install token is not a credential here, as a bearer or any other way.
        let mut headers = h.browser();
        headers.push(("Authorization", "Bearer install-token-that-server-mode-must-refuse".into()));
        let r = h.raw(&op.method.to_uppercase(), &path, &headers, body).await;
        if !public {
            assert_eq!(r.status, 401, "bearer {} {}", op.method, op.path);
        }
    }
    assert!(checked > 170, "{checked}");
    // A cookie that is not a session is refused too, and the browser is told to drop it.
    let r = h.api(Some(&"0".repeat(64)), "GET", "/api/v1/status", None).await;
    assert_eq!(r.status, 401);
    let (line, value) = r.set_cookie("pm_session").expect("a clearing Set-Cookie");
    assert!(value.is_empty() && line.contains("Max-Age=0"), "{line}");
    // The launch link of single-user mode opens nothing.
    let r = h.raw("GET", "/auth?token=install-token-that-server-mode-must-refuse", &[], None).await;
    assert_eq!(r.status, 404);
    assert!(r.all("set-cookie").is_empty());
}

#[tokio::test]
async fn single_user_mode_is_unchanged_and_has_no_account_endpoints() {
    const TOKEN: &str = "t0k3n-for-tests-0123456789abcdef0123456789";
    let svc = Service::new(
        Store::open_in_memory().unwrap(),
        Policy::new(Roe::parse("version: 1\nscope:\n  include: [\"http://127.0.0.1:9/\"]\n").unwrap()),
    )
    .unwrap();
    let state = AppState::new(Arc::new(svc), Actor::parse("human:tester").unwrap(), TOKEN.into(), "p".into()).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, pm_api::router(state)).await.unwrap() });
    let call = |method: &'static str, path: String, headers: Vec<(&'static str, String)>| async move {
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: 2\r\nContent-Type: application/json\r\nHost: 127.0.0.1:{port}\r\n"
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n{}");
        exchange(TcpStream::connect(("127.0.0.1", port)).await.unwrap(), req).await
    };
    for op in pm_api::contracts::operations() {
        let path = concrete(&op.path);
        let m = op.method.to_uppercase();
        let m: &'static str = Box::leak(m.into_boxed_str());
        // No token: 401 from the old guard, for every route, the new ones too.
        let r = call(m, path.clone(), vec![("X-ProxyMind", "1".into())]).await;
        assert_eq!(r.status, 401, "{} {}", op.method, op.path);
        assert_eq!(r.body, "missing or wrong ProxyMind token");
        // With the token, the account endpoints are simply not there; the state probe says "not server mode".
        if op.path == "/api/v1/auth/state" && m == "GET" {
            let r =
                call(m, path, vec![("X-ProxyMind", "1".into()), ("Authorization", format!("Bearer {TOKEN}"))]).await;
            assert_eq!(r.status, 200, "{}", r.body);
            assert_eq!(r.json()["server_mode"], false);
        } else if op.path.starts_with("/api/v1/auth/") {
            let r =
                call(m, path, vec![("X-ProxyMind", "1".into()), ("Authorization", format!("Bearer {TOKEN}"))]).await;
            assert_eq!(r.status, 404, "{} {}: {}", op.method, op.path, r.body);
            assert_eq!(r.code(), "not_server_mode");
        }
    }
    // The install token still works.
    let r = call("GET", "/api/v1/status".into(), vec![("Authorization", format!("Bearer {TOKEN}"))]).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["you_are"], "human:tester");
    let r = call("GET", format!("/auth?token={TOKEN}"), vec![]).await;
    assert_eq!(r.status, 303);
}

// ---- bootstrap -----------------------------------------------------------------------------------------------------

#[tokio::test]
async fn before_setup_only_the_setup_endpoints_answer() {
    let h = Harness::start(Kind::Plain).await;
    let r = h.api(None, "GET", "/api/v1/auth/state", None).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json(), json!({"server_mode": true, "setup_required": true, "setup_allowed": true}));
    for (m, p) in [
        ("GET", "/api/v1/status"),
        ("GET", "/api/v1/exchanges"),
        ("POST", "/api/v1/auth/login"),
        ("POST", "/api/v1/auth/invite/accept"),
        ("GET", "/api/v1/auth/me"),
    ] {
        let r = h.api(None, m, p, Some(json!({}))).await;
        assert_eq!(r.status, 503, "{m} {p}");
        assert_eq!(r.code(), "setup_required");
    }
    // A wrong token is refused with one message and counts against the address.
    for _ in 0..3 {
        let r = h
            .api(
                None,
                "POST",
                "/api/v1/auth/setup",
                Some(json!({"setup_token": "pmset_nope", "username": "owner", "password": PW})),
            )
            .await;
        assert_eq!(r.status, 403);
        assert_eq!(r.code(), "invalid_setup_token");
    }
    // Setup still needs the CSRF layers.
    let r = h.raw("POST", "/api/v1/auth/setup", &[], Some(json!({}))).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.code(), "csrf");
    // After the owner exists the setup token is dead and the server is open for sign-in.
    let tok = h.accounts.create_setup_token().unwrap();
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/setup",
            Some(json!({"setup_token": tok.token.expose(), "username": "owner", "password": "short"})),
        )
        .await;
    assert_eq!(r.status, 400, "a weak password leaves the token unused: {}", r.body);
    let owner = {
        let r = h
            .api(
                None,
                "POST",
                "/api/v1/auth/setup",
                Some(json!({"setup_token": tok.token.expose(), "username": "owner", "password": PW})),
            )
            .await;
        assert_eq!(r.status, 200, "{}", r.body);
        h.finish_enrolment(r.json()["pending"].as_str().unwrap(), "owner").await
    };
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/setup",
            Some(json!({"setup_token": tok.token.expose(), "username": "again", "password": PW})),
        )
        .await;
    assert_eq!(r.status, 403, "a used token is dead: {}", r.body);
    assert_eq!(h.api(None, "GET", "/api/v1/auth/state", None).await.json()["setup_required"], false);
    // The owner owns the served project.
    let me = h.api(Some(&owner.cookie), "GET", "/api/v1/auth/me", None).await.json();
    assert_eq!(me["role"], "owner");
    assert_eq!(me["user"]["server_admin"], true);
    assert_eq!(me["project_id"], h.project.as_str());
}

#[tokio::test]
async fn reset_owner_gives_a_new_setup_token_and_ends_every_session() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    assert_eq!(h.api(Some(&owner.cookie), "GET", "/api/v1/status", None).await.status, 200);
    let tok = h.accounts.reset_owner().unwrap();
    assert_eq!(h.api(Some(&owner.cookie), "GET", "/api/v1/status", None).await.status, 401);
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/setup",
            Some(json!({"setup_token": tok.token.expose(), "username": "second", "password": PW})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let second = h.finish_enrolment(r.json()["pending"].as_str().unwrap(), "second").await;
    // The new owner has the project; the old one can be disabled by it.
    let me = h.api(Some(&second.cookie), "GET", "/api/v1/auth/me", None).await.json();
    assert_eq!(me["role"], "owner");
    let r = h.api(Some(&second.cookie), "POST", &format!("/api/v1/auth/users/{}/disable", owner.user_id), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let entries: Vec<String> = h.accounts.security_log(100).unwrap().into_iter().map(|e| e.kind).collect();
    assert!(entries.contains(&"owner_reset".to_string()) && entries.contains(&"user_disabled".to_string()));
}

// ---- the sign-in flow ----------------------------------------------------------------------------------------------

#[tokio::test]
async fn bootstrap_enrol_login_session_logout() {
    let h = Harness::start(Kind::Plain).await;
    let h = &h;
    let mut owner = h.setup_owner().await;
    // The enrolment's session works and acts as the account.
    let r = h.api(Some(&owner.cookie), "GET", "/api/v1/status", None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["you_are"], "human:owner");
    assert_eq!(r.header("cache-control"), Some("no-store"));
    // Logout ends it.
    let r = h.api(Some(&owner.cookie), "POST", "/api/v1/auth/logout", None).await;
    assert_eq!(r.status, 200);
    assert!(r.set_cookie("pm_session").unwrap().1.is_empty());
    assert_eq!(h.api(Some(&owner.cookie), "GET", "/api/v1/status", None).await.status, 401);
    // Password, then second factor, then a session that works.
    let cookie = h.relogin(&mut owner).await;
    assert_eq!(h.api(Some(&cookie), "GET", "/api/v1/status", None).await.status, 200);
    // A recovery code signs in once; the same code is dead afterwards.
    let code = owner.codes[0].clone();
    let step = |code: String| async move {
        let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": PW}))).await;
        let pending = r.json()["pending"].as_str().unwrap().to_string();
        h.api(None, "POST", "/api/v1/auth/login/second-factor", Some(json!({"pending": pending, "code": code}))).await
    };
    assert_eq!(step(code.clone()).await.status, 200);
    assert_eq!(step(code).await.status, 401);
    // A wrong TOTP code, and a code of an old step, are refused.
    h.clock.advance(31);
    assert_eq!(step("000000".into()).await.status, 401);
    assert!(h.accounts.verify_security_log().unwrap().is_ok(), "the security log chain verifies");
    let kinds: Vec<String> = h.accounts.security_log(200).unwrap().into_iter().map(|e| e.kind).collect();
    for want in [
        "owner_created",
        "totp_enabled",
        "login_success",
        "session_revoked",
        "recovery_code_used",
        "second_factor_failure",
    ] {
        assert!(kinds.iter().any(|k| k == want), "{want} is in the security log: {kinds:?}");
    }
}

#[tokio::test]
async fn bad_credentials_look_the_same_and_are_throttled() {
    let h = Harness::start(Kind::Plain).await;
    let h = &h;
    let owner = h.setup_owner().await;
    let invited = h.invited_user(&owner, "alice", "tester").await;
    h.api(Some(&owner.cookie), "POST", &format!("/api/v1/auth/users/{}/disable", invited.user_id), None).await;
    let attempt = |user: &'static str, pw: &'static str| async move {
        let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": user, "password": pw}))).await;
        (r.status, r.body)
    };
    let wrong = attempt("owner", "not the password at all").await;
    let unknown = attempt("nobody-here", "not the password at all").await;
    let disabled = attempt("alice", PW).await;
    assert_eq!(wrong.0, 401);
    assert_eq!(wrong, unknown, "an unknown account looks like a wrong password");
    assert_eq!(wrong, disabled, "a disabled account does too, even with its right password");
    assert_eq!(serde_json::from_str::<Value>(&wrong.1).unwrap()["error"], "invalid credentials");
    assert!(h.accounts.dummy_verifications() >= 1, "an unknown user costs a hash like the others");
    // Five free failures per account, then back-off: 429 with Retry-After, before the password is looked at.
    for _ in 0..5 {
        attempt("owner", "not the password at all").await;
    }
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": PW}))).await;
    assert_eq!(r.status, 429, "{}", r.body);
    assert_eq!(r.code(), "throttled");
    assert!(r.header("retry-after").unwrap().parse::<u64>().unwrap() >= 1);
    // Not a lock: it ends.
    h.clock.advance(3600);
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": PW}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    // Oversized input is refused before it is hashed.
    let r = h
        .api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": "x".repeat(2000)})))
        .await;
    assert_eq!(r.status, 400);
}

// ---- cookies -------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn cookie_flags_on_loopback_plain_http() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let r = h.login(&owner, PW).await;
    let line = r.all("set-cookie").into_iter().find(|l| l.starts_with("pm_session=")).expect("pm_session cookie");
    assert!(line.contains("; Path=/") && line.contains("; HttpOnly") && line.contains("SameSite=Strict"), "{line}");
    assert!(!line.contains("Secure") && !line.contains("Domain"), "{line}");
    assert!(r.all("set-cookie").iter().all(|l| !l.starts_with("__Host-")));
    assert!(r.header("strict-transport-security").is_none());
    // 256 random bits, as hex.
    let id = r.set_cookie("pm_session").unwrap().1;
    assert!(id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()));
    // Security headers are on every answer, and there is never a CORS header.
    assert_eq!(r.header("x-frame-options"), Some("DENY"));
    assert!(r.header("access-control-allow-origin").is_none());
    let pre = h
        .raw(
            "OPTIONS",
            "/api/v1/status",
            &[("Origin", h.origin.clone()), ("Access-Control-Request-Method", "GET".into())],
            None,
        )
        .await;
    assert!(pre.all("access-control-allow-origin").is_empty() && pre.all("access-control-allow-methods").is_empty());
}

#[tokio::test]
async fn cookie_flags_over_tls_and_the_plain_name_is_not_accepted() {
    let h = Harness::start(Kind::SelfSigned).await;
    let owner = h.setup_owner().await;
    let r = h.login(&owner, PW).await;
    let (line, value) = r.set_cookie("__Host-pm_session").expect("a __Host- cookie over TLS");
    assert_eq!(line, format!("__Host-pm_session={value}; Path=/; HttpOnly; SameSite=Strict; Secure"));
    assert!(r.all("set-cookie").iter().all(|l| !l.starts_with("pm_session=")));
    // Self-signed: no HSTS (the browser would pin an error page for a year).
    assert!(r.header("strict-transport-security").is_none());
    // The session works under its own name only.
    assert_eq!(h.api(Some(&value), "GET", "/api/v1/status", None).await.status, 200);
    let plain_name = h.raw("GET", "/api/v1/status", &[("Cookie", format!("pm_session={value}"))], None).await;
    assert_eq!(plain_name.status, 401);
}

#[tokio::test]
async fn hsts_only_for_certificates_that_are_not_self_signed() {
    let h = Harness::start(Kind::OwnCert).await;
    let r = h.api(None, "GET", "/api/v1/auth/state", None).await;
    assert_eq!(r.header("strict-transport-security"), Some("max-age=31536000"));
    let h = Harness::start(Kind::SelfSigned).await;
    assert!(h.api(None, "GET", "/api/v1/auth/state", None).await.header("strict-transport-security").is_none());
    // Plain loopback: none either.
    let h = Harness::start(Kind::Plain).await;
    assert!(h.api(None, "GET", "/api/v1/auth/state", None).await.header("strict-transport-security").is_none());
}

// ---- CSRF ----------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn csrf_layers_on_state_changing_requests() {
    let h = Harness::start(Kind::Plain).await;
    let h = &h;
    let owner = h.setup_owner().await;
    let cookie = ("Cookie", format!("pm_session={}", owner.cookie));
    let o = h.origin.clone();
    // A mutating project route and a login route: the same rules.
    for path in ["/api/v1/findings", "/api/v1/auth/login"] {
        let call = |headers: Vec<(&'static str, String)>| {
            let cookie = cookie.clone();
            async move {
                let mut hs = vec![cookie];
                hs.extend(headers);
                h.raw("POST", path, &hs, Some(json!({}))).await
            }
        };
        let refused = |r: &Resp, what: &str| {
            assert_eq!(r.status, 403, "{path}: {what}: {}", r.body);
            assert_eq!(r.code(), "csrf", "{path}: {what}");
        };
        refused(&call(vec![("Origin", o.clone())]).await, "no X-ProxyMind");
        refused(&call(vec![("X-ProxyMind", "1".into())]).await, "no Origin and no Sec-Fetch-Site");
        refused(
            &call(vec![("X-ProxyMind", "1".into()), ("Origin", "https://evil.example".into())]).await,
            "wrong Origin",
        );
        refused(&call(vec![("X-ProxyMind", "1".into()), ("Origin", "null".into())]).await, "null Origin");
        refused(
            &call(vec![("X-ProxyMind", "1".into()), ("Origin", o.replace("127.0.0.1", "localhost.evil.example"))])
                .await,
            "lookalike Origin",
        );
        refused(&call(vec![("X-ProxyMind", "1".into()), ("Sec-Fetch-Site", "cross-site".into())]).await, "cross-site");
        refused(&call(vec![("X-ProxyMind", "1".into()), ("Sec-Fetch-Site", "same-site".into())]).await, "same-site");
        refused(
            &call(vec![("X-ProxyMind", "1".into()), ("Origin", o.clone()), ("Sec-Fetch-Site", "cross-site".into())])
                .await,
            "right Origin, cross-site fetch metadata",
        );
        // The two accepted shapes get past CSRF (the empty body is then a 4xx of the handler, never a 403 csrf).
        let ok_origin = call(vec![("X-ProxyMind", "1".into()), ("Origin", o.clone())]).await;
        assert!(ok_origin.status != 403 || ok_origin.code() != "csrf", "{path}: {}", ok_origin.body);
        let ok_site = call(vec![("X-ProxyMind", "1".into()), ("Sec-Fetch-Site", "same-origin".into())]).await;
        assert!(ok_site.status != 403 || ok_site.code() != "csrf", "{path}: {}", ok_site.body);
    }
    // Other mutating methods are covered the same way; GET never needs the headers.
    for m in ["PUT", "PATCH", "DELETE"] {
        let r = h.raw(m, "/api/v1/findings/1", std::slice::from_ref(&cookie), Some(json!({}))).await;
        assert_eq!((r.status, r.code().as_str()), (403, "csrf"), "{m}");
    }
    assert_eq!(h.raw("GET", "/api/v1/status", &[cookie], None).await.status, 200);
    // A request to another host name is refused whatever else it carries.
    let r = h.raw("GET", "/api/v1/auth/state", &[("Host", "evil.example".into())], None).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.code(), "bad_host");
    let r = h.raw("GET", "/", &[("Host", "evil.example".into())], None).await;
    assert_eq!(r.status, 403, "pages too (DNS rebinding)");
}

// ---- fixation and next= --------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_pre_login_cookie_is_never_promoted() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let planted = "ab".repeat(32);
    // The attacker's cookie rides along on every step of the victim's sign-in.
    h.clock.advance(31);
    let with = |extra: Vec<(&'static str, String)>| {
        let mut hs = h.browser();
        hs.push(("Cookie", format!("pm_session={planted}")));
        hs.extend(extra);
        hs
    };
    let r =
        h.raw("POST", "/api/v1/auth/login", &with(vec![]), Some(json!({"username": "owner", "password": PW}))).await;
    let pending = r.json()["pending"].as_str().unwrap().to_string();
    let r = h
        .raw(
            "POST",
            "/api/v1/auth/login/second-factor",
            &with(vec![]),
            Some(json!({"pending": pending, "code": h.code(&owner.secret)})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let fresh = r.set_cookie("pm_session").unwrap().1;
    assert_ne!(fresh, planted, "a new id, never the one the client brought");
    assert_eq!(
        h.api(Some(&planted), "GET", "/api/v1/status", None).await.status,
        401,
        "the planted id stays worthless"
    );
    assert_eq!(h.api(Some(&fresh), "GET", "/api/v1/status", None).await.status, 200);

    // Someone else's live session in the victim's browser is not touched by the victim's sign-in...
    let other = h.invited_user(&Signed { cookie: fresh.clone(), ..clone_signed(&owner) }, "mallory", "tester").await;
    h.clock.advance(31);
    let r = h
        .raw(
            "POST",
            "/api/v1/auth/login",
            &{
                let mut hs = h.browser();
                hs.push(("Cookie", format!("pm_session={}", other.cookie)));
                hs
            },
            Some(json!({"username": "owner", "password": PW})),
        )
        .await;
    assert_eq!(r.json()["step"], "second_factor_required");
    assert_eq!(h.api(Some(&other.cookie), "GET", "/api/v1/status", None).await.status, 200, "not the victim's to end");
    // ...while signing in again as the same user ends the old session (the step-up) and issues another.
    h.clock.advance(31);
    let r = h
        .raw(
            "POST",
            "/api/v1/auth/login",
            &{
                let mut hs = h.browser();
                hs.push(("Cookie", format!("pm_session={fresh}")));
                hs
            },
            Some(json!({"username": "owner", "password": PW})),
        )
        .await;
    let pending = r.json()["pending"].as_str().unwrap().to_string();
    let r = h
        .raw(
            "POST",
            "/api/v1/auth/login/second-factor",
            &{
                let mut hs = h.browser();
                hs.push(("Cookie", format!("pm_session={fresh}")));
                hs
            },
            Some(json!({"pending": pending, "code": h.code(&owner.secret)})),
        )
        .await;
    let newer = r.set_cookie("pm_session").unwrap().1;
    assert_ne!(newer, fresh);
    assert_eq!(h.api(Some(&fresh), "GET", "/api/v1/status", None).await.status, 401);
    assert_eq!(h.api(Some(&newer), "GET", "/api/v1/status", None).await.status, 200);
}

fn clone_signed(s: &Signed) -> Signed {
    Signed {
        username: s.username.clone(),
        cookie: s.cookie.clone(),
        secret: s.secret.clone(),
        codes: s.codes.clone(),
        user_id: s.user_id.clone(),
    }
}

#[tokio::test]
async fn next_after_sign_in_is_a_same_origin_path_or_slash() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    for (sent, back) in [
        (json!("/findings?id=3"), "/findings?id=3"),
        (json!("//evil.example"), "/"),
        (json!("/\\evil.example"), "/"),
        (json!("https://evil.example"), "/"),
        (json!("javascript:alert(1)"), "/"),
        (Value::Null, "/"),
    ] {
        h.clock.advance(31);
        let r = h
            .api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": PW, "next": sent})))
            .await;
        assert_eq!(r.json()["next"], back, "{sent}");
        let pending = r.json()["pending"].as_str().unwrap().to_string();
        let r = h
            .api(
                None,
                "POST",
                "/api/v1/auth/login/second-factor",
                Some(json!({"pending": pending, "code": h.code(&owner.secret), "next": sent})),
            )
            .await;
        assert_eq!(r.json()["next"], back, "{sent}");
    }
}

// ---- invites, membership, sessions, admin --------------------------------------------------------------------------

#[tokio::test]
async fn invite_accept_enrol_and_the_fresh_login_rule() {
    let h = Harness::start(Kind::Plain).await;
    let h = &h;
    let mut owner = h.setup_owner().await;
    // Sensitive: needs a sign-in within ten minutes.
    h.clock.advance(601);
    let r = h.api(Some(&owner.cookie), "POST", "/api/v1/auth/invites", Some(json!({"role": "tester"}))).await;
    assert_eq!(r.status, 403, "{}", r.body);
    assert_eq!(r.code(), "fresh_login_required");
    assert_eq!(h.api(Some(&owner.cookie), "GET", "/api/v1/auth/me", None).await.json()["fresh"], false);
    // Signing in again is the step-up.
    h.relogin(&mut owner).await;
    assert_eq!(h.api(Some(&owner.cookie), "GET", "/api/v1/auth/me", None).await.json()["fresh"], true);
    let r = h
        .api(Some(&owner.cookie), "POST", "/api/v1/auth/invites", Some(json!({"role": "tester", "ttl_hours": 24})))
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let token = r.json()["token"].as_str().unwrap().to_string();
    let url = r.json()["url"].as_str().unwrap().to_string();
    assert_eq!(url, format!("{}/#invite={token}", h.origin), "the token is in the fragment");
    let invite_id = r.json()["id"].as_str().unwrap().to_string();
    // The list shows it, without the secret.
    let list = h.api(Some(&owner.cookie), "GET", "/api/v1/auth/invites", None).await;
    assert!(list.body.contains(&invite_id) && !list.body.contains(&token));
    // Accept: a weak password and a bad username leave the invite unused.
    let accept = |user: &'static str, pw: &'static str| {
        let token = token.clone();
        async move {
            h.api(
                None,
                "POST",
                "/api/v1/auth/invite/accept",
                Some(json!({"invite": token, "username": user, "password": pw})),
            )
            .await
        }
    };
    assert_eq!(accept("alice", "short").await.status, 400);
    assert_eq!(accept("a", PW).await.status, 400);
    let r = accept("alice", PW).await;
    assert_eq!(r.status, 200, "{}", r.body);
    // Straight into enrolment; there is no session before a second factor exists.
    assert_eq!(r.json()["step"], "enrolment_required");
    assert!(r.set_cookie("pm_session").is_none());
    assert_eq!(accept("bob", PW).await.status, 400, "single use");
    let alice = h.finish_enrolment(r.json()["pending"].as_str().unwrap(), "alice").await;
    let me = h.api(Some(&alice.cookie), "GET", "/api/v1/auth/me", None).await.json();
    assert_eq!(
        (me["role"].as_str(), me["actor"].as_str(), me["user"]["server_admin"].as_bool()),
        (Some("tester"), Some("human:alice"), Some(false))
    );
    assert_eq!(h.api(Some(&alice.cookie), "GET", "/api/v1/status", None).await.json()["you_are"], "human:alice");
    // A tester neither lists users nor invites others (accounts layer: not an owner).
    assert_eq!(h.api(Some(&alice.cookie), "GET", "/api/v1/auth/users", None).await.status, 403);
    assert_eq!(h.api(Some(&alice.cookie), "GET", "/api/v1/auth/invites", None).await.status, 403);
    let r = h.api(Some(&alice.cookie), "POST", "/api/v1/auth/invites", Some(json!({"role": "viewer"}))).await;
    assert_eq!((r.status, r.code().as_str()), (403, "not_authorised"));
    // Revoking: an unused invite goes, a used one cannot.
    let r = h.api(Some(&owner.cookie), "POST", "/api/v1/auth/invites", Some(json!({"role": "viewer"}))).await;
    let spare = r.json()["id"].as_str().unwrap().to_string();
    assert_eq!(h.api(Some(&owner.cookie), "DELETE", &format!("/api/v1/auth/invites/{spare}"), None).await.status, 200);
    assert_eq!(
        h.api(Some(&owner.cookie), "DELETE", &format!("/api/v1/auth/invites/{invite_id}"), None).await.status,
        400
    );
}

#[tokio::test]
async fn a_signed_in_user_without_a_membership_gets_403_on_the_project() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let owner_id = owner.user_id.clone();
    // An invite that names no project makes an account with no membership.
    let inv = h.accounts.create_invite(&owner_id, pm_accounts::Role::Tester, None, Duration::from_secs(3600)).unwrap();
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/invite/accept",
            Some(json!({"invite": inv.token.expose(), "username": "carol", "password": PW})),
        )
        .await;
    let carol = h.finish_enrolment(r.json()["pending"].as_str().unwrap(), "carol").await;
    let r = h.api(Some(&carol.cookie), "GET", "/api/v1/status", None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "not_a_member"));
    for p in ["/api/v1/exchanges", "/api/v1/findings", "/api/v1/audit"] {
        assert_eq!(h.api(Some(&carol.cookie), "GET", p, None).await.status, 403, "{p}");
    }
    // She can still see who she is and manage her own sessions.
    let me = h.api(Some(&carol.cookie), "GET", "/api/v1/auth/me", None).await.json();
    assert!(me["role"].is_null());
    assert_eq!(h.api(Some(&carol.cookie), "GET", "/api/v1/auth/sessions", None).await.status, 200);
    // A membership opens the project (and ends her sessions only on demotion or removal, not on promotion).
    h.accounts.set_membership(&owner_id, &h.project, &carol.user_id, pm_accounts::Role::Viewer).unwrap();
    assert_eq!(h.api(Some(&carol.cookie), "GET", "/api/v1/status", None).await.status, 200);
    // Removing it closes the project and ends her sessions.
    h.accounts.remove_membership(&owner_id, &h.project, &carol.user_id).unwrap();
    assert_eq!(h.api(Some(&carol.cookie), "GET", "/api/v1/status", None).await.status, 401);

    // A server admin with no membership keeps the account-admin endpoints and loses the project. (The project
    // must keep an owner: carol takes over.)
    h.accounts.set_membership(&owner_id, &h.project, &carol.user_id, pm_accounts::Role::Owner).unwrap();
    h.accounts.remove_membership(&owner_id, &h.project, &owner_id).unwrap();
    let mut owner = owner;
    h.relogin(&mut owner).await;
    assert_eq!(h.api(Some(&owner.cookie), "GET", "/api/v1/status", None).await.status, 403);
    let r = h.api(Some(&owner.cookie), "GET", "/api/v1/auth/users", None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.json().as_array().unwrap().len() >= 2);
}

#[tokio::test]
async fn sessions_list_revoke_and_sign_out_everywhere() {
    let h = Harness::start(Kind::Plain).await;
    let mut owner = h.setup_owner().await;
    let first = owner.cookie.clone();
    let second = h.relogin(&mut owner).await;
    let list = h.api(Some(&second), "GET", "/api/v1/auth/sessions", None).await.json();
    let list = list.as_array().unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list.iter().filter(|s| s["current"] == true).count(), 1);
    let other_ref = list.iter().find(|s| s["current"] == false).unwrap()["reference"].as_str().unwrap().to_string();
    assert!(
        !h.api(Some(&second), "GET", "/api/v1/auth/sessions", None).await.body.contains(&second),
        "the id itself is never listed"
    );
    // Revoke the other one.
    assert_eq!(h.api(Some(&second), "DELETE", "/api/v1/auth/sessions/nonesuchref", None).await.status, 404);
    assert_eq!(h.api(Some(&second), "DELETE", &format!("/api/v1/auth/sessions/{other_ref}"), None).await.status, 200);
    assert_eq!(h.api(Some(&first), "GET", "/api/v1/status", None).await.status, 401);
    // Sign out everywhere, keeping this one; then everywhere including it.
    let third = h.relogin(&mut owner).await;
    let r = h.api(Some(&third), "POST", "/api/v1/auth/sessions/revoke-all", Some(json!({"keep_current": true}))).await;
    assert_eq!(r.json()["revoked"], 1);
    assert_eq!(h.api(Some(&second), "GET", "/api/v1/status", None).await.status, 401);
    assert_eq!(h.api(Some(&third), "GET", "/api/v1/status", None).await.status, 200);
    let r = h.api(Some(&third), "POST", "/api/v1/auth/sessions/revoke-all", None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.set_cookie("pm_session").unwrap().1.is_empty());
    assert_eq!(h.api(Some(&third), "GET", "/api/v1/status", None).await.status, 401);
}

#[tokio::test]
async fn changing_the_password_ends_other_sessions_and_renews_this_one() {
    let h = Harness::start(Kind::Plain).await;
    let h = &h;
    let mut owner = h.setup_owner().await;
    let elsewhere = owner.cookie.clone();
    let here = h.relogin(&mut owner).await;
    let change = |current: &'static str, new: &'static str| {
        let here = here.clone();
        async move {
            h.api(Some(&here), "POST", "/api/v1/auth/password", Some(json!({"current": current, "new_password": new})))
                .await
        }
    };
    assert_eq!(change("wrong current password", PW2).await.status, 401);
    assert_eq!(change(PW, "short").await.status, 400);
    h.clock.advance(601);
    assert_eq!(change(PW, PW2).await.code(), "fresh_login_required");
    let here = h.relogin(&mut owner).await;
    let r =
        h.api(Some(&here), "POST", "/api/v1/auth/password", Some(json!({"current": PW, "new_password": PW2}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let renewed = r.set_cookie("pm_session").unwrap().1;
    assert_ne!(renewed, here);
    assert_eq!(
        h.api(Some(&here), "GET", "/api/v1/status", None).await.status,
        401,
        "rotation: the old id is dead at once"
    );
    assert_eq!(h.api(Some(&elsewhere), "GET", "/api/v1/status", None).await.status, 401);
    assert_eq!(h.api(Some(&renewed), "GET", "/api/v1/status", None).await.status, 200);
    // The old password no longer works, the new one does.
    h.clock.advance(31);
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": PW}))).await;
    assert_eq!(r.status, 401);
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": PW2}))).await;
    assert_eq!(r.json()["step"], "second_factor_required");
    let kinds: Vec<String> = h.accounts.security_log(200).unwrap().into_iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&"password_changed".to_string()) && kinds.contains(&"password_change_failure".to_string()));
}

#[tokio::test]
async fn second_factor_endpoints() {
    let h = Harness::start(Kind::Plain).await;
    let mut owner = h.setup_owner().await;
    let c = owner.cookie.clone();
    // Already enrolled.
    let r = h.api(Some(&c), "POST", "/api/v1/auth/totp/begin", None).await;
    assert_eq!((r.status, r.code().as_str()), (409, "already_enrolled"));
    // New recovery codes replace the old ones.
    let old = owner.codes[0].clone();
    let r = h.api(Some(&c), "POST", "/api/v1/auth/recovery-codes", None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let new: Vec<String> =
        r.json()["recovery_codes"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().into()).collect();
    assert_eq!(new.len(), 10);
    assert!(!new.contains(&old));
    h.clock.advance(31);
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": PW}))).await;
    let pending = r.json()["pending"].as_str().unwrap().to_string();
    let r =
        h.api(None, "POST", "/api/v1/auth/login/second-factor", Some(json!({"pending": pending, "code": old}))).await;
    assert_eq!(r.status, 401, "an old recovery code is dead");
    // An owner cannot drop the factor.
    let r = h.api(Some(&c), "POST", "/api/v1/auth/totp/disable", None).await;
    assert_eq!((r.status, r.code().as_str()), (409, "second_factor_required"));
    // An admin clears a lost one: the person's next password step asks for enrolment again.
    let alice = h.invited_user(&owner, "alice", "tester").await;
    let r = h.api(Some(&c), "POST", &format!("/api/v1/auth/users/{}/reset-second-factor", alice.user_id), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(h.api(Some(&alice.cookie), "GET", "/api/v1/status", None).await.status, 401, "their sessions ended");
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "alice", "password": PW}))).await;
    assert_eq!(r.json()["step"], "enrolment_required");
    // A tester may not.
    let bob = h.invited_user(&owner, "bob", "tester").await;
    let r = h
        .api(Some(&bob.cookie), "POST", &format!("/api/v1/auth/users/{}/reset-second-factor", owner.user_id), None)
        .await;
    assert_eq!((r.status, r.code().as_str()), (403, "server_admin_required"));
    h.relogin(&mut owner).await;
}

#[tokio::test]
async fn admins_disable_and_enable_accounts_but_not_the_last_admin() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let alice = h.invited_user(&owner, "alice", "tester").await;
    let users = h.api(Some(&owner.cookie), "GET", "/api/v1/auth/users", None).await.json();
    assert_eq!(users.as_array().unwrap().len(), 2);
    let r = h.api(Some(&owner.cookie), "POST", &format!("/api/v1/auth/users/{}/disable", alice.user_id), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(h.api(Some(&alice.cookie), "GET", "/api/v1/status", None).await.status, 401);
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "alice", "password": PW}))).await;
    assert_eq!(r.status, 401);
    let r = h.api(Some(&owner.cookie), "POST", &format!("/api/v1/auth/users/{}/enable", alice.user_id), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "alice", "password": PW}))).await;
    assert_eq!(r.json()["step"], "second_factor_required");
    // The only admin cannot be disabled, not even by itself.
    let r = h.api(Some(&owner.cookie), "POST", &format!("/api/v1/auth/users/{}/disable", owner.user_id), None).await;
    assert_eq!((r.status, r.code().as_str()), (409, "last_admin"));
    assert_eq!(h.api(Some(&owner.cookie), "POST", "/api/v1/auth/users/u_nosuchuser/disable", None).await.status, 404);
}

// ---- proxies -------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn behind_a_trusted_proxy_forwarded_headers_count() {
    let h = Harness::start(Kind::Proxy).await;
    // Over the proxy's HTTPS: setup is allowed, the cookie is the Secure __Host- one, HSTS is sent.
    let r = h.api(None, "GET", "/api/v1/auth/state", None).await;
    assert_eq!(r.json()["setup_allowed"], true);
    assert_eq!(r.header("strict-transport-security"), Some("max-age=31536000"));
    let owner = h.setup_owner().await;
    let r = h.login(&owner, PW).await;
    let (line, _) = r.set_cookie("__Host-pm_session").unwrap();
    assert!(line.ends_with("; Path=/; HttpOnly; SameSite=Strict; Secure") || line.contains("; Secure"), "{line}");
    // The client address in the security log is the forwarded one, not the proxy's.
    h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": "wrong password here"})))
        .await;
    let log = h.accounts.security_log(50).unwrap();
    let failure = log.iter().find(|e| e.kind == "login_failure").unwrap();
    assert_eq!(failure.client_addr.as_deref(), Some("198.51.100.7"));
    // Without the proxy's say-so that the request was HTTPS, plain HTTP is not treated as secure.
    let mut headers = h.browser();
    headers.retain(|(k, _)| *k != "X-Forwarded-Proto");
    let r = h.raw("GET", "/api/v1/auth/state", &headers, None).await;
    assert_eq!(r.json()["setup_allowed"], false);
    assert!(r.header("strict-transport-security").is_none());
}

#[tokio::test]
async fn a_peer_that_is_not_a_trusted_proxy_is_not_believed() {
    let h = Harness::start(Kind::ProxyOther).await;
    // It claims HTTPS and a client address, but it is not the configured proxy.
    let r = h.api(None, "GET", "/api/v1/auth/state", None).await;
    assert_eq!(r.json()["setup_allowed"], false, "forwarded proto ignored");
    assert!(r.header("strict-transport-security").is_none());
    let tok = h.accounts.create_setup_token().unwrap();
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/setup",
            Some(json!({"setup_token": tok.token.expose(), "username": "owner", "password": PW})),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (403, "setup_insecure"));
    h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "x", "password": "y"}))).await;
}

// ---- TLS and pinning -----------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_pinned_client_connects_and_a_wrong_pin_fails_hard() {
    let h = Harness::start(Kind::SelfSigned).await;
    let pin = h.pin.unwrap();
    // Right pin: an ordinary API answer over TLS.
    let r = h.api(None, "GET", "/api/v1/auth/state", None).await;
    assert_eq!(r.status, 200);
    // Wrong pin: the handshake itself fails, with both pins in the error.
    let wrong = Pin::from_bytes([1; 32]);
    let Err(err) = h.connect_tls(wrong).await else { panic!("a wrong pin must not connect") };
    assert!(err.to_string().contains("does not match the pin") && err.to_string().contains(&pin.to_string()), "{err}");
    // The pin is `sha256:` and base64; the hex form parses to the same pin.
    assert!(pin.to_string().starts_with("sha256:") && pin.to_string().len() == 51);
    assert_eq!(Pin::parse(&format!("sha256:{}", pin.hex())).unwrap(), pin);
    // A client that does not check anything at all is not what pin_client_config builds; plain HTTP to the TLS
    // port gets no HTTP answer.
    let mut s = TcpStream::connect(("127.0.0.1", h.port)).await.unwrap();
    s.write_all(b"GET /api/v1/auth/state HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf)).await;
    assert!(!String::from_utf8_lossy(&buf).starts_with("HTTP/"), "no cleartext HTTP on the TLS port");
}

#[tokio::test]
async fn the_server_certificate_keeps_its_key_across_restarts() {
    let a = Harness::start(Kind::SelfSigned).await;
    let pin = a.pin.unwrap();
    // The same home, started again, presents the same key: the pin printed the first time still works.
    let names = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    let again = pm_tls::server::SelfSigned::load_or_create(&a.dir, &names).unwrap();
    assert_eq!(again.pin, pin);
    assert!(!again.new_key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&again.key_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test]
async fn handshake_failures_and_stalls_do_not_end_the_accept_loop() {
    let h = Harness::start(Kind::SelfSigned).await;
    // Garbage instead of a ClientHello, a connection that says nothing, a hello cut short.
    let mut junk = TcpStream::connect(("127.0.0.1", h.port)).await.unwrap();
    junk.write_all(&[0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5]).await.unwrap();
    let mut silent = TcpStream::connect(("127.0.0.1", h.port)).await.unwrap();
    let mut half = TcpStream::connect(("127.0.0.1", h.port)).await.unwrap();
    half.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01]).await.unwrap();
    for _ in 0..20 {
        let mut s = TcpStream::connect(("127.0.0.1", h.port)).await.unwrap();
        let _ = s.write_all(b"\x00\x00\x00\x00").await;
    }
    // The server still answers real clients straight away.
    let r = tokio::time::timeout(Duration::from_secs(5), h.api(None, "GET", "/api/v1/auth/state", None)).await.unwrap();
    assert_eq!(r.status, 200);
    let _ = silent.shutdown().await;
}

#[tokio::test]
async fn alpn_offers_h2_and_the_server_speaks_it() {
    let h = Harness::start(Kind::SelfSigned).await;
    let tcp = TcpStream::connect(("127.0.0.1", h.port)).await.unwrap();
    let cfg = pin_client_config(h.pin.unwrap(), &[b"h2", b"http/1.1"]).unwrap();
    let mut tls =
        pm_tls::TlsConnector::from(cfg).connect(pm_tls::server_name("localhost").unwrap(), tcp).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    // HTTP/2: the client preface and an empty SETTINGS frame; the server answers with its own SETTINGS frame.
    tls.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
    tls.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).await.unwrap();
    let mut head = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), tls.read_exact(&mut head)).await.unwrap().unwrap();
    assert_eq!(head[3], 4, "the first frame is SETTINGS");
    // And a client that offers only http/1.1 gets http/1.1.
    let tcp = TcpStream::connect(("127.0.0.1", h.port)).await.unwrap();
    let cfg = pin_client_config(h.pin.unwrap(), &[b"http/1.1"]).unwrap();
    let tls = pm_tls::TlsConnector::from(cfg).connect(pm_tls::server_name("localhost").unwrap(), tcp).await.unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"http/1.1".as_slice()));
}

// ---- secrets stay out of logs and bodies ---------------------------------------------------------------------------

#[tokio::test]
async fn no_password_secret_or_token_reaches_a_log_a_body_or_an_error() {
    let lines = captured().clone();
    tracing::info!("capture self-test");
    assert!(lines.lock().unwrap().iter().any(|l| l.contains("capture self-test")), "the log capture works");
    let h = Harness::start(Kind::Plain).await;
    let secret_pw = "Zq9-unique-pass-phrase-for-grep";
    let secret_pw2 = "Yw8-another-unique-phrase-grep";
    let tok = h.accounts.create_setup_token().unwrap();
    // Answers that must not hold any secret, with a label for the failure message.
    let mut bodies: Vec<(&str, String)> = Vec::new();
    // Every secret value this run produced: session ids, pending sign-in tokens, tokens, codes.
    let mut secrets: Vec<(&str, String)> = vec![
        ("password", secret_pw.into()),
        ("password 2", secret_pw2.into()),
        ("setup token", tok.token.expose().into()),
    ];

    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/setup",
            Some(json!({"setup_token": tok.token.expose(), "username": "owner", "password": secret_pw})),
        )
        .await;
    bodies.push(("setup", r.body.clone()));
    let pending = r.json()["pending"].as_str().unwrap().to_string();
    secrets.push(("pending token", pending.clone()));
    // The enrolment answer returns the TOTP secret once, by design; it is the only answer allowed to.
    let r = h.api(None, "POST", "/api/v1/auth/login/enrol", Some(json!({"pending": pending}))).await;
    let secret = r.json()["secret_base32"].as_str().unwrap().to_string();
    secrets.push(("totp secret", secret.clone()));
    secrets.push(("totp secret (hex)", b32_decode(&secret).iter().map(|b| format!("{b:02x}")).collect()));
    // So does the confirmation, with the recovery codes (and the cookie, which is a header).
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/login/enrol/confirm",
            Some(json!({"pending": pending, "code": h.code(&secret)})),
        )
        .await;
    let cookie = r.set_cookie("pm_session").unwrap().1;
    let codes: Vec<String> =
        r.json()["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
    assert!(codes.iter().all(|c| r.body.contains(c)), "the codes are shown once, here");
    assert!(!r.body.contains(&cookie), "the session id is a cookie, never in a body");
    secrets.extend(codes.iter().map(|c| ("recovery code", c.clone())));
    secrets.push(("session id", cookie.clone()));
    let owner = Signed {
        username: "owner".into(),
        cookie: cookie.clone(),
        secret: secret.clone(),
        codes,
        user_id: String::new(),
    };

    // Failures with the secrets in the request: nothing is echoed.
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": secret_pw2}))).await;
    bodies.push(("wrong password", r.body));
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": secret_pw}))).await;
    let p = r.json()["pending"].as_str().unwrap().to_string();
    secrets.push(("pending token", p.clone()));
    let r =
        h.api(None, "POST", "/api/v1/auth/login/second-factor", Some(json!({"pending": p, "code": "123456"}))).await;
    bodies.push(("wrong second factor", r.body));
    let r = h
        .raw("POST", "/api/v1/auth/login", &h.browser(), Some(json!({"username": "owner", "pasword": secret_pw})))
        .await;
    bodies.push(("bad body", r.body));
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/invite/accept",
            Some(json!({"invite": "pminv_deadbeef", "username": "zed", "password": secret_pw2})),
        )
        .await;
    bodies.push(("bad invite", r.body));
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/setup",
            Some(json!({"setup_token": tok.token.expose(), "username": "x2", "password": secret_pw2})),
        )
        .await;
    bodies.push(("reused setup token", r.body));
    let r = h
        .api(
            Some(&cookie),
            "POST",
            "/api/v1/auth/password",
            Some(json!({"current": secret_pw, "new_password": "short"})),
        )
        .await;
    bodies.push(("weak new password", r.body));
    for (what, path) in [("sessions", "/api/v1/auth/sessions"), ("me", "/api/v1/auth/me"), ("status", "/api/v1/status")]
    {
        bodies.push((what, h.api(Some(&cookie), "GET", path, None).await.body));
    }

    // An invite: its token is returned to its creator once and shown nowhere else.
    let r = h.api(Some(&cookie), "POST", "/api/v1/auth/invites", Some(json!({"role": "tester"}))).await;
    let invite = r.json()["token"].as_str().unwrap().to_string();
    secrets.push(("invite token", invite.clone()));
    for (what, path) in [("invites list", "/api/v1/auth/invites"), ("users list", "/api/v1/auth/users")] {
        bodies.push((what, h.api(Some(&cookie), "GET", path, None).await.body));
    }
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/invite/accept",
            Some(json!({"invite": invite, "username": "alice", "password": secret_pw2})),
        )
        .await;
    bodies.push(("accept", r.body.clone()));
    let alice = h.finish_enrolment(r.json()["pending"].as_str().unwrap(), "alice").await;
    secrets.push(("session id", alice.cookie.clone()));
    secrets.push(("totp secret", alice.secret.clone()));
    secrets.extend(alice.codes.iter().map(|c| ("recovery code", c.clone())));

    // A password change renews the session and answers without it.
    let c = h.relogin_for(&owner, secret_pw).await;
    secrets.push(("session id", c.clone()));
    let r = h
        .api(Some(&c), "POST", "/api/v1/auth/password", Some(json!({"current": secret_pw, "new_password": secret_pw2})))
        .await;
    bodies.push(("password change", r.body.clone()));
    let renewed = r.set_cookie("pm_session").unwrap().1;
    secrets.push(("session id", renewed.clone()));
    let r = h.api(Some(&renewed), "POST", "/api/v1/auth/logout", None).await;
    bodies.push(("logout", r.body));

    // 1. No answer outside the intended ones holds a password, a TOTP secret, a recovery code, a session id, a
    //    pending token (outside the sign-in steps that return it), the setup token or an invite token.
    for (what, body) in &bodies {
        for (kind, w) in &secrets {
            // The sign-in steps hand a pending token to the client that is signing in; that is their job.
            if *kind == "pending token" && body.contains("\"step\"") {
                continue;
            }
            assert!(!body.contains(w.as_str()), "the {what} answer contains a {kind}: {body}");
        }
    }
    // 2. The security log holds ids, kinds and fixed words only.
    let log = h.accounts.security_log(1000).unwrap();
    assert!(log.len() > 10);
    let dump = format!("{log:?}");
    for (kind, w) in &secrets {
        assert!(!dump.contains(w.as_str()), "the security log contains a {kind}");
    }
    // 3. Nor does anything logged through tracing while all this ran.
    let logged = lines.lock().unwrap().join("\n");
    for (kind, w) in &secrets {
        assert!(!logged.contains(w.as_str()), "a log line contains a {kind}");
    }
}

impl Harness {
    /// Password and TOTP sign-in with an arbitrary password; returns the session id.
    async fn relogin_for(&self, who: &Signed, password: &str) -> String {
        let r = self.login(who, password).await;
        assert_eq!(r.status, 200, "{}", r.body);
        r.set_cookie(self.cookie_name()).unwrap().1
    }
}

// ---- tokens (ADR-0022 step 5) -------------------------------------------------------------------------------------

/// Makes a token through the API as a signed-in person; returns the secret and the answer.
async fn make_token(h: &Harness, who: &Signed, body: Value) -> (String, Value) {
    let r = h.api(Some(&who.cookie), "POST", "/api/v1/tokens", Some(body)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    (v["token"].as_str().unwrap().to_string(), v)
}

/// What curl, a CI job or the MCP bridge sends: the bearer header and nothing else a browser would add.
async fn bearer(h: &Harness, method: &str, path: &str, token: &str, body: Option<Value>) -> Resp {
    h.raw(method, path, &[("Authorization", format!("Bearer {token}"))], body).await
}

fn mcp_call(id: u32, name: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})
}

fn tool_json(r: &Resp) -> Value {
    assert_eq!(r.status, 200, "{}", r.body);
    let text = r.json()["result"]["content"][0]["text"].as_str().unwrap_or_default().to_string();
    serde_json::from_str(&text).unwrap_or_else(|_| json!(text))
}

#[tokio::test]
async fn a_token_acts_as_its_own_actor_and_the_client_cannot_choose_another() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let (secret, made) = make_token(&h, &owner, json!({"kind": "agent", "name": "claude"})).await;
    assert!(secret.starts_with("pm3_agent_") && secret.len() == 4 + 5 + 1 + 64, "{secret}");
    assert_eq!(made["actor"], "agent:claude");
    assert_eq!(made["role"], "tester");
    assert_eq!(made["status"], "active");
    assert_eq!(made["owner"], owner.user_id.as_str());
    // The default lifetime is 30 days.
    assert_eq!(made["expires_at"].as_i64().unwrap() - made["created_at"].as_i64().unwrap(), 30 * 86_400);

    let r = bearer(&h, "GET", "/api/v1/status", &secret, None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["you_are"], "agent:claude");
    // Nothing the client sends changes who it is.
    let r = h
        .raw(
            "GET",
            "/api/v1/status?actor=human:owner&you_are=human:owner",
            &[
                ("Authorization", format!("Bearer {secret}")),
                ("X-ProxyMind-Actor", "human:owner".into()),
                ("X-Actor", "human:owner".into()),
            ],
            None,
        )
        .await;
    assert_eq!(r.json()["you_are"], "agent:claude");
    // The token is accepted in the Authorization header only: not in the query, not as a cookie.
    let r = h.raw("GET", &format!("/api/v1/status?token={secret}&access_token={secret}"), &[], None).await;
    assert_eq!(r.status, 401);
    let r =
        h.raw("GET", "/api/v1/status", &[("Cookie", format!("pm_session={secret}; pm_token={secret}"))], None).await;
    assert_eq!(r.status, 401);
    // Each kind is its own actor kind.
    for (kind, name) in [("ci", "pipeline"), ("plugin", "hosts-panel")] {
        let (s, v) = make_token(&h, &owner, json!({"kind": kind, "name": name})).await;
        assert_eq!(v["actor"], format!("{kind}:{name}"));
        assert_eq!(bearer(&h, "GET", "/api/v1/status", &s, None).await.json()["you_are"], format!("{kind}:{name}"));
    }
    // The install token is not a credential here, a malformed pm3_ is refused like a wrong one, and the answers say so
    // in one way only.
    let wrong = format!("pm3_agent_{}", "0".repeat(64));
    for t in [wrong.as_str(), "pm3_agent_short", "pm3_", "install-token-that-server-mode-must-refuse"] {
        let r = bearer(&h, "GET", "/api/v1/status", t, None).await;
        assert_eq!(r.status, 401, "{t}");
        assert!(r.body.len() < 200 && !r.body.contains(t), "{}", r.body);
    }
    let r = bearer(&h, "GET", "/api/v1/status", &wrong, None).await;
    assert_eq!(r.code(), "invalid_token");
    assert_eq!(r.header("www-authenticate"), Some("Bearer"));
    // Listing shows it without the secret, with its use.
    let r = h.api(Some(&owner.cookie), "GET", "/api/v1/tokens", None).await;
    assert_eq!(r.status, 200);
    assert!(!r.body.contains(&secret) && !r.body.contains(&secret[secret.len() - 20..]));
    let list = r.json();
    let row = list.as_array().unwrap().iter().find(|t| t["name"] == "claude").unwrap();
    assert!(row["use_count"].as_u64().unwrap() >= 2 && row["last_used_at"].is_i64(), "{row}");
}

#[tokio::test]
async fn bearer_requests_skip_the_browser_layers_and_a_cookie_brings_them_back() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let (secret, _) = make_token(&h, &owner, json!({"kind": "agent", "name": "claude"})).await;
    let auth = ("Authorization", format!("Bearer {secret}"));
    // No cookie: no Origin and no X-ProxyMind needed (a script or CI job sends neither); it gets to the handler.
    let r = h.raw("POST", "/api/v1/findings", std::slice::from_ref(&auth), Some(json!({}))).await;
    assert!(r.status != 403 || r.code() != "csrf", "{} {}", r.status, r.body);
    let r = h
        .raw("POST", "/api/v1/mcp", std::slice::from_ref(&auth), Some(json!({"jsonrpc":"2.0","id":1,"method":"ping"})))
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    // The session cookie, valid or not, makes it a cookie request: the cookie path's layers apply in full.
    for cookie in [owner.cookie.clone(), "0".repeat(64)] {
        let with_cookie = ("Cookie", format!("pm_session={cookie}"));
        let r = h.raw("POST", "/api/v1/findings", &[auth.clone(), with_cookie.clone()], Some(json!({}))).await;
        assert_eq!((r.status, r.code().as_str()), (403, "csrf"), "cookie and bearer, no headers");
        let r = h
            .raw(
                "POST",
                "/api/v1/findings",
                &[
                    auth.clone(),
                    with_cookie.clone(),
                    ("X-ProxyMind", "1".into()),
                    ("Origin", "https://evil.example".into()),
                ],
                Some(json!({})),
            )
            .await;
        assert_eq!((r.status, r.code().as_str()), (403, "csrf"), "cookie and bearer, wrong Origin");
    }
    // With the cookie and the browser headers the cookie wins: the person acts, not the token.
    let r =
        h.raw("GET", "/api/v1/status", &[auth.clone(), ("Cookie", format!("pm_session={}", owner.cookie))], None).await;
    assert_eq!(r.json()["you_are"], "human:owner");
    // Something that is not a pm3_ token is not a bearer credential here, so the browser layers apply to it too.
    let r =
        h.raw("POST", "/api/v1/findings", &[("Authorization", "Bearer something-else".into())], Some(json!({}))).await;
    assert_eq!((r.status, r.code().as_str()), (403, "csrf"));
    let r = h.raw("GET", "/api/v1/status", &[("Authorization", "Bearer something-else".into())], None).await;
    assert_eq!(r.status, 401);
    // The scheme name is case-insensitive; a bare token is not a bearer header.
    let r = h.raw("GET", "/api/v1/status", &[("Authorization", format!("bearer {secret}"))], None).await;
    assert_eq!(r.status, 200);
    let r = h.raw("GET", "/api/v1/status", &[("Authorization", secret.clone())], None).await;
    assert_eq!(r.status, 401);
    // Host checks still apply to bearer requests (DNS rebinding).
    let r = h.raw("GET", "/api/v1/status", &[auth.clone(), ("Host", "evil.example".into())], None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "bad_host"));
}

#[tokio::test]
async fn a_token_cannot_create_list_or_revoke_tokens_or_use_account_endpoints() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let (secret, made) = make_token(&h, &owner, json!({"kind": "agent", "name": "claude"})).await;
    let id = made["id"].as_str().unwrap().to_string();
    let attempts = [
        ("POST", "/api/v1/tokens".to_string(), Some(json!({"kind": "agent", "name": "child"}))),
        ("GET", "/api/v1/tokens".to_string(), None),
        ("GET", "/api/v1/tokens?all=true".to_string(), None),
        ("DELETE", format!("/api/v1/tokens/{id}"), None),
    ];
    for (m, p, body) in attempts {
        let r = bearer(&h, m, &p, &secret, body).await;
        assert_eq!((r.status, r.code().as_str()), (403, "tokens_need_a_person"), "{m} {p}: {}", r.body);
    }
    for (m, p) in [
        ("GET", "/api/v1/auth/me"),
        ("GET", "/api/v1/auth/users"),
        ("GET", "/api/v1/auth/sessions"),
        ("POST", "/api/v1/auth/invites"),
        ("POST", "/api/v1/auth/logout"),
    ] {
        let r = bearer(&h, m, p, &secret, Some(json!({"role": "tester"}))).await;
        assert_eq!((r.status, r.code().as_str()), (403, "token_not_allowed"), "{m} {p}");
    }
    // Still alive: nothing above revoked it, and no child token exists.
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &secret, None).await.status, 200);
    let list = h.api(Some(&owner.cookie), "GET", "/api/v1/tokens", None).await.json();
    assert_eq!(list.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn token_rules_are_enforced_when_making_one() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let post = |body: Value| h.api(Some(&owner.cookie), "POST", "/api/v1/tokens", Some(body));
    // Never owner or admin: not a role of a token, and nothing else is accepted.
    for body in [
        json!({"kind": "agent", "name": "x", "role": "owner"}),
        json!({"kind": "agent", "name": "x", "role": "admin"}),
        json!({"kind": "human", "name": "x"}),
        json!({"kind": "agent", "name": "x", "tier_cap": "everything"}),
        json!({"kind": "agent", "name": "x", "surprise": 1}),
        json!({"kind": "agent", "name": "has space"}),
        json!({"kind": "agent", "name": ""}),
        json!({"kind": "agent", "name": "x", "expires_days": 0}),
        json!({"kind": "agent", "name": "x", "expires_days": 366}),
    ] {
        let r = post(body.clone()).await;
        assert!(r.status == 400 || r.status == 422, "{body}: {} {}", r.status, r.body);
    }
    let r =
        post(json!({"kind": "agent", "name": "x", "expires_days": 365, "tier_cap": "active_safe", "role": "viewer"}))
            .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    assert_eq!((v["role"].as_str(), v["tier_cap"].as_str()), (Some("viewer"), Some("active_safe")));
    assert_eq!(v["expires_at"].as_i64().unwrap() - v["created_at"].as_i64().unwrap(), 365 * 86_400);
    // A name is taken while its token lives, in any case.
    let r = post(json!({"kind": "agent", "name": "X"})).await;
    assert_eq!((r.status, r.code().as_str()), (409, "token_name_taken"));
    assert_eq!(post(json!({"kind": "ci", "name": "x"})).await.status, 200, "another kind is another actor");
    // Without a session, and without the browser headers: refused.
    assert_eq!(
        h.raw("POST", "/api/v1/tokens", &h.browser(), Some(json!({"kind": "agent", "name": "y"}))).await.status,
        401
    );
    let cookie = ("Cookie", format!("pm_session={}", owner.cookie));
    let r = h.raw("POST", "/api/v1/tokens", &[cookie], Some(json!({"kind": "agent", "name": "y"}))).await;
    assert_eq!((r.status, r.code().as_str()), (403, "csrf"));
}

#[tokio::test]
async fn managing_other_peoples_tokens_needs_an_owner_and_a_fresh_sign_in() {
    let h = Harness::start(Kind::Plain).await;
    let mut owner = h.setup_owner().await;
    let tester = h.invited_user(&owner, "tester1", "tester").await;
    let viewer = h.invited_user(&owner, "viewer1", "viewer").await;
    // A tester makes their own, lists their own, revokes their own: no fresh sign-in needed for one's own.
    h.clock.advance(3600);
    let (t_secret, t_made) = make_token(&h, &tester, json!({"kind": "agent", "name": "mine"})).await;
    let r = h.api(Some(&tester.cookie), "GET", "/api/v1/tokens", None).await;
    assert_eq!(r.json().as_array().unwrap().len(), 1);
    // ...but not other people's, and not "all".
    let r = h
        .api(
            Some(&tester.cookie),
            "POST",
            "/api/v1/tokens",
            Some(json!({"kind": "agent", "name": "x", "for_user": "owner"})),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (403, "not_authorised"));
    let r = h.api(Some(&tester.cookie), "GET", "/api/v1/tokens?all=true", None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "not_authorised"));
    // A viewer may not manage tokens at all.
    let r = h.api(Some(&viewer.cookie), "POST", "/api/v1/tokens", Some(json!({"kind": "agent", "name": "v"}))).await;
    assert_eq!((r.status, r.code().as_str()), (403, "not_authorised"));
    // The owner's session is an hour old: for someone else's, it must be fresh.
    let r = h
        .api(
            Some(&owner.cookie),
            "POST",
            "/api/v1/tokens",
            Some(json!({"kind": "ci", "name": "for-tester", "for_user": "tester1"})),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (403, "fresh_login_required"), "{}", r.body);
    let r =
        h.api(Some(&owner.cookie), "DELETE", &format!("/api/v1/tokens/{}", t_made["id"].as_str().unwrap()), None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "fresh_login_required"), "{}", r.body);
    assert_eq!(
        bearer(&h, "GET", "/api/v1/status", &t_secret, None).await.status,
        200,
        "a refused revoke revokes nothing"
    );
    // ...but their own is not a sensitive action.
    make_token(&h, &owner, json!({"kind": "agent", "name": "owners"})).await;
    // After signing in again: fine, and the owner's list shows everyone's, with names.
    h.relogin(&mut owner).await;
    let (c_secret, c) =
        make_token(&h, &owner, json!({"kind": "ci", "name": "for-tester", "for_user": "tester1"})).await;
    assert_eq!(c["owner"], tester.user_id.as_str());
    assert_eq!(c["owner_name"], "tester1");
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &c_secret, None).await.json()["you_are"], "ci:for-tester");
    let all = h.api(Some(&owner.cookie), "GET", "/api/v1/tokens?all=true", None).await.json();
    assert_eq!(all.as_array().unwrap().len(), 3);
    assert_eq!(h.api(Some(&owner.cookie), "GET", "/api/v1/tokens", None).await.json().as_array().unwrap().len(), 1);
    // Not for a user who does not exist or is not a member.
    let r = h
        .api(
            Some(&owner.cookie),
            "POST",
            "/api/v1/tokens",
            Some(json!({"kind": "ci", "name": "ghost", "for_user": "nobody"})),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (404, "no_such_user"));
    // The owner revokes the tester's; the tester cannot revoke the owner's.
    let owners_id =
        all.as_array().unwrap().iter().find(|t| t["name"] == "owners").unwrap()["id"].as_str().unwrap().to_string();
    let r = h.api(Some(&tester.cookie), "DELETE", &format!("/api/v1/tokens/{owners_id}"), None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "not_authorised"));
    let r =
        h.api(Some(&owner.cookie), "DELETE", &format!("/api/v1/tokens/{}", t_made["id"].as_str().unwrap()), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &t_secret, None).await.status, 401, "dead at the next request");
    let r = h.api(Some(&owner.cookie), "DELETE", "/api/v1/tokens/t_unknown", None).await;
    assert_eq!((r.status, r.code().as_str()), (404, "no_such_token"));
    // The security log has creation and revocation, and who did it, never a secret.
    let log = format!("{:?}", h.accounts.security_log(300).unwrap());
    assert!(log.contains("token_created") && log.contains("token_revoked") && log.contains("token_first_use"));
    for s in [&t_secret, &c_secret] {
        assert!(!log.contains(s.as_str()));
    }
}

#[tokio::test]
async fn expiry_revocation_and_the_owners_state_take_effect_on_the_next_request() {
    let h = Harness::start(Kind::Plain).await;
    let mut owner = h.setup_owner().await;
    let mut tester = h.invited_user(&owner, "tester1", "tester").await;
    // Expiry, to the second.
    let (short, _) = make_token(&h, &tester, json!({"kind": "ci", "name": "job", "expires_days": 1})).await;
    h.clock.advance(86_399);
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &short, None).await.status, 200);
    h.clock.advance(1);
    let r = bearer(&h, "GET", "/api/v1/status", &short, None).await;
    assert_eq!((r.status, r.code().as_str()), (401, "invalid_token"));
    h.relogin(&mut owner).await;
    h.relogin(&mut tester).await;
    // Revocation by the owner of the token.
    let (s1, m1) = make_token(&h, &tester, json!({"kind": "agent", "name": "a1"})).await;
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &s1, None).await.status, 200);
    let r =
        h.api(Some(&tester.cookie), "DELETE", &format!("/api/v1/tokens/{}", m1["id"].as_str().unwrap()), None).await;
    assert_eq!(r.status, 200);
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &s1, None).await.status, 401);
    let listed = h.api(Some(&tester.cookie), "GET", "/api/v1/tokens", None).await.json();
    assert!(listed.as_array().unwrap().iter().any(|t| t["id"] == m1["id"] && t["status"] == "revoked"));
    // Demotion narrows: a tester's token becomes read-only at once; promotion does not widen it past its ceiling.
    let (s2, _) = make_token(&h, &tester, json!({"kind": "agent", "name": "a2"})).await;
    let hr = &h;
    let post = |s: String| async move { bearer(hr, "POST", "/api/v1/findings", &s, Some(json!({}))).await };
    assert!(post(s2.clone()).await.status != 403);
    h.accounts.set_membership(&owner.user_id, &h.project, &tester.user_id, pm_accounts::Role::Viewer).unwrap();
    let r = post(s2.clone()).await;
    assert_eq!((r.status, r.code().as_str()), (403, "read_only_token"), "{}", r.body);
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &s2, None).await.status, 200, "it can still read");
    h.accounts.set_membership(&owner.user_id, &h.project, &tester.user_id, pm_accounts::Role::Tester).unwrap();
    assert!(post(s2.clone()).await.status != 403, "back to tester");
    // A viewer's own ceiling: read-only whatever the owner is.
    let (s3, v3) = make_token(&h, &owner, json!({"kind": "plugin", "name": "reader", "role": "viewer"})).await;
    assert_eq!(v3["role"], "viewer");
    let r = post(s3.clone()).await;
    assert_eq!((r.status, r.code().as_str()), (403, "read_only_token"));
    assert_eq!(bearer(&h, "GET", "/api/v1/exchanges", &s3, None).await.status, 200);
    // Removing the membership kills the token; adding the person back does not bring it back.
    h.accounts.remove_membership(&owner.user_id, &h.project, &tester.user_id).unwrap();
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &s2, None).await.status, 401);
    h.accounts.set_membership(&owner.user_id, &h.project, &tester.user_id, pm_accounts::Role::Tester).unwrap();
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &s2, None).await.status, 401);
    // Disabling the owner (through the admin API) kills theirs at once; enabling does not revive them.
    let r = h
        .api(
            Some(&owner.cookie),
            "POST",
            "/api/v1/tokens",
            Some(json!({"kind": "agent", "name": "a4", "for_user": "tester1"})),
        )
        .await;
    let s4 = r.json()["token"].as_str().unwrap().to_string();
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &s4, None).await.status, 200);
    let r = h.api(Some(&owner.cookie), "POST", &format!("/api/v1/auth/users/{}/disable", tester.user_id), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &s4, None).await.status, 401);
    let r = h.api(Some(&owner.cookie), "POST", &format!("/api/v1/auth/users/{}/enable", tester.user_id), None).await;
    assert_eq!(r.status, 200);
    assert_eq!(bearer(&h, "GET", "/api/v1/status", &s4, None).await.status, 401);
}

#[tokio::test]
async fn a_tier_cap_is_enforced_by_the_gate_and_denials_are_audited() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let (capped, _) = make_token(&h, &owner, json!({"kind": "agent", "name": "careful", "tier_cap": "passive"})).await;
    let (free, _) = make_token(&h, &owner, json!({"kind": "agent", "name": "free"})).await;
    let send = json!({"url": "http://127.0.0.1:9/", "raw": "GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"});
    // The capped agent: a GET is active_safe, above its cap: denied by the gate, and the reason says why.
    let r = bearer(&h, "POST", "/api/v1/replay", &capped, Some(send.clone())).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["status"], "denied", "{}", r.body);
    assert!(r.json()["reasons"][0].as_str().unwrap().contains("limited to passive"), "{}", r.body);
    // The uncapped agent with the same rules gets past the gate (the send itself fails: nothing listens there).
    let r = bearer(&h, "POST", "/api/v1/replay", &free, Some(send.clone())).await;
    assert_ne!(r.json()["status"], "denied", "{}", r.body);
    // Both are recorded: the denial with the actor and the reason.
    let r = h.api(Some(&owner.cookie), "GET", "/api/v1/audit", None).await;
    let audit = r.json();
    let denied: Vec<&Value> =
        audit.as_array().unwrap().iter().filter(|a| a["actor"] == "agent:careful" && a["decision"] == "deny").collect();
    assert_eq!(denied.len(), 1, "{}", r.body);
    assert!(denied[0]["detail"].to_string().contains("limited to passive"), "{}", denied[0]);
    assert!(audit.as_array().unwrap().iter().any(|a| a["actor"] == "agent:free" && a["decision"] == "allow"));
    // Reading is not capped away: passive tools and plain reads work.
    assert_eq!(bearer(&h, "GET", "/api/v1/exchanges", &capped, None).await.status, 200);
    // The cap follows the credential, not the request: a new uncapped token of that name lifts it; the old one's
    // cap is held for the actor id until then.
    let again = bearer(&h, "POST", "/api/v1/replay", &capped, Some(send)).await;
    assert_eq!(again.json()["status"], "denied");
    // Approving cannot lift it: the gate checks the cap again when an approved action runs.
    let (mid, _) = make_token(&h, &owner, json!({"kind": "agent", "name": "mid", "tier_cap": "active_safe"})).await;
    let post = json!({"url": "http://127.0.0.1:9/x", "raw": "POST /x HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Length: 0\r\n\r\n"});
    let r = bearer(&h, "POST", "/api/v1/replay", &mid, Some(post)).await;
    assert_eq!(r.json()["status"], "denied", "{}", r.body);
    assert!(r.json()["reasons"][0].as_str().unwrap().contains("limited to active_safe"));
}

#[tokio::test]
async fn mcp_over_http_runs_the_tools_as_the_tokens_agent() {
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let (secret, _) =
        make_token(&h, &owner, json!({"kind": "agent", "name": "claude", "tier_cap": "active_safe"})).await;
    let rpc = |body: Value| bearer(&h, "POST", "/api/v1/mcp", &secret, Some(body));
    // The handshake and the tool list: the same 80-odd tools a local MCP agent gets.
    let r =
        rpc(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}))
            .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["result"]["serverInfo"]["name"], "proxymind");
    assert_eq!(rpc(json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).await.status, 204);
    let r = rpc(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).await;
    let names: Vec<String> =
        r.json()["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().into()).collect();
    assert!(names.len() > 80 && names.iter().any(|n| n == "replay_send") && names.iter().any(|n| n == "roe_get"));
    // A tool call acts as the token's agent, with its cap shown; an actor named in the message is ignored.
    let mut call = mcp_call(3, "roe_get", json!({}));
    call["params"]["actor"] = json!("human:owner");
    call["actor"] = json!("human:owner");
    let r = h
        .raw(
            "POST",
            "/api/v1/mcp?actor=human:owner",
            &[("Authorization", format!("Bearer {secret}")), ("X-ProxyMind-Actor", "human:owner".into())],
            Some(call),
        )
        .await;
    let roe = tool_json(&r);
    assert_eq!(roe["you_are"], "agent:claude", "{roe}");
    assert_eq!(roe["credential_tier_cap"], "active_safe");
    assert_eq!(roe["your_permissions"]["active_intrusive"], "deny", "the cap shows in what the agent may do");
    assert_eq!(roe["your_permissions"]["active_safe"], "allow");
    assert_eq!(roe["secrets_redacted"], true, "agents get what local MCP agents get: redaction");
    // A tool call that goes through the gate: denied above the cap, with the reason, as for a local agent.
    let r = rpc(mcp_call(4, "replay_send", json!({"url": "http://127.0.0.1:9/x", "raw": "POST /x HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Length: 0\r\n\r\n"}))).await;
    let v = tool_json(&r);
    assert_eq!(v["status"], "denied", "{v}");
    // Batches, errors and bad bodies.
    let r =
        rpc(json!([{"jsonrpc":"2.0","id":5,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"}]))
            .await;
    assert_eq!(r.json().as_array().unwrap().len(), 1);
    let r = rpc(json!({"jsonrpc":"2.0","id":6,"method":"nope"})).await;
    assert_eq!(r.json()["error"]["code"], -32601);
    let r = h.raw("POST", "/api/v1/mcp", &[("Authorization", format!("Bearer {secret}"))], None).await;
    assert_eq!((r.status, r.json()["error"]["code"].as_i64()), (400, Some(-32700)));
    // No credential, no MCP.
    let ping = json!({"jsonrpc":"2.0","id":1,"method":"ping"});
    assert_eq!(h.api(None, "POST", "/api/v1/mcp", Some(ping.clone())).await.status, 401);
    assert_eq!(
        h.raw("POST", "/api/v1/mcp", &[], Some(ping)).await.status,
        403,
        "not a bearer request: the browser layers apply"
    );
    // A viewer's token lists tools and calls the read ones (ADR-0022 step 6: roles are per tool); the tools that send
    // are refused.
    let (v, _) = make_token(&h, &owner, json!({"kind": "agent", "name": "reader", "role": "viewer"})).await;
    let r = bearer(&h, "POST", "/api/v1/mcp", &v, Some(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))).await;
    assert!(r.json()["result"]["tools"].is_array());
    let r = bearer(&h, "POST", "/api/v1/mcp", &v, Some(mcp_call(2, "roe_get", json!({})))).await;
    assert_eq!(r.json()["result"]["isError"], false, "{}", r.body);
    let r =
        bearer(&h, "POST", "/api/v1/mcp", &v, Some(mcp_call(3, "replay_send", json!({"url": "http://127.0.0.1:9/"}))))
            .await;
    assert_eq!(r.json()["result"]["isError"], true, "{}", r.body);
    assert!(r.json()["result"]["content"][0]["text"].as_str().unwrap().starts_with("access denied:"), "{}", r.body);
    // A signed-in person reaches it too, with the browser layers, and is the person.
    let r = h.api(Some(&owner.cookie), "POST", "/api/v1/mcp", Some(mcp_call(7, "roe_get", json!({})))).await;
    assert_eq!(tool_json(&r)["you_are"], "human:owner");
}

#[tokio::test]
async fn no_token_reaches_a_log_the_audit_trail_or_an_error() {
    let lines = captured().clone();
    let h = Harness::start(Kind::Plain).await;
    let owner = h.setup_owner().await;
    let mut secrets = Vec::new();
    for (kind, name, cap) in [("agent", "claude", Some("passive")), ("ci", "pipeline", None), ("plugin", "p", None)] {
        let mut body = json!({"kind": kind, "name": name});
        if let Some(c) = cap {
            body["tier_cap"] = json!(c);
        }
        let (s, v) = make_token(&h, &owner, body).await;
        // The answer that makes it holds the secret once; nothing else does.
        assert!(v.to_string().contains(&s));
        secrets.push(s);
    }
    let mut bodies: Vec<String> = Vec::new();
    for s in &secrets {
        // Use, a denied send, MCP, attempts to manage tokens and accounts: nothing answers with the token.
        for (m, p, b) in [
            ("GET", "/api/v1/status".to_string(), None),
            ("POST", "/api/v1/mcp".to_string(), Some(mcp_call(1, "roe_get", json!({})))),
            ("POST", "/api/v1/tokens".to_string(), Some(json!({"kind": "agent", "name": "child"}))),
            ("DELETE", "/api/v1/tokens/t_x".to_string(), None),
            ("GET", "/api/v1/auth/me".to_string(), None),
            (
                "POST",
                "/api/v1/replay".to_string(),
                Some(json!({"url": "http://127.0.0.1:9/", "raw": "GET / HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"})),
            ),
        ] {
            bodies.push(bearer(&h, m, &p, s, b).await.body);
        }
        // Failures with a near copy, and with the token where it does not belong (a query, a cookie).
        let mut near = s.clone();
        near.replace_range(near.len() - 1.., if near.ends_with('0') { "1" } else { "0" });
        bodies.push(bearer(&h, "GET", "/api/v1/status", &near, None).await.body);
        bodies.push(
            h.raw("GET", &format!("/api/v1/status?token={s}"), &[("Cookie", format!("pm_session={s}"))], None)
                .await
                .body,
        );
    }
    let owner_views = [
        h.api(Some(&owner.cookie), "GET", "/api/v1/tokens?all=true", None).await.body,
        h.api(Some(&owner.cookie), "GET", "/api/v1/audit", None).await.body,
        h.api(Some(&owner.cookie), "GET", "/api/v1/exchanges", None).await.body,
    ];
    let security = format!("{:?}", h.accounts.security_log(1000).unwrap());
    let logs = lines.lock().unwrap().join("\n");
    for s in &secrets {
        let tail = &s[s.len() - 24..];
        for (what, text) in [("log lines", &logs), ("security log", &security)] {
            assert!(!text.contains(s.as_str()) && !text.contains(tail), "a token is in the {what}");
        }
        for b in bodies.iter().chain(owner_views.iter()) {
            assert!(!b.contains(s.as_str()) && !b.contains(tail), "an answer holds a token: {b}");
        }
    }
    // The audit trail names tokens by id, and the security log recorded the failures.
    assert!(owner_views[1].contains("token_create"), "{}", owner_views[1]);
    assert!(security.contains("token_failure"));
}
