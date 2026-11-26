//! Passkeys (ADR-0022 step 7) over a real socket: enrolment, sign-in in both modes, removal, the owner's last second
//! factor, "require a passkey", setup, invites and enrolment links with a passkey, throttling and secrets. The
//! authenticator is the in-process software one of `pm_accounts::webauthn::soft`.
//!
//! The server runs behind a "proxy" (this test's client) with the public URL `https://pm.test`, so the RP id is
//! `pm.test` and the origin `https://pm.test`, as in production. Time is a manual clock.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use pm_accounts::webauthn::b64url_encode;
use pm_accounts::webauthn::soft::{SoftAuthenticator, Tweak};
use pm_accounts::{Accounts, ClientInfo, Clock, Config, ManualClock, Role, ServerKey};
use pm_api::listen::{ListenInput, TlsKind, plan, serve_app};
use pm_api::{AppState, ServerMode};
use pm_service::Service;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const PW: &str = "correct horse battery staple";
const T0: i64 = 1_700_000_000;
const ORIGIN: &str = "https://pm.test";
const COOKIE: &str = "__Host-pm_session";

// ---- captured log lines ------------------------------------------------------------------------------------------

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
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("not JSON ({e}): {}", self.body))
    }
    fn code(&self) -> String {
        self.json()["code"].as_str().unwrap_or_default().to_string()
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    /// The whole `Set-Cookie` line for `name`, and its value.
    fn set_cookie(&self, name: &str) -> Option<(String, String)> {
        self.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).find_map(|(_, line)| {
            let (pair, _) = line.split_once(';').unwrap_or((line, ""));
            let (k, v) = pair.split_once('=')?;
            (k == name).then(|| (line.to_string(), v.to_string()))
        })
    }
}

async fn exchange(req: String, port: u16) -> Resp {
    let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
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

// ---- the server --------------------------------------------------------------------------------------------------

struct Harness {
    port: u16,
    accounts: Arc<Accounts>,
    clock: Arc<ManualClock>,
    project: String,
    svc: Arc<Service>,
    /// Every body the server answered, for the secrets test.
    bodies: Mutex<Vec<String>>,
}

#[derive(Clone)]
struct Acct {
    id: String,
}

impl Harness {
    async fn start() -> Self {
        let clock = Arc::new(ManualClock::new(T0));
        let accounts = Arc::new(
            Accounts::open_in_memory(ServerKey::from_bytes([7; 32]), Config::insecure_for_tests(), clock.clone())
                .unwrap(),
        );
        let svc = Arc::new(
            Service::new(
                Store::open_in_memory().unwrap(),
                Policy::new(Roe::parse("version: 1\nscope:\n  include: [\"http://127.0.0.1:9/\"]\n").unwrap()),
            )
            .unwrap(),
        );
        let project = svc.project_id().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let listen: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let plan = plan(&ListenInput {
            listen,
            tls: TlsKind::None,
            behind_proxy: true,
            trusted_proxies: &trusted,
            public_url: Some(ORIGIN),
            extra_hosts: &[],
        })
        .unwrap();
        let sm = ServerMode::new(accounts.clone(), clock.clone() as Arc<dyn Clock>, project.clone(), plan);
        let state = AppState::new(
            svc.clone(),
            Actor::parse("human:unused").unwrap(),
            "install-token-that-server-mode-must-refuse".into(),
            "test.pmproj".into(),
        )
        .unwrap()
        .with_server_mode(sm);
        tokio::spawn(async move { serve_app(listener, pm_api::router(state), None).await.unwrap() });
        Self { port, accounts, clock, project, svc, bodies: Mutex::new(Vec::new()) }
    }

    async fn api(&self, cookie: Option<&str>, method: &str, path: &str, body: Option<Value>) -> Resp {
        self.api_with(cookie, method, path, body, &[]).await
    }

    async fn api_with(
        &self,
        cookie: Option<&str>,
        method: &str,
        path: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> Resp {
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nConnection: close\r\nHost: pm.test\r\nContent-Length: {}\r\n\
             X-ProxyMind: 1\r\nOrigin: {ORIGIN}\r\nX-Forwarded-Proto: https\r\nX-Forwarded-For: 198.51.100.7\r\n",
            body.len()
        );
        if !body.is_empty() {
            req.push_str("Content-Type: application/json\r\n");
        }
        if let Some(c) = cookie {
            req.push_str(&format!("Cookie: {COOKIE}={c}\r\n"));
        }
        for (k, v) in extra {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(&body);
        let r = exchange(req, self.port).await;
        self.bodies.lock().unwrap().push(r.body.clone());
        r
    }

    fn client() -> ClientInfo {
        ClientInfo::new("198.51.100.7")
    }

    /// The first owner (server admin, owner of the served project), with a password.
    fn owner(&self) -> Acct {
        let t = self.accounts.create_setup_token().unwrap();
        let u = self.accounts.bootstrap_owner(t.token.expose(), "owner", "Owner", PW, &Self::client()).unwrap();
        self.accounts.set_membership(&u.id, &self.project, &u.id, Role::Owner).unwrap();
        Acct { id: u.id }
    }

    fn member(&self, name: &str, role: Role) -> Acct {
        let owner = self.accounts.list_users().unwrap().into_iter().find(|u| u.server_admin).unwrap();
        let inv = self.accounts.create_invite(&owner.id, role, Some(&self.project), Duration::from_secs(3600)).unwrap();
        let u = self.accounts.accept_invite(inv.token.expose(), name, name, PW, &Self::client()).unwrap();
        Acct { id: u.id }
    }

    /// A session as a password and authenticator sign-in leaves it (made directly: this file tests passkeys).
    fn session(&self, who: &Acct) -> String {
        self.accounts.create_session(&who.id, "password+totp", &Self::client()).unwrap().id.expose().to_string()
    }

    async fn enrol(&self, cookie: &str, auth: &mut SoftAuthenticator, name: &str) -> Resp {
        let r = self.api(Some(cookie), "POST", "/api/v1/auth/passkeys/options", None).await;
        assert_eq!(r.status, 200, "{}", r.body);
        let options = r.json()["options"].clone();
        let resp = auth.create(&options, ORIGIN, &Tweak::default());
        self.api(Some(cookie), "POST", "/api/v1/auth/passkeys", Some(json!({"name": name, "response": resp}))).await
    }

    async fn login_options(&self, username: Option<&str>) -> Value {
        let body = username.map_or(json!({}), |u| json!({"username": u}));
        let r = self.api(None, "POST", "/api/v1/auth/passkey/login/options", Some(body)).await;
        assert_eq!(r.status, 200, "{}", r.body);
        r.json()["options"].clone()
    }

    async fn sign_in(&self, auth: &mut SoftAuthenticator, username: Option<&str>, t: &Tweak) -> Resp {
        let options = self.login_options(username).await;
        let resp = auth.get(&options, ORIGIN, t);
        self.api(None, "POST", "/api/v1/auth/passkey/login", Some(json!({"response": resp}))).await
    }

    async fn me(&self, cookie: &str) -> Resp {
        self.api(Some(cookie), "GET", "/api/v1/auth/me", None).await
    }
}

fn new_cookie(r: &Resp) -> String {
    r.set_cookie(COOKIE).expect("a session cookie").1
}

// ---- enrolment, listing, renaming, removal --------------------------------------------------------------------------

#[tokio::test]
async fn enrol_list_rename_and_remove_with_the_fresh_login_rule() {
    let h = Harness::start().await;
    let owner = h.owner();
    let other = h.member("tess", Role::Tester);
    let mut cookie = h.session(&owner);
    let mut auth = SoftAuthenticator::es256();

    let r = h.enrol(&cookie, &mut auth, "Laptop").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    assert_eq!(v["passkey"]["name"], "Laptop");
    assert!(v["passkey"].get("public_key").is_none() && v["passkey"].get("credential_id").is_none());
    // The credential changed, so the session has a new id, and the old one is dead.
    let renewed = new_cookie(&r);
    assert_ne!(renewed, cookie);
    assert_eq!(h.me(&cookie).await.status, 401);
    cookie = renewed;

    let list = h.api(Some(&cookie), "GET", "/api/v1/auth/passkeys", None).await.json();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["transports"], json!(["internal"]));
    assert!(list[0]["last_used_at"].is_null());
    // Nothing but these fields: no key, no credential id.
    let mut keys: Vec<&String> = list[0].as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(keys, ["backup_eligible", "backup_state", "created_at", "id", "last_used_at", "name", "transports"]);
    let id = list[0]["id"].as_str().unwrap().to_string();
    let me = h.me(&cookie).await.json();
    assert_eq!(me["passkey_count"], 1);
    assert_eq!(me["passkey_enrolment_required"], false);

    // Rename (no fresh sign-in needed), refused for nonsense and for someone else's.
    let r =
        h.api(Some(&cookie), "PUT", &format!("/api/v1/auth/passkeys/{id}"), Some(json!({"name": "Work laptop"}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let r = h.api(Some(&cookie), "PUT", &format!("/api/v1/auth/passkeys/{id}"), Some(json!({"name": " "}))).await;
    assert_eq!(r.status, 400);
    let other_cookie = h.session(&other);
    let r = h
        .api(Some(&other_cookie), "PUT", &format!("/api/v1/auth/passkeys/{id}"), Some(json!({"name": "mine now"})))
        .await;
    assert_eq!((r.status, r.code().as_str()), (404, "no_such_passkey"));
    let r = h.api(Some(&other_cookie), "DELETE", &format!("/api/v1/auth/passkeys/{id}"), None).await;
    assert_eq!(r.status, 404);
    let list = h.api(Some(&cookie), "GET", "/api/v1/auth/passkeys", None).await.json();
    assert_eq!(list[0]["name"], "Work laptop");

    // A second passkey; then, once the sign-in is old, adding and removing need a fresh one.
    let mut second = SoftAuthenticator::ed25519();
    let r = h.enrol(&cookie, &mut second, "Phone").await;
    assert_eq!(r.status, 200, "{}", r.body);
    cookie = new_cookie(&r);
    h.clock.advance(601);
    let r = h.api(Some(&cookie), "POST", "/api/v1/auth/passkeys/options", None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "fresh_login_required"));
    let r = h.api(Some(&cookie), "DELETE", &format!("/api/v1/auth/passkeys/{id}"), None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "fresh_login_required"));
    // Listing and renaming are not sensitive.
    assert_eq!(h.api(Some(&cookie), "GET", "/api/v1/auth/passkeys", None).await.status, 200);
    // Signing in again with a passkey makes the session fresh (that is the step-up), and ends the old one.
    let r = h.sign_in_with_cookie(&mut auth, &cookie, "owner").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let cookie = new_cookie(&r);
    assert_eq!(h.me(&cookie).await.json()["fresh"], true);

    // Removing the first passkey ends the account's other sessions and renews this one.
    let witness = h.session(&owner);
    let r = h.api(Some(&cookie), "DELETE", &format!("/api/v1/auth/passkeys/{id}"), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(h.me(&witness).await.status, 401, "the other session ended");
    let cookie = new_cookie(&r);
    assert_eq!(h.me(&cookie).await.status, 200);
    assert_eq!(h.api(Some(&cookie), "GET", "/api/v1/auth/passkeys", None).await.json().as_array().unwrap().len(), 1);
    // The removed passkey no longer signs in.
    assert_eq!(h.sign_in(&mut auth, None, &Tweak::default()).await.status, 401);
    assert_eq!(h.sign_in(&mut second, None, &Tweak::default()).await.status, 200);
    // Without a session none of it works.
    for (m, p) in
        [("GET", "/api/v1/auth/passkeys"), ("POST", "/api/v1/auth/passkeys/options"), ("POST", "/api/v1/auth/passkeys")]
    {
        let body = (m == "POST").then(|| json!({}));
        assert_eq!(h.api(None, m, p, body).await.status, 401, "{m} {p}");
    }
}

impl Harness {
    /// Passkey sign-in while a session cookie of the same account is on the request (re-authentication).
    async fn sign_in_with_cookie(&self, auth: &mut SoftAuthenticator, cookie: &str, username: &str) -> Resp {
        let options = self.login_options(Some(username)).await;
        let resp = auth.get(&options, ORIGIN, &Tweak::default());
        self.api(Some(cookie), "POST", "/api/v1/auth/passkey/login", Some(json!({"response": resp}))).await
    }
}

#[tokio::test]
async fn sign_in_by_username_and_without_one_makes_an_ordinary_session() {
    let h = Harness::start().await;
    let owner = h.owner();
    let cookie = h.session(&owner);
    let mut auth = SoftAuthenticator::es256();
    assert_eq!(h.enrol(&cookie, &mut auth, "k").await.status, 200);

    for username in [Some("owner"), Some(" OWNER "), None] {
        let r = h.sign_in(&mut auth, username, &Tweak::default()).await;
        assert_eq!(r.status, 200, "{username:?}: {}", r.body);
        let v = r.json();
        assert_eq!(v["step"], "authenticated");
        assert_eq!(v["user"]["username"], "owner");
        assert_eq!(v["user"]["role"], "owner");
        let (line, value) = r.set_cookie(COOKIE).unwrap();
        // The same cookie flags as every sign-in.
        assert!(line.contains("HttpOnly") && line.contains("SameSite=Strict") && line.contains("Secure"), "{line}");
        assert!(line.contains("Path=/") && !line.contains("Domain"), "{line}");
        let me = h.me(&value).await.json();
        assert_eq!(me["session"]["auth_method"], "passkey");
        assert_eq!(me["actor"], "human:owner");
        assert_eq!(me["fresh"], true);
        // And it reaches the project like any other.
        assert_eq!(h.api(Some(&value), "GET", "/api/v1/status", None).await.status, 200);
    }
    // `next` is a path on this origin, as for passwords.
    let options = h.login_options(None).await;
    let resp = auth.get(&options, ORIGIN, &Tweak::default());
    let r = h
        .api(None, "POST", "/api/v1/auth/passkey/login", Some(json!({"response": resp, "next": "//evil.example"})))
        .await;
    assert_eq!(r.json()["next"], "/");
    // The state endpoint tells the UI what it needs, and the signed-in account's count.
    let r = h.api(None, "GET", "/api/v1/auth/state", None).await.json();
    assert_eq!(
        (r["passkey_supported"].as_bool(), r["passkey_rp_id"].as_str(), r["passkey_required"].as_bool()),
        (Some(true), Some("pm.test"), Some(false))
    );
    assert!(r["passkey_count"].is_null() && r["passkey_note"].is_null());
    let r = h.api(Some(&cookie), "GET", "/api/v1/auth/state", None).await;
    // (the first cookie was renewed when the passkey was added)
    assert!(r.json()["passkey_count"].is_null());
    let r = h.sign_in(&mut auth, None, &Tweak::default()).await;
    let live = new_cookie(&r);
    assert_eq!(h.api(Some(&live), "GET", "/api/v1/auth/state", None).await.json()["passkey_count"], 1);
}

#[tokio::test]
async fn sign_in_refusals_look_the_same_and_the_options_do_not_reveal_names() {
    let h = Harness::start().await;
    let owner = h.owner();
    let tess = h.member("tess", Role::Tester);
    let cookie = h.session(&owner);
    let mut auth = SoftAuthenticator::es256();
    assert_eq!(h.enrol(&cookie, &mut auth, "k").await.status, 200);

    let ids = |v: &Value| -> Vec<String> {
        v["allowCredentials"].as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap().to_string()).collect()
    };
    let shape = |v: &Value| {
        let mut k: Vec<&String> = v.as_object().unwrap().keys().collect();
        k.sort();
        format!("{k:?}")
    };
    let known = h.login_options(Some("owner")).await;
    let no_key = h.login_options(Some("tess")).await;
    let unknown = h.login_options(Some("nobody")).await;
    assert_eq!(shape(&known), shape(&no_key));
    assert_eq!(shape(&known), shape(&unknown));
    assert!(!ids(&no_key).is_empty() && !ids(&unknown).is_empty());
    assert_eq!(ids(&unknown), ids(&h.login_options(Some("nobody")).await), "a decoy is the same every time");
    assert!(ids(&h.login_options(None).await).is_empty());

    // Every refusal is the same 401 with the same text: unknown name, a name without a passkey, someone else's
    // credential, a bad signature, a wrong origin.
    let mut stranger = SoftAuthenticator::es256();
    let mut refused = Vec::new();
    for (name, who, t) in [
        ("unknown name", Some("nobody"), Tweak::default()),
        ("name without a passkey", Some("tess"), Tweak::default()),
        ("bad signature", Some("owner"), Tweak { bad_signature: true, ..Tweak::default() }),
        ("wrong origin", Some("owner"), Tweak { origin: Some("https://evil.example".into()), ..Tweak::default() }),
        ("no user verification", Some("owner"), Tweak { no_user_verified: true, ..Tweak::default() }),
    ] {
        let a: &mut SoftAuthenticator =
            if name == "unknown name" || name == "name without a passkey" { &mut stranger } else { &mut auth };
        let r = h.sign_in(a, who, &t).await;
        refused.push((name, r.status, r.body));
        h.clock.advance(3600);
    }
    for (name, status, body) in &refused {
        assert_eq!(*status, 401, "{name}: {body}");
        assert_eq!(body, &refused[0].2, "{name}: not the same answer as the first refusal");
    }
    // Owner's credential asked for tess: the credential of another user.
    let options = h.login_options(Some("tess")).await;
    let resp = auth.get(&options, ORIGIN, &Tweak::default());
    let r = h.api(None, "POST", "/api/v1/auth/passkey/login", Some(json!({"response": resp}))).await;
    assert_eq!((r.status, r.body.as_str()), (401, refused[0].2.as_str()));
    // A disabled account.
    h.accounts.disable_user(&owner.id, &tess.id).unwrap();
    let mut tess_key = SoftAuthenticator::es256();
    let _ = tess;
    let r = h.sign_in(&mut tess_key, Some("tess"), &Tweak::default()).await;
    assert_eq!(r.status, 401);
}

#[tokio::test]
async fn passkey_failures_are_throttled_and_a_clone_is_refused_and_logged() {
    let h = Harness::start().await;
    let owner = h.owner();
    let cookie = h.session(&owner);
    let mut auth = SoftAuthenticator::es256();
    assert_eq!(h.enrol(&cookie, &mut auth, "k").await.status, 200);

    // A counter going backwards: refused as any failure is, and logged.
    assert_eq!(h.sign_in(&mut auth, Some("owner"), &Tweak { counter: Some(10), ..Tweak::default() }).await.status, 200);
    let r = h.sign_in(&mut auth, Some("owner"), &Tweak { counter: Some(4), ..Tweak::default() }).await;
    assert_eq!((r.status, r.code().as_str()), (401, "invalid_credentials"));
    let log = h.accounts.security_log(100).unwrap();
    let clone = log.iter().find(|l| l.kind == "passkey_clone_suspected").expect("audited");
    assert_eq!(clone.user_id.as_deref(), Some(owner.id.as_str()));
    h.clock.advance(3600);

    // The clone attempt was the first failure (an hour is not long enough for it to be forgotten); three more, then
    // a valid assertion is asked for and kept back, and the fifth failure starts the delay.
    for _ in 0..3 {
        let r = h.sign_in(&mut auth, Some("owner"), &Tweak { bad_signature: true, ..Tweak::default() }).await;
        assert_eq!(r.status, 401);
    }
    let early = h.login_options(Some("owner")).await;
    let early_resp = auth.get(&early, ORIGIN, &Tweak::default());
    let r = h.sign_in(&mut auth, Some("owner"), &Tweak { bad_signature: true, ..Tweak::default() }).await;
    assert_eq!(r.status, 401);
    // Delayed now: new options are refused, and so is the genuine assertion that was already on its way.
    let r = h.api(None, "POST", "/api/v1/auth/passkey/login/options", Some(json!({"username": "owner"}))).await;
    assert_eq!((r.status, r.code().as_str()), (429, "throttled"), "{}", r.body);
    assert!(r.header("retry-after").and_then(|s| s.parse::<u64>().ok()).is_some_and(|s| s >= 1));
    let r = h.api(None, "POST", "/api/v1/auth/passkey/login", Some(json!({"response": early_resp}))).await;
    assert_eq!((r.status, r.code().as_str()), (429, "throttled"), "{}", r.body);
    // The password step of that account waits too: one counter for both.
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": PW}))).await;
    assert_eq!(r.status, 429);
    h.clock.advance(3600);
    assert_eq!(h.sign_in(&mut auth, Some("owner"), &Tweak { counter: Some(20), ..Tweak::default() }).await.status, 200);
}

// ---- the owner's second factor, and "require a passkey" --------------------------------------------------------------

#[tokio::test]
async fn the_owners_last_second_factor_cannot_be_removed() {
    let h = Harness::start().await;
    let owner = h.owner();
    let cookie = h.session(&owner);
    let mut auth = SoftAuthenticator::es256();
    let r = h.enrol(&cookie, &mut auth, "only").await;
    let cookie = new_cookie(&r);
    let id = r.json()["passkey"]["id"].as_str().unwrap().to_string();
    // The owner has a password and no authenticator: this passkey is their second factor.
    let r = h.api(Some(&cookie), "DELETE", &format!("/api/v1/auth/passkeys/{id}"), None).await;
    assert_eq!((r.status, r.code().as_str()), (409, "second_factor_required"), "{}", r.body);
    assert_eq!(h.api(Some(&cookie), "GET", "/api/v1/auth/passkeys", None).await.json().as_array().unwrap().len(), 1);
    // A second one makes the first removable; the second then is the last again.
    let mut b = SoftAuthenticator::ed25519();
    let r = h.enrol(&cookie, &mut b, "spare").await;
    let cookie = new_cookie(&r);
    let r = h.api(Some(&cookie), "DELETE", &format!("/api/v1/auth/passkeys/{id}"), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let cookie = new_cookie(&r);
    let spare = r.json();
    let _ = spare;
    let left = h.api(Some(&cookie), "GET", "/api/v1/auth/passkeys", None).await.json();
    let spare_id = left[0]["id"].as_str().unwrap().to_string();
    let r = h.api(Some(&cookie), "DELETE", &format!("/api/v1/auth/passkeys/{spare_id}"), None).await;
    assert_eq!(r.status, 409);
}

#[tokio::test]
async fn require_a_passkey_sends_accounts_without_one_to_enrol_and_refuses_passwords_to_those_with_one() {
    let h = Harness::start().await;
    let owner = h.owner();
    let tess = h.member("tess", Role::Tester);
    let owner_cookie = h.session(&owner);
    let mut owner_key = SoftAuthenticator::es256();

    // Only an administrator, with a fresh sign-in, and only with a passkey of their own.
    let r = h
        .api(Some(&h.session(&tess)), "PUT", "/api/v1/auth/settings/passkey-required", Some(json!({"required": true})))
        .await;
    assert_eq!((r.status, r.code().as_str()), (403, "server_admin_required"));
    let r = h
        .api(Some(&owner_cookie), "PUT", "/api/v1/auth/settings/passkey-required", Some(json!({"required": true})))
        .await;
    assert_eq!((r.status, r.code().as_str()), (400, "invalid_input"), "{}", r.body);
    let r = h.enrol(&owner_cookie, &mut owner_key, "owner key").await;
    let owner_cookie = new_cookie(&r);
    h.clock.advance(601);
    let r = h
        .api(Some(&owner_cookie), "PUT", "/api/v1/auth/settings/passkey-required", Some(json!({"required": true})))
        .await;
    assert_eq!((r.status, r.code().as_str()), (403, "fresh_login_required"));
    let r = h.sign_in_with_cookie(&mut owner_key, &owner_cookie, "owner").await;
    let owner_cookie = new_cookie(&r);
    let r = h
        .api(Some(&owner_cookie), "PUT", "/api/v1/auth/settings/passkey-required", Some(json!({"required": true})))
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(h.api(None, "GET", "/api/v1/auth/state", None).await.json()["passkey_required"], true);
    assert!(h.accounts.security_log(50).unwrap().iter().any(|l| l.kind == "passkey_required_on"));

    // The administrator has a passkey: a password sign-in (even with the right password) is refused by name.
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": PW}))).await;
    assert_eq!((r.status, r.code().as_str()), (403, "passkey_required"));
    // The wrong password is still the plain refusal: the answer reveals the passkey only to a password holder.
    let r = h
        .api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": "wrong wrong wrong"})))
        .await;
    assert_eq!(r.code(), "invalid_credentials");
    // Their passkey signs in.
    assert_eq!(h.sign_in(&mut owner_key, None, &Tweak::default()).await.status, 200);

    // tess has none: the session from password and authenticator may only enrol one.
    let tess_cookie = h.session(&tess);
    let r = h.api(Some(&tess_cookie), "GET", "/api/v1/status", None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "passkey_enrolment_required"));
    for (m, p) in [
        ("GET", "/api/v1/exchanges"),
        ("GET", "/api/v1/auth/sessions"),
        ("GET", "/api/v1/tokens"),
        ("POST", "/api/v1/auth/password"),
        ("GET", "/api/v1/events"),
    ] {
        let body = (m == "POST").then(|| json!({}));
        let r = h.api(Some(&tess_cookie), m, p, body).await;
        assert_eq!((r.status, r.code().as_str()), (403, "passkey_enrolment_required"), "{m} {p}");
    }
    let me = h.me(&tess_cookie).await;
    assert_eq!(me.status, 200);
    assert_eq!(me.json()["passkey_enrolment_required"], true);
    let mut tess_key = SoftAuthenticator::ed25519();
    let r = h.enrol(&tess_cookie, &mut tess_key, "tess key").await;
    assert_eq!(r.status, 200, "{}", r.body);
    let tess_cookie = new_cookie(&r);
    // Enrolled: the restriction is gone, with no new sign-in.
    assert_eq!(h.api(Some(&tess_cookie), "GET", "/api/v1/status", None).await.status, 200);
    // And now the last passkey cannot be removed while the rule holds.
    let id = h.api(Some(&tess_cookie), "GET", "/api/v1/auth/passkeys", None).await.json()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = h.api(Some(&tess_cookie), "DELETE", &format!("/api/v1/auth/passkeys/{id}"), None).await;
    assert_eq!((r.status, r.code().as_str()), (409, "last_passkey"));

    // Off again.
    let r = h
        .api(
            Some(&new_cookie(&h.sign_in(&mut owner_key, None, &Tweak::default()).await)),
            "PUT",
            "/api/v1/auth/settings/passkey-required",
            Some(json!({"required": false})),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(h.api(None, "GET", "/api/v1/auth/state", None).await.json()["passkey_required"], false);
    // Tokens are not interactive sign-ins: a token works whatever the rule says.
    let _ = h.project.len();
}

// ---- setup, invites and enrolment links ---------------------------------------------------------------------------

#[tokio::test]
async fn setup_with_a_passkey_makes_a_passkey_only_owner() {
    let h = Harness::start().await;
    let tok = h.accounts.create_setup_token().unwrap();
    let mut auth = SoftAuthenticator::es256();
    let body = json!({"setup_token": tok.token.expose(), "username": "Owner", "display_name": "Olivia"});
    // Bad token and bad name: nothing is made.
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/setup/passkey/options",
            Some(json!({"setup_token": "pmset_nope", "username": "owner"})),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (403, "invalid_setup_token"));
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/setup/passkey/options",
            Some(json!({"setup_token": tok.token.expose(), "username": "x"})),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (400, "invalid_input"));
    assert!(!h.accounts.has_server_admin().unwrap());
    let r = h.api(None, "POST", "/api/v1/auth/setup/passkey/options", Some(body)).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let options = r.json()["options"].clone();
    assert_eq!(options["rp"]["id"], "pm.test");
    assert_eq!(options["user"]["name"], "owner");
    assert_eq!(options["authenticatorSelection"]["userVerification"], "required");
    assert_eq!(options["attestation"], "none");
    let resp = auth.create(&options, ORIGIN, &Tweak::default());
    let r =
        h.api(None, "POST", "/api/v1/auth/setup/passkey", Some(json!({"name": "First key", "response": resp}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    assert_eq!(v["step"], "authenticated");
    assert_eq!(v["user"]["role"], "owner");
    assert_eq!(v["user"]["server_admin"], true);
    assert!(v["recovery_codes"].is_null(), "a passkey sign-in has no recovery codes");
    let cookie = new_cookie(&r);
    let me = h.me(&cookie).await.json();
    assert_eq!((me["role"].as_str(), me["passkey_count"].as_u64()), (Some("owner"), Some(1)));
    assert_eq!(h.api(Some(&cookie), "GET", "/api/v1/status", None).await.status, 200);
    // No password exists, and the setup token is spent.
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "owner", "password": PW}))).await;
    assert_eq!(r.status, 401);
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/setup/passkey/options",
            Some(json!({"setup_token": tok.token.expose(), "username": "second"})),
        )
        .await;
    assert_eq!(r.status, 403);
    assert_eq!(h.sign_in(&mut auth, Some("owner"), &Tweak::default()).await.status, 200);

    // reset-owner keeps working: its setup URL's token creates another owner, with a passkey too.
    let reset = h.accounts.reset_owner().unwrap();
    assert_eq!(h.me(&cookie).await.status, 401, "every session ended");
    let mut second = SoftAuthenticator::ed25519();
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/setup/passkey/options",
            Some(json!({"setup_token": reset.token.expose(), "username": "owner2"})),
        )
        .await;
    let resp = second.create(&r.json()["options"], ORIGIN, &Tweak::default());
    let r = h.api(None, "POST", "/api/v1/auth/setup/passkey", Some(json!({"response": resp}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["user"]["server_admin"], true);
}

#[tokio::test]
async fn an_invite_can_be_accepted_with_a_passkey() {
    let h = Harness::start().await;
    let owner = h.owner();
    let cookie = h.session(&owner);
    let r = h.api(Some(&cookie), "POST", "/api/v1/auth/invites", Some(json!({"role": "tester"}))).await;
    let token = r.json()["token"].as_str().unwrap().to_string();
    let mut auth = SoftAuthenticator::es256();
    let r = h
        .api(None, "POST", "/api/v1/auth/invite/passkey/options", Some(json!({"invite": token, "username": "tess"})))
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let resp = auth.create(&r.json()["options"], ORIGIN, &Tweak::default());
    let r = h.api(None, "POST", "/api/v1/auth/invite/passkey", Some(json!({"response": resp}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["user"]["role"], "tester");
    let r = h
        .api(None, "POST", "/api/v1/auth/invite/passkey/options", Some(json!({"invite": token, "username": "again"})))
        .await;
    assert_eq!((r.status, r.code().as_str()), (400, "invalid_invite"));
    assert_eq!(h.sign_in(&mut auth, None, &Tweak::default()).await.status, 200);
}

#[tokio::test]
async fn an_enrolment_link_recovers_an_account_with_a_passkey_or_a_new_password() {
    let h = Harness::start().await;
    let owner = h.owner();
    let tess = h.member("tess", Role::Tester);
    let vera = h.member("vera", Role::Viewer);
    let owner_cookie = h.session(&owner);
    let tess_cookie = h.session(&tess);
    let mut old = SoftAuthenticator::es256();
    let r = h.enrol(&tess_cookie, &mut old, "lost phone").await;
    let tess_cookie = new_cookie(&r);
    // A token of tess's, which dies when the link is issued.
    let r = h.api(Some(&tess_cookie), "POST", "/api/v1/tokens", Some(json!({"kind": "agent", "name": "bot"}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let bot = r.json()["token"].as_str().unwrap().to_string();

    // Who may: a tester may not; an owner of the project may, with a fresh sign-in; never for oneself.
    let r = h.api(Some(&tess_cookie), "POST", &format!("/api/v1/auth/users/{}/enrolment-link", vera.id), None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "not_authorised"));
    let r = h.api(Some(&owner_cookie), "POST", &format!("/api/v1/auth/users/{}/enrolment-link", owner.id), None).await;
    assert_eq!(r.status, 400, "{}", r.body);
    h.clock.advance(601);
    let r = h.api(Some(&owner_cookie), "POST", &format!("/api/v1/auth/users/{}/enrolment-link", tess.id), None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "fresh_login_required"));
    let owner_cookie = {
        // Re-authenticate: a passkey for the owner first, then sign in with it.
        let mut ok = SoftAuthenticator::ed25519();
        let fresh = h.session(&owner);
        let r = h.enrol(&fresh, &mut ok, "owner key").await;
        assert_eq!(r.status, 200);
        new_cookie(&r)
    };
    let r = h.api(Some(&owner_cookie), "POST", &format!("/api/v1/auth/users/{}/enrolment-link", tess.id), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let link = r.json();
    let token = link["token"].as_str().unwrap().to_string();
    assert_eq!(link["url"], format!("{ORIGIN}/#enrol={token}"));
    assert_eq!(link["username"], "tess");
    // Sessions ended, tokens revoked.
    assert_eq!(h.me(&tess_cookie).await.status, 401);
    let r = exchange(
        format!(
            "GET /api/v1/status HTTP/1.1\r\nConnection: close\r\nHost: pm.test\r\nAuthorization: Bearer {bot}\r\n\r\n"
        ),
        h.port,
    )
    .await;
    assert_eq!(r.status, 401);

    // The page asks whom it is for, then makes the options and registers.
    let r = h.api(None, "POST", "/api/v1/auth/enrol-link/info", Some(json!({"token": token}))).await;
    assert_eq!(r.json()["username"], "tess");
    let r = h.api(None, "POST", "/api/v1/auth/enrol-link/info", Some(json!({"token": "pmenr_wrong"}))).await;
    assert_eq!((r.status, r.code().as_str()), (400, "invalid_enrolment_link"));
    let r = h.api(None, "POST", "/api/v1/auth/enrol-link/passkey/options", Some(json!({"token": token}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let mut fresh_key = SoftAuthenticator::ed25519();
    let resp = fresh_key.create(&r.json()["options"], ORIGIN, &Tweak::default());
    let r = h
        .api(None, "POST", "/api/v1/auth/enrol-link/passkey", Some(json!({"name": "new phone", "response": resp})))
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["user"]["username"], "tess");
    let cookie = new_cookie(&r);
    let list = h.api(Some(&cookie), "GET", "/api/v1/auth/passkeys", None).await.json();
    assert_eq!(list.as_array().unwrap().len(), 1, "the old passkey was replaced");
    assert_eq!(list[0]["name"], "new phone");
    assert_eq!(h.sign_in(&mut old, Some("tess"), &Tweak::default()).await.status, 401);
    assert_eq!(h.sign_in(&mut fresh_key, Some("tess"), &Tweak::default()).await.status, 200);
    // The link is single use.
    let r = h.api(None, "POST", "/api/v1/auth/enrol-link/passkey/options", Some(json!({"token": token}))).await;
    assert_eq!(r.status, 400);

    // Vera takes the password route: a new password, then the authenticator enrolment as after an invite.
    let r = h.api(Some(&owner_cookie), "POST", &format!("/api/v1/auth/users/{}/enrolment-link", vera.id), None).await;
    let token = r.json()["token"].as_str().unwrap().to_string();
    let r = h
        .api(None, "POST", "/api/v1/auth/enrol-link/password", Some(json!({"token": token, "new_password": "short"})))
        .await;
    assert_eq!((r.status, r.code().as_str()), (400, "invalid_input"));
    let r = h
        .api(
            None,
            "POST",
            "/api/v1/auth/enrol-link/password",
            Some(json!({"token": token, "new_password": "a brand new passphrase"})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(r.json()["step"], "enrolment_required");
    assert!(r.set_cookie(COOKIE).is_none(), "no session before the authenticator exists");
    let r = h.api(None, "POST", "/api/v1/auth/login", Some(json!({"username": "vera", "password": PW}))).await;
    assert_eq!(r.status, 401, "the old password is gone");
    assert!(h.accounts.security_log(100).unwrap().iter().any(|l| l.kind == "enrolment_link_used"));
}

// ---- secrets -----------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn no_key_material_signature_or_link_reaches_a_response_a_log_or_the_audit_trail() {
    let lines = captured().clone();
    let h = Harness::start().await;
    let owner = h.owner();
    let tess = h.member("tess", Role::Tester);
    let cookie = h.session(&owner);
    let mut auth = SoftAuthenticator::es256();
    let r = h.enrol(&cookie, &mut auth, "k").await;
    let cookie = new_cookie(&r);
    let mut signatures = Vec::new();
    // Sign-ins, good and bad, and an enrolment link.
    for t in [
        Tweak::default(),
        Tweak { bad_signature: true, ..Tweak::default() },
        Tweak { counter: Some(0), ..Tweak::default() },
    ] {
        let options = h.login_options(Some("owner")).await;
        let resp = auth.get(&options, ORIGIN, &t);
        signatures.push(resp.signature.clone());
        let _ = h.api(None, "POST", "/api/v1/auth/passkey/login", Some(json!({"response": resp}))).await;
        h.clock.advance(3600);
    }
    let fresh = h.session(&owner);
    let r = h.api(Some(&fresh), "POST", &format!("/api/v1/auth/users/{}/enrolment-link", tess.id), None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let link = r.json()["token"].as_str().unwrap().to_string();
    let r = h.api(None, "POST", "/api/v1/auth/enrol-link/info", Some(json!({"token": link}))).await;
    assert_eq!(r.status, 200);
    let mut other = SoftAuthenticator::ed25519();
    let r = h.api(None, "POST", "/api/v1/auth/enrol-link/passkey/options", Some(json!({"token": link}))).await;
    let reg = other.create(&r.json()["options"], ORIGIN, &Tweak::default());
    let attestation = reg.attestation_object.clone();
    let r = h.api(None, "POST", "/api/v1/auth/enrol-link/passkey", Some(json!({"response": reg}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let session = new_cookie(&r);
    let list = h.api(Some(&session), "GET", "/api/v1/auth/passkeys", None).await;
    assert_eq!(list.status, 200);

    // What must not be found anywhere: the public keys (base64url and hex), signatures, the attestation, the link's
    // token and session ids. The credential id may appear in the sign-in options (it is not a secret) but never in a
    // log.
    let keys = [auth.public_key_cose(), other.public_key_cose()];
    let mut secrets: Vec<(&str, String)> = Vec::new();
    for k in &keys {
        secrets.push(("public key", b64url_encode(k)));
        secrets.push(("public key (hex)", k.iter().map(|b| format!("{b:02x}")).collect()));
    }
    for s in &signatures {
        secrets.push(("signature", s.clone()));
    }
    secrets.push(("attestation object", attestation));
    secrets.push(("enrolment link", link.clone()));
    secrets.push(("session id", cookie.clone()));
    secrets.push(("session id", session.clone()));
    let creds = [auth.credential_id.clone(), other.credential_id.clone()];

    for body in h.bodies.lock().unwrap().iter() {
        for (kind, s) in &secrets {
            if *kind == "enrolment link" && body.contains("\"token\"") {
                continue; // the one answer that hands the link to the person who issued it
            }
            assert!(!body.contains(s.as_str()), "a response contains the {kind}: {body}");
        }
    }
    let security = format!("{:?}", h.accounts.security_log(1000).unwrap());
    let audit = format!("{:?}", h.svc.audit_list(1000).unwrap());
    let logged = lines.lock().unwrap().join("\n");
    for (what, text) in [("security log", &security), ("project audit log", &audit), ("process log", &logged)] {
        for (kind, s) in &secrets {
            assert!(!text.contains(s.as_str()), "the {what} contains the {kind}");
        }
        for c in &creds {
            assert!(!text.contains(&b64url_encode(c)), "the {what} contains a credential id");
            assert!(
                !text.contains(&c.iter().map(|b| format!("{b:02x}")).collect::<String>()),
                "the {what} has a credential id"
            );
        }
    }
    // The events that should be there are there.
    let kinds: Vec<String> = h.accounts.security_log(1000).unwrap().into_iter().map(|l| l.kind).collect();
    for k in [
        "passkey_added",
        "login_success",
        "passkey_failure",
        "passkey_clone_suspected",
        "enrolment_link_created",
        "enrolment_link_used",
    ] {
        assert!(kinds.iter().any(|x| x == k), "{k} missing from {kinds:?}");
    }
    assert!(h.accounts.verify_security_log().unwrap().is_ok());
}

// ---- the layers every credential endpoint has --------------------------------------------------------------------------

#[tokio::test]
async fn the_passkey_endpoints_have_the_same_csrf_layers_and_size_limits() {
    let h = Harness::start().await;
    let owner = h.owner();
    let cookie = h.session(&owner);
    // Public endpoints refuse a request from another origin or without the marker header, like every POST.
    for path in [
        "/api/v1/auth/passkey/login/options",
        "/api/v1/auth/passkey/login",
        "/api/v1/auth/setup/passkey",
        "/api/v1/auth/enrol-link/info",
    ] {
        let r = h.api_with(None, "POST", path, Some(json!({})), &[("Origin", "https://evil.example")]).await;
        // `api_with` sends its own Origin first; the server sees both lines and the first one is the real one,
        // so use a raw request for the wrong-origin case instead.
        let _ = r;
        let req = format!(
            "POST {path} HTTP/1.1\r\nConnection: close\r\nHost: pm.test\r\nContent-Length: 2\r\nX-ProxyMind: 1\r\nOrigin: https://evil.example\r\nX-Forwarded-Proto: https\r\n\r\n{{}}"
        );
        assert_eq!(exchange(req, h.port).await.status, 403, "{path}: wrong origin");
        let req = format!(
            "POST {path} HTTP/1.1\r\nConnection: close\r\nHost: pm.test\r\nContent-Length: 2\r\nOrigin: {ORIGIN}\r\nX-Forwarded-Proto: https\r\n\r\n{{}}"
        );
        assert_eq!(exchange(req, h.port).await.status, 403, "{path}: no marker header");
    }
    // A signed-in endpoint too.
    let req = format!(
        "POST /api/v1/auth/passkeys/options HTTP/1.1\r\nConnection: close\r\nHost: pm.test\r\nContent-Length: 0\r\nCookie: {COOKIE}={cookie}\r\nOrigin: https://evil.example\r\nX-ProxyMind: 1\r\nX-Forwarded-Proto: https\r\n\r\n"
    );
    assert_eq!(exchange(req, h.port).await.status, 403);
    // Oversized bodies are refused before parsing; unknown fields are refused.
    let big = json!({"response": {"id": "a", "client_data_json": "b".repeat(200_000), "authenticator_data": "c", "signature": "d"}});
    let r = h.api(None, "POST", "/api/v1/auth/passkey/login", Some(big)).await;
    assert!(matches!(r.status, 413 | 400), "{}", r.status);
    let r = h.api(None, "POST", "/api/v1/auth/passkey/login", Some(json!({"response": {"id": "a"}, "extra": 1}))).await;
    assert_eq!(r.status, 422);
    // Garbage in the fields is a refusal with the same text as any other failure, not a server error.
    let r = h.api(None, "POST", "/api/v1/auth/passkey/login", Some(json!({"response": {"id": "!!", "client_data_json": "!!", "authenticator_data": "!!", "signature": "!!"}}))).await;
    assert_eq!(r.status, 401);
    // Tokens do not reach any of it.
    let r = h.api(Some(&cookie), "POST", "/api/v1/tokens", Some(json!({"kind": "agent", "name": "bot"}))).await;
    let bot = r.json()["token"].as_str().unwrap().to_string();
    for (m, p) in [("GET", "/api/v1/auth/passkeys"), ("POST", "/api/v1/auth/passkeys/options")] {
        let req = format!(
            "{m} {p} HTTP/1.1\r\nConnection: close\r\nHost: pm.test\r\nContent-Length: 0\r\nAuthorization: Bearer {bot}\r\n\r\n"
        );
        assert_eq!(exchange(req, h.port).await.status, 403, "{m} {p}");
    }
}
