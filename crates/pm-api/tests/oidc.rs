//! Signing in with an OpenID Connect provider (ADR-0022 step 8) over a real socket, against an in-process fake provider
//! (`common::Idp`: discovery, a key set with RS256 and ES256 keys, an authorize endpoint that redirects back, a token
//! endpoint that checks the `redirect_uri`, PKCE S256, the client's credentials and that a code is used once).
//!
//! The browser is played by this file: it follows the redirects by hand with a cookie jar, and, as a real browser does,
//! sends only the `SameSite=Lax` state cookie to the callback (the `Strict` session cookie does not travel on a
//! redirect from another site). The server runs behind a "proxy" with the public URL `https://pm.test`; time is a
//! manual clock shared with the provider.

mod common;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use common::{Grant, Idp, IssParam, NonceMode, Tweak, browser_get};
use pm_accounts::oidc::{BeginPurpose, OidcOutcome, OidcProvider, ProviderInput, RoleMapping, SecretChange};
use pm_accounts::webauthn::RelyingParty;
use pm_accounts::webauthn::soft::{SoftAuthenticator, Tweak as SoftTweak};
use pm_accounts::{Accounts, ClientInfo, Clock, Config, ManualClock, Role, Secret, ServerKey};
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
const CALLBACK: &str = "https://pm.test/api/v1/auth/oidc/callback";
const SESSION: &str = "__Host-pm_session";
const STATE: &str = "__Host-pm_oidc";
const CLIENT_SECRET: &str = "Cs-9f3a1c77-unique-client-secret-for-grep";

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
    fn set_cookies(&self) -> Vec<&str> {
        self.headers.iter().filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie")).map(|(_, v)| v.as_str()).collect()
    }
    fn set_cookie(&self, name: &str) -> Option<&str> {
        self.set_cookies().into_iter().find(|l| l.starts_with(&format!("{name}=")))
    }
    fn location(&self) -> &str {
        self.header("location").unwrap_or_else(|| panic!("no Location in {self:?}"))
    }
    /// The `oidc_error` code of a redirect, if it carries one.
    fn error(&self) -> Option<String> {
        let l = self.header("location")?;
        let q = l.split_once('?')?.1.split('#').next()?;
        url::form_urlencoded::parse(q.as_bytes()).find(|(k, _)| k == "oidc_error").map(|(_, v)| v.into_owned())
    }
    fn raw(&self) -> String {
        format!("{} {:?} {}", self.status, self.headers, self.body)
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

/// The cookies a browser holds for the server.
#[derive(Default, Clone)]
struct Jar(HashMap<String, String>);

impl Jar {
    fn take(&mut self, r: &Resp) {
        for line in r.set_cookies() {
            let (pair, attrs) = line.split_once(';').unwrap_or((line, ""));
            let Some((k, v)) = pair.split_once('=') else { continue };
            if attrs.contains("Max-Age=0") || v.is_empty() {
                self.0.remove(k);
            } else {
                self.0.insert(k.to_string(), v.to_string());
            }
        }
    }
    fn session(&self) -> Option<&str> {
        self.0.get(SESSION).map(String::as_str)
    }
    fn state(&self) -> Option<&str> {
        self.0.get(STATE).map(String::as_str)
    }
    /// What the browser sends to the callback: the Lax state cookie only.
    fn for_callback(&self) -> Jar {
        Jar(self.0.iter().filter(|(k, _)| k.as_str() == STATE).map(|(k, v)| (k.clone(), v.clone())).collect())
    }
    fn header(&self) -> Option<String> {
        (!self.0.is_empty()).then(|| self.0.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("; "))
    }
}

// ---- the server --------------------------------------------------------------------------------------------------

struct H {
    port: u16,
    accounts: Arc<Accounts>,
    clock: Arc<ManualClock>,
    project: String,
    svc: Arc<Service>,
    idp: Idp,
    admin: Acct,
    /// Every response the server made, whole, for the secrets test.
    seen: Mutex<Vec<String>>,
    /// Every value the provider handed out (codes, verifiers, tokens).
    handed_out: Mutex<Vec<String>>,
}

#[derive(Clone)]
struct Acct {
    id: String,
}

impl H {
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
        let idp = Idp::start(clock.clone(), CALLBACK, CLIENT_SECRET).await;
        let t = accounts.create_setup_token().unwrap();
        let u = accounts.bootstrap_owner(t.token.expose(), "owner", "Owner", PW, &Self::client()).unwrap();
        accounts.set_membership(&u.id, &project, &u.id, Role::Owner).unwrap();
        Self {
            port,
            accounts,
            clock,
            project,
            svc,
            idp,
            admin: Acct { id: u.id },
            seen: Mutex::new(vec![]),
            handed_out: Mutex::new(vec![]),
        }
    }

    fn client() -> ClientInfo {
        ClientInfo::new("198.51.100.7")
    }

    async fn send(&self, method: &str, path: &str, jar: &Jar, body: Option<Value>) -> Resp {
        let body = body.map(|b| b.to_string()).unwrap_or_default();
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nConnection: close\r\nHost: pm.test\r\nContent-Length: {}\r\n\
             X-Forwarded-Proto: https\r\nX-Forwarded-For: 198.51.100.7\r\n",
            body.len()
        );
        if method != "GET" {
            req.push_str(&format!("X-ProxyMind: 1\r\nOrigin: {ORIGIN}\r\n"));
        }
        if !body.is_empty() {
            req.push_str("Content-Type: application/json\r\n");
        }
        if let Some(c) = jar.header() {
            req.push_str(&format!("Cookie: {c}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(&body);
        let r = exchange(req, self.port).await;
        self.seen.lock().unwrap().push(r.raw());
        r
    }

    async fn get(&self, path: &str, jar: &Jar) -> Resp {
        self.send("GET", path, jar, None).await
    }

    async fn api(&self, method: &str, path: &str, cookie: &str, body: Option<Value>) -> Resp {
        let jar = Jar(HashMap::from([(SESSION.to_string(), cookie.to_string())]));
        self.send(method, path, &jar, body).await
    }

    fn member(&self, name: &str, role: Role) -> Acct {
        let inv =
            self.accounts.create_invite(&self.admin.id, role, Some(&self.project), Duration::from_secs(3600)).unwrap();
        let u = self.accounts.accept_invite(inv.token.expose(), name, name, PW, &Self::client()).unwrap();
        Acct { id: u.id }
    }

    fn session(&self, who: &Acct) -> String {
        self.accounts.create_session(&who.id, "password+totp", &Self::client()).unwrap().id.expose().to_string()
    }

    fn input(&self, edit: impl FnOnce(&mut ProviderInput)) -> ProviderInput {
        let mut i = ProviderInput {
            name: "Corp SSO".into(),
            issuer: self.idp.issuer.clone(),
            client_id: self.idp.client_id.clone(),
            client_secret: SecretChange::Set(Secret::new(CLIENT_SECRET)),
            scopes: vec!["profile".into(), "email".into()],
            group_claim: Some("groups".into()),
            role_map: vec![],
            auto_create_domains: vec![],
            email_linking: false,
            required_acr: vec![],
            required_amr: vec![],
            enabled: true,
        };
        edit(&mut i);
        i
    }

    fn provider(&self, edit: impl FnOnce(&mut ProviderInput)) -> OidcProvider {
        self.accounts.oidc_provider_create(&self.admin.id, self.input(edit)).unwrap()
    }

    /// Links `sub` to `who` the way the Account page does, without the browser (a live fresh session of theirs).
    fn link(&self, p: &OidcProvider, who: &Acct, sub: &str, email: Option<&str>) {
        let s = self.accounts.create_session(&who.id, "password+totp", &Self::client()).unwrap();
        let b = self
            .accounts
            .oidc_begin(
                &p.id,
                BeginPurpose::Link { user_id: who.id.clone(), session_ref: s.reference, fresh_secs: 600 },
                "/",
                &Self::client(),
            )
            .unwrap();
        let pending = self.accounts.oidc_take(b.binding.expose(), &b.state).unwrap();
        let claims = pm_accounts::oidc::jwt::IdClaims {
            iss: p.issuer.clone(),
            sub: sub.into(),
            email: email.map(str::to_string),
            email_verified: email.is_some(),
            name: None,
            preferred_username: None,
            groups: vec![],
            acr: None,
            amr: vec![],
        };
        assert!(matches!(
            self.accounts.oidc_complete(pending, &claims, &self.project, &Self::client()).unwrap(),
            OidcOutcome::Linked(_)
        ));
    }

    /// A passkey for `who` (so an owner has a local way in), made with the software authenticator.
    fn passkey(&self, who: &Acct) {
        let rp = RelyingParty { id: "pm.test".into(), name: "ProxyMind".into(), origins: vec![ORIGIN.into()] };
        let s = self.session(who);
        let mut auth = SoftAuthenticator::es256();
        let opts = self.accounts.passkey_begin_enrol(&rp, &who.id, &s).unwrap();
        let resp = auth.create(&opts, ORIGIN, &SoftTweak::default());
        self.accounts.passkey_finish_enrol(&rp, &who.id, &s, "key", &resp).unwrap();
    }

    // ---- the browser's part of the flow ---------------------------------------------------------------------

    /// `GET /start`: returns the provider URL the browser is sent to (and keeps the state cookie in `jar`).
    async fn begin(&self, jar: &mut Jar, provider: &str, query: &str) -> (Resp, String) {
        let r = self.get(&format!("/api/v1/auth/oidc/{provider}/start{query}"), jar).await;
        jar.take(&r);
        let loc = r.header("location").unwrap_or_default().to_string();
        (r, loc)
    }

    /// The provider's answer to the browser: the callback path (and query) it redirects to.
    async fn authorize(&self, location: &str) -> String {
        let (status, loc) = browser_get(location).await;
        assert_eq!(status, 302, "the provider did not redirect: {location}");
        let loc = loc.unwrap();
        self.note_handed_out();
        loc.strip_prefix(ORIGIN).unwrap_or_else(|| panic!("redirected away from the server: {loc}")).to_string()
    }

    async fn callback(&self, jar: &mut Jar, path: &str) -> Resp {
        let r = self.get(path, &jar.for_callback()).await;
        jar.take(&r);
        self.note_handed_out();
        r
    }

    /// A whole sign-in: start, the provider, the callback. Returns the callback's answer.
    async fn sign_in(&self, jar: &mut Jar, provider: &str, query: &str) -> Resp {
        let (r, loc) = self.begin(jar, provider, query).await;
        assert_eq!(r.status, 302, "{r:?}");
        let cb = self.authorize(&loc).await;
        self.callback(jar, &cb).await
    }

    fn note_handed_out(&self) {
        self.idp.with(|i| {
            let mut v = self.handed_out.lock().unwrap();
            v.extend([i.last_code.clone(), i.last_verifier.clone(), i.last_id_token.clone()].into_iter().flatten());
        });
    }

    async fn me(&self, jar: &Jar) -> Resp {
        let c = jar.session().expect("a session cookie");
        self.api("GET", "/api/v1/auth/me", c, None).await
    }

    fn failures(&self, reason: &str) -> usize {
        self.accounts
            .security_log(500)
            .unwrap()
            .iter()
            .filter(|l| l.kind == "oidc_failure" && l.detail == reason)
            .count()
    }

    fn role_of(&self, who: &Acct) -> Option<Role> {
        self.accounts
            .memberships_of_user(&who.id)
            .unwrap()
            .into_iter()
            .find(|m| m.project_id == self.project)
            .map(|m| m.role)
    }
}

#[track_caller]
fn signed_in(r: &Resp, jar: &Jar) {
    assert_eq!(r.status, 302, "{r:?}");
    assert!(r.error().is_none(), "refused: {:?}", r.error());
    assert!(jar.session().is_some(), "no session cookie after {r:?}");
}

#[track_caller]
fn refused(r: &Resp, jar: &Jar, code: &str) {
    assert_eq!(r.status, 302, "{r:?}");
    assert_eq!(r.error().as_deref(), Some(code), "{r:?}");
    assert!(jar.session().is_none(), "a refused sign-in set a session cookie");
    assert!(r.location().starts_with('/'), "an error redirect must stay on this origin: {}", r.location());
}

// ---- the happy path ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_linked_user_signs_in_with_rs256_and_with_es256() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    h.link(&p, &tess, "sub-tess", Some("tess@corp.example"));
    for (signer, alg) in [(0usize, "RS256"), (1, "ES256")] {
        h.idp.set_grant(Grant::new("sub-tess").email("tess@corp.example", true));
        h.idp.set_tweak(Tweak { signer, ..Tweak::default() });
        let mut jar = Jar::default();
        let (r, loc) = h.begin(&mut jar, &p.id, "?next=%2F%23%2Faccount").await;
        // The state cookie: HttpOnly, Lax, host-only (`__Host-`), Secure behind TLS, ten minutes.
        let cookie = r.set_cookie(STATE).expect("a state cookie");
        for part in ["Path=/", "HttpOnly", "SameSite=Lax", "Max-Age=600", "Secure"] {
            assert!(cookie.contains(part), "{cookie}");
        }
        assert!(!cookie.contains("Domain") && !cookie.contains("Strict"));
        // What the provider was asked: code flow, PKCE S256, the exact redirect URI, openid plus the configured scopes.
        let cb = h.authorize(&loc).await;
        let q = h.idp.with(|i| i.authorize_queries.last().cloned().unwrap());
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["redirect_uri"], CALLBACK);
        assert_eq!(q["scope"], "openid profile email");
        assert_eq!(q["client_id"], "proxymind-test");
        assert!(q["state"].len() >= 40 && q["nonce"].len() >= 40 && q["code_challenge"].len() == 43);
        let r = h.callback(&mut jar, &cb).await;
        signed_in(&r, &jar);
        assert_eq!(r.location(), "/#/account", "{alg}: lands where it was going");
        assert!(r.set_cookie(STATE).is_some_and(|c| c.contains("Max-Age=0")), "the state cookie is spent");
        assert!(jar.state().is_none());
        let me = h.me(&jar).await.json();
        assert_eq!(me["user"]["username"], "tess", "{alg}");
        assert_eq!(me["session"]["auth_method"], "oidc");
        assert_eq!(me["role"], "tester");
    }
    assert_eq!(h.idp.with(|i| i.pkce_failures), 0, "the provider checked every S256 challenge");
    assert_eq!(h.idp.with(|i| i.bad_redirect_uris), 0);
    // Discovery and keys were fetched once and cached for the second sign-in.
    assert_eq!(h.idp.hits("discovery"), 1);
    assert_eq!(h.idp.hits("jwks"), 1);
    // The audit trail names the method and the link.
    let kinds: Vec<String> = h.accounts.security_log(100).unwrap().into_iter().map(|l| l.kind).collect();
    assert!(kinds.iter().any(|k| k == "login_success"));
    assert!(kinds.iter().any(|k| k == "oidc_identity_linked"));
}

#[tokio::test]
async fn the_login_page_lists_providers_by_id_and_name_only() {
    let h = H::start().await;
    let p = h.provider(|_| {});
    let r = h.get("/api/v1/auth/state", &Jar::default()).await;
    let list = r.json()["oidc_providers"].clone();
    assert_eq!(list, json!([{"id": p.id, "name": "Corp SSO"}]));
    let off = h.input(|i| {
        i.enabled = false;
        i.client_secret = SecretChange::Keep;
    });
    h.accounts.oidc_provider_update(&h.admin.id, &p.id, off).unwrap();
    assert_eq!(h.get("/api/v1/auth/state", &Jar::default()).await.json()["oidc_providers"], json!([]));
    // A disabled or unknown provider does not start.
    let (r, _) = h.begin(&mut Jar::default(), &p.id, "").await;
    assert_eq!(r.error().as_deref(), Some("unknown_provider"));
    let (r, _) = h.begin(&mut Jar::default(), "op_0000000000000000", "").await;
    assert_eq!(r.error().as_deref(), Some("unknown_provider"));
}

// ---- tokens that must be refused ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_token_that_is_not_exactly_right_is_refused() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    h.link(&p, &tess, "sub-tess", None);
    h.idp.set_grant(Grant::new("sub-tess"));
    let id = h.idp.client_id.clone();
    let cases: Vec<(&str, Tweak, &str)> = vec![
        ("wrong iss", Tweak { iss: Some("https://evil.example".into()), ..Tweak::default() }, "iss mismatch"),
        ("iss with a slash", Tweak { iss: Some(format!("{}/", h.idp.issuer)), ..Tweak::default() }, "iss mismatch"),
        ("wrong aud", Tweak { aud: Some(json!("someone-else")), ..Tweak::default() }, "aud mismatch"),
        ("aud list without us", Tweak { aud: Some(json!(["a", "b"])), ..Tweak::default() }, "aud mismatch"),
        (
            "azp is not us",
            Tweak { aud: Some(json!([id.clone(), "other"])), azp: Some(json!("other")), ..Tweak::default() },
            "azp mismatch",
        ),
        (
            "several audiences, no azp",
            Tweak { aud: Some(json!([id.clone(), "other"])), ..Tweak::default() },
            "azp missing",
        ),
        ("wrong nonce", Tweak { nonce: NonceMode::Wrong, ..Tweak::default() }, "nonce mismatch"),
        ("no nonce", Tweak { nonce: NonceMode::Missing, ..Tweak::default() }, "nonce missing"),
        ("expired", Tweak { exp_delta: -3600, ..Tweak::default() }, "expired"),
        ("iat in the future", Tweak { iat_delta: 3600, ..Tweak::default() }, "iat in the future"),
        ("alg none", Tweak { alg: Some("none"), ..Tweak::default() }, "algorithm not allowed"),
        ("HS256 with the client secret", Tweak { alg: Some("HS256"), ..Tweak::default() }, "algorithm not allowed"),
    ];
    let mut by_reason: HashMap<&str, usize> = HashMap::new();
    for (name, tweak, reason) in cases {
        h.idp.set_tweak(tweak);
        let mut jar = Jar::default();
        let r = h.sign_in(&mut jar, &p.id, "").await;
        refused(&r, &jar, "invalid_token");
        *by_reason.entry(reason).or_default() += 1;
        assert_eq!(h.failures(reason), by_reason[reason], "{name}: the security log names the reason");
        // Failures count against the address: let them fade so the next case is judged on its own.
        h.clock.advance(4000);
    }
    // And the good token still works afterwards.
    h.idp.set_tweak(Tweak::default());
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
}

#[tokio::test]
async fn a_token_from_an_unknown_key_refetches_the_key_set_once_and_rotation_works() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    h.link(&p, &tess, "sub-tess", None);
    h.idp.set_grant(Grant::new("sub-tess"));
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    assert_eq!(h.idp.hits("jwks"), 1);
    // The provider signs with a key its key set does not list: one refetch, then refused.
    h.idp.set_tweak(Tweak { signer: 2, ..Tweak::default() });
    h.clock.advance(31);
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "invalid_token");
    assert_eq!(h.idp.hits("jwks"), 2, "one refetch");
    // Forged tokens do not make the server hammer the provider: no second refetch inside the interval.
    for _ in 0..3 {
        h.clock.advance(1);
        let mut jar = Jar::default();
        refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "invalid_token");
    }
    assert_eq!(h.idp.hits("jwks"), 2, "rate limited");
    assert!(h.failures("unknown signing key") >= 4);
    // The provider publishes the new key (rotation): the next unknown kid, after the interval, refetches and works.
    h.idp.with(|i| i.published = vec![0, 1, 2]);
    h.clock.advance(31);
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    assert_eq!(h.idp.hits("jwks"), 3);
    // The old key is withdrawn: tokens from it are refused once the key set is refreshed (an hour), the new one works.
    h.idp.with(|i| i.published = vec![2]);
    h.clock.advance(3601);
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    h.idp.set_tweak(Tweak { signer: 0, ..Tweak::default() });
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "invalid_token");
}

#[tokio::test]
async fn keys_are_never_fetched_from_a_url_in_the_token() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    h.link(&p, &tess, "sub-tess", None);
    h.idp.set_grant(Grant::new("sub-tess"));
    let evil = format!("{}/evil", h.idp.issuer);
    // A valid token that carries a `jku` still signs in (the header is ignored), and nothing is fetched from it.
    h.idp.set_tweak(Tweak { jku: Some(evil.clone()), ..Tweak::default() });
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    // A token signed by an unlisted key that points at its own key set is refused, and that URL is not fetched either.
    h.idp.set_tweak(Tweak { jku: Some(evil), signer: 2, ..Tweak::default() });
    h.clock.advance(31);
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "invalid_token");
    assert_eq!(h.idp.hits("evil"), 0);
}

// ---- discovery and the issuer ----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_discovery_document_with_another_issuer_or_a_plain_http_endpoint_is_refused() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    h.link(&p, &tess, "sub-tess", None);
    h.idp.set_grant(Grant::new("sub-tess"));
    h.idp.with(|i| i.discovery_issuer = Some("https://evil.example".into()));
    let mut jar = Jar::default();
    let (r, _) = h.begin(&mut jar, &p.id, "").await;
    assert_eq!(r.error().as_deref(), Some("provider_unreachable"));
    assert!(jar.state().is_none(), "no state cookie for a sign-in that did not start");
    h.idp.with(|i| {
        i.discovery_issuer = None;
        i.discovery_http_endpoint = true;
    });
    h.clock.advance(3601);
    let (r, _) = h.begin(&mut jar, &p.id, "").await;
    assert_eq!(r.error().as_deref(), Some("provider_unreachable"), "an http endpoint that is not loopback");
    h.idp.with(|i| i.discovery_http_endpoint = false);
    h.clock.advance(3601);
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
}

#[tokio::test]
async fn the_iss_response_parameter_stops_a_mix_up() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    h.link(&p, &tess, "sub-tess", None);
    h.idp.set_grant(Grant::new("sub-tess"));
    // Discovery says the provider sends `iss`: it is then required, and must be the issuer.
    for (name, mode) in
        [("missing", IssParam::Missing), ("another provider's", IssParam::Wrong("https://evil.example".into()))]
    {
        h.idp.with(|i| {
            i.iss_param = mode;
            i.advertise_iss_param = true;
        });
        h.clock.advance(3601);
        let before = h.idp.hits("token");
        let mut jar = Jar::default();
        refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "invalid_state");
        assert_eq!(h.idp.hits("token"), before, "{name}: refused before the code was sent anywhere");
        assert!(h.failures("iss parameter mismatch") >= 1);
    }
    // A provider that does not claim to send it: absent is fine, wrong is not.
    h.idp.with(|i| {
        i.advertise_iss_param = false;
        i.iss_param = IssParam::Missing;
    });
    h.clock.advance(3601);
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    h.idp.with(|i| i.iss_param = IssParam::Wrong("https://evil.example".into()));
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "invalid_state");
    h.clock.advance(4000);
    // The right parameter is accepted.
    h.idp.with(|i| i.iss_param = IssParam::Correct);
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
}

// ---- state, replay, foreign browsers --------------------------------------------------------------------------------

#[tokio::test]
async fn state_is_single_use_and_bound_to_the_browser_that_started_it() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    h.link(&p, &tess, "sub-tess", None);
    h.idp.set_grant(Grant::new("sub-tess"));

    // A replayed callback: the same URL and cookie after a successful sign-in find nothing, and never reach the provider.
    let mut jar = Jar::default();
    let (_, loc) = h.begin(&mut jar, &p.id, "").await;
    let cb = h.authorize(&loc).await;
    let saved = jar.for_callback();
    signed_in(&h.callback(&mut jar, &cb).await, &jar);
    let tokens = h.idp.hits("token");
    let mut replayer = saved.clone();
    let r = h.callback(&mut replayer, &cb).await;
    refused(&r, &replayer, "invalid_state");
    assert_eq!(h.idp.hits("token"), tokens, "no second token request");

    // No cookie at all.
    let mut jar = Jar::default();
    let (_, loc) = h.begin(&mut jar, &p.id, "").await;
    let cb = h.authorize(&loc).await;
    let mut bare = Jar::default();
    refused(&h.callback(&mut bare, &cb).await, &bare, "invalid_state");

    // A wrong state, with the right cookie: refused, and the attempt used the sign-in up (no second try).
    let mut jar = Jar::default();
    let (_, loc) = h.begin(&mut jar, &p.id, "").await;
    let cb = h.authorize(&loc).await;
    let forged = cb.replace("state=", "state=x");
    refused(&h.callback(&mut jar.clone(), &forged).await, &Jar::default(), "invalid_state");
    refused(&h.callback(&mut jar.clone(), &cb).await, &Jar::default(), "invalid_state");

    // The callback of one browser carried by another browser's cookie (login CSRF: an attacker's `code` and `state`
    // delivered to a victim) finds nothing.
    let (mut alice, mut mallory) = (Jar::default(), Jar::default());
    let (_, loc_a) = h.begin(&mut alice, &p.id, "").await;
    let (_, _loc_m) = h.begin(&mut mallory, &p.id, "").await;
    let cb_a = h.authorize(&loc_a).await;
    let before = h.idp.hits("token");
    let mut victim = mallory.for_callback();
    refused(&h.callback(&mut victim, &cb_a).await, &victim, "invalid_state");
    assert_eq!(h.idp.hits("token"), before);
    assert!(h.failures("unknown, used or foreign state") >= 3);
}

#[tokio::test]
async fn a_provider_error_or_a_refused_code_is_a_plain_failure() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    h.link(&p, &tess, "sub-tess", None);
    h.idp.set_grant(Grant::new("sub-tess"));
    // The person said no at the provider.
    let mut jar = Jar::default();
    let (_, loc) = h.begin(&mut jar, &p.id, "").await;
    let _ = h.authorize(&loc).await;
    let st = h.idp.with(|i| i.authorize_queries.last().unwrap()["state"].clone());
    let r = h
        .callback(
            &mut jar,
            &format!("/api/v1/auth/oidc/callback?error=access_denied&state={st}&error_description=%3Cscript%3E"),
        )
        .await;
    refused(&r, &jar, "denied");
    assert!(!r.location().contains("script"), "nothing from the provider is echoed");
    // The token endpoint fails.
    h.idp.with(|i| i.token_status = Some(500));
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "provider_error");
    h.idp.with(|i| i.token_status = None);
    // A code the provider already used is refused by the provider (a replayed code at the token endpoint).
    let mut jar = Jar::default();
    let (_, loc) = h.begin(&mut jar, &p.id, "").await;
    let cb = h.authorize(&loc).await;
    let code = h.idp.with(|i| i.last_code.clone().unwrap());
    signed_in(&h.callback(&mut jar, &cb).await, &jar);
    let mut second = Jar::default();
    let (_, loc2) = h.begin(&mut second, &p.id, "").await;
    let st2 = url::Url::parse(&loc2).unwrap().query_pairs().find(|(k, _)| k == "state").unwrap().1.into_owned();
    let _ = h.authorize(&loc2).await;
    // The fresh state with the old, used code.
    let r = h
        .callback(&mut second, &format!("/api/v1/auth/oidc/callback?code={code}&state={st2}&iss={}", h.idp.issuer))
        .await;
    refused(&r, &second, "provider_error");
}

// ---- redirects ---------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn only_a_path_on_this_origin_is_followed_and_the_redirect_uri_is_fixed() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    h.link(&p, &tess, "sub-tess", None);
    h.idp.set_grant(Grant::new("sub-tess"));
    for next in [
        "%2F%2Fevil.example",
        "https%3A%2F%2Fevil.example%2F",
        "%2F%5Cevil.example",
        "javascript%3Aalert(1)",
        "evil.example",
        "%2F%0A%2Fevil.example",
        "%2F%09%2Fevil.example",
    ] {
        let mut jar = Jar::default();
        let r = h.sign_in(&mut jar, &p.id, &format!("?next={next}")).await;
        signed_in(&r, &jar);
        assert_eq!(r.location(), "/", "next={next}");
        h.clock.advance(1);
    }
    let mut jar = Jar::default();
    let r = h.sign_in(&mut jar, &p.id, "?next=%2Fexchanges%3Fid%3D3").await;
    assert_eq!(r.location(), "/exchanges?id=3");
    // A `redirect_uri` (or anything else) in the start request changes nothing: the provider is always told the same.
    let mut jar = Jar::default();
    let r = h.sign_in(&mut jar, &p.id, "?redirect_uri=https%3A%2F%2Fevil.example%2Fcb&next=%2F").await;
    signed_in(&r, &jar);
    assert_eq!(h.idp.with(|i| i.authorize_queries.last().unwrap()["redirect_uri"].clone()), CALLBACK);
    assert_eq!(h.idp.with(|i| i.bad_redirect_uris), 0);
    // An error redirect stays on this origin too, whatever `next` was.
    h.idp.set_tweak(Tweak { iss: Some("https://evil.example".into()), ..Tweak::default() });
    let mut jar = Jar::default();
    let r = h.sign_in(&mut jar, &p.id, "?next=%2F%2Fevil.example").await;
    refused(&r, &jar, "invalid_token");
}

// ---- who gets in and with which role -----------------------------------------------------------------------------------

#[tokio::test]
async fn joining_is_by_invite_unless_the_owner_enabled_auto_create_for_a_domain() {
    let h = H::start().await;
    let off = h.provider(|_| {});
    h.idp.set_grant(Grant::new("newcomer").email("new@corp.example", true));
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &off.id, "").await, &jar, "no_account");
    assert_eq!(h.accounts.list_users().unwrap().len(), 1, "no account was made");
    // On for corp.example: a viewer, and only for that domain with a verified address.
    let on = h.input(|i| {
        i.auto_create_domains = vec!["corp.example".into()];
        i.client_secret = SecretChange::Keep;
        i.role_map = vec![RoleMapping { value: "testers".into(), role: Role::Tester }];
    });
    h.accounts.oidc_provider_update(&h.admin.id, &off.id, on).unwrap();
    h.clock.advance(4000);
    for g in [
        Grant::new("a").email("a@other.example", true),
        Grant::new("b").email("b@corp.example", false),
        Grant::new("c").email("c@sub.corp.example", true),
    ] {
        h.idp.set_grant(g);
        let mut jar = Jar::default();
        refused(&h.sign_in(&mut jar, &off.id, "").await, &jar, "no_account");
    }
    h.clock.advance(4000);
    // The provider also claims the group that maps to tester: a new account is a viewer all the same.
    h.idp.set_grant(Grant::new("newcomer").email("new@corp.example", true).groups(&["testers"]));
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &off.id, "").await, &jar);
    let me = h.me(&jar).await.json();
    assert_eq!(me["user"]["username"], "new@corp.example");
    assert_eq!(me["role"], "viewer");
    assert_eq!(me["user"]["server_admin"], false);
    // A viewer reads and does not send.
    let c = jar.session().unwrap();
    assert_eq!(h.api("GET", "/api/v1/exchanges", c, None).await.status, 200);
    assert_eq!(h.api("POST", "/api/v1/replay", c, Some(json!({}))).await.status, 403);
    // The sign-in made the account with the identity as its only way in, and no password.
    assert!(h.accounts.login_password("new@corp.example", "anything at all", &H::client()).is_err());
    // A passkey requirement does not lock an identity-provider session out (it has the provider's assurance).
    h.passkey(&h.admin);
    h.accounts.set_passkey_required(&h.admin.id, true).unwrap();
    assert_eq!(h.me(&jar).await.json()["passkey_enrolment_required"], false);
    assert_eq!(h.api("GET", "/api/v1/exchanges", c, None).await.status, 200);
}

#[tokio::test]
async fn linking_by_email_is_off_by_default_and_needs_a_verified_address() {
    let h = H::start().await;
    let tess = h.member("tess@corp.example", Role::Tester);
    let p = h.provider(|_| {});
    h.idp.set_grant(Grant::new("sub-1").email("tess@corp.example", true));
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "no_account");
    assert!(h.accounts.oidc_identities(&tess.id).unwrap().is_empty());
    let on = h.input(|i| {
        i.email_linking = true;
        i.client_secret = SecretChange::Keep;
    });
    h.accounts.oidc_provider_update(&h.admin.id, &p.id, on).unwrap();
    h.clock.advance(4000);
    h.idp.set_grant(Grant::new("sub-1").email("tess@corp.example", false));
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "no_account");
    h.idp.set_grant(Grant::new("sub-1").email("tess@corp.example", true));
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    assert_eq!(h.me(&jar).await.json()["user"]["id"], tess.id);
    assert_eq!(h.accounts.oidc_identities(&tess.id).unwrap()[0].linked_by, "email");
    // The identity is now the pair, not the address: the same address under another subject is not this account.
    h.idp.set_grant(Grant::new("sub-2").email("tess@corp.example", true));
    h.clock.advance(4000);
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "already_linked");
    // An owner or administrator is never linked by email.
    let boss = h.member("boss@corp.example", Role::Owner);
    h.idp.set_grant(Grant::new("sub-boss").email("boss@corp.example", true));
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "not_permitted");
    assert!(h.accounts.oidc_identities(&boss.id).unwrap().is_empty());
}

#[tokio::test]
async fn a_disabled_account_is_refused() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    h.link(&p, &tess, "sub-tess", None);
    h.idp.set_grant(Grant::new("sub-tess"));
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    h.accounts.disable_user(&h.admin.id, &tess.id).unwrap();
    let mut jar = Jar::default();
    refused(&h.sign_in(&mut jar, &p.id, "").await, &jar, "not_permitted");
}

#[tokio::test]
async fn a_group_claim_gives_tester_or_viewer_and_never_owner_or_administrator() {
    let h = H::start().await;
    let (vic, tess) = (h.member("vic", Role::Viewer), h.member("tess", Role::Tester));
    let p = h.provider(|i| {
        i.group_claim = Some("groups".into());
        i.role_map = vec![
            RoleMapping { value: "pm-testers".into(), role: Role::Tester },
            RoleMapping { value: "pm-readers".into(), role: Role::Viewer },
        ];
    });
    h.link(&p, &vic, "sub-vic", None);
    h.link(&p, &tess, "sub-tess", None);
    // The claim raises a viewer to tester.
    h.idp.set_grant(Grant::new("sub-vic").groups(&["pm-testers"]));
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    assert_eq!(h.me(&jar).await.json()["role"], "tester");
    // Groups that merely ask for more grant nothing, and one that disappears takes the claim's grant back.
    h.idp.set_grant(Grant::new("sub-vic").groups(&["owner", "admin", "administrators", "proxymind-owner", "pm-owner"]));
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    let me = h.me(&jar).await.json();
    assert_eq!((me["role"].as_str(), me["user"]["server_admin"].as_bool()), (Some("viewer"), Some(false)));
    // A role the owner gave is never lowered by a claim.
    h.idp.set_grant(Grant::new("sub-tess").groups(&["pm-readers"]));
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    assert_eq!(h.me(&jar).await.json()["role"], "tester");
    // The owner (and server administrator) is untouched by any claim, with a local way in as the rule requires.
    h.passkey(&h.admin);
    h.link(&p, &h.admin, "sub-admin", None);
    for groups in [&["pm-readers"][..], &["pm-testers"][..], &["owner"][..]] {
        h.idp.set_grant(Grant::new("sub-admin").groups(groups));
        h.clock.advance(1);
        let mut jar = Jar::default();
        signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
        let me = h.me(&jar).await.json();
        assert_eq!((me["role"].as_str(), me["user"]["server_admin"].as_bool()), (Some("owner"), Some(true)));
    }
    assert_eq!(h.role_of(&h.admin), Some(Role::Owner));
}

#[tokio::test]
async fn an_owner_needs_a_local_way_in_to_link_or_use_a_provider() {
    let h = H::start().await;
    let p = h.provider(|_| {});
    let s = h.session(&h.admin);
    // No passkey and no authenticator yet: linking is refused at the start.
    let r = h.api("POST", &format!("/api/v1/auth/oidc/{}/link", p.id), &s, Some(json!({}))).await;
    assert_eq!((r.status, r.code().as_str()), (403, "owner_needs_local_factor"), "{}", r.body);
    h.passkey(&h.admin);
    let r = h.api("POST", &format!("/api/v1/auth/oidc/{}/link", p.id), &s, Some(json!({}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
}

// ---- the Account page ----------------------------------------------------------------------------------------------------

#[tokio::test]
async fn linking_and_unlinking_from_the_account_page() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    let s = h.session(&tess);
    h.idp.set_grant(Grant::new("sub-tess").email("tess@corp.example", true));

    // Start the link (a fresh sign-in): the answer carries the provider's URL and sets the state cookie.
    let r = h.api("POST", &format!("/api/v1/auth/oidc/{}/link", p.id), &s, Some(json!({"next": "/#/account"}))).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let mut jar = Jar::default();
    jar.take(&r);
    assert!(jar.state().is_some());
    let cb = h.authorize(r.json()["url"].as_str().unwrap()).await;
    // The browser does not send the Strict session cookie on the way back; the link is bound to the session anyway.
    let r = h.callback(&mut jar, &cb).await;
    assert_eq!(r.status, 302, "{r:?}");
    assert_eq!(r.location(), "/?oidc_linked=1#/account");
    assert!(jar.session().is_none(), "linking does not sign anyone in");
    let list = h.api("GET", "/api/v1/auth/oidc/identities", &s, None).await.json();
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(
        (list[0]["provider_name"].as_str(), list[0]["email"].as_str(), list[0]["linked_by"].as_str()),
        (Some("Corp SSO"), Some("tess@corp.example"), Some("self"))
    );
    let id = list[0]["id"].as_str().unwrap().to_string();

    // A second link for the same provider is refused up front.
    let r = h.api("POST", &format!("/api/v1/auth/oidc/{}/link", p.id), &s, Some(json!({}))).await;
    assert_eq!((r.status, r.code().as_str()), (403, "already_linked"));

    // The identity can sign in. Tess has a password but no authenticator, so the identity is her only way in.
    h.idp.set_grant(Grant::new("sub-tess"));
    let mut login = Jar::default();
    signed_in(&h.sign_in(&mut login, &p.id, "").await, &login);
    let live = login.session().unwrap().to_string();
    let r = h.api("DELETE", &format!("/api/v1/auth/oidc/identities/{id}"), &live, None).await;
    assert_eq!((r.status, r.code().as_str()), (409, "last_sign_in"), "{}", r.body);
    // With a passkey of her own it can go, which ends her other sessions but not this one.
    h.passkey(&tess);
    let r = h.api("DELETE", &format!("/api/v1/auth/oidc/identities/{id}"), &live, None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(h.api("GET", "/api/v1/auth/oidc/identities", &live, None).await.json(), json!([]));
    assert_eq!(h.api("GET", "/api/v1/auth/me", &s, None).await.status, 401, "her other session ended");

    // Unlinking, like linking, wants a fresh sign-in.
    let s2 = h.session(&tess);
    h.clock.advance(601);
    let r = h.api("POST", &format!("/api/v1/auth/oidc/{}/link", p.id), &s2, Some(json!({}))).await;
    assert_eq!((r.status, r.code().as_str()), (403, "fresh_login_required"));
}

#[tokio::test]
async fn a_link_dies_with_the_session_that_began_it() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|_| {});
    let s = h.session(&tess);
    h.idp.set_grant(Grant::new("sub-tess"));
    let r = h.api("POST", &format!("/api/v1/auth/oidc/{}/link", p.id), &s, Some(json!({}))).await;
    let mut jar = Jar::default();
    jar.take(&r);
    let cb = h.authorize(r.json()["url"].as_str().unwrap()).await;
    assert_eq!(h.api("POST", "/api/v1/auth/logout", &s, None).await.status, 200);
    let r = h.callback(&mut jar, &cb).await;
    assert_eq!(r.error().as_deref(), Some("link_expired"), "{r:?}");
    assert!(h.accounts.oidc_identities(&tess.id).unwrap().is_empty());
    // Someone else's identity cannot be linked to a second account.
    let vic = h.member("vic", Role::Viewer);
    h.link(&p, &vic, "sub-vic", None);
    let s = h.session(&tess);
    let r = h.api("POST", &format!("/api/v1/auth/oidc/{}/link", p.id), &s, Some(json!({}))).await;
    let mut jar = Jar::default();
    jar.take(&r);
    h.idp.set_grant(Grant::new("sub-vic"));
    let cb = h.authorize(r.json()["url"].as_str().unwrap()).await;
    let r = h.callback(&mut jar, &cb).await;
    assert_eq!(r.error().as_deref(), Some("identity_in_use"), "{r:?}");
}

// ---- invites -------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_invite_is_redeemed_by_signing_in_with_a_provider_except_an_owner_invite() {
    let h = H::start().await;
    let p = h.provider(|_| {});
    let inv = h.accounts.create_invite(&h.admin.id, Role::Tester, Some(&h.project), Duration::from_secs(3600)).unwrap();
    h.idp.set_grant(Grant {
        preferred_username: Some("newbie".into()),
        ..Grant::new("sub-new").email("newbie@corp.example", true)
    });
    let r = h
        .send(
            "POST",
            &format!("/api/v1/auth/oidc/{}/invite", p.id),
            &Jar::default(),
            Some(json!({"invite": inv.token.expose()})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", r.body);
    let mut jar = Jar::default();
    jar.take(&r);
    let cb = h.authorize(r.json()["url"].as_str().unwrap()).await;
    let r = h.callback(&mut jar, &cb).await;
    signed_in(&r, &jar);
    let me = h.me(&jar).await.json();
    assert_eq!((me["user"]["username"].as_str(), me["role"].as_str()), (Some("newbie"), Some("tester")));
    assert_eq!(me["session"]["auth_method"], "oidc");
    // Used up.
    let r = h
        .send(
            "POST",
            &format!("/api/v1/auth/oidc/{}/invite", p.id),
            &Jar::default(),
            Some(json!({"invite": inv.token.expose()})),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (400, "invalid_invite"));
    // An owner must have a local way in: that invite needs a passkey or a password.
    let inv = h.accounts.create_invite(&h.admin.id, Role::Owner, Some(&h.project), Duration::from_secs(3600)).unwrap();
    let r = h
        .send(
            "POST",
            &format!("/api/v1/auth/oidc/{}/invite", p.id),
            &Jar::default(),
            Some(json!({"invite": inv.token.expose()})),
        )
        .await;
    assert_eq!((r.status, r.code().as_str()), (403, "owner_invite"));
    // A made-up token is the same as any other bad invite.
    let r = h
        .send("POST", &format!("/api/v1/auth/oidc/{}/invite", p.id), &Jar::default(), Some(json!({"invite": "nope"})))
        .await;
    assert_eq!((r.status, r.code().as_str()), (400, "invalid_invite"));
}

// ---- configuring providers ---------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_provider_api_masks_the_secret_audits_and_needs_a_fresh_local_administrator() {
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let admin = h.session(&h.admin);
    let body = json!({
        "name": "Corp SSO", "issuer": h.idp.issuer, "client_id": "proxymind-test", "client_secret": CLIENT_SECRET,
        "group_claim": "groups", "group_roles": [{"value": "pm-testers", "role": "tester"}],
        "auto_create_domains": ["corp.example"],
    });
    let r = h.api("POST", "/api/v1/auth/oidc/providers", &admin, Some(body.clone())).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let v = r.json();
    let id = v["id"].as_str().unwrap().to_string();
    assert_eq!(v["client_secret"], "********");
    assert_eq!(v["redirect_uri"], CALLBACK);
    assert_eq!((v["email_linking"].as_bool(), v["enabled"].as_bool()), (Some(false), Some(true)));
    assert!(!r.body.contains(CLIENT_SECRET));
    let list = h.api("GET", "/api/v1/auth/oidc/providers", &admin, None).await;
    assert!(!list.body.contains(CLIENT_SECRET) && list.json()[0]["client_secret"] == "********");
    // Nothing a role may not: not even the stored secret reaches a tester, and a tester cannot configure anything.
    let t = h.session(&tess);
    for (m, path, b) in
        [("GET", "/api/v1/auth/oidc/providers", None), ("POST", "/api/v1/auth/oidc/providers", Some(body.clone()))]
    {
        let r = h.api(m, path, &t, b).await;
        assert_eq!((r.status, r.code().as_str()), (403, "server_admin_required"));
    }
    // A claim never grants owner, even when asked to in the configuration.
    let mut owner = body.clone();
    owner["issuer"] = json!("https://other.example");
    owner["group_roles"] = json!([{"value": "pm-owners", "role": "owner"}]);
    let r = h.api("POST", "/api/v1/auth/oidc/providers", &admin, Some(owner)).await;
    assert_eq!((r.status, r.code().as_str()), (400, "invalid_input"), "{}", r.body);
    let mut bad = body.clone();
    bad["issuer"] = json!("http://idp.example.com");
    assert_eq!(h.api("POST", "/api/v1/auth/oidc/providers", &admin, Some(bad)).await.status, 400);
    // Changing it: the mask keeps the secret, an empty string removes it.
    let mut edit = body.clone();
    edit["client_secret"] = json!("********");
    edit["name"] = json!("Renamed");
    let r = h.api("PUT", &format!("/api/v1/auth/oidc/providers/{id}"), &admin, Some(edit.clone())).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(h.accounts.oidc_client_secret(&id).unwrap().unwrap().expose(), CLIENT_SECRET);
    edit["client_secret"] = json!("");
    let r = h.api("PUT", &format!("/api/v1/auth/oidc/providers/{id}"), &admin, Some(edit.clone())).await;
    assert!(r.json()["client_secret"].is_null());
    assert!(h.accounts.oidc_client_secret(&id).unwrap().is_none());
    edit["client_secret"] = json!(CLIENT_SECRET);
    h.api("PUT", &format!("/api/v1/auth/oidc/providers/{id}"), &admin, Some(edit)).await;
    // The test fetches discovery and keys now and says what it found.
    let r = h.api("POST", &format!("/api/v1/auth/oidc/providers/{id}/test"), &admin, None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    let t = r.json();
    assert_eq!(t["ok"], true, "{t}");
    assert_eq!((t["key_count"].as_u64(), t["iss_parameter_supported"].as_bool()), (Some(2), Some(true)));
    assert_eq!(t["algorithms"], json!(["ES256", "RS256"]));
    assert_eq!(h.idp.hits("discovery"), 1);
    // A provider that does not answer is a failed test, not a server error.
    h.idp.with(|i| i.discovery_issuer = Some("https://evil.example".into()));
    let r = h.api("POST", &format!("/api/v1/auth/oidc/providers/{id}/test"), &admin, None).await;
    assert_eq!((r.status, r.json()["ok"].as_bool()), (200, Some(false)));
    h.idp.with(|i| i.discovery_issuer = None);
    // Writes need a fresh sign-in…
    h.clock.advance(601);
    let r = h.api("POST", &format!("/api/v1/auth/oidc/providers/{id}/test"), &admin, None).await;
    assert_eq!((r.status, r.code().as_str()), (403, "fresh_login_required"));
    // …and one that was not made through a provider.
    let via_provider = h.accounts.create_session(&h.admin.id, "oidc", &H::client()).unwrap().id.expose().to_string();
    let r = h.api("PUT", &format!("/api/v1/auth/oidc/providers/{id}"), &via_provider, Some(body.clone())).await;
    assert_eq!((r.status, r.code().as_str()), (403, "local_sign_in_required"));
    assert_eq!(
        h.api("GET", "/api/v1/auth/oidc/providers", &via_provider, None).await.status,
        200,
        "reading is allowed"
    );
    let fresh = h.session(&h.admin);
    let r = h.api("DELETE", &format!("/api/v1/auth/oidc/providers/{id}"), &fresh, None).await;
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(h.api("GET", "/api/v1/auth/oidc/providers", &fresh, None).await.json(), json!([]));
    // Every change is in the security log, and none of them holds the secret.
    let log = h.accounts.security_log(200).unwrap();
    for kind in ["oidc_provider_created", "oidc_provider_updated", "oidc_provider_tested", "oidc_provider_deleted"] {
        assert!(log.iter().any(|l| l.kind == kind), "{kind} is not in the log");
    }
    assert!(!format!("{log:?}").contains(CLIENT_SECRET));
}

// ---- secrets ---------------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn no_client_secret_code_verifier_or_token_reaches_an_answer_a_log_or_the_audit_trail() {
    let lines = captured().clone();
    let h = H::start().await;
    let tess = h.member("tess", Role::Tester);
    let p = h.provider(|i| i.auto_create_domains = vec!["corp.example".into()]);
    h.link(&p, &tess, "sub-tess", None);
    // A mix of outcomes: signed in, a bad token, a mix-up, a provider that fails, an auto-created account.
    h.idp.set_grant(Grant::new("sub-tess"));
    let mut jar = Jar::default();
    signed_in(&h.sign_in(&mut jar, &p.id, "").await, &jar);
    h.idp.set_tweak(Tweak { nonce: NonceMode::Wrong, ..Tweak::default() });
    refused(&h.sign_in(&mut Jar::default(), &p.id, "").await, &Jar::default(), "invalid_token");
    h.idp.set_tweak(Tweak::default());
    h.idp.with(|i| i.token_status = Some(500));
    let _ = h.sign_in(&mut Jar::default(), &p.id, "").await;
    h.idp.with(|i| i.token_status = None);
    h.idp.set_grant(Grant::new("fresh").email("fresh@corp.example", true));
    let mut jar2 = Jar::default();
    signed_in(&h.sign_in(&mut jar2, &p.id, "").await, &jar2);
    // The administrator's views.
    let admin = h.session(&h.admin);
    h.api("GET", "/api/v1/auth/oidc/providers", &admin, None).await;
    h.api("POST", &format!("/api/v1/auth/oidc/providers/{}/test", p.id), &admin, None).await;
    h.api("GET", "/api/v1/auth/state", &admin, None).await;
    h.me(&jar).await;

    let handed: Vec<String> = h.handed_out.lock().unwrap().clone();
    assert!(handed.len() >= 6, "the provider handed out codes, verifiers and tokens");
    let mut secrets: Vec<(&str, String)> = vec![("client secret", CLIENT_SECRET.into())];
    secrets.extend(handed.iter().map(|v| ("a code, verifier or ID token", v.clone())));
    let seen = h.seen.lock().unwrap().join("\n");
    let log = format!("{:?}", h.accounts.security_log(500).unwrap());
    let tracing_lines = lines.lock().unwrap().join("\n");
    // The audit trail of the project, too (everything the service wrote while this ran).
    let audit = format!("{:?}", h.svc.audit_list(200).unwrap_or_default());
    for (what, s) in &secrets {
        assert!(!s.is_empty());
        assert!(!seen.contains(s.as_str()), "{what} appeared in an answer of the server");
        assert!(!log.contains(s.as_str()), "{what} appeared in the security log");
        assert!(!tracing_lines.contains(s.as_str()), "{what} appeared in a log line");
        assert!(!audit.contains(s.as_str()), "{what} appeared in the project's audit log");
    }
    // The state cookie value (the binding) never comes back either.
    assert!(!seen.contains("Basic "), "no credential header in any answer");
}
