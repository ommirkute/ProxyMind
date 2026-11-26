//! Server mode (ADR-0022 step 4): browser sessions instead of the install token.
//!
//! In server mode the guard in `lib.rs` hands every request to [`server_guard`], which
//!
//! 1. answers only to the configured host names (`allowed_hosts`);
//! 2. on state-changing `/api/` requests, requires `X-ProxyMind: 1` and a matching `Origin` (or, with no `Origin`,
//!    `Sec-Fetch-Site: same-origin`): [`csrf_check`]. No CORS header is ever sent;
//! 3. while the server has no owner yet, serves only the setup endpoints;
//! 4. lets the auth endpoints that must work without a session through ([`is_public`]);
//! 5. for everything else, turns the session cookie into a [`Me`] (the actor `human:<username>` plus the account and
//!    session behind it) or answers 401, and for project routes requires a membership on the served project (403).
//!
//! The install token is not accepted here (it opens `/auth?token=` and `Authorization: Bearer` in single-user mode
//! only). `pm3_` tokens (ADR-0022 step 5) are accepted as `Authorization: Bearer` ([`authenticate_bearer`]) when the
//! request carries no session cookie: such a request has no ambient credential, so the Origin and `X-ProxyMind`
//! layers, which exist to stop a browser from being tricked into using one, do not apply to it. A request that has the
//! session cookie gets the cookie path's checks whatever else it carries.
//!
//! Single-user mode never reaches this file except through [`Me`], which there is the fixed `AppState::actor`.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use pm_accounts::{AccountError, Accounts, Clock, Membership, SessionInfo, TokenAuth, User};
use pm_service::Service;
use pm_service::access::{Principal, Role};
use pm_service::pm_policy::{Actor, Tier};
use serde_json::json;

use crate::listen::{ListenPlan, TlsKind, normalise_origin};

/// A sign-in younger than this counts as "fresh" for sensitive actions (ADR-0022).
pub const FRESH_LOGIN: Duration = Duration::from_secs(600);

/// The idle expiry is only moved forward when the session was last used this long ago, so a busy page does not
/// write to `server.db` on every request.
const TOUCH_EVERY: i64 = 30;

pub(crate) const API_PREFIX: &str = "/api/v1/auth";

/// Everything server mode needs besides the service.
pub struct ServerMode {
    pub accounts: Arc<Accounts>,
    /// The clock `accounts` runs on (tests use a manual one); the freshness check reads it too.
    pub clock: Arc<dyn Clock>,
    /// The id the served project's memberships are filed under: the `project_id` setting inside the project file
    /// (`Service::project_id`), a random value made once. It survives renaming or moving the file, which a path
    /// would not, and it is the id `pm-accounts` memberships and invites already use.
    pub project_id: String,
    pub plan: ListenPlan,
    /// The relying party for passkeys, or why there is none (an IP-address public URL). Decided once from the plan.
    pub passkey_rp: Result<pm_accounts::webauthn::RelyingParty, String>,
}

impl ServerMode {
    pub fn new(accounts: Arc<Accounts>, clock: Arc<dyn Clock>, project_id: String, plan: ListenPlan) -> Self {
        let passkey_rp = plan.passkey_rp();
        Self { accounts, clock, project_id, plan, passkey_rp }
    }

    /// TLS here, or a proxy that terminates it: cookies are `Secure` and named `__Host-pm_session`.
    pub fn cookie_secure(&self) -> bool {
        self.plan.tls != TlsKind::None || self.plan.behind_proxy
    }

    /// `__Host-pm_session` when served over TLS or behind a proxy, else `pm_session` (loopback plain HTTP only; the
    /// listen plan refuses plain HTTP anywhere else).
    pub fn cookie_name(&self) -> &'static str {
        if self.cookie_secure() { "__Host-pm_session" } else { "pm_session" }
    }

    /// The origin to print in a link for a person to open (an invite, an enrolment link): the one the request came
    /// from when it is one of this server's own, else the public origin. A browser sends the address the person typed,
    /// so the link then opens at the same host name; that matters for passkeys, which belong to a host name.
    pub(crate) fn link_origin(&self, headers: &HeaderMap) -> String {
        headers
            .get(header::ORIGIN)
            .and_then(|o| o.to_str().ok())
            .and_then(normalise_origin)
            .filter(|o| self.plan.allowed_origins.contains(o))
            .unwrap_or_else(|| self.plan.public_origin.clone())
    }

    /// Runs a call into `pm-accounts` on a blocking thread (hashing a password takes a while; SQLite blocks).
    pub(crate) async fn run<T: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&Accounts) -> T + Send + 'static,
    ) -> Result<T, AccountError> {
        let acc = self.accounts.clone();
        tokio::task::spawn_blocking(move || f(&acc))
            .await
            .map_err(|_| AccountError::Internal("a background task failed".into()))
    }

    pub(crate) fn fresh(&self, session: &SessionInfo) -> bool {
        let age = self.clock.now().saturating_sub(session.authenticated_at);
        age >= 0 && age <= i64::try_from(FRESH_LOGIN.as_secs()).unwrap_or(600)
    }

    /// What the connection says about itself: who is really connecting and whether it was TLS.
    fn conn_info(&self, req: &Request) -> ConnInfo {
        let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_canonical());
        let headers = req.headers();
        let trusted = self.plan.behind_proxy && peer.is_some_and(|p| self.plan.trusted_proxies.contains(&p));
        let (client_ip, https) = if trusted {
            let forwarded: Vec<&str> =
                headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()).collect();
            let client = forwarded_client(
                peer.unwrap_or(IpAddr::from([0, 0, 0, 0])),
                &forwarded.join(","),
                &self.plan.trusted_proxies,
            );
            let proto = headers
                .get_all("x-forwarded-proto")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .next_back()
                .map(|v| v.trim().to_ascii_lowercase());
            (Some(client), proto.as_deref() == Some("https"))
        } else {
            (peer, self.plan.tls != TlsKind::None)
        };
        let direct_loopback = !self.plan.behind_proxy && peer.is_some_and(|p| p.is_loopback());
        ConnInfo {
            peer,
            client_ip,
            https,
            setup_allowed: https || direct_loopback,
            user_agent: headers
                .get(header::USER_AGENT)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.chars().take(256).collect()),
        }
    }
}

/// Facts about the connection a request arrived on.
#[derive(Debug, Clone, Default)]
pub struct ConnInfo {
    /// The TCP peer (the reverse proxy, when there is one). `None` only when the server was started without
    /// `ConnectInfo`, which `listen::serve_app` always provides.
    pub peer: Option<IpAddr>,
    /// The address throttling and the audit log use: the peer, or behind a trusted proxy the `X-Forwarded-For` client.
    pub client_ip: Option<IpAddr>,
    /// TLS, or a trusted proxy said so with `X-Forwarded-Proto: https`.
    pub https: bool,
    /// The setup endpoint is served only over TLS or from the machine itself.
    pub setup_allowed: bool,
    pub user_agent: Option<String>,
}

impl ConnInfo {
    pub(crate) fn client(&self) -> pm_accounts::ClientInfo {
        pm_accounts::ClientInfo { addr: self.client_ip.map(|i| i.to_string()), user_agent: self.user_agent.clone() }
    }
}

/// Never fails: outside server mode there is no `ConnInfo` and the handler answers 404 before it matters.
impl<S: Send + Sync> FromRequestParts<S> for ConnInfo {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(parts.extensions.get::<ConnInfo>().cloned().unwrap_or_default())
    }
}

// ---- who is asking ---------------------------------------------------------------------------------------------

/// The signed-in account behind a request (server mode only).
pub struct AuthContext {
    pub user: User,
    pub session: SessionInfo,
    /// The session id from the cookie. A secret: never logged, never in `Debug`.
    session_id: String,
    /// The user's role on the served project, `None` for a server admin who is not a member.
    pub role: Option<pm_accounts::Role>,
    /// How many passkeys the account has.
    pub passkeys: usize,
    /// The server requires a passkey from every account ("require a passkey" is on).
    pub passkey_required: bool,
}

impl AuthContext {
    /// A session of an account that must enrol a passkey and has none: it may do only that (see [`restricted_allows`]).
    pub fn passkey_enrolment_required(&self) -> bool {
        self.passkey_required && self.passkeys == 0
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }
}

impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthContext")
            .field("user", &self.user.id)
            .field("session", &self.session.reference)
            .field("role", &self.role)
            .finish()
    }
}

/// Who a request is from, put into the request by the guard. Handlers take `me: Me` and pass `&me.actor` to the
/// service. Single-user mode: the process's actor. Server mode: `human:<username>` of the signed-in user.
#[derive(Debug, Clone)]
pub struct Me {
    pub actor: Actor,
    /// Server mode: the account and session; `None` in single-user mode and for a request made with a token.
    pub auth: Option<Arc<AuthContext>>,
    /// The client's address, when known (server mode).
    pub addr: Option<String>,
    /// The `pm3_` token the request came with, when it came with one. The actor above is then the token's
    /// (`agent:<name>`), never anything the client said.
    pub token: Option<Arc<TokenContext>>,
}

/// What a request authenticated by a `pm3_` token knows about it. No secret.
#[derive(Debug, Clone)]
pub struct TokenContext {
    /// `t_…`: safe to log and to put in audit records.
    pub id: String,
    /// The owning account (`u_…`); `None` in single-user mode.
    pub owner: Option<String>,
    /// The role in force: the lower of the token's ceiling and its owner's current role.
    pub role: Role,
    /// The owner's own role on the project (`None` in single-user mode).
    pub owner_role: Option<Role>,
    /// The tier cap in force (the token's own, and `passive` for a viewer), which the policy gate enforces.
    pub tier_cap: Option<Tier>,
    pub expires_at: i64,
}

impl TokenContext {
    pub(crate) fn of(auth: &TokenAuth) -> Self {
        Self {
            id: auth.info.id.clone(),
            owner: auth.info.user_id.clone(),
            role: access_role(auth.role),
            owner_role: auth.owner_role.map(access_role),
            tier_cap: auth.tier_cap.as_deref().and_then(Tier::parse),
            expires_at: auth.info.expires_at,
        }
    }
}

/// `pm-accounts`' role as `pm-service`'s.
pub(crate) fn access_role(r: pm_accounts::Role) -> Role {
    match r {
        pm_accounts::Role::Owner => Role::Owner,
        pm_accounts::Role::Tester => Role::Tester,
        pm_accounts::Role::Viewer => Role::Viewer,
    }
}

impl Me {
    pub(crate) fn single_user(actor: Actor) -> Self {
        Self { actor, auth: None, addr: None, token: None }
    }

    /// A request made with a token: the actor is the token's, and the policy gate enforces its tier cap.
    pub(crate) fn with_token(actor: Actor, token: TokenContext, addr: Option<String>) -> Self {
        Self { actor, auth: None, addr, token: Some(Arc::new(token)) }
    }

    /// The role this request acts with: a token's effective role, a signed-in member's role on the project, and in
    /// single-user mode the implicit owner (a person) or the machine ceiling (any other actor).
    pub fn role(&self) -> Role {
        if let Some(t) = &self.token {
            return t.role;
        }
        match &self.auth {
            Some(a) => a.role.map_or(Role::Viewer, access_role),
            None => Principal::from_actor(&self.actor).role,
        }
    }

    /// The service-level principal for this request: the actor, the account id, the session reference and the
    /// address, with the real role ([`Me::role`]). The guard registers it with the service and puts it in scope for
    /// the audit writer (`run_as`), so service methods that take an `&Actor` resolve to it.
    pub fn principal(&self) -> Principal {
        let mut p = Principal::new(self.actor.clone(), self.role());
        if let Some(a) = &self.auth {
            p.user_id = Some(a.user.id.clone());
            p.session_id = Some(a.session.reference.clone());
            p.account_role = a.role.map(access_role);
        }
        if let Some(t) = &self.token {
            p.user_id = t.owner.clone();
            p.token_id = Some(t.id.clone());
            p.account_role = t.owner_role;
        }
        p.client_addr = self.addr.clone();
        p
    }
}

impl<S: Send + Sync> FromRequestParts<S> for Me {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Me>().cloned().ok_or((StatusCode::UNAUTHORIZED, "not signed in"))
    }
}

/// The actor name for an account: its handle when the actor syntax allows it (`a-z 0-9 . _ -` and `@`; a handle may
/// also contain `+`, which an actor name cannot), else the stable user id.
pub(crate) fn actor_for(user: &User) -> Actor {
    Actor::parse(&format!("human:{}", user.username))
        .or_else(|_| Actor::parse(&format!("human:{}", user.id)))
        .unwrap_or_else(|_| Actor { kind: pm_service::pm_policy::ActorKind::Human, name: "unknown".into() })
}

/// A `pm3_` bearer token becomes a [`Me`] whose actor is the token's (`agent:<name>`, `ci:<name>`, `plugin:<name>`),
/// with the token id, its owner and its effective role. Everything is read from `server.db` now: expiry, revocation,
/// the owner's state and membership. `Err` for every failure, which the caller answers with one 401; the security log
/// has the reason. The install token is not a `pm3_` token and never gets here.
pub(crate) async fn authenticate_bearer(sm: &Arc<ServerMode>, token: &str, conn: &ConnInfo) -> Result<Me, ()> {
    let (t, project, client) = (token.to_string(), sm.project_id.clone(), conn.client());
    let auth = match sm.run(move |a| a.authenticate_token(&t, &project, &client)).await {
        Ok(Ok(auth)) => auth,
        _ => return Err(()),
    };
    let actor = Actor::parse(&auth.info.actor_id()).map_err(|_| ())?;
    Ok(Me::with_token(actor, TokenContext::of(&auth), conn.client_ip.map(|i| i.to_string())))
}

/// The value of `Authorization: Bearer <value>` (the scheme in any case), if there is one.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let (scheme, rest) = v.split_once(' ')?;
    scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim()).filter(|t| !t.is_empty())
}

/// May a token whose role is `viewer` make this request? Reads only; the MCP endpoint decides for itself (it refuses
/// `tools/call` for a viewer, but answers `initialize` and `tools/list`).
pub(crate) fn viewer_may(method: &Method, path: &str) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) || path == MCP_PATH
}

pub(crate) const MCP_PATH: &str = "/api/v1/mcp";

// ---- pure helpers (unit tested) --------------------------------------------------------------------------------

/// The `Host` header without port and brackets, lower-cased.
pub(crate) fn host_name(headers: &HeaderMap) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        host.rsplit_once(':').map_or(host, |(h, _)| h)
    };
    Some(name.to_ascii_lowercase())
}

/// Is the request addressed to one of the allowed names? (DNS-rebinding defence; single-user mode passes the
/// loopback names.)
pub(crate) fn host_allowed<S: AsRef<str>>(headers: &HeaderMap, allowed: &[S]) -> bool {
    host_name(headers).is_some_and(|h| allowed.iter().any(|a| a.as_ref() == h))
}

/// The client address when `peer` is a trusted proxy: walk `X-Forwarded-For` from the right, skipping the proxies we
/// trust; the first address that is not one of them is the client. Anything unparsable stops the walk and the peer
/// is used. A peer that is not trusted is never believed about anything.
pub(crate) fn forwarded_client(peer: IpAddr, forwarded_for: &str, trusted: &[IpAddr]) -> IpAddr {
    let peer = peer.to_canonical();
    if !trusted.contains(&peer) {
        return peer;
    }
    for part in forwarded_for.rsplit(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.parse::<IpAddr>() {
            Ok(ip) => {
                let ip = ip.to_canonical();
                if !trusted.contains(&ip) {
                    return ip;
                }
            }
            Err(_) => return peer,
        }
    }
    peer
}

/// The CSRF layers for a state-changing request (ADR-0022): `X-ProxyMind: 1`, and an `Origin` equal to the public
/// origin or, when there is none, `Sec-Fetch-Site: same-origin`. A `Sec-Fetch-Site` that says anything else
/// (`cross-site`, `same-site`, `none`) refuses the request whatever `Origin` says. `Err` is the reason.
pub(crate) fn csrf_check(method: &Method, headers: &HeaderMap, allowed_origins: &[String]) -> Result<(), &'static str> {
    if matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS) {
        return Ok(());
    }
    if headers.get("x-proxymind").and_then(|v| v.to_str().ok()) != Some("1") {
        return Err("state-changing requests need the X-ProxyMind: 1 header");
    }
    let site = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok());
    if site.is_some_and(|s| s != "same-origin") {
        return Err("cross-site requests are refused");
    }
    match headers.get(header::ORIGIN) {
        Some(origin) => {
            let ok = origin.to_str().ok().and_then(normalise_origin).is_some_and(|o| allowed_origins.contains(&o));
            if ok { Ok(()) } else { Err("the Origin of this request is not this server's address") }
        }
        None if site == Some("same-origin") => Ok(()),
        None => Err("state-changing requests need an Origin header matching this server's address"),
    }
}

/// The value of cookie `name` (the first one when there are several).
pub(crate) fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
}

/// `Set-Cookie` for a new session: always `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`; `Secure` when the
/// cookie is the `__Host-` one. No `Max-Age`: it ends with the browser session, and the server's idle and absolute
/// expiry decide the rest.
pub(crate) fn session_set_cookie(name: &str, value: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Strict{secure}")
}

/// `Set-Cookie` that removes the session cookie (same attributes, so a `__Host-` cookie is accepted for deletion).
pub(crate) fn session_clear_cookie(name: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0{secure}")
}

/// `next=` after sign-in must be a path on this origin: it starts with exactly one `/`, then neither `/` nor `\`,
/// holds nothing but visible ASCII and no backslash anywhere (browsers turn `\` into `/` and drop tabs and newlines,
/// so `/\t/evil.example` would otherwise become `//evil.example`), and is not unreasonably long. Anything else is `/`.
pub fn safe_next(raw: Option<&str>) -> String {
    let Some(next) = raw.map(str::trim) else { return "/".into() };
    let bytes = next.as_bytes();
    // Visible ASCII only: no control characters, no whitespace, no backslash, nothing a browser might rewrite.
    let ok = (1..=2048).contains(&bytes.len())
        && bytes[0] == b'/'
        && bytes.get(1).is_none_or(|b| *b != b'/' && *b != b'\\')
        && bytes.iter().all(|b| (0x21..=0x7e).contains(b) && *b != b'\\');
    if ok { next.to_string() } else { "/".into() }
}

// ---- the guard -------------------------------------------------------------------------------------------------

const STATE: &str = "/api/v1/auth/state";
const SETUP: &str = "/api/v1/auth/setup";
const SETUP_PASSKEY: &str = "/api/v1/auth/setup/passkey";
const SETUP_PASSKEY_OPTIONS: &str = "/api/v1/auth/setup/passkey/options";

/// The endpoints of setup: with a password, or with a passkey (options, then the registration).
fn is_setup_path(path: &str) -> bool {
    matches!(path, SETUP | SETUP_PASSKEY | SETUP_PASSKEY_OPTIONS)
}

/// Auth endpoints that work without a session. Everything else under `/api/` needs one.
pub(crate) fn is_public(method: &Method, path: &str) -> bool {
    matches!(
        (method.as_str(), path),
        ("GET", STATE)
            | ("POST", SETUP)
            | ("POST", "/api/v1/auth/login")
            | ("POST", "/api/v1/auth/login/second-factor")
            | ("POST", "/api/v1/auth/login/enrol")
            | ("POST", "/api/v1/auth/login/enrol/confirm")
            | ("POST", "/api/v1/auth/invite/accept")
            | ("POST", "/api/v1/auth/passkey/login/options")
            | ("POST", "/api/v1/auth/passkey/login")
            | ("POST", "/api/v1/auth/setup/passkey/options")
            | ("POST", "/api/v1/auth/setup/passkey")
            | ("POST", "/api/v1/auth/invite/passkey/options")
            | ("POST", "/api/v1/auth/invite/passkey")
            | ("POST", "/api/v1/auth/enrol-link/info")
            | ("POST", "/api/v1/auth/enrol-link/passkey/options")
            | ("POST", "/api/v1/auth/enrol-link/passkey")
            | ("POST", "/api/v1/auth/enrol-link/password")
    )
}

/// What a session that must enrol a passkey and has none may still call: see who it is, sign out, and the passkey
/// endpoints (list, options, add). Nothing else on the API, so a password and authenticator get a person to the
/// enrolment page and no further.
pub(crate) fn restricted_allows(method: &Method, path: &str) -> bool {
    matches!(
        (method.as_str(), path),
        ("GET", "/api/v1/auth/me")
            | ("POST", "/api/v1/auth/logout")
            | ("GET" | "POST", "/api/v1/auth/passkeys")
            | ("POST", "/api/v1/auth/passkeys/options")
    )
}

fn deny(status: StatusCode, code: &'static str, msg: &str) -> Response {
    (status, Json(json!({ "error": msg, "code": code }))).into_response()
}

pub(crate) async fn server_guard(sm: Arc<ServerMode>, service: Arc<Service>, req: Request, next: Next) -> Response {
    let conn = sm.conn_info(&req);
    let https = conn.https;
    let mut resp = gate(&sm, &service, conn, req, next).await;
    if sm.plan.hsts && https {
        resp.headers_mut().insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    }
    resp
}

async fn gate(sm: &Arc<ServerMode>, service: &Service, conn: ConnInfo, mut req: Request, next: Next) -> Response {
    if !host_allowed(req.headers(), &sm.plan.allowed_hosts) {
        return deny(
            StatusCode::FORBIDDEN,
            "bad_host",
            "ProxyMind only answers requests addressed to this server's configured host names",
        );
    }
    let path = req.uri().path().to_string();
    // The single-user launch link carries the install token; server mode has no such door.
    if path == "/auth" {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !path.starts_with("/api/") {
        req.extensions_mut().insert(conn);
        return run_next(req, next, false).await;
    }
    // A request with a `pm3_` bearer token and no session cookie has no ambient credential, so there is nothing for a
    // cross-site page to ride on and the browser-only layers (Origin, `X-ProxyMind`) do not apply: a plain
    // `Authorization: Bearer` client (curl, a CI job, the MCP bridge) needs neither. Any session cookie brings the
    // full cookie-path checks back, whatever else the request carries.
    let name = sm.cookie_name();
    let secure = sm.cookie_secure();
    let has_session_cookie = cookie_value(req.headers(), name).is_some();
    let token_bearer = bearer_token(req.headers())
        .filter(|t| t.starts_with(pm_accounts::TOKEN_PREFIX))
        .filter(|_| !has_session_cookie)
        .map(str::to_string);
    if token_bearer.is_none()
        && let Err(why) = csrf_check(req.method(), req.headers(), &sm.plan.allowed_origins)
    {
        return deny(StatusCode::FORBIDDEN, "csrf", why);
    }
    let set_up = match sm.run(|a| a.has_server_admin()).await {
        Ok(Ok(v)) => v,
        _ => return deny(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error"),
    };
    if is_setup_path(&path) && !conn.setup_allowed {
        return deny(
            StatusCode::FORBIDDEN,
            "setup_insecure",
            "setup is served only over TLS or from the machine the server runs on",
        );
    }
    if !set_up && path != STATE && !is_setup_path(&path) {
        return deny(
            StatusCode::SERVICE_UNAVAILABLE,
            "setup_required",
            "this server has no owner yet: finish setup with the one-time URL printed on its console",
        );
    }
    let public = is_public(req.method(), &path);
    let headers = req.headers().clone();
    req.extensions_mut().insert(conn.clone());
    if public {
        return run_next(req, next, true).await;
    }

    let Some(session_id) = cookie_value(&headers, name) else {
        if let Some(token) = token_bearer {
            let Ok(me) = authenticate_bearer(sm, &token, &conn).await else {
                let mut r = deny(StatusCode::UNAUTHORIZED, "invalid_token", "the token is not valid");
                r.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
                return r;
            };
            if let Err(r) = token_restrictions(&me, req.method(), &path) {
                return *r;
            }
            service.policy().set_tier_cap(&me.actor, me.token.as_ref().and_then(|t| t.tier_cap));
            return run_as(service, me, req, next).await;
        }
        return deny(StatusCode::UNAUTHORIZED, "unauthenticated", "not signed in");
    };
    let now = sm.clock.now();
    let id = session_id.clone();
    let looked_up = sm
        .run(move |a| -> Result<(SessionInfo, User, Vec<Membership>, usize, bool), AccountError> {
            let mut info = a.validate_session(&id)?;
            if now.saturating_sub(info.last_seen_at) >= TOUCH_EVERY {
                info = a.touch_session(&id)?;
            }
            let user = a.get_user(&info.user_id)?.ok_or(AccountError::SessionInvalid)?;
            let memberships = a.memberships_of_user(&user.id)?;
            let (passkeys, required) = (a.passkey_count(&user.id)?, a.passkey_required()?);
            Ok((info, user, memberships, passkeys, required))
        })
        .await;
    let (session, user, memberships, passkeys, passkey_required) = match looked_up {
        Ok(Ok(x)) => x,
        Ok(Err(AccountError::SessionInvalid)) => {
            let mut r = deny(StatusCode::UNAUTHORIZED, "unauthenticated", "not signed in");
            if let Ok(v) = HeaderValue::from_str(&session_clear_cookie(name, secure)) {
                r.headers_mut().append(header::SET_COOKIE, v);
            }
            return r;
        }
        _ => return deny(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error"),
    };
    let role = memberships.iter().find(|m| m.project_id == sm.project_id).map(|m| m.role);
    // "Require a passkey": an account that has none signed in with a password and authenticator only to enrol one.
    if passkey_required && passkeys == 0 && !restricted_allows(req.method(), &path) {
        return deny(
            StatusCode::FORBIDDEN,
            "passkey_enrolment_required",
            "this server requires a passkey: add one on the Account page before using anything else",
        );
    }
    if role.is_none() && !path.starts_with(API_PREFIX) {
        return deny(StatusCode::FORBIDDEN, "not_a_member", "you are not a member of this project");
    }
    let me = Me {
        actor: actor_for(&user),
        addr: conn.client_ip.map(|i| i.to_string()),
        auth: Some(Arc::new(AuthContext { user, session, session_id, role, passkeys, passkey_required })),
        token: None,
    };
    run_as(service, me, req, next).await
}

/// Runs the rest of the stack for an authenticated request: the principal is registered with the service (so the role
/// read from `server.db` just now is the one every `require` of this and later work sees: a demotion takes effect on
/// the next request) and put in scope for the audit writer (so every audit record of this request names the account,
/// session or token and address of exactly this request).
pub(crate) async fn run_as(service: &Service, me: Me, mut req: Request, next: Next) -> Response {
    let principal = me.principal();
    service.register_principal(&principal);
    req.extensions_mut().insert(me);
    service.in_request(principal, run_next(req, next, true)).await
}

/// Whether the sign-in or token behind a long-lived request (an event stream) still holds, and the role it holds now:
/// `None` when the session ended or expired, the token was revoked or expired, the account was disabled or the member
/// was removed. Read from `server.db` each time, so a revocation or a demotion reaches a stream that is already open.
pub(crate) async fn still_valid(sm: &Arc<ServerMode>, me: &Me) -> Option<Role> {
    let project = sm.project_id.clone();
    let now = sm.clock.now();
    if let Some(c) = &me.auth {
        let sid = c.session_id().to_string();
        let found = sm
            .run(move |a| -> Result<Option<(User, Option<pm_accounts::Role>)>, AccountError> {
                let info = a.validate_session(&sid)?;
                let user = a.get_user(&info.user_id)?;
                let role =
                    a.memberships_of_user(&info.user_id)?.iter().find(|m| m.project_id == project).map(|m| m.role);
                Ok(user.map(|u| (u, role)))
            })
            .await;
        return match found {
            Ok(Ok(Some((u, Some(role))))) if u.status == pm_accounts::UserStatus::Active => Some(access_role(role)),
            _ => None,
        };
    }
    let t = me.token.as_ref()?;
    let (id, owner) = (t.id.clone(), t.owner.clone()?);
    // The effective role, or `None` when the token or its owner no longer counts.
    let found = sm
        .run(move |a| -> Result<Option<pm_accounts::Role>, AccountError> {
            let Some(info) = a.get_token(&id)?.filter(|i| i.is_live(now)) else { return Ok(None) };
            let Some(owner_user) = a.get_user(&owner)?.filter(|u| u.status == pm_accounts::UserStatus::Active) else {
                return Ok(None);
            };
            let member = a.memberships_of_user(&owner_user.id)?.into_iter().find(|m| m.project_id == project);
            Ok(member.map(|m| if info.role.rank() <= m.role.rank() { info.role } else { m.role }))
        })
        .await;
    match found {
        Ok(Ok(Some(role))) => Some(access_role(role)),
        _ => None,
    }
}

/// What a token may not do whatever its ceiling: use the account endpoints (sessions, passwords, invites, users are for
/// a person who signed in), and, with the effective role `viewer`, anything but reads.
pub(crate) fn token_restrictions(me: &Me, method: &Method, path: &str) -> Result<(), Box<Response>> {
    if path.starts_with(API_PREFIX) && path != STATE {
        return Err(Box::new(deny(
            StatusCode::FORBIDDEN,
            "token_not_allowed",
            "a token cannot use the account endpoints",
        )));
    }
    if me.role() == Role::Viewer && !viewer_may(method, path) {
        return Err(Box::new(deny(
            StatusCode::FORBIDDEN,
            "read_only_token",
            "this token acts as a viewer (its ceiling, or its owner's role) and may only read",
        )));
    }
    Ok(())
}

/// Runs the rest of the stack; API answers are never cached.
async fn run_next(req: Request, next: Next, api: bool) -> Response {
    let mut resp = next.run(req).await;
    if api {
        resp.headers_mut().entry(header::CACHE_CONTROL).or_insert(HeaderValue::from_static("no-store"));
    }
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(header::HeaderName::from_bytes(k.as_bytes()).unwrap(), v.parse().unwrap());
        }
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn next_accepts_only_a_same_origin_path() {
        for ok in ["/", "/x", "/findings?id=3", "/a/b#frag", "/%2Fx", "/x/..//y", "/a?next=/b"] {
            assert_eq!(safe_next(Some(ok)), ok, "{ok}");
        }
        for bad in [
            "//evil.example",
            "///evil.example",
            "/\\evil.example",
            "\\\\evil.example",
            "/x\\y",
            "https://evil.example",
            "http://evil.example/",
            "javascript:alert(1)",
            "data:text/html,x",
            "evil.example",
            "x",
            "",
            "/\t/evil.example",
            "/\n/evil.example",
            "/\r\n/x",
            "/ /x",
            "/x\u{0}",
            "//",
            "/\u{200b}/x\u{85}",
        ] {
            assert_eq!(safe_next(Some(bad)), "/", "{bad:?}");
        }
        assert_eq!(safe_next(None), "/");
        let long = format!("/{}", "a".repeat(3000));
        assert_eq!(safe_next(Some(&long)), "/");
        assert_eq!(safe_next(Some("  /padded  ")), "/padded");
    }

    #[test]
    fn host_checks_use_the_allowed_list() {
        let allowed = ["pm.example.com".to_string(), "::1".to_string()];
        for (host, ok) in [
            ("pm.example.com", true),
            ("PM.Example.com:8443", true),
            ("[::1]:7777", true),
            ("evil.com", false),
            ("pm.example.com.evil.com", false),
            ("localhost", false),
            ("pm.example.com@evil.com", false),
        ] {
            assert_eq!(host_allowed(&headers(&[("host", host)]), &allowed), ok, "{host}");
        }
        assert!(!host_allowed(&HeaderMap::new(), &allowed), "no Host header");
    }

    #[test]
    fn csrf_matrix() {
        let origins = vec!["https://pm.example.com".to_string()];
        let post = Method::POST;
        let ok = |pairs: &[(&str, &str)]| csrf_check(&post, &headers(pairs), &origins);
        // Safe methods are not checked.
        assert!(csrf_check(&Method::GET, &headers(&[]), &origins).is_ok());
        assert!(csrf_check(&Method::HEAD, &headers(&[]), &origins).is_ok());
        assert!(csrf_check(&Method::OPTIONS, &headers(&[]), &origins).is_ok());
        // Both layers present.
        assert!(ok(&[("x-proxymind", "1"), ("origin", "https://pm.example.com")]).is_ok());
        assert!(ok(&[("x-proxymind", "1"), ("origin", "HTTPS://PM.example.com:443")]).is_ok());
        assert!(ok(&[("x-proxymind", "1"), ("sec-fetch-site", "same-origin")]).is_ok());
        assert!(
            ok(&[("x-proxymind", "1"), ("origin", "https://pm.example.com"), ("sec-fetch-site", "same-origin")])
                .is_ok()
        );
        // Missing or wrong marker header.
        assert!(ok(&[("origin", "https://pm.example.com")]).is_err());
        assert!(ok(&[("x-proxymind", "0"), ("origin", "https://pm.example.com")]).is_err());
        // Wrong, null or lookalike origins.
        for origin in [
            "https://evil.example",
            "null",
            "http://pm.example.com",
            "https://pm.example.com.evil.example",
            "https://pm.example.com:8443",
        ] {
            assert!(ok(&[("x-proxymind", "1"), ("origin", origin)]).is_err(), "{origin}");
        }
        // No Origin and no Sec-Fetch-Site: refused (a browser always sends one of them).
        assert!(ok(&[("x-proxymind", "1")]).is_err());
        // Cross-site fetch metadata wins over a matching Origin.
        for site in ["cross-site", "same-site", "none"] {
            assert!(ok(&[("x-proxymind", "1"), ("sec-fetch-site", site)]).is_err(), "{site}");
            assert!(
                ok(&[("x-proxymind", "1"), ("origin", "https://pm.example.com"), ("sec-fetch-site", site)]).is_err(),
                "{site}"
            );
        }
        for m in [Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(csrf_check(&m, &headers(&[("x-proxymind", "1")]), &origins).is_err());
        }
    }

    #[test]
    fn forwarded_headers_are_believed_only_from_trusted_peers() {
        let trusted = [ip("10.0.0.2"), ip("10.0.0.3")];
        // A peer that is not a trusted proxy is itself, whatever it claims.
        assert_eq!(forwarded_client(ip("203.0.113.9"), "1.2.3.4", &trusted), ip("203.0.113.9"));
        // A trusted proxy: the rightmost address that is not a trusted proxy.
        assert_eq!(forwarded_client(ip("10.0.0.2"), "198.51.100.7", &trusted), ip("198.51.100.7"));
        assert_eq!(forwarded_client(ip("10.0.0.2"), "6.6.6.6, 198.51.100.7, 10.0.0.3", &trusted), ip("198.51.100.7"));
        // Spoofed leftmost entries do not win.
        assert_eq!(forwarded_client(ip("10.0.0.2"), "1.1.1.1, 2.2.2.2", &trusted), ip("2.2.2.2"));
        // Nothing usable: the peer. Garbage stops the walk.
        assert_eq!(forwarded_client(ip("10.0.0.2"), "", &trusted), ip("10.0.0.2"));
        assert_eq!(forwarded_client(ip("10.0.0.2"), "10.0.0.3", &trusted), ip("10.0.0.2"));
        assert_eq!(forwarded_client(ip("10.0.0.2"), "1.2.3.4, not-an-ip", &trusted), ip("10.0.0.2"));
        // IPv4-mapped addresses compare as IPv4.
        assert_eq!(forwarded_client(ip("::ffff:10.0.0.2"), "198.51.100.7", &trusted), ip("198.51.100.7"));
        assert_eq!(forwarded_client(ip("10.0.0.2"), "2001:db8::1", &trusted), ip("2001:db8::1"));
    }

    #[test]
    fn session_cookies_have_the_required_flags() {
        let c = session_set_cookie("__Host-pm_session", "abc", true);
        assert_eq!(c, "__Host-pm_session=abc; Path=/; HttpOnly; SameSite=Strict; Secure");
        assert!(!c.contains("Domain"));
        let c = session_set_cookie("pm_session", "abc", false);
        assert_eq!(c, "pm_session=abc; Path=/; HttpOnly; SameSite=Strict");
        let gone = session_clear_cookie("__Host-pm_session", true);
        assert!(gone.contains("Max-Age=0") && gone.contains("Secure") && gone.contains("Path=/"));
    }

    #[test]
    fn cookies_are_read_by_exact_name() {
        let h = headers(&[("cookie", "a=b; pm_session_evil=x; pm_session=real; pm_token=t")]);
        assert_eq!(cookie_value(&h, "pm_session").as_deref(), Some("real"));
        assert_eq!(cookie_value(&h, "__Host-pm_session"), None);
        let h = headers(&[("cookie", "a=b"), ("cookie", "__Host-pm_session=one")]);
        assert_eq!(cookie_value(&h, "__Host-pm_session").as_deref(), Some("one"));
    }

    #[test]
    fn actor_names_follow_the_actor_syntax() {
        let user = |name: &str| User {
            id: "u_0123456789abcdef0123456789abcdef".into(),
            username: name.into(),
            display_name: name.into(),
            status: pm_accounts::UserStatus::Active,
            server_admin: false,
            created_at: 0,
            last_login_at: None,
        };
        assert_eq!(actor_for(&user("alice")).id(), "human:alice");
        assert_eq!(actor_for(&user("a.b_c-d@x")).id(), "human:a.b_c-d@x");
        assert_eq!(actor_for(&user("a+b")).id(), "human:u_0123456789abcdef0123456789abcdef");
    }

    fn server(plan: crate::listen::ListenInput<'_>) -> ServerMode {
        let clock = Arc::new(pm_accounts::ManualClock::new(1_700_000_000));
        let accounts = Arc::new(
            Accounts::open_in_memory(
                pm_accounts::ServerKey::from_bytes([1; 32]),
                pm_accounts::Config::insecure_for_tests(),
                clock.clone(),
            )
            .unwrap(),
        );
        ServerMode::new(accounts, clock, "p".into(), crate::listen::plan(&plan).unwrap())
    }

    fn request(peer: &str, headers: &[(&str, &str)]) -> Request {
        let mut b = Request::builder().uri("/api/v1/auth/state");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut req = b.body(axum::body::Body::empty()).unwrap();
        let addr: SocketAddr = format!("{peer}:50000").parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(addr));
        req
    }

    #[test]
    fn setup_is_served_over_tls_or_from_this_machine_only() {
        use crate::listen::{ListenInput, TlsKind};
        let plain = server(ListenInput {
            listen: "127.0.0.1:7777".parse().unwrap(),
            tls: TlsKind::None,
            behind_proxy: false,
            trusted_proxies: &[],
            public_url: None,
            extra_hosts: &[],
        });
        // Plain HTTP: only a peer on this machine, and forwarded headers mean nothing.
        let c = plain.conn_info(&request("127.0.0.1", &[]));
        assert!(c.setup_allowed && !c.https);
        let c = plain
            .conn_info(&request("203.0.113.9", &[("x-forwarded-proto", "https"), ("x-forwarded-for", "127.0.0.1")]));
        assert!(!c.setup_allowed && !c.https);
        assert_eq!(c.client_ip, Some(ip("203.0.113.9")));
        // No ConnectInfo at all (a server started without it): nothing is assumed.
        let bare = Request::builder().uri("/").body(axum::body::Body::empty()).unwrap();
        let c = plain.conn_info(&bare);
        assert!(!c.setup_allowed && c.peer.is_none() && c.client_ip.is_none());
        // TLS: any peer.
        let tls = server(ListenInput {
            listen: "0.0.0.0:443".parse().unwrap(),
            tls: TlsKind::Own,
            behind_proxy: false,
            trusted_proxies: &[],
            public_url: Some("https://pm.example.com"),
            extra_hosts: &[],
        });
        let c = tls.conn_info(&request("203.0.113.9", &[]));
        assert!(c.setup_allowed && c.https);
        // Behind a proxy: the proxy's word about HTTPS counts, a peer on loopback does not by itself.
        let trusted = [ip("10.0.0.2")];
        let proxied = server(ListenInput {
            listen: "10.0.0.5:7777".parse().unwrap(),
            tls: TlsKind::None,
            behind_proxy: true,
            trusted_proxies: &trusted,
            public_url: Some("https://pm.example.com"),
            extra_hosts: &[],
        });
        let c = proxied
            .conn_info(&request("10.0.0.2", &[("x-forwarded-proto", "https"), ("x-forwarded-for", "198.51.100.7")]));
        assert!(c.setup_allowed && c.https && c.client_ip == Some(ip("198.51.100.7")));
        let c = proxied.conn_info(&request("10.0.0.2", &[("x-forwarded-proto", "http")]));
        assert!(!c.setup_allowed && !c.https);
        let c = proxied.conn_info(&request("127.0.0.1", &[("x-forwarded-proto", "https")]));
        assert!(
            !c.setup_allowed && !c.https,
            "an untrusted peer, even on loopback, is a direct client behind a proxy-only server"
        );
        assert!(proxied.cookie_secure() && proxied.cookie_name() == "__Host-pm_session");
        assert!(!plain.cookie_secure() && plain.cookie_name() == "pm_session");
    }

    #[test]
    fn links_use_the_origin_the_issuer_used_when_it_is_the_servers_own() {
        use crate::listen::{ListenInput, TlsKind};
        let sm = server(ListenInput {
            listen: "127.0.0.1:7777".parse().unwrap(),
            tls: TlsKind::None,
            behind_proxy: false,
            trusted_proxies: &[],
            public_url: None,
            extra_hosts: &[],
        });
        assert_eq!(sm.plan.public_origin, "http://127.0.0.1:7777");
        let from = |o: &str| sm.link_origin(&headers(&[("origin", o)]));
        assert_eq!(from("http://localhost:7777"), "http://localhost:7777");
        assert_eq!(from("HTTP://LOCALHOST:7777"), "http://localhost:7777");
        assert_eq!(from("http://127.0.0.1:7777"), "http://127.0.0.1:7777");
        // Not one of the server's own origins, or none at all: the public one.
        assert_eq!(from("https://evil.example"), "http://127.0.0.1:7777");
        assert_eq!(from("null"), "http://127.0.0.1:7777");
        assert_eq!(sm.link_origin(&headers(&[])), "http://127.0.0.1:7777");
    }

    #[test]
    fn restricted_sessions_may_only_enrol_a_passkey() {
        for (m, p, ok) in [
            ("GET", "/api/v1/auth/me", true),
            ("POST", "/api/v1/auth/logout", true),
            ("GET", "/api/v1/auth/passkeys", true),
            ("POST", "/api/v1/auth/passkeys", true),
            ("POST", "/api/v1/auth/passkeys/options", true),
            ("DELETE", "/api/v1/auth/passkeys/c_1", false),
            ("PUT", "/api/v1/auth/passkeys/c_1", false),
            ("GET", "/api/v1/status", false),
            ("GET", "/api/v1/auth/sessions", false),
            ("POST", "/api/v1/auth/password", false),
            ("POST", "/api/v1/auth/totp/disable", false),
            ("GET", "/api/v1/auth/users", false),
            ("GET", "/api/v1/mcp", false),
        ] {
            assert_eq!(restricted_allows(&Method::from_bytes(m.as_bytes()).unwrap(), p), ok, "{m} {p}");
        }
    }

    #[test]
    fn public_routes_are_exactly_the_sign_in_ones() {
        assert!(is_public(&Method::POST, "/api/v1/auth/login"));
        assert!(is_public(&Method::GET, "/api/v1/auth/state"));
        assert!(!is_public(&Method::POST, "/api/v1/auth/state"));
        assert!(!is_public(&Method::GET, "/api/v1/auth/login"));
        assert!(!is_public(&Method::GET, "/api/v1/auth/me"));
        assert!(!is_public(&Method::GET, "/api/v1/status"));
        assert!(!is_public(&Method::POST, "/api/v1/auth/login/"));
        assert!(!is_public(&Method::POST, "/api/v1/auth/invites"));
    }
}
