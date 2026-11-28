//! Signing in with an OpenID Connect provider over HTTP (ADR-0022 step 8). The decisions are `pm_accounts::oidc`; the
//! fetching is `oidc_http`; this file is the shape of the routes and the rules that need a request.
//!
//! **Routes** (all under `/api/v1/auth`):
//! * `GET  /oidc/{provider}/start?next=`: begins a sign-in and redirects to the provider (public);
//! * `GET  /oidc/callback`: where the provider sends the browser back (public, state-cookie bound; see below);
//! * `POST /oidc/{provider}/link`: begins linking an identity to the signed-in account (fresh sign-in); answers `{url}`;
//! * `POST /oidc/{provider}/invite`: begins redeeming an invite by signing in with the provider (public); answers `{url}`;
//! * `GET /oidc/identities`, `DELETE /oidc/identities/{id}`: the account's linked identities (unlinking: fresh sign-in);
//! * `GET/POST /oidc/providers`, `PUT/DELETE /oidc/providers/{id}`, `POST /oidc/providers/{id}/test`: server administrators
//!   (writes and the test: a fresh sign-in that was **not** itself made with a provider, so a provider cannot reconfigure
//!   itself). The sign-in page learns the public list (id and name) from `GET /auth/state`.
//!
//! **The callback is a `GET` that changes state** (it signs someone in): the provider can only redirect the browser to
//! it. It is protected by what the specification asks for and a little more: the `state` the provider returns must match
//! the one stored under the **state cookie** (`HttpOnly`, `SameSite=Lax` because it has to travel on that cross-site
//! top-level redirect, `__Host-` over TLS, ten minutes, single use: taken out before anything else is looked at), so a
//! callback URL from another browser, or a replayed one, finds nothing. The session cookie is `Strict` and so is *not*
//! sent on the redirect back: a link is therefore bound to the session by its reference, checked still live and fresh.
//!
//! **Errors** never carry text from the provider: a failed sign-in redirects to `<next>?oidc_error=<code>` with a code
//! from a fixed list (the UI has the words), and the security log has the reason.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use pm_accounts::oidc::{
    BeginPurpose, OidcIdentity, OidcOutcome, OidcProvider, PendingPurpose, ProviderInput, RoleMapping, SecretChange,
    discovery::{self, AuthRequest},
};
use pm_accounts::{AccountError, ClientInfo, Role, Secret};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth_api::{AuthError, AuthResult, OkResponse, fresh, limit, reply, server, signed_in};
use crate::oidc_http::{CodeGrant, FlowError, expectations};
use crate::server_mode::{
    AuthContext, ConnInfo, Me, ServerMode, access_role, cookie_value, host_name, safe_next, session_set_cookie,
};

/// The one callback every provider is registered with (public origin + this path), compared exactly by the provider.
pub(crate) const CALLBACK_PATH: &str = "/api/v1/auth/oidc/callback";
/// What the API shows in place of a stored client secret.
pub(crate) const SECRET_MASK: &str = "********";
const MAX_CODE: usize = 2048;

// ---- shapes ----------------------------------------------------------------------------------------------------

/// What the sign-in page lists.
#[derive(Serialize, JsonSchema, Clone)]
pub(crate) struct OidcProviderPublic {
    id: String,
    /// The text of the "Sign in with …" button.
    name: String,
}

#[derive(Serialize, JsonSchema, Clone)]
pub(crate) struct GroupMapping {
    /// The value in the group claim.
    value: String,
    /// `tester` or `viewer`. Never `owner`.
    role: String,
}

/// A configured provider. The client secret is never returned: `client_secret` is `********` when one is stored.
#[derive(Serialize, JsonSchema)]
pub(crate) struct OidcProviderView {
    id: String,
    name: String,
    issuer: String,
    client_id: String,
    /// `********` when a client secret is stored, absent for a public client.
    client_secret: Option<String>,
    /// Scopes besides `openid`.
    scopes: Vec<String>,
    group_claim: Option<String>,
    group_roles: Vec<GroupMapping>,
    auto_create_domains: Vec<String>,
    email_linking: bool,
    required_acr: Vec<String>,
    required_amr: Vec<String>,
    enabled: bool,
    /// The redirect URI to register with the provider: this server's public origin and the fixed callback path.
    redirect_uri: String,
    created_at: i64,
    updated_at: i64,
}

fn provider_view(p: &OidcProvider, redirect_uri: &str) -> OidcProviderView {
    OidcProviderView {
        id: p.id.clone(),
        name: p.name.clone(),
        issuer: p.issuer.clone(),
        client_id: p.client_id.clone(),
        client_secret: p.has_secret.then(|| SECRET_MASK.to_string()),
        scopes: p.scopes.clone(),
        group_claim: p.group_claim.clone(),
        group_roles: p
            .role_map
            .iter()
            .map(|m| GroupMapping { value: m.value.clone(), role: m.role.as_str().to_string() })
            .collect(),
        auto_create_domains: p.auto_create_domains.clone(),
        email_linking: p.email_linking,
        required_acr: p.required_acr.clone(),
        required_amr: p.required_amr.clone(),
        enabled: p.enabled,
        redirect_uri: redirect_uri.to_string(),
        created_at: p.created_at,
        updated_at: p.updated_at,
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupMappingBody {
    value: String,
    /// `tester` or `viewer`; `owner` is refused.
    role: String,
}

/// Body of `POST /auth/oidc/providers` and `PUT /auth/oidc/providers/{id}`.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct OidcProviderBody {
    /// Shown on the sign-in button.
    name: String,
    /// Exactly the issuer string of the provider (what its tokens carry as `iss`).
    issuer: String,
    client_id: String,
    /// The client secret. Left out or `********` keeps the stored one (on a change); an empty string removes it (a
    /// public client).
    #[serde(default)]
    client_secret: Option<String>,
    /// Scopes besides `openid` (default `profile`, `email`).
    #[serde(default)]
    scopes: Option<Vec<String>>,
    /// The claim that lists the user's groups (for example `groups`).
    #[serde(default)]
    group_claim: Option<String>,
    /// Group values and the role they give on this project: `tester` or `viewer`.
    #[serde(default)]
    group_roles: Vec<GroupMappingBody>,
    /// Domains whose verified emails may create an account (a viewer). Empty: nobody (the default).
    #[serde(default)]
    auto_create_domains: Vec<String>,
    /// Link an existing local account whose handle is the verified email (never an owner or administrator).
    #[serde(default)]
    email_linking: bool,
    /// The ID token's `acr` must be one of these.
    #[serde(default)]
    required_acr: Vec<String>,
    /// The ID token's `amr` must contain all of these.
    #[serde(default)]
    required_amr: Vec<String>,
    #[serde(default = "yes")]
    enabled: bool,
}

fn yes() -> bool {
    true
}

impl OidcProviderBody {
    fn into_input(self) -> Result<ProviderInput, AuthError> {
        let secret = match self.client_secret.as_deref() {
            None | Some(SECRET_MASK) => SecretChange::Keep,
            Some("") => SecretChange::Clear,
            Some(s) => SecretChange::Set(Secret::new(s)),
        };
        let mut role_map = Vec::new();
        for m in self.group_roles {
            let role = match m.role.as_str() {
                "tester" => Role::Tester,
                "viewer" => Role::Viewer,
                _ => {
                    return Err(AuthError::new(
                        StatusCode::BAD_REQUEST,
                        "invalid_input",
                        "a group may map to tester or viewer only: a claim never grants owner",
                    ));
                }
            };
            role_map.push(RoleMapping { value: m.value, role });
        }
        Ok(ProviderInput {
            name: self.name,
            issuer: self.issuer,
            client_id: self.client_id,
            client_secret: secret,
            scopes: self.scopes.unwrap_or_else(|| vec!["profile".into(), "email".into()]),
            group_claim: self.group_claim,
            role_map,
            auto_create_domains: self.auto_create_domains,
            email_linking: self.email_linking,
            required_acr: self.required_acr,
            required_amr: self.required_amr,
            enabled: self.enabled,
        })
    }
}

/// An identity linked to the signed-in account.
#[derive(Serialize, JsonSchema)]
pub(crate) struct OidcIdentityView {
    /// Pass this to unlink it.
    id: String,
    provider_id: String,
    provider_name: String,
    /// As the provider last said; display only.
    email: Option<String>,
    name: Option<String>,
    /// How it was linked: `self`, `email`, `invite` or `auto`.
    linked_by: String,
    created_at: i64,
    last_used_at: Option<i64>,
}

impl OidcIdentityView {
    fn of(i: &OidcIdentity) -> Self {
        Self {
            id: i.id.clone(),
            provider_id: i.provider_id.clone(),
            provider_name: i.provider_name.clone(),
            email: i.email.clone(),
            name: i.name.clone(),
            linked_by: i.linked_by.clone(),
            created_at: i.created_at,
            last_used_at: i.last_used_at,
        }
    }
}

/// Where to send the browser to continue a link or an invite.
#[derive(Serialize, JsonSchema)]
pub(crate) struct OidcStartResponse {
    /// The provider's authorization URL. The state cookie is set by this answer.
    url: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct OidcLinkBody {
    /// Where to land afterwards; only a path on this origin is kept.
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct OidcInviteBody {
    /// The token from the invite link.
    invite: String,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
pub(crate) struct OidcStartQuery {
    /// Where to land afterwards; only a path on this origin is kept.
    #[serde(default)]
    next: Option<String>,
}

/// What the provider sends back to the callback.
#[derive(Deserialize, JsonSchema)]
pub(crate) struct OidcCallbackQuery {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    state: Option<String>,
    /// RFC 9207: the issuer that answered.
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    error_description: Option<String>,
}

/// The result of an administrator's test of a provider's configuration.
#[derive(Serialize, JsonSchema)]
pub(crate) struct OidcTestResponse {
    ok: bool,
    /// What went wrong, or notes (the first problem stops the test).
    problems: Vec<String>,
    issuer: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    jwks_uri: Option<String>,
    /// How many usable signing keys the provider's key set has.
    key_count: Option<usize>,
    /// The signing algorithms those keys are for.
    algorithms: Vec<String>,
    /// The provider says it sends the `iss` response parameter (RFC 9207); then ProxyMind requires it.
    iss_parameter_supported: bool,
    /// `client_secret_basic` or `client_secret_post`.
    token_auth: Option<String>,
    redirect_uri: String,
}

// ---- helpers ---------------------------------------------------------------------------------------------------

fn oidc_cookie_name(sm: &ServerMode) -> &'static str {
    if sm.cookie_secure() { "__Host-pm_oidc" } else { "pm_oidc" }
}

/// The state cookie: `HttpOnly`, `SameSite=Lax` (it must travel on the top-level redirect back from the provider),
/// ten minutes, `Secure` and `__Host-` over TLS.
fn state_cookie(name: &str, value: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600{secure}")
}

fn clear_state_cookie(name: &str, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}")
}

pub(crate) fn redirect_uri(sm: &ServerMode) -> String {
    format!("{}{CALLBACK_PATH}", sm.plan.public_origin)
}

/// `next` with `key=value` added to its query (before any `#fragment`, where the UI's own routes live).
fn with_query(next: &str, key: &str, value: &str) -> String {
    let (head, frag) = match next.split_once('#') {
        Some((h, f)) => (h, Some(f)),
        None => (next, None),
    };
    let sep = if head.contains('?') { '&' } else { '?' };
    let mut out = format!("{head}{sep}{key}={value}");
    if let Some(f) = frag {
        out.push('#');
        out.push_str(f);
    }
    out
}

fn redirect(location: &str, cookies: &[String]) -> Response {
    let mut resp = StatusCode::FOUND.into_response();
    if let Ok(v) = HeaderValue::from_str(location) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

/// Is this request on the host name the redirect URI names? The state cookie is host-only, so a flow begun on another
/// of the server's names would lose it on the way back.
fn on_public_host(sm: &ServerMode, headers: &HeaderMap) -> bool {
    let public = url::Url::parse(&sm.plan.public_origin)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.trim_matches(['[', ']']).to_ascii_lowercase()));
    match (host_name(headers), public) {
        (Some(h), Some(p)) => h == p,
        _ => true,
    }
}

fn wrong_host() -> AuthError {
    AuthError::new(
        StatusCode::CONFLICT,
        "use_public_address",
        "sign in with a provider from the server's public address (the one providers are told to return to)",
    )
}

/// The code the UI knows for a refusal.
fn refusal_code(e: &AccountError) -> &'static str {
    match e {
        AccountError::OidcRefused(c) => c,
        AccountError::Throttled { .. } => "throttled",
        AccountError::InvalidPending => "invalid_state",
        AccountError::NoSuchProvider => "unknown_provider",
        AccountError::InvalidInvite => "invalid_invite",
        AccountError::SessionInvalid => "link_expired",
        AccountError::UsernameTaken => "account_exists",
        _ => "internal",
    }
}

fn provider_error(code: &str) -> &'static str {
    // `access_denied` is the person saying no; anything else is the provider's own trouble.
    if code == "access_denied" { "denied" } else { "provider_error" }
}

fn admin(c: &AuthContext) -> Result<(), AuthError> {
    if c.user.server_admin {
        Ok(())
    } else {
        Err(AuthError::new(StatusCode::FORBIDDEN, "server_admin_required", "only a server administrator may do this"))
    }
}

/// Provider configuration needs a server administrator with a fresh sign-in that was not itself made through a
/// provider: whoever controls a provider must not be able to point this server at another one.
fn provider_admin(sm: &ServerMode, c: &AuthContext, write: bool) -> Result<(), AuthError> {
    admin(c)?;
    if write {
        fresh(sm, c)?;
        if c.session.auth_method == "oidc" {
            return Err(AuthError::new(
                StatusCode::FORBIDDEN,
                "local_sign_in_required",
                "provider settings need a fresh sign-in with a password, an authenticator or a passkey, not through a provider",
            ));
        }
    }
    Ok(())
}

fn flow_status(e: &FlowError) -> AuthError {
    AuthError::new(
        StatusCode::BAD_GATEWAY,
        "provider_unreachable",
        format!("the provider could not be reached: {}", e.detail()),
    )
}

/// Everything to send the browser to the provider: the URL and the state cookie.
async fn begin(
    st: &AppState,
    sm: &Arc<ServerMode>,
    provider_id: &str,
    purpose: BeginPurpose,
    next: &str,
    client: &ClientInfo,
) -> Result<(String, String), StartFailure> {
    let id = provider_id.to_string();
    let provider = sm.run(move |a| a.oidc_provider(&id)).await.map_err(StartFailure::Account)?;
    let provider = provider
        .map_err(StartFailure::Account)?
        .filter(|p| p.enabled)
        .ok_or(StartFailure::Account(AccountError::NoSuchProvider))?;
    let now = sm.clock.now();
    let d = sm.oidc.discovery(st, now, &provider, false).await.map_err(StartFailure::Flow)?;
    let (pid, nx, cl) = (provider.id.clone(), next.to_string(), client.clone());
    let begun = sm
        .run(move |a| a.oidc_begin(&pid, purpose, &nx, &cl))
        .await
        .map_err(StartFailure::Account)?
        .map_err(StartFailure::Account)?;
    let redirect_uri = redirect_uri(sm);
    let url = discovery::authorization_url(
        &d,
        &AuthRequest {
            client_id: &provider.client_id,
            scopes: &provider.scopes,
            redirect_uri: &redirect_uri,
            state: &begun.state,
            nonce: &begun.nonce,
            code_challenge: &begun.code_challenge,
        },
    )
    .map_err(|e| StartFailure::Flow(FlowError::Document(e)))?;
    Ok((url, state_cookie(oidc_cookie_name(sm), begun.binding.expose(), sm.cookie_secure())))
}

enum StartFailure {
    Account(AccountError),
    Flow(FlowError),
}

impl StartFailure {
    fn code(&self) -> &'static str {
        match self {
            StartFailure::Account(e) => refusal_code(e),
            StartFailure::Flow(e) => e.code(),
        }
    }

    fn into_auth(self) -> AuthError {
        match self {
            StartFailure::Account(e) => e.into(),
            StartFailure::Flow(e) => flow_status(&e),
        }
    }
}

// ---- sign-in ---------------------------------------------------------------------------------------------------

/// `GET /auth/oidc/{provider}/start`: redirects the browser to the provider.
pub(crate) async fn oidc_start(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Query(q): Query<OidcStartQuery>,
) -> Response {
    let Ok(sm) = server(&st) else { return StatusCode::NOT_FOUND.into_response() };
    let next = safe_next(q.next.as_deref());
    if !on_public_host(&sm, &headers) {
        // Begin again on the host name the provider will send the browser back to.
        let location = format!(
            "{}/api/v1/auth/oidc/{}/start?next={}",
            sm.plan.public_origin,
            url::form_urlencoded::byte_serialize(provider.as_bytes()).collect::<String>(),
            url::form_urlencoded::byte_serialize(next.as_bytes()).collect::<String>()
        );
        return redirect(&location, &[]);
    }
    match begin(&st, &sm, &provider, BeginPurpose::Login, &next, &conn.client()).await {
        Ok((url, cookie)) => redirect(&url, &[cookie]),
        Err(f) => {
            if let StartFailure::Flow(e) = &f {
                tracing::warn!("oidc: provider {provider} could not be started: {}", e.reason());
            }
            redirect(&with_query(&next, "oidc_error", f.code()), &[])
        }
    }
}

/// `POST /auth/oidc/{provider}/link`: begins linking an identity to the signed-in account.
pub(crate) async fn oidc_link(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    me: Me,
    Path(provider): Path<String>,
    Json(b): Json<OidcLinkBody>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    if !on_public_host(&sm, &headers) {
        return Err(wrong_host());
    }
    limit(&[(b.next.as_deref().unwrap_or(""), 2048)])?;
    let next = safe_next(b.next.as_deref());
    let purpose = BeginPurpose::Link {
        user_id: c.user.id.clone(),
        session_ref: c.session.reference.clone(),
        fresh_secs: i64::try_from(crate::server_mode::FRESH_LOGIN.as_secs()).unwrap_or(600),
    };
    let (url, cookie) =
        begin(&st, &sm, &provider, purpose, &next, &conn.client()).await.map_err(StartFailure::into_auth)?;
    Ok(reply(StatusCode::OK, &OidcStartResponse { url }, &[cookie]))
}

/// `POST /auth/oidc/{provider}/invite`: begins redeeming an invite by signing in with a provider.
pub(crate) async fn oidc_invite(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Path(provider): Path<String>,
    Json(b): Json<OidcInviteBody>,
) -> AuthResult {
    let sm = server(&st)?;
    if !on_public_host(&sm, &headers) {
        return Err(wrong_host());
    }
    limit(&[(&b.invite, 256), (b.next.as_deref().unwrap_or(""), 2048)])?;
    let next = safe_next(b.next.as_deref());
    let (url, cookie) = begin(&st, &sm, &provider, BeginPurpose::Invite { token: b.invite }, &next, &conn.client())
        .await
        .map_err(StartFailure::into_auth)?;
    Ok(reply(StatusCode::OK, &OidcStartResponse { url }, &[cookie]))
}

/// What the callback did: where to send the browser and which cookies to set.
struct Landing {
    location: String,
    cookies: Vec<String>,
}

/// `GET /auth/oidc/callback`.
pub(crate) async fn oidc_callback(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Query(q): Query<OidcCallbackQuery>,
) -> Response {
    let Ok(sm) = server(&st) else { return StatusCode::NOT_FOUND.into_response() };
    let cookie_name = oidc_cookie_name(&sm);
    // The state cookie is spent whatever happens.
    let clear = clear_state_cookie(cookie_name, sm.cookie_secure());
    match callback(&st, &sm, &conn, &headers, q).await {
        Ok(mut landing) => {
            landing.cookies.push(clear);
            redirect(&landing.location, &landing.cookies)
        }
        Err((code, next)) => redirect(&with_query(&next, "oidc_error", code), &[clear]),
    }
}

async fn fail(
    sm: &Arc<ServerMode>,
    client: &ClientInfo,
    reason: &'static str,
    code: &'static str,
    next: &str,
) -> (&'static str, String) {
    let (cl, r) = (client.clone(), reason.to_string());
    let _ = sm.run(move |a| a.oidc_record_failure(&cl, &r, None)).await;
    (code, next.to_string())
}

async fn callback(
    st: &AppState,
    sm: &Arc<ServerMode>,
    conn: &ConnInfo,
    headers: &HeaderMap,
    q: OidcCallbackQuery,
) -> Result<Landing, (&'static str, String)> {
    let client = conn.client();
    let cl = client.clone();
    match sm.run(move |a| a.oidc_check_throttle(&cl)).await {
        Ok(Ok(())) => {}
        Ok(Err(AccountError::Throttled { .. })) => return Err(("throttled", "/".into())),
        _ => return Err(("internal", "/".into())),
    }
    // 1. The state: the cookie's binding and the returned `state`. Taken, single use, before anything else.
    let (Some(binding), Some(state)) = (cookie_value(headers, oidc_cookie_name(sm)), q.state.as_deref()) else {
        return Err(fail(sm, &client, "no state cookie or state", "invalid_state", "/").await);
    };
    let state = state.to_string();
    let taken = sm.run(move |a| a.oidc_take(&binding, &state)).await;
    let Ok(Ok(pending)) = taken else {
        return Err(fail(sm, &client, "unknown, used or foreign state", "invalid_state", "/").await);
    };
    let next = pending.next.clone();
    let p = pending.provider.clone();
    // 2. The provider said no.
    if let Some(e) = q.error.as_deref() {
        let code = provider_error(e);
        return Err(fail(sm, &client, "provider returned an error", code, &next).await);
    }
    let now = sm.clock.now();
    let d = match sm.oidc.discovery(st, now, &p, false).await {
        Ok(d) => d,
        Err(e) => return Err(fail(sm, &client, e.reason(), e.code(), &next).await),
    };
    // 3. RFC 9207: the response must come from this provider (mix-up defence).
    if discovery::check_iss_param(q.iss.as_deref(), &p.issuer, d.iss_param_supported).is_err() {
        return Err(fail(sm, &client, "iss parameter mismatch", "invalid_state", &next).await);
    }
    let Some(code) = q.code.as_deref().filter(|c| !c.is_empty() && c.len() <= MAX_CODE) else {
        return Err(fail(sm, &client, "no code", "provider_error", &next).await);
    };
    // 4. The code for the ID token, with the PKCE verifier.
    let pid = p.id.clone();
    let secret = match sm.run(move |a| a.oidc_client_secret(&pid)).await {
        Ok(Ok(s)) => s,
        _ => return Err(("internal", next)),
    };
    let redirect_uri = redirect_uri(sm);
    let grant = CodeGrant { code, verifier: pending.verifier.expose(), redirect_uri: &redirect_uri };
    let id_token = match sm.oidc.exchange(st, &p, &d, secret.as_ref().map(Secret::expose), &grant).await {
        Ok(t) => t,
        Err(e) => return Err(fail(sm, &client, e.reason(), e.code(), &next).await),
    };
    // 5. The ID token.
    let now = sm.clock.now();
    let claims = match sm.oidc.verify(st, now, &p, &d, &id_token, &expectations(&p, &pending.nonce, now)).await {
        Ok(c) => c,
        Err(e) => return Err(fail(sm, &client, e.reason(), e.code(), &next).await),
    };
    // 6. Who it is.
    let (project, cl, kind) = (sm.project_id.clone(), client.clone(), pending.kind);
    let outcome = match sm.run(move |a| a.oidc_complete(pending, &claims, &project, &cl)).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return Err((refusal_code(&e), next)),
        Err(_) => return Err(("internal", next)),
    };
    match outcome {
        OidcOutcome::SignedIn { login, role_change, .. } => {
            if let Some(role) = role_change {
                st.service.principals_of_user_changed(&login.user.id, Some(access_role(role)));
            }
            let cookie = session_set_cookie(sm.cookie_name(), login.session.id.expose(), sm.cookie_secure());
            Ok(Landing { location: next, cookies: vec![cookie] })
        }
        OidcOutcome::Linked(_) if kind == PendingPurpose::Link => {
            Ok(Landing { location: with_query(&next, "oidc_linked", "1"), cookies: vec![] })
        }
        OidcOutcome::Linked(_) => Err(("internal", next)),
    }
}

// ---- the account's identities ----------------------------------------------------------------------------------

pub(crate) async fn oidc_identities(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    let uid = c.user.id.clone();
    let list = sm.run(move |a| a.oidc_identities(&uid)).await??;
    let views: Vec<OidcIdentityView> = list.iter().map(OidcIdentityView::of).collect();
    Ok(reply(StatusCode::OK, &views, &[]))
}

pub(crate) async fn oidc_identity_remove(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    let (uid, sid) = (c.user.id.clone(), c.session_id().to_string());
    sm.run(move |a| a.oidc_unlink(&uid, &id, Some(&sid))).await??;
    Ok(reply(StatusCode::OK, &OkResponse::yes(), &[]))
}

// ---- providers (server administrators) --------------------------------------------------------------------------

pub(crate) async fn oidc_providers(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    provider_admin(&sm, c, false)?;
    let list = sm.run(|a| a.oidc_providers()).await??;
    let uri = redirect_uri(&sm);
    let views: Vec<OidcProviderView> = list.iter().map(|p| provider_view(p, &uri)).collect();
    Ok(reply(StatusCode::OK, &views, &[]))
}

pub(crate) async fn oidc_provider_create(
    State(st): State<AppState>,
    me: Me,
    Json(b): Json<OidcProviderBody>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    provider_admin(&sm, c, true)?;
    limit_body(&b)?;
    let (acting, input) = (c.user.id.clone(), b.into_input()?);
    let p = sm.run(move |a| a.oidc_provider_create(&acting, input)).await??;
    Ok(reply(StatusCode::OK, &provider_view(&p, &redirect_uri(&sm)), &[]))
}

pub(crate) async fn oidc_provider_update(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<String>,
    Json(b): Json<OidcProviderBody>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    provider_admin(&sm, c, true)?;
    limit_body(&b)?;
    let (acting, input, pid) = (c.user.id.clone(), b.into_input()?, id.clone());
    let p = sm.run(move |a| a.oidc_provider_update(&acting, &pid, input)).await??;
    sm.oidc.forget(&id);
    Ok(reply(StatusCode::OK, &provider_view(&p, &redirect_uri(&sm)), &[]))
}

pub(crate) async fn oidc_provider_delete(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    provider_admin(&sm, c, true)?;
    let (acting, pid) = (c.user.id.clone(), id.clone());
    sm.run(move |a| a.oidc_provider_delete(&acting, &pid)).await??;
    sm.oidc.forget(&id);
    Ok(reply(StatusCode::OK, &OkResponse::yes(), &[]))
}

/// Fetches the provider's discovery document and keys now and says what it found.
pub(crate) async fn oidc_provider_test(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    provider_admin(&sm, c, true)?;
    let pid = id.clone();
    let p = sm.run(move |a| a.oidc_provider(&pid)).await??.ok_or(AccountError::NoSuchProvider)?;
    let now = sm.clock.now();
    let mut out = OidcTestResponse {
        ok: false,
        problems: vec![],
        issuer: None,
        authorization_endpoint: None,
        token_endpoint: None,
        jwks_uri: None,
        key_count: None,
        algorithms: vec![],
        iss_parameter_supported: false,
        token_auth: None,
        redirect_uri: redirect_uri(&sm),
    };
    match sm.oidc.discovery(&st, now, &p, true).await {
        Err(e) => out.problems.push(format!("discovery failed: {}", e.detail())),
        Ok(d) => {
            out.issuer = Some(d.issuer.clone());
            out.authorization_endpoint = Some(d.authorization_endpoint.clone());
            out.token_endpoint = Some(d.token_endpoint.clone());
            out.jwks_uri = Some(d.jwks_uri.clone());
            out.iss_parameter_supported = d.iss_param_supported;
            out.token_auth = Some(
                match d.token_auth {
                    discovery::TokenAuth::Basic => "client_secret_basic",
                    discovery::TokenAuth::Post => "client_secret_post",
                }
                .into(),
            );
            match sm.oidc.test_keys(&st, now, &p, &d).await {
                Err(e) => out.problems.push(format!("the key set could not be read: {}", e.detail())),
                Ok(keys) => {
                    out.key_count = Some(keys.len());
                    let mut algs: Vec<String> = keys.iter().map(|k| k.alg.name().to_string()).collect();
                    algs.sort();
                    algs.dedup();
                    out.algorithms = algs;
                    if keys.is_empty() {
                        out.problems.push("the key set has no usable signing key (RS256, ES256 or EdDSA)".into());
                    } else {
                        out.ok = true;
                    }
                }
            }
            if out.ok && !p.has_secret {
                out.problems
                    .push("no client secret is stored: ProxyMind will act as a public client (PKCE only)".into());
            }
        }
    }
    let (acting, pid, ok) = (c.user.id.clone(), id, out.ok);
    sm.run(move |a| a.oidc_provider_tested(&acting, &pid, ok)).await??;
    Ok(reply(StatusCode::OK, &out, &[]))
}

fn limit_body(b: &OidcProviderBody) -> Result<(), AuthError> {
    limit(&[
        (&b.name, 400),
        (&b.issuer, 2048),
        (&b.client_id, 1024),
        (b.client_secret.as_deref().unwrap_or(""), 4096),
    ])?;
    if b.group_roles.len() > 200
        || b.auto_create_domains.len() > 100
        || b.scopes.as_ref().is_some_and(|s| s.len() > 100)
    {
        return Err(AuthError::new(StatusCode::BAD_REQUEST, "too_long", "a list is too long"));
    }
    Ok(())
}

/// The public list the sign-in page shows (id and display name of the enabled providers).
pub(crate) async fn public_providers(sm: &Arc<ServerMode>) -> Vec<OidcProviderPublic> {
    match sm.run(|a| a.oidc_public_providers()).await {
        Ok(Ok(list)) => list.into_iter().map(|(id, name)| OidcProviderPublic { id, name }).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_cookie_is_lax_http_only_and_short() {
        let c = state_cookie("__Host-pm_oidc", "abc", true);
        assert_eq!(c, "__Host-pm_oidc=abc; Path=/; HttpOnly; SameSite=Lax; Max-Age=600; Secure");
        assert!(!c.contains("Domain") && !c.contains("Strict"));
        assert_eq!(state_cookie("pm_oidc", "abc", false), "pm_oidc=abc; Path=/; HttpOnly; SameSite=Lax; Max-Age=600");
        assert!(clear_state_cookie("pm_oidc", false).contains("Max-Age=0"));
    }

    #[test]
    fn query_markers_go_before_the_fragment() {
        assert_eq!(with_query("/", "oidc_error", "denied"), "/?oidc_error=denied");
        assert_eq!(with_query("/#/account", "oidc_linked", "1"), "/?oidc_linked=1#/account");
        assert_eq!(with_query("/x?a=b#/y", "k", "v"), "/x?a=b&k=v#/y");
    }

    #[test]
    fn provider_errors_are_coarse() {
        assert_eq!(provider_error("access_denied"), "denied");
        assert_eq!(provider_error("server_error"), "provider_error");
        assert_eq!(provider_error("<script>"), "provider_error");
    }
}
