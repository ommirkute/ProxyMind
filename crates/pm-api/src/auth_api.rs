//! The auth endpoints of server mode (`/api/v1/auth/...`, ADR-0022 step 4). JSON in, JSON out.
//!
//! Without a session: `state`, `setup`, `login`, `login/second-factor`, `login/enrol`, `login/enrol/confirm` and
//! `invite/accept` (see `server_mode::is_public`). Everything else needs a session; the ones that change a credential
//! or hand out access also need a **fresh** sign-in (within 10 minutes: sign in again, which replaces the session).
//! In single-user mode every handler here answers 404, so the install token never opens an account endpoint.
//!
//! Security notes:
//! * Wrong password, unknown user, disabled user and wrong second factor give one error text (`invalid credentials`).
//! * A sign-in always makes a new session id; the cookie the request came with is never promoted. When it belongs to
//!   the same user it is ended (that is how step-up works), when it is anyone else's it is left alone.
//! * Events go to `pm-accounts`' security log inside the calls here (login, failure, logout, credential changes,
//!   invites, admin actions); this layer writes nothing of its own, so nothing is logged twice. No password, TOTP
//!   secret, session id or token is ever put in a log line or an error message.

use std::sync::Arc;
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use pm_accounts::{AccountError, LoginStep, LoginSuccess, Role, SessionInfo, User, UserStatus};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::server_mode::{
    AuthContext, ConnInfo, Me, ServerMode, cookie_value, safe_next, session_clear_cookie, session_set_cookie,
};

/// Request bodies of the auth endpoints are tiny; anything larger is refused before it is parsed.
pub(crate) const AUTH_BODY_LIMIT: usize = 16 * 1024;
/// Longest username and password accepted at all (the password policy allows 256 characters).
const MAX_USERNAME: usize = 256;
const MAX_PASSWORD: usize = 1024;
const DEFAULT_INVITE_HOURS: u32 = 72;

// ---- errors ----------------------------------------------------------------------------------------------------

/// An error answer: `{"error": "<text>", "code": "<machine readable>"}`.
pub(crate) struct AuthError {
    status: StatusCode,
    code: &'static str,
    message: String,
    retry_after: Option<u64>,
}

impl AuthError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), retry_after: None }
    }

    fn unauthenticated() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthenticated", "not signed in")
    }
}

impl From<AccountError> for AuthError {
    fn from(e: AccountError) -> Self {
        use AccountError as E;
        let (status, code) = match &e {
            E::InvalidCredentials => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            E::Throttled { .. } => (StatusCode::TOO_MANY_REQUESTS, "throttled"),
            E::InvalidPending => (StatusCode::UNAUTHORIZED, "invalid_pending"),
            E::InvalidCode => (StatusCode::BAD_REQUEST, "invalid_code"),
            E::InvalidInvite => (StatusCode::BAD_REQUEST, "invalid_invite"),
            E::InvalidSetupToken => (StatusCode::FORBIDDEN, "invalid_setup_token"),
            E::OwnerExists => (StatusCode::CONFLICT, "owner_exists"),
            E::SessionInvalid => (StatusCode::UNAUTHORIZED, "unauthenticated"),
            E::WeakPassword(_) | E::InvalidUsername(_) | E::InvalidArgument(_) => {
                (StatusCode::BAD_REQUEST, "invalid_input")
            }
            E::UsernameTaken => (StatusCode::CONFLICT, "username_taken"),
            E::NoSuchUser => (StatusCode::NOT_FOUND, "no_such_user"),
            E::NotAuthorised => (StatusCode::FORBIDDEN, "not_authorised"),
            E::LastAdmin => (StatusCode::CONFLICT, "last_admin"),
            E::SecondFactorRequired => (StatusCode::CONFLICT, "second_factor_required"),
            E::AlreadyEnrolled => (StatusCode::CONFLICT, "already_enrolled"),
            E::NotEnrolling => (StatusCode::CONFLICT, "not_enrolling"),
            E::Decrypt | E::ServerKey(_) | E::NewerSchema(_) | E::Storage(_) | E::Io(_) | E::Internal(_) => {
                // The text of a storage or crypto failure stays in the log, not in the answer.
                tracing::error!("accounts error: {e}");
                return Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error");
            }
        };
        let retry_after = match &e {
            E::Throttled { retry_after } => Some(retry_after.as_secs().max(1)),
            _ => None,
        };
        Self { status, code, message: e.to_string(), retry_after }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let mut resp =
            (self.status, Json(serde_json::json!({ "error": self.message, "code": self.code }))).into_response();
        if let Some(s) = self.retry_after
            && let Ok(v) = HeaderValue::from_str(&s.to_string())
        {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        resp
    }
}

type AuthResult = Result<Response, AuthError>;

fn server(st: &AppState) -> Result<Arc<ServerMode>, AuthError> {
    st.server.clone().ok_or_else(|| {
        AuthError::new(StatusCode::NOT_FOUND, "not_server_mode", "this ProxyMind is not running in server mode")
    })
}

fn signed_in(me: &Me) -> Result<&AuthContext, AuthError> {
    me.auth.as_deref().ok_or_else(AuthError::unauthenticated)
}

/// Sensitive actions need a sign-in within the last 10 minutes.
fn fresh(sm: &ServerMode, c: &AuthContext) -> Result<(), AuthError> {
    if sm.fresh(&c.session) {
        Ok(())
    } else {
        Err(AuthError::new(
            StatusCode::FORBIDDEN,
            "fresh_login_required",
            "this needs a recent sign-in: sign in again and repeat it",
        ))
    }
}

fn admin(c: &AuthContext) -> Result<(), AuthError> {
    if c.user.server_admin {
        Ok(())
    } else {
        Err(AuthError::new(StatusCode::FORBIDDEN, "server_admin_required", "only a server administrator may do this"))
    }
}

fn limit(fields: &[(&str, usize)]) -> Result<(), AuthError> {
    for (value, max) in fields {
        if value.len() > *max {
            return Err(AuthError::new(StatusCode::BAD_REQUEST, "too_long", "a value is too long"));
        }
    }
    Ok(())
}

fn reply<T: Serialize>(status: StatusCode, body: &T, cookies: &[String]) -> Response {
    let mut resp = (status, Json(body)).into_response();
    for c in cookies {
        if let Ok(v) = HeaderValue::from_str(c) {
            resp.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    resp
}

// ---- shapes ----------------------------------------------------------------------------------------------------

/// An account as the API shows it. Never holds a credential.
#[derive(Serialize, JsonSchema)]
pub(crate) struct UserView {
    /// Stable id (`u_…`).
    id: String,
    /// The handle, lower case.
    username: String,
    display_name: String,
    /// `active` or `disabled`.
    status: String,
    /// May manage accounts; has no project access by itself.
    server_admin: bool,
    created_at: i64,
    last_login_at: Option<i64>,
    /// The user's role on the served project (`owner`, `tester`, `viewer`); absent for non-members.
    role: Option<String>,
}

impl UserView {
    fn of(u: &User, role: Option<Role>) -> Self {
        Self {
            id: u.id.clone(),
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            status: if u.status == UserStatus::Active { "active" } else { "disabled" }.into(),
            server_admin: u.server_admin,
            created_at: u.created_at,
            last_login_at: u.last_login_at,
            role: role.map(|r| r.as_str().to_string()),
        }
    }
}

/// One browser session of the signed-in user.
#[derive(Serialize, JsonSchema)]
pub(crate) struct SessionView {
    /// Safe to show and to pass to `DELETE /auth/sessions/{reference}`.
    reference: String,
    /// `password`, `password+totp`, `password+recovery`.
    auth_method: String,
    created_at: i64,
    /// When the person last signed in; the fresh-login check reads this.
    authenticated_at: i64,
    last_seen_at: i64,
    idle_expires_at: i64,
    absolute_expires_at: i64,
    client_addr: Option<String>,
    user_agent: Option<String>,
    /// This is the session making the request.
    current: bool,
}

impl SessionView {
    fn of(s: &SessionInfo, current: &str) -> Self {
        Self {
            reference: s.reference.clone(),
            auth_method: s.auth_method.clone(),
            created_at: s.created_at,
            authenticated_at: s.authenticated_at,
            last_seen_at: s.last_seen_at,
            idle_expires_at: s.idle_expires_at,
            absolute_expires_at: s.absolute_expires_at,
            client_addr: s.client_addr.clone(),
            user_agent: s.user_agent.clone(),
            current: s.reference == current,
        }
    }
}

/// Which step of signing in comes next.
#[derive(Serialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StepName {
    /// Signed in: the session cookie was set.
    Authenticated,
    /// Send the TOTP code (or a recovery code) to `login/second-factor` with `pending`.
    SecondFactorRequired,
    /// This account must enrol a second factor first: `login/enrol` then `login/enrol/confirm` with `pending`.
    EnrolmentRequired,
}

/// The answer of every sign-in step.
#[derive(Serialize, JsonSchema)]
pub(crate) struct LoginResponse {
    step: StepName,
    /// The 5-minute token for the next step (not a session).
    pending: Option<String>,
    expires_at: Option<i64>,
    /// Present once signed in.
    user: Option<UserView>,
    /// Shown once, at first enrolment.
    recovery_codes: Option<Vec<String>>,
    /// Where to go next: the `next` the client sent if it is a path on this origin, else `/`.
    next: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct StateResponse {
    server_mode: bool,
    /// No owner exists yet: only `setup` works.
    setup_required: bool,
    /// Setup is served here (TLS, or the machine the server runs on).
    setup_allowed: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct MeResponse {
    user: UserView,
    /// The actor name used in the project's audit log (`human:<username>`).
    actor: String,
    project_id: String,
    /// The user's role on the served project; absent for a server admin who is not a member.
    role: Option<String>,
    session: SessionView,
    /// Signed in within the last 10 minutes: sensitive actions are allowed.
    fresh: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct TotpEnrolmentResponse {
    /// For typing into an authenticator app. Shown once.
    secret_base32: String,
    /// `otpauth://` URI for a QR code. Shown once.
    otpauth_uri: String,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RecoveryCodesResponse {
    /// Ten single-use codes; shown once. Earlier ones stop working.
    recovery_codes: Vec<String>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct OkResponse {
    ok: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct RevokedResponse {
    /// How many sessions ended.
    revoked: usize,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct InviteView {
    id: String,
    role: String,
    project_id: Option<String>,
    created_by: String,
    created_at: i64,
    expires_at: i64,
    used_at: Option<i64>,
    used_by: Option<String>,
    revoked_at: Option<i64>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct InviteCreated {
    id: String,
    /// The invite secret. Shown once; only its HMAC is stored.
    token: String,
    /// `<public origin>/#invite=<token>`; the token is in the fragment, which browsers never send to a server.
    url: String,
    role: String,
    expires_at: i64,
}

/// A role in the served project.
#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RoleName {
    Owner,
    Tester,
    Viewer,
}

impl From<RoleName> for Role {
    fn from(r: RoleName) -> Self {
        match r {
            RoleName::Owner => Role::Owner,
            RoleName::Tester => Role::Tester,
            RoleName::Viewer => Role::Viewer,
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoginBody {
    username: String,
    password: String,
    /// Where to go afterwards; only a path on this origin is kept.
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecondFactorBody {
    /// The `pending` token of the password step.
    pending: String,
    /// A six-digit TOTP code or a recovery code (`ABCD-EFGH-IJKL-MNOP`).
    code: String,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrolBeginBody {
    /// The `pending` token of the password step that answered `enrolment_required`.
    pending: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrolConfirmBody {
    pending: String,
    /// A TOTP code from the authenticator that holds the new secret.
    code: String,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetupBody {
    /// The token from the setup URL the server printed (`#setup=<token>`).
    setup_token: String,
    username: String,
    #[serde(default)]
    display_name: Option<String>,
    password: String,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct InviteAcceptBody {
    /// The token from the invite link (`#invite=<token>`).
    invite: String,
    username: String,
    #[serde(default)]
    display_name: Option<String>,
    password: String,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasswordBody {
    current: String,
    new_password: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TotpConfirmBody {
    code: String,
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct RevokeAllBody {
    /// Keep the session making the request (default: end every session, this one too).
    #[serde(default)]
    keep_current: bool,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct InviteCreateBody {
    /// The role the invited person gets on the served project.
    role: RoleName,
    /// How long the invite lives, in hours (default 72, at most 720).
    #[serde(default)]
    ttl_hours: Option<u32>,
}

// ---- sign-in ---------------------------------------------------------------------------------------------------

/// Ends the session the request came with when it belongs to `user_id` (re-signing in is the step-up). A cookie that
/// is invalid, expired or someone else's is left alone: it is never promoted either way.
async fn retire_presented(sm: &Arc<ServerMode>, headers: &HeaderMap, user_id: &str) {
    let Some(old) = cookie_value(headers, sm.cookie_name()) else { return };
    let uid = user_id.to_string();
    let _ = sm
        .run(move |a| {
            if let Ok(info) = a.validate_session(&old)
                && info.user_id == uid
            {
                let _ = a.revoke_session(&old);
            }
        })
        .await;
}

async fn signed_in_response(
    sm: &Arc<ServerMode>,
    headers: &HeaderMap,
    ok: LoginSuccess,
    recovery_codes: Option<Vec<String>>,
    next: String,
) -> AuthResult {
    retire_presented(sm, headers, &ok.user.id).await;
    let cookie = session_set_cookie(sm.cookie_name(), ok.session.id.expose(), sm.cookie_secure());
    let role = sm.run({
        let (uid, project) = (ok.user.id.clone(), sm.project_id.clone());
        move |a| a.memberships_of_user(&uid).map(|m| m.into_iter().find(|m| m.project_id == project).map(|m| m.role))
    });
    let role = role.await.ok().and_then(Result::ok).flatten();
    let body = LoginResponse {
        step: StepName::Authenticated,
        pending: None,
        expires_at: None,
        user: Some(UserView::of(&ok.user, role)),
        recovery_codes,
        next,
    };
    Ok(reply(StatusCode::OK, &body, &[cookie]))
}

async fn step_response(sm: &Arc<ServerMode>, headers: &HeaderMap, step: LoginStep, next: String) -> AuthResult {
    match step {
        LoginStep::Authenticated(ok) => signed_in_response(sm, headers, *ok, None, next).await,
        LoginStep::SecondFactorRequired { pending, expires_at } => Ok(reply(
            StatusCode::OK,
            &LoginResponse {
                step: StepName::SecondFactorRequired,
                pending: Some(pending.expose().to_string()),
                expires_at: Some(expires_at),
                user: None,
                recovery_codes: None,
                next,
            },
            &[],
        )),
        LoginStep::EnrolmentRequired { pending, expires_at } => Ok(reply(
            StatusCode::OK,
            &LoginResponse {
                step: StepName::EnrolmentRequired,
                pending: Some(pending.expose().to_string()),
                expires_at: Some(expires_at),
                user: None,
                recovery_codes: None,
                next,
            },
            &[],
        )),
    }
}

pub(crate) async fn auth_state(State(st): State<AppState>, conn: ConnInfo) -> AuthResult {
    let sm = server(&st)?;
    let set_up = sm.run(|a| a.has_server_admin()).await??;
    Ok(reply(
        StatusCode::OK,
        &StateResponse { server_mode: true, setup_required: !set_up, setup_allowed: conn.setup_allowed },
        &[],
    ))
}

/// First owner: claims the account with the one-time token, makes it owner of the served project and server admin,
/// and answers like the password step (`enrolment_required`: there is no session before a second factor exists).
pub(crate) async fn auth_setup(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Json(b): Json<SetupBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.username, MAX_USERNAME), (&b.password, MAX_PASSWORD), (&b.setup_token, 256)])?;
    let (client, project, next) = (conn.client(), sm.project_id.clone(), safe_next(b.next.as_deref()));
    let step = sm
        .run(move |a| -> Result<LoginStep, AccountError> {
            let user = a.bootstrap_owner(
                &b.setup_token,
                &b.username,
                b.display_name.as_deref().unwrap_or_default(),
                &b.password,
                &client,
            )?;
            // The first owner owns the project this server serves (an admin has no project access otherwise).
            a.set_membership(&user.id, &project, &user.id, Role::Owner)?;
            a.login_password(&user.username, &b.password, &client)
        })
        .await??;
    step_response(&sm, &headers, step, next).await
}

pub(crate) async fn auth_login(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Json(b): Json<LoginBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.username, MAX_USERNAME), (&b.password, MAX_PASSWORD)])?;
    let (client, next) = (conn.client(), safe_next(b.next.as_deref()));
    let step = sm.run(move |a| a.login_password(&b.username, &b.password, &client)).await??;
    step_response(&sm, &headers, step, next).await
}

pub(crate) async fn auth_login_second_factor(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Json(b): Json<SecondFactorBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.pending, 256), (&b.code, 64)])?;
    let (client, next) = (conn.client(), safe_next(b.next.as_deref()));
    let ok = sm.run(move |a| a.login_second_factor(&b.pending, &b.code, &client)).await??;
    signed_in_response(&sm, &headers, ok, None, next).await
}

pub(crate) async fn auth_login_enrol(State(st): State<AppState>, Json(b): Json<EnrolBeginBody>) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.pending, 256)])?;
    let e = sm.run(move |a| a.begin_totp_enrolment_pending(&b.pending)).await??;
    Ok(reply(
        StatusCode::OK,
        &TotpEnrolmentResponse { secret_base32: e.secret_base32.clone(), otpauth_uri: e.otpauth_uri.clone() },
        &[],
    ))
}

pub(crate) async fn auth_login_enrol_confirm(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Json(b): Json<EnrolConfirmBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.pending, 256), (&b.code, 64)])?;
    let (client, next) = (conn.client(), safe_next(b.next.as_deref()));
    let (ok, codes) = sm.run(move |a| a.finish_enrolment(&b.pending, &b.code, &client)).await??;
    signed_in_response(&sm, &headers, ok, Some(codes), next).await
}

/// Accepts an invite: creates the account (with the invite's role on the served project) and goes straight on to the
/// password step, so a role that needs a second factor lands in enrolment in the same flow.
pub(crate) async fn auth_invite_accept(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Json(b): Json<InviteAcceptBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.username, MAX_USERNAME), (&b.password, MAX_PASSWORD), (&b.invite, 256)])?;
    let (client, next) = (conn.client(), safe_next(b.next.as_deref()));
    let step = sm
        .run(move |a| -> Result<LoginStep, AccountError> {
            let user = a.accept_invite(
                &b.invite,
                &b.username,
                b.display_name.as_deref().unwrap_or_default(),
                &b.password,
                &client,
            )?;
            a.login_password(&user.username, &b.password, &client)
        })
        .await??;
    step_response(&sm, &headers, step, next).await
}

// ---- the signed-in user ----------------------------------------------------------------------------------------

pub(crate) async fn auth_me(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    Ok(reply(
        StatusCode::OK,
        &MeResponse {
            user: UserView::of(&c.user, c.role),
            actor: me.actor.id(),
            project_id: sm.project_id.clone(),
            role: c.role.map(|r| r.as_str().to_string()),
            session: SessionView::of(&c.session, &c.session.reference),
            fresh: sm.fresh(&c.session),
        },
        &[],
    ))
}

pub(crate) async fn auth_logout(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    let id = c.session_id().to_string();
    sm.run(move |a| a.revoke_session(&id)).await??;
    Ok(reply(StatusCode::OK, &OkResponse { ok: true }, &[session_clear_cookie(sm.cookie_name(), sm.cookie_secure())]))
}

pub(crate) async fn auth_sessions(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    let uid = c.user.id.clone();
    let list = sm.run(move |a| a.list_sessions(&uid)).await??;
    let views: Vec<SessionView> = list.iter().map(|s| SessionView::of(s, &c.session.reference)).collect();
    Ok(reply(StatusCode::OK, &views, &[]))
}

pub(crate) async fn auth_session_revoke(
    State(st): State<AppState>,
    me: Me,
    Path(reference): Path<String>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    let uid = c.user.id.clone();
    let r = reference.clone();
    if !sm.run(move |a| a.revoke_session_ref(&uid, &r)).await?? {
        return Err(AuthError::new(StatusCode::NOT_FOUND, "no_such_session", "no such session"));
    }
    let cookies = if reference == c.session.reference {
        vec![session_clear_cookie(sm.cookie_name(), sm.cookie_secure())]
    } else {
        vec![]
    };
    Ok(reply(StatusCode::OK, &OkResponse { ok: true }, &cookies))
}

/// "Sign out everywhere".
pub(crate) async fn auth_sessions_revoke_all(
    State(st): State<AppState>,
    me: Me,
    body: Option<Json<RevokeAllBody>>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    let keep = body.map(|b| b.0.keep_current).unwrap_or_default();
    let (uid, id) = (c.user.id.clone(), c.session_id().to_string());
    let n = sm.run(move |a| a.revoke_all_sessions(&uid, keep.then_some(id.as_str()))).await??;
    let cookies = if keep { vec![] } else { vec![session_clear_cookie(sm.cookie_name(), sm.cookie_secure())] };
    Ok(reply(StatusCode::OK, &RevokedResponse { revoked: n }, &cookies))
}

/// Changes the password (needs the current one and a fresh sign-in), ends every other session and gives this one a
/// new id.
pub(crate) async fn auth_password(
    State(st): State<AppState>,
    conn: ConnInfo,
    me: Me,
    Json(b): Json<PasswordBody>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    limit(&[(&b.current, MAX_PASSWORD), (&b.new_password, MAX_PASSWORD)])?;
    let (uid, id, client) = (c.user.id.clone(), c.session_id().to_string(), conn.client());
    let new = sm
        .run(move |a| {
            a.change_password(&uid, &b.current, &b.new_password, Some(&id))?;
            a.rotate_session(&id, &client)
        })
        .await??;
    let cookie = session_set_cookie(sm.cookie_name(), new.id.expose(), sm.cookie_secure());
    Ok(reply(StatusCode::OK, &OkResponse { ok: true }, &[cookie]))
}

/// Starts enrolling TOTP for the signed-in user (fresh sign-in).
pub(crate) async fn auth_totp_begin(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    let uid = c.user.id.clone();
    let e = sm.run(move |a| a.totp_begin_enrolment(&uid)).await??;
    Ok(reply(
        StatusCode::OK,
        &TotpEnrolmentResponse { secret_base32: e.secret_base32.clone(), otpauth_uri: e.otpauth_uri.clone() },
        &[],
    ))
}

/// Confirms the enrolment with a code, makes new recovery codes (shown once) and gives the session a new id.
pub(crate) async fn auth_totp_confirm(
    State(st): State<AppState>,
    conn: ConnInfo,
    me: Me,
    Json(b): Json<TotpConfirmBody>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    limit(&[(&b.code, 64)])?;
    let (uid, id, client) = (c.user.id.clone(), c.session_id().to_string(), conn.client());
    let (codes, new) = sm
        .run(move |a| -> Result<_, AccountError> {
            a.totp_confirm(&uid, &b.code)?;
            let codes = a.generate_recovery_codes(&uid)?;
            Ok((codes, a.rotate_session(&id, &client)?))
        })
        .await??;
    let cookie = session_set_cookie(sm.cookie_name(), new.id.expose(), sm.cookie_secure());
    Ok(reply(StatusCode::OK, &RecoveryCodesResponse { recovery_codes: codes }, &[cookie]))
}

/// Turns TOTP off (refused for accounts that must keep a second factor) and ends all of the user's sessions.
pub(crate) async fn auth_totp_disable(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    let uid = c.user.id.clone();
    sm.run(move |a| a.totp_disable(&uid)).await??;
    Ok(reply(StatusCode::OK, &OkResponse { ok: true }, &[session_clear_cookie(sm.cookie_name(), sm.cookie_secure())]))
}

/// Makes ten new recovery codes (the old ones stop working). Shown once.
pub(crate) async fn auth_recovery_codes(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    let uid = c.user.id.clone();
    let codes = sm.run(move |a| a.generate_recovery_codes(&uid)).await??;
    Ok(reply(StatusCode::OK, &RecoveryCodesResponse { recovery_codes: codes }, &[]))
}

// ---- administration --------------------------------------------------------------------------------------------

pub(crate) async fn auth_users(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    admin(c)?;
    let project = sm.project_id.clone();
    let (users, members) = sm
        .run(move |a| -> Result<_, AccountError> { Ok((a.list_users()?, a.members_of_project(&project)?)) })
        .await??;
    let views: Vec<UserView> =
        users.iter().map(|u| UserView::of(u, members.iter().find(|m| m.user_id == u.id).map(|m| m.role))).collect();
    Ok(reply(StatusCode::OK, &views, &[]))
}

pub(crate) async fn auth_user_disable(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    admin(c)?;
    fresh(&sm, c)?;
    let acting = c.user.id.clone();
    sm.run(move |a| a.disable_user(&acting, &id)).await??;
    Ok(reply(StatusCode::OK, &OkResponse { ok: true }, &[]))
}

pub(crate) async fn auth_user_enable(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    admin(c)?;
    fresh(&sm, c)?;
    let acting = c.user.id.clone();
    sm.run(move |a| a.enable_user(&acting, &id)).await??;
    Ok(reply(StatusCode::OK, &OkResponse { ok: true }, &[]))
}

/// For a person who lost their authenticator and recovery codes: removes their second factor and ends their
/// sessions; their next password sign-in enrols a new one.
pub(crate) async fn auth_user_reset_second_factor(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<String>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    admin(c)?;
    fresh(&sm, c)?;
    let acting = c.user.id.clone();
    sm.run(move |a| a.reset_second_factor(&acting, &id)).await??;
    Ok(reply(StatusCode::OK, &OkResponse { ok: true }, &[]))
}

fn invite_view(i: &pm_accounts::InviteInfo) -> InviteView {
    InviteView {
        id: i.id.clone(),
        role: i.role.as_str().into(),
        project_id: i.project_id.clone(),
        created_by: i.created_by.clone(),
        created_at: i.created_at,
        expires_at: i.expires_at,
        used_at: i.used_at,
        used_by: i.used_by.clone(),
        revoked_at: i.revoked_at,
    }
}

/// Server admins see every invite; an owner of the served project sees that project's.
pub(crate) async fn auth_invites(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    let is_owner = c.role == Some(Role::Owner);
    if !c.user.server_admin && !is_owner {
        return Err(AuthError::new(StatusCode::FORBIDDEN, "not_authorised", "not authorised"));
    }
    let all = sm.run(|a| a.list_invites()).await??;
    let admin = c.user.server_admin;
    let views: Vec<InviteView> = all
        .iter()
        .filter(|i| admin || i.project_id.as_deref() == Some(sm.project_id.as_str()))
        .map(invite_view)
        .collect();
    Ok(reply(StatusCode::OK, &views, &[]))
}

pub(crate) async fn auth_invite_create(
    State(st): State<AppState>,
    me: Me,
    Json(b): Json<InviteCreateBody>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    let hours = b.ttl_hours.unwrap_or(DEFAULT_INVITE_HOURS).clamp(1, 720);
    let (uid, project, role) = (c.user.id.clone(), sm.project_id.clone(), Role::from(b.role));
    let invite = sm
        .run(move |a| a.create_invite(&uid, role, Some(&project), Duration::from_secs(u64::from(hours) * 3600)))
        .await??;
    let token = invite.token.expose().to_string();
    let body = InviteCreated {
        id: invite.id.clone(),
        url: format!("{}/#invite={token}", sm.plan.public_origin),
        token,
        role: role.as_str().into(),
        expires_at: invite.expires_at,
    };
    Ok(reply(StatusCode::OK, &body, &[]))
}

pub(crate) async fn auth_invite_revoke(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    let acting = c.user.id.clone();
    sm.run(move |a| a.revoke_invite(&acting, &id)).await??;
    Ok(reply(StatusCode::OK, &OkResponse { ok: true }, &[]))
}
