//! Passkeys over HTTP (ADR-0022 step 7): `/api/v1/auth/passkey…`, `/auth/passkeys…`, `/auth/setup/passkey…`,
//! `/auth/invite/passkey…`, `/auth/enrol-link…` and the "require a passkey" setting. Verification, challenges, the
//! counter rule and storage are `pm-accounts`; this file is the HTTP shape and the rules that need a request: CSRF and
//! fresh-sign-in checks (the same as the other credential endpoints), sessions and cookies.
//!
//! Binary values are base64url strings; the options are the `PublicKeyCredential…OptionsJSON` objects of WebAuthn
//! Level 3, with the challenge, user id and credential ids as base64url, which the UI turns into buffers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use pm_accounts::{AccountError, AssertionResponse, PasskeyInfo, RegistrationResponse, Role};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::AppState;
use crate::auth_api::{
    AuthError, AuthResult, OkResponse, fresh, limit, reply, server, signed_in, signed_in_response, step_response,
};
use crate::server_mode::{ConnInfo, Me, ServerMode, safe_next, session_set_cookie};

/// A registration carries an attestation object of up to 64 KiB (base64url inflates it by a third).
pub(crate) const PASSKEY_BODY_LIMIT: usize = 160 * 1024;
const MAX_TOKEN: usize = 256;
const MAX_USERNAME: usize = 256;
const MAX_NAME: usize = 256;
const MAX_PASSWORD: usize = 1024;

fn rp(sm: &ServerMode) -> Result<pm_accounts::webauthn::RelyingParty, AuthError> {
    sm.passkey_rp.clone().map_err(|why| AuthError::new(StatusCode::CONFLICT, "passkeys_unavailable", why))
}

// ---- shapes ----------------------------------------------------------------------------------------------------

/// A passkey as the Account page lists it. Never holds key material.
#[derive(Serialize, JsonSchema)]
pub(crate) struct PasskeyView {
    /// Pass this to rename or remove it.
    id: String,
    name: String,
    created_at: i64,
    last_used_at: Option<i64>,
    /// `internal`, `usb`, `nfc`, `ble`, `hybrid`, `smart-card`, as the authenticator reported them.
    transports: Vec<String>,
    /// The passkey can be backed up (synced); `backup_state` says whether it is.
    backup_eligible: bool,
    backup_state: bool,
}

impl PasskeyView {
    fn of(p: &PasskeyInfo) -> Self {
        Self {
            id: p.id.clone(),
            name: p.name.clone(),
            created_at: p.created_at,
            last_used_at: p.last_used_at,
            transports: p.transports.clone(),
            backup_eligible: p.backup_eligible,
            backup_state: p.backup_state,
        }
    }
}

/// The options to pass to `navigator.credentials.create()` or `.get()` (WebAuthn's JSON form).
#[derive(Serialize, JsonSchema)]
pub(crate) struct PasskeyOptionsResponse {
    /// `PublicKeyCredentialCreationOptionsJSON` or `PublicKeyCredentialRequestOptionsJSON`; the challenge is single
    /// use and lives five minutes.
    options: serde_json::Value,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct PasskeyAdded {
    passkey: PasskeyView,
}

/// The response of `navigator.credentials.create()`, binary fields as base64url.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RegistrationBody {
    /// The credential id.
    id: String,
    client_data_json: String,
    attestation_object: String,
    /// `getTransports()` of the response, when the browser has it.
    #[serde(default)]
    transports: Vec<String>,
}

impl From<RegistrationBody> for RegistrationResponse {
    fn from(b: RegistrationBody) -> Self {
        Self {
            id: b.id,
            client_data_json: b.client_data_json,
            attestation_object: b.attestation_object,
            transports: b.transports,
        }
    }
}

/// The response of `navigator.credentials.get()`, binary fields as base64url.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssertionBody {
    /// The credential id.
    id: String,
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    /// The user handle, when the authenticator returned one.
    #[serde(default)]
    user_handle: Option<String>,
}

impl From<AssertionBody> for AssertionResponse {
    fn from(b: AssertionBody) -> Self {
        Self {
            id: b.id,
            client_data_json: b.client_data_json,
            authenticator_data: b.authenticator_data,
            signature: b.signature,
            user_handle: b.user_handle,
        }
    }
}

#[derive(Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoginOptionsBody {
    /// Sign in as this account (its passkeys are offered). Leave out to sign in without a username: the authenticator
    /// offers its own passkeys for this server.
    #[serde(default)]
    username: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasskeyLoginBody {
    response: AssertionBody,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetupPasskeyOptionsBody {
    /// The token from the setup URL.
    setup_token: String,
    username: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvitePasskeyOptionsBody {
    /// The token from the invite link.
    invite: String,
    username: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct NewAccountPasskeyBody {
    /// What to call the passkey (default "Passkey 1").
    #[serde(default)]
    name: Option<String>,
    response: RegistrationBody,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrolLinkBody {
    /// The token from the enrolment link (`#enrol=<token>`).
    token: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrolLinkPasskeyBody {
    name: Option<String>,
    response: RegistrationBody,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrolLinkPasswordBody {
    token: String,
    new_password: String,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct EnrolLinkInfo {
    username: String,
    display_name: String,
    expires_at: i64,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasskeyAddBody {
    /// What to call the passkey (default "Passkey N").
    #[serde(default)]
    name: Option<String>,
    response: RegistrationBody,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasskeyRenameBody {
    name: String,
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct PasskeyRequiredBody {
    /// Require every account to have a passkey.
    required: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct PasskeyRequiredResponse {
    required: bool,
}

#[derive(Serialize, JsonSchema)]
pub(crate) struct EnrolmentLinkCreated {
    id: String,
    /// The link's secret. Shown once; only its HMAC is stored.
    token: String,
    /// `<origin>/#enrol=<token>` (the origin the issuer's browser used, when it is one of the server's); the token is in
    /// the fragment, which browsers never send to a server.
    url: String,
    /// The account the link is for.
    username: String,
    expires_at: i64,
}

fn check_registration(r: &RegistrationBody) -> Result<(), AuthError> {
    limit(&[(&r.id, 2048), (&r.client_data_json, 16 * 1024), (&r.attestation_object, 100 * 1024)])?;
    if r.transports.len() > 16 || r.transports.iter().any(|t| t.len() > 32) {
        return Err(AuthError::new(StatusCode::BAD_REQUEST, "too_long", "a value is too long"));
    }
    Ok(())
}

fn check_assertion(r: &AssertionBody) -> Result<(), AuthError> {
    limit(&[
        (&r.id, 2048),
        (&r.client_data_json, 16 * 1024),
        (&r.authenticator_data, 32 * 1024),
        (&r.signature, 2048),
        (r.user_handle.as_deref().unwrap_or(""), 256),
    ])
}

fn options_reply(options: serde_json::Value) -> AuthResult {
    Ok(reply(StatusCode::OK, &PasskeyOptionsResponse { options }, &[]))
}

// ---- signing in ------------------------------------------------------------------------------------------------

pub(crate) async fn passkey_login_options(
    State(st): State<AppState>,
    conn: ConnInfo,
    Json(b): Json<LoginOptionsBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(b.username.as_deref().unwrap_or(""), MAX_USERNAME)])?;
    let (rp, client) = (rp(&sm)?, conn.client());
    let options = sm.run(move |a| a.passkey_begin_login(&rp, b.username.as_deref(), &client)).await??;
    options_reply(options)
}

/// Signs in with a passkey. The session is made like a password sign-in's (a new id; the cookie the request came with
/// is never promoted, and is ended when it is the same account's, which is how step-up works).
pub(crate) async fn passkey_login(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Json(b): Json<PasskeyLoginBody>,
) -> AuthResult {
    let sm = server(&st)?;
    check_assertion(&b.response)?;
    let (rp, client, next) = (rp(&sm)?, conn.client(), safe_next(b.next.as_deref()));
    let ok = sm.run(move |a| a.passkey_finish_login(&rp, &b.response.into(), &client)).await??;
    signed_in_response(&sm, &headers, ok, None, next).await
}

// ---- accounts made with a passkey ------------------------------------------------------------------------------

pub(crate) async fn setup_passkey_options(
    State(st): State<AppState>,
    conn: ConnInfo,
    Json(b): Json<SetupPasskeyOptionsBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.setup_token, MAX_TOKEN), (&b.username, MAX_USERNAME), (b.display_name.as_deref().unwrap_or(""), 512)])?;
    let (rp, client) = (rp(&sm)?, conn.client());
    let options = sm
        .run(move |a| {
            a.passkey_begin_setup(
                &rp,
                &b.setup_token,
                &b.username,
                b.display_name.as_deref().unwrap_or_default(),
                &client,
            )
        })
        .await??;
    options_reply(options)
}

/// Finishes setup with a passkey: the first owner (server admin, owner of the served project), signed in at once.
pub(crate) async fn setup_passkey(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Json(b): Json<NewAccountPasskeyBody>,
) -> AuthResult {
    let sm = server(&st)?;
    check_registration(&b.response)?;
    limit(&[(b.name.as_deref().unwrap_or(""), MAX_NAME)])?;
    let (rp, client, project, next) = (rp(&sm)?, conn.client(), sm.project_id.clone(), safe_next(b.next.as_deref()));
    let ok = sm
        .run(move |a| {
            a.passkey_finish_setup(
                &rp,
                b.name.as_deref().unwrap_or_default(),
                &b.response.into(),
                Some(&project),
                &client,
            )
        })
        .await??;
    signed_in_response(&sm, &headers, ok, None, next).await
}

pub(crate) async fn invite_passkey_options(
    State(st): State<AppState>,
    conn: ConnInfo,
    Json(b): Json<InvitePasskeyOptionsBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.invite, MAX_TOKEN), (&b.username, MAX_USERNAME), (b.display_name.as_deref().unwrap_or(""), 512)])?;
    let (rp, client) = (rp(&sm)?, conn.client());
    let options = sm
        .run(move |a| {
            a.passkey_begin_invite(&rp, &b.invite, &b.username, b.display_name.as_deref().unwrap_or_default(), &client)
        })
        .await??;
    options_reply(options)
}

pub(crate) async fn invite_passkey(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Json(b): Json<NewAccountPasskeyBody>,
) -> AuthResult {
    let sm = server(&st)?;
    check_registration(&b.response)?;
    limit(&[(b.name.as_deref().unwrap_or(""), MAX_NAME)])?;
    let (rp, client, next) = (rp(&sm)?, conn.client(), safe_next(b.next.as_deref()));
    let ok = sm
        .run(move |a| a.passkey_finish_invite(&rp, b.name.as_deref().unwrap_or_default(), &b.response.into(), &client))
        .await??;
    signed_in_response(&sm, &headers, ok, None, next).await
}

// ---- enrolment links -------------------------------------------------------------------------------------------

pub(crate) async fn enrol_link_info(
    State(st): State<AppState>,
    conn: ConnInfo,
    Json(b): Json<EnrolLinkBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.token, MAX_TOKEN)])?;
    let client = conn.client();
    let t = sm.run(move |a| a.enrolment_link_target(&b.token, &client)).await??;
    Ok(reply(
        StatusCode::OK,
        &EnrolLinkInfo { username: t.username, display_name: t.display_name, expires_at: t.expires_at },
        &[],
    ))
}

pub(crate) async fn enrol_link_passkey_options(
    State(st): State<AppState>,
    conn: ConnInfo,
    Json(b): Json<EnrolLinkBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.token, MAX_TOKEN)])?;
    let (rp, client) = (rp(&sm)?, conn.client());
    let options = sm.run(move |a| a.passkey_begin_link(&rp, &b.token, &client)).await??;
    options_reply(options)
}

/// Redeems an enrolment link with a passkey: every earlier way to sign in is replaced, and the person is signed in.
pub(crate) async fn enrol_link_passkey(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Json(b): Json<EnrolLinkPasskeyBody>,
) -> AuthResult {
    let sm = server(&st)?;
    check_registration(&b.response)?;
    limit(&[(b.name.as_deref().unwrap_or(""), MAX_NAME)])?;
    let (rp, client, next) = (rp(&sm)?, conn.client(), safe_next(b.next.as_deref()));
    let ok = sm
        .run(move |a| a.passkey_finish_link(&rp, b.name.as_deref().unwrap_or_default(), &b.response.into(), &client))
        .await??;
    signed_in_response(&sm, &headers, ok, None, next).await
}

/// Redeems an enrolment link by choosing a new password: answers `enrolment_required` (an authenticator follows).
pub(crate) async fn enrol_link_password(
    State(st): State<AppState>,
    conn: ConnInfo,
    headers: HeaderMap,
    Json(b): Json<EnrolLinkPasswordBody>,
) -> AuthResult {
    let sm = server(&st)?;
    limit(&[(&b.token, MAX_TOKEN), (&b.new_password, MAX_PASSWORD)])?;
    let (client, next) = (conn.client(), safe_next(b.next.as_deref()));
    let step = sm.run(move |a| a.redeem_link_with_password(&b.token, &b.new_password, &client)).await??;
    step_response(&sm, &headers, step, next).await
}

/// An administrator, or an owner of the served project for a tester or viewer of it, makes a one-time link for someone
/// who lost every way to sign in. Ends their sessions and revokes their tokens.
pub(crate) async fn user_enrolment_link(
    State(st): State<AppState>,
    me: Me,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    if !c.user.server_admin && c.role != Some(Role::Owner) {
        return Err(AuthError::new(StatusCode::FORBIDDEN, "not_authorised", "not authorised"));
    }
    fresh(&sm, c)?;
    let (acting, project, target) = (c.user.id.clone(), sm.project_id.clone(), id.clone());
    let (link, username) = sm
        .run(move |a| -> Result<_, AccountError> {
            let link = a.create_enrolment_link(&acting, &target, Some(&project))?;
            let username = a.get_user(&target)?.map(|u| u.username).unwrap_or_default();
            Ok((link, username))
        })
        .await??;
    // Sessions of that account that are already registered with the service lose their principal at once.
    st.service.principals_of_user_changed(&id, None);
    let token = link.token.expose().to_string();
    Ok(reply(
        StatusCode::OK,
        &EnrolmentLinkCreated {
            id: link.id,
            url: format!("{}/#enrol={token}", sm.link_origin(&headers)),
            token,
            username,
            expires_at: link.expires_at,
        },
        &[],
    ))
}

// ---- the signed-in user's passkeys -----------------------------------------------------------------------------

pub(crate) async fn passkeys_list(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    let uid = c.user.id.clone();
    let list = sm.run(move |a| a.list_passkeys(&uid)).await??;
    let views: Vec<PasskeyView> = list.iter().map(PasskeyView::of).collect();
    Ok(reply(StatusCode::OK, &views, &[]))
}

/// Options for adding a passkey (a fresh sign-in; the challenge is bound to this account and this session).
pub(crate) async fn passkeys_options(State(st): State<AppState>, me: Me) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    let (rp, uid, sid) = (rp(&sm)?, c.user.id.clone(), c.session_id().to_string());
    let options = sm.run(move |a| a.passkey_begin_enrol(&rp, &uid, &sid)).await??;
    options_reply(options)
}

/// Adds the passkey, and gives the session a new id (a credential changed).
pub(crate) async fn passkeys_add(
    State(st): State<AppState>,
    conn: ConnInfo,
    me: Me,
    Json(b): Json<PasskeyAddBody>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    check_registration(&b.response)?;
    limit(&[(b.name.as_deref().unwrap_or(""), MAX_NAME)])?;
    let (rp, uid, sid, client) = (rp(&sm)?, c.user.id.clone(), c.session_id().to_string(), conn.client());
    let (info, new) = sm
        .run(move |a| -> Result<_, AccountError> {
            let info =
                a.passkey_finish_enrol(&rp, &uid, &sid, b.name.as_deref().unwrap_or_default(), &b.response.into())?;
            Ok((info, a.rotate_session(&sid, &client)?))
        })
        .await??;
    let cookie = session_set_cookie(sm.cookie_name(), new.id.expose(), sm.cookie_secure());
    Ok(reply(StatusCode::OK, &PasskeyAdded { passkey: PasskeyView::of(&info) }, &[cookie]))
}

pub(crate) async fn passkey_rename(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<String>,
    Json(b): Json<PasskeyRenameBody>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    limit(&[(&b.name, MAX_NAME)])?;
    let uid = c.user.id.clone();
    sm.run(move |a| a.rename_passkey(&uid, &id, &b.name)).await??;
    Ok(reply(StatusCode::OK, &OkResponse::yes(), &[]))
}

/// Removes a passkey (a fresh sign-in): ends the account's other sessions and renews this one. Refused when it is the
/// last second factor of an account that needs one, or the last passkey while the server requires one.
pub(crate) async fn passkey_remove(
    State(st): State<AppState>,
    conn: ConnInfo,
    me: Me,
    Path(id): Path<String>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    fresh(&sm, c)?;
    let (uid, sid, client) = (c.user.id.clone(), c.session_id().to_string(), conn.client());
    let new = sm
        .run(move |a| -> Result<_, AccountError> {
            a.remove_passkey(&uid, &id, Some(&sid))?;
            a.rotate_session(&sid, &client)
        })
        .await??;
    let cookie = session_set_cookie(sm.cookie_name(), new.id.expose(), sm.cookie_secure());
    Ok(reply(StatusCode::OK, &OkResponse::yes(), &[cookie]))
}

// ---- the server setting ----------------------------------------------------------------------------------------

/// Turns "require a passkey" on or off: a server administrator with a fresh sign-in (and, to turn it on, a passkey of
/// their own, so the setting cannot lock them out).
pub(crate) async fn passkey_required_set(
    State(st): State<AppState>,
    me: Me,
    Json(b): Json<PasskeyRequiredBody>,
) -> AuthResult {
    let sm = server(&st)?;
    let c = signed_in(&me)?;
    if !c.user.server_admin {
        return Err(AuthError::new(
            StatusCode::FORBIDDEN,
            "server_admin_required",
            "only a server administrator may do this",
        ));
    }
    fresh(&sm, c)?;
    let acting = c.user.id.clone();
    let on = b.required;
    sm.run(move |a| a.set_passkey_required(&acting, on)).await??;
    Ok(reply(StatusCode::OK, &PasskeyRequiredResponse { required: on }, &[]))
}
