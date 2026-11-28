//! Token management (ADR-0022 step 5): `GET/POST /api/v1/tokens`, `DELETE /api/v1/tokens/{id}`. Both modes.
//!
//! * **People only.** A token can never create, list or revoke tokens (itself or others'): the handlers refuse any
//!   request that came with one, and `Perm::TokensManage` is `people_only`. In single-user mode the human install token
//!   (or the browser cookie) is the person; in server mode it is a signed-in session.
//! * **Server mode:** a member makes, lists and revokes their own tokens. Owners of the project may list everyone's
//!   (`?all=true`) and make or revoke tokens *for other users*, which needs a fresh sign-in (ADR-0022's list of
//!   sensitive actions). The token's owner must be an active member; the role it gets is a ceiling.
//! * **Single-user mode:** the tokens are in `<home>/tokens.json` (`pm_accounts::TokenFile`); there is one user.
//! * The secret is in the answer of the `POST` once, and nowhere else: not in a list, not in the project audit log
//!   (which records the token's id), not in any error.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use pm_accounts::{AccountError, NewTokenSpec, Role, TokenInfo, TokenKind};
use pm_service::access::Perm;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::AppState;
use crate::auth_api::{AuthError, AuthResult, fresh, reply, signed_in};
use crate::server_mode::Me;

/// What a token acts as.
#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TokenKindName {
    Agent,
    Ci,
    Plugin,
}

impl From<TokenKindName> for TokenKind {
    fn from(k: TokenKindName) -> Self {
        match k {
            TokenKindName::Agent => TokenKind::Agent,
            TokenKindName::Ci => TokenKind::Ci,
            TokenKindName::Plugin => TokenKind::Plugin,
        }
    }
}

/// A token's role ceiling. Never `owner`.
#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TokenRoleName {
    Tester,
    Viewer,
}

/// A tier of the policy gate, as the rules of engagement name them.
#[derive(Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TierName {
    Read,
    Passive,
    ActiveSafe,
    ActiveIntrusive,
    Destructive,
}

impl TierName {
    fn as_str(self) -> &'static str {
        match self {
            TierName::Read => "read",
            TierName::Passive => "passive",
            TierName::ActiveSafe => "active_safe",
            TierName::ActiveIntrusive => "active_intrusive",
            TierName::Destructive => "destructive",
        }
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenCreateBody {
    /// What the token acts as: `agent`, `ci` or `plugin` (`agent:<name>`, `ci:<name>`, `plugin:<name>`).
    kind: TokenKindName,
    /// The actor name: 1 to 64 characters of letters, digits and `- _ . @`. Unique among live tokens of its kind.
    name: String,
    /// The role ceiling, `tester` (default) or `viewer`; never `owner`. The token acts with the lower of this and its
    /// owner's current role.
    #[serde(default)]
    role: Option<TokenRoleName>,
    /// The highest tier the token may reach (the rules of engagement can only narrow it further).
    #[serde(default)]
    tier_cap: Option<TierName>,
    /// Lifetime in days: 1 to 365 (default 30).
    #[serde(default)]
    expires_days: Option<u32>,
    /// Server mode, owners only (and a fresh sign-in): make the token for this other user (their username).
    #[serde(default)]
    for_user: Option<String>,
}

/// Query of `GET /tokens`.
#[derive(Deserialize, JsonSchema, Default)]
pub(crate) struct TokensQuery {
    /// Server mode, owners of the project: list everyone's tokens instead of your own.
    #[serde(default)]
    all: Option<bool>,
}

/// A token as the API shows it. Never holds the secret.
#[derive(Serialize, JsonSchema)]
pub(crate) struct TokenView {
    /// `t_…`: what `DELETE /tokens/{id}` takes, and what the audit log records.
    id: String,
    /// `agent`, `ci` or `plugin`.
    kind: String,
    name: String,
    /// What requests with this token act as, e.g. `agent:claude`.
    actor: String,
    /// The owning account (`u_…`); absent in single-user mode.
    owner: Option<String>,
    /// The owner's username, when known.
    owner_name: Option<String>,
    project_id: Option<String>,
    /// The role ceiling (`tester` or `viewer`).
    role: String,
    /// The highest tier the token may reach; absent for no cap.
    tier_cap: Option<String>,
    created_at: i64,
    expires_at: i64,
    last_used_at: Option<i64>,
    /// Requests made with it (counts at most a minute behind).
    use_count: u64,
    revoked_at: Option<i64>,
    /// `active`, `expired` or `revoked`.
    status: String,
}

fn view(t: &TokenInfo, now: i64, owner_name: Option<String>) -> TokenView {
    TokenView {
        id: t.id.clone(),
        kind: t.kind.as_str().into(),
        name: t.name.clone(),
        actor: t.actor_id(),
        owner: t.user_id.clone(),
        owner_name,
        project_id: t.project_id.clone(),
        role: t.role.as_str().into(),
        tier_cap: t.tier_cap.clone(),
        created_at: t.created_at,
        expires_at: t.expires_at,
        last_used_at: t.last_used_at,
        use_count: t.use_count,
        revoked_at: t.revoked_at,
        status: if t.revoked_at.is_some() {
            "revoked"
        } else if t.expires_at <= now {
            "expired"
        } else {
            "active"
        }
        .into(),
    }
}

/// The answer of `POST /tokens`: the token, and its secret, once.
#[derive(Serialize, JsonSchema)]
pub(crate) struct TokenCreated {
    #[serde(flatten)]
    info: TokenView,
    /// The secret, `pm3_<kind>_<64 hex digits>`. Shown once; only its HMAC is stored.
    token: String,
}

fn forbidden(code: &'static str, msg: &str) -> AuthError {
    AuthError::new(StatusCode::FORBIDDEN, code, msg)
}

/// Only a person acting as themselves manages tokens: never a token, and (by role) not a viewer.
fn require_person(me: &Me) -> Result<(), AuthError> {
    if me.token.is_some() {
        return Err(forbidden("tokens_need_a_person", "a token cannot create, list or revoke tokens"));
    }
    if !me.principal().allows(Perm::TokensManage) {
        return Err(forbidden("not_authorised", "your role may not manage tokens"));
    }
    Ok(())
}

fn others_allowed(me: &Me) -> Result<(), AuthError> {
    if me.principal().allows(Perm::TokensManageOthers) {
        Ok(())
    } else {
        Err(forbidden("not_authorised", "only an owner of the project may manage other people's tokens"))
    }
}

fn store_error(e: AccountError) -> AuthError {
    match e {
        // The text names a file and what is wrong with it (never a token): the person needs to read it.
        AccountError::TokenStore(msg) => AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "token_store", msg),
        other => other.into(),
    }
}

fn single_user_store(st: &AppState) -> Result<std::sync::Arc<pm_accounts::TokenFile>, AuthError> {
    st.tokens.clone().ok_or_else(|| {
        AuthError::new(StatusCode::NOT_FOUND, "tokens_unavailable", "this ProxyMind process has no token store")
    })
}

fn spec_of(b: &TokenCreateBody) -> Result<NewTokenSpec, AuthError> {
    let mut spec = NewTokenSpec::new(b.kind.into(), b.name.clone());
    spec.role = match b.role {
        Some(TokenRoleName::Viewer) => Role::Viewer,
        _ => Role::Tester,
    };
    spec.tier_cap = b.tier_cap.map(|t| t.as_str().to_string());
    spec.ttl = b.expires_days.map(|d| Duration::from_secs(u64::from(d) * 86_400));
    if b.expires_days == Some(0) {
        return Err(AuthError::new(StatusCode::BAD_REQUEST, "invalid_input", "expires_days is 1 to 365"));
    }
    Ok(spec)
}

fn audit(st: &AppState, me: &Me, action: &str, detail: serde_json::Value) {
    if let Err(e) = st.service.audit_principal(&me.principal(), action, detail, "allow") {
        tracing::warn!("the audit record of {action} was not written: {e}");
    }
}

pub(crate) async fn tokens_list(State(st): State<AppState>, me: Me, Query(q): Query<TokensQuery>) -> AuthResult {
    require_person(&me)?;
    let Some(sm) = st.server.clone() else {
        // One user: every token is yours, so `all` changes nothing.
        let store = single_user_store(&st)?;
        let store_now = store.now();
        let list = tokio::task::spawn_blocking(move || store.list())
            .await
            .map_err(|_| AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error"))?
            .map_err(store_error)?;
        let now = store_now;
        let views: Vec<TokenView> = list.iter().map(|t| view(t, now, None)).collect();
        return Ok(reply(StatusCode::OK, &views, &[]));
    };
    let c = signed_in(&me)?;
    let everyone = q.all == Some(true);
    if everyone {
        others_allowed(&me)?;
    }
    let (project, uid) = (sm.project_id.clone(), c.user.id.clone());
    let (list, users) = sm
        .run(move |a| -> Result<_, AccountError> {
            Ok((a.list_tokens(&project, (!everyone).then_some(uid.as_str()))?, a.list_users()?))
        })
        .await??;
    let now = sm.clock.now();
    let name_of = |id: &str| users.iter().find(|u| u.id == id).map(|u| u.username.clone());
    let views: Vec<TokenView> = list.iter().map(|t| view(t, now, t.user_id.as_deref().and_then(name_of))).collect();
    Ok(reply(StatusCode::OK, &views, &[]))
}

pub(crate) async fn token_create(State(st): State<AppState>, me: Me, Json(b): Json<TokenCreateBody>) -> AuthResult {
    require_person(&me)?;
    let spec = spec_of(&b)?;
    let Some(sm) = st.server.clone() else {
        if b.for_user.as_deref().is_some_and(|u| !u.trim().is_empty()) {
            return Err(AuthError::new(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "single-user mode has one user: leave for_user out",
            ));
        }
        let store = single_user_store(&st)?;
        let store_now = store.now();
        let made = tokio::task::spawn_blocking(move || store.create(&spec))
            .await
            .map_err(|_| AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error"))?
            .map_err(store_error)?;
        audit(&st, &me, "token_create", audit_detail(&made.info, None));
        let body = TokenCreated { info: view(&made.info, store_now, None), token: made.token.expose().to_string() };
        return Ok(reply(StatusCode::OK, &body, &[]));
    };
    let c = signed_in(&me)?;
    let acting = c.user.id.clone();
    let (owner, owner_name) = match b.for_user.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(name) if !name.eq_ignore_ascii_case(&c.user.username) => {
            others_allowed(&me)?;
            fresh(&sm, c)?;
            let name = name.to_string();
            let user = sm
                .run(move |a| a.get_user_by_username(&name))
                .await??
                .ok_or_else(|| AuthError::new(StatusCode::NOT_FOUND, "no_such_user", "no such user"))?;
            (user.id, user.username)
        }
        _ => (c.user.id.clone(), c.user.username.clone()),
    };
    let project = sm.project_id.clone();
    let owner_id = owner.clone();
    let made = sm.run(move |a| a.create_token(&acting, &owner_id, &project, &spec)).await??;
    audit(&st, &me, "token_create", audit_detail(&made.info, Some(&owner_name)));
    let body = TokenCreated {
        info: view(&made.info, sm.clock.now(), Some(owner_name)),
        token: made.token.expose().to_string(),
    };
    Ok(reply(StatusCode::OK, &body, &[]))
}

/// What the project's audit log records of a token being made: its id and shape, never the secret.
fn audit_detail(t: &TokenInfo, owner_name: Option<&str>) -> serde_json::Value {
    json!({
        "token_id": t.id,
        "actor": t.actor_id(),
        "role": t.role.as_str(),
        "tier_cap": t.tier_cap,
        "expires_at": t.expires_at,
        "owner": t.user_id,
        "owner_name": owner_name,
    })
}

pub(crate) async fn token_revoke(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> AuthResult {
    require_person(&me)?;
    let Some(sm) = st.server.clone() else {
        let store = single_user_store(&st)?;
        let tid = id.clone();
        tokio::task::spawn_blocking(move || store.revoke(&tid))
            .await
            .map_err(|_| AuthError::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error"))?
            .map_err(store_error)?;
        audit(&st, &me, "token_revoke", json!({ "token_id": id }));
        return Ok(ok());
    };
    let c = signed_in(&me)?;
    let (acting, project, tid) = (c.user.id.clone(), sm.project_id.clone(), id.clone());
    let token = sm
        .run(move |a| a.get_token(&tid))
        .await??
        .filter(|t| t.project_id.as_deref() == Some(project.as_str()))
        .ok_or_else(|| AuthError::new(StatusCode::NOT_FOUND, "no_such_token", "no such token"))?;
    if token.user_id.as_deref() != Some(acting.as_str()) {
        others_allowed(&me)?;
        fresh(&sm, c)?;
    }
    let tid = id.clone();
    sm.run(move |a| a.revoke_token(&acting, &tid)).await??;
    audit(&st, &me, "token_revoke", json!({ "token_id": id, "actor": token.actor_id(), "owner": token.user_id }));
    Ok(ok())
}

fn ok() -> Response {
    reply(StatusCode::OK, &json!({ "ok": true }), &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_names_are_the_gates() {
        // `pm-accounts` knows the names but not `pm-policy` (it depends on no other ProxyMind crate): this is where the
        // two lists meet, and the request enum, the stored names and the gate's tiers must agree.
        let names: Vec<&str> = pm_service::pm_policy::Tier::ALL.iter().map(|t| t.name()).collect();
        assert_eq!(names, pm_accounts::TIER_NAMES);
        for t in
            [TierName::Read, TierName::Passive, TierName::ActiveSafe, TierName::ActiveIntrusive, TierName::Destructive]
        {
            let parsed = pm_service::pm_policy::Tier::parse(t.as_str()).expect("a tier of the gate");
            assert_eq!(parsed.name(), t.as_str());
            assert!(pm_accounts::validate_tier_cap(Some(t.as_str())).is_ok());
        }
    }
}
