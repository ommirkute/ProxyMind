//! The sign-in flow: `oidc_begin` (state, nonce and PKCE made and remembered), `oidc_take` (single use), and
//! `oidc_complete` (a verified ID token becomes a session, a link or a new account).
//!
//! **Pending sign-ins** live in memory (like passkey challenges: a restart costs one retry, and a PKCE verifier never
//! touches the disk). Each is keyed by the HMAC of a random *binding* value that the browser carries in a short-lived
//! `HttpOnly`, `SameSite=Lax` cookie, so a callback URL replayed from another browser finds nothing. It holds the
//! provider, the purpose, the `state` and `nonce` sent to the provider, the PKCE verifier, where to land afterwards, and
//! lives ten minutes. `oidc_take` removes it before it looks at anything else: one try, whatever the outcome.

use std::collections::HashMap;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde_json::{Value, json};

use super::discovery::{new_verifier, pkce_challenge};
use super::jwt::IdClaims;
use super::providers::OidcProvider;
use crate::error::{AccountError, Result};
use crate::model::{ClientInfo, LoginSuccess, Role, User, UserStatus};
use crate::store::Accounts;
use crate::users::{NewAccount, find_user, find_user_by_name, new_id, normalise_username};
use crate::util::{Secret, clip, ct_eq, hex, random};
use crate::webauthn::b64url_encode;

/// How long the browser has to come back from the provider.
pub const PENDING_TTL: i64 = 600;
/// Open sign-ins kept at most (anyone may start one); the oldest go first.
pub const MAX_PENDING: usize = 4096;

/// What a sign-in is for. The data of a link or an invite never leaves this crate.
#[derive(Debug, Clone)]
pub(crate) enum Purpose {
    Login,
    Link { user_id: String, session_ref: String, fresh_secs: i64 },
    Invite { token_hash: Vec<u8> },
}

struct Pending {
    provider_id: String,
    purpose: Purpose,
    state: String,
    nonce: String,
    verifier: String,
    next: String,
    created_at: i64,
    expires_at: i64,
}

#[derive(Default)]
pub struct PendingStore(Mutex<HashMap<Vec<u8>, Pending>>);

impl PendingStore {
    fn insert(&self, key: Vec<u8>, p: Pending, now: i64) {
        let mut map = self.0.lock();
        map.retain(|_, v| v.expires_at > now);
        while map.len() >= MAX_PENDING {
            let Some(oldest) = map.iter().min_by_key(|(_, v)| v.created_at).map(|(k, _)| k.clone()) else { break };
            map.remove(&oldest);
        }
        map.insert(key, p);
    }

    fn remove(&self, key: &[u8]) -> Option<Pending> {
        self.0.lock().remove(key)
    }

    /// How many are open (tests).
    pub fn len(&self) -> usize {
        self.0.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a sign-in is for, as the caller starts it.
#[derive(Debug, Clone)]
pub enum BeginPurpose {
    Login,
    /// Link an identity to `user_id`'s account. Bound to the session `session_ref` (as `SessionInfo::reference`),
    /// which must still be live and signed in within `fresh_secs` when the provider answers.
    Link {
        user_id: String,
        session_ref: String,
        fresh_secs: i64,
    },
    /// Redeem an invite by signing in with the provider (the invite token as the person has it).
    Invite {
        token: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingPurpose {
    Login,
    Link,
    Invite,
}

/// What `oidc_begin` hands the caller: the value for the browser's state cookie, and what goes into the
/// authorization URL.
pub struct OidcBegin {
    /// The cookie value. A secret; the server keeps only its HMAC.
    pub binding: Secret,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
    pub provider: OidcProvider,
}

impl std::fmt::Debug for OidcBegin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OidcBegin([redacted])")
    }
}

/// A pending sign-in taken out of the store by `oidc_take`: what is needed to finish it.
pub struct OidcPendingInfo {
    pub provider: OidcProvider,
    pub kind: PendingPurpose,
    pub nonce: String,
    /// The PKCE verifier, for the token request. Never logged.
    pub verifier: Secret,
    /// Where to land afterwards (already a same-origin path).
    pub next: String,
    purpose: Purpose,
}

impl std::fmt::Debug for OidcPendingInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OidcPendingInfo([redacted])")
    }
}

/// An identity linked to an account, as the Account page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcIdentity {
    /// The credential id (`c_…`): what unlinking names.
    pub id: String,
    pub provider_id: String,
    pub provider_name: String,
    /// As the provider last said (display only).
    pub email: Option<String>,
    pub name: Option<String>,
    /// `self`, `email`, `invite` or `auto`.
    pub linked_by: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug)]
pub enum OidcOutcome {
    SignedIn {
        login: Box<LoginSuccess>,
        /// A new account was made (auto-create or an invite).
        created: bool,
        /// The group claim changed the account's role on the served project to this.
        role_change: Option<Role>,
    },
    Linked(OidcIdentity),
}

enum Decision {
    Done(OidcOutcome),
    Refused { why: &'static str, user: Option<String> },
}

fn external_id(iss: &str, sub: &str) -> Vec<u8> {
    format!("{iss}\n{sub}").into_bytes()
}

fn refuse(why: &'static str, user: Option<&str>) -> Result<Decision> {
    Ok(Decision::Refused { why, user: user.map(str::to_string) })
}

fn display_text(s: &str, max: usize) -> String {
    clip(&s.chars().filter(|c| !c.is_control()).collect::<String>(), max)
}

fn meta_of(provider: &str, claims: &IdClaims, linked_by: &str) -> String {
    json!({
        "provider": provider,
        "email": claims.email.as_deref().map(|e| display_text(e, 254)),
        "name": claims.name.as_deref().map(|n| display_text(n, 100)),
        "linked_by": linked_by,
    })
    .to_string()
}

fn identity_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<OidcIdentity> {
    let meta: Value = r.get::<_, Option<String>>(3)?.and_then(|m| serde_json::from_str(&m).ok()).unwrap_or(Value::Null);
    let s = |k: &str| meta.get(k).and_then(Value::as_str).map(str::to_string);
    Ok(OidcIdentity {
        id: r.get(0)?,
        provider_id: s("provider").unwrap_or_default(),
        provider_name: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
        email: s("email"),
        name: s("name"),
        linked_by: s("linked_by").unwrap_or_default(),
        created_at: r.get(2)?,
        last_used_at: r.get(4)?,
    })
}

const IDENTITY_COLS: &str = "id, label, created_at, meta, last_used_at";

impl Accounts {
    // ---- begin and take ----------------------------------------------------------------------------------------

    /// Starts a sign-in with `provider_id`: makes the state, nonce and PKCE verifier and remembers them under a fresh
    /// binding. Throttled by address. Errors: `NoSuchProvider` (unknown or disabled), `Throttled`, and for a link or
    /// an invite whatever already rules it out (`OidcRefused`, `InvalidInvite`, `SessionInvalid`).
    pub fn oidc_begin(
        &self,
        provider_id: &str,
        purpose: BeginPurpose,
        next: &str,
        client: &ClientInfo,
    ) -> Result<OidcBegin> {
        self.check_throttle(None, client)?;
        let provider = self.oidc_provider(provider_id)?.filter(|p| p.enabled).ok_or(AccountError::NoSuchProvider)?;
        let purpose = match purpose {
            BeginPurpose::Login => Purpose::Login,
            BeginPurpose::Link { user_id, session_ref, fresh_secs } => {
                let conn = self.conn();
                let user = find_user(&conn, &user_id)?.filter(|u| u.status == UserStatus::Active);
                let user = user.ok_or(AccountError::SessionInvalid)?;
                if session_auth_time(&conn, &user.id, &session_ref, self.now())?.is_none() {
                    return Err(AccountError::SessionInvalid);
                }
                if self.is_privileged(&conn, &user)? && !self.has_local_factor(&conn, &user.id)? {
                    return Err(AccountError::OidcRefused("owner_needs_local_factor"));
                }
                if has_link_for(&conn, &user.id, &provider.id)? {
                    return Err(AccountError::OidcRefused("already_linked"));
                }
                Purpose::Link { user_id, session_ref, fresh_secs }
            }
            BeginPurpose::Invite { token } => {
                let hash = Self::mac(&self.keys.token, token.as_bytes());
                let role: Option<String> = {
                    let conn = self.conn();
                    if self.invite_usable(&conn, &token)? {
                        conn.query_row("SELECT role FROM invites WHERE token_hash = ?1", [&hash], |r| r.get(0))
                            .optional()?
                    } else {
                        None
                    }
                };
                let Some(role) = role else {
                    self.record_failure(None, client, "invite_failure", None, "bad invite (oidc)")?;
                    return Err(AccountError::InvalidInvite);
                };
                // An owner must have a local way in: an owner invite is redeemed with a passkey or a password.
                if role == "owner" {
                    return Err(AccountError::OidcRefused("owner_invite"));
                }
                Purpose::Invite { token_hash: hash }
            }
        };
        let binding = hex(&random::<32>()?);
        let (state, nonce, verifier) =
            (b64url_encode(&random::<32>()?), b64url_encode(&random::<32>()?), new_verifier()?);
        let now = self.now();
        let code_challenge = pkce_challenge(&verifier);
        self.oidc_pending.insert(
            Self::mac(&self.keys.token, binding.as_bytes()),
            Pending {
                provider_id: provider.id.clone(),
                purpose,
                state: state.clone(),
                nonce: nonce.clone(),
                verifier,
                next: clip(next, 2048),
                created_at: now,
                expires_at: now.saturating_add(PENDING_TTL),
            },
            now,
        );
        Ok(OidcBegin { binding: Secret(binding), state, nonce, code_challenge, provider })
    }

    /// Takes the pending sign-in of the browser's `binding` cookie, **using it up first**, then requires the `state`
    /// the provider returned to be the one stored. Any problem (no cookie, unknown, expired, another browser's, a
    /// replayed or altered state, a provider disabled meanwhile) is `InvalidPending`.
    pub fn oidc_take(&self, binding: &str, state: &str) -> Result<OidcPendingInfo> {
        if binding.len() != 64 || !binding.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AccountError::InvalidPending);
        }
        let p = self
            .oidc_pending
            .remove(&Self::mac(&self.keys.token, binding.as_bytes()))
            .ok_or(AccountError::InvalidPending)?;
        if p.expires_at <= self.now() || !ct_eq(state.as_bytes(), p.state.as_bytes()) {
            return Err(AccountError::InvalidPending);
        }
        let provider = self.oidc_provider(&p.provider_id)?.filter(|p| p.enabled).ok_or(AccountError::InvalidPending)?;
        let kind = match &p.purpose {
            Purpose::Login => PendingPurpose::Login,
            Purpose::Link { .. } => PendingPurpose::Link,
            Purpose::Invite { .. } => PendingPurpose::Invite,
        };
        Ok(OidcPendingInfo {
            provider,
            kind,
            nonce: p.nonce,
            verifier: Secret(p.verifier),
            next: p.next,
            purpose: p.purpose,
        })
    }

    /// Counts a refused sign-in against the address and writes it to the security log (fixed words only).
    pub fn oidc_record_failure(&self, client: &ClientInfo, reason: &str, user: Option<&str>) -> Result<()> {
        self.record_failure(None, client, "oidc_failure", user, reason)
    }

    /// Refuses (`Throttled`) while a delay runs for the address. Called before any request to the provider.
    pub fn oidc_check_throttle(&self, client: &ClientInfo) -> Result<()> {
        self.check_throttle(None, client)
    }

    // ---- completing --------------------------------------------------------------------------------------------

    /// Finishes a sign-in whose ID token the caller has verified against `pending`'s provider, nonce and keys. `project`
    /// is the id of the project this server serves (group claims set the role there).
    ///
    /// Errors: `OidcRefused(code)` for every refusal that is the person's to fix or to ask an owner about
    /// (`no_account`, `not_permitted`, `owner_needs_local_factor`, `account_exists`, `identity_in_use`,
    /// `already_linked`, `owner_invite`, `link_expired`), after the same throttle and security-log bookkeeping as any
    /// failed sign-in; `InvalidInvite`.
    pub fn oidc_complete(
        &self,
        pending: OidcPendingInfo,
        claims: &IdClaims,
        project: &str,
        client: &ClientInfo,
    ) -> Result<OidcOutcome> {
        let decision = self.tx(|tx| match &pending.purpose {
            Purpose::Login => self.login_in(tx, &pending.provider, claims, project, client),
            Purpose::Link { user_id, session_ref, fresh_secs } => {
                self.link_in(tx, &pending.provider, claims, user_id, session_ref, *fresh_secs)
            }
            Purpose::Invite { token_hash } => self.invite_in(tx, &pending.provider, claims, token_hash, client),
        });
        match decision {
            Ok(Decision::Done(o)) => Ok(o),
            Ok(Decision::Refused { why, user }) => {
                self.record_failure(None, client, "oidc_failure", user.as_deref(), why)?;
                Err(AccountError::OidcRefused(why))
            }
            Err(AccountError::InvalidInvite) => {
                self.record_failure(None, client, "invite_failure", None, "bad invite (oidc)")?;
                Err(AccountError::InvalidInvite)
            }
            Err(e) => Err(e),
        }
    }

    fn is_privileged(&self, conn: &Connection, user: &User) -> Result<bool> {
        if user.server_admin {
            return Ok(true);
        }
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM memberships WHERE user_id = ?1 AND role = 'owner')",
            [&user.id],
            |r| r.get(0),
        )?)
    }

    /// A way in that does not depend on a provider: a passkey, or a password with an authenticator.
    fn has_local_factor(&self, conn: &Connection, user_id: &str) -> Result<bool> {
        let has_password: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM credentials WHERE user_id = ?1 AND kind = 'password')",
            [user_id],
            |r| r.get(0),
        )?;
        Ok(self.has_passkey(conn, user_id)? || (has_password && self.totp_enabled(conn, user_id)?))
    }

    fn identity_row(&self, tx: &Transaction<'_>, ext: &[u8]) -> Result<Option<(String, String)>> {
        Ok(tx
            .query_row("SELECT id, user_id FROM credentials WHERE kind = 'oidc' AND external_id = ?1", [ext], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?)
    }

    fn insert_link(
        &self,
        tx: &Transaction<'_>,
        user: &User,
        p: &OidcProvider,
        ext: &[u8],
        claims: &IdClaims,
        how: &str,
    ) -> Result<std::result::Result<String, &'static str>> {
        let id = new_id("c_")?;
        let inserted = tx.execute(
            "INSERT INTO credentials (id, user_id, kind, label, external_id, meta, created_at, last_used_at) \
             VALUES (?1, ?2, 'oidc', ?3, ?4, ?5, ?6, ?6)",
            rusqlite::params![id, user.id, p.name, ext, meta_of(&p.id, claims, how), self.now()],
        );
        match inserted {
            Ok(_) => {
                self.audit(
                    tx,
                    "oidc_identity_linked",
                    Some(&user.id),
                    &format!("user:{}", user.id),
                    None,
                    &format!("{} {how}", p.id),
                )?;
                Ok(Ok(id))
            }
            Err(rusqlite::Error::SqliteFailure(f, _)) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                Ok(Err("identity_in_use"))
            }
            Err(e) => Err(e.into()),
        }
    }

    fn identity_by_id(&self, tx: &Transaction<'_>, id: &str) -> Result<OidcIdentity> {
        Ok(tx.query_row(&format!("SELECT {IDENTITY_COLS} FROM credentials WHERE id = ?1"), [id], identity_of)?)
    }

    fn sign_in(
        &self,
        tx: &Transaction<'_>,
        user: User,
        cred_id: &str,
        created: bool,
        role_change: Option<Role>,
        client: &ClientInfo,
    ) -> Result<Decision> {
        let login = self.complete_login(tx, user, "oidc", client)?;
        tx.execute("UPDATE credentials SET last_used_at = ?1 WHERE id = ?2", rusqlite::params![self.now(), cred_id])?;
        Ok(Decision::Done(OidcOutcome::SignedIn { login: Box::new(login), created, role_change }))
    }

    fn login_in(
        &self,
        tx: &Transaction<'_>,
        p: &OidcProvider,
        claims: &IdClaims,
        project: &str,
        client: &ClientInfo,
    ) -> Result<Decision> {
        let ext = external_id(&claims.iss, &claims.sub);
        // 1. A linked identity.
        if let Some((cred, uid)) = self.identity_row(tx, &ext)? {
            let Some(user) = find_user(tx, &uid)?.filter(|u| u.status == UserStatus::Active) else {
                return refuse("not_permitted", Some(&uid));
            };
            if self.is_privileged(tx, &user)? && !self.has_local_factor(tx, &user.id)? {
                return refuse("owner_needs_local_factor", Some(&user.id));
            }
            // Keep the display data current (never used for a decision).
            let old: Option<String> =
                tx.query_row("SELECT meta FROM credentials WHERE id = ?1", [&cred], |r| r.get(0)).optional()?.flatten();
            let how = old
                .and_then(|m| serde_json::from_str::<Value>(&m).ok())
                .and_then(|m| m.get("linked_by").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_else(|| "self".into());
            tx.execute(
                "UPDATE credentials SET meta = ?1 WHERE id = ?2",
                rusqlite::params![meta_of(&p.id, claims, &how), cred],
            )?;
            let role_change = self.apply_claims(tx, &user, p, &claims.groups, project)?;
            return self.sign_in(tx, user, &cred, false, role_change, client);
        }
        // 2 and 3 need a verified email.
        let email = claims.email.as_deref().filter(|_| claims.email_verified).map(str::to_ascii_lowercase);
        if let Some(email) = &email {
            let handle = normalise_username(email).ok();
            // 2. Link an existing local account whose handle is the verified email (off by default).
            if p.email_linking
                && let Some(target) = handle.as_deref().map(|h| find_user_by_name(tx, h)).transpose()?.flatten()
            {
                if target.status != UserStatus::Active || self.is_privileged(tx, &target)? {
                    // Never an owner or an administrator: those link from their own Account page.
                    return refuse("not_permitted", Some(&target.id));
                }
                if has_link_for(tx, &target.id, &p.id)? {
                    return refuse("already_linked", Some(&target.id));
                }
                let cred = match self.insert_link(tx, &target, p, &ext, claims, "email")? {
                    Ok(c) => c,
                    Err(why) => return refuse(why, Some(&target.id)),
                };
                let role_change = self.apply_claims(tx, &target, p, &claims.groups, project)?;
                return self.sign_in(tx, target, &cred, false, role_change, client);
            }
            // 3. Auto-create for a listed domain: a viewer, at most.
            let domain = email.rsplit_once('@').map(|(_, d)| d);
            if domain.is_some_and(|d| p.auto_create_domains.iter().any(|a| a == d)) {
                let Some(handle) = handle else { return refuse("no_account", None) };
                if find_user_by_name(tx, &handle)?.is_some() {
                    return refuse("account_exists", None);
                }
                let display = claims.name.as_deref().map_or_else(|| handle.clone(), |n| display_text(n, 100));
                let user = self.insert_user(tx, &handle, &display, false, None, None)?;
                tx.execute(
                    "INSERT INTO memberships (project_id, user_id, role, created_at, created_by) \
                     VALUES (?1, ?2, 'viewer', ?3, ?4)",
                    rusqlite::params![project, user.id, self.now(), format!("oidc:{}", p.id)],
                )?;
                self.audit(
                    tx,
                    "user_created",
                    Some(&user.id),
                    "anonymous",
                    client.addr.as_deref(),
                    &format!("oidc {}", p.id),
                )?;
                let cred = match self.insert_link(tx, &user, p, &ext, claims, "auto")? {
                    Ok(c) => c,
                    Err(why) => return refuse(why, Some(&user.id)),
                };
                return self.sign_in(tx, user, &cred, true, None, client);
            }
        }
        // 4. Joining is by invite.
        refuse("no_account", None)
    }

    fn link_in(
        &self,
        tx: &Transaction<'_>,
        p: &OidcProvider,
        claims: &IdClaims,
        user_id: &str,
        session_ref: &str,
        fresh_secs: i64,
    ) -> Result<Decision> {
        let Some(user) = find_user(tx, user_id)?.filter(|u| u.status == UserStatus::Active) else {
            return refuse("link_expired", Some(user_id));
        };
        // The Strict session cookie does not travel on the redirect back, so the session is checked by reference.
        let fresh = session_auth_time(tx, &user.id, session_ref, self.now())?
            .is_some_and(|t| (0..=fresh_secs).contains(&self.now().saturating_sub(t)));
        if !fresh {
            return refuse("link_expired", Some(&user.id));
        }
        if self.is_privileged(tx, &user)? && !self.has_local_factor(tx, &user.id)? {
            return refuse("owner_needs_local_factor", Some(&user.id));
        }
        let ext = external_id(&claims.iss, &claims.sub);
        if let Some((cred, uid)) = self.identity_row(tx, &ext)? {
            if uid != user.id {
                return refuse("identity_in_use", Some(&user.id));
            }
            tx.execute(
                "UPDATE credentials SET meta = ?1 WHERE id = ?2",
                rusqlite::params![meta_of(&p.id, claims, "self"), cred],
            )?;
            return Ok(Decision::Done(OidcOutcome::Linked(self.identity_by_id(tx, &cred)?)));
        }
        if has_link_for(tx, &user.id, &p.id)? {
            return refuse("already_linked", Some(&user.id));
        }
        match self.insert_link(tx, &user, p, &ext, claims, "self")? {
            Ok(cred) => Ok(Decision::Done(OidcOutcome::Linked(self.identity_by_id(tx, &cred)?))),
            Err(why) => refuse(why, Some(&user.id)),
        }
    }

    fn invite_in(
        &self,
        tx: &Transaction<'_>,
        p: &OidcProvider,
        claims: &IdClaims,
        token_hash: &[u8],
        client: &ClientInfo,
    ) -> Result<Decision> {
        let ext = external_id(&claims.iss, &claims.sub);
        // An identity that already belongs to an account signs in; it does not use up an invite.
        if self.identity_row(tx, &ext)?.is_some() {
            return refuse("already_linked", None);
        }
        let role: Option<String> = tx
            .query_row(
                "SELECT role FROM invites WHERE token_hash = ?1 AND used_at IS NULL AND revoked_at IS NULL \
                 AND expires_at > ?2",
                rusqlite::params![token_hash, self.now()],
                |r| r.get(0),
            )
            .optional()?;
        match role.as_deref() {
            None => return Err(AccountError::InvalidInvite),
            Some("owner") => return refuse("owner_invite", None),
            Some(_) => {}
        }
        let username = self.free_handle(tx, claims)?;
        let display = claims
            .name
            .as_deref()
            .map(|n| display_text(n, 100))
            .or_else(|| claims.email.as_deref().map(|e| display_text(e, 100)))
            .unwrap_or_else(|| username.clone());
        let acct = NewAccount { username: &username, display_name: &display, id: None, phc: None };
        let user = self.finish_invite_in(tx, token_hash, acct, client)?;
        let cred = match self.insert_link(tx, &user, p, &ext, claims, "invite")? {
            Ok(c) => c,
            Err(why) => return refuse(why, Some(&user.id)),
        };
        self.sign_in(tx, user, &cred, true, None, client)
    }

    /// A handle for an account made from an invite: the provider's preferred username or the local part of the email,
    /// cleaned up, with a number added while it is taken.
    fn free_handle(&self, tx: &Transaction<'_>, claims: &IdClaims) -> Result<String> {
        let raw = claims
            .preferred_username
            .as_deref()
            .or_else(|| claims.email.as_deref().and_then(|e| e.split('@').next()))
            .unwrap_or("user");
        let mut base: String = raw
            .to_ascii_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c } else { '-' })
            .collect();
        base = base.trim_start_matches(['.', '_', '-']).chars().take(56).collect();
        if base.len() < 3 {
            base = format!("{base}user");
        }
        for n in 1..=50 {
            let candidate = if n == 1 { base.clone() } else { format!("{base}-{n}") };
            if normalise_username(&candidate).is_ok() && find_user_by_name(tx, &candidate)?.is_none() {
                return Ok(candidate);
            }
        }
        Err(AccountError::UsernameTaken)
    }

    /// Group claims to a role on the served project, at each sign-in. **Never `owner`** (the mapping cannot hold one),
    /// and nothing for an owner or a server administrator. A membership a person made is only ever raised; one the
    /// provider made (`created_by` `oidc:…`: auto-create, or raised by a claim) follows the claim, down to `viewer` when
    /// no group matches any more, and is never removed. A claim never creates a membership for someone who has none.
    fn apply_claims(
        &self,
        tx: &Transaction<'_>,
        user: &User,
        p: &OidcProvider,
        groups: &[String],
        project: &str,
    ) -> Result<Option<Role>> {
        if p.role_map.is_empty() || self.is_privileged(tx, user)? {
            return Ok(None);
        }
        let current: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT role, created_by FROM memberships WHERE project_id = ?1 AND user_id = ?2",
                [project, &user.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((cur, by)) = current else { return Ok(None) };
        let cur = Role::parse(&cur)?;
        if cur == Role::Owner {
            return Ok(None);
        }
        let claimed = p
            .role_map
            .iter()
            .filter(|m| groups.contains(&m.value))
            .map(|m| m.role)
            .filter(|r| *r != Role::Owner)
            .max_by_key(|r| r.rank());
        let managed = by.as_deref().is_some_and(|b| b.starts_with("oidc:"));
        let target = match (claimed, managed) {
            (Some(c), true) => Some(c),
            (Some(c), false) if c.rank() > cur.rank() => Some(c),
            (None, true) if cur.rank() > Role::Viewer.rank() => Some(Role::Viewer),
            _ => None,
        };
        let Some(target) = target.filter(|t| *t != cur && *t != Role::Owner) else { return Ok(None) };
        tx.execute(
            "UPDATE memberships SET role = ?3, created_by = ?4 WHERE project_id = ?1 AND user_id = ?2",
            rusqlite::params![project, user.id, target.as_str(), format!("oidc:{}", p.id)],
        )?;
        if target.rank() < cur.rank() {
            Self::revoke_sessions_in(tx, &user.id, None, "demoted", self.now())?;
        }
        self.audit(
            tx,
            "oidc_role_set",
            Some(&user.id),
            &format!("oidc:{}", p.id),
            None,
            &format!("{project} {}", target.as_str()),
        )?;
        Ok(Some(target))
    }

    // ---- linked identities -------------------------------------------------------------------------------------

    /// The identities linked to an account, oldest first.
    pub fn oidc_identities(&self, user_id: &str) -> Result<Vec<OidcIdentity>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {IDENTITY_COLS} FROM credentials WHERE user_id = ?1 AND kind = 'oidc' ORDER BY created_at, id"
        ))?;
        let rows = stmt.query_map([user_id], identity_of)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// How many identities an account has linked.
    pub fn oidc_identity_count(&self, user_id: &str) -> Result<usize> {
        let n: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM credentials WHERE user_id = ?1 AND kind = 'oidc'",
            [user_id],
            |r| r.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// Unlinks an identity and ends the account's other sessions (`keep_session` is the one making the request).
    /// Refused (`LastSignIn`) when nothing else would let the account sign in: no other identity, no passkey and no
    /// password that works on its own.
    pub fn oidc_unlink(&self, user_id: &str, identity_id: &str, keep_session: Option<&str>) -> Result<()> {
        let keep = keep_session.map(|s| self.session_hash(s));
        self.tx(|tx| {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE id = ?1 AND user_id = ?2 AND kind = 'oidc')",
                [identity_id, user_id],
                |r| r.get(0),
            )?;
            if !exists {
                return Err(AccountError::NoSuchIdentity);
            }
            let others: i64 = tx.query_row(
                "SELECT COUNT(*) FROM credentials WHERE user_id = ?1 AND kind = 'oidc' AND id != ?2",
                [user_id, identity_id],
                |r| r.get(0),
            )?;
            let has_password: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE user_id = ?1 AND kind = 'password')",
                [user_id],
                |r| r.get(0),
            )?;
            let password_route =
                has_password && (self.totp_enabled(tx, user_id)? || !self.requires_second_factor(tx, user_id)?);
            if others == 0 && !self.has_passkey(tx, user_id)? && !password_route {
                return Err(AccountError::LastSignIn);
            }
            tx.execute("DELETE FROM credentials WHERE id = ?1 AND user_id = ?2", [identity_id, user_id])?;
            Self::revoke_sessions_in(tx, user_id, keep.as_deref(), "oidc_unlinked", self.now())?;
            self.audit(tx, "oidc_identity_unlinked", Some(user_id), &format!("user:{user_id}"), None, identity_id)
        })
    }

    /// For tests and diagnostics: the security-log kinds are the contract, this is only a convenience.
    #[doc(hidden)]
    pub fn oidc_pending_len(&self) -> usize {
        self.oidc_pending.len()
    }
}

fn has_link_for(conn: &Connection, user_id: &str, provider_id: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM credentials WHERE user_id = ?1 AND kind = 'oidc' \
         AND json_extract(meta, '$.provider') = ?2)",
        [user_id, provider_id],
        |r| r.get(0),
    )?)
}

/// When the live session `reference` of `user_id` was signed in, or `None` when it is not live.
fn session_auth_time(conn: &Connection, user_id: &str, reference: &str, now: i64) -> Result<Option<i64>> {
    Ok(conn
        .query_row(
            "SELECT authenticated_at FROM sessions WHERE user_id = ?1 AND revoked_at IS NULL \
             AND idle_expires_at > ?3 AND absolute_expires_at > ?3 AND lower(hex(substr(id_hash, 1, 8))) = lower(?2)",
            rusqlite::params![user_id, reference, now],
            |r| r.get(0),
        )
        .optional()?)
}
