//! Passkeys (WebAuthn credentials) in `server.db`: enrolment, sign-in, the counter policy, recovery by enrolment link and
//! the server's "require a passkey" setting (ADR-0022, step 7). The cryptography is `webauthn`; this file is the
//! rules around it and the storage.
//!
//! * **Challenges.** 32 bytes from the OS, issued with the options, kept in memory for five minutes ([`Ceremonies`]),
//!   **single use** (taken out of the table before the response is looked at, so a failed attempt burns it too) and
//!   **bound to who asked**: an enrolment to the user and the session that began it, a setup, invite or enrolment-link
//!   registration to its token and the username it chose, a sign-in to the username it claimed (if any). A response
//!   is matched to its ceremony by the challenge inside `clientDataJSON`.
//! * **Storage.** A `credentials` row of kind `passkey`: `external_id` is the credential id (unique across the
//!   server, whoever owns it), `secret` the COSE public key exactly as registered, `counter` the signature counter,
//!   `label` the user's name for it, `meta` JSON with transports, AAGUID, backup flags and algorithm. No private key
//!   exists on the server; nothing here is a secret, but the API still never returns key material.
//! * **Counter.** If either the stored or the new counter is non-zero, the new one must be greater: otherwise the
//!   sign-in is refused and the security log gets `passkey_clone_suspected` (the authenticator may have been copied).
//!   A counter that is always zero (many platform authenticators, and synced passkeys) is allowed.
//! * **No username leak.** Sign-in options for a username that has no passkey (unknown, disabled, or without one)
//!   come back with **decoy credential ids** derived from a server-key HMAC of the name, so the same name always gets
//!   the same answer and it cannot be told apart from a real account by shape. (A real account's ids are real; an
//!   account with more than three passkeys shows a count a decoy never has. The usernameless mode, an empty
//!   `allowCredentials`, reveals nothing at all.)
//! * **Throttling and audit** are those of password sign-in: failures count against the claimed account (or, once the
//!   credential is known, its account) and against the address; every success, failure and clone suspicion is in the
//!   security log with a fixed reason, never a credential id or a signature.
//! * **Not a password's second factor.** A passkey with user verification is a complete sign-in on its own
//!   (`auth_method` `passkey`); it counts as the owner's required second factor.

use std::collections::HashMap;

use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{AccountError, Result};
use crate::model::{ClientInfo, LoginSuccess, Role, UserStatus};
use crate::store::Accounts;
use crate::users::{NewAccount, find_user, find_user_by_name, new_id, normalise_username};
use crate::util::{clip, ct_eq, hex, random, unhex};
use crate::webauthn::{
    self, RelyingParty, WebAuthnError, b64url_decode, b64url_encode, client_data_challenge, cose::ALLOWED_ALGS,
};

/// Passkeys one account may hold.
pub const MAX_PASSKEYS: usize = 10;
/// Open ceremonies the server keeps; past it the oldest go (an anonymous caller can ask for sign-in options).
const CEREMONY_CAP: usize = 4096;
const MAX_NAME: usize = 64;

/// The response of `navigator.credentials.create()`, every binary field base64url (no padding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResponse {
    /// The credential id.
    pub id: String,
    pub client_data_json: String,
    pub attestation_object: String,
    #[serde(default)]
    pub transports: Vec<String>,
}

/// The response of `navigator.credentials.get()`, every binary field base64url (no padding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertionResponse {
    /// The credential id.
    pub id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
    #[serde(default)]
    pub user_handle: Option<String>,
}

/// A passkey as the account page lists it. No key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyInfo {
    /// The row id (`c_…`), for rename and remove. Not the credential id.
    pub id: String,
    pub name: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub transports: Vec<String>,
    pub backup_eligible: bool,
    pub backup_state: bool,
    /// The authenticator model (AAGUID, 32 hex digits); all zeros when it did not say.
    pub aaguid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEnrolmentLink {
    pub id: String,
    /// `pmenr_…`, shown once; only its HMAC is stored.
    pub token: crate::Secret,
    pub expires_at: i64,
}

/// Whom an enrolment link is for (what the page that redeems it shows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolmentTarget {
    pub username: String,
    pub display_name: String,
    pub expires_at: i64,
}

#[derive(Serialize, Deserialize, Default)]
struct Meta {
    #[serde(default)]
    transports: Vec<String>,
    #[serde(default)]
    aaguid: String,
    #[serde(default)]
    backup_eligible: bool,
    #[serde(default)]
    backup_state: bool,
    #[serde(default)]
    alg: i64,
}

// ---- ceremonies ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AccountRoute {
    Setup,
    Invite,
}

/// What a challenge was issued for, and so who may finish it.
#[derive(Debug, Clone)]
pub(crate) enum Purpose {
    Enrol { user_id: String, session: Vec<u8> },
    Account { route: AccountRoute, token_hash: Vec<u8>, username: String, display_name: String, user_id: String },
    Link { token_hash: Vec<u8>, user_id: String },
    Login { claimed: Option<String>, expected_user: Option<String> },
}

struct Ceremony {
    purpose: Purpose,
    created_at: i64,
    expires_at: i64,
}

#[derive(Default)]
pub(crate) struct Ceremonies(Mutex<HashMap<[u8; 32], Ceremony>>);

impl Ceremonies {
    fn issue(&self, now: i64, ttl: i64, purpose: Purpose) -> Result<[u8; 32]> {
        let challenge = random::<32>()?;
        let mut map = self.0.lock();
        map.retain(|_, c| c.expires_at > now);
        // One open enrolment per user: a new options call replaces the last.
        if let Purpose::Enrol { user_id, .. } = &purpose {
            map.retain(|_, c| !matches!(&c.purpose, Purpose::Enrol { user_id: u, .. } if u == user_id));
        }
        while map.len() >= CEREMONY_CAP {
            let Some(oldest) = map.iter().min_by_key(|(_, c)| c.created_at).map(|(k, _)| *k) else { break };
            map.remove(&oldest);
        }
        map.insert(challenge, Ceremony { purpose, created_at: now, expires_at: now.saturating_add(ttl) });
        Ok(challenge)
    }

    /// Removes and returns the ceremony of `challenge` when it is still live. Used up either way.
    fn take(&self, now: i64, challenge: &[u8]) -> Option<Purpose> {
        let key: [u8; 32] = challenge.try_into().ok()?;
        let c = self.0.lock().remove(&key)?;
        (c.expires_at > now).then_some(c.purpose)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.lock().len()
    }
}

// ---- helpers ---------------------------------------------------------------------------------------------------

/// The WebAuthn user handle of an account: its id without the `u_` prefix, as bytes (16 random bytes, no personal
/// information, as the specification asks).
pub fn user_handle(user_id: &str) -> Vec<u8> {
    user_id.strip_prefix("u_").and_then(unhex).unwrap_or_else(|| user_id.as_bytes().to_vec())
}

fn refused(e: WebAuthnError) -> AccountError {
    AccountError::PasskeyRefused(e.reason())
}

fn decode_field(s: &str, max: usize) -> Option<Vec<u8>> {
    if s.len() > max.saturating_mul(2) {
        return None;
    }
    b64url_decode(s).filter(|b| b.len() <= max)
}

fn clean_name(name: &str) -> Option<String> {
    let t = clip(name.trim(), MAX_NAME);
    (!t.is_empty() && !t.chars().any(char::is_control)).then_some(t)
}

fn known_transports(list: &[String]) -> Vec<String> {
    const OK: [&str; 6] = ["usb", "nfc", "ble", "internal", "hybrid", "smart-card"];
    let mut out: Vec<String> = Vec::new();
    for t in list.iter().take(8) {
        if OK.contains(&t.as_str()) && !out.contains(t) {
            out.push(t.clone());
        }
    }
    out
}

/// The sign counter rule: two zeros are fine (an authenticator that does not count); otherwise it must go up.
pub fn counter_allows(stored: u32, new: u32) -> bool {
    (stored == 0 && new == 0) || new > stored
}

fn creation_options(
    rp: &RelyingParty,
    challenge: &[u8],
    handle: &[u8],
    username: &str,
    display: &str,
    exclude: &[Vec<u8>],
    timeout_ms: i64,
) -> Value {
    json!({
        "rp": { "id": rp.id, "name": rp.name },
        "user": { "id": b64url_encode(handle), "name": username, "displayName": if display.is_empty() { username } else { display } },
        "challenge": b64url_encode(challenge),
        "pubKeyCredParams": ALLOWED_ALGS.iter().map(|a| json!({ "type": "public-key", "alg": a })).collect::<Vec<_>>(),
        "timeout": timeout_ms,
        "excludeCredentials": exclude.iter().map(|id| json!({ "type": "public-key", "id": b64url_encode(id) })).collect::<Vec<_>>(),
        "authenticatorSelection": { "residentKey": "preferred", "requireResidentKey": false, "userVerification": "required" },
        "attestation": "none",
    })
}

fn request_options(rp: &RelyingParty, challenge: &[u8], allow: &[Vec<u8>], timeout_ms: i64) -> Value {
    json!({
        "challenge": b64url_encode(challenge),
        "timeout": timeout_ms,
        "rpId": rp.id,
        "allowCredentials": allow.iter().map(|id| json!({ "type": "public-key", "id": b64url_encode(id) })).collect::<Vec<_>>(),
        "userVerification": "required",
    })
}

struct Row {
    id: String,
    user_id: String,
    cose: Vec<u8>,
    counter: u32,
    meta: Meta,
}

fn info_of(
    id: String,
    name: Option<String>,
    created_at: i64,
    last_used_at: Option<i64>,
    meta: Option<String>,
) -> PasskeyInfo {
    let m: Meta = meta.and_then(|m| serde_json::from_str(&m).ok()).unwrap_or_default();
    PasskeyInfo {
        id,
        name: name.unwrap_or_else(|| "Passkey".into()),
        created_at,
        last_used_at,
        transports: m.transports,
        backup_eligible: m.backup_eligible,
        backup_state: m.backup_state,
        aaguid: m.aaguid,
    }
}

impl Accounts {
    fn ceremony_ttl(&self) -> i64 {
        crate::store::secs(self.cfg.pending_ttl)
    }

    fn issue(&self, purpose: Purpose) -> Result<[u8; 32]> {
        self.ceremonies.issue(self.now(), self.ceremony_ttl(), purpose)
    }

    fn timeout_ms(&self) -> i64 {
        self.ceremony_ttl().saturating_mul(1000)
    }

    // ---- reading ---------------------------------------------------------------------------------------------

    pub(crate) fn passkey_count_in(&self, conn: &Connection, user_id: &str) -> Result<usize> {
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM credentials WHERE user_id = ?1 AND kind = 'passkey' AND enabled = 1",
            [user_id],
            |r| r.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    pub(crate) fn has_passkey(&self, conn: &Connection, user_id: &str) -> Result<bool> {
        Ok(self.passkey_count_in(conn, user_id)? > 0)
    }

    /// How many passkeys the account has.
    pub fn passkey_count(&self, user_id: &str) -> Result<usize> {
        self.passkey_count_in(&self.conn(), user_id)
    }

    /// The account's passkeys, oldest first. No key material.
    pub fn list_passkeys(&self, user_id: &str) -> Result<Vec<PasskeyInfo>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, label, created_at, last_used_at, meta FROM credentials \
             WHERE user_id = ?1 AND kind = 'passkey' AND enabled = 1 ORDER BY created_at, id",
        )?;
        let rows = stmt.query_map([user_id], |r| Ok(info_of(r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn credential_ids(&self, conn: &Connection, user_id: &str) -> Result<Vec<Vec<u8>>> {
        let mut stmt = conn.prepare(
            "SELECT external_id FROM credentials WHERE user_id = ?1 AND kind = 'passkey' AND enabled = 1 \
             AND external_id IS NOT NULL ORDER BY created_at, id",
        )?;
        let rows = stmt.query_map([user_id], |r| r.get::<_, Vec<u8>>(0))?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    fn find_by_credential_id(&self, conn: &Connection, credential_id: &[u8]) -> Result<Option<Row>> {
        type Raw = (String, String, Vec<u8>, i64, Option<String>);
        let row: Option<Raw> = conn
            .query_row(
                "SELECT id, user_id, secret, counter, meta FROM credentials \
                 WHERE kind = 'passkey' AND enabled = 1 AND external_id = ?1",
                [credential_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        Ok(row.map(|(id, user_id, cose, counter, meta)| Row {
            id,
            user_id,
            cose,
            counter: u32::try_from(counter).unwrap_or(u32::MAX),
            meta: meta.and_then(|m| serde_json::from_str(&m).ok()).unwrap_or_default(),
        }))
    }

    // ---- storing ---------------------------------------------------------------------------------------------

    /// Stores a verified registration for `user_id`. A credential id already on the server (any account) is refused.
    fn insert_passkey(
        &self,
        tx: &Transaction<'_>,
        user_id: &str,
        name: Option<&str>,
        reg: &webauthn::Registration,
        transports: &[String],
    ) -> Result<PasskeyInfo> {
        let existing = self.passkey_count_in(tx, user_id)?;
        if existing >= MAX_PASSKEYS {
            return Err(AccountError::PasskeyRefused("this account has the most passkeys it may have"));
        }
        let name = name.and_then(clean_name).unwrap_or_else(|| format!("Passkey {}", existing + 1));
        let meta = Meta {
            transports: known_transports(transports),
            aaguid: hex(&reg.aaguid),
            backup_eligible: reg.backup_eligible,
            backup_state: reg.backup_state,
            alg: reg.alg,
        };
        let meta_json = serde_json::to_string(&meta).map_err(|e| AccountError::Internal(e.to_string()))?;
        let id = new_id("c_")?;
        let now = self.now();
        tx.execute(
            "INSERT INTO credentials (id, user_id, kind, label, external_id, secret, counter, meta, created_at) \
             VALUES (?1, ?2, 'passkey', ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                id,
                user_id,
                name,
                reg.credential_id,
                reg.public_key_cose,
                i64::from(reg.sign_count),
                meta_json,
                now
            ],
        )
        .map_err(|e| match e {
            rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                AccountError::PasskeyRefused("this passkey is already registered")
            }
            other => other.into(),
        })?;
        self.audit(tx, "passkey_added", Some(user_id), &format!("user:{user_id}"), None, &id)?;
        Ok(info_of(id, Some(name), now, None, Some(meta_json)))
    }

    /// Verifies a registration response against its ceremony's challenge. Returns the registration to store.
    fn verify_registration_response(
        &self,
        rp: &RelyingParty,
        resp: &RegistrationResponse,
        purpose_ok: impl FnOnce(&Purpose) -> bool,
        failure_kind: &str,
        user_for_log: Option<&str>,
    ) -> Result<(webauthn::Registration, Purpose)> {
        let fail = |reason: &'static str| -> Result<AccountError> {
            self.tx(|tx| self.audit(tx, failure_kind, user_for_log, "anonymous", None, reason))?;
            Ok(AccountError::PasskeyRefused(reason))
        };
        let (Some(client_data), Some(attestation)) =
            (decode_field(&resp.client_data_json, 8 * 1024), decode_field(&resp.attestation_object, 64 * 1024))
        else {
            return Err(fail("the response is not valid base64url")?);
        };
        let Some(challenge) = client_data_challenge(&client_data) else {
            return Err(fail("the client data is not valid")?);
        };
        // Taken out first: a response that fails verification has used its challenge up.
        let Some(purpose) = self.ceremonies.take(self.now(), &challenge) else {
            return Err(fail("this passkey request has expired or was already used")?);
        };
        if !purpose_ok(&purpose) {
            return Err(fail("this passkey request was not started for this action")?);
        }
        let reg = match webauthn::verify_registration(rp, &challenge, &client_data, &attestation, &ALLOWED_ALGS) {
            Ok(r) => r,
            Err(e) => {
                self.tx(|tx| self.audit(tx, failure_kind, user_for_log, "anonymous", None, e.code()))?;
                return Err(refused(e));
            }
        };
        // The id the browser reports must be the one the authenticator attested.
        match decode_field(&resp.id, 1023) {
            Some(id) if ct_eq(&id, &reg.credential_id) => {}
            _ => return Err(fail("the credential id does not match")?),
        }
        Ok((reg, purpose))
    }

    // ---- enrolling on the account page -----------------------------------------------------------------------

    /// Starts enrolling a passkey for a signed-in user: the options for `navigator.credentials.create()`. The
    /// challenge is bound to this user and this session. Whether the caller may (a fresh sign-in) is the layer above's.
    pub fn passkey_begin_enrol(&self, rp: &RelyingParty, user_id: &str, session_id: &str) -> Result<Value> {
        let (user, exclude) = {
            let conn = self.conn();
            let user = find_user(&conn, user_id)?
                .filter(|u| u.status == UserStatus::Active)
                .ok_or(AccountError::NoSuchUser)?;
            if self.passkey_count_in(&conn, user_id)? >= MAX_PASSKEYS {
                return Err(AccountError::PasskeyRefused("this account has the most passkeys it may have"));
            }
            (user, self.credential_ids(&conn, user_id)?)
        };
        let challenge =
            self.issue(Purpose::Enrol { user_id: user.id.clone(), session: self.session_hash(session_id) })?;
        Ok(creation_options(
            rp,
            &challenge,
            &user_handle(&user.id),
            &user.username,
            &user.display_name,
            &exclude,
            self.timeout_ms(),
        ))
    }

    /// Finishes it: verifies the response, stores the passkey under `name` and returns it.
    pub fn passkey_finish_enrol(
        &self,
        rp: &RelyingParty,
        user_id: &str,
        session_id: &str,
        name: &str,
        resp: &RegistrationResponse,
    ) -> Result<PasskeyInfo> {
        let session = self.session_hash(session_id);
        let (reg, _) = self.verify_registration_response(
            rp,
            resp,
            |p| matches!(p, Purpose::Enrol { user_id: u, session: s } if u == user_id && s == &session),
            "passkey_enrol_failure",
            Some(user_id),
        )?;
        self.tx(|tx| {
            find_user(tx, user_id)?.filter(|u| u.status == UserStatus::Active).ok_or(AccountError::NoSuchUser)?;
            self.insert_passkey(tx, user_id, Some(name), &reg, &resp.transports)
        })
    }

    pub fn rename_passkey(&self, user_id: &str, passkey_id: &str, name: &str) -> Result<()> {
        let name =
            clean_name(name).ok_or(AccountError::InvalidArgument("the name must be 1 to 64 printable characters"))?;
        self.tx(|tx| {
            let n = tx.execute(
                "UPDATE credentials SET label = ?1 WHERE id = ?2 AND user_id = ?3 AND kind = 'passkey'",
                rusqlite::params![name, passkey_id, user_id],
            )?;
            if n == 0 {
                return Err(AccountError::NoSuchPasskey);
            }
            self.audit(tx, "passkey_renamed", Some(user_id), &format!("user:{user_id}"), None, passkey_id)
        })
    }

    /// Removes a passkey and ends the user's other sessions (`keep_session` is the one making the request).
    ///
    /// Refused, so no account locks itself out: when it is the account's **last** passkey and the server requires a
    /// passkey (`LastPasskey`), or when nothing else would let the account sign in, i.e. it has no password with an
    /// authenticator behind it (`SecondFactorRequired` for an account that must have a second factor, which is every
    /// owner and server admin; `LastPasskey` for a passkey-only account).
    pub fn remove_passkey(&self, user_id: &str, passkey_id: &str, keep_session: Option<&str>) -> Result<()> {
        let keep = keep_session.map(|s| self.session_hash(s));
        self.tx(|tx| {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM credentials WHERE id = ?1 AND user_id = ?2 AND kind = 'passkey')",
                [passkey_id, user_id],
                |r| r.get(0),
            )?;
            if !exists {
                return Err(AccountError::NoSuchPasskey);
            }
            if self.passkey_count_in(tx, user_id)? <= 1 {
                if self.passkey_required_in(tx)? {
                    return Err(AccountError::LastPasskey);
                }
                let has_password: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE user_id = ?1 AND kind = 'password')",
                    [user_id],
                    |r| r.get(0),
                )?;
                let password_route =
                    has_password && (self.totp_enabled(tx, user_id)? || !self.requires_second_factor(tx, user_id)?);
                if !password_route {
                    return Err(if has_password {
                        AccountError::SecondFactorRequired
                    } else {
                        AccountError::LastPasskey
                    });
                }
            }
            tx.execute("DELETE FROM credentials WHERE id = ?1 AND user_id = ?2", [passkey_id, user_id])?;
            Self::revoke_sessions_in(tx, user_id, keep.as_deref(), "passkey_removed", self.now())?;
            self.audit(tx, "passkey_removed", Some(user_id), &format!("user:{user_id}"), None, passkey_id)
        })
    }

    // ---- signing in ------------------------------------------------------------------------------------------

    /// Options for `navigator.credentials.get()`. With a `username`: the user's credentials (or decoys, see the
    /// module doc). Without: usernameless, an empty list, and the authenticator offers its discoverable passkeys.
    pub fn passkey_begin_login(&self, rp: &RelyingParty, username: Option<&str>, client: &ClientInfo) -> Result<Value> {
        let claimed = username.map(str::trim).filter(|u| !u.is_empty());
        let akey = claimed.map(|c| self.account_key(c));
        self.check_throttle(akey.as_deref(), client)?;
        let (allow, expected_user) = match claimed {
            None => (Vec::new(), None),
            Some(name) => {
                let found = match normalise_username(name) {
                    Ok(n) => {
                        let conn = self.conn();
                        match find_user_by_name(&conn, &n)?.filter(|u| u.status == UserStatus::Active) {
                            Some(u) => {
                                let ids = self.credential_ids(&conn, &u.id)?;
                                (!ids.is_empty()).then_some((u.id, ids))
                            }
                            None => None,
                        }
                    }
                    Err(_) => None,
                };
                match found {
                    Some((id, ids)) => (ids, Some(id)),
                    None => (self.decoy_ids(name), None),
                }
            }
        };
        let challenge = self.issue(Purpose::Login { claimed: claimed.map(str::to_string), expected_user })?;
        Ok(request_options(rp, &challenge, &allow, self.timeout_ms()))
    }

    /// 1 to 3 plausible credential ids for a name that has none, the same ones every time.
    fn decoy_ids(&self, claimed: &str) -> Vec<Vec<u8>> {
        let canon = clip(claimed.trim(), 256).to_lowercase();
        let seed = Self::mac(&self.keys.decoy, canon.as_bytes());
        let n = 1 + usize::from(seed[0]) % 3;
        (0..n)
            .map(|i| {
                let mut m = seed.clone();
                m.push(u8::try_from(i).unwrap_or(0));
                Self::mac(&self.keys.decoy, &m)
            })
            .collect()
    }

    fn passkey_failure(
        &self,
        account_key: Option<&str>,
        client: &ClientInfo,
        user_id: Option<&str>,
        reason: &str,
    ) -> Result<AccountError> {
        self.record_failure(account_key, client, "passkey_failure", user_id, reason)?;
        Ok(AccountError::InvalidCredentials)
    }

    /// Finishes a sign-in with the response of `navigator.credentials.get()`; on success the session is made like a
    /// password sign-in's. Every refusal is `InvalidCredentials` (the reason goes to the security log), after the same
    /// bookkeeping.
    pub fn passkey_finish_login(
        &self,
        rp: &RelyingParty,
        resp: &AssertionResponse,
        client: &ClientInfo,
    ) -> Result<LoginSuccess> {
        let decoded = (|| {
            Some((
                decode_field(&resp.id, 1023)?,
                decode_field(&resp.client_data_json, 8 * 1024)?,
                decode_field(&resp.authenticator_data, 16 * 1024)?,
                decode_field(&resp.signature, 1024)?,
                match &resp.user_handle {
                    Some(h) => Some(decode_field(h, 64)?),
                    None => None,
                },
            ))
        })();
        let Some((cred_id, client_data, auth_data, signature, handle)) = decoded else {
            self.check_throttle(None, client)?;
            return Err(self.passkey_failure(None, client, None, "malformed")?);
        };
        let purpose = client_data_challenge(&client_data).and_then(|c| self.ceremonies.take(self.now(), &c));
        let (claimed, expected_user) = match purpose {
            Some(Purpose::Login { claimed, expected_user }) => (claimed, expected_user),
            _ => {
                self.check_throttle(None, client)?;
                return Err(self.passkey_failure(None, client, None, "unknown or used challenge")?);
            }
        };
        let akey = claimed.as_deref().map(|c| self.account_key(c));
        self.check_throttle(akey.as_deref(), client)?;
        // A name that had no passkey when the options were asked for is a failure whatever follows.
        if claimed.is_some() && expected_user.is_none() {
            return Err(self.passkey_failure(akey.as_deref(), client, None, "no passkey for that name")?);
        }
        let (row, user) = {
            let conn = self.conn();
            let Some(row) = self.find_by_credential_id(&conn, &cred_id)? else {
                drop(conn);
                return Err(self.passkey_failure(akey.as_deref(), client, None, "unknown credential")?);
            };
            let user = find_user(&conn, &row.user_id)?;
            (row, user)
        };
        let Some(user) = user.filter(|u| u.status == UserStatus::Active) else {
            return Err(self.passkey_failure(akey.as_deref(), client, Some(&row.user_id), "user not active")?);
        };
        // The key for throttling once the account is known: the same one a password attempt would have used.
        let akey = akey.or_else(|| Some(self.account_key(&user.username)));
        if expected_user.as_deref().is_some_and(|u| u != user.id) {
            return Err(self.passkey_failure(akey.as_deref(), client, Some(&user.id), "credential of another user")?);
        }
        if handle.as_deref().is_some_and(|h| !ct_eq(h, &user_handle(&user.id))) {
            return Err(self.passkey_failure(akey.as_deref(), client, Some(&user.id), "user handle mismatch")?);
        }
        let challenge = client_data_challenge(&client_data).unwrap_or_default();
        let assertion =
            match webauthn::verify_assertion(rp, &challenge, &client_data, &auth_data, &signature, &row.cose) {
                Ok(a) => a,
                Err(e) => return Err(self.passkey_failure(akey.as_deref(), client, Some(&user.id), e.code())?),
            };
        if !counter_allows(row.counter, assertion.sign_count) {
            self.record_failure(
                akey.as_deref(),
                client,
                "passkey_clone_suspected",
                Some(&user.id),
                &format!("sign count {} not above {} (credential {})", assertion.sign_count, row.counter, row.id),
            )?;
            return Err(AccountError::InvalidCredentials);
        }
        let mut meta = row.meta;
        meta.backup_eligible = assertion.backup_eligible;
        meta.backup_state = assertion.backup_state;
        let meta_json = serde_json::to_string(&meta).map_err(|e| AccountError::Internal(e.to_string()))?;
        self.tx(|tx| {
            // Conditional, so two sign-ins that race with one counter cannot both move it (the loser's counter is no
            // longer above the stored one at the next attempt, which is what the policy above catches).
            tx.execute(
                "UPDATE credentials SET counter = ?1, last_used_at = ?2, meta = ?3 WHERE id = ?4",
                rusqlite::params![i64::from(assertion.sign_count), self.now(), meta_json, row.id],
            )?;
            self.complete_login(tx, user, "passkey", client)
        })
    }

    // ---- accounts made with a passkey -----------------------------------------------------------------------

    fn begin_account(
        &self,
        rp: &RelyingParty,
        route: AccountRoute,
        token: &str,
        username: &str,
        display_name: &str,
        client: &ClientInfo,
    ) -> Result<Value> {
        self.check_throttle(None, client)?;
        let usable = match route {
            AccountRoute::Setup => self.setup_token_usable(&self.conn(), token)?,
            AccountRoute::Invite => self.invite_usable(&self.conn(), token)?,
        };
        if !usable {
            let (kind, detail, err) = match route {
                AccountRoute::Setup => ("setup_failure", "bad setup token", AccountError::InvalidSetupToken),
                AccountRoute::Invite => ("invite_failure", "bad invite", AccountError::InvalidInvite),
            };
            self.record_failure(None, client, kind, None, detail)?;
            return Err(err);
        }
        let username = normalise_username(username)?;
        if find_user_by_name(&self.conn(), &username)?.is_some() {
            return Err(AccountError::UsernameTaken);
        }
        let display = match clip(display_name.trim(), 100) {
            d if d.is_empty() => username.clone(),
            d => d,
        };
        let user_id = new_id("u_")?;
        let handle = user_handle(&user_id);
        let challenge = self.issue(Purpose::Account {
            route,
            token_hash: Self::mac(&self.keys.token, token.as_bytes()),
            username: username.clone(),
            display_name: display.clone(),
            user_id,
        })?;
        Ok(creation_options(rp, &challenge, &handle, &username, &display, &[], self.timeout_ms()))
    }

    /// First step of setup with a passkey: checks the one-time setup token (without using it) and the username, and
    /// returns the options. The token is used up, and the account made, only when the registration verifies.
    pub fn passkey_begin_setup(
        &self,
        rp: &RelyingParty,
        setup_token: &str,
        username: &str,
        display_name: &str,
        client: &ClientInfo,
    ) -> Result<Value> {
        self.begin_account(rp, AccountRoute::Setup, setup_token, username, display_name, client)
    }

    /// Accepting an invite with a passkey instead of a password (first step).
    pub fn passkey_begin_invite(
        &self,
        rp: &RelyingParty,
        invite_token: &str,
        username: &str,
        display_name: &str,
        client: &ClientInfo,
    ) -> Result<Value> {
        self.begin_account(rp, AccountRoute::Invite, invite_token, username, display_name, client)
    }

    fn finish_account(
        &self,
        rp: &RelyingParty,
        route: AccountRoute,
        name: &str,
        resp: &RegistrationResponse,
        owner_of: Option<&str>,
        client: &ClientInfo,
    ) -> Result<LoginSuccess> {
        self.check_throttle(None, client)?;
        let (reg, purpose) = self.verify_registration_response(
            rp,
            resp,
            |p| matches!(p, Purpose::Account { route: r, .. } if *r == route),
            "passkey_enrol_failure",
            None,
        )?;
        let Purpose::Account { token_hash, username, display_name, user_id, .. } = purpose else {
            return Err(AccountError::PasskeyRefused("this passkey request was not started for this action"));
        };
        self.tx(|tx| {
            let acct = NewAccount { username: &username, display_name: &display_name, id: Some(user_id.clone()), phc: None };
            let user = match route {
                AccountRoute::Setup => self.finish_setup_in(tx, &token_hash, acct, client)?,
                AccountRoute::Invite => self.finish_invite_in(tx, &token_hash, acct, client)?,
            };
            // The owner of the served project (setup) is made in the same transaction as the account.
            if let Some(project) = owner_of {
                tx.execute(
                    "INSERT INTO memberships (project_id, user_id, role, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5) \
                     ON CONFLICT(project_id, user_id) DO UPDATE SET role = ?3",
                    rusqlite::params![project, user.id, Role::Owner.as_str(), self.now(), user.id],
                )?;
                self.audit(tx, "role_set", Some(&user.id), &format!("user:{}", user.id), None, &format!("{project} owner"))?;
            }
            self.insert_passkey(tx, &user.id, Some(name), &reg, &resp.transports)?;
            self.complete_login(tx, user, "passkey", client)
        })
    }

    /// Finishes setup with a passkey: verifies the registration, burns the setup token, creates the owner account
    /// (server admin, no password) with the passkey and, when `project_id` is given, makes it that project's owner;
    /// then signs it in. A passkey with user verification is a complete sign-in, so there is no further step.
    pub fn passkey_finish_setup(
        &self,
        rp: &RelyingParty,
        name: &str,
        resp: &RegistrationResponse,
        project_id: Option<&str>,
        client: &ClientInfo,
    ) -> Result<LoginSuccess> {
        self.finish_account(rp, AccountRoute::Setup, name, resp, project_id, client)
    }

    /// Finishes accepting an invite with a passkey.
    pub fn passkey_finish_invite(
        &self,
        rp: &RelyingParty,
        name: &str,
        resp: &RegistrationResponse,
        client: &ClientInfo,
    ) -> Result<LoginSuccess> {
        self.finish_account(rp, AccountRoute::Invite, name, resp, None, client)
    }

    // ---- recovery: the one-time enrolment link ---------------------------------------------------------------

    /// An owner's or administrator's recovery for someone who lost every way to sign in: a **one-time link**, valid
    /// for `setup_token_ttl` (an hour), that replaces how the account signs in. Issuing it ends the user's sessions
    /// and revokes their tokens (they work again only once the user has signed in and been issued new ones: a revoked
    /// token stays revoked) and is in the security log.
    ///
    /// Who may: an active **server administrator** for any other account; an **owner of `project_id`** for a member of
    /// that project who is neither an owner nor a server administrator (a project owner must not be able to take over
    /// a peer's or an administrator's account). Never for oneself. Replaces any earlier unused link for the user.
    pub fn create_enrolment_link(
        &self,
        acting: &str,
        target: &str,
        project_id: Option<&str>,
    ) -> Result<NewEnrolmentLink> {
        self.tx(|tx| {
            let actor = find_user(tx, acting)?.filter(|u| u.status == UserStatus::Active).ok_or(AccountError::NotAuthorised)?;
            let user = find_user(tx, target)?.ok_or(AccountError::NoSuchUser)?;
            if user.id == actor.id {
                return Err(AccountError::InvalidArgument("use your account page to change how you sign in"));
            }
            if !actor.server_admin {
                let project = project_id.ok_or(AccountError::NotAuthorised)?;
                let role: Option<String> = tx
                    .query_row(
                        "SELECT role FROM memberships WHERE project_id = ?1 AND user_id = ?2",
                        [project, target],
                        |r| r.get(0),
                    )
                    .optional()?;
                let allowed = Self::is_project_owner(tx, &actor.id, project)?
                    && role.as_deref().is_some_and(|r| r != "owner")
                    && !user.server_admin;
                if !allowed {
                    return Err(AccountError::NotAuthorised);
                }
            }
            let now = self.now();
            let expires_at = now.saturating_add(crate::store::secs(self.cfg.setup_token_ttl));
            let token = format!("pmenr_{}", hex(&random::<32>()?));
            let id = new_id("e_")?;
            tx.execute(
                "UPDATE enrolment_links SET revoked_at = ?1 WHERE user_id = ?2 AND used_at IS NULL AND revoked_at IS NULL",
                rusqlite::params![now, target],
            )?;
            tx.execute(
                "INSERT INTO enrolment_links (id, token_hash, user_id, created_by, created_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, Self::mac(&self.keys.token, token.as_bytes()), target, acting, now, expires_at],
            )?;
            tx.execute("DELETE FROM pending_logins WHERE user_id = ?1", [target])?;
            Self::revoke_sessions_in(tx, target, None, "enrolment_link", now)?;
            self.revoke_tokens_in(tx, target, None, "enrolment_link", now)?;
            self.audit(tx, "enrolment_link_created", Some(target), &format!("user:{acting}"), None, &id)?;
            Ok(NewEnrolmentLink { id, token: crate::Secret(token), expires_at })
        })
    }

    fn link_row(&self, conn: &Connection, token: &str) -> Result<Option<(String, String, i64)>> {
        Ok(conn
            .query_row(
                "SELECT l.id, l.user_id, l.expires_at FROM enrolment_links l JOIN users u ON u.id = l.user_id \
                 WHERE l.token_hash = ?1 AND l.used_at IS NULL AND l.revoked_at IS NULL AND l.expires_at > ?2 \
                 AND u.status = 'active'",
                rusqlite::params![Self::mac(&self.keys.token, token.as_bytes()), self.now()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?)
    }

    /// Whom a link is for, if it is still usable (a bad one counts as a failure against the address).
    pub fn enrolment_link_target(&self, token: &str, client: &ClientInfo) -> Result<EnrolmentTarget> {
        self.check_throttle(None, client)?;
        let found = {
            let conn = self.conn();
            match self.link_row(&conn, token)? {
                Some((_, user_id, expires_at)) => find_user(&conn, &user_id)?.map(|u| (u, expires_at)),
                None => None,
            }
        };
        match found {
            Some((u, expires_at)) => {
                Ok(EnrolmentTarget { username: u.username, display_name: u.display_name, expires_at })
            }
            None => {
                self.record_failure(None, client, "enrolment_link_failure", None, "bad link")?;
                Err(AccountError::InvalidEnrolmentLink)
            }
        }
    }

    /// First step of redeeming a link with a passkey: the options. The link is used up when the registration verifies.
    pub fn passkey_begin_link(&self, rp: &RelyingParty, token: &str, client: &ClientInfo) -> Result<Value> {
        let target = self.enrolment_link_target(token, client)?;
        let user = self.get_user_by_username(&target.username)?.ok_or(AccountError::InvalidEnrolmentLink)?;
        let handle = user_handle(&user.id);
        let challenge = self.issue(Purpose::Link {
            token_hash: Self::mac(&self.keys.token, token.as_bytes()),
            user_id: user.id.clone(),
        })?;
        Ok(creation_options(rp, &challenge, &handle, &user.username, &user.display_name, &[], self.timeout_ms()))
    }

    /// Removes how an account signed in before (password, authenticator, recovery codes, passkeys, linked identity-provider
    /// accounts: a recovery must also cut off whoever got in through one), for a link.
    fn wipe_sign_in(&self, tx: &Transaction<'_>, user_id: &str) -> Result<()> {
        tx.execute(
            "DELETE FROM credentials WHERE user_id = ?1 AND kind IN ('password', 'totp', 'passkey', 'oidc')",
            [user_id],
        )?;
        tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
        tx.execute("DELETE FROM pending_logins WHERE user_id = ?1", [user_id])?;
        let now = self.now();
        Self::revoke_sessions_in(tx, user_id, None, "enrolment_link", now)?;
        self.revoke_tokens_in(tx, user_id, None, "enrolment_link", now)?;
        Ok(())
    }

    /// Burns the link for `user_id` (single use; a conditional update, so two redemptions cannot both win).
    fn burn_link(&self, tx: &Transaction<'_>, token_hash: &[u8], user_id: &str) -> Result<String> {
        let id: Option<String> = tx
            .query_row(
                "SELECT id FROM enrolment_links WHERE token_hash = ?1 AND user_id = ?2 AND used_at IS NULL \
                 AND revoked_at IS NULL AND expires_at > ?3",
                rusqlite::params![token_hash, user_id, self.now()],
                |r| r.get(0),
            )
            .optional()?;
        let id = id.ok_or(AccountError::InvalidEnrolmentLink)?;
        let n = tx.execute(
            "UPDATE enrolment_links SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL",
            rusqlite::params![self.now(), id],
        )?;
        if n != 1 {
            return Err(AccountError::InvalidEnrolmentLink);
        }
        Ok(id)
    }

    /// Finishes a link redemption with a passkey: the link is used up, every earlier way to sign in is removed, the
    /// passkey is stored and the person is signed in.
    pub fn passkey_finish_link(
        &self,
        rp: &RelyingParty,
        name: &str,
        resp: &RegistrationResponse,
        client: &ClientInfo,
    ) -> Result<LoginSuccess> {
        self.check_throttle(None, client)?;
        let (reg, purpose) = self.verify_registration_response(
            rp,
            resp,
            |p| matches!(p, Purpose::Link { .. }),
            "passkey_enrol_failure",
            None,
        )?;
        let Purpose::Link { token_hash, user_id, .. } = purpose else {
            return Err(AccountError::PasskeyRefused("this passkey request was not started for this action"));
        };
        self.tx(|tx| {
            let user = find_user(tx, &user_id)?
                .filter(|u| u.status == UserStatus::Active)
                .ok_or(AccountError::InvalidEnrolmentLink)?;
            let link = self.burn_link(tx, &token_hash, &user_id)?;
            self.wipe_sign_in(tx, &user_id)?;
            self.insert_passkey(tx, &user_id, Some(name), &reg, &resp.transports)?;
            self.audit(
                tx,
                "enrolment_link_used",
                Some(&user_id),
                "anonymous",
                client.addr.as_deref(),
                &format!("{link} passkey"),
            )?;
            self.complete_login(tx, user, "passkey", client)
        })
    }

    /// Redeems a link by choosing a new password: the link is used up, every earlier way to sign in is removed, the
    /// password is set, and the answer is `EnrolmentRequired` (an authenticator must follow, as after an invite).
    pub fn redeem_link_with_password(
        &self,
        token: &str,
        new_password: &str,
        client: &ClientInfo,
    ) -> Result<crate::LoginStep> {
        let target = self.enrolment_link_target(token, client)?;
        crate::password::check_policy(new_password, &target.username)?;
        let phc = self.hash_password(new_password)?;
        let hash = Self::mac(&self.keys.token, token.as_bytes());
        let user = self.tx(|tx| {
            let user_id = self.link_row(tx, token)?.map(|(_, u, _)| u).ok_or(AccountError::InvalidEnrolmentLink)?;
            let user = find_user(tx, &user_id)?.ok_or(AccountError::InvalidEnrolmentLink)?;
            let link = self.burn_link(tx, &hash, &user_id)?;
            self.wipe_sign_in(tx, &user_id)?;
            tx.execute(
                "INSERT INTO credentials (id, user_id, kind, secret, created_at) VALUES (?1, ?2, 'password', ?3, ?4)",
                rusqlite::params![new_id("c_")?, user_id, phc.as_bytes(), self.now()],
            )?;
            self.audit(
                tx,
                "enrolment_link_used",
                Some(&user_id),
                "anonymous",
                client.addr.as_deref(),
                &format!("{link} password"),
            )?;
            Ok(user)
        })?;
        let (pending, expires_at) = self.create_pending(&user.id, "enrol", client)?;
        Ok(crate::LoginStep::EnrolmentRequired { pending, expires_at })
    }

    // ---- the server setting ----------------------------------------------------------------------------------

    pub(crate) fn passkey_required_in(&self, conn: &Connection) -> Result<bool> {
        let v: Option<String> = conn
            .query_row("SELECT value FROM server_settings WHERE key = 'require_passkey'", [], |r| r.get(0))
            .optional()?;
        Ok(v.as_deref() == Some("1"))
    }

    /// "Require a passkey" is on: every account must have one (see `docs/server-mode.md`).
    pub fn passkey_required(&self) -> Result<bool> {
        self.passkey_required_in(&self.conn())
    }

    /// Turns "require a passkey" on or off. Only an active server administrator; turning it on needs a passkey on the
    /// administrator's own account (so the setting cannot lock the person who sets it out).
    pub fn set_passkey_required(&self, acting: &str, on: bool) -> Result<()> {
        self.tx(|tx| {
            Self::require_admin(tx, acting)?;
            if on && !self.has_passkey(tx, acting)? {
                return Err(AccountError::InvalidArgument("enrol a passkey on your own account before requiring them"));
            }
            tx.execute(
                "INSERT INTO server_settings (key, value, updated_at, updated_by) VALUES ('require_passkey', ?1, ?2, ?3) \
                 ON CONFLICT(key) DO UPDATE SET value = ?1, updated_at = ?2, updated_by = ?3",
                rusqlite::params![if on { "1" } else { "0" }, self.now(), acting],
            )?;
            self.audit(
                tx,
                if on { "passkey_required_on" } else { "passkey_required_off" },
                Some(acting),
                &format!("user:{acting}"),
                None,
                "",
            )
        })
    }
}
