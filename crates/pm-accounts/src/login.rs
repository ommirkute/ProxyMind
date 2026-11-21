//! Signing in: the password step, the second factor (TOTP or a recovery code), enrolment, and the credentials behind
//! them.
//!
//! * **Unknown users.** A handle that does not exist, a disabled user and a user without a password all go through one
//!   Argon2 verification of a dummy hash at the current cost and end in the same `InvalidCredentials` after the same
//!   throttle bookkeeping; a counter ([`Accounts::dummy_verifications`]) lets tests assert that the path ran.
//! * **TOTP replay.** A code is accepted for the current step and one on either side, but only for a step later than
//!   the last accepted one (`credentials.counter`, advanced by a conditional `UPDATE`, so two concurrent uses of one
//!   code cannot both win).
//! * **Second factor policy.** Owners, server admins and testers always need one; so does everyone unless
//!   `allow_password_only_viewers`. An account that needs one and has none gets `EnrolmentRequired` after a correct
//!   password, and enrols with the pending token before it has a session.

use rusqlite::{Connection, OptionalExtension};

use crate::error::{AccountError, Result};
use crate::model::{ClientInfo, LoginStep, LoginSuccess, TotpEnrolment, User, UserStatus};
use crate::password;
use crate::store::{Accounts, secs};
use crate::totp::{match_step, normalise_code, otpauth_uri};
use crate::users::{find_user, find_user_by_name, normalise_username, password_phc};
use crate::util::{Secret, base32, clip, hex, random};

const RECOVERY_CODES: usize = 10;

pub(crate) fn totp_aad(user_id: &str) -> Vec<u8> {
    format!("proxymind/totp/v1/{user_id}").into_bytes()
}

/// `ABCD-EFGH-IJKL-MNOP` from 80 random bits.
fn new_recovery_code() -> Result<String> {
    let b32 = base32(&random::<10>()?);
    Ok(format!("{}-{}-{}-{}", &b32[0..4], &b32[4..8], &b32[8..12], &b32[12..16]))
}

/// Upper case, no dashes or spaces; `None` unless it can be a recovery code.
fn normalise_recovery(input: &str) -> Option<String> {
    let s: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect::<String>().to_ascii_uppercase();
    (s.len() == 16 && s.bytes().all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))).then_some(s)
}

/// Only claimed handles that look like handles go to the log (people sometimes type a password into that field).
fn loggable_handle(claimed: &str) -> String {
    match normalise_username(claimed) {
        Ok(h) => format!("handle {h}"),
        Err(_) => "handle not valid".into(),
    }
}

impl Accounts {
    // ---- the password step -----------------------------------------------------------------------------------

    pub fn login_password(&self, username: &str, password: &str, client: &ClientInfo) -> Result<LoginStep> {
        let akey = self.account_key(username);
        self.check_throttle(Some(&akey), client)?;
        let found = match normalise_username(username) {
            Ok(name) => {
                let conn = self.conn();
                match find_user_by_name(&conn, &name)? {
                    Some(u) => {
                        let phc = password_phc(&conn, &u.id)?;
                        Some((u, phc))
                    }
                    None => None,
                }
            }
            Err(_) => None,
        };
        let known_id = found.as_ref().map(|(u, _)| u.id.clone());
        // One verification on every path; `None` verifies the dummy hash.
        let ok = self.verify_password(found.as_ref().and_then(|(_, p)| p.as_deref()), password);
        let (user, phc) = match found {
            Some((u, Some(phc))) if ok && u.status == UserStatus::Active => (u, phc),
            _ => {
                self.record_failure(
                    Some(&akey),
                    client,
                    "login_failure",
                    known_id.as_deref(),
                    &loggable_handle(username),
                )?;
                return Err(AccountError::InvalidCredentials);
            }
        };
        // Upgrade the stored hash to the current cost. Only replaces the hash that was just verified.
        if password::needs_rehash(&phc, self.cfg.argon2) {
            let upgraded = self.hash_password(password)?;
            self.tx(|tx| {
                tx.execute(
                    "UPDATE credentials SET secret = ?1 WHERE user_id = ?2 AND kind = 'password' AND secret = ?3",
                    rusqlite::params![upgraded.as_bytes(), user.id, phc.as_bytes()],
                )?;
                self.audit(tx, "password_rehashed", Some(&user.id), &format!("user:{}", user.id), None, "")
            })?;
        }
        let (has_totp, needs_factor) = {
            let conn = self.conn();
            (self.totp_enabled(&conn, &user.id)?, self.requires_second_factor(&conn, &user.id)?)
        };
        if has_totp {
            let (pending, expires_at) = self.create_pending(&user.id, "second_factor", client)?;
            return Ok(LoginStep::SecondFactorRequired { pending, expires_at });
        }
        if needs_factor {
            let (pending, expires_at) = self.create_pending(&user.id, "enrol", client)?;
            return Ok(LoginStep::EnrolmentRequired { pending, expires_at });
        }
        let success = self.tx(|tx| self.complete_login(tx, user, "password", client))?;
        Ok(LoginStep::Authenticated(Box::new(success)))
    }

    fn complete_login(&self, tx: &Connection, user: User, method: &str, client: &ClientInfo) -> Result<LoginSuccess> {
        let now = self.now();
        let session = self.insert_session(
            tx,
            &user.id,
            method,
            crate::sessions::Carry { authenticated_at: now, absolute: None, rotated_from: None },
            client,
        )?;
        tx.execute("UPDATE users SET last_login_at = ?1 WHERE id = ?2", rusqlite::params![now, user.id])?;
        tx.execute(
            "UPDATE credentials SET last_used_at = ?1 WHERE user_id = ?2 AND kind = 'password'",
            rusqlite::params![now, user.id],
        )?;
        self.reset_account_throttle(tx, &self.account_key(&user.username))?;
        self.audit(tx, "login_success", Some(&user.id), &format!("user:{}", user.id), client.addr.as_deref(), method)?;
        Ok(LoginSuccess { user: User { last_login_at: Some(now), ..user }, session })
    }

    // ---- pending sign-ins ------------------------------------------------------------------------------------

    fn create_pending(&self, user_id: &str, purpose: &str, client: &ClientInfo) -> Result<(Secret, i64)> {
        let now = self.now();
        let expires_at = now.saturating_add(secs(self.cfg.pending_ttl));
        let token = hex(&random::<32>()?);
        self.tx(|tx| {
            // One open sign-in per user and purpose: a new password step replaces the last.
            tx.execute("DELETE FROM pending_logins WHERE user_id = ?1 AND purpose = ?2", [user_id, purpose])?;
            tx.execute(
                "INSERT INTO pending_logins (id_hash, user_id, purpose, created_at, expires_at, client_addr) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    self.session_hash(&token),
                    user_id,
                    purpose,
                    now,
                    expires_at,
                    client.addr.as_deref().map(|a| clip(a, 64))
                ],
            )?;
            Ok(())
        })?;
        Ok((Secret(token), expires_at))
    }

    /// The user behind a live pending token of `purpose` (not expired, attempts left), with its hash.
    fn pending_user(&self, conn: &Connection, token: &str, purpose: &str) -> Result<(Vec<u8>, User)> {
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AccountError::InvalidPending);
        }
        let hash = self.session_hash(token);
        let user_id: Option<String> = conn
            .query_row(
                "SELECT user_id FROM pending_logins WHERE id_hash = ?1 AND purpose = ?2 AND expires_at > ?3 \
                 AND attempts < ?4",
                rusqlite::params![hash, purpose, self.now(), self.cfg.pending_max_attempts],
                |r| r.get(0),
            )
            .optional()?;
        let user = user_id
            .and_then(|id| find_user(conn, &id).transpose())
            .transpose()?
            .filter(|u| u.status == UserStatus::Active)
            .ok_or(AccountError::InvalidPending)?;
        Ok((hash, user))
    }

    /// Uses up one of the pending sign-in's attempts before the code is looked at, so parallel guesses cannot exceed it.
    fn spend_attempt(&self, hash: &[u8]) -> Result<()> {
        let n = self.conn().execute(
            "UPDATE pending_logins SET attempts = attempts + 1 WHERE id_hash = ?1 AND attempts < ?2 AND expires_at > ?3",
            rusqlite::params![hash, self.cfg.pending_max_attempts, self.now()],
        )?;
        if n == 1 { Ok(()) } else { Err(AccountError::InvalidPending) }
    }

    // ---- the second factor -----------------------------------------------------------------------------------

    /// Finishes a sign-in that returned `SecondFactorRequired`. `code` is a six-digit TOTP code or a recovery code.
    /// A wrong code counts against the account and the address and against the token's five attempts.
    pub fn login_second_factor(&self, pending: &str, code: &str, client: &ClientInfo) -> Result<LoginSuccess> {
        let (hash, user) = self.pending_user(&self.conn(), pending, "second_factor")?;
        let akey = self.account_key(&user.username);
        self.check_throttle(Some(&akey), client)?;
        self.spend_attempt(&hash)?;
        let method = if normalise_code(code).is_some() {
            self.totp_accept(&user.id, code)?.then_some("password+totp")
        } else {
            self.use_recovery_code(&user.id, code)?.then_some("password+recovery")
        };
        let Some(method) = method else {
            self.record_failure(Some(&akey), client, "second_factor_failure", Some(&user.id), "wrong code")?;
            return Err(AccountError::InvalidCredentials);
        };
        self.tx(|tx| {
            tx.execute("DELETE FROM pending_logins WHERE id_hash = ?1", [&hash])?;
            if method == "password+recovery" {
                let left: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
                    [&user.id],
                    |r| r.get(0),
                )?;
                self.audit(
                    tx,
                    "recovery_code_used",
                    Some(&user.id),
                    &format!("user:{}", user.id),
                    None,
                    &format!("{left} left"),
                )?;
            }
            self.complete_login(tx, user, method, client)
        })
    }

    // ---- TOTP ------------------------------------------------------------------------------------------------

    pub(crate) fn totp_enabled(&self, conn: &Connection, user_id: &str) -> Result<bool> {
        Ok(conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM credentials WHERE user_id = ?1 AND kind = 'totp' AND enabled = 1)",
            [user_id],
            |r| r.get(0),
        )?)
    }

    fn begin_enrolment_in(&self, conn: &Connection, user_id: &str) -> Result<TotpEnrolment> {
        let user =
            find_user(conn, user_id)?.filter(|u| u.status == UserStatus::Active).ok_or(AccountError::NoSuchUser)?;
        if self.totp_enabled(conn, user_id)? {
            return Err(AccountError::AlreadyEnrolled);
        }
        let secret = random::<20>()?;
        let sealed = self.seal_secret(&secret, &totp_aad(user_id))?;
        conn.execute("DELETE FROM credentials WHERE user_id = ?1 AND kind = 'totp' AND enabled = 0", [user_id])?;
        conn.execute(
            "INSERT INTO credentials (id, user_id, kind, secret, enabled, created_at) VALUES (?1, ?2, 'totp', ?3, 0, ?4)",
            rusqlite::params![format!("c_{}", hex(&random::<16>()?)), user_id, sealed, self.now()],
        )?;
        self.audit(conn, "totp_enrolment_started", Some(user_id), &format!("user:{user_id}"), None, "")?;
        let secret_base32 = base32(&secret);
        let uri = otpauth_uri(&self.cfg.totp_issuer, &user.username, &secret_base32);
        Ok(TotpEnrolment { secret_base32, otpauth_uri: uri })
    }

    /// Starts enrolling TOTP for a signed-in user: a new secret (160 bits), stored encrypted and not yet active.
    /// Returns what the client renders as a QR code. Replaces an unconfirmed earlier attempt; refused when TOTP is
    /// already on. Whether this caller may enrol (a fresh sign-in, ADR-0022) is the layer above's decision.
    pub fn totp_begin_enrolment(&self, user_id: &str) -> Result<TotpEnrolment> {
        self.tx(|tx| self.begin_enrolment_in(tx, user_id))
    }

    fn confirm_in(&self, conn: &Connection, user_id: &str, code: &str) -> Result<()> {
        let row: Option<(String, Vec<u8>)> = conn
            .query_row(
                "SELECT id, secret FROM credentials WHERE user_id = ?1 AND kind = 'totp' AND enabled = 0",
                [user_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (id, sealed) = row.ok_or(AccountError::NotEnrolling)?;
        let secret = self.open_secret(&sealed, &totp_aad(user_id))?;
        let step = match_step(&secret, code, self.now()).ok_or(AccountError::InvalidCode)?;
        conn.execute(
            "UPDATE credentials SET enabled = 1, counter = ?1, last_used_at = ?2 WHERE id = ?3",
            rusqlite::params![step, self.now(), id],
        )?;
        self.audit(conn, "totp_enabled", Some(user_id), &format!("user:{user_id}"), None, "")?;
        Ok(())
    }

    /// Activates the enrolment started by `totp_begin_enrolment` when `code` is right. The step it used counts as
    /// used, so the same code cannot sign in afterwards.
    pub fn totp_confirm(&self, user_id: &str, code: &str) -> Result<()> {
        self.tx(|tx| self.confirm_in(tx, user_id, code))
    }

    /// Checks `code` against the active TOTP of the user, within one step either way, and **consumes its step**: a
    /// second call with the same code (or an older step's) returns `false`. Also the check for step-up.
    pub fn totp_verify(&self, user_id: &str, code: &str) -> Result<bool> {
        self.totp_accept(user_id, code)
    }

    fn totp_accept(&self, user_id: &str, code: &str) -> Result<bool> {
        let conn = self.conn();
        let row: Option<(String, Vec<u8>, i64)> = conn
            .query_row(
                "SELECT id, secret, counter FROM credentials WHERE user_id = ?1 AND kind = 'totp' AND enabled = 1",
                [user_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((id, sealed, _)) = row else { return Ok(false) };
        let secret = self.open_secret(&sealed, &totp_aad(user_id))?;
        let Some(step) = match_step(&secret, code, self.now()) else { return Ok(false) };
        let n = conn.execute(
            "UPDATE credentials SET counter = ?1, last_used_at = ?2 WHERE id = ?3 AND enabled = 1 AND counter < ?1",
            rusqlite::params![step, self.now(), id],
        )?;
        Ok(n == 1)
    }

    /// Turns TOTP off and ends the user's sessions. Refused (`SecondFactorRequired`) for an account that needs a second
    /// factor; an administrator removes one with [`reset_second_factor`](Self::reset_second_factor) instead.
    pub fn totp_disable(&self, user_id: &str) -> Result<()> {
        self.tx(|tx| {
            if self.requires_second_factor(tx, user_id)? {
                return Err(AccountError::SecondFactorRequired);
            }
            self.remove_second_factor(tx, user_id, user_id, "totp_disabled")
        })
    }

    fn remove_second_factor(&self, tx: &Connection, user_id: &str, acting: &str, kind: &str) -> Result<()> {
        tx.execute("DELETE FROM credentials WHERE user_id = ?1 AND kind = 'totp'", [user_id])?;
        tx.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
        tx.execute("DELETE FROM pending_logins WHERE user_id = ?1", [user_id])?;
        Self::revoke_sessions_in(tx, user_id, None, kind, self.now())?;
        self.audit(tx, kind, Some(user_id), &format!("user:{acting}"), None, "")
    }

    /// For a user who lost their factor and their recovery codes: an active server admin removes TOTP and recovery
    /// codes and ends the user's sessions. The user's next password sign-in is `EnrolmentRequired`.
    pub fn reset_second_factor(&self, acting: &str, target: &str) -> Result<()> {
        self.tx(|tx| {
            Self::require_admin(tx, acting)?;
            find_user(tx, target)?.ok_or(AccountError::NoSuchUser)?;
            self.remove_second_factor(tx, target, acting, "second_factor_reset")
        })
    }

    /// First enrolment during sign-in (`EnrolmentRequired`): returns the secret and URI for the pending user.
    pub fn begin_totp_enrolment_pending(&self, pending: &str) -> Result<TotpEnrolment> {
        self.tx(|tx| {
            let (_, user) = self.pending_user(tx, pending, "enrol")?;
            self.begin_enrolment_in(tx, &user.id)
        })
    }

    /// Completes the first enrolment: confirms the code, creates the recovery codes (shown once, returned here) and the
    /// session. A wrong code spends one of the token's attempts.
    pub fn finish_enrolment(
        &self,
        pending: &str,
        code: &str,
        client: &ClientInfo,
    ) -> Result<(LoginSuccess, Vec<String>)> {
        let (hash, user) = self.pending_user(&self.conn(), pending, "enrol")?;
        let akey = self.account_key(&user.username);
        self.check_throttle(Some(&akey), client)?;
        self.spend_attempt(&hash)?;
        let result = self.tx(|tx| {
            self.confirm_in(tx, &user.id, code)?;
            let codes = self.generate_codes_in(tx, &user.id)?;
            tx.execute("DELETE FROM pending_logins WHERE id_hash = ?1", [&hash])?;
            let success = self.complete_login(tx, user.clone(), "password+totp", client)?;
            Ok((success, codes))
        });
        if matches!(result, Err(AccountError::InvalidCode)) {
            self.record_failure(Some(&akey), client, "second_factor_failure", Some(&user.id), "wrong enrolment code")?;
        }
        result
    }

    // ---- recovery codes --------------------------------------------------------------------------------------

    fn generate_codes_in(&self, conn: &Connection, user_id: &str) -> Result<Vec<String>> {
        if !self.totp_enabled(conn, user_id)? {
            return Err(AccountError::NotEnrolling);
        }
        conn.execute("DELETE FROM recovery_codes WHERE user_id = ?1", [user_id])?;
        let mut codes = Vec::with_capacity(RECOVERY_CODES);
        for _ in 0..RECOVERY_CODES {
            let code = new_recovery_code()?;
            let norm = normalise_recovery(&code).unwrap_or_default();
            conn.execute(
                "INSERT INTO recovery_codes (user_id, code_hash, created_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![user_id, Self::mac(&self.keys.recovery, norm.as_bytes()), self.now()],
            )?;
            codes.push(code);
        }
        self.audit(conn, "recovery_codes_generated", Some(user_id), &format!("user:{user_id}"), None, "")?;
        Ok(codes)
    }

    /// Makes 10 new single-use codes (80 bits each, shown once, stored as HMAC-SHA256) and invalidates all earlier
    /// ones, used or not. Needs TOTP to be on. Whether this caller may (a fresh sign-in) is the layer above's decision.
    pub fn generate_recovery_codes(&self, user_id: &str) -> Result<Vec<String>> {
        self.tx(|tx| self.generate_codes_in(tx, user_id))
    }

    pub fn remaining_recovery_codes(&self, user_id: &str) -> Result<usize> {
        let n: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ?1 AND used_at IS NULL",
            [user_id],
            |r| r.get(0),
        )?;
        Ok(usize::try_from(n).unwrap_or(0))
    }

    /// True once per code. The conditional `UPDATE` makes concurrent uses of one code a single success.
    fn use_recovery_code(&self, user_id: &str, code: &str) -> Result<bool> {
        let Some(norm) = normalise_recovery(code) else { return Ok(false) };
        let n = self.conn().execute(
            "UPDATE recovery_codes SET used_at = ?1 WHERE user_id = ?2 AND code_hash = ?3 AND used_at IS NULL",
            rusqlite::params![self.now(), user_id, Self::mac(&self.keys.recovery, norm.as_bytes())],
        )?;
        Ok(n == 1)
    }
}
