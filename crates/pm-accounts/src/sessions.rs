//! Server-side sessions. The id is 32 random bytes (64 hex digits) returned once; the database holds only its
//! HMAC-SHA256 under the session key, so a copy of `server.db` cannot be replayed as cookies. Expiry is checked on every
//! validation: idle (reset by `touch_session`) and absolute (fixed at sign-in, kept through rotation).

use rusqlite::{Connection, OptionalExtension, Row};

use crate::error::{AccountError, Result};
use crate::model::{ClientInfo, NewSession, SessionInfo};
use crate::store::{Accounts, secs};
use crate::util::{Secret, clip, hex, random};

const COLS: &str = "s.id_hash, s.user_id, s.auth_method, s.created_at, s.authenticated_at, s.last_seen_at, \
                    s.idle_expires_at, s.absolute_expires_at, s.client_addr, s.user_agent";

fn reference(hash: &[u8]) -> String {
    hex(&hash[..8.min(hash.len())])
}

fn info_from_row(r: &Row<'_>) -> rusqlite::Result<SessionInfo> {
    let hash: Vec<u8> = r.get(0)?;
    Ok(SessionInfo {
        reference: reference(&hash),
        user_id: r.get(1)?,
        auth_method: r.get(2)?,
        created_at: r.get(3)?,
        authenticated_at: r.get(4)?,
        last_seen_at: r.get(5)?,
        idle_expires_at: r.get(6)?,
        absolute_expires_at: r.get(7)?,
        client_addr: r.get(8)?,
        user_agent: r.get(9)?,
    })
}

/// What a new session inherits from the one it replaces (nothing, at sign-in).
pub(crate) struct Carry<'a> {
    pub authenticated_at: i64,
    pub absolute: Option<i64>,
    pub rotated_from: Option<&'a [u8]>,
}

impl Accounts {
    pub(crate) fn session_hash(&self, id: &str) -> Vec<u8> {
        Self::mac(&self.keys.session, id.as_bytes())
    }

    fn well_formed(id: &str) -> bool {
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit())
    }

    /// A live session: not revoked, not past either expiry, and its user is active.
    fn live(&self, conn: &Connection, hash: &[u8]) -> Result<Option<SessionInfo>> {
        Ok(conn
            .query_row(
                &format!(
                    "SELECT {COLS} FROM sessions s JOIN users u ON u.id = s.user_id \
                     WHERE s.id_hash = ?1 AND s.revoked_at IS NULL AND u.status = 'active' \
                     AND s.idle_expires_at > ?2 AND s.absolute_expires_at > ?2"
                ),
                rusqlite::params![hash, self.now()],
                info_from_row,
            )
            .optional()?)
    }

    pub(crate) fn insert_session(
        &self,
        conn: &Connection,
        user_id: &str,
        method: &str,
        carry: Carry<'_>,
        client: &ClientInfo,
    ) -> Result<NewSession> {
        let Carry { authenticated_at, absolute, rotated_from } = carry;
        let now = self.now();
        let id = hex(&random::<32>()?);
        let hash = self.session_hash(&id);
        let absolute_expires_at = absolute.unwrap_or_else(|| now.saturating_add(secs(self.cfg.absolute_timeout)));
        let idle_expires_at = now.saturating_add(secs(self.cfg.idle_timeout)).min(absolute_expires_at);
        conn.execute(
            "INSERT INTO sessions (id_hash, user_id, auth_method, created_at, authenticated_at, last_seen_at, \
             idle_expires_at, absolute_expires_at, rotated_from, client_addr, user_agent) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?4, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                hash,
                user_id,
                method,
                now,
                authenticated_at,
                idle_expires_at,
                absolute_expires_at,
                rotated_from,
                client.addr.as_deref().map(|a| clip(a, 64)),
                client.user_agent.as_deref().map(|a| clip(a, 256)),
            ],
        )?;
        Ok(NewSession {
            id: Secret(id),
            reference: reference(&hash),
            user_id: user_id.to_string(),
            created_at: now,
            idle_expires_at,
            absolute_expires_at,
        })
    }

    /// Starts a session for an active user. For sign-in methods other than the ones in this crate (passkeys, OIDC).
    /// `auth_method` is recorded as given. Always a new id: a pre-login id is never promoted.
    pub fn create_session(&self, user_id: &str, auth_method: &str, client: &ClientInfo) -> Result<NewSession> {
        self.tx(|tx| {
            let active =
                crate::users::find_user(tx, user_id)?.is_some_and(|u| u.status == crate::model::UserStatus::Active);
            if !active {
                return Err(AccountError::NoSuchUser);
            }
            self.insert_session(
                tx,
                user_id,
                auth_method,
                Carry { authenticated_at: self.now(), absolute: None, rotated_from: None },
                client,
            )
        })
    }

    /// Checks the id and both expiries. Does not extend anything.
    pub fn validate_session(&self, id: &str) -> Result<SessionInfo> {
        if !Self::well_formed(id) {
            return Err(AccountError::SessionInvalid);
        }
        self.live(&self.conn(), &self.session_hash(id))?.ok_or(AccountError::SessionInvalid)
    }

    /// Validates and moves the idle expiry to `now + idle_timeout` (never past the absolute expiry).
    pub fn touch_session(&self, id: &str) -> Result<SessionInfo> {
        if !Self::well_formed(id) {
            return Err(AccountError::SessionInvalid);
        }
        let hash = self.session_hash(id);
        self.tx(|tx| {
            let info = self.live(tx, &hash)?.ok_or(AccountError::SessionInvalid)?;
            let now = self.now();
            let idle = now.saturating_add(secs(self.cfg.idle_timeout)).min(info.absolute_expires_at);
            tx.execute(
                "UPDATE sessions SET last_seen_at = ?1, idle_expires_at = ?2 WHERE id_hash = ?3",
                rusqlite::params![now, idle, hash],
            )?;
            Ok(SessionInfo { last_seen_at: now, idle_expires_at: idle, ..info })
        })
    }

    /// Gives the session a new id and invalidates the old one at once (no grace period). Use at login, after step-up,
    /// and when a user's role or credentials change. The absolute expiry and `authenticated_at` carry over.
    pub fn rotate_session(&self, id: &str, client: &ClientInfo) -> Result<NewSession> {
        if !Self::well_formed(id) {
            return Err(AccountError::SessionInvalid);
        }
        let old = self.session_hash(id);
        self.tx(|tx| {
            let info = self.live(tx, &old)?.ok_or(AccountError::SessionInvalid)?;
            tx.execute(
                "UPDATE sessions SET revoked_at = ?1, revoked_reason = 'rotated' WHERE id_hash = ?2",
                rusqlite::params![self.now(), old],
            )?;
            self.insert_session(
                tx,
                &info.user_id,
                &info.auth_method,
                Carry {
                    authenticated_at: info.authenticated_at,
                    absolute: Some(info.absolute_expires_at),
                    rotated_from: Some(&old),
                },
                client,
            )
        })
    }

    /// Ends one session (sign out). Unknown or already ended ids are not an error.
    pub fn revoke_session(&self, id: &str) -> Result<()> {
        if !Self::well_formed(id) {
            return Ok(());
        }
        let hash = self.session_hash(id);
        self.tx(|tx| {
            let user: Option<String> = tx
                .query_row("SELECT user_id FROM sessions WHERE id_hash = ?1 AND revoked_at IS NULL", [&hash], |r| {
                    r.get(0)
                })
                .optional()?;
            if let Some(user) = user {
                tx.execute(
                    "UPDATE sessions SET revoked_at = ?1, revoked_reason = 'signed_out' WHERE id_hash = ?2",
                    rusqlite::params![self.now(), hash],
                )?;
                self.audit(tx, "session_revoked", Some(&user), &format!("user:{user}"), None, &reference(&hash))?;
            }
            Ok(())
        })
    }

    /// Ends one of a user's sessions by its [`SessionInfo::reference`] (the session list). True when one was ended.
    pub fn revoke_session_ref(&self, user_id: &str, session_ref: &str) -> Result<bool> {
        self.tx(|tx| {
            let n = tx.execute(
                "UPDATE sessions SET revoked_at = ?1, revoked_reason = 'revoked' \
                 WHERE user_id = ?2 AND revoked_at IS NULL AND lower(hex(substr(id_hash, 1, 8))) = lower(?3)",
                rusqlite::params![self.now(), user_id, session_ref],
            )?;
            if n > 0 {
                self.audit(tx, "session_revoked", Some(user_id), &format!("user:{user_id}"), None, session_ref)?;
            }
            Ok(n > 0)
        })
    }

    /// Ends every session of a user, except `except` (an id) when given. Returns how many ended.
    pub fn revoke_all_sessions(&self, user_id: &str, except: Option<&str>) -> Result<usize> {
        let keep = except.map(|s| self.session_hash(s));
        self.tx(|tx| {
            let n = Self::revoke_sessions_in(tx, user_id, keep.as_deref(), "revoked_all", self.now())?;
            self.audit(tx, "sessions_revoked", Some(user_id), &format!("user:{user_id}"), None, &n.to_string())?;
            Ok(n)
        })
    }

    pub(crate) fn revoke_sessions_in(
        conn: &Connection,
        user_id: &str,
        except: Option<&[u8]>,
        reason: &str,
        now: i64,
    ) -> Result<usize> {
        let keep: &[u8] = except.unwrap_or(&[]);
        Ok(conn.execute(
            "UPDATE sessions SET revoked_at = ?1, revoked_reason = ?2 \
             WHERE user_id = ?3 AND revoked_at IS NULL AND id_hash != ?4",
            rusqlite::params![now, reason, user_id, keep],
        )?)
    }

    /// A user's live sessions, newest first.
    pub fn list_sessions(&self, user_id: &str) -> Result<Vec<SessionInfo>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLS} FROM sessions s WHERE s.user_id = ?1 AND s.revoked_at IS NULL \
             AND s.idle_expires_at > ?2 AND s.absolute_expires_at > ?2 ORDER BY s.created_at DESC, s.id_hash"
        ))?;
        let rows = stmt.query_map(rusqlite::params![user_id, self.now()], info_from_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
}
