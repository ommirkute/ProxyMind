//! `pm3_` tokens in `server.db` (ADR-0022 step 5, server mode). The rules a token must satisfy and the format are in
//! `token.rs`, shared with the single-user file store.
//!
//! * **Stored as HMAC-SHA256** under the `ApiToken` subkey; the secret is returned once by [`Accounts::create_token`].
//!   Lookup is by that hash (indexed), and the stored and presented digests are then compared in constant time.
//! * **A token is its owner's credential.** It works only while its owner is an active account *and* a member of the
//!   project, and its effective role is the lower of its ceiling and the owner's current role, read at every request:
//!   a demotion narrows the owner's tokens at once, a removal kills them. Disabling the account or removing the
//!   membership also revokes the rows (so enabling the account again does not bring them back).
//! * **No caching beyond a call.** Expiry, revocation and the owner's state are read from the database every time.
//!   Only the bookkeeping (last use, use count) is batched: written at most once a minute per token.
//! * **The security log** records creation, the first use, revocation and failed use. Failures are logged with the
//!   address, the reason and the token's id when it is known, never the value, and a flood of bad tokens from one
//!   address is logged less and less often (the same back-off as logins, in a separate bucket so it cannot lock anyone
//!   out of signing in).

use rusqlite::{Connection, OptionalExtension, Row};

use crate::error::{AccountError, Result};
use crate::model::{ClientInfo, Role, UserStatus};
use crate::store::Accounts;
use crate::throttle::ADDRESS;
use crate::token::{
    NewToken, NewTokenSpec, TokenAuth, TokenInfo, TokenKind, digest, effective_role, effective_tier_cap, generate,
    new_id, same_digest, shape,
};
use crate::users::find_user;
use crate::util::clip;

/// Stands for the person at the server host's console in `acting` (`proxymind token … --server-home`): write access to
/// the server home is the authority over `server.db` and `server.key` anyway, as for `reset_owner`. The security log
/// records `local_console` as the actor. Account ids are `u_…`, so no account can be mistaken for it.
pub const CONSOLE: &str = "local_console";

/// Live tokens one account may hold in a project (a guard against a runaway script, not a quota).
const MAX_LIVE_PER_USER: i64 = 100;

const COLS: &str = "t.id, t.kind, t.name, t.user_id, t.project_id, t.role, t.tier_cap, t.created_at, t.created_by, \
                    t.expires_at, t.last_used_at, t.use_count, t.revoked_at, t.revoked_reason";

fn info_from_row(r: &Row<'_>) -> rusqlite::Result<TokenInfo> {
    Ok(TokenInfo {
        id: r.get(0)?,
        kind: TokenKind::parse(&r.get::<_, String>(1)?).unwrap_or(TokenKind::Agent),
        name: r.get(2)?,
        user_id: Some(r.get(3)?),
        project_id: Some(r.get(4)?),
        role: Role::parse(&r.get::<_, String>(5)?).unwrap_or(Role::Viewer),
        tier_cap: r.get(6)?,
        created_at: r.get(7)?,
        created_by: r.get(8)?,
        expires_at: r.get(9)?,
        last_used_at: r.get(10)?,
        use_count: u64::try_from(r.get::<_, i64>(11)?).unwrap_or(0),
        revoked_at: r.get(12)?,
        revoked_reason: r.get(13)?,
    })
}

impl Accounts {
    /// Makes a token for `owner` on `project_id`. `acting` is the signed-in account that asks: the owner themself, or
    /// an owner of the project (making one for someone else). The owner must be an active member of the project. The
    /// secret is in the result once and nowhere else; a name already used by a live token of the project (any case)
    /// is refused, so every actor id has exactly one credential behind it.
    pub fn create_token(&self, acting: &str, owner: &str, project_id: &str, spec: &NewTokenSpec) -> Result<NewToken> {
        let spec = spec.checked()?;
        self.tx(|tx| {
            let actor = find_user(tx, acting)?.filter(|u| u.status == UserStatus::Active);
            let allowed = acting == CONSOLE
                || match &actor {
                    Some(u) => u.id == owner || Self::is_project_owner(tx, &u.id, project_id)?,
                    None => false,
                };
            if !allowed {
                return Err(AccountError::NotAuthorised);
            }
            let owner_user = find_user(tx, owner)?.filter(|u| u.status == UserStatus::Active);
            let is_member: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM memberships WHERE project_id = ?1 AND user_id = ?2)",
                [project_id, owner],
                |r| r.get(0),
            )?;
            if owner_user.is_none() || !is_member {
                return Err(AccountError::NoSuchUser);
            }
            let now = self.now();
            let live: i64 = tx.query_row(
                "SELECT COUNT(*) FROM tokens WHERE user_id = ?1 AND project_id = ?2 AND revoked_at IS NULL \
                 AND expires_at > ?3",
                rusqlite::params![owner, project_id, now],
                |r| r.get(0),
            )?;
            if live >= MAX_LIVE_PER_USER {
                return Err(AccountError::TooManyTokens);
            }
            let taken: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM tokens WHERE project_id = ?1 AND kind = ?2 AND lower(name) = lower(?3) \
                 AND revoked_at IS NULL AND expires_at > ?4)",
                rusqlite::params![project_id, spec.kind.as_str(), spec.name, now],
                |r| r.get(0),
            )?;
            if taken {
                return Err(AccountError::TokenNameTaken);
            }
            let secret = generate(spec.kind)?;
            let info = TokenInfo {
                id: new_id()?,
                kind: spec.kind,
                name: spec.name,
                user_id: Some(owner.to_string()),
                project_id: Some(project_id.to_string()),
                role: spec.role,
                tier_cap: spec.tier_cap,
                created_at: now,
                created_by: acting.to_string(),
                expires_at: now.saturating_add(i64::try_from(spec.ttl.as_secs()).unwrap_or(i64::MAX)),
                last_used_at: None,
                use_count: 0,
                revoked_at: None,
                revoked_reason: None,
            };
            tx.execute(
                "INSERT INTO tokens (id, token_hash, kind, name, user_id, project_id, role, tier_cap, created_at, \
                 created_by, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                rusqlite::params![
                    info.id,
                    digest(&self.keys.api_token, secret.expose()),
                    info.kind.as_str(),
                    info.name,
                    owner,
                    project_id,
                    info.role.as_str(),
                    info.tier_cap,
                    now,
                    acting,
                    info.expires_at
                ],
            )?;
            let detail = format!(
                "{} {} role={} cap={} expires={}",
                info.id,
                info.actor_id(),
                info.role.as_str(),
                info.tier_cap.as_deref().unwrap_or("none"),
                info.expires_at
            );
            let by = if acting == CONSOLE { CONSOLE.to_string() } else { format!("user:{acting}") };
            self.audit(tx, "token_created", Some(owner), &by, None, &detail)?;
            Ok(NewToken { info, token: secret })
        })
    }

    /// Checks a presented token for `project_id`. `Err(InvalidToken)` for every reason (unknown, malformed, revoked,
    /// expired, another project, owner disabled or no longer a member); the security log says which. On success: the
    /// token, its effective role (the lower of its ceiling and the owner's current role) and the tier cap in force.
    pub fn authenticate_token(&self, token: &str, project_id: &str, client: &ClientInfo) -> Result<TokenAuth> {
        let now = self.now();
        if shape(token).is_none() {
            self.token_failure(client, None, None, "malformed token");
            return Err(AccountError::InvalidToken);
        }
        let presented = digest(&self.keys.api_token, token);
        let found = {
            let conn = self.conn();
            conn.query_row(
                &format!(
                    "SELECT {COLS}, u.status, m.role, t.token_hash FROM tokens t \
                     JOIN users u ON u.id = t.user_id \
                     LEFT JOIN memberships m ON m.project_id = t.project_id AND m.user_id = t.user_id \
                     WHERE t.token_hash = ?1"
                ),
                [&presented],
                |r| {
                    Ok((
                        info_from_row(r)?,
                        r.get::<_, String>(14)?,
                        r.get::<_, Option<String>>(15)?,
                        r.get::<_, Vec<u8>>(16)?,
                    ))
                },
            )
            .optional()?
        };
        let Some((mut info, user_status, member_role, stored)) = found else {
            self.token_failure(client, None, None, "unknown token");
            return Err(AccountError::InvalidToken);
        };
        // The lookup was by hash; this is the comparison that must not stop at the first differing byte.
        let deny = |why: &str| {
            self.token_failure(client, Some(&info.id), info.user_id.as_deref(), why);
            Err(AccountError::InvalidToken)
        };
        if !same_digest(&stored, &presented) {
            return deny("unknown token");
        }
        if info.revoked_at.is_some() {
            return deny("revoked");
        }
        if info.expires_at <= now {
            return deny("expired");
        }
        if info.project_id.as_deref() != Some(project_id) {
            return deny("another project");
        }
        if UserStatus::parse(&user_status) != UserStatus::Active {
            return deny("owner disabled");
        }
        let Some(owner_role) = member_role.and_then(|r| Role::parse(&r).ok()) else {
            return deny("owner is not a member");
        };
        let role = effective_role(info.role, owner_role);
        let tier_cap = effective_tier_cap(role, info.tier_cap.as_deref());
        // Bookkeeping, at most once a minute per token; the first use is in the security log.
        let stored_count = info.use_count;
        let mut written = 0;
        if let Some(add) = self.token_uses.note(&info.id, now, info.last_used_at) {
            let first = info.last_used_at.is_none();
            let user = info.user_id.clone();
            let id = info.id.clone();
            let wrote = self.tx(|tx| {
                tx.execute(
                    "UPDATE tokens SET last_used_at = ?1, use_count = use_count + ?2 WHERE id = ?3",
                    rusqlite::params![now, i64::try_from(add).unwrap_or(i64::MAX), id],
                )?;
                if first {
                    self.audit(tx, "token_first_use", user.as_deref(), "token", client.addr.as_deref(), &id)?;
                }
                Ok(())
            });
            if wrote.is_ok() {
                info.last_used_at = Some(now);
                written = add;
            }
        }
        info.use_count = stored_count + written + self.token_uses.pending(&info.id);
        Ok(TokenAuth { info, role, tier_cap, owner_role: Some(owner_role) })
    }

    /// A project's tokens, newest first: `owner` only, or everyone's (`None`). Revoked and expired ones are listed
    /// too (for 90 days), so a person can see what happened. The use count includes uses not yet written.
    pub fn list_tokens(&self, project_id: &str, owner: Option<&str>) -> Result<Vec<TokenInfo>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT {COLS} FROM tokens t WHERE t.project_id = ?1 AND (?2 IS NULL OR t.user_id = ?2) \
             ORDER BY t.created_at DESC, t.id"
        ))?;
        let rows = stmt.query_map(rusqlite::params![project_id, owner], info_from_row)?;
        let mut out: Vec<TokenInfo> = rows.collect::<std::result::Result<_, _>>()?;
        for t in &mut out {
            t.use_count += self.token_uses.pending(&t.id);
        }
        Ok(out)
    }

    /// One token by id, whatever its state.
    pub fn get_token(&self, id: &str) -> Result<Option<TokenInfo>> {
        let conn = self.conn();
        Ok(conn.query_row(&format!("SELECT {COLS} FROM tokens t WHERE t.id = ?1"), [id], info_from_row).optional()?)
    }

    /// Revokes a token (it stops working at its next request). `acting` is its owner, or an owner of its project.
    pub fn revoke_token(&self, acting: &str, id: &str) -> Result<()> {
        self.tx(|tx| {
            let row: Option<(String, String)> = tx
                .query_row("SELECT user_id, project_id FROM tokens WHERE id = ?1", [id], |r| Ok((r.get(0)?, r.get(1)?)))
                .optional()?;
            let (owner, project) = row.ok_or(AccountError::NoSuchToken)?;
            let actor = find_user(tx, acting)?.filter(|u| u.status == UserStatus::Active);
            let allowed = acting == CONSOLE
                || match &actor {
                    Some(u) => u.id == owner || Self::is_project_owner(tx, &u.id, &project)?,
                    None => false,
                };
            if !allowed {
                // Not told whether the id exists to someone who may not touch it.
                return Err(AccountError::NoSuchToken);
            }
            let n = tx.execute(
                "UPDATE tokens SET revoked_at = ?1, revoked_reason = 'revoked' WHERE id = ?2 AND revoked_at IS NULL",
                rusqlite::params![self.now(), id],
            )?;
            if n == 0 {
                return Err(AccountError::NoSuchToken);
            }
            self.token_uses.forget(id);
            let by = if acting == CONSOLE { CONSOLE.to_string() } else { format!("user:{acting}") };
            self.audit(tx, "token_revoked", Some(&owner), &by, None, id)
        })
    }

    /// Revokes a user's live tokens, in a project or everywhere. Part of disabling an account and removing a
    /// membership; writes one security-log entry when there was anything to revoke.
    pub(crate) fn revoke_tokens_in(
        &self,
        conn: &Connection,
        user_id: &str,
        project: Option<&str>,
        reason: &str,
        now: i64,
    ) -> Result<usize> {
        let ids: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT id FROM tokens WHERE user_id = ?1 AND (?2 IS NULL OR project_id = ?2) AND revoked_at IS NULL",
            )?;
            stmt.query_map(rusqlite::params![user_id, project], |r| r.get(0))?.collect::<std::result::Result<_, _>>()?
        };
        for id in &ids {
            conn.execute(
                "UPDATE tokens SET revoked_at = ?1, revoked_reason = ?2 WHERE id = ?3",
                rusqlite::params![now, reason, id],
            )?;
            self.token_uses.forget(id);
        }
        if !ids.is_empty() {
            self.audit(conn, "tokens_revoked", Some(user_id), "system", None, &format!("{reason}: {}", ids.join(" ")))?;
        }
        Ok(ids.len())
    }

    /// Writes a failed use to the security log: the reason, the address and the token's id when it is known. A flood
    /// from one address is logged less and less often (the delay doubles after 20 failures), in its own bucket.
    fn token_failure(&self, client: &ClientInfo, token_id: Option<&str>, user_id: Option<&str>, reason: &str) {
        let key = format!(
            "token:{}",
            client.addr.as_deref().map(|a| clip(a.trim(), 64).to_lowercase()).unwrap_or_else(|| "-".into())
        );
        let now = self.now();
        let detail = match token_id {
            Some(id) => format!("{reason} (token {id})"),
            None => reason.to_string(),
        };
        // A failed write here must never become anything the caller sees: the request is refused either way.
        let _ = (|| -> Result<()> {
            let retry = Self::retry_of(&self.conn(), ADDRESS, &key, now)?;
            if retry > 0 {
                return Ok(());
            }
            self.tx(|tx| {
                self.bump(tx, ADDRESS, &key, self.cfg.throttle.address_free_failures, now)?;
                self.audit(tx, "token_failure", user_id, "anonymous", client.addr.as_deref(), &detail)
            })
        })();
    }
}
