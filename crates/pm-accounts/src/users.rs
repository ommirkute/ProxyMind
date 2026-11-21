//! Users: the first owner, invites, passwords, memberships, disabling, and the local-console recovery path.

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, Row, Transaction};

use crate::error::{AccountError, Result};
use crate::model::{ClientInfo, InviteInfo, Membership, NewInvite, Role, SetupToken, User, UserStatus};
use crate::password::check_policy;
use crate::store::{Accounts, secs};
use crate::util::{Secret, clip, hex, random};

const USER_COLS: &str = "id, username, display_name, status, server_admin, created_at, last_login_at";

fn user_from_row(r: &Row<'_>) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(0)?,
        username: r.get(1)?,
        display_name: r.get(2)?,
        status: UserStatus::parse(&r.get::<_, String>(3)?),
        server_admin: r.get::<_, i64>(4)? != 0,
        created_at: r.get(5)?,
        last_login_at: r.get(6)?,
    })
}

pub(crate) fn find_user(conn: &Connection, id: &str) -> Result<Option<User>> {
    Ok(conn.query_row(&format!("SELECT {USER_COLS} FROM users WHERE id = ?1"), [id], user_from_row).optional()?)
}

pub(crate) fn find_user_by_name(conn: &Connection, username: &str) -> Result<Option<User>> {
    Ok(conn
        .query_row(&format!("SELECT {USER_COLS} FROM users WHERE username = ?1"), [username], user_from_row)
        .optional()?)
}

pub(crate) fn password_phc(conn: &Connection, user_id: &str) -> Result<Option<String>> {
    let blob: Option<Vec<u8>> = conn
        .query_row("SELECT secret FROM credentials WHERE user_id = ?1 AND kind = 'password'", [user_id], |r| r.get(0))
        .optional()?;
    Ok(blob.and_then(|b| String::from_utf8(b).ok()))
}

/// Lower-cases and checks a handle: 3 to 64 characters of `a-z 0-9 . _ @ + -`, starting with a letter or digit.
/// ASCII only, so two handles cannot look alike.
pub(crate) fn normalise_username(s: &str) -> Result<String> {
    let t = s.trim().to_ascii_lowercase();
    if !(3..=64).contains(&t.len()) {
        return Err(AccountError::InvalidUsername("must be 3 to 64 characters"));
    }
    if !t.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-'))
    {
        return Err(AccountError::InvalidUsername("only letters, digits and . _ @ + - are allowed"));
    }
    if !t.as_bytes()[0].is_ascii_alphanumeric() {
        return Err(AccountError::InvalidUsername("must start with a letter or digit"));
    }
    Ok(t)
}

fn is_constraint(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation)
}

fn new_id(prefix: &str) -> Result<String> {
    Ok(format!("{prefix}{}", hex(&random::<16>()?)))
}

fn owner_exists(conn: &Connection) -> Result<bool> {
    Ok(conn.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE server_admin = 1)", [], |r| r.get(0))?)
}

impl Accounts {
    // ---- reading ---------------------------------------------------------------------------------------------

    pub fn get_user(&self, id: &str) -> Result<Option<User>> {
        find_user(&self.conn(), id)
    }

    pub fn get_user_by_username(&self, username: &str) -> Result<Option<User>> {
        let Ok(name) = normalise_username(username) else { return Ok(None) };
        find_user_by_name(&self.conn(), &name)
    }

    pub fn list_users(&self) -> Result<Vec<User>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!("SELECT {USER_COLS} FROM users ORDER BY created_at, id"))?;
        let rows = stmt.query_map([], user_from_row)?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    pub(crate) fn require_admin(conn: &Connection, acting: &str) -> Result<User> {
        match find_user(conn, acting)? {
            Some(u) if u.status == UserStatus::Active && u.server_admin => Ok(u),
            _ => Err(AccountError::NotAuthorised),
        }
    }

    fn is_project_owner(conn: &Connection, user_id: &str, project: &str) -> Result<bool> {
        let role: Option<String> = conn
            .query_row(
                "SELECT m.role FROM memberships m JOIN users u ON u.id = m.user_id \
                 WHERE m.project_id = ?1 AND m.user_id = ?2 AND u.status = 'active'",
                [project, user_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(role.as_deref() == Some("owner"))
    }

    /// May this user sign in with a password alone? Only a viewer-level account, and only when the owner allowed it.
    pub fn user_requires_second_factor(&self, user_id: &str) -> Result<bool> {
        let conn = self.conn();
        self.requires_second_factor(&conn, user_id)
    }

    pub(crate) fn requires_second_factor(&self, conn: &Connection, user_id: &str) -> Result<bool> {
        if !self.cfg.allow_password_only_viewers {
            return Ok(true);
        }
        let can_send: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id = ?1 AND server_admin = 1) \
             OR EXISTS(SELECT 1 FROM memberships WHERE user_id = ?1 AND role IN ('owner', 'tester'))",
            [user_id],
            |r| r.get(0),
        )?;
        Ok(can_send)
    }

    // ---- creating accounts -----------------------------------------------------------------------------------

    fn insert_user(
        &self,
        tx: &Transaction<'_>,
        username: &str,
        display_name: &str,
        server_admin: bool,
        phc: &str,
    ) -> Result<User> {
        let now = self.now();
        let id = new_id("u_")?;
        let display = match clip(display_name.trim(), 100) {
            d if d.is_empty() => username.to_string(),
            d => d,
        };
        tx.execute(
            "INSERT INTO users (id, username, display_name, status, server_admin, created_at) \
             VALUES (?1, ?2, ?3, 'active', ?4, ?5)",
            rusqlite::params![id, username, display, i64::from(server_admin), now],
        )
        .map_err(|e| if is_constraint(&e) { AccountError::UsernameTaken } else { e.into() })?;
        tx.execute(
            "INSERT INTO credentials (id, user_id, kind, secret, created_at) VALUES (?1, ?2, 'password', ?3, ?4)",
            rusqlite::params![new_id("c_")?, id, phc.as_bytes(), now],
        )?;
        Ok(User {
            id,
            username: username.to_string(),
            display_name: display,
            status: UserStatus::Active,
            server_admin,
            created_at: now,
            last_login_at: None,
        })
    }

    fn issue_setup_token(&self, tx: &Transaction<'_>, kind: &str) -> Result<SetupToken> {
        let now = self.now();
        let expires_at = now.saturating_add(secs(self.cfg.setup_token_ttl));
        let token = format!("pmset_{}", hex(&random::<16>()?));
        // Only one setup token is valid at a time.
        tx.execute("DELETE FROM setup_tokens WHERE used_at IS NULL", [])?;
        tx.execute(
            "INSERT INTO setup_tokens (id, token_hash, kind, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![new_id("s_")?, Self::mac(&self.keys.token, token.as_bytes()), kind, now, expires_at],
        )?;
        Ok(SetupToken { token: Secret(token), expires_at })
    }

    /// A one-time token (128 bits, valid `setup_token_ttl`, single use) for claiming the first owner account. The
    /// server prints it as part of the setup URL. Refused when an owner already exists. Replaces any earlier one.
    pub fn create_setup_token(&self) -> Result<SetupToken> {
        self.tx(|tx| {
            if owner_exists(tx)? {
                return Err(AccountError::OwnerExists);
            }
            let t = self.issue_setup_token(tx, "bootstrap")?;
            self.audit(tx, "setup_token_created", None, "local_console", None, "bootstrap")?;
            Ok(t)
        })
    }

    fn setup_token_usable(&self, conn: &Connection, token: &str) -> Result<bool> {
        let row: Option<(i64, Option<i64>)> = conn
            .query_row(
                "SELECT expires_at, used_at FROM setup_tokens WHERE token_hash = ?1",
                [Self::mac(&self.keys.token, token.as_bytes())],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(matches!(row, Some((exp, None)) if exp > self.now()))
    }

    /// Claims the first owner account with the setup token: creates a user who is server admin. The token dies with
    /// this call. The new account has no second factor yet, and an owner cannot sign in without one, so the first
    /// `login_password` returns `EnrolmentRequired` and the setup page finishes the enrolment (ADR-0022).
    ///
    /// Refused with `OwnerExists` when any server admin exists, unless the token came from [`reset_owner`](Self::reset_owner).
    pub fn bootstrap_owner(
        &self,
        setup_token: &str,
        username: &str,
        display_name: &str,
        password: &str,
        client: &ClientInfo,
    ) -> Result<User> {
        self.check_throttle(None, client)?;
        if !self.setup_token_usable(&self.conn(), setup_token)? {
            self.record_failure(None, client, "setup_failure", None, "bad setup token")?;
            return Err(AccountError::InvalidSetupToken);
        }
        let username = normalise_username(username)?;
        check_policy(password, &username)?;
        let phc = self.hash_password(password)?;
        let hash = Self::mac(&self.keys.token, setup_token.as_bytes());
        self.tx(|tx| {
            let (kind, expires_at, used): (String, i64, Option<i64>) = tx
                .query_row("SELECT kind, expires_at, used_at FROM setup_tokens WHERE token_hash = ?1", [&hash], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })
                .optional()?
                .ok_or(AccountError::InvalidSetupToken)?;
            if used.is_some() || expires_at <= self.now() {
                return Err(AccountError::InvalidSetupToken);
            }
            if kind == "bootstrap" && owner_exists(tx)? {
                return Err(AccountError::OwnerExists);
            }
            let burned = tx.execute(
                "UPDATE setup_tokens SET used_at = ?1 WHERE token_hash = ?2 AND used_at IS NULL",
                rusqlite::params![self.now(), hash],
            )?;
            if burned != 1 {
                return Err(AccountError::InvalidSetupToken);
            }
            let user = self.insert_user(tx, &username, display_name, true, &phc)?;
            self.audit(tx, "owner_created", Some(&user.id), "anonymous", client.addr.as_deref(), &kind)?;
            Ok(user)
        })
    }

    /// Local-console recovery (`proxymind server reset-owner`): ends every session and pending sign-in, voids earlier
    /// setup tokens, and returns a fresh one that works even though an owner exists; whoever holds it can create a new
    /// owner account (then disable the old one). **The only authority it needs is write access to the server home**, which
    /// is the authority over `server.db` and `server.key` anyway. Writes a `local_console` entry to the security log.
    pub fn reset_owner(&self) -> Result<SetupToken> {
        self.tx(|tx| {
            let now = self.now();
            tx.execute(
                "UPDATE sessions SET revoked_at = ?1, revoked_reason = 'reset_owner' WHERE revoked_at IS NULL",
                [now],
            )?;
            tx.execute("DELETE FROM pending_logins", [])?;
            let t = self.issue_setup_token(tx, "reset")?;
            self.audit(tx, "owner_reset", None, "local_console", None, "all sessions ended, new setup token")?;
            Ok(t)
        })
    }

    // ---- invites ---------------------------------------------------------------------------------------------

    /// Creates an invite. `created_by` must be an active server admin or an owner of `project_id`. The token is
    /// returned once; only its HMAC is stored. `role` applies to `project_id` (no membership is made when it is `None`).
    pub fn create_invite(
        &self,
        created_by: &str,
        role: Role,
        project_id: Option<&str>,
        ttl: Duration,
    ) -> Result<NewInvite> {
        if ttl.is_zero() || ttl > self.cfg.max_invite_ttl {
            return Err(AccountError::InvalidArgument("invite lifetime must be positive and within the maximum"));
        }
        self.tx(|tx| {
            let creator = find_user(tx, created_by)?.filter(|u| u.status == UserStatus::Active);
            let allowed = match (&creator, project_id) {
                (Some(u), _) if u.server_admin => true,
                (Some(u), Some(p)) => Self::is_project_owner(tx, &u.id, p)?,
                _ => false,
            };
            if !allowed {
                return Err(AccountError::NotAuthorised);
            }
            let now = self.now();
            let id = new_id("i_")?;
            let token = format!("pminv_{}", hex(&random::<32>()?));
            let expires_at = now.saturating_add(secs(ttl));
            tx.execute(
                "INSERT INTO invites (id, token_hash, role, project_id, created_by, created_at, expires_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    id,
                    Self::mac(&self.keys.token, token.as_bytes()),
                    role.as_str(),
                    project_id,
                    created_by,
                    now,
                    expires_at
                ],
            )?;
            self.audit(tx, "invite_created", Some(created_by), &format!("user:{created_by}"), None, &id)?;
            Ok(NewInvite { id, token: Secret(token), expires_at })
        })
    }

    pub fn list_invites(&self) -> Result<Vec<InviteInfo>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT id, role, project_id, created_by, created_at, expires_at, used_at, used_by, revoked_at \
             FROM invites ORDER BY created_at DESC, id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(InviteInfo {
                id: r.get(0)?,
                role: Role::parse(&r.get::<_, String>(1)?).unwrap_or(Role::Viewer),
                project_id: r.get(2)?,
                created_by: r.get(3)?,
                created_at: r.get(4)?,
                expires_at: r.get(5)?,
                used_at: r.get(6)?,
                used_by: r.get(7)?,
                revoked_at: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Revokes an unused invite. `acting` must be a server admin or the invite's creator.
    pub fn revoke_invite(&self, acting: &str, invite_id: &str) -> Result<()> {
        self.tx(|tx| {
            let creator: Option<String> =
                tx.query_row("SELECT created_by FROM invites WHERE id = ?1", [invite_id], |r| r.get(0)).optional()?;
            let creator = creator.ok_or(AccountError::InvalidInvite)?;
            if creator != acting {
                Self::require_admin(tx, acting)?;
            }
            let n = tx.execute(
                "UPDATE invites SET revoked_at = ?1 WHERE id = ?2 AND used_at IS NULL AND revoked_at IS NULL",
                rusqlite::params![self.now(), invite_id],
            )?;
            if n == 0 {
                return Err(AccountError::InvalidInvite);
            }
            self.audit(tx, "invite_revoked", Some(acting), &format!("user:{acting}"), None, invite_id)
        })
    }

    fn invite_usable(&self, conn: &Connection, token: &str) -> Result<bool> {
        let row: Option<(i64, Option<i64>, Option<i64>)> = conn
            .query_row(
                "SELECT expires_at, used_at, revoked_at FROM invites WHERE token_hash = ?1",
                [Self::mac(&self.keys.token, token.as_bytes())],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        Ok(matches!(row, Some((exp, None, None)) if exp > self.now()))
    }

    /// The only way to get an account other than the bootstrap: uses up the invite, creates the user (with the
    /// invite's membership, if it names a project) and sets the password. Single use; refused when expired, revoked or
    /// when the inviter has been disabled. A taken username leaves the invite unused.
    pub fn accept_invite(
        &self,
        invite_token: &str,
        username: &str,
        display_name: &str,
        password: &str,
        client: &ClientInfo,
    ) -> Result<User> {
        self.check_throttle(None, client)?;
        if !self.invite_usable(&self.conn(), invite_token)? {
            self.record_failure(None, client, "invite_failure", None, "bad invite")?;
            return Err(AccountError::InvalidInvite);
        }
        let username = normalise_username(username)?;
        check_policy(password, &username)?;
        let phc = self.hash_password(password)?;
        let hash = Self::mac(&self.keys.token, invite_token.as_bytes());
        self.tx(|tx| {
            let (id, role, project, creator): (String, String, Option<String>, String) = tx
                .query_row(
                    "SELECT id, role, project_id, created_by FROM invites WHERE token_hash = ?1 \
                     AND used_at IS NULL AND revoked_at IS NULL AND expires_at > ?2",
                    rusqlite::params![hash, self.now()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?
                .ok_or(AccountError::InvalidInvite)?;
            if !find_user(tx, &creator)?.is_some_and(|u| u.status == UserStatus::Active) {
                return Err(AccountError::InvalidInvite);
            }
            let user = self.insert_user(tx, &username, display_name, false, &phc)?;
            tx.execute(
                "UPDATE invites SET used_at = ?1, used_by = ?2 WHERE id = ?3",
                rusqlite::params![self.now(), user.id, id],
            )?;
            if let Some(project) = project {
                tx.execute(
                    "INSERT INTO memberships (project_id, user_id, role, created_at, created_by) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![project, user.id, role, self.now(), creator],
                )?;
            }
            self.audit(
                tx,
                "user_created",
                Some(&user.id),
                "anonymous",
                client.addr.as_deref(),
                &format!("invite {id}"),
            )?;
            Ok(user)
        })
    }

    // ---- passwords -------------------------------------------------------------------------------------------

    /// Sets a password without asking for the old one (an administrator's reset, or a completed recovery). Checks the
    /// policy. Ends every session of the user except `keep_session` (a session id, if the caller is the user).
    pub fn set_password(&self, user_id: &str, new_password: &str, keep_session: Option<&str>) -> Result<()> {
        let user = self.get_user(user_id)?.ok_or(AccountError::NoSuchUser)?;
        check_policy(new_password, &user.username)?;
        let phc = self.hash_password(new_password)?;
        let keep = keep_session.map(|s| self.session_hash(s));
        self.tx(|tx| {
            let n = tx.execute(
                "UPDATE credentials SET secret = ?1, last_used_at = NULL WHERE user_id = ?2 AND kind = 'password'",
                rusqlite::params![phc.as_bytes(), user_id],
            )?;
            if n == 0 {
                tx.execute(
                    "INSERT INTO credentials (id, user_id, kind, secret, created_at) VALUES (?1, ?2, 'password', ?3, ?4)",
                    rusqlite::params![new_id("c_")?, user_id, phc.as_bytes(), self.now()],
                )?;
            }
            Self::revoke_sessions_in(tx, user_id, keep.as_deref(), "password_changed", self.now())?;
            self.audit(tx, "password_changed", Some(user_id), &format!("user:{user_id}"), None, "")
        })
    }

    /// The user changes their own password: needs the current one (counted against the throttle when wrong).
    pub fn change_password(
        &self,
        user_id: &str,
        current: &str,
        new_password: &str,
        keep_session: Option<&str>,
    ) -> Result<()> {
        let user = self.get_user(user_id)?.ok_or(AccountError::NoSuchUser)?;
        let key = self.account_key(&user.username);
        let client = ClientInfo::default();
        self.check_throttle(Some(&key), &client)?;
        let phc = password_phc(&self.conn(), user_id)?;
        if !self.verify_password(phc.as_deref(), current) || phc.is_none() {
            self.record_failure(
                Some(&key),
                &client,
                "password_change_failure",
                Some(user_id),
                "wrong current password",
            )?;
            return Err(AccountError::InvalidCredentials);
        }
        self.set_password(user_id, new_password, keep_session)
    }

    // ---- state -----------------------------------------------------------------------------------------------

    /// Disables an account: ends its sessions and pending sign-ins; it keeps its id and its history. `acting` must be
    /// an active server admin; the last one cannot be disabled.
    pub fn disable_user(&self, acting: &str, target: &str) -> Result<()> {
        self.tx(|tx| {
            Self::require_admin(tx, acting)?;
            let user = find_user(tx, target)?.ok_or(AccountError::NoSuchUser)?;
            if user.server_admin && user.status == UserStatus::Active {
                let others: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM users WHERE server_admin = 1 AND status = 'active' AND id != ?1",
                    [target],
                    |r| r.get(0),
                )?;
                if others == 0 {
                    return Err(AccountError::LastAdmin);
                }
            }
            tx.execute("UPDATE users SET status = 'disabled' WHERE id = ?1", [target])?;
            tx.execute("DELETE FROM pending_logins WHERE user_id = ?1", [target])?;
            Self::revoke_sessions_in(tx, target, None, "user_disabled", self.now())?;
            self.audit(tx, "user_disabled", Some(target), &format!("user:{acting}"), None, "")
        })
    }

    pub fn enable_user(&self, acting: &str, target: &str) -> Result<()> {
        self.tx(|tx| {
            Self::require_admin(tx, acting)?;
            let n = tx.execute("UPDATE users SET status = 'active' WHERE id = ?1", [target])?;
            if n == 0 {
                return Err(AccountError::NoSuchUser);
            }
            self.audit(tx, "user_enabled", Some(target), &format!("user:{acting}"), None, "")
        })
    }

    // ---- memberships -----------------------------------------------------------------------------------------

    /// Gives `user_id` a role in a project (or changes it). `acting` must be an active server admin or an owner of the
    /// project. A demotion ends the user's sessions (ADR-0022: demoting ends theirs); a promotion does not.
    pub fn set_membership(&self, acting: &str, project_id: &str, user_id: &str, role: Role) -> Result<()> {
        self.tx(|tx| {
            let actor = find_user(tx, acting)?.filter(|u| u.status == UserStatus::Active);
            let allowed = match &actor {
                Some(u) => u.server_admin || Self::is_project_owner(tx, &u.id, project_id)?,
                None => false,
            };
            if !allowed {
                return Err(AccountError::NotAuthorised);
            }
            find_user(tx, user_id)?.ok_or(AccountError::NoSuchUser)?;
            let old: Option<String> = tx
                .query_row(
                    "SELECT role FROM memberships WHERE project_id = ?1 AND user_id = ?2",
                    [project_id, user_id],
                    |r| r.get(0),
                )
                .optional()?;
            tx.execute(
                "INSERT INTO memberships (project_id, user_id, role, created_at, created_by) VALUES (?1, ?2, ?3, ?4, ?5) \
                 ON CONFLICT(project_id, user_id) DO UPDATE SET role = ?3",
                rusqlite::params![project_id, user_id, role.as_str(), self.now(), acting],
            )?;
            if let Some(old) = old.as_deref().and_then(|o| Role::parse(o).ok())
                && role.rank() < old.rank()
            {
                Self::revoke_sessions_in(tx, user_id, None, "demoted", self.now())?;
            }
            self.audit(tx, "role_set", Some(user_id), &format!("user:{acting}"), None, &format!("{project_id} {}", role.as_str()))
        })
    }

    /// Removes a membership and ends the user's sessions.
    pub fn remove_membership(&self, acting: &str, project_id: &str, user_id: &str) -> Result<()> {
        self.tx(|tx| {
            let actor = find_user(tx, acting)?.filter(|u| u.status == UserStatus::Active);
            let allowed = match &actor {
                Some(u) => u.server_admin || Self::is_project_owner(tx, &u.id, project_id)?,
                None => false,
            };
            if !allowed {
                return Err(AccountError::NotAuthorised);
            }
            let n =
                tx.execute("DELETE FROM memberships WHERE project_id = ?1 AND user_id = ?2", [project_id, user_id])?;
            if n > 0 {
                Self::revoke_sessions_in(tx, user_id, None, "membership_removed", self.now())?;
                self.audit(tx, "role_removed", Some(user_id), &format!("user:{acting}"), None, project_id)?;
            }
            Ok(())
        })
    }

    pub fn memberships_of_user(&self, user_id: &str) -> Result<Vec<Membership>> {
        self.memberships("WHERE user_id = ?1", user_id)
    }

    pub fn members_of_project(&self, project_id: &str) -> Result<Vec<Membership>> {
        self.memberships("WHERE project_id = ?1", project_id)
    }

    fn memberships(&self, filter: &str, arg: &str) -> Result<Vec<Membership>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(&format!(
            "SELECT project_id, user_id, role, created_at, created_by FROM memberships {filter} ORDER BY project_id, user_id"
        ))?;
        let rows = stmt.query_map([arg], |r| {
            Ok(Membership {
                project_id: r.get(0)?,
                user_id: r.get(1)?,
                role: Role::parse(&r.get::<_, String>(2)?).unwrap_or(Role::Viewer),
                created_at: r.get(3)?,
                created_by: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }
}
