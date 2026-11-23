//! `proxymind token create | list | revoke` (ADR-0022 step 5).
//!
//! * **Single-user mode** (no `--server-home`): the install's token file, `<home>/tokens.json`, opened directly. A
//!   running `proxymind ui` reads the file at every request, so a token made or revoked here works or stops working at
//!   once, with no restart.
//! * **Server mode** (`--server-home DIR --user NAME`): on the server host, with write access to the server home (the
//!   same authority as the data and the key), for the named account. The security log records `local_console` as the
//!   actor. Away from the host, tokens are made in the web UI (Account → Tokens) or with `POST /api/v1/tokens`.
//!
//! The secret is printed once, on stdout alone, so `TOKEN=$(proxymind token create …)` works; everything else goes to
//! stderr. It is never stored in clear text, here or anywhere else.

use std::path::Path;

use anyhow::{Context, Result};
use pm_accounts::{NewTokenSpec, Role, TokenInfo, TokenKind, parse_ttl};

/// Where the tokens live: the install's file, or a server home's database for one of its accounts.
pub enum Store {
    Home(Box<pm_accounts::TokenFile>),
    Server { accounts: Box<pm_accounts::Accounts>, project_id: String, owner: Option<String> },
}

pub struct ServerArgs<'a> {
    pub server_home: &'a Path,
    pub user: Option<&'a str>,
    pub project_id: Option<&'a str>,
    /// The project file, to read its id from when `project_id` is not given.
    pub project_file: &'a Path,
}

pub fn open_home(home: &Path) -> Result<Store> {
    Ok(Store::Home(Box::new(pm_accounts::TokenFile::open(home)?)))
}

pub fn open_server(a: &ServerArgs<'_>, need_user: bool) -> Result<Store> {
    anyhow::ensure!(
        a.server_home.join("server.db").exists() && a.server_home.join("server.key").exists(),
        "no server.db and server.key in {}: this is not a server home (pass --server-home)",
        a.server_home.display()
    );
    let key = pm_accounts::ServerKey::load_or_create(&a.server_home.join("server.key"))?;
    let accounts = pm_accounts::Accounts::open(&a.server_home.join("server.db"), key)?;
    let project_id = match a.project_id {
        Some(p) => p.to_string(),
        None => Some(a.project_file)
            .filter(|f| f.exists())
            .and_then(|f| pm_store::Store::open(f).ok())
            .and_then(|s| s.get_setting("project_id").ok().flatten())
            .filter(|s| !s.is_empty())
            .with_context(|| {
                format!(
                    "{} has no project id yet (the server makes one when it first serves the project); pass \
                     --project-id",
                    a.project_file.display()
                )
            })?,
    };
    let owner = match a.user {
        Some(name) => Some(
            accounts.get_user_by_username(name)?.with_context(|| format!("no user named {name} on this server"))?.id,
        ),
        None => {
            anyhow::ensure!(!need_user, "a server's tokens belong to an account: pass --user NAME");
            None
        }
    };
    Ok(Store::Server { accounts: Box::new(accounts), project_id, owner })
}

pub fn spec(kind: &str, name: &str, role: &str, tier_cap: Option<&str>, expires: &str) -> Result<NewTokenSpec> {
    let mut s = NewTokenSpec::new(TokenKind::parse(kind)?, name);
    s.role = Role::parse(role)?;
    s.tier_cap = tier_cap.map(str::to_string);
    s.ttl = Some(parse_ttl(expires)?);
    Ok(s)
}

fn when(t: i64) -> String {
    jiff::Timestamp::from_second(t)
        .map(|t| t.strftime("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|_| t.to_string())
}

pub fn describe(t: &TokenInfo) -> String {
    format!(
        "{} as {} (role {}, tier cap {}, expires {})",
        t.id,
        t.actor_id(),
        t.role.as_str(),
        t.tier_cap.as_deref().unwrap_or("none"),
        when(t.expires_at)
    )
}

impl Store {
    pub fn create(&self, spec: &NewTokenSpec) -> Result<pm_accounts::NewToken> {
        match self {
            Store::Home(f) => Ok(f.create(spec)?),
            Store::Server { accounts, project_id, owner } => {
                let owner = owner.as_deref().context("a server's tokens belong to an account: pass --user NAME")?;
                Ok(accounts.create_token(pm_accounts::CONSOLE, owner, project_id, spec)?)
            }
        }
    }

    pub fn list(&self, all: bool) -> Result<Vec<TokenInfo>> {
        match self {
            Store::Home(f) => Ok(f.list()?),
            Store::Server { accounts, project_id, owner } => {
                let only = if all { None } else { owner.as_deref() };
                Ok(accounts.list_tokens(project_id, only)?)
            }
        }
    }

    pub fn revoke(&self, id: &str) -> Result<()> {
        match self {
            Store::Home(f) => Ok(f.revoke(id)?),
            Store::Server { accounts, .. } => Ok(accounts.revoke_token(pm_accounts::CONSOLE, id)?),
        }
    }
}

/// The table `token list` prints.
pub fn table(tokens: &[TokenInfo], now: i64) -> String {
    let mut out = format!(
        "{:<20} {:<26} {:<7} {:<17} {:<8} {:<22} {:<22} {}\n",
        "ID", "ACTOR", "ROLE", "TIER CAP", "STATUS", "EXPIRES", "LAST USED", "USES"
    );
    for t in tokens {
        let status = if t.revoked_at.is_some() {
            "revoked"
        } else if t.expires_at <= now {
            "expired"
        } else {
            "active"
        };
        out.push_str(&format!(
            "{:<20} {:<26} {:<7} {:<17} {:<8} {:<22} {:<22} {}\n",
            t.id,
            t.actor_id(),
            t.role.as_str(),
            t.tier_cap.as_deref().unwrap_or("-"),
            status,
            when(t.expires_at),
            t.last_used_at.map_or("never".to_string(), when),
            t.use_count
        ));
    }
    out
}
