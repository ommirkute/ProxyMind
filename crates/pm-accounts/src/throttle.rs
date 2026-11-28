//! Login throttling: failure counters per account and per address with exponential back-off.
//!
//! After `free` failures every further failure sets a delay that doubles (`base`, 2×`base`, 4×`base`, …) up to `max`.
//! While a delay runs, attempts are refused *before* any password is checked and do not extend it, so an attacker
//! cannot push the delay of a victim past `max`, and nothing is ever locked for good (a permanent lock would let anyone
//! lock the owner out). A success resets the account's counter; the address counter is *not* reset by a success
//! (otherwise an attacker holding one valid login could clear it between guesses) and fades after `forget_after`.
//!
//! The account counter is keyed by an HMAC of the *claimed* handle, so a name that does not exist is throttled exactly
//! like one that does, and the table holds no usernames.

use std::time::Duration;

use rusqlite::{Connection, OptionalExtension};

use crate::error::{AccountError, Result};
use crate::model::ClientInfo;
use crate::store::{Accounts, secs};
use crate::util::{clip, hex};

#[derive(Debug, Clone)]
pub struct ThrottleConfig {
    /// Failures per account before the first delay. Default 5.
    pub account_free_failures: u32,
    /// Failures per address before the first delay. Higher, because an office or a proxy shares one. Default 20.
    pub address_free_failures: u32,
    /// The first delay. Default 2 s.
    pub base_delay: Duration,
    /// The longest delay. Default 15 min.
    pub max_delay: Duration,
    /// A counter whose last failure is older than this starts from zero. Default 1 h.
    pub forget_after: Duration,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            account_free_failures: 5,
            address_free_failures: 20,
            base_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(900),
            forget_after: Duration::from_secs(3600),
        }
    }
}

impl ThrottleConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.base_delay.is_zero() || self.max_delay < self.base_delay || self.forget_after < self.max_delay {
            return Err(AccountError::InvalidArgument(
                "throttle: base_delay > 0, max_delay >= base_delay and forget_after >= max_delay",
            ));
        }
        Ok(())
    }

    /// The delay that follows the `n`-th failure past the free ones (`n` = 0 for the first delayed one), in seconds.
    pub fn delay_after(&self, n: u32) -> i64 {
        let base = secs(self.base_delay);
        let shifted = base.checked_shl(n.min(40)).filter(|v| v >> n.min(40) == base).unwrap_or(i64::MAX);
        shifted.min(secs(self.max_delay))
    }
}

pub(crate) const ACCOUNT: &str = "account";
pub(crate) const ADDRESS: &str = "address";

impl Accounts {
    /// The throttle key for a claimed handle, normalised or not.
    pub(crate) fn account_key(&self, claimed: &str) -> String {
        let canon = clip(claimed.trim(), 256).to_lowercase();
        hex(&Self::mac(&self.keys.throttle, canon.as_bytes()))
    }

    fn address_key(client: &ClientInfo) -> Option<String> {
        client.addr.as_deref().map(|a| clip(a.trim(), 64).to_lowercase())
    }

    pub(crate) fn retry_of(conn: &Connection, scope: &str, key: &str, now: i64) -> Result<i64> {
        let blocked: Option<i64> = conn
            .query_row("SELECT blocked_until FROM login_throttle WHERE scope = ?1 AND key = ?2", [scope, key], |r| {
                r.get(0)
            })
            .optional()?;
        Ok(blocked.map_or(0, |b| (b - now).max(0)))
    }

    /// Refuses with [`AccountError::Throttled`] while a delay runs for the account or the address.
    pub(crate) fn check_throttle(&self, account_key: Option<&str>, client: &ClientInfo) -> Result<()> {
        let now = self.now();
        let conn = self.conn();
        let mut retry = 0;
        if let Some(k) = account_key {
            retry = retry.max(Self::retry_of(&conn, ACCOUNT, k, now)?);
        }
        if let Some(k) = Self::address_key(client) {
            retry = retry.max(Self::retry_of(&conn, ADDRESS, &k, now)?);
        }
        if retry > 0 {
            return Err(AccountError::Throttled { retry_after: Duration::from_secs(retry.unsigned_abs()) });
        }
        Ok(())
    }

    /// How long until `claimed` could try again from `client`; `None` when no delay runs.
    pub fn login_retry_after(&self, claimed: &str, client: &ClientInfo) -> Result<Option<Duration>> {
        match self.check_throttle(Some(&self.account_key(claimed)), client) {
            Err(AccountError::Throttled { retry_after }) => Ok(Some(retry_after)),
            Err(e) => Err(e),
            Ok(()) => Ok(None),
        }
    }

    pub(crate) fn bump(&self, conn: &Connection, scope: &str, key: &str, free: u32, now: i64) -> Result<()> {
        let row: Option<(i64, i64)> = conn
            .query_row(
                "SELECT failures, last_failure_at FROM login_throttle WHERE scope = ?1 AND key = ?2",
                [scope, key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let forget = secs(self.cfg.throttle.forget_after);
        let previous = match row {
            Some((n, last)) if now - last <= forget => n,
            _ => 0,
        };
        let failures = previous.saturating_add(1);
        let blocked_until = match u32::try_from(failures) {
            Ok(n) if n >= free => now.saturating_add(self.cfg.throttle.delay_after(n - free)),
            Ok(_) => 0,
            Err(_) => now.saturating_add(secs(self.cfg.throttle.max_delay)),
        };
        conn.execute(
            "INSERT INTO login_throttle (scope, key, failures, last_failure_at, blocked_until) \
             VALUES (?1, ?2, ?3, ?4, ?5) \
             ON CONFLICT(scope, key) DO UPDATE SET failures = ?3, last_failure_at = ?4, blocked_until = ?5",
            rusqlite::params![scope, key, failures, now, blocked_until],
        )?;
        Ok(())
    }

    /// Counts one failure against the account (when known) and the address, and writes the security log entry.
    pub(crate) fn record_failure(
        &self,
        account_key: Option<&str>,
        client: &ClientInfo,
        kind: &str,
        user_id: Option<&str>,
        detail: &str,
    ) -> Result<()> {
        let now = self.now();
        self.tx(|tx| {
            if let Some(k) = account_key {
                self.bump(tx, ACCOUNT, k, self.cfg.throttle.account_free_failures, now)?;
            }
            if let Some(k) = Self::address_key(client) {
                self.bump(tx, ADDRESS, &k, self.cfg.throttle.address_free_failures, now)?;
            }
            self.audit(tx, kind, user_id, "anonymous", client.addr.as_deref(), detail)
        })
    }

    pub(crate) fn reset_account_throttle(&self, tx: &Connection, account_key: &str) -> Result<()> {
        tx.execute("DELETE FROM login_throttle WHERE scope = ?1 AND key = ?2", [ACCOUNT, account_key])?;
        Ok(())
    }
}
