//! `pm3_` tokens (ADR-0022 step 5): the part that is the same in both modes. Format, generation, the keyed hash,
//! and the rules a token must satisfy (kind, actor name, role ceiling, tier cap, lifetime). No storage here:
//! `tokens.rs` keeps them in `server.db` (server mode) and `token_file.rs` in `<home>/tokens.json` (single-user mode),
//! and both call the functions below, so a rule cannot differ between the two.
//!
//! A token is `pm3_<kind>_<64 hex digits>`: 256 bits from the system's secure random source. The `pm3_` prefix lets
//! secret scanners find a leak. The secret is shown once; what is stored is HMAC-SHA256 of the whole string under the
//! `ApiToken` subkey of the server key (or, in single-user mode, of the install's own `tokens.key`).
//!
//! Role and tier cap: the *effective* role is the lower of the token's ceiling and its owner's current role; a token
//! never carries `owner`. The tier cap names a tier of the policy gate (`read`, `passive`, `active_safe`,
//! `active_intrusive`; `destructive` is no cap at all). A viewer's token is additionally held to `passive`, the highest
//! tier that sends nothing to a target ([`effective_tier_cap`]).

use std::time::Duration;

use ring::hmac;

use crate::error::{AccountError, Result};
use crate::model::Role;
use crate::util::{Secret, ct_eq, hex, random};

pub const TOKEN_PREFIX: &str = "pm3_";
/// Default lifetime: 30 days.
pub const DEFAULT_TTL: Duration = Duration::from_secs(30 * 86_400);
/// Longest lifetime: one year.
pub const MAX_TTL: Duration = Duration::from_secs(365 * 86_400);
/// Shortest lifetime: a minute (short lives are for CI jobs and tests).
pub const MIN_TTL: Duration = Duration::from_secs(60);
/// How long a token's last-use time and use count may lag behind: they are written at most this often per token.
pub const USE_WRITE_EVERY: i64 = 60;
/// The longest actor name (`agent:<name>`).
pub const MAX_NAME: usize = 64;

/// The policy gate's tiers, lowest first. `pm_policy::Tier` has the same names; a test in `pm-api` checks that the two
/// lists agree (this crate depends on no other ProxyMind crate).
pub const TIER_NAMES: [&str; 5] = ["read", "passive", "active_safe", "active_intrusive", "destructive"];

/// What a token acts as: `agent:<name>`, `ci:<name>` or `plugin:<name>`. Never `human`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenKind {
    Agent,
    Ci,
    Plugin,
}

impl TokenKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenKind::Agent => "agent",
            TokenKind::Ci => "ci",
            TokenKind::Plugin => "plugin",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "agent" => Ok(TokenKind::Agent),
            "ci" => Ok(TokenKind::Ci),
            "plugin" => Ok(TokenKind::Plugin),
            _ => Err(AccountError::InvalidArgument("a token's kind is agent, ci or plugin")),
        }
    }
}

/// What a caller asks for when making a token.
#[derive(Debug, Clone)]
pub struct NewTokenSpec {
    pub kind: TokenKind,
    /// The actor name (`claude` in `agent:claude`); checked by [`validate_name`].
    pub name: String,
    /// The ceiling: `Tester` or `Viewer`, never `Owner`. Default `Tester`.
    pub role: Role,
    /// A tier name from [`TIER_NAMES`].
    pub tier_cap: Option<String>,
    /// Default [`DEFAULT_TTL`]; between [`MIN_TTL`] and [`MAX_TTL`].
    pub ttl: Option<Duration>,
}

impl NewTokenSpec {
    pub fn new(kind: TokenKind, name: impl Into<String>) -> Self {
        Self { kind, name: name.into(), role: Role::Tester, tier_cap: None, ttl: None }
    }

    /// Every rule at once: the normalised values the stores save.
    pub(crate) fn checked(&self) -> Result<CheckedSpec> {
        Ok(CheckedSpec {
            kind: self.kind,
            name: validate_name(&self.name)?,
            role: validate_role(self.role)?,
            tier_cap: validate_tier_cap(self.tier_cap.as_deref())?,
            ttl: validate_ttl(self.ttl)?,
        })
    }
}

pub(crate) struct CheckedSpec {
    pub kind: TokenKind,
    pub name: String,
    pub role: Role,
    pub tier_cap: Option<String>,
    pub ttl: Duration,
}

/// A token as the stores and the API know it. Holds no secret: not the value, and not its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenInfo {
    /// `t_` plus 16 hex digits. Safe to log, show and put in audit records.
    pub id: String,
    pub kind: TokenKind,
    /// The actor name.
    pub name: String,
    /// The owning account (`u_…`); `None` in single-user mode, where the owner is the person at the keyboard.
    pub user_id: Option<String>,
    /// The project it is for; `None` in single-user mode (the token works for whatever project that install serves).
    pub project_id: Option<String>,
    /// The ceiling (`Tester` or `Viewer`).
    pub role: Role,
    pub tier_cap: Option<String>,
    pub created_at: i64,
    /// Who made it: an account id, or `local` (single-user mode).
    pub created_by: String,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
    pub use_count: u64,
    pub revoked_at: Option<i64>,
    pub revoked_reason: Option<String>,
}

impl TokenInfo {
    /// `agent:claude`: the actor every request with this token acts as.
    pub fn actor_id(&self) -> String {
        format!("{}:{}", self.kind.as_str(), self.name)
    }

    pub fn is_live(&self, now: i64) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// A token just made: the secret is here and nowhere else, once.
#[derive(Debug, Clone)]
pub struct NewToken {
    pub info: TokenInfo,
    pub token: Secret,
}

/// A token that passed authentication, with what this request may do.
#[derive(Debug, Clone)]
pub struct TokenAuth {
    pub info: TokenInfo,
    /// The lower of the token's ceiling and its owner's current role on the project.
    pub role: Role,
    /// The cap in force now: the token's own, narrowed to `passive` when the effective role is `viewer`.
    pub tier_cap: Option<String>,
    /// The owner's current role on the project (`None` in single-user mode, where a token has no owner account).
    pub owner_role: Option<Role>,
}

/// `pm3_<kind>_<64 hex>`.
pub fn generate(kind: TokenKind) -> Result<Secret> {
    Ok(Secret(format!("{TOKEN_PREFIX}{}_{}", kind.as_str(), hex(&random::<32>()?))))
}

/// The kind of a well-formed token, or `None`: exactly `pm3_`, a kind, `_`, 64 lower-case hex digits.
pub fn shape(token: &str) -> Option<TokenKind> {
    let rest = token.strip_prefix(TOKEN_PREFIX)?;
    let (kind, secret) = rest.split_once('_')?;
    let kind = TokenKind::parse(kind).ok()?;
    (secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).then_some(kind)
}

/// A new id for a token record.
pub(crate) fn new_id() -> Result<String> {
    Ok(format!("t_{}", hex(&random::<8>()?)))
}

pub(crate) fn mac_key(derived: &[u8; 32]) -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, derived)
}

/// What is stored: HMAC-SHA256 of the token string.
pub(crate) fn digest(key: &hmac::Key, token: &str) -> Vec<u8> {
    hmac::sign(key, token.as_bytes()).as_ref().to_vec()
}

/// Constant-time comparison of a stored digest with the digest of a presented token.
pub(crate) fn same_digest(stored: &[u8], presented: &[u8]) -> bool {
    ct_eq(stored, presented)
}

/// The actor name: 1 to 64 characters of `A-Z a-z 0-9 - _ . @`, which is the actor syntax of the policy gate
/// (`Actor::parse`), so `agent:<name>` always parses.
pub fn validate_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(AccountError::InvalidArgument("a token's name is 1 to 64 characters"));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c)) {
        return Err(AccountError::InvalidArgument("a token's name may use letters, digits and - _ . @ only"));
    }
    Ok(name.to_string())
}

/// A token's ceiling is `tester` or `viewer`: tokens never grant `owner` (ADR-0022).
pub fn validate_role(role: Role) -> Result<Role> {
    match role {
        Role::Owner => Err(AccountError::InvalidArgument("a token's role is tester or viewer, never owner")),
        r => Ok(r),
    }
}

fn tier_rank(name: &str) -> Option<usize> {
    TIER_NAMES.iter().position(|t| *t == name)
}

/// A tier name of the policy gate. `destructive` is the highest tier, so capping at it caps nothing: it is stored as
/// no cap.
pub fn validate_tier_cap(cap: Option<&str>) -> Result<Option<String>> {
    let Some(cap) = cap.map(str::trim).filter(|c| !c.is_empty()) else { return Ok(None) };
    let Some(rank) = tier_rank(cap) else {
        return Err(AccountError::InvalidArgument(
            "a tier cap is one of read, passive, active_safe, active_intrusive, destructive",
        ));
    };
    Ok((rank + 1 < TIER_NAMES.len()).then(|| cap.to_string()))
}

pub fn validate_ttl(ttl: Option<Duration>) -> Result<Duration> {
    let ttl = ttl.unwrap_or(DEFAULT_TTL);
    if ttl < MIN_TTL || ttl > MAX_TTL {
        return Err(AccountError::InvalidArgument("a token lives from one minute to one year"));
    }
    Ok(ttl)
}

/// The lower of two roles (`viewer` < `tester` < `owner`).
pub fn effective_role(a: Role, b: Role) -> Role {
    if a.rank() <= b.rank() { a } else { b }
}

/// The tier cap in force: the token's own, and for an effective `viewer` at most `passive` (a viewer sends nothing to
/// a target). The lower of the two when both apply.
pub fn effective_tier_cap(role: Role, cap: Option<&str>) -> Option<String> {
    let viewer_cap = (role == Role::Viewer).then_some("passive");
    match (cap, viewer_cap) {
        (Some(c), Some(v)) => {
            let (rc, rv) = (tier_rank(c).unwrap_or(usize::MAX), tier_rank(v).unwrap_or(usize::MAX));
            Some(if rc <= rv { c } else { v }.to_string())
        }
        (Some(c), None) => Some(c.to_string()),
        (None, Some(v)) => Some(v.to_string()),
        (None, None) => None,
    }
}

/// Keeps a token's last-use time and use count from being written on every request: counts uses in memory and says
/// when a write is due (the first use of a process, then at most once per [`USE_WRITE_EVERY`] seconds per token).
/// What has not been written yet is reported with the stored count, so a listing is exact; a crash loses at most a
/// minute's count.
#[derive(Default)]
pub(crate) struct UseTracker {
    inner: parking_lot::Mutex<std::collections::HashMap<String, Pending>>,
}

struct Pending {
    count: u64,
    last_write: i64,
}

impl UseTracker {
    /// Notes one use at `now`. `Some(n)` means: write `last_used_at = now` and add `n` to the stored count.
    pub(crate) fn note(&self, id: &str, now: i64, stored_last_used: Option<i64>) -> Option<u64> {
        let mut map = self.inner.lock();
        let p = map.entry(id.to_string()).or_insert(Pending { count: 0, last_write: stored_last_used.unwrap_or(0) });
        p.count += 1;
        (now - p.last_write >= USE_WRITE_EVERY).then(|| {
            p.last_write = now;
            std::mem::take(&mut p.count)
        })
    }

    pub(crate) fn pending(&self, id: &str) -> u64 {
        self.inner.lock().get(id).map_or(0, |p| p.count)
    }

    pub(crate) fn forget(&self, id: &str) {
        self.inner.lock().remove(id);
    }
}

/// Reads `30d`, `12h`, `90m` or a plain number of days (the CLI's `--expires`).
pub fn parse_ttl(text: &str) -> Result<Duration> {
    let t = text.trim();
    let bad = AccountError::InvalidArgument("a lifetime looks like 30d, 12h or 90m");
    let (num, unit) = match t.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => (&t[..i], c),
        Some(_) => (t, 'd'),
        None => return Err(bad),
    };
    let n: u64 = num.parse().map_err(|_| AccountError::InvalidArgument("a lifetime looks like 30d, 12h or 90m"))?;
    let secs = match unit {
        'd' => n.checked_mul(86_400),
        'h' => n.checked_mul(3600),
        'm' => n.checked_mul(60),
        _ => return Err(bad),
    };
    secs.map(Duration::from_secs).ok_or(AccountError::InvalidArgument("a lifetime looks like 30d, 12h or 90m"))
}
