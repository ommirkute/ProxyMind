//! `pm3_` tokens in single-user mode (ADR-0022 step 5): `<home>/tokens.json`, with the same records and the same rules
//! as the server's table (`token.rs`), hashed with an install-local key in `<home>/tokens.key`.
//!
//! * **Both files are private.** Created 0600 on Unix, and *refused* (every token then fails to authenticate, and the
//!   CLI says why) when group or world can read them: a token file that others can read is as good as published, and
//!   so is the key that makes its hashes useful to an attacker who already holds the file.
//! * **The format** is JSON: `{"version": 1, "tokens": [{"id", "kind", "name", "hash", "role", "tier_cap",
//!   "created_at", "expires_at", "last_used_at", "use_count", "revoked_at", "revoked_reason"}]}`; `hash` is the hex of
//!   HMAC-SHA256 of the token under the key. There is no owner and no project: the owner is the person who owns the
//!   home, and a token works for whatever project that install serves (`project_id` is `None` in [`TokenInfo`]).
//! * **Several processes share the file** (`proxymind token create` while `proxymind ui` runs). Writers take a lock
//!   file, re-read the records and replace the file atomically (write a temporary file, rename), so a CLI revoke is
//!   seen by the running UI at its next request and the UI's bookkeeping cannot undo it. Readers need no lock.
//! * **Nothing is cached** beyond a call, as in server mode; last use and use count are written at most once a minute
//!   per token.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ring::hmac;
use serde::{Deserialize, Serialize};

use crate::clock::{Clock, SystemClock};
use crate::error::{AccountError, Result};
use crate::key::{KeyPurpose, ServerKey};
use crate::model::Role;
use crate::token::{
    NewToken, NewTokenSpec, TokenAuth, TokenInfo, TokenKind, UseTracker, digest, effective_tier_cap, generate, mac_key,
    new_id, same_digest, shape,
};
use crate::util::{hex, unhex};

/// Live tokens one install may hold.
const MAX_LIVE: usize = 200;
/// A lock file older than this is taken to be left by a process that died.
const STALE_LOCK: Duration = Duration::from_secs(10);

#[derive(Serialize, Deserialize, Clone)]
struct Record {
    id: String,
    kind: String,
    name: String,
    hash: String,
    role: String,
    #[serde(default)]
    tier_cap: Option<String>,
    created_at: i64,
    expires_at: i64,
    #[serde(default)]
    last_used_at: Option<i64>,
    #[serde(default)]
    use_count: u64,
    #[serde(default)]
    revoked_at: Option<i64>,
    #[serde(default)]
    revoked_reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Document {
    version: u32,
    tokens: Vec<Record>,
}

impl Record {
    fn info(&self) -> Result<TokenInfo> {
        Ok(TokenInfo {
            id: self.id.clone(),
            kind: TokenKind::parse(&self.kind).map_err(|_| damaged())?,
            name: self.name.clone(),
            user_id: None,
            project_id: None,
            role: crate::token::validate_role(Role::parse(&self.role)?).map_err(|_| damaged())?,
            tier_cap: self.tier_cap.clone(),
            created_at: self.created_at,
            created_by: "local".into(),
            expires_at: self.expires_at,
            last_used_at: self.last_used_at,
            use_count: self.use_count,
            revoked_at: self.revoked_at,
            revoked_reason: self.revoked_reason.clone(),
        })
    }
}

fn damaged() -> AccountError {
    AccountError::TokenStore("tokens.json is damaged: fix or remove it".into())
}

/// The single-user token store.
pub struct TokenFile {
    path: PathBuf,
    lock_path: PathBuf,
    key: hmac::Key,
    clock: Arc<dyn Clock>,
    uses: UseTracker,
}

/// Refuses a private file that group or others can read (Unix; elsewhere the home directory's own protection is all
/// there is).
fn require_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(AccountError::TokenStore(format!(
                "{} is readable by other users (mode {:o}); chmod 600 it, and consider its tokens exposed",
                path.display(),
                mode & 0o777
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

impl TokenFile {
    /// Opens the store in `home` (the ProxyMind home directory): creates `tokens.key` (0600) when it is missing and
    /// refuses a key or token file that other users can read.
    pub fn open(home: &Path) -> Result<Self> {
        Self::open_with_clock(home, Arc::new(SystemClock))
    }

    pub fn open_with_clock(home: &Path, clock: Arc<dyn Clock>) -> Result<Self> {
        std::fs::create_dir_all(home)?;
        let key = ServerKey::load_or_create(&home.join("tokens.key"))?;
        let path = home.join("tokens.json");
        if path.exists() {
            require_private(&path)?;
        }
        Ok(Self {
            lock_path: home.join("tokens.lock"),
            path,
            key: mac_key(&key.derive(KeyPurpose::ApiToken)),
            clock,
            uses: UseTracker::default(),
        })
    }

    /// The store's clock, in seconds (what expiry is judged by).
    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    fn read(&self) -> Result<Document> {
        match std::fs::metadata(&self.path) {
            Ok(_) => {
                require_private(&self.path)?;
                let text = std::fs::read_to_string(&self.path)?;
                let doc: Document = serde_json::from_str(&text).map_err(|_| damaged())?;
                if doc.version != 1 {
                    return Err(AccountError::TokenStore(format!(
                        "tokens.json has format version {}; this ProxyMind reads version 1",
                        doc.version
                    )));
                }
                Ok(doc)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Document { version: 1, tokens: Vec::new() }),
            Err(e) => Err(e.into()),
        }
    }

    /// Writes a new version: a temporary file (0600) beside it, then a rename.
    fn write(&self, doc: &Document) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&tmp)?;
        f.write_all(serde_json::to_string_pretty(doc).map_err(|_| damaged())?.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Runs `f` on the freshly read records under the lock, and saves what it changed.
    fn update<T>(&self, f: impl FnOnce(&mut Document) -> Result<T>) -> Result<T> {
        let _lock = Lock::take(&self.lock_path)?;
        let mut doc = self.read()?;
        let out = f(&mut doc)?;
        self.write(&doc)?;
        Ok(out)
    }

    /// Makes a token. The secret is in the result once; a name used by a live token of the same kind (any case) is
    /// refused.
    pub fn create(&self, spec: &NewTokenSpec) -> Result<NewToken> {
        let spec = spec.checked()?;
        let now = self.clock.now();
        self.update(|doc| {
            let live = doc.tokens.iter().filter(|r| r.revoked_at.is_none() && r.expires_at > now);
            if live.clone().count() >= MAX_LIVE {
                return Err(AccountError::TooManyTokens);
            }
            if live.into_iter().any(|r| r.kind == spec.kind.as_str() && r.name.eq_ignore_ascii_case(&spec.name)) {
                return Err(AccountError::TokenNameTaken);
            }
            let secret = generate(spec.kind)?;
            let rec = Record {
                id: new_id()?,
                kind: spec.kind.as_str().into(),
                name: spec.name,
                hash: hex(&digest(&self.key, secret.expose())),
                role: spec.role.as_str().into(),
                tier_cap: spec.tier_cap,
                created_at: now,
                expires_at: now.saturating_add(i64::try_from(spec.ttl.as_secs()).unwrap_or(i64::MAX)),
                last_used_at: None,
                use_count: 0,
                revoked_at: None,
                revoked_reason: None,
            };
            let info = rec.info()?;
            doc.tokens.push(rec);
            Ok(NewToken { info, token: secret })
        })
    }

    /// Checks a presented token. `Err(InvalidToken)` for every reason (malformed, unknown, revoked, expired); an
    /// unreadable or world-readable token file is `Err(TokenStore)`, which callers treat as "no token works".
    pub fn authenticate(&self, token: &str) -> Result<TokenAuth> {
        if shape(token).is_none() {
            return Err(AccountError::InvalidToken);
        }
        let now = self.clock.now();
        let presented = digest(&self.key, token);
        let doc = self.read()?;
        // Every record is compared, so the time taken does not say which one matched.
        let mut found: Option<&Record> = None;
        for r in &doc.tokens {
            let stored = unhex(&r.hash).unwrap_or_default();
            if same_digest(&stored, &presented) {
                found = Some(r);
            }
        }
        let rec = found.ok_or(AccountError::InvalidToken)?;
        let mut info = rec.info()?;
        if !info.is_live(now) {
            return Err(AccountError::InvalidToken);
        }
        let tier_cap = effective_tier_cap(info.role, info.tier_cap.as_deref());
        let stored_count = info.use_count;
        let mut written = 0;
        if let Some(add) = self.uses.note(&info.id, now, info.last_used_at) {
            let id = info.id.clone();
            let wrote = self.update(|doc| {
                // Re-read under the lock: a revoke made meanwhile (by the CLI) must not be undone.
                if let Some(r) = doc.tokens.iter_mut().find(|r| r.id == id) {
                    r.last_used_at = Some(now);
                    r.use_count = r.use_count.saturating_add(add);
                }
                Ok(())
            });
            if wrote.is_ok() {
                info.last_used_at = Some(now);
                written = add;
            }
        }
        info.use_count = stored_count + written + self.uses.pending(&info.id);
        Ok(TokenAuth { role: info.role, info, tier_cap })
    }

    /// Every token, newest first, revoked and expired ones too.
    pub fn list(&self) -> Result<Vec<TokenInfo>> {
        let mut out = self.read()?.tokens.iter().map(Record::info).collect::<Result<Vec<_>>>()?;
        out.sort_by(|a, b| b.created_at.cmp(&a.created_at).then_with(|| a.id.cmp(&b.id)));
        for t in &mut out {
            t.use_count += self.uses.pending(&t.id);
        }
        Ok(out)
    }

    /// Revokes a token: it stops working at its next request.
    pub fn revoke(&self, id: &str) -> Result<()> {
        let now = self.clock.now();
        self.update(|doc| {
            let rec = doc
                .tokens
                .iter_mut()
                .find(|r| r.id == id && r.revoked_at.is_none())
                .ok_or(AccountError::NoSuchToken)?;
            rec.revoked_at = Some(now);
            rec.revoked_reason = Some("revoked".into());
            Ok(())
        })?;
        self.uses.forget(id);
        Ok(())
    }
}

/// The lock file beside `tokens.json`: created exclusively, removed when dropped, broken when it is old enough to be a
/// leftover of a process that died.
struct Lock(PathBuf);

impl Lock {
    fn take(path: &Path) -> Result<Self> {
        for _ in 0..100 {
            match std::fs::OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(_) => return Ok(Self(path.to_path_buf())),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    let old = std::fs::metadata(path)
                        .and_then(|m| m.modified())
                        .ok()
                        .and_then(|t| SystemTime::now().duration_since(t).ok())
                        .is_some_and(|age| age > STALE_LOCK);
                    if old {
                        let _ = std::fs::remove_file(path);
                    } else {
                        std::thread::sleep(Duration::from_millis(30));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        Err(AccountError::TokenStore("tokens.lock is held by another process".into()))
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
