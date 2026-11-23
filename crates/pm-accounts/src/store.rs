//! The `Accounts` handle: connection, keys, configuration and the helpers every feature shares.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::{Mutex, MutexGuard};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::hmac;
use rusqlite::{Connection, Transaction, TransactionBehavior};

use crate::clock::{Clock, SystemClock};
use crate::error::{AccountError, Result};
use crate::key::{KeyPurpose, ServerKey};
use crate::password::{self, Argon2Cost, Gate};
use crate::throttle::ThrottleConfig;
use crate::util::{hex, random};

/// Lifetimes and costs. [`Config::default`] is what ADR-0022 decides.
#[derive(Debug, Clone)]
pub struct Config {
    /// A session with no use for this long ends. Default 8 h, at most 30 d.
    pub idle_timeout: Duration,
    /// A session ends this long after sign-in whatever its use. Default 7 d, at most 90 d.
    pub absolute_timeout: Duration,
    /// How long between the password step and the second factor. Default 5 min.
    pub pending_ttl: Duration,
    /// How many wrong second-factor attempts one pending sign-in allows. Default 5.
    pub pending_max_attempts: u32,
    /// Default 1 h.
    pub setup_token_ttl: Duration,
    /// An invite lives at most this long. Default 30 d.
    pub max_invite_ttl: Duration,
    pub argon2: Argon2Cost,
    /// Hashes that may run at once (each takes `argon2.memory_kib`). Default 4.
    pub hash_slots: usize,
    pub throttle: ThrottleConfig,
    /// Let accounts that can only view sign in with a password alone. Off by default (ADR-0022). Owners, server
    /// admins and testers always need a second factor.
    pub allow_password_only_viewers: bool,
    /// Shown by authenticator apps.
    pub totp_issuer: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(8 * 3600),
            absolute_timeout: Duration::from_secs(7 * 86_400),
            pending_ttl: Duration::from_secs(300),
            pending_max_attempts: 5,
            setup_token_ttl: Duration::from_secs(3600),
            max_invite_ttl: Duration::from_secs(30 * 86_400),
            argon2: Argon2Cost::default(),
            hash_slots: 4,
            throttle: ThrottleConfig::default(),
            allow_password_only_viewers: false,
            totp_issuer: "ProxyMind".into(),
        }
    }
}

impl Config {
    /// Cheap Argon2 for tests only.
    pub fn insecure_for_tests() -> Self {
        Self { argon2: Argon2Cost::insecure_for_tests(), ..Self::default() }
    }

    fn validate(&self) -> Result<()> {
        let day = 86_400;
        if self.idle_timeout.is_zero() || self.idle_timeout.as_secs() > 30 * day {
            return Err(AccountError::InvalidArgument("idle_timeout must be between 1 s and 30 days"));
        }
        if self.absolute_timeout.is_zero() || self.absolute_timeout.as_secs() > 90 * day {
            return Err(AccountError::InvalidArgument("absolute_timeout must be between 1 s and 90 days"));
        }
        if self.pending_ttl.is_zero() || self.pending_max_attempts == 0 || self.setup_token_ttl.is_zero() {
            return Err(AccountError::InvalidArgument("pending and setup lifetimes must be positive"));
        }
        self.throttle.validate()
    }
}

pub(crate) struct Keys {
    totp: LessSafeKey,
    pub(crate) session: hmac::Key,
    pub(crate) recovery: hmac::Key,
    pub(crate) token: hmac::Key,
    /// HMAC of `pm3_` API tokens.
    pub(crate) api_token: hmac::Key,
    pub(crate) throttle: hmac::Key,
    pub(crate) audit: hmac::Key,
}

pub(crate) fn secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

/// The handle to `server.db`. Cheap to share behind an `Arc`; all methods take `&self`.
pub struct Accounts {
    conn: Mutex<Connection>,
    pub(crate) keys: Keys,
    server_key: ServerKey,
    pub(crate) cfg: Config,
    clock: Arc<dyn Clock>,
    gate: Gate,
    pub(crate) dummy_hash: String,
    dummy_verifications: AtomicU64,
    pub(crate) token_uses: crate::token::UseTracker,
}

impl Accounts {
    /// Opens (creating and migrating) `server.db` at `path` with the default configuration and the system clock.
    pub fn open(path: &Path, key: ServerKey) -> Result<Self> {
        Self::open_with(path, key, Config::default(), Arc::new(SystemClock))
    }

    pub fn open_with(path: &Path, key: ServerKey, cfg: Config, clock: Arc<dyn Clock>) -> Result<Self> {
        let conn = Connection::open(path)?;
        // The file holds password hashes and encrypted secrets: owner only. WAL side files inherit the mode.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Self::init(conn, key, cfg, clock)
    }

    pub fn open_in_memory(key: ServerKey, cfg: Config, clock: Arc<dyn Clock>) -> Result<Self> {
        Self::init(Connection::open_in_memory()?, key, cfg, clock)
    }

    fn init(mut conn: Connection, key: ServerKey, cfg: Config, clock: Arc<dyn Clock>) -> Result<Self> {
        cfg.validate()?;
        conn.busy_timeout(Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        crate::migrations::apply(&mut conn)?;
        let mac = |p: KeyPurpose| hmac::Key::new(hmac::HMAC_SHA256, &key.derive(p));
        let totp_key = UnboundKey::new(&CHACHA20_POLY1305, &key.derive(KeyPurpose::TotpEncryption))
            .map_err(|_| AccountError::Internal("cannot build the TOTP encryption key".into()))?;
        let keys = Keys {
            totp: LessSafeKey::new(totp_key),
            session: mac(KeyPurpose::SessionId),
            recovery: mac(KeyPurpose::RecoveryCode),
            token: mac(KeyPurpose::OneTimeToken),
            api_token: mac(KeyPurpose::ApiToken),
            throttle: mac(KeyPurpose::Throttle),
            audit: mac(KeyPurpose::AuditChain),
        };
        let gate = Gate::new(cfg.hash_slots);
        // A hash of a random password at the current cost, verified when the user does not exist.
        let dummy_hash = password::hash(&hex(&random::<16>()?), cfg.argon2)?;
        let accounts = Self {
            conn: Mutex::new(conn),
            keys,
            server_key: key,
            cfg,
            clock,
            gate,
            dummy_hash,
            dummy_verifications: AtomicU64::new(0),
            token_uses: Default::default(),
        };
        accounts.purge_expired()?;
        Ok(accounts)
    }

    /// The server key, for deriving keys other layers need (`KeyPurpose::AuditChain` for the project audit log,
    /// `KeyPurpose::ApiToken` for tokens).
    pub fn server_key(&self) -> &ServerKey {
        &self.server_key
    }

    pub(crate) fn now(&self) -> i64 {
        self.clock.now()
    }

    pub(crate) fn conn(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock()
    }

    /// Runs `f` in one IMMEDIATE transaction; commits when it returns `Ok`, rolls back otherwise.
    pub(crate) fn tx<T>(&self, f: impl FnOnce(&Transaction<'_>) -> Result<T>) -> Result<T> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    pub(crate) fn mac(key: &hmac::Key, data: &[u8]) -> Vec<u8> {
        hmac::sign(key, data).as_ref().to_vec()
    }

    pub(crate) fn hash_password(&self, password: &str) -> Result<String> {
        let _permit = self.gate.acquire();
        password::hash(password, self.cfg.argon2)
    }

    /// Verifies `password` against `phc`; with `None` verifies against the dummy hash (and counts it).
    pub(crate) fn verify_password(&self, phc: Option<&str>, password: &str) -> bool {
        let _permit = self.gate.acquire();
        match phc {
            Some(phc) => password::verify(phc, password),
            None => {
                self.dummy_verifications.fetch_add(1, Ordering::SeqCst);
                // The result is discarded: the dummy is of a random password and must never "succeed".
                let _ = password::verify(&self.dummy_hash, password);
                false
            }
        }
    }

    /// How many times the dummy hash has been verified because the user did not exist (or had no password).
    /// Diagnostics, and what the tests of constant behaviour for unknown users assert on.
    pub fn dummy_verifications(&self) -> u64 {
        self.dummy_verifications.load(Ordering::SeqCst)
    }

    /// `nonce || ciphertext || tag`, bound to `aad`.
    pub(crate) fn seal_secret(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = random::<12>()?;
        let mut buf = plaintext.to_vec();
        self.keys
            .totp
            .seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce_bytes), Aad::from(aad), &mut buf)
            .map_err(|_| AccountError::Internal("encryption failed".into()))?;
        let mut out = nonce_bytes.to_vec();
        out.extend_from_slice(&buf);
        Ok(out)
    }

    pub(crate) fn open_secret(&self, sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < 12 + CHACHA20_POLY1305.tag_len() {
            return Err(AccountError::Decrypt);
        }
        let (nonce, rest) = sealed.split_at(12);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| AccountError::Decrypt)?;
        let mut buf = rest.to_vec();
        let plain = self.keys.totp.open_in_place(nonce, Aad::from(aad), &mut buf).map_err(|_| AccountError::Decrypt)?;
        Ok(plain.to_vec())
    }

    /// Deletes what can no longer matter: expired pending sign-ins, setup tokens and throttle rows, and sessions that
    /// ended more than a day ago. Called at open; a server may call it now and then.
    pub fn purge_expired(&self) -> Result<()> {
        let now = self.now();
        let forget = secs(self.cfg.throttle.forget_after);
        self.tx(|tx| {
            tx.execute("DELETE FROM pending_logins WHERE expires_at < ?1", [now])?;
            tx.execute("DELETE FROM setup_tokens WHERE expires_at < ?1", [now - 86_400])?;
            tx.execute("DELETE FROM login_throttle WHERE last_failure_at < ?1", [now - forget])?;
            // A token that ended (revoked, or past its expiry) is kept for 90 days so an id in a log still has a name.
            tx.execute(
                "DELETE FROM tokens WHERE MIN(COALESCE(revoked_at, expires_at), expires_at) < ?1",
                [now - 90 * 86_400],
            )?;
            tx.execute(
                "DELETE FROM sessions WHERE MIN(absolute_expires_at, idle_expires_at) < ?1 \
                 OR (revoked_at IS NOT NULL AND revoked_at < ?1)",
                [now - 86_400],
            )?;
            Ok(())
        })
    }
}
