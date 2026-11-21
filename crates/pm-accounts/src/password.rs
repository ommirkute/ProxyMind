//! Argon2id password hashing (PHC strings), the password policy and a cap on concurrent hashes.
//!
//! Policy (documented deviation from ADR-0022, which names a bundled list of common passwords): at least 12
//! characters, at most 256, not the username (or containing it), not one character repeated, and not on a short
//! built-in list of the most common long passwords. No composition rules. A larger list can replace the short one
//! without changing the API.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use parking_lot::{Condvar, Mutex};

use crate::error::{AccountError, Result};
use crate::util::random;

/// Argon2id cost. The defaults are `pm-vault`'s: 64 MiB, 3 passes, 1 lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Cost {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2Cost {
    fn default() -> Self {
        Self { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 }
    }
}

impl Argon2Cost {
    /// Cheap settings for tests only.
    pub fn insecure_for_tests() -> Self {
        Self { memory_kib: 64, iterations: 1, parallelism: 1 }
    }

    fn argon2(self) -> Result<Argon2<'static>> {
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, None)
            .map_err(|e| AccountError::Internal(format!("argon2 parameters: {e}")))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

pub(crate) fn hash(password: &str, cost: Argon2Cost) -> Result<String> {
    let salt = SaltString::encode_b64(&random::<16>()?).map_err(|e| AccountError::Internal(format!("salt: {e}")))?;
    let phc = cost
        .argon2()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AccountError::Internal(format!("argon2: {e}")))?;
    Ok(phc.to_string())
}

/// Verifies against the parameters stored in the PHC string. An unparsable string never verifies.
pub(crate) fn verify(phc: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else { return false };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}

/// True when `phc` is not Argon2id v19 or any of its costs is below `cost`.
pub(crate) fn needs_rehash(phc: &str, cost: Argon2Cost) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else { return true };
    if parsed.algorithm.as_str() != "argon2id" || parsed.version != Some(19) {
        return true;
    }
    let Ok(p) = Params::try_from(&parsed) else { return true };
    p.m_cost() < cost.memory_kib || p.t_cost() < cost.iterations || p.p_cost() < cost.parallelism
}

/// Limits how many hashes run at once, because each takes tens of MiB.
pub(crate) struct Gate {
    free: Mutex<usize>,
    cv: Condvar,
}

pub(crate) struct Permit<'a>(&'a Gate);

impl Gate {
    pub(crate) fn new(slots: usize) -> Self {
        Self { free: Mutex::new(slots.max(1)), cv: Condvar::new() }
    }

    pub(crate) fn acquire(&self) -> Permit<'_> {
        let mut free = self.free.lock();
        while *free == 0 {
            self.cv.wait(&mut free);
        }
        *free -= 1;
        Permit(self)
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.free.lock() += 1;
        self.0.cv.notify_one();
    }
}

const COMMON: &[&str] = &[
    "123456789012",
    "1234567890123",
    "12345678901234",
    "123456789abc",
    "1q2w3e4r5t6y",
    "1qaz2wsx3edc",
    "abcdefghijkl",
    "abcdefghijklmnop",
    "adminadmin12",
    "administrator",
    "administrator1",
    "changemechangeme",
    "changeme1234",
    "correcthorsebatterystaple",
    "iloveyou1234",
    "letmein12345",
    "letmeinletmein",
    "mypassword123",
    "passw0rd1234",
    "password1234",
    "password12345",
    "password123456",
    "passwordpassword",
    "proxymind1234",
    "qazwsxedcrfv",
    "qwerty123456",
    "qwertyuiop12",
    "qwertyuiopas",
    "qwertyuiopasdfgh",
    "trustno1trustno1",
    "welcome12345",
    "welcome123456",
    "zxcvbnmasdfg",
];

/// Checks `password` against the policy for the account `username` (already normalised).
pub fn check_policy(password: &str, username: &str) -> Result<()> {
    let n = password.chars().count();
    if n < 12 {
        return Err(AccountError::WeakPassword("must be at least 12 characters"));
    }
    if n > 256 {
        return Err(AccountError::WeakPassword("must be at most 256 characters"));
    }
    let lower = password.to_lowercase();
    if !username.is_empty() && lower.contains(&username.to_lowercase()) {
        return Err(AccountError::WeakPassword("must not contain the username"));
    }
    let mut chars = password.chars();
    if let Some(first) = chars.next()
        && chars.all(|c| c == first)
    {
        return Err(AccountError::WeakPassword("must not be one character repeated"));
    }
    if COMMON.contains(&lower.as_str()) {
        return Err(AccountError::WeakPassword("is one of the most common passwords"));
    }
    Ok(())
}
