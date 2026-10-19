//! Sealing project files with a passphrase.
//!
//! A project holds a client's traffic, credentials and findings. `seal`
//! turns it into a `.pmlock` file that is safe to store or hand over;
//! `open` turns it back. Format (all integers big-endian):
//!
//! ```text
//! header  "PMLOCK1\0" | version u8 = 1 | m_kib u32 | t u32 | p u32 | salt [16] | nonce_prefix [7]
//! chunks  repeated: len u32 | ciphertext+tag (len bytes)
//! ```
//!
//! The key comes from Argon2id over the passphrase and salt. Each chunk
//! (1 MiB of plaintext) is sealed with ChaCha20-Poly1305 under the nonce
//! `nonce_prefix | counter u32 | last u8`, with the whole header as
//! associated data. So chunks can't be reordered, dropped, truncated or
//! moved between files, and the KDF parameters can't be swapped, without
//! decryption failing. Wrong passphrases and tampering look the same.

use std::io::{Read, Write};

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

const MAGIC: &[u8; 8] = b"PMLOCK1\0";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 8 + 1 + 12 + 16 + 7;
const CHUNK: usize = 1 << 20;
const TAG: usize = 16;

/// Argon2id cost. The defaults take about a second on a laptop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cost {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Cost {
    fn default() -> Self {
        Cost { memory_kib: 64 * 1024, iterations: 3, parallelism: 1 }
    }
}

impl Cost {
    /// Cheap settings for tests only.
    pub fn insecure_for_tests() -> Self {
        Cost { memory_kib: 64, iterations: 1, parallelism: 1 }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("not a ProxyMind locked project")]
    NotLocked,
    #[error("unsupported locked-project version {0}")]
    Version(u8),
    #[error("wrong passphrase, or the file was changed or cut short")]
    Decrypt,
    #[error("the passphrase must be at least 12 characters")]
    WeakPassphrase,
    #[error("unreasonable key-derivation settings in the file")]
    BadCost,
    #[error("no system randomness")]
    Random,
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;

fn derive(passphrase: &str, salt: &[u8], cost: Cost) -> Result<LessSafeKey> {
    let params = argon2::Params::new(cost.memory_kib, cost.iterations, cost.parallelism, Some(32))
        .map_err(|e| VaultError::Kdf(e.to_string()))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; 32];
    a.hash_password_into(passphrase.as_bytes(), salt, &mut key).map_err(|e| VaultError::Kdf(e.to_string()))?;
    let k = UnboundKey::new(&CHACHA20_POLY1305, &key).map_err(|_| VaultError::Kdf("bad key".into()))?;
    key.fill(0);
    Ok(LessSafeKey::new(k))
}

fn nonce(prefix: &[u8; 7], counter: u32, last: bool) -> Nonce {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(last);
    Nonce::assume_unique_for_key(n)
}

/// Reads up to `buf.len()` bytes, stopping early only at end of input.
fn fill(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..])? {
            0 => break,
            k => n += k,
        }
    }
    Ok(n)
}

/// Encrypts everything from `input` into `output`.
pub fn seal(input: &mut impl Read, output: &mut impl Write, passphrase: &str, cost: Cost) -> Result<u64> {
    if passphrase.chars().count() < 12 {
        return Err(VaultError::WeakPassphrase);
    }
    let rng = SystemRandom::new();
    let mut salt = [0u8; 16];
    let mut prefix = [0u8; 7];
    rng.fill(&mut salt).map_err(|_| VaultError::Random)?;
    rng.fill(&mut prefix).map_err(|_| VaultError::Random)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    for v in [cost.memory_kib, cost.iterations, cost.parallelism] {
        header.extend_from_slice(&v.to_be_bytes());
    }
    header.extend_from_slice(&salt);
    header.extend_from_slice(&prefix);
    output.write_all(&header)?;
    let key = derive(passphrase, &salt, cost)?;

    // Read one chunk ahead so the last one can be marked.
    let mut cur = vec![0u8; CHUNK];
    let mut next = vec![0u8; CHUNK];
    let mut cur_len = fill(input, &mut cur)?;
    let mut counter: u32 = 0;
    let mut total = 0u64;
    loop {
        let next_len = if cur_len == CHUNK { fill(input, &mut next)? } else { 0 };
        let last = next_len == 0;
        let mut block = cur[..cur_len].to_vec();
        key.seal_in_place_append_tag(nonce(&prefix, counter, last), Aad::from(&header), &mut block)
            .map_err(|_| VaultError::Decrypt)?;
        output.write_all(&(block.len() as u32).to_be_bytes())?;
        output.write_all(&block)?;
        total += cur_len as u64;
        if last {
            break;
        }
        counter = counter.checked_add(1).ok_or(VaultError::Decrypt)?;
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
    }
    cur.fill(0);
    next.fill(0);
    output.flush()?;
    Ok(total)
}

/// Whether `head` (the first bytes of a file) looks like a sealed project.
pub fn is_sealed(head: &[u8]) -> bool {
    head.starts_with(MAGIC)
}

/// Decrypts a sealed stream into `output`. On any error, discard what was
/// written: it isn't authenticated as a whole until the last chunk opens.
pub fn open(input: &mut impl Read, output: &mut impl Write, passphrase: &str) -> Result<u64> {
    let mut header = [0u8; HEADER_LEN];
    if fill(input, &mut header)? != HEADER_LEN || !is_sealed(&header) {
        return Err(VaultError::NotLocked);
    }
    if header[8] != VERSION {
        return Err(VaultError::Version(header[8]));
    }
    let word = |i: usize| u32::from_be_bytes(header[9 + 4 * i..13 + 4 * i].try_into().unwrap_or_default());
    let cost = Cost { memory_kib: word(0), iterations: word(1), parallelism: word(2) };
    // Refuse settings that would make opening a hostile file hang or eat memory.
    if cost.memory_kib > 4 * 1024 * 1024 || cost.iterations > 100 || cost.parallelism > 64 || cost.iterations == 0 {
        return Err(VaultError::BadCost);
    }
    let salt = &header[21..37];
    let mut prefix = [0u8; 7];
    prefix.copy_from_slice(&header[37..44]);
    let key = derive(passphrase, salt, cost)?;
    let mut counter: u32 = 0;
    let mut total = 0u64;
    loop {
        let mut len = [0u8; 4];
        if fill(input, &mut len)? != 4 {
            return Err(VaultError::Decrypt); // cut short before the last chunk
        }
        let len = u32::from_be_bytes(len) as usize;
        if !(TAG..=CHUNK + TAG).contains(&len) {
            return Err(VaultError::Decrypt);
        }
        let mut block = vec![0u8; len];
        if fill(input, &mut block)? != len {
            return Err(VaultError::Decrypt);
        }
        // Try as an inner chunk, then as the last one.
        let mut copy = block.clone();
        let (plain, last) = match key.open_in_place(nonce(&prefix, counter, false), Aad::from(&header), &mut block) {
            Ok(p) => (p.to_vec(), false),
            Err(_) => match key.open_in_place(nonce(&prefix, counter, true), Aad::from(&header), &mut copy) {
                Ok(p) => (p.to_vec(), true),
                Err(_) => return Err(VaultError::Decrypt),
            },
        };
        output.write_all(&plain)?;
        total += plain.len() as u64;
        if last {
            let mut extra = [0u8; 1];
            if fill(input, &mut extra)? != 0 {
                return Err(VaultError::Decrypt); // data after the last chunk
            }
            break;
        }
        counter = counter.checked_add(1).ok_or(VaultError::Decrypt)?;
    }
    output.flush()?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "correct horse battery";

    fn roundtrip(data: &[u8]) -> Vec<u8> {
        let mut sealed = Vec::new();
        seal(&mut &data[..], &mut sealed, PW, Cost::insecure_for_tests()).unwrap();
        assert!(is_sealed(&sealed));
        let mut out = Vec::new();
        open(&mut &sealed[..], &mut out, PW).unwrap();
        out
    }

    #[test]
    fn roundtrips_any_size() {
        for n in [0, 1, 1000, CHUNK - 1, CHUNK, CHUNK + 1, 2 * CHUNK + 7] {
            let data: Vec<u8> = (0..n).map(|i| (i * 31 % 251) as u8).collect();
            assert_eq!(roundtrip(&data), data, "size {n}");
        }
    }

    fn sealed(n: usize) -> Vec<u8> {
        let data = vec![7u8; n];
        let mut out = Vec::new();
        seal(&mut &data[..], &mut out, PW, Cost::insecure_for_tests()).unwrap();
        out
    }

    fn opens(bytes: &[u8], pw: &str) -> bool {
        open(&mut &bytes[..], &mut Vec::new(), pw).is_ok()
    }

    #[test]
    fn rejects_wrong_passphrase_tampering_and_truncation() {
        let s = sealed(CHUNK + 100);
        assert!(opens(&s, PW));
        assert!(!opens(&s, "wrong passphrase!!"));
        let mut flipped = s.clone();
        let i = flipped.len() / 2;
        flipped[i] ^= 1;
        assert!(!opens(&flipped, PW), "tampered body");
        let mut header = s.clone();
        header[12] ^= 1; // KDF settings are authenticated
        assert!(!opens(&header, PW));
        // Cut after the first chunk: the missing last chunk is detected.
        let first = HEADER_LEN + 4 + CHUNK + TAG;
        assert!(!opens(&s[..first], PW), "truncated at a chunk boundary");
        assert!(!opens(&s[..s.len() - 1], PW));
        let mut extra = s.clone();
        extra.push(0);
        assert!(!opens(&extra, PW), "trailing data");
        // Chunks from another file don't fit.
        let other = sealed(CHUNK + 100);
        let mut spliced = s[..first].to_vec();
        spliced.extend_from_slice(&other[first..]);
        assert!(!opens(&spliced, PW));
    }

    #[test]
    fn refuses_weak_passphrases_and_garbage() {
        let r = seal(&mut &b"x"[..], &mut Vec::new(), "short", Cost::insecure_for_tests());
        assert!(matches!(r, Err(VaultError::WeakPassphrase)));
        assert!(matches!(open(&mut &b"SQLite format 3\0"[..], &mut Vec::new(), PW), Err(VaultError::NotLocked)));
        let mut hostile = sealed(10);
        hostile[9..13].copy_from_slice(&u32::MAX.to_be_bytes()); // absurd memory cost
        assert!(matches!(open(&mut &hostile[..], &mut Vec::new(), PW), Err(VaultError::BadCost)));
    }
}
