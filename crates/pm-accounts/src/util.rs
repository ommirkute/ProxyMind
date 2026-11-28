use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{AccountError, Result};

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    SystemRandom::new().fill(&mut out).map_err(|_| AccountError::Internal("the system random source failed".into()))?;
    Ok(out)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[usize::from(b >> 4)] as char);
        s.push(DIGITS[usize::from(b & 15)] as char);
    }
    s
}

pub(crate) fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// RFC 4648 base32, upper case, no padding.
pub(crate) fn base32(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buf >> bits) & 31) as usize] as char);
        }
        buf &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Compares without stopping at the first difference (lengths are not secret here).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && std::hint::black_box(a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y))) == 0
}

/// Cuts a client-supplied string to `max` characters.
pub(crate) fn clip(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// A secret value that is shown once (session id, pending sign-in token, invite, setup token). Never in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(pub(crate) String);

impl Secret {
    /// Wraps a value that must not be logged (a client secret on its way in).
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The value to hand to the person or client. Do not log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([redacted])")
    }
}
