//! HOTP (RFC 4226) and TOTP (RFC 6238) with SHA-1, which is what authenticator apps implement. SHA-1 is safe here:
//! it is only used inside HMAC.

use ring::hmac;

/// The HOTP value for `counter`, as a number below `10^digits`.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let h = tag.as_ref();
    let offset = usize::from(h[19] & 0x0f);
    let bin = u32::from_be_bytes([h[offset] & 0x7f, h[offset + 1], h[offset + 2], h[offset + 3]]);
    bin % 10u32.pow(digits)
}

/// The TOTP value at `unix_time` with a step of `step_secs`.
pub fn totp(secret: &[u8], unix_time: u64, step_secs: u64, digits: u32) -> u32 {
    hotp(secret, unix_time / step_secs, digits)
}

pub(crate) const STEP_SECS: i64 = 30;
pub(crate) const DIGITS: u32 = 6;

/// The code as it is typed: zero-padded to six digits.
pub(crate) fn format_code(n: u32) -> String {
    format!("{n:0width$}", width = DIGITS as usize)
}

/// What a person typed, with spaces and dashes removed; `None` unless exactly six digits.
pub(crate) fn normalise_code(input: &str) -> Option<String> {
    let s: String = input.chars().filter(|c| !c.is_whitespace() && *c != '-').collect();
    (s.len() == DIGITS as usize && s.bytes().all(|b| b.is_ascii_digit())).then_some(s)
}

/// The time steps accepted for `code` at `now`: the current step and one either side (clock skew). Returns the
/// matched step. All three candidates are always computed and compared.
pub(crate) fn match_step(secret: &[u8], code: &str, now: i64) -> Option<i64> {
    let code = normalise_code(code)?;
    let current = now.div_euclid(STEP_SECS);
    let mut found = None;
    for step in [current - 1, current, current + 1] {
        let Ok(counter) = u64::try_from(step) else { continue };
        let expected = format_code(hotp(secret, counter, DIGITS));
        if crate::util::ct_eq(expected.as_bytes(), code.as_bytes()) {
            found = Some(step);
        }
    }
    found
}

/// Percent-encodes everything outside the unreserved set.
fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The `otpauth://` URI authenticator apps read from a QR code.
pub(crate) fn otpauth_uri(issuer: &str, account: &str, secret_base32: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        pct(issuer),
        pct(account),
        secret_base32,
        pct(issuer),
        DIGITS,
        STEP_SECS
    )
}
