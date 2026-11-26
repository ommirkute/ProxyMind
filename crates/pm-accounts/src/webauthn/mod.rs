//! WebAuthn (W3C Web Authentication Level 3) verification, written for ProxyMind's needs and nothing more.
//!
//! **Why not a crate.** `webauthn-rs` no longer needs OpenSSL (0.6 uses RustCrypto), but it brings about 230 crates,
//! 96 of them new to this workspace, including a second cryptography stack (release-candidate `rsa`, `p256`, `ecdsa`)
//! next to `ring`, and x509 and attestation-statement code for attestation we never request. ADR-0003 prefers rustls
//! and ring, and ring already verifies everything WebAuthn needs: ES256, Ed25519 and RS256. What is left is a small
//! strict CBOR decoder ([`cbor`]), COSE key parsing ([`cose`]) and the checks of the specification, here.
//!
//! **What is verified** (registration and assertion), in this order:
//! 1. `clientDataJSON`: `type` is `webauthn.create` or `webauthn.get`; `challenge` equals the one the server issued
//!    for this ceremony (constant-time compare; the caller has made the challenge single use); `origin` is exactly
//!    one of the server's origins; `crossOrigin` is not true and there is no `topOrigin` (the page is not framed by
//!    another site).
//! 2. Authenticator data: `rpIdHash` is SHA-256 of the server's RP id; the user-present and user-verified flags are
//!    both set (the server always asks for user verification); backup state implies backup eligibility. For a
//!    registration the attested-credential-data flag is set and the credential id (16 to 1023 bytes) and COSE key are
//!    present; for an assertion it is not. The extension-data flag is honoured: when set, a CBOR item must follow and
//!    use up the rest; when clear, nothing may follow.
//! 3. The COSE key uses an algorithm in the allow-list (ES256, EdDSA, RS256).
//! 4. For an assertion, the signature over `authenticatorData || SHA-256(clientDataJSON)` verifies with the stored key.
//!
//! **Not verified:** the attestation statement. The server asks for attestation `none`, so the format and statement
//! are parsed (they must be well-formed CBOR) and ignored. The sign counter policy and the credential's owner are
//! the caller's (`passkeys.rs`), because they need the database.

pub mod cbor;
pub mod cose;
#[cfg(any(test, feature = "test-support"))]
pub mod soft;

use ring::digest;
use serde::Deserialize;

use crate::util::ct_eq;
use cbor::Value;
use cose::PublicKey;

/// User present.
pub const FLAG_UP: u8 = 0x01;
/// User verified.
pub const FLAG_UV: u8 = 0x04;
/// Backup eligible.
pub const FLAG_BE: u8 = 0x08;
/// Backup state.
pub const FLAG_BS: u8 = 0x10;
/// Attested credential data included.
pub const FLAG_AT: u8 = 0x40;
/// Extension data included.
pub const FLAG_ED: u8 = 0x80;

const MAX_CLIENT_DATA: usize = 8 * 1024;
const MAX_ATTESTATION_OBJECT: usize = 64 * 1024;
const MAX_AUTH_DATA: usize = 16 * 1024;
const MAX_SIGNATURE: usize = 1024;

/// Who the server is to an authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    /// The RP id: the server's host name (never an IP address), e.g. `pm.example.com`. Passkeys are bound to it.
    pub id: String,
    /// Shown by authenticators.
    pub name: String,
    /// The origins a browser may report in `clientDataJSON` (scheme, host and non-default port, no path), as
    /// `listen::plan()` computes them. Compared exactly.
    pub origins: Vec<String>,
}

/// Why a ceremony was refused. The short [`code`](Self::code) is safe to log; none of it is a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebAuthnError {
    /// Missing, oversized or not JSON.
    ClientData,
    WrongType,
    WrongChallenge,
    WrongOrigin,
    CrossOrigin,
    BadCbor,
    BadAuthData,
    WrongRpId,
    UserNotPresent,
    UserNotVerified,
    NoCredentialData,
    UnexpectedCredentialData,
    UnsupportedAlgorithm,
    BadKey,
    BadSignature,
}

impl WebAuthnError {
    pub fn code(self) -> &'static str {
        match self {
            Self::ClientData => "bad_client_data",
            Self::WrongType => "wrong_type",
            Self::WrongChallenge => "wrong_challenge",
            Self::WrongOrigin => "wrong_origin",
            Self::CrossOrigin => "cross_origin",
            Self::BadCbor => "bad_cbor",
            Self::BadAuthData => "bad_authenticator_data",
            Self::WrongRpId => "wrong_rp_id",
            Self::UserNotPresent => "user_not_present",
            Self::UserNotVerified => "user_not_verified",
            Self::NoCredentialData => "no_credential_data",
            Self::UnexpectedCredentialData => "unexpected_credential_data",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::BadKey => "bad_public_key",
            Self::BadSignature => "bad_signature",
        }
    }
}

impl WebAuthnError {
    /// A plain sentence for the person who sees the refusal.
    pub fn reason(self) -> &'static str {
        match self {
            Self::ClientData => "the client data is not valid",
            Self::WrongType => "the ceremony type is wrong",
            Self::WrongChallenge => "the challenge is not the one this server issued",
            Self::WrongOrigin => "the origin is not this server's address",
            Self::CrossOrigin => "a cross-origin request is refused",
            Self::BadCbor => "the attestation is not valid CBOR",
            Self::BadAuthData => "the authenticator data is not valid",
            Self::WrongRpId => "the relying party id is not this server's",
            Self::UserNotPresent => "the user was not present",
            Self::UserNotVerified => "the user was not verified (a PIN, biometric or similar is required)",
            Self::NoCredentialData => "the authenticator sent no credential",
            Self::UnexpectedCredentialData => "unexpected credential data in an assertion",
            Self::UnsupportedAlgorithm => "the passkey uses an algorithm this server does not accept",
            Self::BadKey => "the passkey's public key is not valid",
            Self::BadSignature => "the signature does not verify",
        }
    }
}

impl std::fmt::Display for WebAuthnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for WebAuthnError {}

// ---- base64url -------------------------------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// RFC 4648 base64url without padding (the form WebAuthn's JSON uses).
pub fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        let chars = chunk.len() + 1;
        for i in 0..chars {
            out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Strict decoding: the URL-safe alphabet only, no padding, no whitespace, and the unused bits must be zero.
pub fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let v = B64.iter().position(|b| *b == c)? as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    (buf == 0).then_some(out)
}

// ---- client data -----------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
    #[serde(rename = "topOrigin", default)]
    top_origin: Option<String>,
}

fn parse_client_data(json: &[u8]) -> Result<ClientData, WebAuthnError> {
    if json.is_empty() || json.len() > MAX_CLIENT_DATA {
        return Err(WebAuthnError::ClientData);
    }
    serde_json::from_slice(json).map_err(|_| WebAuthnError::ClientData)
}

/// The challenge a `clientDataJSON` claims (what the ceremony table is looked up by). Not a verification.
pub fn client_data_challenge(json: &[u8]) -> Option<Vec<u8>> {
    b64url_decode(&parse_client_data(json).ok()?.challenge)
}

fn check_client_data(
    rp: &RelyingParty,
    expected_type: &str,
    challenge: &[u8],
    json: &[u8],
) -> Result<(), WebAuthnError> {
    let cd = parse_client_data(json)?;
    if cd.kind != expected_type {
        return Err(WebAuthnError::WrongType);
    }
    let got = b64url_decode(&cd.challenge).ok_or(WebAuthnError::WrongChallenge)?;
    if !ct_eq(&got, challenge) {
        return Err(WebAuthnError::WrongChallenge);
    }
    if !rp.origins.contains(&cd.origin) {
        return Err(WebAuthnError::WrongOrigin);
    }
    if cd.cross_origin == Some(true) || cd.top_origin.is_some() {
        return Err(WebAuthnError::CrossOrigin);
    }
    Ok(())
}

// ---- authenticator data ----------------------------------------------------------------------------------------

/// The attested credential data of a registration.
#[derive(Debug, Clone)]
pub struct AttestedCredential {
    pub aaguid: [u8; 16],
    pub credential_id: Vec<u8>,
    /// The COSE_Key exactly as the authenticator sent it (what is stored).
    pub public_key_cose: Vec<u8>,
    pub key: PublicKey,
    pub alg: i64,
}

#[derive(Debug, Clone)]
pub struct AuthData {
    pub rp_id_hash: [u8; 32],
    pub flags: u8,
    pub sign_count: u32,
    pub attested: Option<AttestedCredential>,
}

impl AuthData {
    pub fn user_present(&self) -> bool {
        self.flags & FLAG_UP != 0
    }
    pub fn user_verified(&self) -> bool {
        self.flags & FLAG_UV != 0
    }
    pub fn backup_eligible(&self) -> bool {
        self.flags & FLAG_BE != 0
    }
    pub fn backup_state(&self) -> bool {
        self.flags & FLAG_BS != 0
    }
}

/// Parses authenticator data (WebAuthn section 6.1). Structure only: the callers check the flags and the hash.
pub fn parse_auth_data(data: &[u8], allowed_algs: &[i64]) -> Result<AuthData, WebAuthnError> {
    if data.len() < 37 || data.len() > MAX_AUTH_DATA {
        return Err(WebAuthnError::BadAuthData);
    }
    let rp_id_hash: [u8; 32] = data[..32].try_into().map_err(|_| WebAuthnError::BadAuthData)?;
    let flags = data[32];
    let sign_count = u32::from_be_bytes(data[33..37].try_into().map_err(|_| WebAuthnError::BadAuthData)?);
    // Backup state is only meaningful for an eligible credential.
    if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        return Err(WebAuthnError::BadAuthData);
    }
    let mut pos = 37;
    let mut attested = None;
    if flags & FLAG_AT != 0 {
        if data.len() < pos + 18 {
            return Err(WebAuthnError::BadAuthData);
        }
        let aaguid: [u8; 16] = data[pos..pos + 16].try_into().map_err(|_| WebAuthnError::BadAuthData)?;
        let id_len = usize::from(u16::from_be_bytes([data[pos + 16], data[pos + 17]]));
        pos += 18;
        // The specification allows 16 to 1023 bytes.
        if !(16..=1023).contains(&id_len) || data.len() < pos + id_len {
            return Err(WebAuthnError::BadAuthData);
        }
        let credential_id = data[pos..pos + id_len].to_vec();
        pos += id_len;
        let (cose, used) = cbor::decode_prefix(&data[pos..]).map_err(|_| WebAuthnError::BadCbor)?;
        let public_key_cose = data[pos..pos + used].to_vec();
        pos += used;
        let (key, alg) = PublicKey::from_cose(&cose, allowed_algs).map_err(|e| match e {
            cose::KeyError::Unsupported => WebAuthnError::UnsupportedAlgorithm,
            cose::KeyError::Malformed => WebAuthnError::BadKey,
        })?;
        attested = Some(AttestedCredential { aaguid, credential_id, public_key_cose, key, alg });
    }
    let rest = &data[pos..];
    if flags & FLAG_ED != 0 {
        // Extension data: one CBOR map that uses up the rest.
        match cbor::decode(rest) {
            Ok(Value::Map(_)) => {}
            _ => return Err(WebAuthnError::BadCbor),
        }
    } else if !rest.is_empty() {
        return Err(WebAuthnError::BadAuthData);
    }
    Ok(AuthData { rp_id_hash, flags, sign_count, attested })
}

pub fn rp_id_hash(rp_id: &str) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, rp_id.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

fn check_flags(rp: &RelyingParty, ad: &AuthData, require_uv: bool) -> Result<(), WebAuthnError> {
    if !ct_eq(&ad.rp_id_hash, &rp_id_hash(&rp.id)) {
        return Err(WebAuthnError::WrongRpId);
    }
    if !ad.user_present() {
        return Err(WebAuthnError::UserNotPresent);
    }
    // The server always asks for user verification, and a sign-in that skipped it is not accepted.
    if require_uv && !ad.user_verified() {
        return Err(WebAuthnError::UserNotVerified);
    }
    Ok(())
}

// ---- registration ----------------------------------------------------------------------------------------------

/// A verified registration, ready to store.
#[derive(Debug, Clone)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub public_key_cose: Vec<u8>,
    pub alg: i64,
    pub sign_count: u32,
    pub aaguid: [u8; 16],
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// Verifies the response of `navigator.credentials.create()` against the challenge the server issued.
pub fn verify_registration(
    rp: &RelyingParty,
    challenge: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
    allowed_algs: &[i64],
) -> Result<Registration, WebAuthnError> {
    check_client_data(rp, "webauthn.create", challenge, client_data_json)?;
    if attestation_object.is_empty() || attestation_object.len() > MAX_ATTESTATION_OBJECT {
        return Err(WebAuthnError::BadCbor);
    }
    let obj = cbor::decode(attestation_object).map_err(|_| WebAuthnError::BadCbor)?;
    // `fmt` and `attStmt` must be present and of the right shape; the statement is not verified (attestation none).
    if obj.get_text("fmt").and_then(Value::as_text).is_none() || !matches!(obj.get_text("attStmt"), Some(Value::Map(_)))
    {
        return Err(WebAuthnError::BadCbor);
    }
    let auth_data = obj.get_text("authData").and_then(Value::as_bytes).ok_or(WebAuthnError::BadCbor)?;
    let ad = parse_auth_data(auth_data, allowed_algs)?;
    check_flags(rp, &ad, true)?;
    let attested = ad.attested.clone().ok_or(WebAuthnError::NoCredentialData)?;
    Ok(Registration {
        credential_id: attested.credential_id,
        public_key_cose: attested.public_key_cose,
        alg: attested.alg,
        sign_count: ad.sign_count,
        aaguid: attested.aaguid,
        backup_eligible: ad.backup_eligible(),
        backup_state: ad.backup_state(),
    })
}

// ---- assertion -------------------------------------------------------------------------------------------------

/// What a verified assertion says. The caller applies the counter policy.
#[derive(Debug, Clone, Copy)]
pub struct Assertion {
    pub sign_count: u32,
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// Verifies the response of `navigator.credentials.get()` against the challenge and the stored COSE key.
pub fn verify_assertion(
    rp: &RelyingParty,
    challenge: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    stored_cose: &[u8],
) -> Result<Assertion, WebAuthnError> {
    verify_assertion_with(rp, challenge, client_data_json, authenticator_data, signature, stored_cose, true)
}

/// As [`verify_assertion`], with the user-verification requirement as a parameter so the tests can check the
/// signature of captured real-world assertions that predate it. The server itself always passes `true`.
fn verify_assertion_with(
    rp: &RelyingParty,
    challenge: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    stored_cose: &[u8],
    require_uv: bool,
) -> Result<Assertion, WebAuthnError> {
    check_client_data(rp, "webauthn.get", challenge, client_data_json)?;
    let ad = parse_auth_data(authenticator_data, &cose::ALLOWED_ALGS)?;
    check_flags(rp, &ad, require_uv)?;
    if ad.attested.is_some() {
        return Err(WebAuthnError::UnexpectedCredentialData);
    }
    if signature.is_empty() || signature.len() > MAX_SIGNATURE {
        return Err(WebAuthnError::BadSignature);
    }
    let cose = cbor::decode(stored_cose).map_err(|_| WebAuthnError::BadKey)?;
    let (key, _) = PublicKey::from_cose(&cose, &cose::ALLOWED_ALGS).map_err(|_| WebAuthnError::BadKey)?;
    let mut signed = authenticator_data.to_vec();
    signed.extend_from_slice(digest::digest(&digest::SHA256, client_data_json).as_ref());
    if !key.verify(&signed, signature) {
        return Err(WebAuthnError::BadSignature);
    }
    Ok(Assertion { sign_count: ad.sign_count, backup_eligible: ad.backup_eligible(), backup_state: ad.backup_state() })
}

#[cfg(test)]
mod tests;
