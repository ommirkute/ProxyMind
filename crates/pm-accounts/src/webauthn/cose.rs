//! COSE public keys (RFC 9052/9053) as WebAuthn uses them, and signature verification with ring.
//!
//! Algorithms: **ES256** (ECDSA with P-256 and SHA-256, ASN.1 DER signatures; what nearly every authenticator
//! offers), **EdDSA** (Ed25519) and **RS256** (RSASSA-PKCS1-v1_5 with SHA-256, modulus 2048 to 8192 bits; some
//! Windows Hello configurations). Nothing else is accepted, so a server never verifies with an algorithm nobody
//! chose for it.

use ring::signature::{self, UnparsedPublicKey};

use super::cbor::Value;

/// COSE algorithm identifiers.
pub const ES256: i64 = -7;
pub const EDDSA: i64 = -8;
pub const RS256: i64 = -257;

/// What the server offers and accepts, most preferred first.
pub const ALLOWED_ALGS: [i64; 3] = [ES256, EDDSA, RS256];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    /// An uncompressed P-256 point, `0x04 || x || y`.
    Es256([u8; 65]),
    Ed25519([u8; 32]),
    /// `RSAPublicKey` DER (`SEQUENCE { n, e }`), as ring wants it.
    Rs256(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// Not a COSE_Key map, or a field is missing or of the wrong type.
    Malformed,
    /// A well-formed key of an algorithm, curve or size we do not accept.
    Unsupported,
}

impl PublicKey {
    /// Reads a COSE_Key and checks that its algorithm is in `allowed`.
    pub fn from_cose(key: &Value, allowed: &[i64]) -> Result<(Self, i64), KeyError> {
        if !matches!(key, Value::Map(_)) {
            return Err(KeyError::Malformed);
        }
        let kty = key.get_int(1).and_then(Value::as_int).ok_or(KeyError::Malformed)?;
        let alg = key.get_int(3).and_then(Value::as_int).ok_or(KeyError::Malformed)?;
        if !allowed.contains(&alg) {
            return Err(KeyError::Unsupported);
        }
        let bytes = |label: i64| key.get_int(label).and_then(Value::as_bytes).ok_or(KeyError::Malformed);
        match (alg, kty) {
            // EC2, P-256.
            (ES256, 2) => {
                if key.get_int(-1).and_then(Value::as_int) != Some(1) {
                    return Err(KeyError::Unsupported);
                }
                let (x, y) = (bytes(-2)?, bytes(-3)?);
                if x.len() != 32 || y.len() != 32 {
                    return Err(KeyError::Malformed);
                }
                let mut point = [0u8; 65];
                point[0] = 4;
                point[1..33].copy_from_slice(x);
                point[33..].copy_from_slice(y);
                Ok((PublicKey::Es256(point), alg))
            }
            // OKP, Ed25519.
            (EDDSA, 1) => {
                if key.get_int(-1).and_then(Value::as_int) != Some(6) {
                    return Err(KeyError::Unsupported);
                }
                let x: [u8; 32] = bytes(-2)?.try_into().map_err(|_| KeyError::Malformed)?;
                Ok((PublicKey::Ed25519(x), alg))
            }
            // RSA.
            (RS256, 3) => {
                let (n, e) = (strip_zeros(bytes(-1)?), strip_zeros(bytes(-2)?));
                // ring accepts 2048 to 8192 bits; the exponent must be a small odd number (65537 in practice).
                if !(256..=1024).contains(&n.len())
                    || n[0] == 0
                    || e.is_empty()
                    || e.len() > 4
                    || e[e.len() - 1] & 1 == 0
                {
                    return Err(KeyError::Unsupported);
                }
                Ok((PublicKey::Rs256(rsa_public_key_der(n, e)), alg))
            }
            _ => Err(KeyError::Unsupported),
        }
    }

    /// True when `sig` is a valid signature of `msg` under this key.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self {
            PublicKey::Es256(point) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, point.as_slice()).verify(msg, sig).is_ok()
            }
            PublicKey::Ed25519(x) => UnparsedPublicKey::new(&signature::ED25519, x.as_slice()).verify(msg, sig).is_ok(),
            PublicKey::Rs256(der) => {
                UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, der.as_slice()).verify(msg, sig).is_ok()
            }
        }
    }
}

fn strip_zeros(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|v| *v != 0).unwrap_or(b.len());
    &b[i..]
}

fn der_len(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.extend([0x81, len as u8]);
    } else {
        out.extend([0x82, (len >> 8) as u8, len as u8]);
    }
}

fn der_uint(out: &mut Vec<u8>, v: &[u8]) {
    out.push(0x02);
    let pad = v.first().is_some_and(|b| b & 0x80 != 0);
    der_len(out, v.len() + usize::from(pad));
    if pad {
        out.push(0);
    }
    out.extend_from_slice(v);
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }` from big-endian `n` and `e`.
pub(crate) fn rsa_public_key_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(n.len() + e.len() + 12);
    der_uint(&mut body, n);
    der_uint(&mut body, e);
    let mut out = vec![0x30];
    der_len(&mut out, body.len());
    out.extend(body);
    out
}
