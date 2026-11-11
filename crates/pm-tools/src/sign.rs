//! Ed25519 signing for evidence packs: a key per installation signs a pack's
//! manifest; anyone with the pack checks it against the public key it
//! carries, and the person who received it compares the key's fingerprint
//! with the one the tester gave them. No I/O.

use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

/// A new private key (PKCS#8 bytes).
pub fn generate() -> Result<Vec<u8>, String> {
    Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map(|d| d.as_ref().to_vec())
        .map_err(|_| "key generation failed".into())
}

/// The public key of a PKCS#8 private key.
pub fn public_key(pkcs8: &[u8]) -> Result<Vec<u8>, String> {
    Ok(Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| "bad signing key".to_string())?.public_key().as_ref().to_vec())
}

pub fn sign(pkcs8: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    Ok(Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| "bad signing key".to_string())?.sign(msg).as_ref().to_vec())
}

pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    UnparsedPublicKey::new(&ED25519, public_key).verify(msg, sig).is_ok()
}

/// A short, readable fingerprint of a public key: the first 16 bytes of its
/// SHA-256, in groups of four hex digits.
pub fn fingerprint(public_key: &[u8]) -> String {
    let d = ring::digest::digest(&ring::digest::SHA256, public_key);
    let hex: String = d.as_ref()[..16].iter().map(|b| format!("{b:02x}")).collect();
    hex.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(":")
}

/// SHA-256 of `data`, as hex.
pub fn sha256_hex(data: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, data).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_and_verifies() {
        let k = generate().unwrap();
        let pk = public_key(&k).unwrap();
        let sig = sign(&k, b"manifest").unwrap();
        assert!(verify(&pk, b"manifest", &sig));
        assert!(!verify(&pk, b"manifest!", &sig));
        let other = public_key(&generate().unwrap()).unwrap();
        assert!(!verify(&other, b"manifest", &sig));
        assert_eq!(fingerprint(&pk).len(), 39);
        assert_eq!(sha256_hex(b"").len(), 64);
    }
}
