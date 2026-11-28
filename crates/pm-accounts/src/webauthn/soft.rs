//! A software authenticator for tests: what a browser and a platform authenticator would send, built in-process and
//! signed with ring. Only compiled for this crate's tests and with the `test-support` feature (`pm-api`'s tests use
//! it over a real socket). It can be told to misbehave ([`Tweak`]) so each refusal has a test.

use ring::digest;
use ring::rand::SystemRandom;
use ring::rsa::KeyPair as RsaKeyPair;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RSA_PKCS1_SHA256};
use serde_json::Value;

use super::cose::{EDDSA, ES256, RS256};
use super::{FLAG_AT, FLAG_BE, FLAG_BS, FLAG_ED, FLAG_UP, FLAG_UV, b64url_decode, b64url_encode, rp_id_hash};
use crate::passkeys::{AssertionResponse, RegistrationResponse};

/// A 2048-bit RSA key (PKCS#1 DER, base64) made for these tests only.
const RSA_TEST_KEY_B64: &str = concat!(
    "MIIEowIBAAKCAQEA6eyS/PgjTT3sonTqIHgOKaihjK9vrRfwSKGlQVquBxyDO0ij+tdIqwABzGMEPl76FbmOIwGgvkfolMCr",
    "gkqtYszUUFmhTGWMGkpza41fQO9cGK50lQAAk+qUXi0jX82UBuODXHgl86HwXgF+vYqYmzl/1Fc44UntMrBj9HO1pc/DIf3Q",
    "ms0vS1ChI9Y7aYhKp3DA8qxDvdy/sabEzzABjVEHqD5LLcoJVX0r5IXL5nVZ+54fjq9TSvHUAT9mQbpsbh7o8u7g5yXmL2tt",
    "Yts0onKQqP+xpS6NtedheF0OSLrteEfhmWdKCwB8aTe9UK9lMXesOqbBduEMUKUE6VRLqQIDAQABAoIBAAk22eVgCtfwkAEo",
    "NM65m+k1LMPjZzU8w6jAwUctQLyj+WFc76SiVUjzE58O6Wxhhl1TtU8YsdG8+GLfogHcWi8RnW1a0nk1aMriUuCSLYXbx9dr",
    "C8mQufUZoOWCxqlv6hxJWvPKAciygMrbKThjHLbEkY32L5XkORUtkIphAm85CBCyRi8LFn9UXGnGfLCiNafZtpvq2IYDp1CX",
    "fh78pGvSjSpQOflzeuQWGtxUgfN/aqZojLfLrN9elimK2mbwRxAfL77yBCaCLkEp+pnGsRk3LtGp6FjSGN5FhPQCH2lyPPf5",
    "a0wFfGkTiv/6Htef8iGZg9CqRSVwN1XLf2RdRQ8CgYEA+frRRSohUkGc73k6meQm9+vgTk3RUSvstD1vcVkO2pkR+cc2cyks",
    "08OOeXij0ba3LuUi+P95l3O6o6ndn6USMOV7zmavRBOR6OljqC6Vcrq3k4XqoADjcF1ZwhUYdOM+umdCiU4QYYPX3XtoZnEe",
    "rlL2glpQxtLrHMl8K4oqKrcCgYEA747FIA9pOBTfTbFDE/9doBO8oXzL1JX8aHLMGvAtm1SKUsOWtxOxKFMcRP81Zge99JAw",
    "XbYxc/Cn8FDvPkcbkFTljw5hHyExcNGVwF6JzG0VFCi2XPx1ZAP5izRauK1EbShJZXCZKKIjAqO4WbmOQmSQZOmZeyPzFQ/H",
    "ZhqGXJ8CgYBRwKZaAUo+dXjWlIYGuCfKYtjLowV2j2/tDj55ClAiS3cmgfEbvnaLluPsc/jXZ/MGoidK2XoxfsamKbJyOHD3",
    "jsVrngdpsyC/1DwkT3/OsqPA2kX+J+w53j2xjGagK4VjPsvyzZXr3ktlgquE/S+0gStfPBw4udfsZTR3pMrfhwKBgQCIJxzi",
    "m9+xgCtqfNUjCICt+om7PrKaoKRUuOpIZTmGjwYPBBsk8ow93v6yOFqhIsVTup/Co0p4Gs9YRqezPbbs0VOnewS4LKVs+bGj",
    "JBgtl9HjI0CCmPofXiL2e0sUq2W4pK0SemySK5S6a1LbrBquoXlv4VTaKBSAY/dwkKLNAQKBgEghZfJReQqtLKdUohReV2gf",
    "9g0cfnLwlZl7RWUZl0bqQnahpbXhPwrihh1bfajsALn5s3/DLPYz+vGRqvZQypZ7tCJ2WWRmFj3bR7OmiwGXxdjyDSQccwAP",
    "UfXfPmCo1XGSvWZKWkJdpErLuTyOj2/kYwZoLXH0Xv1ea6jSOiMt",
);

/// The test RSA key as PKCS#1 DER, for tests of crates above this one that need an RS256 signer (a fake OIDC provider).
pub fn rsa_test_key_der() -> Vec<u8> {
    base64_std(RSA_TEST_KEY_B64)
}

enum Key {
    Es(EcdsaKeyPair),
    Ed(Ed25519KeyPair),
    Rsa(RsaKeyPair),
}

/// Things a test can make go wrong. Every field defaults to the correct behaviour.
#[derive(Clone, Default)]
pub struct Tweak {
    /// Report this origin instead of the one asked for.
    pub origin: Option<String>,
    /// Hash this RP id instead of the options' one.
    pub rp_id: Option<String>,
    /// Put this (base64url) challenge in the client data.
    pub challenge: Option<String>,
    /// `type` in the client data.
    pub kind: Option<String>,
    pub no_user_present: bool,
    pub no_user_verified: bool,
    pub cross_origin: bool,
    pub top_origin: bool,
    /// Sign count to report (default: the authenticator's own counter, which grows by one per assertion).
    pub counter: Option<u32>,
    /// Flip a bit of the signature.
    pub bad_signature: bool,
    /// Append an extension-data map and set the ED flag.
    pub extension_data: bool,
    /// Append garbage after the authenticator data without setting ED.
    pub trailing_garbage: bool,
    /// Attestation format in the attestation object (default `none`).
    pub fmt: Option<String>,
    /// Do not send a user handle (a discoverable assertion normally carries one).
    pub no_user_handle: bool,
    /// Send this credential id instead of the real one (the `id` of the response and, in a registration, the
    /// attested one stays real).
    pub response_id: Option<String>,
}

pub struct SoftAuthenticator {
    key: Key,
    alg: i64,
    pub credential_id: Vec<u8>,
    /// The user handle the credential was made for (set by `create`).
    pub user_handle: Option<Vec<u8>>,
    pub counter: u32,
    pub aaguid: [u8; 16],
    pub backup_eligible: bool,
    pub backup_state: bool,
}

// ---- a tiny CBOR encoder ---------------------------------------------------------------------------------------

fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let m = major << 5;
    match n {
        0..=23 => out.push(m | n as u8),
        24..=0xff => out.extend([m | 24, n as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend((n as u16).to_be_bytes());
        }
        _ => {
            out.push(m | 26);
            out.extend((n as u32).to_be_bytes());
        }
    }
}

fn int(out: &mut Vec<u8>, v: i64) {
    if v >= 0 { head(out, 0, v as u64) } else { head(out, 1, (-1 - v) as u64) }
}

fn bytes(out: &mut Vec<u8>, b: &[u8]) {
    head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

fn text(out: &mut Vec<u8>, t: &str) {
    head(out, 3, t.len() as u64);
    out.extend_from_slice(t.as_bytes());
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    ring::rand::SecureRandom::fill(&SystemRandom::new(), &mut b).expect("system randomness");
    b
}

impl SoftAuthenticator {
    pub fn es256() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("keygen");
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).expect("key");
        Self::with(Key::Es(key), ES256)
    }

    pub fn ed25519() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("keygen");
        Self::with(Key::Ed(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("key")), EDDSA)
    }

    pub fn rs256() -> Self {
        let der = base64_std(RSA_TEST_KEY_B64);
        Self::with(Key::Rsa(RsaKeyPair::from_der(&der).expect("the test RSA key")), RS256)
    }

    fn with(key: Key, alg: i64) -> Self {
        Self {
            key,
            alg,
            credential_id: rand_bytes::<32>().to_vec(),
            user_handle: None,
            counter: 0,
            aaguid: [0xa1; 16],
            backup_eligible: false,
            backup_state: false,
        }
    }

    pub fn alg(&self) -> i64 {
        self.alg
    }

    fn cose_key(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match &self.key {
            Key::Es(k) => {
                let p = k.public_key().as_ref();
                head(&mut out, 5, 5);
                int(&mut out, 1);
                int(&mut out, 2);
                int(&mut out, 3);
                int(&mut out, ES256);
                int(&mut out, -1);
                int(&mut out, 1);
                int(&mut out, -2);
                bytes(&mut out, &p[1..33]);
                int(&mut out, -3);
                bytes(&mut out, &p[33..65]);
            }
            Key::Ed(k) => {
                head(&mut out, 5, 4);
                int(&mut out, 1);
                int(&mut out, 1);
                int(&mut out, 3);
                int(&mut out, EDDSA);
                int(&mut out, -1);
                int(&mut out, 6);
                int(&mut out, -2);
                bytes(&mut out, k.public_key().as_ref());
            }
            Key::Rsa(k) => {
                let (n, e) = rsa_components(k.public().as_ref());
                head(&mut out, 5, 4);
                int(&mut out, 1);
                int(&mut out, 3);
                int(&mut out, 3);
                int(&mut out, RS256);
                int(&mut out, -1);
                bytes(&mut out, &n);
                int(&mut out, -2);
                bytes(&mut out, &e);
            }
        }
        out
    }

    /// The COSE key this authenticator registers (tests compare it with what the server stored).
    pub fn public_key_cose(&self) -> Vec<u8> {
        self.cose_key()
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        match &self.key {
            Key::Es(k) => k.sign(&rng, msg).expect("sign").as_ref().to_vec(),
            Key::Ed(k) => k.sign(msg).as_ref().to_vec(),
            Key::Rsa(k) => {
                let mut sig = vec![0u8; k.public().modulus_len()];
                k.sign(&RSA_PKCS1_SHA256, &rng, msg, &mut sig).expect("sign");
                sig
            }
        }
    }

    fn flags(&self, t: &Tweak, attested: bool) -> u8 {
        let mut f = 0;
        if !t.no_user_present {
            f |= FLAG_UP;
        }
        if !t.no_user_verified {
            f |= FLAG_UV;
        }
        if self.backup_eligible {
            f |= FLAG_BE;
        }
        if self.backup_state {
            f |= FLAG_BS;
        }
        if attested {
            f |= FLAG_AT;
        }
        if t.extension_data {
            f |= FLAG_ED;
        }
        f
    }

    fn client_data(&self, kind: &str, options: &Value, origin: &str, t: &Tweak) -> Vec<u8> {
        let challenge = t.challenge.clone().unwrap_or_else(|| options["challenge"].as_str().unwrap_or_default().into());
        let mut v = serde_json::json!({
            "type": t.kind.clone().unwrap_or_else(|| kind.to_string()),
            "challenge": challenge,
            "origin": t.origin.clone().unwrap_or_else(|| origin.to_string()),
            "crossOrigin": t.cross_origin,
        });
        if t.top_origin {
            v["topOrigin"] = Value::String("https://top.example".into());
        }
        v.to_string().into_bytes()
    }

    fn auth_data(&self, rp_id: &str, flags: u8, counter: u32, attested: Option<&[u8]>, t: &Tweak) -> Vec<u8> {
        let mut out = rp_id_hash(&t.rp_id.clone().unwrap_or_else(|| rp_id.to_string())).to_vec();
        out.push(flags);
        out.extend(counter.to_be_bytes());
        if let Some(cose) = attested {
            out.extend(self.aaguid);
            out.extend((self.credential_id.len() as u16).to_be_bytes());
            out.extend(&self.credential_id);
            out.extend(cose);
        }
        if t.extension_data {
            head(&mut out, 5, 1);
            text(&mut out, "credProtect");
            int(&mut out, 1);
        }
        if t.trailing_garbage {
            out.extend([0xde, 0xad]);
        }
        out
    }

    /// `navigator.credentials.create()` for the `options` the server sent (as JSON), from a page at `origin`.
    pub fn create(&mut self, options: &Value, origin: &str, t: &Tweak) -> RegistrationResponse {
        let rp_id = options["rp"]["id"].as_str().unwrap_or_default().to_string();
        self.user_handle = options["user"]["id"].as_str().and_then(b64url_decode);
        let client_data = self.client_data("webauthn.create", options, origin, t);
        let cose = self.cose_key();
        let counter = t.counter.unwrap_or(self.counter);
        let auth_data = self.auth_data(&rp_id, self.flags(t, true), counter, Some(&cose), t);
        let mut obj = Vec::new();
        head(&mut obj, 5, 3);
        text(&mut obj, "fmt");
        text(&mut obj, t.fmt.as_deref().unwrap_or("none"));
        text(&mut obj, "attStmt");
        head(&mut obj, 5, 0);
        text(&mut obj, "authData");
        bytes(&mut obj, &auth_data);
        RegistrationResponse {
            id: t.response_id.clone().unwrap_or_else(|| b64url_encode(&self.credential_id)),
            client_data_json: b64url_encode(&client_data),
            attestation_object: b64url_encode(&obj),
            transports: vec!["internal".into()],
        }
    }

    /// `navigator.credentials.get()` for the `options` the server sent (as JSON), from a page at `origin`.
    pub fn get(&mut self, options: &Value, origin: &str, t: &Tweak) -> AssertionResponse {
        let rp_id = options["rpId"].as_str().unwrap_or_default().to_string();
        let client_data = self.client_data("webauthn.get", options, origin, t);
        self.counter = self.counter.wrapping_add(1);
        let counter = t.counter.unwrap_or(self.counter);
        let auth_data = self.auth_data(&rp_id, self.flags(t, false), counter, None, t);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(digest::digest(&digest::SHA256, &client_data).as_ref());
        let mut sig = self.sign(&signed);
        if t.bad_signature {
            let last = sig.len() - 1;
            sig[last] ^= 1;
        }
        AssertionResponse {
            id: t.response_id.clone().unwrap_or_else(|| b64url_encode(&self.credential_id)),
            client_data_json: b64url_encode(&client_data),
            authenticator_data: b64url_encode(&auth_data),
            signature: b64url_encode(&sig),
            user_handle: if t.no_user_handle { None } else { self.user_handle.as_deref().map(b64url_encode) },
        }
    }
}

/// `n` and `e` (big-endian, no leading zero) out of an `RSAPublicKey` DER.
fn rsa_components(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn len(d: &[u8], pos: &mut usize) -> usize {
        let b = d[*pos];
        *pos += 1;
        if b < 0x80 {
            return usize::from(b);
        }
        let n = usize::from(b & 0x7f);
        let v = d[*pos..*pos + n].iter().fold(0usize, |a, x| (a << 8) | usize::from(*x));
        *pos += n;
        v
    }
    let mut pos = 1; // SEQUENCE
    len(der, &mut pos);
    let mut ints = Vec::new();
    for _ in 0..2 {
        assert_eq!(der[pos], 0x02);
        pos += 1;
        let l = len(der, &mut pos);
        let v = &der[pos..pos + l];
        pos += l;
        let start = v.iter().position(|b| *b != 0).unwrap_or(v.len());
        ints.push(v[start..].to_vec());
    }
    let e = ints.pop().unwrap();
    (ints.pop().unwrap(), e)
}

/// Standard base64 (with padding), for the embedded test key.
fn base64_std(s: &str) -> Vec<u8> {
    let (mut buf, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.bytes().filter(|c| *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("not base64"),
        };
        buf = (buf << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}
