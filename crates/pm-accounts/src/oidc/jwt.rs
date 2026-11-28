//! ID tokens and JSON Web Keys (RFC 7515/7517/7519, OpenID Connect Core 3.1.3.7), verified with ring. Pure: bytes in,
//! a verdict out. Nothing here fetches anything; the caller hands over the keys it got from the provider's `jwks_uri`
//! (the one named by the *discovery document*, never by the token).
//!
//! * **Algorithms:** `RS256` (RSA 2048 to 8192 bits), `ES256` (P-256, raw `r || s` signature) and `EdDSA` (Ed25519).
//!   Anything else is refused: `none`, every `HS*` (a token "signed" with the client secret as an HMAC key), `PS*`,
//!   `RS384`, ... The algorithm comes from the token's header, but it only ever selects among keys of that very
//!   algorithm: a key's type fixes its algorithm (RSA is `RS256`, an EC P-256 key `ES256`, an Ed25519 OKP key `EdDSA`),
//!   and a JWK that names another `alg` is not used.
//! * **Header:** `jku`, `x5u`, `jwk` and `x5c` are ignored (never followed, never trusted); `crit` makes the token
//!   invalid (we understand no critical extension).
//! * **Claims:** `iss` exactly the configured issuer; `aud` contains the client id; `azp`, when present, is the client
//!   id (OIDC Core 3.1.3.7 step 4 and 5); `exp` and `iat` required (60 s of clock skew; `iat` not in the future);
//!   `nbf` honoured when present; `nonce` equals the one stored for this sign-in; `sub` present and short; optional
//!   `acr` / `amr` requirements.

use ring::signature::{self, UnparsedPublicKey};
use serde_json::Value;

use crate::util::ct_eq;
use crate::webauthn::b64url_decode;
use crate::webauthn::cose::rsa_public_key_der;

/// An ID token longer than this is refused unread.
pub const MAX_TOKEN_BYTES: usize = 64 * 1024;
/// A JWKS with more usable keys than this is cut (a provider has a handful).
pub const MAX_KEYS: usize = 64;
/// Seconds of clock difference tolerated for `exp`, `iat` and `nbf`.
pub const CLOCK_SKEW: i64 = 60;
const MAX_GROUPS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Rs256,
    Es256,
    EdDsa,
}

impl Alg {
    /// Only the three names in the allow-list; `None` for `none`, `HS256`, `PS256`, ... and anything else.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "RS256" => Some(Alg::Rs256),
            "ES256" => Some(Alg::Es256),
            "EdDSA" => Some(Alg::EdDsa),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Alg::Rs256 => "RS256",
            Alg::Es256 => "ES256",
            Alg::EdDsa => "EdDSA",
        }
    }
}

#[derive(Clone)]
enum Material {
    /// `RSAPublicKey` DER.
    Rsa(Vec<u8>),
    /// Uncompressed P-256 point.
    Ec([u8; 65]),
    Okp([u8; 32]),
}

/// One usable public key from a JWKS.
#[derive(Clone)]
pub struct JwkKey {
    pub kid: Option<String>,
    pub alg: Alg,
    material: Material,
}

impl std::fmt::Debug for JwkKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwkKey").field("kid", &self.kid).field("alg", &self.alg).finish()
    }
}

impl JwkKey {
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match &self.material {
            Material::Rsa(der) => {
                UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, der.as_slice()).verify(msg, sig).is_ok()
            }
            // JWS ES256 is the fixed-size `r || s`, not DER.
            Material::Ec(point) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point.as_slice()).verify(msg, sig).is_ok()
            }
            Material::Okp(x) => UnparsedPublicKey::new(&signature::ED25519, x.as_slice()).verify(msg, sig).is_ok(),
        }
    }
}

/// Why a token or a key set was refused. The words go to the security log; they hold no token content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtError {
    /// Not a three-part compact JWS, bad base64url or JSON, or too large.
    Malformed,
    /// The header's `alg` is not in the allow-list (including `none` and `HS*`), or it carries `crit`.
    UnsupportedAlg,
    /// No key of that algorithm with the header's `kid` is known: the caller may refetch the key set once.
    UnknownKey,
    /// A key with that `kid` exists but is for another algorithm.
    AlgMismatch,
    BadSignature,
    /// A claim is missing or wrong; the word names which.
    Claim(&'static str),
}

impl JwtError {
    pub fn reason(self) -> &'static str {
        match self {
            JwtError::Malformed => "malformed token",
            JwtError::UnsupportedAlg => "algorithm not allowed",
            JwtError::UnknownKey => "unknown signing key",
            JwtError::AlgMismatch => "key and algorithm differ",
            JwtError::BadSignature => "bad signature",
            JwtError::Claim(c) => c,
        }
    }
}

// ---- keys ------------------------------------------------------------------------------------------------------

fn strip_zeros(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|v| *v != 0).unwrap_or(b.len());
    &b[i..]
}

fn field(k: &Value, name: &str) -> Option<Vec<u8>> {
    b64url_decode(k.get(name)?.as_str()?)
}

fn one_key(k: &Value) -> Option<JwkKey> {
    let kty = k.get("kty")?.as_str()?;
    // A key meant for encryption is not a signing key.
    if k.get("use").is_some_and(|u| u.as_str() != Some("sig")) {
        return None;
    }
    if let Some(ops) = k.get("key_ops").and_then(Value::as_array)
        && !ops.iter().any(|o| o.as_str() == Some("verify"))
    {
        return None;
    }
    let declared = k.get("alg").map(|a| a.as_str().and_then(Alg::parse));
    let kid = k.get("kid").and_then(Value::as_str).filter(|s| s.len() <= 256).map(str::to_string);
    let (alg, material) = match kty {
        "RSA" => {
            let (n, e) = (field(k, "n")?, field(k, "e")?);
            let (n, e) = (strip_zeros(&n), strip_zeros(&e));
            if !(256..=1024).contains(&n.len()) || e.is_empty() || e.len() > 4 || e[e.len() - 1] & 1 == 0 {
                return None;
            }
            (Alg::Rs256, Material::Rsa(rsa_public_key_der(n, e)))
        }
        "EC" => {
            if k.get("crv")?.as_str()? != "P-256" {
                return None;
            }
            let (x, y) = (field(k, "x")?, field(k, "y")?);
            if x.len() != 32 || y.len() != 32 {
                return None;
            }
            let mut point = [0u8; 65];
            point[0] = 4;
            point[1..33].copy_from_slice(&x);
            point[33..].copy_from_slice(&y);
            (Alg::Es256, Material::Ec(point))
        }
        "OKP" => {
            if k.get("crv")?.as_str()? != "Ed25519" {
                return None;
            }
            let x: [u8; 32] = field(k, "x")?.try_into().ok()?;
            (Alg::EdDsa, Material::Okp(x))
        }
        _ => return None,
    };
    // A JWK that names a different algorithm than its key type allows (or one we do not accept) is not used.
    if let Some(d) = declared
        && d != Some(alg)
    {
        return None;
    }
    Some(JwkKey { kid, alg, material })
}

/// The usable keys of a JWKS document. Keys of other types, curves, sizes or uses are skipped, not an error.
pub fn parse_jwks(bytes: &[u8]) -> Result<Vec<JwkKey>, JwtError> {
    let doc: Value = serde_json::from_slice(bytes).map_err(|_| JwtError::Malformed)?;
    let keys = doc.get("keys").and_then(Value::as_array).ok_or(JwtError::Malformed)?;
    Ok(keys.iter().filter_map(one_key).take(MAX_KEYS).collect())
}

// ---- tokens ----------------------------------------------------------------------------------------------------

/// What this sign-in expects of the token.
pub struct Expect<'a> {
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub nonce: &'a str,
    /// Unix seconds.
    pub now: i64,
    /// The claim that lists the user's groups, when the provider maps them to roles.
    pub group_claim: Option<&'a str>,
    /// The token's `acr` must be one of these (when not empty).
    pub required_acr: &'a [String],
    /// The token's `amr` must contain all of these.
    pub required_amr: &'a [String],
}

/// The claims of a verified ID token that ProxyMind uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdClaims {
    pub iss: String,
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub groups: Vec<String>,
    pub acr: Option<String>,
    pub amr: Vec<String>,
}

fn seconds(v: &Value) -> Option<i64> {
    // Some providers write NumericDate as a float.
    v.as_i64().or_else(|| v.as_f64().filter(|f| f.is_finite() && f.abs() < 1e15).map(|f| f.floor() as i64))
}

fn text(v: &Value, name: &str, max: usize) -> Option<String> {
    v.get(name).and_then(Value::as_str).filter(|s| !s.is_empty() && s.len() <= max).map(str::to_string)
}

fn strings(v: &Value) -> Vec<String> {
    match v {
        Value::String(s) if s.len() <= 256 => vec![s.clone()],
        Value::Array(a) => {
            a.iter().filter_map(Value::as_str).filter(|s| s.len() <= 256).take(MAX_GROUPS).map(str::to_string).collect()
        }
        _ => Vec::new(),
    }
}

/// Verifies `token` against `keys` and `expect`.
pub fn verify_id_token(token: &str, keys: &[JwkKey], expect: &Expect<'_>) -> Result<IdClaims, JwtError> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(JwtError::Malformed);
    }
    let mut parts = token.split('.');
    let (Some(h64), Some(p64), Some(s64), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(JwtError::Malformed);
    };
    let header: Value =
        serde_json::from_slice(&b64url_decode(h64).ok_or(JwtError::Malformed)?).map_err(|_| JwtError::Malformed)?;
    if !header.is_object() {
        return Err(JwtError::Malformed);
    }
    if header.get("crit").is_some() {
        return Err(JwtError::UnsupportedAlg);
    }
    let alg = header.get("alg").and_then(Value::as_str).and_then(Alg::parse).ok_or(JwtError::UnsupportedAlg)?;
    let kid = match header.get("kid") {
        None => None,
        Some(Value::String(k)) => Some(k.as_str()),
        Some(_) => return Err(JwtError::Malformed),
    };
    let sig = b64url_decode(s64).ok_or(JwtError::Malformed)?;
    let signing_input = format!("{h64}.{p64}");

    let candidates: Vec<&JwkKey> = match kid {
        Some(k) => {
            let named: Vec<&JwkKey> = keys.iter().filter(|j| j.kid.as_deref() == Some(k)).collect();
            if named.is_empty() {
                return Err(JwtError::UnknownKey);
            }
            let ok: Vec<&JwkKey> = named.into_iter().filter(|j| j.alg == alg).collect();
            if ok.is_empty() {
                return Err(JwtError::AlgMismatch);
            }
            ok
        }
        // No `kid`: any key of the algorithm (a provider with one signing key need not name it).
        None => {
            let ok: Vec<&JwkKey> = keys.iter().filter(|j| j.alg == alg).collect();
            if ok.is_empty() {
                return Err(JwtError::UnknownKey);
            }
            ok
        }
    };
    if !candidates.iter().any(|k| k.verify(signing_input.as_bytes(), &sig)) {
        return Err(JwtError::BadSignature);
    }

    // The signature holds: now the claims.
    let claims: Value =
        serde_json::from_slice(&b64url_decode(p64).ok_or(JwtError::Malformed)?).map_err(|_| JwtError::Malformed)?;
    if !claims.is_object() {
        return Err(JwtError::Malformed);
    }
    let iss = claims.get("iss").and_then(Value::as_str).ok_or(JwtError::Claim("iss missing"))?;
    if iss != expect.issuer {
        return Err(JwtError::Claim("iss mismatch"));
    }
    let aud = strings(claims.get("aud").ok_or(JwtError::Claim("aud missing"))?);
    if !aud.iter().any(|a| a == expect.client_id) {
        return Err(JwtError::Claim("aud mismatch"));
    }
    if let Some(azp) = claims.get("azp") {
        if azp.as_str() != Some(expect.client_id) {
            return Err(JwtError::Claim("azp mismatch"));
        }
    } else if aud.len() > 1 {
        return Err(JwtError::Claim("azp missing"));
    }
    let exp = claims.get("exp").and_then(seconds).ok_or(JwtError::Claim("exp missing"))?;
    if exp.saturating_add(CLOCK_SKEW) <= expect.now {
        return Err(JwtError::Claim("expired"));
    }
    let iat = claims.get("iat").and_then(seconds).ok_or(JwtError::Claim("iat missing"))?;
    if iat > expect.now.saturating_add(CLOCK_SKEW) {
        return Err(JwtError::Claim("iat in the future"));
    }
    if let Some(nbf) = claims.get("nbf").and_then(seconds)
        && nbf > expect.now.saturating_add(CLOCK_SKEW)
    {
        return Err(JwtError::Claim("not yet valid"));
    }
    match claims.get("nonce").and_then(Value::as_str) {
        Some(n) if ct_eq(n.as_bytes(), expect.nonce.as_bytes()) => {}
        Some(_) => return Err(JwtError::Claim("nonce mismatch")),
        None => return Err(JwtError::Claim("nonce missing")),
    }
    let sub = text(&claims, "sub", 255).ok_or(JwtError::Claim("sub missing"))?;
    let acr = text(&claims, "acr", 256);
    let amr = claims.get("amr").map(strings).unwrap_or_default();
    if !expect.required_acr.is_empty() && !acr.as_ref().is_some_and(|a| expect.required_acr.iter().any(|r| r == a)) {
        return Err(JwtError::Claim("acr not accepted"));
    }
    if !expect.required_amr.iter().all(|r| amr.iter().any(|a| a == r)) {
        return Err(JwtError::Claim("amr not accepted"));
    }
    let email_verified = match claims.get("email_verified") {
        Some(Value::Bool(b)) => *b,
        // Some providers send the string.
        Some(Value::String(s)) => s == "true",
        _ => false,
    };
    let groups = expect.group_claim.and_then(|c| claims.get(c)).map(strings).unwrap_or_default();
    Ok(IdClaims {
        iss: iss.to_string(),
        sub,
        email: text(&claims, "email", 254),
        email_verified,
        name: text(&claims, "name", 200),
        preferred_username: text(&claims, "preferred_username", 128),
        groups,
        acr,
        amr,
    })
}

/// Test helper for other modules: the compact serialization of a signed token is `header.payload.signature`.
#[cfg(any(test, feature = "test-support"))]
pub fn compact(header: &Value, payload: &Value, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> String {
    let (h, p) = (b64url_encode(header.to_string().as_bytes()), b64url_encode(payload.to_string().as_bytes()));
    let input = format!("{h}.{p}");
    let sig = sign(input.as_bytes());
    format!("{input}.{}", b64url_encode(&sig))
}

#[cfg(any(test, feature = "test-support"))]
use crate::webauthn::b64url_encode;

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
    use serde_json::json;

    use super::*;

    const NOW: i64 = 1_700_000_000;

    struct Es {
        pair: EcdsaKeyPair,
    }

    fn es() -> Es {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        Es { pair: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap() }
    }

    impl Es {
        fn jwk(&self, kid: &str) -> Value {
            let p = self.pair.public_key().as_ref();
            json!({"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
                   "x": b64url_encode(&p[1..33]), "y": b64url_encode(&p[33..])})
        }
        fn sign(&self, kid: Option<&str>, claims: &Value) -> String {
            let mut h = json!({"alg": "ES256", "typ": "JWT"});
            if let Some(k) = kid {
                h["kid"] = json!(k);
            }
            compact(&h, claims, |m| self.pair.sign(&SystemRandom::new(), m).unwrap().as_ref().to_vec())
        }
    }

    fn keys(jwks: Value) -> Vec<JwkKey> {
        parse_jwks(jwks.to_string().as_bytes()).unwrap()
    }

    fn good() -> Value {
        json!({"iss": "https://idp.example", "sub": "alice", "aud": "pm", "exp": NOW + 300, "iat": NOW - 5,
               "nonce": "n0", "email": "a@x.example", "email_verified": true, "groups": ["g1", "g2"]})
    }

    fn expect<'a>() -> Expect<'a> {
        Expect {
            issuer: "https://idp.example",
            client_id: "pm",
            nonce: "n0",
            now: NOW,
            group_claim: Some("groups"),
            required_acr: &[],
            required_amr: &[],
        }
    }

    fn with(claims: Value, edit: impl FnOnce(&mut Value)) -> Value {
        let mut c = claims;
        edit(&mut c);
        c
    }

    #[test]
    fn a_good_es256_token_verifies_and_yields_claims() {
        let k = es();
        let set = keys(json!({"keys": [k.jwk("k1")]}));
        let c = verify_id_token(&k.sign(Some("k1"), &good()), &set, &expect()).unwrap();
        assert_eq!((c.sub.as_str(), c.email.as_deref(), c.email_verified), ("alice", Some("a@x.example"), true));
        assert_eq!(c.groups, ["g1", "g2"]);
        // No `kid` in the header: the only ES256 key is tried.
        assert!(verify_id_token(&k.sign(None, &good()), &set, &expect()).is_ok());
    }

    #[test]
    fn eddsa_tokens_verify() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let jwk = json!({"kty": "OKP", "crv": "Ed25519", "kid": "e", "x": b64url_encode(pair.public_key().as_ref())});
        let t = compact(&json!({"alg": "EdDSA", "kid": "e"}), &good(), |m| pair.sign(m).as_ref().to_vec());
        assert!(verify_id_token(&t, &keys(json!({"keys": [jwk]})), &expect()).is_ok());
    }

    #[test]
    fn none_and_hmac_and_other_algorithms_are_refused() {
        let k = es();
        let set = keys(json!({"keys": [k.jwk("k1")]}));
        for alg in ["none", "None", "HS256", "HS512", "PS256", "RS384", "ES384", "RS512", ""] {
            let t = compact(&json!({"alg": alg, "kid": "k1"}), &good(), |_| b"x".to_vec());
            assert_eq!(verify_id_token(&t, &set, &expect()), Err(JwtError::UnsupportedAlg), "{alg}");
        }
        // "none" with no signature part at all.
        let h = b64url_encode(br#"{"alg":"none"}"#);
        let p = b64url_encode(good().to_string().as_bytes());
        assert!(verify_id_token(&format!("{h}.{p}."), &set, &expect()).is_err());
        assert!(verify_id_token(&format!("{h}.{p}"), &set, &expect()).is_err());
        // `crit` is not understood.
        let t = compact(&json!({"alg": "ES256", "crit": ["x"]}), &good(), |_| vec![0; 64]);
        assert_eq!(verify_id_token(&t, &set, &expect()), Err(JwtError::UnsupportedAlg));
    }

    #[test]
    fn an_hs256_token_signed_with_the_public_key_bytes_is_not_accepted() {
        // The classic confusion: HMAC-SHA256 keyed with the key material. `alg` HS256 never reaches a key.
        let k = es();
        let set = keys(json!({"keys": [k.jwk("k1")]}));
        let secret = k.pair.public_key().as_ref().to_vec();
        let t = compact(&json!({"alg": "HS256", "kid": "k1"}), &good(), |m| {
            ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret), m).as_ref().to_vec()
        });
        assert_eq!(verify_id_token(&t, &set, &expect()), Err(JwtError::UnsupportedAlg));
    }

    #[test]
    fn an_unknown_kid_is_reported_so_the_caller_can_refetch_once() {
        let k = es();
        let set = keys(json!({"keys": [k.jwk("k1")]}));
        assert_eq!(verify_id_token(&k.sign(Some("rotated"), &good()), &set, &expect()), Err(JwtError::UnknownKey));
        assert_eq!(verify_id_token(&k.sign(Some("k1"), &good()), &[], &expect()), Err(JwtError::UnknownKey));
    }

    #[test]
    fn a_key_for_another_algorithm_is_not_used() {
        let k = es();
        // The JWK says RS256 but is an EC key: not used at all.
        let mut bad = k.jwk("k1");
        bad["alg"] = json!("RS256");
        assert!(keys(json!({"keys": [bad]})).is_empty());
        // A token claiming RS256 under an EC key's kid.
        let set = keys(json!({"keys": [k.jwk("k1")]}));
        let t = compact(&json!({"alg": "RS256", "kid": "k1"}), &good(), |_| vec![1; 256]);
        assert_eq!(verify_id_token(&t, &set, &expect()), Err(JwtError::AlgMismatch));
        // Encryption keys and unknown key types are skipped.
        let mut enc = k.jwk("e");
        enc["use"] = json!("enc");
        let oct = json!({"kty": "oct", "kid": "h", "k": "AAAA"});
        assert!(keys(json!({"keys": [enc, oct]})).is_empty());
    }

    #[test]
    fn a_tampered_token_or_another_key_fails() {
        let (a, b) = (es(), es());
        let set = keys(json!({"keys": [a.jwk("k1")]}));
        assert_eq!(verify_id_token(&b.sign(Some("k1"), &good()), &set, &expect()), Err(JwtError::BadSignature));
        let t = a.sign(Some("k1"), &good());
        let mut parts: Vec<&str> = t.split('.').collect();
        let forged = b64url_encode(with(good(), |c| c["sub"] = json!("mallory")).to_string().as_bytes());
        parts[1] = &forged;
        assert_eq!(verify_id_token(&parts.join("."), &set, &expect()), Err(JwtError::BadSignature));
    }

    #[test]
    fn each_claim_is_checked() {
        let k = es();
        let set = keys(json!({"keys": [k.jwk("k1")]}));
        let run =
            |edit: &dyn Fn(&mut Value)| verify_id_token(&k.sign(Some("k1"), &with(good(), edit)), &set, &expect());
        let claim = |r: Result<IdClaims, JwtError>| match r {
            Err(JwtError::Claim(c)) => c,
            other => panic!("{other:?}"),
        };
        assert_eq!(claim(run(&|c| c["iss"] = json!("https://evil.example"))), "iss mismatch");
        assert_eq!(claim(run(&|c| c["iss"] = json!("https://idp.example/"))), "iss mismatch");
        assert_eq!(claim(run(&|c| c["aud"] = json!("other"))), "aud mismatch");
        assert_eq!(claim(run(&|c| c["aud"] = json!(["other", "third"]))), "aud mismatch");
        assert_eq!(claim(run(&|c| c["aud"] = json!(["pm", "other"]))), "azp missing");
        assert!(
            run(&|c| {
                c["aud"] = json!(["pm", "other"]);
                c["azp"] = json!("pm");
            })
            .is_ok()
        );
        assert_eq!(
            claim(run(&|c| {
                c["aud"] = json!(["pm", "other"]);
                c["azp"] = json!("other");
            })),
            "azp mismatch"
        );
        assert_eq!(claim(run(&|c| c["azp"] = json!("other"))), "azp mismatch");
        assert_eq!(claim(run(&|c| c["exp"] = json!(NOW - 61))), "expired");
        assert!(run(&|c| c["exp"] = json!(NOW - 30)).is_ok(), "within the skew");
        assert_eq!(claim(run(&|c| c["iat"] = json!(NOW + 3600))), "iat in the future");
        assert_eq!(claim(run(&|c| c["nbf"] = json!(NOW + 3600))), "not yet valid");
        assert_eq!(claim(run(&|c| c["nonce"] = json!("other"))), "nonce mismatch");
        assert_eq!(claim(run(&|c| drop(c.as_object_mut().unwrap().remove("nonce")))), "nonce missing");
        assert_eq!(claim(run(&|c| drop(c.as_object_mut().unwrap().remove("exp")))), "exp missing");
        assert_eq!(claim(run(&|c| drop(c.as_object_mut().unwrap().remove("iat")))), "iat missing");
        assert_eq!(claim(run(&|c| c["sub"] = json!(""))), "sub missing");
        assert_eq!(claim(run(&|c| c["sub"] = json!("s".repeat(300)))), "sub missing");
    }

    #[test]
    fn acr_and_amr_requirements() {
        let k = es();
        let set = keys(json!({"keys": [k.jwk("k1")]}));
        let t = k.sign(
            Some("k1"),
            &with(good(), |c| {
                c["acr"] = json!("urn:mfa");
                c["amr"] = json!(["pwd", "otp"]);
            }),
        );
        let acr = ["urn:mfa".to_string(), "urn:hw".to_string()];
        let amr = ["otp".to_string()];
        let mut e = expect();
        e.required_acr = &acr;
        e.required_amr = &amr;
        assert!(verify_id_token(&t, &set, &e).is_ok());
        let wrong = ["urn:other".to_string()];
        e.required_acr = &wrong;
        assert_eq!(verify_id_token(&t, &set, &e), Err(JwtError::Claim("acr not accepted")));
        e.required_acr = &[];
        let hw = ["hwk".to_string()];
        e.required_amr = &hw;
        assert_eq!(verify_id_token(&t, &set, &e), Err(JwtError::Claim("amr not accepted")));
        // No acr in the token at all.
        e.required_amr = &[];
        e.required_acr = &acr;
        assert!(verify_id_token(&k.sign(Some("k1"), &good()), &set, &e).is_err());
    }

    #[test]
    fn email_verified_may_be_a_string_and_groups_a_single_string() {
        let k = es();
        let set = keys(json!({"keys": [k.jwk("k1")]}));
        let t = k.sign(
            Some("k1"),
            &with(good(), |c| {
                c["email_verified"] = json!("true");
                c["groups"] = json!("only");
            }),
        );
        let c = verify_id_token(&t, &set, &expect()).unwrap();
        assert!(c.email_verified);
        assert_eq!(c.groups, ["only"]);
        let t = k.sign(Some("k1"), &with(good(), |c| c["email_verified"] = json!("yes")));
        assert!(!verify_id_token(&t, &set, &expect()).unwrap().email_verified);
    }

    #[test]
    fn garbage_never_panics() {
        let k = es();
        let set = keys(json!({"keys": [k.jwk("k1")]}));
        for t in ["", ".", "..", "a.b.c", "....", "e30.e30.e30", &"x".repeat(MAX_TOKEN_BYTES + 1)] {
            assert!(verify_id_token(t, &set, &expect()).is_err());
        }
        assert!(parse_jwks(b"not json").is_err());
        assert!(parse_jwks(b"{}").is_err());
        assert!(parse_jwks(br#"{"keys": [1, "a", {"kty": "RSA"}]}"#).unwrap().is_empty());
    }
}
