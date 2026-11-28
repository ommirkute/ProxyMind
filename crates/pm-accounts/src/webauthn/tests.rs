//! Tests of the verifier: real captured ceremonies, RFC test vectors, a software authenticator for every refusal.
//!
//! Sources of the captured vectors (recorded from real authenticators, used here as data):
//! * the Yubico Security Key assertion and the YubiKey 5 Bio EdDSA registration are from the test suite of `webauthn-rs`
//!   (`webauthn-rs-core` 0.6.2, `src/core.rs`: `test_authentication`, `test_yk5bio_fallback_alg_attest_none`), MPL-2.0;
//! * the ES256 registration with user verification (Edge on macOS Touch ID, packed self attestation) is from
//!   `duo-labs/webauthn` (BSD-3-Clause), through the same file (`test_edge_touchid_rk_verified`).
//!
//! The Ed25519 signature check is also run on RFC 8032 section 7.1 "TEST 1".

use ring::digest;

use super::cose::{ALLOWED_ALGS, EDDSA, ES256, PublicKey, RS256};
use super::soft::{SoftAuthenticator, Tweak};
use super::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn b(s: &str) -> Vec<u8> {
    b64url_decode(s).unwrap_or_else(|| panic!("not base64url: {s}"))
}

fn rp_localhost_8080() -> RelyingParty {
    RelyingParty { id: "localhost".into(), name: "test".into(), origins: vec!["http://localhost:8080".into()] }
}

fn rp() -> RelyingParty {
    RelyingParty {
        id: "pm.example.com".into(),
        name: "ProxyMind".into(),
        origins: vec!["https://pm.example.com".into()],
    }
}

const ORIGIN: &str = "https://pm.example.com";

// ---- captured, real -----------------------------------------------------------------------------------------------

#[test]
fn a_real_es256_assertion_from_a_security_key_verifies() {
    // Yubico key, origin http://localhost:8080. Flags 0x01: user present, no user verification (it predates the rule).
    let challenge = b("WgXz_kTv3WUU1kw8hm-OGoGS4ZCHX_3bEqHH2PvVp8M");
    let client_data = b(
        "eyJjaGFsbGVuZ2UiOiJXZ1h6X2tUdjNXVVUxa3c4aG0tT0dvR1M0WkNIWF8zYkVxSEgyUHZWcDhNIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9",
    );
    let auth_data = b("SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAFA");
    let signature =
        b("MEYCIQDmLVOqv85cdRup4Fr8Pf9zC4AWO-XKBJqa8xPwYFCCMAIhAOiExLoyes0xipmUmq0BVlqJaCKLn_MFKG9GIDsCGq_-");
    // The COSE key the registration of that credential gave: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
    let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    cose.extend(unhex("2e794ce976d0fa4ae3b608912d2e0509c7ba545307ed8249105a113621ff3638"));
    cose.extend([0x22, 0x58, 0x20]);
    cose.extend(unhex("75690117fddf4387fddbfddf11f75bc5cde18f3b2f8a46784a9bb1b1a6e93047"));

    let a = verify_assertion_with(&rp_localhost_8080(), &challenge, &client_data, &auth_data, &signature, &cose, false)
        .expect("a real assertion verifies");
    assert_eq!(a.sign_count, 20);
    // The server's own rule refuses it: no user verification.
    assert_eq!(
        verify_assertion(&rp_localhost_8080(), &challenge, &client_data, &auth_data, &signature, &cose).unwrap_err(),
        WebAuthnError::UserNotVerified
    );
    // Any change to the signed data breaks it.
    let mut other = auth_data.clone();
    other[36] ^= 1;
    assert_eq!(
        verify_assertion_with(&rp_localhost_8080(), &challenge, &client_data, &other, &signature, &cose, false)
            .unwrap_err(),
        WebAuthnError::BadSignature
    );
    // Another RP id: the hash in the authenticator data no longer matches.
    let mut other_rp = rp_localhost_8080();
    other_rp.id = "example.com".into();
    assert_eq!(
        verify_assertion_with(&other_rp, &challenge, &client_data, &auth_data, &signature, &cose, false).unwrap_err(),
        WebAuthnError::WrongRpId
    );
    // Another origin.
    let mut other_origin = rp_localhost_8080();
    other_origin.origins = vec!["http://localhost:8081".into()];
    assert_eq!(
        verify_assertion_with(&other_origin, &challenge, &client_data, &auth_data, &signature, &cose, false)
            .unwrap_err(),
        WebAuthnError::WrongOrigin
    );
}

#[test]
fn a_real_ed25519_registration_from_a_yubikey_5_bio_verifies() {
    let challenge = b("NE6dm0mgUe47-X0Yf5nRdhYokY3A8XAzs10KBLGlVY0");
    let client_data = b(
        "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiTkU2ZG0wbWdVZTQ3LVgwWWY1blJkaFlva1kzQThYQXpzMTBLQkxHbFZZMCIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
    );
    let attestation = b(
        "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjhSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAQAAAAAAAAAAAAAAAAAAAAAAgJPPjd7G4EHv83ufLOW_eeYi0a6nIs5prPmDqhUE0GwW2yS0rbfQmkd71GFxGo8uDttnwIHcmNWjr3Oh1vaNYpKoklnntgsV1yXtgxONG8iOPpuKHrB35s-Lq3zMZCKwHf-IvKYFhzS1ZU0jLQM4Qlx9emMOLlLHbJ7b9R6WIrvepAEBAycgBiFYICgd3qEI_iQqhYAi0y47WqeU2Bf2kVY4Mq02t1zgTzkV",
    );
    let reg = verify_registration(&rp_localhost_8080(), &challenge, &client_data, &attestation, &ALLOWED_ALGS)
        .expect("a real EdDSA registration verifies");
    assert_eq!(reg.alg, EDDSA);
    assert_eq!(reg.credential_id.len(), 128);
    assert_eq!(reg.sign_count, 1);
    assert!(!reg.backup_eligible);
    // With EdDSA left out of the allow-list it is refused as an unsupported algorithm.
    assert_eq!(
        verify_registration(&rp_localhost_8080(), &challenge, &client_data, &attestation, &[ES256]).unwrap_err(),
        WebAuthnError::UnsupportedAlgorithm
    );
    // The stored key parses and is an Ed25519 key.
    let (key, alg) = PublicKey::from_cose(&cbor::decode(&reg.public_key_cose).unwrap(), &ALLOWED_ALGS).unwrap();
    assert!(matches!(key, PublicKey::Ed25519(_)) && alg == EDDSA);
}

#[test]
fn a_real_es256_registration_with_user_verification_verifies() {
    // Edge on macOS (Touch ID), a resident key, packed self attestation: the statement is parsed and ignored.
    let challenge = b("bCE-p6LqJD-w56E6Kel1ndL0exzCZCJEIAG38GThtjA");
    let client_data = b(
        "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiYkNFLXA2THFKRC13NTZFNktlbDFuZEwwZXh6Q1pDSkVJQUczOEdUaHRqQSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
    );
    let attestation = b(
        "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAOpCgJUKTloGtzqjcnCSL8ywG1baTYd5WChecwfd-A0lAiEAuz9KEXKBM--RgNh1J7-CBu9PD1A6NBIYOa59xvguirFoYXV0aERhdGFYqUmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRWJM2x-tzgACNbzGCmSLCyXx8FUDACUBa1P41Jgc2ZmM_ZH0kBsGbB_exYzGz8vj87Zegi8jwdj6sY-MpQECAyYgASFYII__M-4cJoL1GDCkdTFmjmcZLv2J5BDcgxHlNKVL4NrtIlggc5greCirh25w_RyOmgkJlV7-k-smBNca2TP1l5TAjak",
    );
    let reg = verify_registration(&rp_localhost_8080(), &challenge, &client_data, &attestation, &ALLOWED_ALGS).unwrap();
    assert_eq!(reg.alg, ES256);
    assert_eq!(reg.credential_id.len(), 37);
    // Touch ID counts in a large, ever-growing number; we only compare it with the last one.
    assert_eq!(reg.sign_count, u32::from_be_bytes([0x62, 0x4c, 0xdb, 0x1f]));
}

#[test]
fn ed25519_signature_check_matches_rfc_8032() {
    // RFC 8032 section 7.1, TEST 1: the empty message.
    let public: [u8; 32] =
        unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").try_into().unwrap();
    let sig = unhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    let key = PublicKey::Ed25519(public);
    assert!(key.verify(b"", &sig));
    assert!(!key.verify(b"x", &sig));
}

// ---- the software authenticator, every algorithm -----------------------------------------------------------------

fn options(challenge: &[u8; 32]) -> (serde_json::Value, serde_json::Value) {
    let c = b64url_encode(challenge);
    (
        serde_json::json!({ "challenge": c, "rp": { "id": "pm.example.com" }, "user": { "id": b64url_encode(b"handle-1234567890") } }),
        serde_json::json!({ "challenge": c, "rpId": "pm.example.com" }),
    )
}

fn register(auth: &mut SoftAuthenticator, t: &Tweak) -> (Result<Registration, WebAuthnError>, [u8; 32]) {
    let chal = [7u8; 32];
    let (create, _) = options(&chal);
    let r = auth.create(&create, ORIGIN, t);
    let res = verify_registration(&rp(), &chal, &b(&r.client_data_json), &b(&r.attestation_object), &ALLOWED_ALGS);
    (res, chal)
}

fn assert_with(auth: &mut SoftAuthenticator, cose: &[u8], t: &Tweak) -> Result<Assertion, WebAuthnError> {
    let chal = [9u8; 32];
    let (_, get) = options(&chal);
    let r = auth.get(&get, ORIGIN, t);
    verify_assertion(&rp(), &chal, &b(&r.client_data_json), &b(&r.authenticator_data), &b(&r.signature), cose)
}

#[test]
fn every_algorithm_registers_and_signs_in() {
    for (mut auth, alg) in [
        (SoftAuthenticator::es256(), ES256),
        (SoftAuthenticator::ed25519(), EDDSA),
        (SoftAuthenticator::rs256(), RS256),
    ] {
        let (reg, _) = register(&mut auth, &Tweak::default());
        let reg = reg.unwrap_or_else(|e| panic!("alg {alg}: {e}"));
        assert_eq!(reg.alg, alg);
        assert_eq!(reg.credential_id, auth.credential_id);
        assert_eq!(reg.public_key_cose, auth.public_key_cose());
        let a = assert_with(&mut auth, &reg.public_key_cose, &Tweak::default())
            .unwrap_or_else(|e| panic!("alg {alg}: {e}"));
        assert_eq!(a.sign_count, 1);
        // The next one counts up.
        assert_eq!(assert_with(&mut auth, &reg.public_key_cose, &Tweak::default()).unwrap().sign_count, 2);
    }
}

#[test]
fn flags_are_read_and_extensions_and_backup_state_are_handled() {
    let mut auth = SoftAuthenticator::es256();
    auth.backup_eligible = true;
    auth.backup_state = true;
    let (reg, _) = register(&mut auth, &Tweak { extension_data: true, ..Tweak::default() });
    let reg = reg.unwrap();
    assert!(reg.backup_eligible && reg.backup_state);
    let a = assert_with(&mut auth, &reg.public_key_cose, &Tweak { extension_data: true, ..Tweak::default() }).unwrap();
    assert!(a.backup_eligible && a.backup_state);
    // Backup state without eligibility is not a state an authenticator can be in.
    auth.backup_eligible = false;
    assert_eq!(
        assert_with(&mut auth, &reg.public_key_cose, &Tweak::default()).unwrap_err(),
        WebAuthnError::BadAuthData
    );
}

#[test]
fn registrations_are_refused_for_each_wrong_thing() {
    let cases: Vec<(&str, Tweak, WebAuthnError)> = vec![
        (
            "origin",
            Tweak { origin: Some("https://evil.example".into()), ..Tweak::default() },
            WebAuthnError::WrongOrigin,
        ),
        (
            "origin with a path",
            Tweak { origin: Some("https://pm.example.com/".into()), ..Tweak::default() },
            WebAuthnError::WrongOrigin,
        ),
        ("rp id", Tweak { rp_id: Some("evil.example".into()), ..Tweak::default() }, WebAuthnError::WrongRpId),
        (
            "challenge",
            Tweak { challenge: Some(b64url_encode(&[1u8; 32])), ..Tweak::default() },
            WebAuthnError::WrongChallenge,
        ),
        (
            "short challenge",
            Tweak { challenge: Some(b64url_encode(&[7u8; 31])), ..Tweak::default() },
            WebAuthnError::WrongChallenge,
        ),
        ("type", Tweak { kind: Some("webauthn.get".into()), ..Tweak::default() }, WebAuthnError::WrongType),
        ("no UP", Tweak { no_user_present: true, ..Tweak::default() }, WebAuthnError::UserNotPresent),
        ("no UV", Tweak { no_user_verified: true, ..Tweak::default() }, WebAuthnError::UserNotVerified),
        ("cross origin", Tweak { cross_origin: true, ..Tweak::default() }, WebAuthnError::CrossOrigin),
        ("top origin", Tweak { top_origin: true, ..Tweak::default() }, WebAuthnError::CrossOrigin),
        ("trailing bytes", Tweak { trailing_garbage: true, ..Tweak::default() }, WebAuthnError::BadAuthData),
    ];
    for (name, t, want) in cases {
        let mut auth = SoftAuthenticator::es256();
        let (res, _) = register(&mut auth, &t);
        assert_eq!(res.unwrap_err(), want, "{name}");
    }
    // An algorithm outside the allow-list.
    let mut auth = SoftAuthenticator::rs256();
    let chal = [7u8; 32];
    let (create, _) = options(&chal);
    let r = auth.create(&create, ORIGIN, &Tweak::default());
    assert_eq!(
        verify_registration(&rp(), &chal, &b(&r.client_data_json), &b(&r.attestation_object), &[ES256, EDDSA])
            .unwrap_err(),
        WebAuthnError::UnsupportedAlgorithm
    );
}

#[test]
fn assertions_are_refused_for_each_wrong_thing() {
    let cases: Vec<(&str, Tweak, WebAuthnError)> = vec![
        (
            "origin",
            Tweak { origin: Some("https://pm.example.com:8443".into()), ..Tweak::default() },
            WebAuthnError::WrongOrigin,
        ),
        ("rp id", Tweak { rp_id: Some("example.com".into()), ..Tweak::default() }, WebAuthnError::WrongRpId),
        (
            "challenge",
            Tweak { challenge: Some(b64url_encode(&[3u8; 32])), ..Tweak::default() },
            WebAuthnError::WrongChallenge,
        ),
        ("type", Tweak { kind: Some("webauthn.create".into()), ..Tweak::default() }, WebAuthnError::WrongType),
        ("no UP", Tweak { no_user_present: true, ..Tweak::default() }, WebAuthnError::UserNotPresent),
        ("no UV", Tweak { no_user_verified: true, ..Tweak::default() }, WebAuthnError::UserNotVerified),
        ("cross origin", Tweak { cross_origin: true, ..Tweak::default() }, WebAuthnError::CrossOrigin),
        ("signature", Tweak { bad_signature: true, ..Tweak::default() }, WebAuthnError::BadSignature),
        ("trailing bytes", Tweak { trailing_garbage: true, ..Tweak::default() }, WebAuthnError::BadAuthData),
    ];
    for (name, t, want) in cases {
        let mut auth = SoftAuthenticator::es256();
        let (reg, _) = register(&mut auth, &Tweak::default());
        let reg = reg.unwrap();
        assert_eq!(assert_with(&mut auth, &reg.public_key_cose, &t).unwrap_err(), want, "{name}");
    }
    // A signature by another key.
    let mut a = SoftAuthenticator::es256();
    let mut other = SoftAuthenticator::es256();
    let (reg, _) = register(&mut a, &Tweak::default());
    assert_eq!(
        assert_with(&mut other, &reg.unwrap().public_key_cose, &Tweak::default()).unwrap_err(),
        WebAuthnError::BadSignature
    );
    // Attested credential data has no place in an assertion.
    let mut auth = SoftAuthenticator::es256();
    let (reg, _) = register(&mut auth, &Tweak::default());
    let chal = [9u8; 32];
    let (create, _) = options(&chal);
    let made = auth.create(&create, ORIGIN, &Tweak { kind: Some("webauthn.get".into()), ..Tweak::default() });
    let att = cbor::decode(&b(&made.attestation_object)).unwrap();
    let auth_data = att.get_text("authData").and_then(cbor::Value::as_bytes).unwrap().to_vec();
    assert_eq!(
        verify_assertion(
            &rp(),
            &chal,
            &b(&made.client_data_json),
            &auth_data,
            &[0u8; 64],
            &reg.unwrap().public_key_cose
        )
        .unwrap_err(),
        WebAuthnError::UnexpectedCredentialData
    );
}

#[test]
fn a_challenge_must_match_byte_for_byte_and_encoding_is_strict() {
    let mut auth = SoftAuthenticator::es256();
    let chal = [7u8; 32];
    let (create, _) = options(&chal);
    // Padding, a stray space and a character outside the alphabet are all not the issued challenge.
    let good = b64url_encode(&chal);
    for bad in [format!("{good}="), format!("{good} "), format!("+{good}"), String::new(), "AAAA".into()] {
        let r = auth.create(&create, ORIGIN, &Tweak { challenge: Some(bad.clone()), ..Tweak::default() });
        let res = verify_registration(&rp(), &chal, &b(&r.client_data_json), &b(&r.attestation_object), &ALLOWED_ALGS);
        assert_eq!(res.unwrap_err(), WebAuthnError::WrongChallenge, "{bad:?}");
    }
}

#[test]
fn garbage_is_refused_without_panicking() {
    let mut auth = SoftAuthenticator::es256();
    let chal = [7u8; 32];
    let (create, _) = options(&chal);
    let r = auth.create(&create, ORIGIN, &Tweak::default());
    let cd = b(&r.client_data_json);
    let att = b(&r.attestation_object);
    // Random attestation objects, and every truncation and single-byte change of a valid one.
    let mut s = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    for _ in 0..5000 {
        let len = (next() % 200) as usize;
        let junk: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
        assert!(verify_registration(&rp(), &chal, &cd, &junk, &ALLOWED_ALGS).is_err());
        let _ = parse_auth_data(&junk, &ALLOWED_ALGS);
        let _ = verify_assertion(&rp(), &chal, &cd, &junk, &junk, &junk);
        let _ = client_data_challenge(&junk);
    }
    for i in 0..att.len() {
        let _ = verify_registration(&rp(), &chal, &cd, &att[..i], &ALLOWED_ALGS);
        let mut m = att.clone();
        m[i] ^= 0xff;
        let _ = verify_registration(&rp(), &chal, &cd, &m, &ALLOWED_ALGS);
    }
    // Client data that is not JSON, is empty, is huge or has a duplicated field.
    for bad in [&b""[..], b"{", b"[]", b"null", b"{\"type\":1}", &vec![b'a'; 20_000]] {
        assert_eq!(verify_registration(&rp(), &chal, bad, &att, &ALLOWED_ALGS).unwrap_err(), WebAuthnError::ClientData);
    }
    let dup = format!(
        "{{\"type\":\"webauthn.create\",\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"{ORIGIN}\"}}",
        b64url_encode(&chal)
    );
    assert_eq!(
        verify_registration(&rp(), &chal, dup.as_bytes(), &att, &ALLOWED_ALGS).unwrap_err(),
        WebAuthnError::ClientData
    );
    // Authenticator data: too short, a credential id length that runs past the end, an id that is too short.
    assert!(parse_auth_data(&[0u8; 36], &ALLOWED_ALGS).is_err());
    let mut ad = vec![0u8; 32];
    ad.extend([FLAG_UP | FLAG_UV | FLAG_AT, 0, 0, 0, 1]);
    ad.extend([0u8; 16]);
    ad.extend([0xff, 0xff]);
    assert_eq!(parse_auth_data(&ad, &ALLOWED_ALGS).unwrap_err(), WebAuthnError::BadAuthData);
    let mut ad = vec![0u8; 32];
    ad.extend([FLAG_UP | FLAG_UV | FLAG_AT, 0, 0, 0, 1]);
    ad.extend([0u8; 16]);
    ad.extend([0, 8]);
    ad.extend([0u8; 8]);
    assert_eq!(parse_auth_data(&ad, &ALLOWED_ALGS).unwrap_err(), WebAuthnError::BadAuthData);
}

#[test]
fn cose_keys_outside_the_allow_list_or_malformed_are_refused() {
    let key = |entries: Vec<(i64, cbor::Value)>| {
        cbor::Value::Map(entries.into_iter().map(|(k, v)| (cbor::Value::Int(k), v)).collect())
    };
    use cbor::Value::{Bytes, Int};
    let x = Bytes(vec![1; 32]);
    // P-384 is not accepted, nor ES256 with the wrong curve or short coordinates, nor an unknown algorithm.
    for bad in [
        key(vec![(1, Int(2)), (3, Int(-35)), (-1, Int(2)), (-2, Bytes(vec![1; 48])), (-3, Bytes(vec![1; 48]))]),
        key(vec![(1, Int(2)), (3, Int(-7)), (-1, Int(2)), (-2, x.clone()), (-3, x.clone())]),
        key(vec![(1, Int(2)), (3, Int(-7)), (-1, Int(1)), (-2, Bytes(vec![1; 31])), (-3, x.clone())]),
        key(vec![(1, Int(1)), (3, Int(-8)), (-1, Int(7)), (-2, x.clone())]),
        key(vec![(1, Int(3)), (3, Int(-257)), (-1, Bytes(vec![0xff; 100])), (-2, Bytes(vec![1, 0, 1]))]),
        key(vec![(1, Int(3)), (3, Int(-257)), (-1, Bytes(vec![0xff; 256])), (-2, Bytes(vec![2]))]),
        key(vec![(1, Int(2)), (3, Int(-7))]),
        cbor::Value::Array(vec![]),
    ] {
        assert!(PublicKey::from_cose(&bad, &ALLOWED_ALGS).is_err(), "{bad:?}");
    }
}

#[test]
fn base64url_round_trips_and_is_strict() {
    for len in 0..70usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
        let enc = b64url_encode(&data);
        assert!(!enc.contains('=') && !enc.contains('+') && !enc.contains('/'));
        assert_eq!(b64url_decode(&enc).unwrap(), data, "{len}");
    }
    assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
    assert_eq!(b64url_encode(b"fooba"), "Zm9vYmE");
    for bad in ["Zm9vYg==", "Zm9vYg=", "Zm9v+g", "Zm9v/g", "Zm 9v", "Z", "Zm9vYh", "Zm9vYmFyZ", "\u{e9}AAA"] {
        assert!(b64url_decode(bad).is_none(), "{bad:?}");
    }
    // Unused bits must be zero: "Zg" is "f", "Zh" has a stray bit.
    assert_eq!(b64url_decode("Zg").unwrap(), b"f");
    assert!(b64url_decode("Zh").is_none());
}

#[test]
fn rp_id_hash_is_sha256_of_the_id() {
    assert_eq!(rp_id_hash("pm.example.com").as_slice(), digest::digest(&digest::SHA256, b"pm.example.com").as_ref());
}
