//! Passkey flows (ADR-0022 step 7) against `server.db` with a software authenticator and a manual clock.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::webauthn::soft::{SoftAuthenticator, Tweak};
use crate::webauthn::{RelyingParty, b64url_encode};
use crate::*;

const T0: i64 = 1_700_000_000;
const PW: &str = "correct horse battery";
const ORIGIN: &str = "https://pm.example.com";

struct Env {
    acc: Accounts,
    clock: Arc<ManualClock>,
    rp: RelyingParty,
}

fn env() -> Env {
    let clock = Arc::new(ManualClock::new(T0));
    let acc =
        Accounts::open_in_memory(ServerKey::from_bytes([7; 32]), Config::insecure_for_tests(), clock.clone()).unwrap();
    let rp = RelyingParty { id: "pm.example.com".into(), name: "ProxyMind".into(), origins: vec![ORIGIN.into()] };
    Env { acc, clock, rp }
}

fn c() -> ClientInfo {
    ClientInfo::new("203.0.113.9")
}

struct Who {
    user: User,
    session: String,
}

/// An account with a password and a signed-in session (a session made for a test: the passkey flows do not care how it
/// was got, only that it is the account's).
fn signed_in(e: &Env, name: &str, admin: bool) -> Who {
    let user = if admin {
        let t = e.acc.create_setup_token().unwrap();
        e.acc.bootstrap_owner(t.token.expose(), name, name, PW, &c()).unwrap()
    } else {
        let owner = e.acc.list_users().unwrap().into_iter().find(|u| u.server_admin).unwrap();
        let inv = e.acc.create_invite(&owner.id, Role::Tester, Some("p"), Duration::from_secs(3600)).unwrap();
        e.acc.accept_invite(inv.token.expose(), name, name, PW, &c()).unwrap()
    };
    let s = e.acc.create_session(&user.id, "password+totp", &c()).unwrap();
    Who { user, session: s.id.expose().to_string() }
}

/// Enrols `auth` as a passkey of `who`, named `name`.
fn enrol(e: &Env, who: &Who, auth: &mut SoftAuthenticator, name: &str) -> PasskeyInfo {
    let opts = e.acc.passkey_begin_enrol(&e.rp, &who.user.id, &who.session).unwrap();
    let resp = auth.create(&opts, ORIGIN, &Tweak::default());
    e.acc.passkey_finish_enrol(&e.rp, &who.user.id, &who.session, name, &resp).unwrap()
}

fn login(e: &Env, auth: &mut SoftAuthenticator, username: Option<&str>, t: &Tweak) -> Result<LoginSuccess> {
    let opts = e.acc.passkey_begin_login(&e.rp, username, &c())?;
    let resp = auth.get(&opts, ORIGIN, t);
    e.acc.passkey_finish_login(&e.rp, &resp, &c())
}

fn log_has(e: &Env, kind: &str) -> bool {
    e.acc.security_log(500).unwrap().iter().any(|l| l.kind == kind)
}

#[test]
fn enrol_list_and_sign_in_by_username_and_without_one() {
    let e = env();
    let who = signed_in(&e, "owner", true);
    let mut auth = SoftAuthenticator::es256();
    let info = enrol(&e, &who, &mut auth, "Laptop");
    assert_eq!(info.name, "Laptop");
    let listed = e.acc.list_passkeys(&who.user.id).unwrap();
    assert_eq!(listed, vec![info.clone()]);
    assert_eq!(listed[0].transports, vec!["internal".to_string()]);
    assert_eq!(e.acc.passkey_count(&who.user.id).unwrap(), 1);

    // Username first, then no username at all (the user handle in the assertion finds the account).
    let ok = login(&e, &mut auth, Some("OWNER"), &Tweak::default()).unwrap();
    assert_eq!(ok.user.id, who.user.id);
    let s = e.acc.validate_session(ok.session.id.expose()).unwrap();
    assert_eq!(s.auth_method, "passkey");
    assert_eq!(s.user_id, who.user.id);
    let ok = login(&e, &mut auth, None, &Tweak::default()).unwrap();
    assert_eq!(ok.user.id, who.user.id);
    // A discoverable assertion without a user handle still finds it by credential id.
    login(&e, &mut auth, None, &Tweak { no_user_handle: true, ..Tweak::default() }).unwrap();

    let after = e.acc.list_passkeys(&who.user.id).unwrap();
    assert!(after[0].last_used_at.is_some());
    // The stored counter followed the authenticator's.
    let stored: i64 =
        e.acc.conn().query_row("SELECT counter FROM credentials WHERE kind = 'passkey'", [], |r| r.get(0)).unwrap();
    assert_eq!(stored, i64::from(auth.counter));
    assert!(log_has(&e, "login_success"));
}

#[test]
fn every_algorithm_signs_in_through_the_database() {
    let e = env();
    let who = signed_in(&e, "owner", true);
    for (mut auth, name) in
        [(SoftAuthenticator::es256(), "es"), (SoftAuthenticator::ed25519(), "ed"), (SoftAuthenticator::rs256(), "rs")]
    {
        enrol(&e, &who, &mut auth, name);
        login(&e, &mut auth, Some("owner"), &Tweak::default()).unwrap_or_else(|err| panic!("{name}: {err}"));
        login(&e, &mut auth, None, &Tweak::default()).unwrap_or_else(|err| panic!("{name}: {err}"));
    }
    assert_eq!(e.acc.passkey_count(&who.user.id).unwrap(), 3);
}

#[test]
fn a_challenge_is_single_use_short_lived_and_bound_to_its_ceremony() {
    let e = env();
    let who = signed_in(&e, "owner", true);
    let mut auth = SoftAuthenticator::es256();
    enrol(&e, &who, &mut auth, "k");

    // Reuse: the same response twice.
    let opts = e.acc.passkey_begin_login(&e.rp, Some("owner"), &c()).unwrap();
    let resp = auth.get(&opts, ORIGIN, &Tweak::default());
    e.acc.passkey_finish_login(&e.rp, &resp, &c()).unwrap();
    assert!(matches!(e.acc.passkey_finish_login(&e.rp, &resp, &c()), Err(AccountError::InvalidCredentials)));

    // A failed attempt uses the challenge up too: the correct response afterwards is refused.
    let opts = e.acc.passkey_begin_login(&e.rp, Some("owner"), &c()).unwrap();
    let bad = auth.get(&opts, ORIGIN, &Tweak { bad_signature: true, ..Tweak::default() });
    assert!(e.acc.passkey_finish_login(&e.rp, &bad, &c()).is_err());
    let good = auth.get(&opts, ORIGIN, &Tweak::default());
    assert!(matches!(e.acc.passkey_finish_login(&e.rp, &good, &c()), Err(AccountError::InvalidCredentials)));

    // Expiry: five minutes.
    let opts = e.acc.passkey_begin_login(&e.rp, Some("owner"), &c()).unwrap();
    let resp = auth.get(&opts, ORIGIN, &Tweak::default());
    e.clock.advance(301);
    assert!(matches!(e.acc.passkey_finish_login(&e.rp, &resp, &c()), Err(AccountError::InvalidCredentials)));

    // A challenge the server never issued.
    let opts = e.acc.passkey_begin_login(&e.rp, Some("owner"), &c()).unwrap();
    let forged = auth.get(&opts, ORIGIN, &Tweak { challenge: Some(b64url_encode(&[5u8; 32])), ..Tweak::default() });
    assert!(e.acc.passkey_finish_login(&e.rp, &forged, &c()).is_err());

    // An enrolment challenge cannot be used to sign in, nor a sign-in challenge to enrol.
    let create = e.acc.passkey_begin_enrol(&e.rp, &who.user.id, &who.session).unwrap();
    let mut other = SoftAuthenticator::es256();
    let as_login = other.get(
        &serde_json::json!({ "challenge": create["challenge"], "rpId": "pm.example.com" }),
        ORIGIN,
        &Tweak::default(),
    );
    assert!(e.acc.passkey_finish_login(&e.rp, &as_login, &c()).is_err());
    let ropts = e.acc.passkey_begin_login(&e.rp, Some("owner"), &c()).unwrap();
    let as_enrol = other.create(&serde_json::json!({ "challenge": ropts["challenge"], "rp": { "id": "pm.example.com" }, "user": { "id": "AAAA" } }), ORIGIN, &Tweak::default());
    assert!(matches!(
        e.acc.passkey_finish_enrol(&e.rp, &who.user.id, &who.session, "x", &as_enrol),
        Err(AccountError::PasskeyRefused(_))
    ));
    assert_eq!(e.acc.passkey_count(&who.user.id).unwrap(), 1);
}

#[test]
fn an_enrolment_is_bound_to_the_user_and_the_session_that_asked() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    let tess = signed_in(&e, "tess", false);
    let other_session = e.acc.create_session(&owner.user.id, "password+totp", &c()).unwrap().id.expose().to_string();
    let mut auth = SoftAuthenticator::es256();

    let opts = e.acc.passkey_begin_enrol(&e.rp, &owner.user.id, &owner.session).unwrap();
    let resp = auth.create(&opts, ORIGIN, &Tweak::default());
    // Another user, another session of the same user: refused, and the challenge is gone for the right one as well.
    assert!(matches!(
        e.acc.passkey_finish_enrol(&e.rp, &tess.user.id, &tess.session, "x", &resp),
        Err(AccountError::PasskeyRefused(_))
    ));
    let opts = e.acc.passkey_begin_enrol(&e.rp, &owner.user.id, &owner.session).unwrap();
    let resp = auth.create(&opts, ORIGIN, &Tweak::default());
    assert!(matches!(
        e.acc.passkey_finish_enrol(&e.rp, &owner.user.id, &other_session, "x", &resp),
        Err(AccountError::PasskeyRefused(_))
    ));
    assert_eq!(e.acc.passkey_count(&owner.user.id).unwrap() + e.acc.passkey_count(&tess.user.id).unwrap(), 0);
    // A new options call replaces the last one for the user.
    let first = e.acc.passkey_begin_enrol(&e.rp, &owner.user.id, &owner.session).unwrap();
    let second = e.acc.passkey_begin_enrol(&e.rp, &owner.user.id, &owner.session).unwrap();
    let old = auth.create(&first, ORIGIN, &Tweak::default());
    assert!(e.acc.passkey_finish_enrol(&e.rp, &owner.user.id, &owner.session, "x", &old).is_err());
    let new = auth.create(&second, ORIGIN, &Tweak::default());
    e.acc.passkey_finish_enrol(&e.rp, &owner.user.id, &owner.session, "x", &new).unwrap();
}

#[test]
fn registrations_with_something_wrong_store_nothing() {
    let e = env();
    let who = signed_in(&e, "owner", true);
    let cases = [
        Tweak { origin: Some("https://evil.example".into()), ..Tweak::default() },
        Tweak { rp_id: Some("evil.example".into()), ..Tweak::default() },
        Tweak { no_user_verified: true, ..Tweak::default() },
        Tweak { no_user_present: true, ..Tweak::default() },
        Tweak { kind: Some("webauthn.get".into()), ..Tweak::default() },
        Tweak { cross_origin: true, ..Tweak::default() },
        Tweak { response_id: Some(b64url_encode(&[1u8; 32])), ..Tweak::default() },
    ];
    for t in cases {
        let mut auth = SoftAuthenticator::es256();
        let opts = e.acc.passkey_begin_enrol(&e.rp, &who.user.id, &who.session).unwrap();
        let resp = auth.create(&opts, ORIGIN, &t);
        assert!(matches!(
            e.acc.passkey_finish_enrol(&e.rp, &who.user.id, &who.session, "x", &resp),
            Err(AccountError::PasskeyRefused(_))
        ));
    }
    assert_eq!(e.acc.passkey_count(&who.user.id).unwrap(), 0);
    assert!(log_has(&e, "passkey_enrol_failure"));
    // Garbage in the fields.
    let opts = e.acc.passkey_begin_enrol(&e.rp, &who.user.id, &who.session).unwrap();
    let mut auth = SoftAuthenticator::es256();
    let mut resp = auth.create(&opts, ORIGIN, &Tweak::default());
    resp.attestation_object = "not base64!".into();
    assert!(matches!(
        e.acc.passkey_finish_enrol(&e.rp, &who.user.id, &who.session, "x", &resp),
        Err(AccountError::PasskeyRefused(_))
    ));
}

#[test]
fn a_credential_id_is_unique_across_the_server() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    let tess = signed_in(&e, "tess", false);
    let mut auth = SoftAuthenticator::es256();
    enrol(&e, &owner, &mut auth, "mine");
    // The same authenticator offered to a second account: refused (and not listed for it).
    let opts = e.acc.passkey_begin_enrol(&e.rp, &tess.user.id, &tess.session).unwrap();
    let resp = auth.create(&opts, ORIGIN, &Tweak::default());
    assert!(matches!(
        e.acc.passkey_finish_enrol(&e.rp, &tess.user.id, &tess.session, "x", &resp),
        Err(AccountError::PasskeyRefused(_))
    ));
    assert_eq!(e.acc.passkey_count(&tess.user.id).unwrap(), 0);
    // The options for the owner exclude the owner's existing credential.
    let opts = e.acc.passkey_begin_enrol(&e.rp, &owner.user.id, &owner.session).unwrap();
    assert_eq!(opts["excludeCredentials"].as_array().unwrap().len(), 1);
}

#[test]
fn the_credential_of_another_user_does_not_sign_in_username_first() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    let tess = signed_in(&e, "tess", false);
    let mut a = SoftAuthenticator::es256();
    let mut b = SoftAuthenticator::es256();
    enrol(&e, &owner, &mut a, "a");
    enrol(&e, &tess, &mut b, "b");
    // Asking for tess's options and answering with the owner's credential.
    let opts = e.acc.passkey_begin_login(&e.rp, Some("tess"), &c()).unwrap();
    let resp = a.get(&opts, ORIGIN, &Tweak::default());
    assert!(matches!(e.acc.passkey_finish_login(&e.rp, &resp, &c()), Err(AccountError::InvalidCredentials)));
    assert!(
        e.acc
            .security_log(50)
            .unwrap()
            .iter()
            .any(|l| l.kind == "passkey_failure" && l.detail.contains("another user"))
    );
    // A user handle that belongs to someone else is refused as well.
    let opts = e.acc.passkey_begin_login(&e.rp, None, &c()).unwrap();
    let mut resp = a.get(&opts, ORIGIN, &Tweak::default());
    resp.user_handle = Some(b64url_encode(&crate::user_handle(&tess.user.id)));
    assert!(matches!(e.acc.passkey_finish_login(&e.rp, &resp, &c()), Err(AccountError::InvalidCredentials)));
    // A credential the server has never seen.
    let mut stranger = SoftAuthenticator::es256();
    let _ = stranger.create(
        &serde_json::json!({ "challenge": "AAAA", "rp": { "id": "pm.example.com" }, "user": { "id": "AAAA" } }),
        ORIGIN,
        &Tweak::default(),
    );
    assert!(login(&e, &mut stranger, None, &Tweak::default()).is_err());
    assert!(login(&e, &mut stranger, Some("tess"), &Tweak::default()).is_err());
}

#[test]
fn sign_in_checks_origin_rp_id_user_verification_and_the_signature() {
    let e = env();
    let who = signed_in(&e, "owner", true);
    let mut auth = SoftAuthenticator::es256();
    enrol(&e, &who, &mut auth, "k");
    for t in [
        Tweak { origin: Some("https://evil.example".into()), ..Tweak::default() },
        Tweak { rp_id: Some("evil.example".into()), ..Tweak::default() },
        Tweak { no_user_verified: true, ..Tweak::default() },
        Tweak { no_user_present: true, ..Tweak::default() },
        Tweak { bad_signature: true, ..Tweak::default() },
        Tweak { kind: Some("webauthn.create".into()), ..Tweak::default() },
        Tweak { cross_origin: true, ..Tweak::default() },
    ] {
        assert!(matches!(login(&e, &mut auth, Some("owner"), &t), Err(AccountError::InvalidCredentials)));
        e.clock.advance(3600); // so the throttle of this loop does not hide the checks
    }
}

#[test]
fn a_counter_that_goes_backwards_is_refused_and_audited_and_zero_is_fine() {
    let e = env();
    let who = signed_in(&e, "owner", true);
    let mut auth = SoftAuthenticator::es256();
    enrol(&e, &who, &mut auth, "k");
    login(&e, &mut auth, Some("owner"), &Tweak { counter: Some(10), ..Tweak::default() }).unwrap();
    login(&e, &mut auth, Some("owner"), &Tweak { counter: Some(11), ..Tweak::default() }).unwrap();
    // The same count again, and a lower one: a clone.
    for n in [11, 5, 0] {
        let r = login(&e, &mut auth, Some("owner"), &Tweak { counter: Some(n), ..Tweak::default() });
        assert!(matches!(r, Err(AccountError::InvalidCredentials)), "{n}");
    }
    let clones: Vec<_> =
        e.acc.security_log(100).unwrap().into_iter().filter(|l| l.kind == "passkey_clone_suspected").collect();
    assert_eq!(clones.len(), 3);
    assert_eq!(clones[0].user_id.as_deref(), Some(who.user.id.as_str()));
    assert!(clones.iter().all(|l| !l.detail.contains(&b64url_encode(&auth.credential_id))));
    // The stored counter did not move, so the genuine authenticator (at 12) still works.
    e.clock.advance(3600);
    login(&e, &mut auth, Some("owner"), &Tweak { counter: Some(12), ..Tweak::default() }).unwrap();

    // An authenticator that always says zero is allowed, any number of times.
    let mut zero = SoftAuthenticator::ed25519();
    let w2 = signed_in(&e, "tess", false);
    enrol(&e, &w2, &mut zero, "z");
    for _ in 0..3 {
        login(&e, &mut zero, Some("tess"), &Tweak { counter: Some(0), ..Tweak::default() }).unwrap();
    }
    // ... but once it has counted, going back to zero is a regression.
    login(&e, &mut zero, Some("tess"), &Tweak { counter: Some(3), ..Tweak::default() }).unwrap();
    assert!(login(&e, &mut zero, Some("tess"), &Tweak { counter: Some(0), ..Tweak::default() }).is_err());
    assert!(crate::counter_allows(0, 0) && crate::counter_allows(5, 6) && !crate::counter_allows(5, 5));
    assert!(!crate::counter_allows(5, 0) && crate::counter_allows(0, 1));
}

#[test]
fn failures_are_throttled_like_password_failures_and_the_options_do_not_reveal_names() {
    let e = env();
    let who = signed_in(&e, "owner", true);
    let mut auth = SoftAuthenticator::es256();
    enrol(&e, &who, &mut auth, "k");
    // Five bad assertions for the account (the free ones), then the account is delayed.
    for _ in 0..5 {
        let r = login(&e, &mut auth, Some("owner"), &Tweak { bad_signature: true, ..Tweak::default() });
        assert!(matches!(r, Err(AccountError::InvalidCredentials)));
    }
    assert!(matches!(login(&e, &mut auth, Some("owner"), &Tweak::default()), Err(AccountError::Throttled { .. })));
    // The password step of the same account is held up as well: one counter.
    assert!(matches!(e.acc.login_password("owner", PW, &c()), Err(AccountError::Throttled { .. })));
    e.clock.advance(3600);
    login(&e, &mut auth, Some("owner"), &Tweak::default()).unwrap();

    // The options for a known name with a passkey, one without and an unknown one look alike, and a decoy is stable.
    let tess = signed_in(&e, "tess", false);
    let known = e.acc.passkey_begin_login(&e.rp, Some("owner"), &c()).unwrap();
    let no_key = e.acc.passkey_begin_login(&e.rp, Some("tess"), &c()).unwrap();
    let unknown_a = e.acc.passkey_begin_login(&e.rp, Some("nobody"), &c()).unwrap();
    let unknown_b = e.acc.passkey_begin_login(&e.rp, Some("Nobody "), &c()).unwrap();
    let ids = |v: &Value| -> Vec<String> {
        v["allowCredentials"].as_array().unwrap().iter().map(|d| d["id"].as_str().unwrap().to_string()).collect()
    };
    assert_eq!(ids(&known).len(), 1);
    assert!(!ids(&no_key).is_empty() && !ids(&unknown_a).is_empty());
    assert_eq!(ids(&unknown_a), ids(&unknown_b), "the same decoy for the same name");
    assert_eq!(ids(&no_key), ids(&e.acc.passkey_begin_login(&e.rp, Some("tess"), &c()).unwrap()));
    assert_ne!(ids(&no_key), ids(&unknown_a));
    for v in [&known, &no_key, &unknown_a] {
        assert_eq!(v["userVerification"], "required");
        assert_eq!(v["rpId"], "pm.example.com");
        let mut keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["allowCredentials", "challenge", "rpId", "timeout", "userVerification"]);
    }
    // Answering a decoy list is a failure with the same error as everything else; so is a disabled user.
    let mut stranger = SoftAuthenticator::es256();
    assert!(matches!(
        login(&e, &mut stranger, Some("nobody"), &Tweak::default()),
        Err(AccountError::InvalidCredentials)
    ));
    e.acc.disable_user(&who.user.id, &tess.user.id).unwrap();
    assert!(!ids(&e.acc.passkey_begin_login(&e.rp, Some("tess"), &c()).unwrap()).is_empty());
    // Usernameless: no list at all.
    assert!(ids(&e.acc.passkey_begin_login(&e.rp, None, &c()).unwrap()).is_empty());
}

#[test]
fn a_disabled_account_cannot_sign_in_with_its_passkey() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    let tess = signed_in(&e, "tess", false);
    let mut auth = SoftAuthenticator::es256();
    enrol(&e, &tess, &mut auth, "k");
    login(&e, &mut auth, None, &Tweak::default()).unwrap();
    e.acc.disable_user(&owner.user.id, &tess.user.id).unwrap();
    assert!(matches!(login(&e, &mut auth, None, &Tweak::default()), Err(AccountError::InvalidCredentials)));
    assert!(matches!(login(&e, &mut auth, Some("tess"), &Tweak::default()), Err(AccountError::InvalidCredentials)));
}

#[test]
fn rename_and_remove_with_the_protections() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    let mut a = SoftAuthenticator::es256();
    let mut b = SoftAuthenticator::ed25519();
    let pa = enrol(&e, &owner, &mut a, "first");
    let pb = enrol(&e, &owner, &mut b, "second");
    e.acc.rename_passkey(&owner.user.id, &pa.id, "  Work laptop  ").unwrap();
    let listed = e.acc.list_passkeys(&owner.user.id).unwrap();
    assert_eq!(listed.iter().find(|p| p.id == pa.id).unwrap().name, "Work laptop");
    for bad in ["", "   ", "tab\there"] {
        assert!(e.acc.rename_passkey(&owner.user.id, &pa.id, bad).is_err());
    }
    assert!(matches!(e.acc.rename_passkey(&owner.user.id, "c_nope", "x"), Err(AccountError::NoSuchPasskey)));
    assert!(matches!(e.acc.rename_passkey("u_other", &pa.id, "x"), Err(AccountError::NoSuchPasskey)));

    // Another session of the user exists: removing a passkey ends it, and keeps the one that asked.
    let other = e.acc.create_session(&owner.user.id, "passkey", &c()).unwrap();
    e.acc.remove_passkey(&owner.user.id, &pb.id, Some(&owner.session)).unwrap();
    assert!(e.acc.validate_session(&owner.session).is_ok());
    assert!(e.acc.validate_session(other.id.expose()).is_err());
    assert!(log_has(&e, "passkey_removed"));
    // The removed passkey no longer signs in.
    assert!(login(&e, &mut b, None, &Tweak::default()).is_err());
    // Not someone else's.
    assert!(matches!(e.acc.remove_passkey("u_other", &pa.id, None), Err(AccountError::NoSuchPasskey)));

    // The owner has a password but no authenticator: the last passkey is the account's only second factor.
    assert!(matches!(e.acc.remove_passkey(&owner.user.id, &pa.id, None), Err(AccountError::SecondFactorRequired)));
    assert_eq!(e.acc.passkey_count(&owner.user.id).unwrap(), 1);
}

#[test]
fn the_last_passkey_goes_when_a_password_and_authenticator_remain_but_not_when_the_server_requires_one() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    // Give the owner a working password + TOTP the long way round.
    let LoginStep::EnrolmentRequired { pending, .. } = e.acc.login_password("owner", PW, &c()).unwrap() else {
        panic!("expected enrolment")
    };
    e.acc.begin_totp_enrolment_pending(pending.expose()).unwrap();
    let secret: Vec<u8> = {
        let sealed: Vec<u8> = e
            .acc
            .conn()
            .query_row("SELECT secret FROM credentials WHERE user_id = ?1 AND kind = 'totp'", [&owner.user.id], |r| {
                r.get(0)
            })
            .unwrap();
        e.acc.open_secret(&sealed, &crate::login::totp_aad(&owner.user.id)).unwrap()
    };
    let code = format!("{:06}", crate::totp(&secret, e.clock.now() as u64, 30, 6));
    e.acc.finish_enrolment(pending.expose(), &code, &c()).unwrap();

    let mut auth = SoftAuthenticator::es256();
    let p = enrol(&e, &owner, &mut auth, "k");
    // With the server requiring passkeys, the last one stays.
    e.acc.set_passkey_required(&owner.user.id, true).unwrap();
    assert!(matches!(e.acc.remove_passkey(&owner.user.id, &p.id, None), Err(AccountError::LastPasskey)));
    e.acc.set_passkey_required(&owner.user.id, false).unwrap();
    e.acc.remove_passkey(&owner.user.id, &p.id, None).unwrap();
    assert_eq!(e.acc.passkey_count(&owner.user.id).unwrap(), 0);
}

#[test]
fn a_passkey_counts_as_the_second_factor_and_password_alone_is_refused_for_such_an_account() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    let mut auth = SoftAuthenticator::es256();
    // Before: the password step asks for the authenticator to be set up.
    assert!(matches!(e.acc.login_password("owner", PW, &c()).unwrap(), LoginStep::EnrolmentRequired { .. }));
    enrol(&e, &owner, &mut auth, "k");
    // After: a password holder is told to use the passkey, and is not offered to enrol an authenticator.
    assert!(matches!(e.acc.login_password("owner", PW, &c()), Err(AccountError::PasskeyRequired)));
    // The wrong password is still the plain refusal.
    assert!(matches!(
        e.acc.login_password("owner", "wrong password here", &c()),
        Err(AccountError::InvalidCredentials)
    ));
}

#[test]
fn require_a_passkey_is_an_admin_setting_that_needs_the_admins_own_passkey() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    let tess = signed_in(&e, "tess", false);
    assert!(!e.acc.passkey_required().unwrap());
    // Not without a passkey of one's own, and not by anyone but an administrator.
    assert!(matches!(e.acc.set_passkey_required(&owner.user.id, true), Err(AccountError::InvalidArgument(_))));
    assert!(matches!(e.acc.set_passkey_required(&tess.user.id, false), Err(AccountError::NotAuthorised)));
    let mut auth = SoftAuthenticator::es256();
    enrol(&e, &owner, &mut auth, "k");
    e.acc.set_passkey_required(&owner.user.id, true).unwrap();
    assert!(e.acc.passkey_required().unwrap());
    assert!(log_has(&e, "passkey_required_on"));
    e.acc.set_passkey_required(&owner.user.id, false).unwrap();
    assert!(log_has(&e, "passkey_required_off"));
    assert!(e.acc.verify_security_log().unwrap().is_ok());
}

#[test]
fn with_passkeys_required_a_password_account_without_one_still_signs_in_and_one_with_one_does_not() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    let tess = signed_in(&e, "tess", false);
    let mut auth = SoftAuthenticator::es256();
    enrol(&e, &owner, &mut auth, "k");
    // tess has a password + authenticator, no passkey.
    {
        let LoginStep::EnrolmentRequired { pending, .. } = e.acc.login_password("tess", PW, &c()).unwrap() else {
            panic!()
        };
        e.acc.begin_totp_enrolment_pending(pending.expose()).unwrap();
        let sealed: Vec<u8> = e
            .acc
            .conn()
            .query_row("SELECT secret FROM credentials WHERE user_id = ?1 AND kind = 'totp'", [&tess.user.id], |r| {
                r.get(0)
            })
            .unwrap();
        let secret = e.acc.open_secret(&sealed, &crate::login::totp_aad(&tess.user.id)).unwrap();
        let code = format!("{:06}", crate::totp(&secret, e.clock.now() as u64, 30, 6));
        e.acc.finish_enrolment(pending.expose(), &code, &c()).unwrap();
    }
    e.acc.set_passkey_required(&owner.user.id, true).unwrap();
    // tess can still get to a session by password and code: the layer above restricts it to enrolling a passkey.
    let step = e.acc.login_password("tess", PW, &c()).unwrap();
    assert!(matches!(step, LoginStep::SecondFactorRequired { .. }));
    // The owner has a passkey and an owner with a passkey is refused the password route altogether.
    assert!(matches!(e.acc.login_password("owner", PW, &c()), Err(AccountError::PasskeyRequired)));
    login(&e, &mut auth, Some("owner"), &Tweak::default()).unwrap();
}

#[test]
fn setup_with_a_passkey_makes_a_passkey_only_owner() {
    let e = env();
    let t = e.acc.create_setup_token().unwrap();
    let mut auth = SoftAuthenticator::es256();
    // A bad token, a taken-looking name and an invalid name are refused before anything is made.
    assert!(matches!(
        e.acc.passkey_begin_setup(&e.rp, "pmset_nope", "owner", "", &c()),
        Err(AccountError::InvalidSetupToken)
    ));
    assert!(matches!(
        e.acc.passkey_begin_setup(&e.rp, t.token.expose(), "x", "", &c()),
        Err(AccountError::InvalidUsername(_))
    ));
    let opts = e.acc.passkey_begin_setup(&e.rp, t.token.expose(), "Owner", "Olivia", &c()).unwrap();
    assert_eq!(opts["user"]["name"], "owner");
    assert_eq!(opts["user"]["displayName"], "Olivia");
    assert!(!e.acc.has_server_admin().unwrap(), "nothing is made until the registration verifies");
    // A bad registration does not use the token up.
    let bad = auth.create(&opts, "https://evil.example", &Tweak::default());
    assert!(matches!(
        e.acc.passkey_finish_setup(&e.rp, "k", &bad, Some("p"), &c()),
        Err(AccountError::PasskeyRefused(_))
    ));
    assert!(!e.acc.has_server_admin().unwrap());
    let opts = e.acc.passkey_begin_setup(&e.rp, t.token.expose(), "Owner", "Olivia", &c()).unwrap();
    let resp = auth.create(&opts, ORIGIN, &Tweak::default());
    let ok = e.acc.passkey_finish_setup(&e.rp, "First key", &resp, Some("p"), &c()).unwrap();
    assert!(ok.user.server_admin && ok.user.username == "owner" && ok.user.display_name == "Olivia");
    assert_eq!(e.acc.validate_session(ok.session.id.expose()).unwrap().auth_method, "passkey");
    assert_eq!(e.acc.memberships_of_user(&ok.user.id).unwrap()[0].role, Role::Owner);
    // The user handle is made from the account id the options announced.
    assert_eq!(opts["user"]["id"], b64url_encode(&crate::user_handle(&ok.user.id)));
    // No password exists: the password step is the plain failure, and the dummy hash ran.
    let before = e.acc.dummy_verifications();
    assert!(matches!(e.acc.login_password("owner", PW, &c()), Err(AccountError::InvalidCredentials)));
    assert_eq!(e.acc.dummy_verifications(), before + 1);
    // The setup token is dead (a second registration with it fails), and the passkey signs in.
    assert!(matches!(
        e.acc.passkey_begin_setup(&e.rp, t.token.expose(), "second", "", &c()),
        Err(AccountError::InvalidSetupToken)
    ));
    login(&e, &mut auth, Some("owner"), &Tweak::default()).unwrap();
    assert_eq!(e.acc.list_passkeys(&ok.user.id).unwrap()[0].name, "First key");
    // The same challenge cannot finish twice.
    assert!(e.acc.passkey_finish_setup(&e.rp, "k", &resp, Some("p"), &c()).is_err());
}

#[test]
fn setup_after_reset_owner_with_a_passkey_and_invites_with_a_passkey() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    // An invite accepted with a passkey: the account has the invite's role, no password.
    let inv = e.acc.create_invite(&owner.user.id, Role::Viewer, Some("p"), Duration::from_secs(3600)).unwrap();
    let mut auth = SoftAuthenticator::ed25519();
    let opts = e.acc.passkey_begin_invite(&e.rp, inv.token.expose(), "vera", "Vera", &c()).unwrap();
    let resp = auth.create(&opts, ORIGIN, &Tweak::default());
    // The setup route's challenge does not finish an invite.
    let ok = e.acc.passkey_finish_invite(&e.rp, "phone", &resp, &c()).unwrap();
    assert_eq!(ok.user.username, "vera");
    assert_eq!(e.acc.memberships_of_user(&ok.user.id).unwrap()[0].role, Role::Viewer);
    login(&e, &mut auth, Some("vera"), &Tweak::default()).unwrap();
    // The invite is used up.
    assert!(matches!(
        e.acc.passkey_begin_invite(&e.rp, inv.token.expose(), "vera2", "", &c()),
        Err(AccountError::InvalidInvite)
    ));

    // reset-owner: a new setup token works although an owner exists, and the new account may use a passkey.
    let reset = e.acc.reset_owner().unwrap();
    let mut a2 = SoftAuthenticator::es256();
    let opts = e.acc.passkey_begin_setup(&e.rp, reset.token.expose(), "owner2", "", &c()).unwrap();
    let resp = a2.create(&opts, ORIGIN, &Tweak::default());
    let ok = e.acc.passkey_finish_setup(&e.rp, "k", &resp, None, &c()).unwrap();
    assert!(ok.user.server_admin);
    assert!(e.acc.security_log(100).unwrap().iter().any(|l| l.kind == "owner_reset"));
}

#[test]
fn an_enrolment_link_replaces_how_an_account_signs_in() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    let tess = signed_in(&e, "tess", false);
    let mut old = SoftAuthenticator::es256();
    enrol(&e, &tess, &mut old, "lost phone");
    let token =
        e.acc.create_token(&tess.user.id, &tess.user.id, "p", &NewTokenSpec::new(TokenKind::Agent, "bot")).unwrap();
    assert!(e.acc.validate_session(&tess.session).is_ok());

    let link = e.acc.create_enrolment_link(&owner.user.id, &tess.user.id, Some("p")).unwrap();
    assert!(link.token.expose().starts_with("pmenr_"));
    // Issuing it ended the user's sessions and revoked their tokens.
    assert!(e.acc.validate_session(&tess.session).is_err());
    assert!(e.acc.authenticate_token(token.token.expose(), "p", &c()).is_err());
    assert!(log_has(&e, "enrolment_link_created"));
    // It names the person and nothing else.
    let target = e.acc.enrolment_link_target(link.token.expose(), &c()).unwrap();
    assert_eq!(target.username, "tess");
    assert!(matches!(e.acc.enrolment_link_target("pmenr_wrong", &c()), Err(AccountError::InvalidEnrolmentLink)));

    // A new passkey through the link: single use, every earlier way in is gone, the person is signed in.
    let mut fresh = SoftAuthenticator::ed25519();
    let opts = e.acc.passkey_begin_link(&e.rp, link.token.expose(), &c()).unwrap();
    assert_eq!(opts["user"]["name"], "tess");
    let resp = fresh.create(&opts, ORIGIN, &Tweak::default());
    let ok = e.acc.passkey_finish_link(&e.rp, "new phone", &resp, &c()).unwrap();
    assert_eq!(ok.user.id, tess.user.id);
    let list = e.acc.list_passkeys(&tess.user.id).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "new phone");
    assert!(login(&e, &mut old, Some("tess"), &Tweak::default()).is_err(), "the old passkey is gone");
    assert!(
        matches!(e.acc.login_password("tess", PW, &c()), Err(AccountError::InvalidCredentials)),
        "and the old password"
    );
    login(&e, &mut fresh, Some("tess"), &Tweak::default()).unwrap();
    assert!(matches!(
        e.acc.passkey_begin_link(&e.rp, link.token.expose(), &c()),
        Err(AccountError::InvalidEnrolmentLink)
    ));
    assert!(log_has(&e, "enrolment_link_used"));
}

#[test]
fn an_enrolment_link_can_set_a_new_password_that_leads_to_an_authenticator() {
    let e = env();
    let owner = signed_in(&e, "owner", true);
    let tess = signed_in(&e, "tess", false);
    let link = e.acc.create_enrolment_link(&owner.user.id, &tess.user.id, Some("p")).unwrap();
    assert!(matches!(
        e.acc.redeem_link_with_password(link.token.expose(), "short", &c()),
        Err(AccountError::WeakPassword(_))
    ));
    let step = e.acc.redeem_link_with_password(link.token.expose(), "a brand new passphrase", &c()).unwrap();
    let LoginStep::EnrolmentRequired { pending, .. } = step else { panic!("expected enrolment") };
    e.acc.begin_totp_enrolment_pending(pending.expose()).unwrap();
    // Single use; the old password is replaced.
    assert!(matches!(
        e.acc.redeem_link_with_password(link.token.expose(), "a brand new passphrase", &c()),
        Err(AccountError::InvalidEnrolmentLink)
    ));
    assert!(matches!(e.acc.login_password("tess", PW, &c()), Err(AccountError::InvalidCredentials)));
    assert!(matches!(
        e.acc.login_password("tess", "a brand new passphrase", &c()).unwrap(),
        LoginStep::EnrolmentRequired { .. }
    ));
}

#[test]
fn who_may_issue_an_enrolment_link() {
    let e = env();
    let admin = signed_in(&e, "admin", true);
    let owner2 = signed_in(&e, "owen", false);
    e.acc.set_membership(&admin.user.id, "p", &owner2.user.id, Role::Owner).unwrap();
    let tess = signed_in(&e, "tess", false);
    let vera = signed_in(&e, "vera", false);
    e.acc.set_membership(&admin.user.id, "p", &vera.user.id, Role::Viewer).unwrap();
    // A project owner may for a tester or viewer of that project ...
    e.acc.create_enrolment_link(&owner2.user.id, &tess.user.id, Some("p")).unwrap();
    e.acc.create_enrolment_link(&owner2.user.id, &vera.user.id, Some("p")).unwrap();
    // ... not for another project, a peer owner, a server administrator, or oneself, and a tester may not at all.
    assert!(matches!(
        e.acc.create_enrolment_link(&owner2.user.id, &tess.user.id, Some("other")),
        Err(AccountError::NotAuthorised)
    ));
    assert!(matches!(
        e.acc.create_enrolment_link(&owner2.user.id, &tess.user.id, None),
        Err(AccountError::NotAuthorised)
    ));
    e.acc.set_membership(&admin.user.id, "p", &admin.user.id, Role::Owner).unwrap();
    assert!(matches!(
        e.acc.create_enrolment_link(&owner2.user.id, &admin.user.id, Some("p")),
        Err(AccountError::NotAuthorised)
    ));
    let owner3 = signed_in(&e, "olga", false);
    e.acc.set_membership(&admin.user.id, "p", &owner3.user.id, Role::Owner).unwrap();
    assert!(matches!(
        e.acc.create_enrolment_link(&owner2.user.id, &owner3.user.id, Some("p")),
        Err(AccountError::NotAuthorised)
    ));
    assert!(matches!(
        e.acc.create_enrolment_link(&owner2.user.id, &owner2.user.id, Some("p")),
        Err(AccountError::InvalidArgument(_))
    ));
    assert!(matches!(
        e.acc.create_enrolment_link(&tess.user.id, &vera.user.id, Some("p")),
        Err(AccountError::NotAuthorised)
    ));
    // An administrator may for anyone else, owners included.
    e.acc.create_enrolment_link(&admin.user.id, &owner3.user.id, None).unwrap();
    assert!(matches!(e.acc.create_enrolment_link(&admin.user.id, "u_nobody", None), Err(AccountError::NoSuchUser)));
    // A new link replaces the last one for that user.
    let a = e.acc.create_enrolment_link(&admin.user.id, &tess.user.id, None).unwrap();
    let b = e.acc.create_enrolment_link(&admin.user.id, &tess.user.id, None).unwrap();
    assert!(e.acc.enrolment_link_target(a.token.expose(), &c()).is_err());
    assert!(e.acc.enrolment_link_target(b.token.expose(), &c()).is_ok());
    // Expiry: one hour.
    e.clock.advance(3601);
    assert!(e.acc.enrolment_link_target(b.token.expose(), &c()).is_err());
}

#[test]
fn passkey_limits_and_ceremony_table_are_bounded() {
    let e = env();
    let who = signed_in(&e, "owner", true);
    for i in 0..MAX_PASSKEYS {
        let mut a = SoftAuthenticator::es256();
        enrol(&e, &who, &mut a, &format!("k{i}"));
    }
    assert!(matches!(
        e.acc.passkey_begin_enrol(&e.rp, &who.user.id, &who.session),
        Err(AccountError::PasskeyRefused(_))
    ));
    // Anonymous sign-in options cannot grow the table without bound.
    for _ in 0..5000 {
        let _ = e.acc.passkey_begin_login(&e.rp, None, &ClientInfo::default()).unwrap();
    }
    assert!(e.acc.ceremonies.len() <= 4096);
}

#[test]
fn the_security_log_names_events_and_holds_no_key_material() {
    let e = env();
    let who = signed_in(&e, "owner", true);
    let mut auth = SoftAuthenticator::es256();
    enrol(&e, &who, &mut auth, "k");
    login(&e, &mut auth, Some("owner"), &Tweak::default()).unwrap();
    let _ = login(&e, &mut auth, Some("owner"), &Tweak { bad_signature: true, ..Tweak::default() });
    let _ = login(&e, &mut auth, Some("owner"), &Tweak { counter: Some(0), ..Tweak::default() });
    let log = e.acc.security_log(200).unwrap();
    let text: String = log
        .iter()
        .map(|l| format!("{} {} {} {}\n", l.kind, l.actor, l.client_addr.clone().unwrap_or_default(), l.detail))
        .collect();
    for needle in [
        b64url_encode(&auth.credential_id),
        crate::util::hex(&auth.credential_id),
        b64url_encode(&auth.public_key_cose()),
    ] {
        assert!(!text.contains(&needle), "{needle} in the security log");
    }
    for kind in ["passkey_added", "login_success", "passkey_failure", "passkey_clone_suspected"] {
        assert!(log.iter().any(|l| l.kind == kind), "{kind}");
    }
    assert!(e.acc.verify_security_log().unwrap().is_ok());
}
