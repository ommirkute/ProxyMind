//! OIDC (ADR-0022 step 8) against `server.db`: providers, the single-use pending sign-in, identity mapping, linking,
//! auto-create, group claims and the owner rules. The network side (discovery, the token request) is `pm-api`'s; the
//! tokens' verification is in `oidc::jwt`'s own tests.

use std::sync::Arc;
use std::time::Duration;

use crate::oidc::jwt::IdClaims;
use crate::oidc::*;
use crate::*;

const T0: i64 = 1_700_000_000;
const PW: &str = "correct horse battery";
const PROJECT: &str = "p";
const ISS: &str = "https://idp.example";

struct Env {
    acc: Accounts,
    clock: Arc<ManualClock>,
    admin: User,
}

fn c() -> ClientInfo {
    ClientInfo::new("203.0.113.9")
}

fn env() -> Env {
    let clock = Arc::new(ManualClock::new(T0));
    let acc =
        Accounts::open_in_memory(ServerKey::from_bytes([7; 32]), Config::insecure_for_tests(), clock.clone()).unwrap();
    let t = acc.create_setup_token().unwrap();
    let admin = acc.bootstrap_owner(t.token.expose(), "admin", "Admin", PW, &c()).unwrap();
    acc.set_membership(&admin.id, PROJECT, &admin.id, Role::Owner).unwrap();
    Env { acc, clock, admin }
}

fn input(name: &str) -> ProviderInput {
    ProviderInput {
        name: name.into(),
        issuer: ISS.into(),
        client_id: "pm".into(),
        client_secret: SecretChange::Set(Secret::new("s3cret-value-xyz")),
        scopes: vec!["profile".into(), "email".into()],
        group_claim: None,
        role_map: vec![],
        auto_create_domains: vec![],
        email_linking: false,
        required_acr: vec![],
        required_amr: vec![],
        enabled: true,
    }
}

fn provider(e: &Env, edit: impl FnOnce(&mut ProviderInput)) -> OidcProvider {
    let mut i = input("Corp SSO");
    edit(&mut i);
    e.acc.oidc_provider_create(&e.admin.id, i).unwrap()
}

fn claims(sub: &str, email: Option<&str>, verified: bool, groups: &[&str]) -> IdClaims {
    IdClaims {
        iss: ISS.into(),
        sub: sub.into(),
        email: email.map(str::to_string),
        email_verified: verified,
        name: Some("Some Person".into()),
        preferred_username: None,
        groups: groups.iter().map(|g| g.to_string()).collect(),
        acr: None,
        amr: vec![],
    }
}

/// begin + take, as the browser's round trip does.
fn pending(e: &Env, p: &OidcProvider, purpose: BeginPurpose) -> OidcPendingInfo {
    let b = e.acc.oidc_begin(&p.id, purpose, "/x", &c()).unwrap();
    e.acc.oidc_take(b.binding.expose(), &b.state).unwrap()
}

fn sign_in(e: &Env, p: &OidcProvider, cl: &IdClaims) -> Result<OidcOutcome> {
    e.acc.oidc_complete(pending(e, p, BeginPurpose::Login), cl, PROJECT, &c())
}

fn refused(r: Result<OidcOutcome>) -> &'static str {
    match r {
        Err(AccountError::OidcRefused(why)) => why,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn user_of(o: OidcOutcome) -> (User, SessionMethod) {
    match o {
        OidcOutcome::SignedIn { login, .. } => {
            (login.user.clone(), SessionMethod(login.session.id.expose().to_string()))
        }
        other => panic!("{other:?}"),
    }
}

struct SessionMethod(String);

/// A viewer-or-tester account made by invitation (password route), so it exists before any link.
fn member(e: &Env, name: &str, role: Role) -> User {
    let inv = e.acc.create_invite(&e.admin.id, role, Some(PROJECT), Duration::from_secs(3600)).unwrap();
    e.acc.accept_invite(inv.token.expose(), name, name, PW, &c()).unwrap()
}

fn role_of(e: &Env, user: &User) -> Option<Role> {
    e.acc.memberships_of_user(&user.id).unwrap().into_iter().find(|m| m.project_id == PROJECT).map(|m| m.role)
}

fn add_passkey_row(e: &Env, user: &User) {
    e.acc
        .conn()
        .execute(
            "INSERT INTO credentials (id, user_id, kind, external_id, secret, counter, created_at) \
             VALUES (?1, ?2, 'passkey', x'0102030405060708', x'00', 0, 0)",
            rusqlite::params![format!("c_{}", user.id), user.id],
        )
        .unwrap();
}

fn log_kinds(e: &Env) -> Vec<String> {
    e.acc.security_log(500).unwrap().into_iter().map(|l| l.kind).collect()
}

// ---- providers ------------------------------------------------------------------------------------------------------

#[test]
fn only_a_server_admin_configures_providers_and_the_secret_is_sealed() {
    let e = env();
    let tess = member(&e, "tess", Role::Tester);
    assert!(matches!(e.acc.oidc_provider_create(&tess.id, input("x")), Err(AccountError::NotAuthorised)));
    let p = provider(&e, |_| {});
    assert!(p.has_secret && p.enabled && !p.email_linking && p.auto_create_domains.is_empty());
    assert_eq!(e.acc.oidc_client_secret(&p.id).unwrap().unwrap().expose(), "s3cret-value-xyz");
    // The stored blob is not the secret, and a different provider id would not open it.
    let blob: Vec<u8> = e
        .acc
        .conn()
        .query_row("SELECT client_secret FROM oidc_providers WHERE id = ?1", [&p.id], |r| r.get(0))
        .unwrap();
    assert!(!blob.windows(6).any(|w| w == b"s3cret"));
    assert!(matches!(e.acc.open_oidc(&blob, b"proxymind/oidc-secret/v1/other"), Err(AccountError::Decrypt)));
    // The TOTP key does not open it either (separate keys per purpose).
    assert!(e.acc.open_secret(&blob, format!("proxymind/oidc-secret/v1/{}", p.id).as_bytes()).is_err());
    assert!(!format!("{p:?}").contains("s3cret"));
    // Keep leaves it, Clear removes it, Set replaces it.
    let mut keep = input("Corp SSO");
    keep.client_secret = SecretChange::Keep;
    e.acc.oidc_provider_update(&e.admin.id, &p.id, keep.clone()).unwrap();
    assert_eq!(e.acc.oidc_client_secret(&p.id).unwrap().unwrap().expose(), "s3cret-value-xyz");
    keep.client_secret = SecretChange::Set(Secret::new("new-one"));
    e.acc.oidc_provider_update(&e.admin.id, &p.id, keep.clone()).unwrap();
    assert_eq!(e.acc.oidc_client_secret(&p.id).unwrap().unwrap().expose(), "new-one");
    keep.client_secret = SecretChange::Clear;
    let q = e.acc.oidc_provider_update(&e.admin.id, &p.id, keep).unwrap();
    assert!(!q.has_secret && e.acc.oidc_client_secret(&p.id).unwrap().is_none());
    // No secret anywhere in the security log.
    let log = format!("{:?}", e.acc.security_log(100).unwrap());
    assert!(!log.contains("s3cret") && !log.contains("new-one"));
    assert!(log_kinds(&e).iter().any(|k| k == "oidc_provider_created"));
    assert!(log_kinds(&e).iter().any(|k| k == "oidc_provider_updated"));
}

#[test]
fn a_mapping_to_owner_cannot_be_written_and_bad_input_is_refused() {
    let e = env();
    let mut bad = input("x");
    bad.group_claim = Some("groups".into());
    bad.role_map = vec![RoleMapping { value: "pm-owners".into(), role: Role::Owner }];
    assert!(matches!(e.acc.oidc_provider_create(&e.admin.id, bad), Err(AccountError::InvalidArgument(_))));
    for edit in [
        (|i: &mut ProviderInput| i.issuer = "http://idp.example".into()) as fn(&mut ProviderInput),
        |i| i.issuer = "https://idp.example/?x=1".into(),
        |i| i.issuer = "not a url".into(),
        |i| i.name = " ".into(),
        |i| i.client_id = "has space".into(),
        |i| i.scopes = vec!["bad scope".into()],
        |i| i.auto_create_domains = vec!["*.example.com".into()],
        |i| i.auto_create_domains = vec!["@example.com".into()],
        |i| i.auto_create_domains = vec!["localhost".into()],
        |i| i.role_map = vec![RoleMapping { value: "g".into(), role: Role::Viewer }],
        |i| i.group_claim = Some("a b".into()),
    ] {
        let mut i = input("x");
        edit(&mut i);
        assert!(e.acc.oidc_provider_create(&e.admin.id, i).is_err());
    }
    // One issuer, one provider.
    provider(&e, |_| {});
    assert!(e.acc.oidc_provider_create(&e.admin.id, input("again")).is_err());
}

#[test]
fn the_public_list_has_enabled_providers_only() {
    let e = env();
    let p = provider(&e, |_| {});
    assert_eq!(e.acc.oidc_public_providers().unwrap(), vec![(p.id.clone(), "Corp SSO".to_string())]);
    let mut off = input("Corp SSO");
    off.enabled = false;
    off.client_secret = SecretChange::Keep;
    e.acc.oidc_provider_update(&e.admin.id, &p.id, off).unwrap();
    assert!(e.acc.oidc_public_providers().unwrap().is_empty());
    assert!(matches!(e.acc.oidc_begin(&p.id, BeginPurpose::Login, "/", &c()), Err(AccountError::NoSuchProvider)));
}

// ---- the pending sign-in --------------------------------------------------------------------------------------------

#[test]
fn a_pending_sign_in_is_used_up_by_the_first_try() {
    let e = env();
    let p = provider(&e, |_| {});
    let b = e.acc.oidc_begin(&p.id, BeginPurpose::Login, "/next", &c()).unwrap();
    assert_eq!(e.acc.oidc_pending_len(), 1);
    assert!(b.state.len() >= 40 && b.nonce.len() >= 40 && b.binding.expose().len() == 64);
    let info = e.acc.oidc_take(b.binding.expose(), &b.state).unwrap();
    assert_eq!((info.next.as_str(), info.kind), ("/next", PendingPurpose::Login));
    assert_eq!(info.nonce, b.nonce);
    assert_eq!(crate::oidc::discovery::pkce_challenge(info.verifier.expose()), b.code_challenge);
    // Replayed.
    assert!(matches!(e.acc.oidc_take(b.binding.expose(), &b.state), Err(AccountError::InvalidPending)));
    // A wrong state uses it up too: no second try with the right one.
    let b = e.acc.oidc_begin(&p.id, BeginPurpose::Login, "/", &c()).unwrap();
    assert!(matches!(e.acc.oidc_take(b.binding.expose(), "wrong"), Err(AccountError::InvalidPending)));
    assert!(matches!(e.acc.oidc_take(b.binding.expose(), &b.state), Err(AccountError::InvalidPending)));
    // Another browser's binding finds nothing, and neither does a malformed one.
    let b = e.acc.oidc_begin(&p.id, BeginPurpose::Login, "/", &c()).unwrap();
    assert!(matches!(e.acc.oidc_take(&"0".repeat(64), &b.state), Err(AccountError::InvalidPending)));
    assert!(matches!(e.acc.oidc_take("short", &b.state), Err(AccountError::InvalidPending)));
    assert!(matches!(e.acc.oidc_take("", ""), Err(AccountError::InvalidPending)));
    // The real binding is still there (the foreign attempts did not touch it) and expires after ten minutes.
    e.clock.advance(601);
    assert!(matches!(e.acc.oidc_take(b.binding.expose(), &b.state), Err(AccountError::InvalidPending)));
}

#[test]
fn the_store_is_bounded() {
    let e = env();
    let p = provider(&e, |_| {});
    for _ in 0..MAX_PENDING + 20 {
        e.acc.oidc_begin(&p.id, BeginPurpose::Login, "/", &c()).unwrap();
    }
    assert_eq!(e.acc.oidc_pending_len(), MAX_PENDING);
}

// ---- who signs in ---------------------------------------------------------------------------------------------------

#[test]
fn an_unknown_identity_is_refused_by_default() {
    let e = env();
    let p = provider(&e, |_| {});
    assert_eq!(refused(sign_in(&e, &p, &claims("sub-1", Some("new@corp.example"), true, &[]))), "no_account");
    assert!(log_kinds(&e).iter().any(|k| k == "oidc_failure"));
    assert!(e.acc.list_users().unwrap().len() == 1, "nothing was created");
}

#[test]
fn email_linking_is_off_by_default_and_needs_a_verified_email_when_on() {
    let e = env();
    let tess = member(&e, "tess@corp.example", Role::Tester);
    let off = provider(&e, |_| {});
    assert_eq!(refused(sign_in(&e, &off, &claims("s1", Some("tess@corp.example"), true, &[]))), "no_account");
    assert!(e.acc.oidc_identities(&tess.id).unwrap().is_empty());
    let mut on = input("Corp SSO");
    on.email_linking = true;
    on.client_secret = SecretChange::Keep;
    e.acc.oidc_provider_update(&e.admin.id, &off.id, on).unwrap();
    let p = e.acc.oidc_provider(&off.id).unwrap().unwrap();
    // Unverified: no link.
    assert_eq!(refused(sign_in(&e, &p, &claims("s1", Some("tess@corp.example"), false, &[]))), "no_account");
    assert!(e.acc.oidc_identities(&tess.id).unwrap().is_empty());
    // Verified: linked, signed in, audited.
    let (u, _) = user_of(sign_in(&e, &p, &claims("s1", Some("TESS@corp.example"), true, &[])).unwrap());
    assert_eq!(u.id, tess.id);
    let ids = e.acc.oidc_identities(&tess.id).unwrap();
    assert_eq!((ids.len(), ids[0].linked_by.as_str()), (1, "email"));
    assert_eq!(ids[0].email.as_deref(), Some("TESS@corp.example"));
    assert!(log_kinds(&e).iter().any(|k| k == "oidc_identity_linked"));
    // From now on the pair (iss, sub) is the identity: a different sub with the same email is not the account.
    assert_eq!(refused(sign_in(&e, &p, &claims("other-sub", Some("tess@corp.example"), true, &[]))), "already_linked");
    // And the same sub with another email still is (the email is display only).
    let (u, _) = user_of(sign_in(&e, &p, &claims("s1", Some("changed@corp.example"), true, &[])).unwrap());
    assert_eq!(u.id, tess.id);
    assert_eq!(e.acc.oidc_identities(&tess.id).unwrap()[0].email.as_deref(), Some("changed@corp.example"));
}

#[test]
fn email_linking_never_takes_over_an_owner_or_an_administrator() {
    let e = env();
    // An administrator whose handle is an email.
    let boss = member(&e, "boss@corp.example", Role::Owner);
    let p = provider(&e, |i| i.email_linking = true);
    assert_eq!(refused(sign_in(&e, &p, &claims("s9", Some("boss@corp.example"), true, &[]))), "not_permitted");
    assert!(e.acc.oidc_identities(&boss.id).unwrap().is_empty());
}

#[test]
fn auto_create_gives_a_viewer_for_listed_domains_only() {
    let e = env();
    let p = provider(&e, |i| i.auto_create_domains = vec!["corp.example".into()]);
    // Not listed, unverified, and subdomains do not match.
    for (email, verified) in [
        ("a@other.example", true),
        ("a@corp.example", false),
        ("a@sub.corp.example", true),
        ("a@corp.example.evil", true),
    ] {
        assert_eq!(refused(sign_in(&e, &p, &claims("x", Some(email), verified, &[]))), "no_account", "{email}");
    }
    assert_eq!(e.acc.list_users().unwrap().len(), 1);
    let (u, _) = user_of(sign_in(&e, &p, &claims("sub-a", Some("Ann@Corp.Example"), true, &[])).unwrap());
    assert_eq!(u.username, "ann@corp.example");
    assert_eq!(role_of(&e, &u), Some(Role::Viewer));
    assert!(!u.server_admin);
    // Created with no password and no other way in; signs in again by identity.
    assert!(e.acc.login_password("ann@corp.example", "anything at all", &c()).is_err());
    let (again, _) = user_of(sign_in(&e, &p, &claims("sub-a", Some("ann@corp.example"), true, &[])).unwrap());
    assert_eq!(again.id, u.id);
    // A taken handle is not taken over.
    let _ = member(&e, "bob@corp.example", Role::Tester);
    assert_eq!(refused(sign_in(&e, &p, &claims("sub-b", Some("bob@corp.example"), true, &[]))), "account_exists");
}

#[test]
fn a_group_claim_gives_tester_or_viewer_never_owner_and_leaves_owners_alone() {
    let e = env();
    let map = |i: &mut ProviderInput| {
        i.group_claim = Some("groups".into());
        i.role_map = vec![
            RoleMapping { value: "testers".into(), role: Role::Tester },
            RoleMapping { value: "readers".into(), role: Role::Viewer },
        ];
        i.auto_create_domains = vec!["corp.example".into()];
    };
    let p = provider(&e, map);
    // A new account is a viewer whatever the claim says; the claim is applied at the next sign-in.
    let (u, _) = user_of(sign_in(&e, &p, &claims("s1", Some("a@corp.example"), true, &["testers"])).unwrap());
    assert_eq!(role_of(&e, &u), Some(Role::Viewer));
    let (_, _) =
        user_of(sign_in(&e, &p, &claims("s1", Some("a@corp.example"), true, &["testers", "readers"])).unwrap());
    assert_eq!(role_of(&e, &u), Some(Role::Tester), "the higher mapped role wins");
    // Group removed: back to viewer, not removed.
    let (_, _) = user_of(sign_in(&e, &p, &claims("s1", Some("a@corp.example"), true, &[])).unwrap());
    assert_eq!(role_of(&e, &u), Some(Role::Viewer));
    // Groups that merely look like owner or admin grant nothing.
    let (_, _) = user_of(
        sign_in(&e, &p, &claims("s1", Some("a@corp.example"), true, &["owner", "admin", "owners", "proxymind-owner"]))
            .unwrap(),
    );
    assert_eq!(role_of(&e, &u), Some(Role::Viewer));
    // A role a person gave is never lowered by a claim (and a viewer by hand may be raised).
    let tess = member(&e, "tess", Role::Tester);
    let tess_link = pending(
        &e,
        &p,
        BeginPurpose::Link {
            user_id: tess.id.clone(),
            session_ref: {
                let s = e.acc.create_session(&tess.id, "password+totp", &c()).unwrap();
                s.reference
            },
            fresh_secs: 600,
        },
    );
    e.acc.oidc_complete(tess_link, &claims("t1", Some("tess@x.example"), true, &["readers"]), PROJECT, &c()).unwrap();
    let (_, _) = user_of(sign_in(&e, &p, &claims("t1", Some("tess@x.example"), true, &["readers"])).unwrap());
    assert_eq!(role_of(&e, &tess), Some(Role::Tester), "the owner's grant stands");
    // The owner is untouched, whatever the claim, and gets no session without a local second factor.
    let owner_session = e.acc.create_session(&e.admin.id, "password+totp", &c()).unwrap();
    add_passkey_row(&e, &e.admin);
    let pending_link = pending(
        &e,
        &p,
        BeginPurpose::Link { user_id: e.admin.id.clone(), session_ref: owner_session.reference, fresh_secs: 600 },
    );
    e.acc.oidc_complete(pending_link, &claims("o1", None, false, &[]), PROJECT, &c()).unwrap();
    let (o, _) = user_of(sign_in(&e, &p, &claims("o1", None, false, &["readers"])).unwrap());
    assert_eq!(o.id, e.admin.id);
    assert_eq!(role_of(&e, &e.admin), Some(Role::Owner));
    assert!(e.acc.get_user(&e.admin.id).unwrap().unwrap().server_admin);
}

#[test]
fn an_owner_or_administrator_needs_a_local_way_in_to_use_a_provider() {
    let e = env();
    let p = provider(&e, |_| {});
    let session = e.acc.create_session(&e.admin.id, "password+totp", &c()).unwrap();
    // Linking is refused at the start while the account has no passkey (and no authenticator).
    let begun = e.acc.oidc_begin(
        &p.id,
        BeginPurpose::Link { user_id: e.admin.id.clone(), session_ref: session.reference.clone(), fresh_secs: 600 },
        "/",
        &c(),
    );
    assert!(matches!(begun, Err(AccountError::OidcRefused("owner_needs_local_factor"))));
    add_passkey_row(&e, &e.admin);
    let pend = pending(
        &e,
        &p,
        BeginPurpose::Link { user_id: e.admin.id.clone(), session_ref: session.reference.clone(), fresh_secs: 600 },
    );
    match e.acc.oidc_complete(pend, &claims("adm", None, false, &[]), PROJECT, &c()).unwrap() {
        OidcOutcome::Linked(i) => assert_eq!((i.linked_by.as_str(), i.provider_id.as_str()), ("self", p.id.as_str())),
        other => panic!("{other:?}"),
    }
    // Signing in works while the passkey stays, and stops when it is gone.
    assert!(sign_in(&e, &p, &claims("adm", None, false, &[])).is_ok());
    e.acc.conn().execute("DELETE FROM credentials WHERE kind = 'passkey'", []).unwrap();
    assert_eq!(refused(sign_in(&e, &p, &claims("adm", None, false, &[]))), "owner_needs_local_factor");
}

#[test]
fn a_disabled_account_is_refused() {
    let e = env();
    let p = provider(&e, |i| i.auto_create_domains = vec!["corp.example".into()]);
    let (u, _) = user_of(sign_in(&e, &p, &claims("s1", Some("a@corp.example"), true, &[])).unwrap());
    e.acc.disable_user(&e.admin.id, &u.id).unwrap();
    assert_eq!(refused(sign_in(&e, &p, &claims("s1", Some("a@corp.example"), true, &[]))), "not_permitted");
    assert!(e.acc.list_sessions(&u.id).unwrap().is_empty());
}

#[test]
fn refusals_are_throttled_by_address_like_other_sign_ins() {
    let e = env();
    let p = provider(&e, |_| {});
    for _ in 0..20 {
        let _ = sign_in(&e, &p, &claims("nobody", None, false, &[]));
    }
    assert!(matches!(e.acc.oidc_begin(&p.id, BeginPurpose::Login, "/", &c()), Err(AccountError::Throttled { .. })));
    assert!(matches!(e.acc.oidc_check_throttle(&c()), Err(AccountError::Throttled { .. })));
    // Another address is not affected.
    assert!(e.acc.oidc_begin(&p.id, BeginPurpose::Login, "/", &ClientInfo::new("198.51.100.1")).is_ok());
}

// ---- linking and unlinking ------------------------------------------------------------------------------------------

#[test]
fn linking_is_bound_to_a_live_fresh_session_and_to_one_identity_per_provider() {
    let e = env();
    let p = provider(&e, |_| {});
    let tess = member(&e, "tess", Role::Tester);
    let vic = member(&e, "vic", Role::Viewer);
    let s = e.acc.create_session(&tess.id, "password+totp", &c()).unwrap();
    let link = |user: &User, sref: &str| BeginPurpose::Link {
        user_id: user.id.clone(),
        session_ref: sref.into(),
        fresh_secs: 600,
    };
    // Someone else's session reference, or none.
    assert!(matches!(e.acc.oidc_begin(&p.id, link(&vic, &s.reference), "/", &c()), Err(AccountError::SessionInvalid)));
    assert!(matches!(
        e.acc.oidc_begin(&p.id, link(&tess, "0000000000000000"), "/", &c()),
        Err(AccountError::SessionInvalid)
    ));
    // A session that ends before the provider answers.
    let pend = pending(&e, &p, link(&tess, &s.reference));
    e.acc.revoke_session(s.id.expose()).unwrap();
    assert_eq!(refused(e.acc.oidc_complete(pend, &claims("t1", None, false, &[]), PROJECT, &c())), "link_expired");
    // A sign-in that is too old by the time it answers.
    let s = e.acc.create_session(&tess.id, "password+totp", &c()).unwrap();
    let pend = pending(&e, &p, link(&tess, &s.reference));
    e.clock.advance(601);
    assert_eq!(refused(e.acc.oidc_complete(pend, &claims("t1", None, false, &[]), PROJECT, &c())), "link_expired");
    // The good case, then a second link for the same provider and the same identity on another account.
    let s = e.acc.create_session(&tess.id, "password+totp", &c()).unwrap();
    let pend = pending(&e, &p, link(&tess, &s.reference));
    assert!(matches!(
        e.acc.oidc_complete(pend, &claims("t1", Some("t@x.example"), true, &[]), PROJECT, &c()),
        Ok(OidcOutcome::Linked(_))
    ));
    assert!(matches!(
        e.acc.oidc_begin(&p.id, link(&tess, &s.reference), "/", &c()),
        Err(AccountError::OidcRefused("already_linked"))
    ));
    let sv = e.acc.create_session(&vic.id, "password+totp", &c()).unwrap();
    let pend = pending(&e, &p, link(&vic, &sv.reference));
    assert_eq!(refused(e.acc.oidc_complete(pend, &claims("t1", None, false, &[]), PROJECT, &c())), "identity_in_use");
    assert!(e.acc.oidc_identities(&vic.id).unwrap().is_empty());
    // Signing in with the linked identity gives the OIDC session method.
    let (u, sid) = user_of(sign_in(&e, &p, &claims("t1", None, false, &[])).unwrap());
    assert_eq!(u.id, tess.id);
    assert_eq!(e.acc.validate_session(&sid.0).unwrap().auth_method, "oidc");
}

#[test]
fn unlinking_keeps_a_way_to_sign_in_and_ends_other_sessions() {
    let e = env();
    let p = provider(&e, |i| i.auto_create_domains = vec!["corp.example".into()]);
    // An account that only has the identity cannot drop it.
    let (only, sid) = user_of(sign_in(&e, &p, &claims("s1", Some("a@corp.example"), true, &[])).unwrap());
    let id = e.acc.oidc_identities(&only.id).unwrap()[0].id.clone();
    assert!(matches!(e.acc.oidc_unlink(&only.id, &id, Some(&sid.0)), Err(AccountError::LastSignIn)));
    // With a passkey it can; the other session ends, the current one stays.
    add_passkey_row(&e, &only);
    let (_, other) = user_of(sign_in(&e, &p, &claims("s1", Some("a@corp.example"), true, &[])).unwrap());
    e.acc.oidc_unlink(&only.id, &id, Some(&sid.0)).unwrap();
    assert!(e.acc.validate_session(&sid.0).is_ok());
    assert!(e.acc.validate_session(&other.0).is_err());
    assert!(e.acc.oidc_identities(&only.id).unwrap().is_empty());
    assert!(matches!(e.acc.oidc_unlink(&only.id, &id, None), Err(AccountError::NoSuchIdentity)));
    // Someone else's identity is not theirs to unlink.
    let (b, _) = user_of(sign_in(&e, &p, &claims("s2", Some("b@corp.example"), true, &[])).unwrap());
    let bid = e.acc.oidc_identities(&b.id).unwrap()[0].id.clone();
    assert!(matches!(e.acc.oidc_unlink(&only.id, &bid, None), Err(AccountError::NoSuchIdentity)));
    assert!(log_kinds(&e).iter().any(|k| k == "oidc_identity_unlinked"));
}

#[test]
fn deleting_a_provider_unlinks_its_identities() {
    let e = env();
    let p = provider(&e, |i| i.auto_create_domains = vec!["corp.example".into()]);
    let (u, _) = user_of(sign_in(&e, &p, &claims("s1", Some("a@corp.example"), true, &[])).unwrap());
    e.acc.oidc_provider_delete(&e.admin.id, &p.id).unwrap();
    assert!(e.acc.oidc_identities(&u.id).unwrap().is_empty());
    assert!(e.acc.oidc_provider(&p.id).unwrap().is_none());
    assert!(matches!(e.acc.oidc_provider_delete(&e.admin.id, &p.id), Err(AccountError::NoSuchProvider)));
}

// ---- invites --------------------------------------------------------------------------------------------------------

#[test]
fn an_invite_can_be_redeemed_by_signing_in_with_a_provider() {
    let e = env();
    let p = provider(&e, |_| {});
    let inv = e.acc.create_invite(&e.admin.id, Role::Tester, Some(PROJECT), Duration::from_secs(3600)).unwrap();
    let begin = BeginPurpose::Invite { token: inv.token.expose().to_string() };
    let mut cl = claims("inv-sub", Some("New.Person@corp.example"), true, &[]);
    cl.preferred_username = Some("new.person".into());
    let out = e.acc.oidc_complete(pending(&e, &p, begin.clone()), &cl, PROJECT, &c()).unwrap();
    let OidcOutcome::SignedIn { login, created, .. } = out else { panic!() };
    assert!(created);
    assert_eq!(login.user.username, "new.person");
    assert_eq!(role_of(&e, &login.user), Some(Role::Tester));
    assert_eq!(e.acc.validate_session(login.session.id.expose()).unwrap().auth_method, "oidc");
    assert_eq!(e.acc.oidc_identities(&login.user.id).unwrap()[0].linked_by, "invite");
    // Used up.
    assert!(matches!(e.acc.oidc_begin(&p.id, begin, "/", &c()), Err(AccountError::InvalidInvite)));
    // An owner invite is not redeemable this way.
    let inv = e.acc.create_invite(&e.admin.id, Role::Owner, Some(PROJECT), Duration::from_secs(3600)).unwrap();
    let r = e.acc.oidc_begin(&p.id, BeginPurpose::Invite { token: inv.token.expose().into() }, "/", &c());
    assert!(matches!(r, Err(AccountError::OidcRefused("owner_invite"))));
    // A taken handle gets a number; an identity that already has an account does not burn an invite.
    let inv = e.acc.create_invite(&e.admin.id, Role::Viewer, Some(PROJECT), Duration::from_secs(3600)).unwrap();
    let mut other = claims("inv-sub-2", Some("x@corp.example"), true, &[]);
    other.preferred_username = Some("new.person".into());
    let begin = BeginPurpose::Invite { token: inv.token.expose().into() };
    let OidcOutcome::SignedIn { login, .. } =
        e.acc.oidc_complete(pending(&e, &p, begin), &other, PROJECT, &c()).unwrap()
    else {
        panic!()
    };
    assert_eq!(login.user.username, "new.person-2");
    let inv = e.acc.create_invite(&e.admin.id, Role::Viewer, Some(PROJECT), Duration::from_secs(3600)).unwrap();
    let begin = BeginPurpose::Invite { token: inv.token.expose().into() };
    assert_eq!(refused(e.acc.oidc_complete(pending(&e, &p, begin), &cl, PROJECT, &c())), "already_linked");
    assert!(
        e.acc.list_invites().unwrap().iter().filter(|i| i.used_at.is_none() && i.revoked_at.is_none()).count() == 2,
        "the owner invite and this one are still open"
    );
    // A bad token is an invalid invite, and counts as a failure.
    assert!(matches!(
        e.acc.oidc_begin(&p.id, BeginPurpose::Invite { token: "nope".into() }, "/", &c()),
        Err(AccountError::InvalidInvite)
    ));
}

#[test]
fn an_enrolment_link_also_cuts_off_the_identities_linked_to_the_account() {
    let e = env();
    let p = provider(&e, |i| i.auto_create_domains = vec!["corp.example".into()]);
    let (u, _) = user_of(sign_in(&e, &p, &claims("s1", Some("a@corp.example"), true, &[])).unwrap());
    assert_eq!(e.acc.oidc_identity_count(&u.id).unwrap(), 1);
    let link = e.acc.create_enrolment_link(&e.admin.id, &u.id, Some(PROJECT)).unwrap();
    // Issuing the link ends the sessions; redeeming it replaces how the account signs in, identities included.
    assert!(e.acc.list_sessions(&u.id).unwrap().is_empty());
    e.acc.redeem_link_with_password(link.token.expose(), "a brand new passphrase", &c()).unwrap();
    assert_eq!(e.acc.oidc_identity_count(&u.id).unwrap(), 0);
    assert_eq!(refused(sign_in(&e, &p, &claims("s1", None, false, &[]))), "no_account");
}
