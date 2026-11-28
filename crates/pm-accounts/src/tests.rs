//! Tests for the whole crate. Time is a `ManualClock`; Argon2 runs at test cost.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::totp::{format_code, hotp, totp};
use crate::util::{base32, hex, random};
use crate::*;

const T0: i64 = 1_700_000_000;
const PW: &str = "correct horse battery";

fn key() -> ServerKey {
    ServerKey::from_bytes([7; 32])
}

fn c() -> ClientInfo {
    ClientInfo::new("203.0.113.9")
}

struct Env {
    acc: Accounts,
    clock: Arc<ManualClock>,
}

fn env_with(cfg: Config) -> Env {
    let clock = Arc::new(ManualClock::new(T0));
    let acc = Accounts::open_in_memory(key(), cfg, clock.clone()).unwrap();
    Env { acc, clock }
}

fn env() -> Env {
    env_with(Config::insecure_for_tests())
}

fn viewer_env() -> Env {
    env_with(Config { allow_password_only_viewers: true, ..Config::insecure_for_tests() })
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let p = std::env::temp_dir().join(format!("pm-accounts-{name}-{}", hex(&random::<8>().unwrap())));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn code_at(secret: &[u8], t: i64) -> String {
    format_code(totp(secret, t as u64, 30, 6))
}

/// The raw TOTP secret of a user (what an authenticator holds), read back through the server key.
fn raw_secret(acc: &Accounts, user_id: &str) -> Vec<u8> {
    let sealed: Vec<u8> = acc
        .conn()
        .query_row("SELECT secret FROM credentials WHERE user_id = ?1 AND kind = 'totp'", [user_id], |r| r.get(0))
        .unwrap();
    acc.open_secret(&sealed, &crate::login::totp_aad(user_id)).unwrap()
}

fn bootstrap(e: &Env) -> User {
    let t = e.acc.create_setup_token().unwrap();
    e.acc.bootstrap_owner(t.token.expose(), "owner", "Owner", PW, &c()).unwrap()
}

struct Signed {
    user: User,
    secret: Vec<u8>,
    session: String,
    codes: Vec<String>,
}

/// Bootstraps the owner and completes the first sign-in with TOTP enrolment.
fn owner(e: &Env) -> Signed {
    let user = bootstrap(e);
    enrol(e, "owner", PW, user)
}

fn enrol(e: &Env, username: &str, password: &str, user: User) -> Signed {
    let LoginStep::EnrolmentRequired { pending, .. } = e.acc.login_password(username, password, &c()).unwrap() else {
        panic!("expected enrolment")
    };
    e.acc.begin_totp_enrolment_pending(pending.expose()).unwrap();
    let secret = raw_secret(&e.acc, &user.id);
    let (ok, codes) = e.acc.finish_enrolment(pending.expose(), &code_at(&secret, e.clock.now()), &c()).unwrap();
    Signed { user, secret, session: ok.session.id.expose().to_string(), codes }
}

/// Signs `username` in with its TOTP at the current time (the caller moves the clock to a fresh step first).
fn sign_in(e: &Env, username: &str, secret: &[u8]) -> LoginSuccess {
    let LoginStep::SecondFactorRequired { pending, .. } = e.acc.login_password(username, PW, &c()).unwrap() else {
        panic!("expected second factor")
    };
    e.acc.login_second_factor(pending.expose(), &code_at(secret, e.clock.now()), &c()).unwrap()
}

/// An invited user with a role in project `p` (invited by `admin`).
fn invited(e: &Env, admin: &str, name: &str, role: Role) -> User {
    let inv = e.acc.create_invite(admin, role, Some("p"), Duration::from_secs(3600)).unwrap();
    e.acc.accept_invite(inv.token.expose(), name, name, PW, &c()).unwrap()
}

fn session_of(step: LoginStep) -> String {
    match step {
        LoginStep::Authenticated(s) => s.session.id.expose().to_string(),
        other => panic!("expected a session, got {other:?}"),
    }
}

// ---- primitives ---------------------------------------------------------------------------------------------

#[test]
fn hotp_matches_rfc_4226_appendix_d() {
    let secret = b"12345678901234567890";
    let want = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489];
    for (counter, w) in want.iter().enumerate() {
        assert_eq!(hotp(secret, counter as u64, 6), *w, "counter {counter}");
    }
}

#[test]
fn totp_matches_rfc_6238_sha1_vectors() {
    let secret = b"12345678901234567890";
    let vectors = [
        (59, 94287082),
        (1111111109, 7081804),
        (1111111111, 14050471),
        (1234567890, 89005924),
        (2000000000, 69279037),
        (20000000000, 65353130),
    ];
    for (t, want) in vectors {
        assert_eq!(totp(secret, t, 30, 8), want, "t = {t}");
    }
}

#[test]
fn base32_matches_rfc_4648() {
    for (plain, want) in
        [("", ""), ("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foob", "MZXW6YQ"), ("foobar", "MZXW6YTBOI")]
    {
        assert_eq!(base32(plain.as_bytes()), want);
    }
}

#[test]
fn password_policy() {
    use crate::check_password_policy as check;
    assert!(check("short", "alice").is_err());
    assert!(check("a long enough password", "alice").is_ok());
    assert!(check("xxALICExxxxxxxx", "alice").is_err(), "contains the username");
    assert!(check("aaaaaaaaaaaaaaaa", "alice").is_err(), "one character repeated");
    assert!(check("Password12345", "alice").is_err(), "common, any case");
    assert!(check(&"a1".repeat(129), "alice").is_err(), "over 256 characters");
    assert!(check("пароль пароль пароль", "alice").is_ok(), "length is in characters, any script");
}

#[test]
fn gate_limits_concurrency() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let gate = Arc::new(crate::password::Gate::new(2));
    let (now, max) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let (gate, now, max) = (gate.clone(), now.clone(), max.clone());
            std::thread::spawn(move || {
                let _p = gate.acquire();
                let n = now.fetch_add(1, Ordering::SeqCst) + 1;
                max.fetch_max(n, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(20));
                now.fetch_sub(1, Ordering::SeqCst);
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert!(max.load(Ordering::SeqCst) <= 2);
}

// ---- storage and keys ---------------------------------------------------------------------------------------

#[test]
fn migrations_apply_to_an_empty_database_and_are_idempotent() {
    let dir = TempDir::new("migrate");
    let path = dir.file("server.db");
    drop(Accounts::open(&path, key()).unwrap());
    let acc = Accounts::open(&path, key()).unwrap();
    let version: i64 = acc.conn().pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
    assert_eq!(version as usize, crate::migrations::MIGRATIONS.len());
    let tables: i64 = acc
        .conn()
        .query_row("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        tables, 14,
        "the 11 of the first two migrations, enrolment_links and server_settings, then oidc_providers"
    );
    // Applying again to a migrated connection changes nothing.
    crate::migrations::apply(&mut acc.conn()).unwrap();
    drop(acc);
    // A database from a newer ProxyMind is refused rather than misread.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", 999).unwrap();
    drop(conn);
    assert!(matches!(Accounts::open(&path, key()), Err(AccountError::NewerSchema(999))));
}

#[cfg(unix)]
#[test]
fn server_db_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new("dbmode");
    let path = dir.file("server.db");
    drop(Accounts::open(&path, key()).unwrap());
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn server_key_file_is_created_0600_and_reused() {
    let dir = TempDir::new("key");
    let path = dir.file("home/server.key");
    let a = ServerKey::load_or_create(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let b = ServerKey::load_or_create(&path).unwrap();
    assert_eq!(a.derive(KeyPurpose::SessionId), b.derive(KeyPurpose::SessionId), "the same file gives the same key");
    let other = ServerKey::generate().unwrap();
    assert_ne!(a.derive(KeyPurpose::SessionId), other.derive(KeyPurpose::SessionId));
    assert!(!format!("{a:?}").contains(&hex(&a.derive(KeyPurpose::SessionId))));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            matches!(ServerKey::load_or_create(&path), Err(AccountError::ServerKey(_))),
            "world-readable is refused"
        );
    }
}

#[test]
fn derived_keys_are_separate_per_purpose() {
    use KeyPurpose::*;
    let k = key();
    let all = [TotpEncryption, SessionId, RecoveryCode, OneTimeToken, Throttle, AuditChain, ApiToken];
    let derived: Vec<[u8; 32]> = all.iter().map(|p| k.derive(*p)).collect();
    for i in 0..derived.len() {
        assert_ne!(derived[i], [0; 32]);
        for j in i + 1..derived.len() {
            assert_ne!(derived[i], derived[j]);
        }
        assert_ne!(derived[i], [7; 32], "never the master key itself");
    }
    assert_eq!(k.derive(AuditChain), key().derive(AuditChain), "stable");
    assert!(ServerKey::from_hex("zz").is_err() && ServerKey::from_hex(&"ab".repeat(31)).is_err());
    assert!(ServerKey::from_hex(&"ab".repeat(32)).is_ok());
}

#[test]
fn nothing_secret_is_stored_in_plaintext() {
    let dir = TempDir::new("plain");
    let path = dir.file("server.db");
    let clock = Arc::new(ManualClock::new(T0));
    let acc = Accounts::open_with(&path, key(), Config::insecure_for_tests(), clock.clone()).unwrap();
    let e = Env { acc, clock };
    let setup = e.acc.create_setup_token().unwrap();
    let user =
        e.acc.bootstrap_owner(setup.token.expose(), "owner", "Owner", "unique-hunter2-passphrase", &c()).unwrap();
    let LoginStep::EnrolmentRequired { pending, .. } =
        e.acc.login_password("owner", "unique-hunter2-passphrase", &c()).unwrap()
    else {
        panic!()
    };
    let enrolment = e.acc.begin_totp_enrolment_pending(pending.expose()).unwrap();
    let secret = raw_secret(&e.acc, &user.id);
    let (ok, codes) = e.acc.finish_enrolment(pending.expose(), &code_at(&secret, T0), &c()).unwrap();
    let invite = e.acc.create_invite(&user.id, Role::Viewer, Some("p"), Duration::from_secs(60)).unwrap();
    let rotated = e.acc.rotate_session(ok.session.id.expose(), &c()).unwrap();

    let mut disk = Vec::new();
    for name in ["server.db", "server.db-wal"] {
        if let Ok(b) = std::fs::read(dir.file(name)) {
            disk.extend(b);
        }
    }
    let contains = |needle: &[u8]| disk.windows(needle.len()).any(|w| w == needle);
    for (what, text) in [
        ("password", "unique-hunter2-passphrase".to_string()),
        ("setup token", setup.token.expose().into()),
        ("pending token", pending.expose().into()),
        ("session id", ok.session.id.expose().into()),
        ("rotated session id", rotated.id.expose().into()),
        ("invite token", invite.token.expose().into()),
        ("totp base32", enrolment.secret_base32.clone()),
        ("recovery code", codes[0].clone()),
        ("recovery code (bare)", codes[0].replace('-', "")),
    ] {
        assert!(!contains(text.as_bytes()), "{what} is on disk in plain text");
    }
    assert!(!contains(&secret), "the raw TOTP secret is on disk");
    assert!(contains(b"$argon2id$"), "the password is an Argon2id PHC string");
    // The session row holds a 32-byte hash that is not the id.
    let (hash, n): (Vec<u8>, i64) = e
        .acc
        .conn()
        .query_row("SELECT id_hash, COUNT(*) FROM sessions WHERE rotated_from IS NULL", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!((hash.len(), n), (32, 1));
    assert_ne!(hex(&hash), ok.session.id.expose());
}

// ---- bootstrap and invites ----------------------------------------------------------------------------------

#[test]
fn bootstrap_creates_the_first_owner_once() {
    let e = env();
    let t = e.acc.create_setup_token().unwrap();
    assert!(t.token.expose().starts_with("pmset_") && t.expires_at == T0 + 3600);
    assert!(matches!(
        e.acc.bootstrap_owner("pmset_nope", "owner", "O", PW, &c()),
        Err(AccountError::InvalidSetupToken)
    ));
    assert!(matches!(
        e.acc.bootstrap_owner(t.token.expose(), "owner", "O", "short", &c()),
        Err(AccountError::WeakPassword(_))
    ));
    let user = e.acc.bootstrap_owner(t.token.expose(), "Owner", "O", PW, &c()).unwrap();
    assert!(
        user.server_admin && user.username == "owner" && user.id.starts_with("u_") && user.status == UserStatus::Active
    );
    // The token is dead, and no new one can be made while an owner exists.
    assert!(matches!(
        e.acc.bootstrap_owner(t.token.expose(), "second", "S", PW, &c()),
        Err(AccountError::InvalidSetupToken)
    ));
    assert!(matches!(e.acc.create_setup_token(), Err(AccountError::OwnerExists)));
    assert_eq!(e.acc.list_users().unwrap().len(), 1);
}

#[test]
fn bootstrap_refuses_when_an_owner_exists_even_with_an_older_token() {
    let e = env();
    let t = e.acc.create_setup_token().unwrap();
    // An owner appears (say, a parallel setup) before this token is used: it must not work.
    let other = e.acc.create_setup_token().unwrap();
    e.acc.bootstrap_owner(other.token.expose(), "first", "F", PW, &c()).unwrap();
    assert!(e.acc.bootstrap_owner(t.token.expose(), "second", "S", PW, &c()).is_err());
    assert_eq!(e.acc.list_users().unwrap().len(), 1);
}

#[test]
fn setup_token_expires_and_only_the_newest_works() {
    let e = env();
    let old = e.acc.create_setup_token().unwrap();
    let new = e.acc.create_setup_token().unwrap();
    assert!(e.acc.bootstrap_owner(old.token.expose(), "owner", "O", PW, &c()).is_err(), "replaced");
    e.clock.advance(3601);
    assert!(matches!(
        e.acc.bootstrap_owner(new.token.expose(), "owner", "O", PW, &c()),
        Err(AccountError::InvalidSetupToken)
    ));
    assert!(e.acc.list_users().unwrap().is_empty());
}

#[test]
fn invites_are_the_only_way_in() {
    let e = env();
    let o = bootstrap(&e);
    // No invite: nothing creates an account.
    for bogus in ["", "pminv_00", &format!("pminv_{}", "0".repeat(64)), "pmset_whatever"] {
        assert!(matches!(e.acc.accept_invite(bogus, "mallory", "M", PW, &c()), Err(AccountError::InvalidInvite)));
    }
    assert_eq!(e.acc.list_users().unwrap().len(), 1);

    let inv = e.acc.create_invite(&o.id, Role::Tester, Some("proj1"), Duration::from_secs(3600)).unwrap();
    let alice = e.acc.accept_invite(inv.token.expose(), "Alice", "Alice A", PW, &c()).unwrap();
    assert!(!alice.server_admin && alice.display_name == "Alice A");
    let m = e.acc.memberships_of_user(&alice.id).unwrap();
    assert_eq!((m.len(), m[0].role, m[0].project_id.as_str()), (1, Role::Tester, "proj1"));
    // Single use.
    assert!(matches!(e.acc.accept_invite(inv.token.expose(), "bob", "B", PW, &c()), Err(AccountError::InvalidInvite)));
    let listed = e.acc.list_invites().unwrap();
    assert_eq!((listed[0].used_by.as_deref(), listed[0].created_by.as_str()), (Some(alice.id.as_str()), o.id.as_str()));
}

#[test]
fn invites_expire_can_be_revoked_and_do_not_burn_on_a_taken_name() {
    let e = env();
    let o = bootstrap(&e);
    let a = e.acc.create_invite(&o.id, Role::Viewer, Some("p"), Duration::from_secs(60)).unwrap();
    e.clock.advance(61);
    assert!(matches!(e.acc.accept_invite(a.token.expose(), "x-user", "X", PW, &c()), Err(AccountError::InvalidInvite)));

    let b = e.acc.create_invite(&o.id, Role::Viewer, Some("p"), Duration::from_secs(60)).unwrap();
    e.acc.revoke_invite(&o.id, &b.id).unwrap();
    assert!(matches!(e.acc.accept_invite(b.token.expose(), "x-user", "X", PW, &c()), Err(AccountError::InvalidInvite)));
    assert!(e.acc.revoke_invite(&o.id, &b.id).is_err(), "already revoked");

    let d = e.acc.create_invite(&o.id, Role::Viewer, Some("p"), Duration::from_secs(60)).unwrap();
    assert!(matches!(e.acc.accept_invite(d.token.expose(), "OWNER", "X", PW, &c()), Err(AccountError::UsernameTaken)));
    assert!(e.acc.accept_invite(d.token.expose(), "someone-else", "X", PW, &c()).is_ok(), "the invite was not used up");

    assert!(e.acc.create_invite(&o.id, Role::Viewer, None, Duration::ZERO).is_err());
    assert!(e.acc.create_invite(&o.id, Role::Viewer, None, Duration::from_secs(31 * 86_400)).is_err());
}

#[test]
fn only_admins_and_project_owners_may_invite() {
    let e = env();
    let o = bootstrap(&e);
    let tester = invited(&e, &o.id, "tester1", Role::Tester);
    let boss = invited(&e, &o.id, "boss", Role::Owner);
    let ttl = Duration::from_secs(60);
    assert!(matches!(e.acc.create_invite(&tester.id, Role::Viewer, Some("p"), ttl), Err(AccountError::NotAuthorised)));
    assert!(matches!(e.acc.create_invite("u_nobody", Role::Viewer, Some("p"), ttl), Err(AccountError::NotAuthorised)));
    assert!(e.acc.create_invite(&boss.id, Role::Viewer, Some("p"), ttl).is_ok(), "owner of project p");
    assert!(matches!(
        e.acc.create_invite(&boss.id, Role::Viewer, Some("other"), ttl),
        Err(AccountError::NotAuthorised)
    ));
    assert!(matches!(e.acc.create_invite(&boss.id, Role::Viewer, None, ttl), Err(AccountError::NotAuthorised)));
    // A disabled inviter's open invites die with it.
    let inv = e.acc.create_invite(&boss.id, Role::Viewer, Some("p"), ttl).unwrap();
    e.acc.disable_user(&o.id, &boss.id).unwrap();
    assert!(matches!(e.acc.accept_invite(inv.token.expose(), "late", "L", PW, &c()), Err(AccountError::InvalidInvite)));
}

#[test]
fn reset_owner_recovers_a_locked_out_server() {
    let e = env();
    let s = owner(&e);
    let sess = e.acc.validate_session(&s.session).unwrap();
    assert_eq!(sess.user_id, s.user.id);
    let t = e.acc.reset_owner().unwrap();
    assert!(e.acc.validate_session(&s.session).is_err(), "all sessions ended");
    let n = e.acc.bootstrap_owner(t.token.expose(), "owner2", "O2", PW, &c()).unwrap();
    assert!(n.server_admin);
    assert_eq!(e.acc.list_users().unwrap().len(), 2);
    assert!(matches!(
        e.acc.bootstrap_owner(t.token.expose(), "owner3", "O3", PW, &c()),
        Err(AccountError::InvalidSetupToken)
    ));
    let log = e.acc.security_log(50).unwrap();
    assert!(log.iter().any(|ev| ev.kind == "owner_reset" && ev.actor == "local_console"));
}

// ---- passwords and login ------------------------------------------------------------------------------------

#[test]
fn password_hash_is_upgraded_at_login() {
    let dir = TempDir::new("upgrade");
    let path = dir.file("server.db");
    let clock = Arc::new(ManualClock::new(T0));
    let weak = Config {
        argon2: Argon2Cost { memory_kib: 64, iterations: 1, parallelism: 1 },
        allow_password_only_viewers: true,
        ..Config::default()
    };
    let acc = Accounts::open_with(&path, key(), weak, clock.clone()).unwrap();
    let e = Env { acc, clock: clock.clone() };
    let o = bootstrap(&e);
    let u = invited(&e, &o.id, "viewer1", Role::Viewer);
    let phc_of = |acc: &Accounts| crate::users::password_phc(&acc.conn(), &u.id).unwrap().unwrap();
    assert!(phc_of(&e.acc).contains("m=64,t=1,p=1"));
    drop(e);

    let strong = Config {
        argon2: Argon2Cost { memory_kib: 128, iterations: 2, parallelism: 1 },
        allow_password_only_viewers: true,
        ..Config::default()
    };
    let acc = Accounts::open_with(&path, key(), strong.clone(), clock.clone()).unwrap();
    assert!(matches!(acc.login_password("viewer1", "not the password!", &c()), Err(AccountError::InvalidCredentials)));
    assert!(phc_of(&acc).contains("m=64,t=1,p=1"), "a failed login does not rehash");
    session_of(acc.login_password("viewer1", PW, &c()).unwrap());
    let upgraded = phc_of(&acc);
    assert!(upgraded.starts_with("$argon2id$v=19$m=128,t=2,p=1$"), "{upgraded}");
    // Still verifies, and a login at the same cost does not rehash again.
    session_of(acc.login_password("viewer1", PW, &c()).unwrap());
    assert_eq!(phc_of(&acc), upgraded);
    drop(acc);

    // A stronger stored hash is never downgraded.
    let acc = Accounts::open_with(
        &path,
        key(),
        Config { allow_password_only_viewers: true, argon2: Argon2Cost::insecure_for_tests(), ..Config::default() },
        clock,
    )
    .unwrap();
    session_of(acc.login_password("viewer1", PW, &c()).unwrap());
    assert_eq!(phc_of(&acc), upgraded);
}

#[test]
fn unknown_users_cost_a_dummy_hash_and_look_the_same() {
    let e = viewer_env();
    let o = bootstrap(&e);
    let u = invited(&e, &o.id, "viewer1", Role::Viewer);
    e.acc.disable_user(&o.id, &invited(&e, &o.id, "victim", Role::Viewer).id).unwrap();

    let before = e.acc.dummy_verifications();
    let wrong = e.acc.login_password("viewer1", "wrong password here", &c()).unwrap_err();
    assert_eq!(e.acc.dummy_verifications(), before, "a known user is verified against their own hash");

    let unknown = e.acc.login_password("nobody-here", "wrong password here", &c()).unwrap_err();
    assert_eq!(e.acc.dummy_verifications(), before + 1, "an unknown user goes through the dummy hash");
    let bad_handle = e.acc.login_password("not a valid handle!", PW, &c()).unwrap_err();
    assert_eq!(e.acc.dummy_verifications(), before + 2, "so does a handle that cannot exist");
    let disabled = e.acc.login_password("victim", PW, &c()).unwrap_err();
    for err in [&wrong, &unknown, &bad_handle, &disabled] {
        assert!(matches!(err, AccountError::InvalidCredentials));
        assert_eq!(err.to_string(), "invalid credentials");
    }
    // The right password for a user that exists still works.
    assert!(matches!(e.acc.login_password("viewer1", PW, &c()), Ok(LoginStep::Authenticated(_))));
    assert_eq!(u.username, "viewer1");
}

#[test]
fn the_dummy_hash_never_logs_anyone_in() {
    let e = env();
    bootstrap(&e);
    let dummy = e.acc.dummy_hash.clone();
    assert!(dummy.starts_with("$argon2id$"));
    // Whatever the dummy was hashed from, a guess of any user's name or the usual passwords is not it.
    assert!(!e.acc.verify_password(None, PW));
}

#[test]
fn owners_get_a_session_only_with_a_second_factor() {
    let e = env();
    let s = owner(&e);
    assert_eq!(s.codes.len(), 10);
    let info = e.acc.validate_session(&s.session).unwrap();
    assert_eq!((info.auth_method.as_str(), info.user_id.as_str()), ("password+totp", s.user.id.as_str()));

    // Second sign-in: password alone gives only a pending token.
    e.clock.advance(30);
    let step = e.acc.login_password("owner", PW, &c()).unwrap();
    let LoginStep::SecondFactorRequired { pending, expires_at } = step else { panic!("{step:?}") };
    assert_eq!(expires_at, e.clock.now() + 300);
    assert!(e.acc.validate_session(pending.expose()).is_err(), "a pending token is not a session");
    let ok = e.acc.login_second_factor(pending.expose(), &code_at(&s.secret, e.clock.now()), &c()).unwrap();
    assert_eq!(ok.user.last_login_at, Some(e.clock.now()));
    assert!(e.acc.validate_session(ok.session.id.expose()).is_ok());
    // The token is spent.
    assert!(matches!(
        e.acc.login_second_factor(pending.expose(), &code_at(&s.secret, e.clock.now() + 30), &c()),
        Err(AccountError::InvalidPending)
    ));
}

#[test]
fn second_factor_policy_by_role() {
    let strict = env();
    let o = bootstrap(&strict);
    let v = invited(&strict, &o.id, "viewer1", Role::Viewer);
    assert!(strict.acc.user_requires_second_factor(&v.id).unwrap(), "default: everyone");
    assert!(matches!(strict.acc.login_password("viewer1", PW, &c()), Ok(LoginStep::EnrolmentRequired { .. })));

    let e = viewer_env();
    let o = bootstrap(&e);
    let viewer = invited(&e, &o.id, "viewer1", Role::Viewer);
    let tester = invited(&e, &o.id, "tester1", Role::Tester);
    assert!(!e.acc.user_requires_second_factor(&viewer.id).unwrap());
    assert!(e.acc.user_requires_second_factor(&tester.id).unwrap());
    assert!(e.acc.user_requires_second_factor(&o.id).unwrap(), "server admin");
    assert!(matches!(e.acc.login_password("viewer1", PW, &c()), Ok(LoginStep::Authenticated(_))));
    assert!(matches!(e.acc.login_password("tester1", PW, &c()), Ok(LoginStep::EnrolmentRequired { .. })));
    assert!(matches!(e.acc.login_password("owner", PW, &c()), Ok(LoginStep::EnrolmentRequired { .. })));
    // A viewer promoted to tester now needs one.
    e.acc.set_membership(&o.id, "p2", &viewer.id, Role::Tester).unwrap();
    assert!(matches!(e.acc.login_password("viewer1", PW, &c()), Ok(LoginStep::EnrolmentRequired { .. })));
}

#[test]
fn password_change_ends_other_sessions() {
    let e = viewer_env();
    let o = bootstrap(&e);
    let u = invited(&e, &o.id, "viewer1", Role::Viewer);
    let s1 = session_of(e.acc.login_password("viewer1", PW, &c()).unwrap());
    let s2 = session_of(e.acc.login_password("viewer1", PW, &c()).unwrap());
    assert!(matches!(
        e.acc.change_password(&u.id, "wrong wrong wrong", "another long passphrase", Some(&s1)),
        Err(AccountError::InvalidCredentials)
    ));
    assert!(matches!(e.acc.change_password(&u.id, PW, "short", Some(&s1)), Err(AccountError::WeakPassword(_))));
    e.acc.change_password(&u.id, PW, "another long passphrase", Some(&s1)).unwrap();
    assert!(e.acc.validate_session(&s1).is_ok(), "the session that changed it stays");
    assert!(e.acc.validate_session(&s2).is_err(), "the others end");
    assert!(e.acc.login_password("viewer1", PW, &c()).is_err());
    assert!(e.acc.login_password("viewer1", "another long passphrase", &c()).is_ok());
}

// ---- TOTP and recovery codes --------------------------------------------------------------------------------

#[test]
fn totp_accepts_one_step_either_way_but_not_two() {
    let e = env();
    let s = owner(&e);
    let now = e.clock.now() + 300;
    e.clock.set(now);
    let step = now.div_euclid(30) * 30;
    let id = &s.user.id;
    assert!(!e.acc.totp_verify(id, &code_at(&s.secret, step + 60)).unwrap(), "two steps ahead");
    assert!(!e.acc.totp_verify(id, &code_at(&s.secret, step - 60)).unwrap(), "two steps behind");
    assert!(!e.acc.totp_verify(id, "000000").unwrap() || code_at(&s.secret, step) == "000000");
    assert!(e.acc.totp_verify(id, &code_at(&s.secret, step - 30)).unwrap(), "one behind");
    // Later steps are fine, earlier ones are now replays.
    assert!(e.acc.totp_verify(id, &code_at(&s.secret, step + 30)).unwrap(), "one ahead");
    assert!(!e.acc.totp_verify(id, &code_at(&s.secret, step)).unwrap(), "older than the last accepted step");
    assert!(!e.acc.totp_verify(id, &code_at(&s.secret, step + 30)).unwrap(), "the same step again");
    // Spaces and a dash are tolerated, letters are not.
    e.clock.advance(60);
    let code = code_at(&s.secret, e.clock.now());
    assert!(!e.acc.totp_verify(id, &format!("{}ab", &code[..4])).unwrap());
    assert!(e.acc.totp_verify(id, &format!("{} {}", &code[..3], &code[3..])).unwrap());
}

#[test]
fn totp_replay_is_refused_at_login() {
    let e = env();
    let s = owner(&e);
    e.clock.advance(30);
    sign_in(&e, "owner", &s.secret); // uses the code of this step
    let LoginStep::SecondFactorRequired { pending, .. } = e.acc.login_password("owner", PW, &c()).unwrap() else {
        panic!()
    };
    let same = code_at(&s.secret, e.clock.now());
    assert!(matches!(e.acc.login_second_factor(pending.expose(), &same, &c()), Err(AccountError::InvalidCredentials)));
    // The first factor's code from the enrolment step is also unusable (it was consumed by the confirmation).
    let enrolment_code = code_at(&s.secret, T0);
    assert!(matches!(
        e.acc.login_second_factor(pending.expose(), &enrolment_code, &c()),
        Err(AccountError::InvalidCredentials)
    ));
    // A fresh step works.
    e.clock.advance(30);
    assert!(e.acc.login_second_factor(pending.expose(), &code_at(&s.secret, e.clock.now()), &c()).is_ok());
}

#[test]
fn a_wrong_enrolment_code_does_not_enrol() {
    let e = env();
    let user = bootstrap(&e);
    let LoginStep::EnrolmentRequired { pending, .. } = e.acc.login_password("owner", PW, &c()).unwrap() else {
        panic!()
    };
    assert!(
        matches!(e.acc.finish_enrolment(pending.expose(), "123456", &c()), Err(AccountError::NotEnrolling)),
        "enrolment must be started first"
    );
    let en = e.acc.begin_totp_enrolment_pending(pending.expose()).unwrap();
    assert!(en.otpauth_uri.starts_with("otpauth://totp/ProxyMind:owner?secret="), "{}", en.otpauth_uri);
    assert!(
        en.otpauth_uri.contains(&en.secret_base32) && en.otpauth_uri.contains("period=30&")
            || en.otpauth_uri.ends_with("period=30")
    );
    let secret = raw_secret(&e.acc, &user.id);
    let wrong = code_at(&secret, T0 + 600);
    assert!(matches!(e.acc.finish_enrolment(pending.expose(), &wrong, &c()), Err(AccountError::InvalidCode)));
    assert!(!e.acc.totp_enabled(&e.acc.conn(), &user.id).unwrap());
    assert!(e.acc.finish_enrolment(pending.expose(), &code_at(&secret, T0), &c()).is_ok());
}

#[test]
fn totp_enrolment_for_a_signed_in_user() {
    let e = viewer_env();
    let o = bootstrap(&e);
    let u = invited(&e, &o.id, "viewer1", Role::Viewer);
    assert!(matches!(e.acc.totp_confirm(&u.id, "123456"), Err(AccountError::NotEnrolling)));
    e.acc.totp_begin_enrolment(&u.id).unwrap();
    let first = raw_secret(&e.acc, &u.id);
    e.acc.totp_begin_enrolment(&u.id).unwrap();
    assert_ne!(raw_secret(&e.acc, &u.id), first, "an unconfirmed attempt is replaced");
    let secret = raw_secret(&e.acc, &u.id);
    assert!(matches!(e.acc.totp_confirm(&u.id, &code_at(&secret, T0 + 900)), Err(AccountError::InvalidCode)));
    e.acc.totp_confirm(&u.id, &code_at(&secret, T0)).unwrap();
    assert!(matches!(e.acc.totp_begin_enrolment(&u.id), Err(AccountError::AlreadyEnrolled)));
    // Now password alone is not enough for this viewer.
    assert!(matches!(e.acc.login_password("viewer1", PW, &c()), Ok(LoginStep::SecondFactorRequired { .. })));
    // A viewer may turn it off (the owner allowed password-only viewers); sessions end.
    let s = session_of({
        e.acc.totp_disable(&u.id).unwrap();
        e.acc.login_password("viewer1", PW, &c()).unwrap()
    });
    assert!(e.acc.validate_session(&s).is_ok());
    assert!(matches!(e.acc.totp_disable(&o.id), Err(AccountError::SecondFactorRequired)), "owners cannot");
}

#[test]
fn totp_secret_is_encrypted_and_bound_to_its_user() {
    let e = env();
    let a = owner(&e);
    let b_user = invited(&e, &a.user.id, "second", Role::Tester);
    let b = enrol(&e, "second", PW, b_user);
    let sealed_of = |id: &str| -> Vec<u8> {
        e.acc
            .conn()
            .query_row("SELECT secret FROM credentials WHERE user_id = ?1 AND kind = 'totp'", [id], |r| r.get(0))
            .unwrap()
    };
    let sealed_a = sealed_of(&a.user.id);
    assert_eq!(sealed_a.len(), 12 + 20 + 16, "nonce, secret, tag");
    assert!(!sealed_a.windows(20).any(|w| w == a.secret.as_slice()), "not plaintext");
    // Moving A's encrypted secret into B's record: decrypting as B fails.
    e.acc
        .conn()
        .execute(
            "UPDATE credentials SET secret = ?1 WHERE user_id = ?2 AND kind = 'totp'",
            rusqlite::params![sealed_a, b.user.id],
        )
        .unwrap();
    e.clock.advance(60);
    assert!(matches!(e.acc.totp_verify(&b.user.id, &code_at(&a.secret, e.clock.now())), Err(AccountError::Decrypt)));
    assert!(matches!(e.acc.totp_verify(&b.user.id, &code_at(&b.secret, e.clock.now())), Err(AccountError::Decrypt)));
    // A's own record still works, and a different server key cannot read it.
    assert!(e.acc.totp_verify(&a.user.id, &code_at(&a.secret, e.clock.now())).unwrap());
    let other = Accounts::open_in_memory(ServerKey::from_bytes([9; 32]), Config::insecure_for_tests(), e.clock.clone())
        .unwrap();
    assert!(matches!(
        other.open_secret(&sealed_of(&a.user.id), &crate::login::totp_aad(&a.user.id)),
        Err(AccountError::Decrypt)
    ));
}

#[test]
fn recovery_codes_are_single_use_and_regeneration_invalidates_old_ones() {
    let e = env();
    let s = owner(&e);
    assert_eq!(e.acc.remaining_recovery_codes(&s.user.id).unwrap(), 10);
    for code in &s.codes {
        assert_eq!(code.len(), 19);
        assert!(
            code.split('-').count() == 4
                && code.bytes().all(|b| b == b'-' || b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
        );
    }
    let unique: std::collections::HashSet<_> = s.codes.iter().collect();
    assert_eq!(unique.len(), 10);

    let login_with = |code: &str| {
        let LoginStep::SecondFactorRequired { pending, .. } = e.acc.login_password("owner", PW, &c()).unwrap() else {
            panic!()
        };
        e.acc.login_second_factor(pending.expose(), code, &c())
    };
    let ok = login_with(&s.codes[0].to_lowercase().replace('-', " ")).unwrap();
    assert_eq!(e.acc.validate_session(ok.session.id.expose()).unwrap().auth_method, "password+recovery");
    assert_eq!(e.acc.remaining_recovery_codes(&s.user.id).unwrap(), 9);
    assert!(matches!(login_with(&s.codes[0]), Err(AccountError::InvalidCredentials)), "a used code is dead");
    assert!(login_with(&s.codes[1]).is_ok(), "the others are untouched");

    let fresh = e.acc.generate_recovery_codes(&s.user.id).unwrap();
    assert_eq!(e.acc.remaining_recovery_codes(&s.user.id).unwrap(), 10);
    e.clock.advance(3600); // past any back-off from the failure above
    assert!(matches!(login_with(&s.codes[2]), Err(AccountError::InvalidCredentials)), "old unused codes are dead");
    assert!(login_with(&fresh[0]).is_ok());
    // Only the HMAC is stored: nothing in the table equals the code or its bare form.
    let hashes: Vec<Vec<u8>> = {
        let conn = e.acc.conn();
        let mut st = conn.prepare("SELECT code_hash FROM recovery_codes").unwrap();
        st.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    assert!(hashes.iter().all(|h| h.len() == 32 && h != fresh[1].replace('-', "").as_bytes()));
}

#[test]
fn recovery_codes_need_totp() {
    let e = viewer_env();
    let o = bootstrap(&e);
    let v = invited(&e, &o.id, "viewer1", Role::Viewer);
    assert!(matches!(e.acc.generate_recovery_codes(&v.id), Err(AccountError::NotEnrolling)));
}

#[test]
fn admin_can_reset_a_lost_second_factor() {
    let e = env();
    let s = owner(&e);
    let t = invited(&e, &s.user.id, "tester1", Role::Tester);
    let ts = enrol(&e, "tester1", PW, t.clone());
    assert!(e.acc.validate_session(&ts.session).is_ok());
    assert!(matches!(e.acc.reset_second_factor(&t.id, &s.user.id), Err(AccountError::NotAuthorised)));
    e.acc.reset_second_factor(&s.user.id, &t.id).unwrap();
    assert!(e.acc.validate_session(&ts.session).is_err());
    assert_eq!(e.acc.remaining_recovery_codes(&t.id).unwrap(), 0);
    assert!(matches!(e.acc.login_password("tester1", PW, &c()), Ok(LoginStep::EnrolmentRequired { .. })));
}

// ---- pending sign-ins ---------------------------------------------------------------------------------------

#[test]
fn pending_sign_in_expires_and_limits_attempts() {
    let e = env();
    let s = owner(&e);
    e.clock.advance(30);
    let pend = || match e.acc.login_password("owner", PW, &c()).unwrap() {
        LoginStep::SecondFactorRequired { pending, .. } => pending,
        other => panic!("{other:?}"),
    };
    let p = pend();
    e.clock.advance(301);
    assert!(matches!(
        e.acc.login_second_factor(p.expose(), &code_at(&s.secret, e.clock.now()), &c()),
        Err(AccountError::InvalidPending)
    ));
    // Five wrong codes kill the token even for the right code afterwards.
    let p = pend();
    for _ in 0..5 {
        assert!(matches!(e.acc.login_second_factor(p.expose(), "000000", &c()), Err(AccountError::InvalidCredentials)));
    }
    assert!(matches!(
        e.acc.login_second_factor(p.expose(), &code_at(&s.secret, e.clock.now()), &c()),
        Err(AccountError::InvalidPending)
    ));
    // Garbage and wrong-kind tokens are the same error.
    e.clock.advance(60); // past the back-off the failures caused
    assert!(matches!(e.acc.login_second_factor("garbage", "000000", &c()), Err(AccountError::InvalidPending)));
    assert!(matches!(e.acc.begin_totp_enrolment_pending(pend().expose()), Err(AccountError::InvalidPending)));
}

// ---- throttling ---------------------------------------------------------------------------------------------

#[test]
fn throttle_backs_off_exponentially_to_a_cap_and_never_locks_for_good() {
    let throttle = ThrottleConfig { address_free_failures: 10_000, ..ThrottleConfig::default() };
    let e = env_with(Config { allow_password_only_viewers: true, throttle, ..Config::insecure_for_tests() });
    let o = bootstrap(&e);
    invited(&e, &o.id, "viewer1", Role::Viewer);
    let fail = || e.acc.login_password("viewer1", "wrong wrong wrong", &c()).unwrap_err();
    for _ in 0..5 {
        assert!(matches!(fail(), AccountError::InvalidCredentials));
    }
    let mut seen = Vec::new();
    for _ in 0..14 {
        let AccountError::Throttled { retry_after } = fail() else { panic!("expected throttle") };
        seen.push(retry_after.as_secs());
        // While delayed, even the right password is refused and nothing is extended.
        assert!(matches!(e.acc.login_password("viewer1", PW, &c()), Err(AccountError::Throttled { .. })));
        assert_eq!(e.acc.login_retry_after("viewer1", &c()).unwrap(), Some(retry_after));
        e.clock.advance(retry_after.as_secs() as i64);
        assert!(e.acc.login_retry_after("VIEWER1 ", &c()).unwrap().is_none(), "handle case and spaces do not matter");
        assert!(matches!(fail_once(&e), AccountError::InvalidCredentials));
    }
    assert_eq!(&seen[..5], &[2, 4, 8, 16, 32], "doubles");
    assert!(seen.iter().all(|s| *s <= 900));
    assert_eq!(*seen.last().unwrap(), 900, "capped");
    // Waiting out the delay is enough: the right password works, and success resets the counter.
    let AccountError::Throttled { retry_after } = fail() else { panic!() };
    e.clock.advance(retry_after.as_secs() as i64);
    assert!(matches!(e.acc.login_password("viewer1", PW, &c()), Ok(LoginStep::Authenticated(_))));
    for _ in 0..5 {
        assert!(matches!(fail(), AccountError::InvalidCredentials), "the count started again from zero");
    }
}

fn fail_once(e: &Env) -> AccountError {
    e.acc.login_password("viewer1", "wrong wrong wrong", &c()).unwrap_err()
}

#[test]
fn counters_fade_after_a_quiet_hour() {
    let e = env();
    bootstrap(&e);
    for _ in 0..5 {
        let _ = e.acc.login_password("owner", "wrong wrong wrong", &c());
    }
    assert!(matches!(e.acc.login_password("owner", "wrong wrong wrong", &c()), Err(AccountError::Throttled { .. })));
    e.clock.advance(3601);
    assert!(matches!(e.acc.login_password("owner", "wrong wrong wrong", &c()), Err(AccountError::InvalidCredentials)));
}

#[test]
fn unknown_handles_are_throttled_like_real_ones() {
    let e = env();
    bootstrap(&e);
    let real: Vec<bool> = (0..7)
        .map(|_| {
            matches!(e.acc.login_password("owner", "wrong wrong wrong", &c()), Err(AccountError::Throttled { .. }))
        })
        .collect();
    let ghost: Vec<bool> = (0..7)
        .map(|_| {
            matches!(e.acc.login_password("ghost", "wrong wrong wrong", &c()), Err(AccountError::Throttled { .. }))
        })
        .collect();
    assert_eq!(real, ghost);
    assert_eq!(real, [false, false, false, false, false, true, true]);
    // The throttle table holds no handles, only HMACs.
    let keys: Vec<String> = {
        let conn = e.acc.conn();
        let mut st = conn.prepare("SELECT key FROM login_throttle WHERE scope = 'account'").unwrap();
        st.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(keys.len(), 2);
    assert!(keys.iter().all(|k| k.len() == 64 && k != "owner" && k != "ghost"));
}

#[test]
fn address_throttle_is_separate_and_not_reset_by_a_success() {
    let e = viewer_env();
    let o = bootstrap(&e);
    invited(&e, &o.id, "viewer1", Role::Viewer);
    let attacker = ClientInfo::new("198.51.100.7");
    // 20 failures, each against a different handle, so no account is throttled.
    for i in 0..20 {
        assert!(matches!(
            e.acc.login_password(&format!("guess{i:02}"), "wrong wrong wrong", &attacker),
            Err(AccountError::InvalidCredentials)
        ));
    }
    assert!(matches!(
        e.acc.login_password("guess99", "wrong wrong wrong", &attacker),
        Err(AccountError::Throttled { .. })
    ));
    // The attacker's own valid account does not help while the delay runs; other addresses are unaffected.
    assert!(matches!(e.acc.login_password("viewer1", PW, &attacker), Err(AccountError::Throttled { .. })));
    assert!(matches!(
        e.acc.login_password("viewer1", PW, &ClientInfo::new("192.0.2.1")),
        Ok(LoginStep::Authenticated(_))
    ));
    // Bad setup tokens and invites count against the address too.
    let bad = ClientInfo::new("198.51.100.8");
    for _ in 0..20 {
        let _ = e.acc.accept_invite("pminv_bad", "someone", "S", PW, &bad);
    }
    assert!(matches!(e.acc.accept_invite("pminv_bad", "someone", "S", PW, &bad), Err(AccountError::Throttled { .. })));
}

// ---- sessions -----------------------------------------------------------------------------------------------

fn viewer_session(e: &Env) -> (User, String) {
    let o = e.acc.list_users().unwrap().into_iter().find(|u| u.server_admin).unwrap_or_else(|| bootstrap(e));
    let u = invited(e, &o.id, &format!("viewer{}", e.acc.list_users().unwrap().len()), Role::Viewer);
    let s = session_of(e.acc.login_password(&u.username, PW, &c()).unwrap());
    (u, s)
}

#[test]
fn session_ids_are_random_and_returned_once() {
    let e = viewer_env();
    let (u, s) = viewer_session(&e);
    assert_eq!(s.len(), 64);
    let second = session_of(e.acc.login_password(&u.username, PW, &c()).unwrap());
    assert_ne!(s, second);
    let info = e.acc.validate_session(&s).unwrap();
    assert_eq!(info.user_id, u.id);
    assert_eq!(info.idle_expires_at, T0 + 8 * 3600);
    assert_eq!(info.absolute_expires_at, T0 + 7 * 86_400);
    assert_eq!(info.client_addr.as_deref(), Some("203.0.113.9"));
    let list = e.acc.list_sessions(&u.id).unwrap();
    assert_eq!(list.len(), 2);
    assert!(list.iter().all(|i| i.reference.len() == 16 && !s.contains(&i.reference) || i.reference != s[..16]));
    // Malformed ids are refused without touching the database.
    for bad in ["", "abc", &"z".repeat(64), &"0".repeat(64), &format!("{s}0")] {
        assert!(matches!(e.acc.validate_session(bad), Err(AccountError::SessionInvalid)));
    }
}

#[test]
fn sessions_end_when_idle() {
    let e = viewer_env();
    let (_, s) = viewer_session(&e);
    e.clock.advance(8 * 3600 - 1);
    assert!(e.acc.validate_session(&s).is_ok());
    e.clock.advance(1);
    assert!(matches!(e.acc.validate_session(&s), Err(AccountError::SessionInvalid)), "idle expiry is exclusive");
    assert!(e.acc.touch_session(&s).is_err(), "an expired session cannot be revived by a touch");
}

#[test]
fn touching_extends_idle_but_never_past_the_absolute_limit() {
    let e = viewer_env();
    let (_, s) = viewer_session(&e);
    // Active every 7 hours keeps it alive for almost the whole absolute lifetime...
    for _ in 0..23 {
        e.clock.advance(7 * 3600);
        e.acc.touch_session(&s).unwrap();
    }
    assert!(e.acc.validate_session(&s).is_ok());
    // ...but at 7 days it ends whatever the activity.
    e.clock.set(T0 + 167 * 3600);
    let t = e.acc.touch_session(&s).unwrap();
    assert_eq!(t.idle_expires_at, T0 + 7 * 86_400, "idle expiry is clamped to the absolute one");
    e.clock.set(T0 + 7 * 86_400);
    assert!(matches!(e.acc.validate_session(&s), Err(AccountError::SessionInvalid)));
}

#[test]
fn limits_are_configurable_but_bounded() {
    let e = env_with(Config {
        idle_timeout: Duration::from_secs(60),
        absolute_timeout: Duration::from_secs(600),
        allow_password_only_viewers: true,
        ..Config::insecure_for_tests()
    });
    let (_, s) = viewer_session(&e);
    e.clock.advance(59);
    e.acc.touch_session(&s).unwrap();
    e.clock.advance(61);
    assert!(e.acc.validate_session(&s).is_err());
    let clock = Arc::new(ManualClock::new(T0));
    for bad in [
        Config { idle_timeout: Duration::from_secs(31 * 86_400), ..Config::default() },
        Config { absolute_timeout: Duration::from_secs(91 * 86_400), ..Config::default() },
        Config { idle_timeout: Duration::ZERO, ..Config::default() },
    ] {
        assert!(Accounts::open_in_memory(key(), bad, clock.clone()).is_err());
    }
}

#[test]
fn rotation_invalidates_the_old_id() {
    let e = viewer_env();
    let (u, old) = viewer_session(&e);
    e.clock.advance(3600);
    let new = e.acc.rotate_session(&old, &ClientInfo::new("203.0.113.77")).unwrap();
    assert_ne!(new.id.expose(), old);
    assert!(matches!(e.acc.validate_session(&old), Err(AccountError::SessionInvalid)), "the old id dies at once");
    assert!(
        matches!(e.acc.rotate_session(&old, &c()), Err(AccountError::SessionInvalid)),
        "and cannot be rotated again"
    );
    let info = e.acc.validate_session(new.id.expose()).unwrap();
    assert_eq!(info.user_id, u.id);
    assert_eq!(info.absolute_expires_at, T0 + 7 * 86_400, "rotation does not extend the absolute limit");
    assert_eq!(info.authenticated_at, T0, "nor claims a fresh sign-in");
    assert_eq!(info.created_at, T0 + 3600);
    assert_eq!(info.client_addr.as_deref(), Some("203.0.113.77"));
    let chained: i64 = e
        .acc
        .conn()
        .query_row("SELECT COUNT(*) FROM sessions WHERE rotated_from IS NOT NULL AND revoked_at IS NULL", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(chained, 1);
    assert_eq!(e.acc.list_sessions(&u.id).unwrap().len(), 1);
}

#[test]
fn revoking_one_or_all_sessions() {
    let e = viewer_env();
    let (u, a) = viewer_session(&e);
    let b = session_of(e.acc.login_password(&u.username, PW, &c()).unwrap());
    let d = session_of(e.acc.login_password(&u.username, PW, &c()).unwrap());
    e.acc.revoke_session(&a).unwrap();
    assert!(e.acc.validate_session(&a).is_err() && e.acc.validate_session(&b).is_ok());
    e.acc.revoke_session(&a).unwrap();
    e.acc.revoke_session("not an id").unwrap();
    // By reference, as the session list does it; only for the owner of the session.
    let r = e.acc.validate_session(&b).unwrap().reference;
    assert!(!e.acc.revoke_session_ref("u_someone_else", &r).unwrap());
    assert!(e.acc.revoke_session_ref(&u.id, &r).unwrap());
    assert!(e.acc.validate_session(&b).is_err());
    let extra = session_of(e.acc.login_password(&u.username, PW, &c()).unwrap());
    assert_eq!(e.acc.revoke_all_sessions(&u.id, Some(&extra)).unwrap(), 1, "d only; extra is kept");
    assert!(e.acc.validate_session(&d).is_err() && e.acc.validate_session(&extra).is_ok());
    assert_eq!(e.acc.revoke_all_sessions(&u.id, None).unwrap(), 1);
    assert!(e.acc.validate_session(&extra).is_err());
    assert!(e.acc.list_sessions(&u.id).unwrap().is_empty());
}

#[test]
fn disabling_a_user_ends_their_sessions_and_sign_in() {
    let e = viewer_env();
    let (u, s) = viewer_session(&e);
    let admin = e.acc.list_users().unwrap().into_iter().find(|x| x.server_admin).unwrap();
    assert!(matches!(e.acc.disable_user(&u.id, &admin.id), Err(AccountError::NotAuthorised)));
    e.acc.disable_user(&admin.id, &u.id).unwrap();
    assert!(e.acc.validate_session(&s).is_err());
    assert!(matches!(e.acc.login_password(&u.username, PW, &c()), Err(AccountError::InvalidCredentials)));
    assert!(e.acc.create_session(&u.id, "test", &c()).is_err());
    assert_eq!(e.acc.get_user(&u.id).unwrap().unwrap().status, UserStatus::Disabled);
    e.acc.enable_user(&admin.id, &u.id).unwrap();
    assert!(e.acc.login_password(&u.username, PW, &c()).is_ok());
    // The last active administrator cannot be disabled, not even by themselves.
    assert!(matches!(e.acc.disable_user(&admin.id, &admin.id), Err(AccountError::LastAdmin)));
}

#[test]
fn memberships_demotion_ends_sessions() {
    let e = viewer_env();
    let o = bootstrap(&e);
    let t = invited(&e, &o.id, "tester1", Role::Tester);
    let s = e.acc.create_session(&t.id, "test", &c()).unwrap();
    let id = s.id.expose();
    // Promotion keeps sessions; demotion ends them.
    e.acc.set_membership(&o.id, "p", &t.id, Role::Owner).unwrap();
    assert!(e.acc.validate_session(id).is_ok());
    assert!(
        matches!(e.acc.set_membership(&t.id, "other", &t.id, Role::Owner), Err(AccountError::NotAuthorised)),
        "owning p says nothing about another project"
    );
    // The last owner of a project is never demoted or removed (ADR-0022 step 6); with a second owner it is allowed.
    assert!(matches!(e.acc.set_membership(&o.id, "p", &t.id, Role::Viewer), Err(AccountError::LastOwner)));
    assert!(matches!(e.acc.remove_membership(&o.id, "p", &t.id), Err(AccountError::LastOwner)));
    assert!(e.acc.validate_session(id).is_ok(), "a refused demotion ends nothing");
    e.acc.set_membership(&o.id, "p", &o.id, Role::Owner).unwrap();
    e.acc.set_membership(&o.id, "p", &t.id, Role::Viewer).unwrap();
    assert!(e.acc.validate_session(id).is_err());
    assert_eq!(e.acc.memberships_of_user(&t.id).unwrap()[0].role, Role::Viewer);
    assert_eq!(e.acc.members_of_project("p").unwrap().len(), 2);
    let s = e.acc.create_session(&t.id, "test", &c()).unwrap();
    assert!(matches!(e.acc.remove_membership(&t.id, "p", &t.id), Err(AccountError::NotAuthorised)));
    e.acc.remove_membership(&o.id, "p", &t.id).unwrap();
    assert!(e.acc.validate_session(s.id.expose()).is_err());
    assert!(e.acc.memberships_of_user(&t.id).unwrap().is_empty());
}

// ---- security log -------------------------------------------------------------------------------------------

#[test]
fn security_log_is_chained_and_holds_no_secrets() {
    let e = env();
    let s = owner(&e);
    let bad_pw = "my-secret-wrong-password-1";
    let _ = e.acc.login_password("owner", bad_pw, &c());
    let typed_in_handle_field = "my secret wrong password";
    let _ = e.acc.login_password(typed_in_handle_field, PW, &c());
    e.clock.advance(60);
    sign_in(&e, "owner", &s.secret);
    let log = e.acc.security_log(100).unwrap();
    for kind in [
        "owner_created",
        "totp_enabled",
        "recovery_codes_generated",
        "login_failure",
        "login_success",
        "setup_token_created",
    ] {
        assert!(log.iter().any(|ev| ev.kind == kind), "{kind} missing");
    }
    let failure = log.iter().find(|ev| ev.kind == "login_failure").unwrap();
    assert_eq!(failure.client_addr.as_deref(), Some("203.0.113.9"));
    let dump = format!("{log:?}");
    for secret in [bad_pw, typed_in_handle_field, PW, &s.codes[0], &hex(&s.secret), &s.session] {
        assert!(!dump.contains(secret), "the log contains a secret");
    }
    assert_eq!(e.acc.verify_security_log().unwrap(), Ok(log.len()));
    // Changing a record, or removing one from the middle, is detected.
    e.acc.conn().execute("UPDATE security_audit SET actor = 'user:someone-else' WHERE seq = 3", []).unwrap();
    assert_eq!(e.acc.verify_security_log().unwrap(), Err(3));
    e.acc
        .conn()
        .execute("UPDATE security_audit SET actor = (SELECT actor FROM security_audit WHERE seq = 2) WHERE seq = 3", [])
        .unwrap();
    let _ = e.acc.verify_security_log().unwrap();
}

#[test]
fn security_log_detects_a_deleted_middle_record() {
    let e = env();
    owner(&e);
    assert!(e.acc.verify_security_log().unwrap().is_ok());
    e.acc.conn().execute("DELETE FROM security_audit WHERE seq = 2", []).unwrap();
    assert!(e.acc.verify_security_log().unwrap().is_err());
}

#[test]
fn the_audit_key_comes_from_the_server_key() {
    let e = env();
    let k = e.acc.server_key().derive(KeyPurpose::AuditChain);
    assert_ne!(k, e.acc.server_key().derive(KeyPurpose::SessionId));
    assert_eq!(k.len(), 32);
}

#[test]
fn credential_table_has_room_for_passkeys() {
    // Step 7 adds a credential kind without a migration: the generic columns are enough.
    let e = env();
    let o = bootstrap(&e);
    let conn = e.acc.conn();
    for (id, ext) in [("c1", b"cred-a".to_vec()), ("c2", b"cred-b".to_vec())] {
        conn.execute(
            "INSERT INTO credentials (id, user_id, kind, label, external_id, secret, counter, meta, created_at) \
             VALUES (?1, ?2, 'passkey', 'laptop', ?3, x'A5', 4, '{\"transports\":[\"usb\"]}', 0)",
            rusqlite::params![id, o.id, ext],
        )
        .unwrap();
    }
    let dup = conn.execute(
        "INSERT INTO credentials (id, user_id, kind, external_id, created_at) VALUES ('c3', ?1, 'passkey', ?2, 0)",
        rusqlite::params![o.id, b"cred-a".to_vec()],
    );
    assert!(dup.is_err(), "a credential id is unique per kind");
}

// ---- tokens (ADR-0022 step 5) -----------------------------------------------------------------------------

mod tokens {
    use super::*;
    use crate::token::{self, DEFAULT_TTL, TokenKind};

    fn spec(kind: TokenKind, name: &str) -> NewTokenSpec {
        NewTokenSpec::new(kind, name)
    }

    /// An admin who owns project `p`, plus a tester and a viewer member.
    fn team(e: &Env) -> (User, User, User) {
        let admin = bootstrap(e);
        e.acc.set_membership(&admin.id, "p", &admin.id, Role::Owner).unwrap();
        let tester = invited(e, &admin.id, "tester1", Role::Tester);
        let viewer = invited(e, &admin.id, "viewer1", Role::Viewer);
        (admin, tester, viewer)
    }

    fn auth(e: &Env, token: &str) -> Result<TokenAuth> {
        e.acc.authenticate_token(token, "p", &c())
    }

    fn log_kinds(e: &Env) -> Vec<String> {
        e.acc.security_log(200).unwrap().into_iter().map(|x| x.kind).collect()
    }

    #[test]
    fn format_and_rules() {
        for kind in [TokenKind::Agent, TokenKind::Ci, TokenKind::Plugin] {
            let t = token::generate(kind).unwrap();
            let t = t.expose();
            assert!(t.starts_with(&format!("pm3_{}_", kind.as_str())), "{t}");
            assert_eq!(t.len(), 4 + kind.as_str().len() + 1 + 64);
            assert_eq!(token::shape(t), Some(kind));
        }
        assert_ne!(token::generate(TokenKind::Agent).unwrap(), token::generate(TokenKind::Agent).unwrap());
        let good = format!("pm3_agent_{}", "ab".repeat(32));
        assert_eq!(token::shape(&good), Some(TokenKind::Agent));
        for bad in [
            "",
            "pm3_",
            "pm2_agent_00",
            &format!("pm3_human_{}", "ab".repeat(32)),
            &format!("pm3_agent_{}", "AB".repeat(32)),
            &format!("pm3_agent_{}", "ab".repeat(31)),
            &format!("pm3_agent_{}x", "ab".repeat(32)),
            &format!(" pm3_agent_{}", "ab".repeat(32)),
            &format!("pm3_agent_{}\n", "ab".repeat(32)),
        ] {
            assert_eq!(token::shape(bad), None, "{bad:?}");
        }
        // Names follow the actor syntax.
        for ok in ["claude", "ci-1", "a.b_c@d", &"x".repeat(64)] {
            assert!(token::validate_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", "   ", "has space", "a:b", "x/y", &"x".repeat(65), "\u{e9}"] {
            assert!(token::validate_name(bad).is_err(), "{bad:?}");
        }
        // Roles: never owner. Tier caps: names of the gate, destructive caps nothing.
        assert!(token::validate_role(Role::Owner).is_err());
        assert_eq!(token::validate_role(Role::Viewer).unwrap(), Role::Viewer);
        assert_eq!(token::validate_tier_cap(Some("passive")).unwrap().as_deref(), Some("passive"));
        assert_eq!(token::validate_tier_cap(Some("destructive")).unwrap(), None);
        assert_eq!(token::validate_tier_cap(None).unwrap(), None);
        assert!(token::validate_tier_cap(Some("everything")).is_err());
        assert!(token::validate_tier_cap(Some("Passive")).is_err());
        // Lifetimes: default 30 d, one minute to one year.
        assert_eq!(token::validate_ttl(None).unwrap(), DEFAULT_TTL);
        assert!(token::validate_ttl(Some(Duration::from_secs(59))).is_err());
        assert!(token::validate_ttl(Some(Duration::from_secs(365 * 86_400 + 1))).is_err());
        assert!(token::validate_ttl(Some(Duration::from_secs(365 * 86_400))).is_ok());
        assert_eq!(parse_ttl("30d").unwrap(), Duration::from_secs(30 * 86_400));
        assert_eq!(parse_ttl("12h").unwrap(), Duration::from_secs(12 * 3600));
        assert_eq!(parse_ttl("90m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_ttl("7").unwrap(), Duration::from_secs(7 * 86_400));
        for bad in ["", "d", "-1d", "1w", "1.5d", "99999999999999999999d"] {
            assert!(parse_ttl(bad).is_err(), "{bad}");
        }
        // The effective role is the lower; a viewer's cap is at most passive.
        assert_eq!(effective_role(Role::Tester, Role::Viewer), Role::Viewer);
        assert_eq!(effective_role(Role::Viewer, Role::Owner), Role::Viewer);
        assert_eq!(effective_role(Role::Tester, Role::Owner), Role::Tester);
        assert_eq!(effective_tier_cap(Role::Tester, None), None);
        assert_eq!(effective_tier_cap(Role::Tester, Some("active_safe")).as_deref(), Some("active_safe"));
        assert_eq!(effective_tier_cap(Role::Viewer, None).as_deref(), Some("passive"));
        assert_eq!(effective_tier_cap(Role::Viewer, Some("read")).as_deref(), Some("read"));
        assert_eq!(effective_tier_cap(Role::Viewer, Some("active_safe")).as_deref(), Some("passive"));
        // The list of tier names is the gate's, lowest first.
        assert_eq!(TIER_NAMES, ["read", "passive", "active_safe", "active_intrusive", "destructive"]);
    }

    #[test]
    fn a_token_authenticates_its_owner_with_a_ceiling_and_a_cap() {
        let e = env();
        let (_, tester, _) = team(&e);
        let mut s = spec(TokenKind::Agent, "claude");
        s.tier_cap = Some("active_safe".into());
        let made = e.acc.create_token(&tester.id, &tester.id, "p", &s).unwrap();
        assert_eq!(made.info.actor_id(), "agent:claude");
        assert_eq!(made.info.expires_at, T0 + 30 * 86_400, "30 days by default");
        let a = auth(&e, made.token.expose()).unwrap();
        assert_eq!(a.info.id, made.info.id);
        assert_eq!(a.info.user_id.as_deref(), Some(tester.id.as_str()));
        assert_eq!((a.role, a.tier_cap.as_deref()), (Role::Tester, Some("active_safe")));
        // Wrong token, wrong shape, wrong project: all one error.
        let other = token::generate(TokenKind::Agent).unwrap();
        for t in [other.expose(), "pm3_agent_x", "", made.token.expose().to_uppercase().as_str()] {
            assert!(matches!(auth(&e, t), Err(AccountError::InvalidToken)), "{t}");
        }
        assert!(matches!(
            e.acc.authenticate_token(made.token.expose(), "elsewhere", &c()),
            Err(AccountError::InvalidToken)
        ));
        // A viewer ceiling, however the owner is ranked, and a tester token of a viewer member are both viewers, which
        // sends nothing: held to `passive`.
        let mut v = spec(TokenKind::Ci, "reader");
        v.role = Role::Viewer;
        let read = e.acc.create_token(&tester.id, &tester.id, "p", &v).unwrap();
        let a = auth(&e, read.token.expose()).unwrap();
        assert_eq!((a.role, a.tier_cap.as_deref()), (Role::Viewer, Some("passive")));
    }

    #[test]
    fn tokens_are_never_owner_and_never_made_by_the_wrong_person() {
        let e = env();
        let (admin, tester, viewer) = team(&e);
        let mut s = spec(TokenKind::Agent, "x");
        s.role = Role::Owner;
        assert!(matches!(e.acc.create_token(&admin.id, &admin.id, "p", &s), Err(AccountError::InvalidArgument(_))));
        let ok = spec(TokenKind::Agent, "mine");
        // A member may not make one for somebody else; the project's owner may.
        assert!(matches!(e.acc.create_token(&tester.id, &viewer.id, "p", &ok), Err(AccountError::NotAuthorised)));
        let t = e.acc.create_token(&admin.id, &viewer.id, "p", &ok).unwrap();
        assert_eq!(t.info.created_by, admin.id);
        assert_eq!(t.info.user_id.as_deref(), Some(viewer.id.as_str()));
        // Not for a user who is not a member, nor of a project the maker does not own.
        let stranger = invited(&e, &admin.id, "stranger", Role::Tester);
        e.acc.remove_membership(&admin.id, "p", &stranger.id).unwrap();
        assert!(matches!(
            e.acc.create_token(&stranger.id, &stranger.id, "p", &spec(TokenKind::Agent, "s")),
            Err(AccountError::NoSuchUser)
        ));
        assert!(matches!(
            e.acc.create_token(&tester.id, &tester.id, "q", &spec(TokenKind::Agent, "q")),
            Err(AccountError::NoSuchUser)
        ));
        // Names: one live token per actor id, in any case; free again once revoked.
        e.acc.create_token(&tester.id, &tester.id, "p", &spec(TokenKind::Agent, "Claude")).unwrap();
        assert!(matches!(
            e.acc.create_token(&admin.id, &admin.id, "p", &spec(TokenKind::Agent, "claude")),
            Err(AccountError::TokenNameTaken)
        ));
        e.acc.create_token(&admin.id, &admin.id, "p", &spec(TokenKind::Ci, "claude")).unwrap();
        let id = e.acc.list_tokens("p", Some(&tester.id)).unwrap()[0].id.clone();
        e.acc.revoke_token(&tester.id, &id).unwrap();
        e.acc.create_token(&admin.id, &admin.id, "p", &spec(TokenKind::Agent, "claude")).unwrap();
        // A disabled maker can do nothing.
        e.acc.disable_user(&admin.id, &tester.id).unwrap();
        assert!(matches!(
            e.acc.create_token(&tester.id, &tester.id, "p", &spec(TokenKind::Agent, "again")),
            Err(AccountError::NotAuthorised)
        ));
    }

    #[test]
    fn expiry_and_revocation_take_effect_on_the_next_call() {
        let e = env();
        let (admin, tester, viewer) = team(&e);
        let mut short = spec(TokenKind::Ci, "job");
        short.ttl = Some(Duration::from_secs(3600));
        let t = e.acc.create_token(&tester.id, &tester.id, "p", &short).unwrap();
        assert!(auth(&e, t.token.expose()).is_ok());
        e.clock.advance(3599);
        assert!(auth(&e, t.token.expose()).is_ok());
        e.clock.advance(1);
        assert!(matches!(auth(&e, t.token.expose()), Err(AccountError::InvalidToken)), "expired at its expiry");
        // Revocation: by the owner, or by an owner of the project; not by another member.
        let t2 = e.acc.create_token(&tester.id, &tester.id, "p", &spec(TokenKind::Agent, "a")).unwrap();
        assert!(auth(&e, t2.token.expose()).is_ok());
        assert!(matches!(e.acc.revoke_token(&viewer.id, &t2.info.id), Err(AccountError::NoSuchToken)));
        assert!(auth(&e, t2.token.expose()).is_ok(), "a refused revoke changes nothing");
        e.acc.revoke_token(&admin.id, &t2.info.id).unwrap();
        assert!(matches!(auth(&e, t2.token.expose()), Err(AccountError::InvalidToken)));
        assert!(matches!(e.acc.revoke_token(&admin.id, &t2.info.id), Err(AccountError::NoSuchToken)), "once");
        assert!(matches!(e.acc.revoke_token(&admin.id, "t_nope"), Err(AccountError::NoSuchToken)));
        let listed = e.acc.list_tokens("p", None).unwrap();
        assert!(listed.iter().any(|x| x.id == t2.info.id && x.revoked_at.is_some()));
        assert_eq!(e.acc.list_tokens("p", Some(&viewer.id)).unwrap().len(), 0);
    }

    #[test]
    fn the_owners_state_decides_what_a_token_can_do() {
        let e = env();
        let (admin, tester, _) = team(&e);
        let t = e.acc.create_token(&tester.id, &tester.id, "p", &spec(TokenKind::Agent, "claude")).unwrap();
        let ok = |role: Role, cap: Option<&str>| {
            let a = auth(&e, t.token.expose()).unwrap();
            assert_eq!((a.role, a.tier_cap.as_deref()), (role, cap));
        };
        ok(Role::Tester, None);
        // Promotion does not widen a token past its ceiling.
        e.acc.set_membership(&admin.id, "p", &tester.id, Role::Owner).unwrap();
        ok(Role::Tester, None);
        // Demotion narrows it at once, to a viewer who sends nothing.
        e.acc.set_membership(&admin.id, "p", &tester.id, Role::Viewer).unwrap();
        ok(Role::Viewer, Some("passive"));
        e.acc.set_membership(&admin.id, "p", &tester.id, Role::Tester).unwrap();
        ok(Role::Tester, None);
        // Removal kills the token, and it stays dead if the person is added back.
        e.acc.remove_membership(&admin.id, "p", &tester.id).unwrap();
        assert!(matches!(auth(&e, t.token.expose()), Err(AccountError::InvalidToken)));
        e.acc.set_membership(&admin.id, "p", &tester.id, Role::Tester).unwrap();
        assert!(matches!(auth(&e, t.token.expose()), Err(AccountError::InvalidToken)));
        let reason = e.acc.get_token(&t.info.id).unwrap().unwrap().revoked_reason;
        assert_eq!(reason.as_deref(), Some("membership_removed"));
        // Disabling the owner kills theirs, and enabling does not bring them back.
        let t = e.acc.create_token(&tester.id, &tester.id, "p", &spec(TokenKind::Plugin, "hosts")).unwrap();
        assert!(auth(&e, t.token.expose()).is_ok());
        e.acc.disable_user(&admin.id, &tester.id).unwrap();
        assert!(matches!(auth(&e, t.token.expose()), Err(AccountError::InvalidToken)));
        e.acc.enable_user(&admin.id, &tester.id).unwrap();
        assert!(matches!(auth(&e, t.token.expose()), Err(AccountError::InvalidToken)));
        assert_eq!(e.acc.get_token(&t.info.id).unwrap().unwrap().revoked_reason.as_deref(), Some("user_disabled"));
        // A disabled owner's token is dead even if the row were not revoked (checked at use, not only at disable).
        let t = e.acc.create_token(&tester.id, &tester.id, "p", &spec(TokenKind::Plugin, "later")).unwrap();
        e.acc.conn().execute("UPDATE users SET status = 'disabled' WHERE id = ?1", [&tester.id]).unwrap();
        assert!(matches!(auth(&e, t.token.expose()), Err(AccountError::InvalidToken)));
    }

    #[test]
    fn use_is_counted_at_most_once_a_minute_and_the_first_use_is_logged() {
        let e = env();
        let (_, tester, _) = team(&e);
        let t = e.acc.create_token(&tester.id, &tester.id, "p", &spec(TokenKind::Agent, "claude")).unwrap();
        assert!(e.acc.get_token(&t.info.id).unwrap().unwrap().last_used_at.is_none());
        for _ in 0..5 {
            auth(&e, t.token.expose()).unwrap();
        }
        let stored = e.acc.get_token(&t.info.id).unwrap().unwrap();
        assert_eq!((stored.last_used_at, stored.use_count), (Some(T0), 1), "one write: the first use");
        assert_eq!(e.acc.list_tokens("p", None).unwrap()[0].use_count, 5, "a listing includes what is not written yet");
        e.clock.advance(61);
        let a = auth(&e, t.token.expose()).unwrap();
        assert_eq!(a.info.use_count, 6);
        let stored = e.acc.get_token(&t.info.id).unwrap().unwrap();
        assert_eq!((stored.last_used_at, stored.use_count), (Some(T0 + 61), 6));
        assert_eq!(log_kinds(&e).iter().filter(|k| *k == "token_first_use").count(), 1);
        assert!(log_kinds(&e).contains(&"token_created".to_string()));
        e.acc.revoke_token(&tester.id, &t.info.id).unwrap();
        assert!(log_kinds(&e).contains(&"token_revoked".to_string()));
    }

    #[test]
    fn failures_are_logged_without_the_value_and_a_flood_is_not_logged_forever() {
        let e = env();
        let (_, tester, _) = team(&e);
        let t = e.acc.create_token(&tester.id, &tester.id, "p", &spec(TokenKind::Agent, "claude")).unwrap();
        e.acc.revoke_token(&tester.id, &t.info.id).unwrap();
        let _ = auth(&e, t.token.expose());
        let guess = token::generate(TokenKind::Agent).unwrap();
        let _ = auth(&e, guess.expose());
        let _ = auth(&e, "pm3_not-a-token");
        let log = e.acc.security_log(50).unwrap();
        let fails: Vec<&SecurityEvent> = log.iter().filter(|x| x.kind == "token_failure").collect();
        assert_eq!(fails.len(), 3);
        assert!(fails.iter().any(|f| f.detail.starts_with("revoked") && f.detail.contains(&t.info.id)));
        assert!(fails.iter().any(|f| f.detail == "unknown token"));
        assert!(fails.iter().any(|f| f.detail == "malformed token"));
        assert!(fails.iter().all(|f| f.client_addr.as_deref() == Some("203.0.113.9")));
        let dump = format!("{log:?}");
        for secret in [t.token.expose(), guess.expose()] {
            assert!(!dump.contains(secret), "a token value is in the security log");
            assert!(!dump.contains(&secret[secret.len() - 16..]), "part of a token value is in the security log");
        }
        // A flood from one address: after the free failures the log entries thin out (the delay doubles), and a
        // valid token is never refused because of it.
        let live = e.acc.create_token(&tester.id, &tester.id, "p", &spec(TokenKind::Agent, "live")).unwrap();
        for _ in 0..200 {
            let _ = auth(&e, guess.expose());
        }
        let n = e.acc.security_log(1000).unwrap().iter().filter(|x| x.kind == "token_failure").count();
        assert!(n < 30, "{n} failures logged out of 203");
        assert!(auth(&e, live.token.expose()).is_ok());
        // The flood does not throttle sign-in from the same address.
        assert!(e.acc.login_retry_after("tester1", &c()).unwrap().is_none());
        assert!(e.acc.verify_security_log().unwrap().is_ok());
    }

    #[test]
    fn only_a_hash_is_stored() {
        let dir = TempDir::new("tokdisk");
        let path = dir.file("server.db");
        let clock = Arc::new(ManualClock::new(T0));
        let acc = Accounts::open_with(&path, key(), Config::insecure_for_tests(), clock.clone()).unwrap();
        let e = Env { acc, clock };
        let (_, tester, _) = team(&e);
        let t = e.acc.create_token(&tester.id, &tester.id, "p", &spec(TokenKind::Agent, "claude")).unwrap();
        let secret = t.token.expose().to_string();
        let bare = secret.rsplit('_').next().unwrap().to_string();
        let mut disk = Vec::new();
        for name in ["server.db", "server.db-wal"] {
            if let Ok(b) = std::fs::read(dir.file(name)) {
                disk.extend(b);
            }
        }
        for needle in [secret.as_bytes(), bare.as_bytes()] {
            assert!(!disk.windows(needle.len()).any(|w| w == needle), "the token is on disk in plain text");
        }
        let (hash, count): (Vec<u8>, i64) = e
            .acc
            .conn()
            .query_row("SELECT token_hash, COUNT(*) FROM tokens", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!((hash.len(), count), (32, 1));
        // The hash is keyed: a server with another key cannot verify it.
        let other =
            Accounts::open_in_memory(ServerKey::from_bytes([8; 32]), Config::insecure_for_tests(), e.clock.clone())
                .unwrap();
        assert_ne!(token::digest(&other.keys.api_token, &secret), hash);
        assert_eq!(token::digest(&e.acc.keys.api_token, &secret), hash);
    }

    #[test]
    fn the_server_console_may_make_and_revoke_tokens_and_is_logged_as_such() {
        let e = env();
        let (_, tester, _) = team(&e);
        let made = e.acc.create_token(CONSOLE, &tester.id, "p", &spec(TokenKind::Agent, "claude")).unwrap();
        assert_eq!(made.info.created_by, CONSOLE);
        assert!(auth(&e, made.token.expose()).is_ok());
        // Still for a real member of the project, and nobody can claim to be the console by id.
        assert!(matches!(
            e.acc.create_token(CONSOLE, "u_nobody", "p", &spec(TokenKind::Agent, "x")),
            Err(AccountError::NoSuchUser)
        ));
        assert!(matches!(
            e.acc.create_token("local_console ", &tester.id, "p", &spec(TokenKind::Agent, "y")),
            Err(AccountError::NotAuthorised)
        ));
        e.acc.revoke_token(CONSOLE, &made.info.id).unwrap();
        assert!(matches!(auth(&e, made.token.expose()), Err(AccountError::InvalidToken)));
        let log = e.acc.security_log(50).unwrap();
        assert!(log.iter().any(|x| x.kind == "token_created" && x.actor == CONSOLE));
        assert!(log.iter().any(|x| x.kind == "token_revoked" && x.actor == CONSOLE));
        assert!(e.acc.verify_security_log().unwrap().is_ok());
    }

    // ---- the single-user file ---------------------------------------------------------------------------

    fn file_store(dir: &TempDir, clock: Arc<ManualClock>) -> TokenFile {
        TokenFile::open_with_clock(&dir.0, clock).unwrap()
    }

    #[test]
    fn the_token_file_has_the_same_rules() {
        let dir = TempDir::new("tokfile");
        let clock = Arc::new(ManualClock::new(T0));
        let f = file_store(&dir, clock.clone());
        assert!(f.list().unwrap().is_empty());
        let mut s = spec(TokenKind::Agent, "claude");
        s.tier_cap = Some("passive".into());
        let t = f.create(&s).unwrap();
        assert_eq!((t.info.user_id.clone(), t.info.project_id.clone()), (None, None));
        assert_eq!(t.info.expires_at, T0 + 30 * 86_400);
        let a = f.authenticate(t.token.expose()).unwrap();
        assert_eq!(
            (a.info.actor_id(), a.role, a.tier_cap.as_deref()),
            ("agent:claude".into(), Role::Tester, Some("passive"))
        );
        // Rules: names, roles, caps, unique live names.
        let mut owner = spec(TokenKind::Agent, "o");
        owner.role = Role::Owner;
        assert!(f.create(&owner).is_err());
        assert!(f.create(&spec(TokenKind::Agent, "bad name")).is_err());
        assert!(matches!(f.create(&spec(TokenKind::Agent, "CLAUDE")), Err(AccountError::TokenNameTaken)));
        f.create(&spec(TokenKind::Ci, "claude")).unwrap();
        // A viewer ceiling is held to passive.
        let mut v = spec(TokenKind::Plugin, "reader");
        v.role = Role::Viewer;
        let v = f.create(&v).unwrap();
        let a = f.authenticate(v.token.expose()).unwrap();
        assert_eq!((a.role, a.tier_cap.as_deref()), (Role::Viewer, Some("passive")));
        // Unknown, malformed, expired, revoked.
        let guess = token::generate(TokenKind::Agent).unwrap();
        assert!(matches!(f.authenticate(guess.expose()), Err(AccountError::InvalidToken)));
        assert!(matches!(f.authenticate("pm3_x"), Err(AccountError::InvalidToken)));
        let mut short = spec(TokenKind::Ci, "short");
        short.ttl = Some(Duration::from_secs(120));
        let short = f.create(&short).unwrap();
        assert!(f.authenticate(short.token.expose()).is_ok());
        clock.advance(120);
        assert!(matches!(f.authenticate(short.token.expose()), Err(AccountError::InvalidToken)));
        f.revoke(&t.info.id).unwrap();
        assert!(matches!(f.authenticate(t.token.expose()), Err(AccountError::InvalidToken)));
        assert!(matches!(f.revoke(&t.info.id), Err(AccountError::NoSuchToken)));
        // The name is free again once revoked.
        f.create(&spec(TokenKind::Agent, "claude")).unwrap();
    }

    #[test]
    fn the_token_file_is_private_hashed_and_shared_between_processes() {
        let dir = TempDir::new("tokfile2");
        let clock = Arc::new(ManualClock::new(T0));
        let ui = file_store(&dir, clock.clone());
        let cli = file_store(&dir, clock.clone());
        let t = cli.create(&spec(TokenKind::Agent, "claude")).unwrap();
        // The other handle (the running UI) sees it at once, and a revoke by the CLI is seen at the next request.
        let first = ui.authenticate(t.token.expose()).unwrap();
        assert_eq!(first.info.use_count, 1);
        cli.revoke(&t.info.id).unwrap();
        assert!(matches!(ui.authenticate(t.token.expose()), Err(AccountError::InvalidToken)));
        // The UI's bookkeeping cannot undo it: its next write re-reads under the lock.
        let t2 = cli.create(&spec(TokenKind::Agent, "second")).unwrap();
        ui.authenticate(t2.token.expose()).unwrap();
        clock.advance(61);
        ui.authenticate(t2.token.expose()).unwrap();
        cli.revoke(&t2.info.id).unwrap();
        let docs = cli.list().unwrap();
        assert!(docs.iter().all(|d| d.revoked_at.is_some()));
        assert_eq!(docs.iter().find(|d| d.id == t2.info.id).unwrap().use_count, 2);
        // On disk: the hash only, in files only the owner can read; no lock file left behind.
        let text = std::fs::read_to_string(dir.file("tokens.json")).unwrap();
        let bare = t.token.expose().rsplit('_').next().unwrap().to_string();
        assert!(!text.contains(t.token.expose()) && !text.contains(&bare), "the token is in the file");
        assert!(text.contains("\"hash\""));
        assert!(!dir.file("tokens.lock").exists());
        assert!(!dir.file("tokens.json.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["tokens.json", "tokens.key"] {
                let mode = std::fs::metadata(dir.file(name)).unwrap().permissions().mode();
                assert_eq!(mode & 0o777, 0o600, "{name}");
            }
            // A file that others can read is refused, by reads and by a new handle.
            std::fs::set_permissions(dir.file("tokens.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(ui.authenticate(t2.token.expose()), Err(AccountError::TokenStore(_))));
            assert!(matches!(ui.list(), Err(AccountError::TokenStore(_))));
            assert!(matches!(ui.create(&spec(TokenKind::Ci, "x")), Err(AccountError::TokenStore(_))));
            assert!(TokenFile::open(&dir.0).is_err());
            std::fs::set_permissions(dir.file("tokens.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(dir.file("tokens.key"), std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(TokenFile::open(&dir.0).is_err(), "a key others can read is refused");
        }
    }

    #[test]
    fn a_token_made_in_another_home_does_not_work_here() {
        let (a, b) = (TempDir::new("homea"), TempDir::new("homeb"));
        let clock = Arc::new(ManualClock::new(T0));
        let fa = file_store(&a, clock.clone());
        let fb = file_store(&b, clock.clone());
        let t = fa.create(&spec(TokenKind::Agent, "claude")).unwrap();
        assert!(matches!(fb.authenticate(t.token.expose()), Err(AccountError::InvalidToken)));
        // Even with the file copied over, the key is the home's own.
        std::fs::copy(a.file("tokens.json"), b.file("tokens.json")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(b.file("tokens.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(fb.authenticate(t.token.expose()), Err(AccountError::InvalidToken)));
        assert!(fa.authenticate(t.token.expose()).is_ok());
        // A damaged file fails closed.
        std::fs::write(a.file("tokens.json"), "{ not json").unwrap();
        assert!(matches!(fa.authenticate(t.token.expose()), Err(AccountError::TokenStore(_))));
    }
}
