//! ADR-0022 step 2: audit record version 2, the keyed chain and signed checkpoints.
//!
//! Old (version 1) logs still verify; a log may be version 1 then version 2; any changed version 2 field fails; a
//! chain rebuilt after tampering passes the plain check and fails the keyed one; cutting the tail is caught by a
//! checkpoint; a forged checkpoint is refused; evidence packs with and without a checkpoint verify.

use std::path::PathBuf;
use std::sync::Arc;

use pm_service::access::{Principal, Role};
use pm_service::pm_policy::audit::{self, AuditKey, HmacKey};
use pm_service::pm_policy::checkpoint::Checkpoint;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{AuditRecord, Store};
use pm_service::pm_tools::zip;
use pm_service::{AuditSecurity, AuditVerifyOptions, Service, verify_audit_report, verify_evidence};
use serde_json::json;

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

fn roe() -> Roe {
    Roe::parse("version: 1\nscope:\n  include: [\"http://127.0.0.1/\"]\n").unwrap()
}

fn temp(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("pm-auditv2-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("p.pmproj");
    (dir, file)
}

fn key() -> Arc<dyn AuditKey> {
    Arc::new(HmacKey::new(&[42u8; 32]).unwrap())
}

fn records(file: &std::path::Path) -> Vec<AuditRecord> {
    Store::open(file).unwrap().audit_records().unwrap()
}

/// Opens the file with SQLite directly, as someone who can write it would, with the append-only triggers gone.
fn raw(file: &std::path::Path) -> rusqlite::Connection {
    let c = rusqlite::Connection::open(file).unwrap();
    c.execute_batch(
        "DROP TRIGGER IF EXISTS audit_log_no_update; DROP TRIGGER IF EXISTS audit_log_no_delete;
         DROP TRIGGER IF EXISTS audit_checkpoints_no_update; DROP TRIGGER IF EXISTS audit_checkpoints_no_delete;",
    )
    .unwrap();
    c
}

/// Writes records back with every hash (and, with `mac`, every MAC) recomputed, as an attacker who can write the
/// file but does not hold the key would: hashes yes, MACs they cannot.
fn rebuild(file: &std::path::Path, edit: impl Fn(&mut Vec<AuditRecord>)) {
    let mut recs = records(file);
    edit(&mut recs);
    let mut prev = audit::GENESIS.to_vec();
    for r in recs.iter_mut() {
        r.prev_hash = prev.clone();
        r.hash = audit::record_hash(r).to_vec();
        prev = r.hash.clone();
    }
    let c = raw(file);
    c.execute("DELETE FROM audit_log", []).unwrap();
    drop(c);
    let mut s = Store::open(file).unwrap();
    for r in &recs {
        s.append_audit(r).unwrap();
    }
}

fn service(file: &std::path::Path) -> Service {
    Service::new(Store::open(file).unwrap(), Policy::new(roe())).unwrap()
}

fn do_some_actions(s: &Service, n: usize) {
    for i in 0..n {
        s.roe_set(&human(), &format!("version: 1\nscope:\n  include: [\"http://127.0.0.1/{i}\"]\n")).unwrap();
    }
}

fn report(file: &std::path::Path, opts: &AuditVerifyOptions) -> pm_service::AuditVerification {
    verify_audit_report(&Store::open(file).unwrap(), opts)
}

/// A project file as the previous release left it: a version 1 log and schema 25.
fn old_project(file: &std::path::Path, n: usize) {
    {
        let mut s = Store::open(file).unwrap();
        for i in 0..n {
            let prev = s.last_audit().unwrap();
            let r = audit::next_record(prev.as_ref(), i as i64, "human:old", "roe_set", &json!({ "i": i }), "ok");
            s.append_audit(&r).unwrap();
        }
    }
    let c = rusqlite::Connection::open(file).unwrap();
    c.execute_batch(
        "ALTER TABLE approvals DROP COLUMN requested_user; ALTER TABLE approvals DROP COLUMN requested_token;
         ALTER TABLE approvals DROP COLUMN requested_role;
         DROP TABLE audit_checkpoints; ALTER TABLE audit_log DROP COLUMN version;
         ALTER TABLE audit_log DROP COLUMN principal_kind; ALTER TABLE audit_log DROP COLUMN user_id;
         ALTER TABLE audit_log DROP COLUMN token_id; ALTER TABLE audit_log DROP COLUMN project_id;
         ALTER TABLE audit_log DROP COLUMN session_id; ALTER TABLE audit_log DROP COLUMN client_addr;
         ALTER TABLE audit_log DROP COLUMN mac; PRAGMA user_version = 25;",
    )
    .unwrap();
}

#[test]
fn an_old_log_verifies_and_new_records_follow_it() {
    let (dir, file) = temp("old");
    old_project(&file, 4);
    // Opening migrates (migration 26); the old rows are version 1 with no context.
    let before = report(&file, &AuditVerifyOptions::default());
    assert!(before.intact, "{:?}", before.error);
    assert_eq!((before.records, before.v1_records, before.v2_records), (4, 4, 0));

    let s = service(&file);
    do_some_actions(&s, 3);
    let v = s.audit_verify_report(vec![], None);
    assert!(v.intact, "{:?}", v.error);
    assert_eq!(v.v1_records, 4);
    assert!(v.v2_records >= 3);
    assert_eq!(v.keyed_records, 0);
    assert_eq!(v.key_check, "not_keyed");
    assert_eq!(s.audit_verify().unwrap(), v.records);

    // New records say who and where, in single-user terms: local, this project.
    let recs = records(&file);
    let last = recs.last().unwrap();
    assert_eq!((last.version, last.principal_kind.as_deref()), (2, Some("local")));
    assert!(last.project_id.as_deref().is_some_and(|p| !p.is_empty()));
    assert!(last.user_id.is_none() && last.token_id.is_none() && last.session_id.is_none() && last.mac.is_none());
    // Version 1 records are untouched and their JSON has no new fields.
    let j = serde_json::to_string(&recs[0]).unwrap();
    assert!(!j.contains("version") && !j.contains("user_id") && !j.contains("mac"), "{j}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_principal_feeds_the_context_and_every_v2_field_is_protected() {
    let (dir, file) = temp("ctx");
    let s = service(&file);
    let mut p = Principal::new(Actor::parse("agent:claude").unwrap(), Role::Tester).with_addr("10.1.2.3");
    p.user_id = Some("u_alice".into());
    p.token_id = Some("tok_1".into());
    s.audit_principal(&p, "replay_send", json!({"x": 1}), "allow").unwrap();
    let rec = records(&file).pop().unwrap();
    assert_eq!(rec.actor, "agent:claude");
    assert_eq!(
        (rec.principal_kind.as_deref(), rec.user_id.as_deref(), rec.token_id.as_deref(), rec.client_addr.as_deref()),
        (Some("token"), Some("u_alice"), Some("tok_1"), Some("10.1.2.3"))
    );
    assert!(s.audit_verify_report(vec![], None).intact);
    drop(s);

    for (col, val) in [
        ("user_id", "u_mallory"),
        ("token_id", "tok_2"),
        ("client_addr", "6.6.6.6"),
        ("project_id", "other"),
        ("principal_kind", "local"),
    ] {
        let c = raw(&file);
        let seq = rec.seq;
        let old: Option<String> =
            c.query_row(&format!("SELECT {col} FROM audit_log WHERE seq = {seq}"), [], |r| r.get(0)).unwrap();
        c.execute(&format!("UPDATE audit_log SET {col} = ?1 WHERE seq = ?2"), rusqlite::params![val, seq]).unwrap();
        let v = report(&file, &AuditVerifyOptions::default());
        assert!(!v.intact, "changing {col} must fail verification");
        assert!(v.error.unwrap().contains(&format!("record {seq}")), "{col}");
        c.execute(&format!("UPDATE audit_log SET {col} = ?1 WHERE seq = ?2"), rusqlite::params![old, seq]).unwrap();
        assert!(report(&file, &AuditVerifyOptions::default()).intact, "restored {col}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_rebuilt_chain_passes_the_plain_check_and_fails_the_keyed_one() {
    let (dir, file) = temp("keyed");
    let s = service(&file);
    s.set_audit_security(AuditSecurity { key: Some(key()), require_keyed: true, ..Default::default() });
    do_some_actions(&s, 4);
    let v = s.audit_verify_report(vec![], None);
    assert!(v.intact, "{:?}", v.error);
    assert_eq!((v.key_check.as_str(), v.keyed_records), ("verified", v.records - v.v1_records));
    assert!(v.keyed_records >= 4);
    drop(s);

    // With the key; without the key (plain chain checked, key check skipped and said so).
    let with = AuditVerifyOptions { key: Some(key()), require_keyed: true, ..Default::default() };
    assert!(report(&file, &with).intact);
    let without = report(&file, &AuditVerifyOptions::default());
    assert!(without.intact);
    assert_eq!(without.key_check, "skipped");
    assert!(without.key_note.contains("no audit key was given"));

    // Someone who can write the file rewrites an actor and recomputes every hash.
    rebuild(&file, |r| {
        let i = r.len() - 2;
        r[i].actor = "human:somebody-else".into();
    });
    let plain = report(&file, &AuditVerifyOptions::default());
    assert!(plain.intact, "the plain chain was rebuilt consistently: {:?}", plain.error);
    let keyed = report(&file, &with);
    assert!(!keyed.intact);
    assert_eq!(keyed.key_check, "failed");
    assert!(keyed.error.unwrap().contains("MAC"));
    // A different key is no better.
    let other = AuditVerifyOptions { key: Some(Arc::new(HmacKey::new(&[1u8; 32]).unwrap())), ..Default::default() };
    assert!(!report(&file, &other).intact);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_checkpoint_catches_truncation_and_rewriting_and_forgery_is_refused() {
    let (dir, file) = temp("cp");
    let home = dir.join("home");
    let s = service(&file);
    s.attach_plugin_home(home.clone());
    assert!(s.audit_checkpoint(&Actor::parse("agent:x").unwrap()).is_err(), "people only");
    do_some_actions(&s, 3);
    let cp = s.audit_checkpoint(&human()).unwrap();
    assert!(cp.signature_valid());
    let exported = serde_json::to_string_pretty(&cp).unwrap();
    do_some_actions(&s, 2);
    let v = s.audit_verify_report(vec![], None);
    assert!(v.intact, "{:?}", v.error);
    assert_eq!(v.checkpoints.status, "ok");
    assert_eq!((v.checkpoints.stored, v.checkpoints.latest_seq), (1, Some(cp.seq)));
    assert!(v.checkpoints.signer_pinned, "the home key is known");
    let key_file = home.join(pm_service::CHECKPOINT_KEY_FILE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let signer = pm_service::checkpoint_signer_public(&home).unwrap();
    drop(s);

    let opts = |cps: Vec<Checkpoint>| AuditVerifyOptions {
        checkpoints: cps,
        trusted_signer: Some(signer.clone()),
        ..Default::default()
    };
    let exported_cp = Checkpoint::parse_many(&exported).unwrap();
    assert!(report(&file, &opts(exported_cp.clone())).intact);
    // Pinning by fingerprint.
    let by_fp = AuditVerifyOptions {
        checkpoints: exported_cp.clone(),
        pinned_fingerprint: Some(cp.fingerprint()),
        ..Default::default()
    };
    assert!(report(&file, &by_fp).intact);
    let wrong_fp = AuditVerifyOptions { pinned_fingerprint: Some("0000:1111:2222:3333".into()), ..by_fp.clone() };
    assert!(!report(&file, &wrong_fp).intact);

    // 1. A forged checkpoint (signature altered, or signed by another key) is refused.
    let mut forged = exported_cp[0].clone();
    forged.signature = format!("{:0<128}", "ab");
    let v = report(&file, &opts(vec![forged]));
    assert!(!v.intact && v.error.unwrap().contains("invalid signature"));
    let evil = pm_service::pm_tools::sign::generate().unwrap();
    let head = records(&file).pop().unwrap();
    let fake = Checkpoint::create(&evil, head.seq, &head.hash, 1, None).unwrap();
    let v = report(&file, &opts(vec![fake]));
    assert!(!v.intact && v.error.unwrap().contains("unexpected key"));

    // 2. Records cut off the end: the remaining chain verifies, the checkpoint does not.
    let backup = std::fs::read(&file).unwrap();
    let total = records(&file).len() as i64;
    let c = raw(&file);
    c.execute("DELETE FROM audit_log WHERE seq > ?1", [cp.seq - 2]).unwrap();
    // The stored copy is deleted as well, as a writer of the file would.
    c.execute("DELETE FROM audit_checkpoints", []).unwrap();
    drop(c);
    let v = report(&file, &AuditVerifyOptions::default());
    assert!(v.intact, "without any checkpoint, truncation is invisible: {:?}", v.error);
    assert_eq!(v.checkpoints.status, "none");
    let v = report(&file, &opts(exported_cp.clone()));
    assert!(!v.intact, "the exported checkpoint shows it ({total} -> {})", v.records);
    assert!(v.error.unwrap().contains("removed from the end"));

    // 3. Rewritten before the checkpoint with the chain rebuilt: the checkpoint's head no longer matches.
    std::fs::write(&file, &backup).unwrap();
    rebuild(&file, |r| r[1].actor = "human:forged".into());
    let v = report(&file, &opts(exported_cp));
    assert!(!v.intact);
    assert!(v.error.unwrap().contains("rewritten"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn automatic_checkpoints_are_written_every_n_records() {
    let (dir, file) = temp("auto");
    let s = service(&file);
    let sk = pm_service::pm_tools::sign::generate().unwrap();
    s.set_audit_security(AuditSecurity {
        key: Some(key()),
        require_keyed: true,
        signing_key: Some(Arc::new(sk)),
        checkpoint_every: Some(3),
    });
    do_some_actions(&s, 8);
    let cps = s.audit_checkpoints().unwrap();
    assert!(cps.len() >= 2 && cps.iter().all(|c| c.seq % 3 == 0 && c.signature_valid()), "{cps:?}");
    let v = s.audit_verify_report(vec![], None);
    assert!(v.intact, "{:?}", v.error);
    assert_eq!(v.checkpoints.status, "ok");
    assert!(v.checkpoints.signer_pinned);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn evidence_packs_with_and_without_a_checkpoint_verify() {
    let (dir, file) = temp("pack");
    let home = dir.join("home");
    let s = service(&file);
    s.attach_plugin_home(home);
    do_some_actions(&s, 2);

    // No checkpoint yet: the pack is as it was before this change (no extra file) and verifies.
    let (pack, _) = s.evidence_pack(&human(), false).unwrap();
    let names: Vec<String> = zip::read(&pack).unwrap().into_iter().map(|(n, _)| n).collect();
    assert!(!names.iter().any(|n| n == "audit-checkpoint.json"));
    let v = verify_evidence(&pack);
    assert!(v.ok, "{:?}", v.checks);

    // With one: it is in the pack, checked, and covered by the manifest's signature.
    s.audit_checkpoint(&human()).unwrap();
    let (pack, _) = s.evidence_pack(&human(), false).unwrap();
    let entries = zip::read(&pack).unwrap();
    assert!(entries.iter().any(|(n, _)| n == "audit-checkpoint.json"));
    let v = verify_evidence(&pack);
    assert!(v.ok, "{:?}", v.checks);
    assert!(v.checks.iter().any(|c| c.name == "audit checkpoint" && c.ok));

    // Swapping the checkpoint file for another breaks the manifest's hash.
    let evil = pm_service::pm_tools::sign::generate().unwrap();
    let fake = Checkpoint::create(&evil, 1, &[1; 32], 1, None).unwrap();
    let swapped: Vec<(String, Vec<u8>)> = entries
        .into_iter()
        .map(|(n, d)| if n == "audit-checkpoint.json" { (n, serde_json::to_vec(&fake).unwrap()) } else { (n, d) })
        .collect();
    let v = verify_evidence(&zip::write(&swapped).unwrap());
    assert!(!v.ok);
    let _ = std::fs::remove_dir_all(dir);
}
