//! Hash-chained audit log.
//!
//! Each record's hash covers its own fields and the previous record's hash,
//! so editing, deleting or reordering any record breaks the chain from that
//! point on. The database also refuses updates and deletes, but the chain is
//! what proves integrity if someone edits the file directly.
//!
//! # Record versions (ADR-0022 step 2)
//!
//! * **Version 1** (every record before this change, and every record from a build without it) hashes
//!   `seq, ts_ms, actor, action, detail, decision, prev_hash`. It still verifies exactly as before.
//! * **Version 2** also hashes the *context*: `principal_kind` (`local`, `session` or `token`), `user_id`, `token_id`
//!   (never the secret), `project_id`, `session_id` (first 8 bytes of the stored hash of the session id, hex) and
//!   `client_addr`. A log may hold version 1 records followed by version 2 records, never the other way round (a
//!   later version 1 record would be a way to write a record whose context is not covered by its hash).
//!
//! ## Canonical serialization of version 2
//!
//! The hash is BLAKE3 over, in order:
//!
//! ```text
//! "proxymind-audit-v2"                                  (the domain, raw bytes, no length)
//! field(seq as 8 bytes little endian)  field(ts_ms as 8 bytes little endian)
//! field(actor) field(action) field(detail) field(decision) field(prev_hash)
//! opt(principal_kind) opt(user_id) opt(token_id) opt(project_id) opt(session_id) opt(client_addr)
//!
//! field(x) = (length of x as 8 bytes little endian) || x
//! opt(None) = 0x00        opt(Some(s)) = 0x01 || field(s)
//! ```
//!
//! Absent and empty differ (`None` is `0x00`, `Some("")` is `0x01` followed by a zero length), so a field cannot be
//! switched between "not set" and "set to nothing" without changing the hash. A version 1 record must have none of the
//! context fields and no MAC; verification rejects one that does, because they would not be covered by its hash.
//!
//! ## The keyed chain (server mode, F-6)
//!
//! A version 2 record may carry `mac = HMAC-SHA256(audit key, "proxymind-audit-mac-v1" || hash)`. The hash already
//! covers the previous hash, so each MAC vouches for the whole log up to its record. Someone who can only write the
//! file cannot rebuild the chain: the plain hashes can be recomputed, the MACs cannot. Once a record carries a MAC,
//! every later record must (no downgrade). The key is given by the caller as an [`AuditKey`]; where it is stored is
//! not this crate's business (the server's `server.key`, step 3). Without the key, [`verify_with`] still checks the
//! plain chain and reports that the key check was skipped.
//!
//! The MAC does not detect removal of the newest records. Signed checkpoints do ([`crate::checkpoint`]).

use pm_store::AuditRecord;

use crate::PolicyError;

pub const GENESIS: [u8; 32] = [0; 32];

/// The record version new records are written with.
pub const CURRENT_VERSION: u8 = 2;

const MAC_DOMAIN: &[u8] = b"proxymind-audit-mac-v1";

/// Hex blake3 hash of arbitrary content (used to reference large audit details).
pub fn content_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn field(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

fn opt_field(h: &mut blake3::Hasher, v: &Option<String>) {
    match v {
        None => {
            h.update(&[0]);
        }
        Some(s) => {
            h.update(&[1]);
            field(h, s.as_bytes());
        }
    }
}

/// Who and where for a version 2 record. Everything is optional: single-user mode has no account, token or session.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditContext {
    /// `local` (single-user mode), `session` or `token`.
    pub principal_kind: Option<String>,
    pub user_id: Option<String>,
    pub token_id: Option<String>,
    pub project_id: Option<String>,
    pub session_id: Option<String>,
    pub client_addr: Option<String>,
}

impl AuditContext {
    /// Single-user mode: a local principal in this project.
    pub fn local(project_id: Option<String>) -> Self {
        Self { principal_kind: Some("local".into()), project_id, ..Self::default() }
    }
}

/// The key that makes the chain keyed. Implemented by whatever holds the secret (the server's key store); the secret
/// never has to be visible to this crate. `mac` must be a pure function of the key and the message.
pub trait AuditKey: Send + Sync {
    fn mac(&self, message: &[u8]) -> [u8; 32];
}

/// An HMAC-SHA256 key held in memory.
pub struct HmacKey(ring::hmac::Key);

impl HmacKey {
    /// At least 16 bytes (the server derives 32).
    pub fn new(secret: &[u8]) -> Result<Self, PolicyError> {
        if secret.len() < 16 {
            return Err(PolicyError::AuditKey("the key must be at least 16 bytes".into()));
        }
        Ok(Self(ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret)))
    }

    /// From a file's text: 64+ hex digits (whitespace ignored), else the raw bytes.
    pub fn from_file_bytes(data: &[u8]) -> Result<Self, PolicyError> {
        let text: String = String::from_utf8_lossy(data).chars().filter(|c| !c.is_whitespace()).collect();
        if text.len() >= 32 && text.len().is_multiple_of(2) && text.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes: Vec<u8> =
                (0..text.len()).step_by(2).filter_map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect();
            return Self::new(&bytes);
        }
        Self::new(data)
    }
}

impl AuditKey for HmacKey {
    fn mac(&self, message: &[u8]) -> [u8; 32] {
        let tag = ring::hmac::sign(&self.0, message);
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        out
    }
}

/// The MAC of a record hash under `key`.
pub fn record_mac(key: &dyn AuditKey, hash: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(MAC_DOMAIN.len() + hash.len());
    m.extend_from_slice(MAC_DOMAIN);
    m.extend_from_slice(hash);
    key.mac(&m).to_vec()
}

/// Compares without stopping at the first difference.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn has_context(r: &AuditRecord) -> bool {
    r.principal_kind.is_some()
        || r.user_id.is_some()
        || r.token_id.is_some()
        || r.project_id.is_some()
        || r.session_id.is_some()
        || r.client_addr.is_some()
}

/// Hash of a record's contents (everything except `hash` and `mac`), by the record's version. An unknown version
/// hashes like version 2 (verification refuses it before it gets here).
pub fn record_hash(r: &AuditRecord) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    let v1 = r.version == 1;
    h.update(if v1 { b"proxymind-audit-v1" as &[u8] } else { b"proxymind-audit-v2" });
    field(&mut h, &r.seq.to_le_bytes());
    field(&mut h, &r.ts_ms.to_le_bytes());
    field(&mut h, r.actor.as_bytes());
    field(&mut h, r.action.as_bytes());
    field(&mut h, r.detail.as_bytes());
    field(&mut h, r.decision.as_bytes());
    field(&mut h, &r.prev_hash);
    if !v1 {
        opt_field(&mut h, &r.principal_kind);
        opt_field(&mut h, &r.user_id);
        opt_field(&mut h, &r.token_id);
        opt_field(&mut h, &r.project_id);
        opt_field(&mut h, &r.session_id);
        opt_field(&mut h, &r.client_addr);
    }
    *h.finalize().as_bytes()
}

fn blank(
    prev: Option<&AuditRecord>,
    ts_ms: i64,
    actor: &str,
    action: &str,
    detail: &serde_json::Value,
    decision: &str,
) -> AuditRecord {
    AuditRecord {
        seq: prev.map_or(1, |p| p.seq + 1),
        ts_ms,
        actor: actor.to_string(),
        action: action.to_string(),
        detail: detail.to_string(),
        decision: decision.to_string(),
        prev_hash: prev.map_or(GENESIS.to_vec(), |p| p.hash.clone()),
        hash: Vec::new(),
        version: 1,
        principal_kind: None,
        user_id: None,
        token_id: None,
        project_id: None,
        session_id: None,
        client_addr: None,
        mac: None,
    }
}

/// Builds the next record in the chain after `prev`, as a **version 1** record (no context). Kept for tests that
/// need an old-format log and for callers with no context; the service writes [`next_record_v2`].
pub fn next_record(
    prev: Option<&AuditRecord>,
    ts_ms: i64,
    actor: &str,
    action: &str,
    detail: &serde_json::Value,
    decision: &str,
) -> AuditRecord {
    let mut r = blank(prev, ts_ms, actor, action, detail, decision);
    r.hash = record_hash(&r).to_vec();
    r
}

/// What happened, for [`next_record_v2`].
pub struct Entry<'a> {
    pub actor: &'a str,
    pub action: &'a str,
    pub detail: &'a serde_json::Value,
    pub decision: &'a str,
}

/// Builds the next record as **version 2**: the context is hashed into the record and, given a key, the record
/// carries its MAC.
pub fn next_record_v2(
    prev: Option<&AuditRecord>,
    ts_ms: i64,
    entry: &Entry<'_>,
    ctx: &AuditContext,
    key: Option<&dyn AuditKey>,
) -> AuditRecord {
    let mut r = blank(prev, ts_ms, entry.actor, entry.action, entry.detail, entry.decision);
    r.version = CURRENT_VERSION;
    r.principal_kind = ctx.principal_kind.clone();
    r.user_id = ctx.user_id.clone();
    r.token_id = ctx.token_id.clone();
    r.project_id = ctx.project_id.clone();
    r.session_id = ctx.session_id.clone();
    r.client_addr = ctx.client_addr.clone();
    r.hash = record_hash(&r).to_vec();
    r.mac = key.map(|k| record_mac(k, &r.hash));
    r
}

/// How the key check went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCheck {
    /// Every keyed record's MAC matched the key.
    Verified,
    /// The log has keyed records but no key was given: only the plain chain was checked.
    Skipped,
    /// No record is keyed (single-user mode, or a log from before the key) and none was required.
    NotKeyed,
}

/// What [`verify_with`] checks beyond the plain chain.
#[derive(Default, Clone, Copy)]
pub struct VerifyOptions<'a> {
    /// Check the MACs of keyed records against this key.
    pub key: Option<&'a dyn AuditKey>,
    /// The log must be keyed (server mode): a non-empty log with no keyed record, or a version 2 record without a MAC
    /// after the first keyed one, fails. Needs `key` to mean anything, but is also checked without it.
    pub require_keyed: bool,
}

/// What a successful verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verification {
    pub records: usize,
    pub v1: usize,
    pub v2: usize,
    /// Records that carry a MAC.
    pub keyed: usize,
    pub key_check: KeyCheck,
    /// Hex of the newest record's hash (empty for an empty log).
    pub head: String,
}

fn broken(seq: i64, why: &'static str) -> PolicyError {
    PolicyError::AuditBroken { seq, why }
}

/// Checks a full log, plain chain only. Returns the number of records on success, or the first sequence number where
/// the chain is broken. Version 1 and version 2 records are both checked; a MAC is not (see [`verify_with`]).
pub fn verify(records: &[AuditRecord]) -> Result<usize, PolicyError> {
    verify_with(records, VerifyOptions::default()).map(|v| v.records)
}

/// Checks a full log: the chain and every record's hash by its version, the version order, and (when asked) the keyed
/// chain.
pub fn verify_with(records: &[AuditRecord], opts: VerifyOptions<'_>) -> Result<Verification, PolicyError> {
    let mut prev_hash = GENESIS.to_vec();
    let (mut v1, mut v2, mut keyed) = (0usize, 0usize, 0usize);
    let mut macs_checked = true;
    for (i, r) in records.iter().enumerate() {
        let expected_seq = i as i64 + 1;
        if r.seq != expected_seq {
            return Err(broken(expected_seq, "record missing or out of order"));
        }
        if r.prev_hash != prev_hash {
            return Err(broken(r.seq, "previous-hash link does not match"));
        }
        match r.version {
            1 => {
                if v2 > 0 {
                    return Err(broken(r.seq, "a version 1 record follows a version 2 record"));
                }
                if has_context(r) || r.mac.is_some() {
                    return Err(broken(r.seq, "a version 1 record carries version 2 fields"));
                }
                v1 += 1;
            }
            2 => v2 += 1,
            _ => return Err(broken(r.seq, "unknown record version")),
        }
        if r.hash != record_hash(r) {
            return Err(broken(r.seq, "record contents were changed"));
        }
        match &r.mac {
            Some(mac) => {
                keyed += 1;
                match opts.key {
                    Some(k) => {
                        let want = record_mac(k, &r.hash);
                        if !constant_time_eq(&want, mac) {
                            return Err(broken(r.seq, "the record's MAC does not match the audit key"));
                        }
                    }
                    None => macs_checked = false,
                }
            }
            None => {
                if keyed > 0 {
                    return Err(broken(r.seq, "a keyed chain continues without a MAC"));
                }
            }
        }
        prev_hash = r.hash.clone();
    }
    if opts.require_keyed && !records.is_empty() && keyed == 0 {
        return Err(broken(1, "the log is not keyed but a keyed log is required"));
    }
    let key_check = if keyed == 0 {
        KeyCheck::NotKeyed
    } else if macs_checked {
        KeyCheck::Verified
    } else {
        KeyCheck::Skipped
    };
    Ok(Verification {
        records: records.len(),
        v1,
        v2,
        keyed,
        key_check,
        head: if records.is_empty() { String::new() } else { hex(&prev_hash) },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{self, Checkpoint};
    use serde_json::json;

    fn chain(n: usize) -> Vec<AuditRecord> {
        let mut v: Vec<AuditRecord> = Vec::new();
        for i in 0..n {
            let r = next_record(v.last(), i as i64, "agent:a", "replay_send", &json!({"i": i}), "allow");
            v.push(r);
        }
        v
    }

    fn ctx() -> AuditContext {
        AuditContext {
            principal_kind: Some("token".into()),
            user_id: Some("u_1".into()),
            token_id: Some("t_1".into()),
            project_id: Some("proj".into()),
            session_id: None,
            client_addr: Some("10.0.0.2".into()),
        }
    }

    fn key(b: u8) -> HmacKey {
        HmacKey::new(&[b; 32]).unwrap()
    }

    /// `n` records appended to `v`, as version 2, keyed when `k` is given.
    fn push_v2(v: &mut Vec<AuditRecord>, n: usize, k: Option<&dyn AuditKey>) {
        for i in 0..n {
            let detail = json!({ "v2": i });
            let e = Entry { actor: "human:alice", action: "roe_set", detail: &detail, decision: "allow" };
            let r = next_record_v2(v.last(), 100 + i as i64, &e, &ctx(), k);
            v.push(r);
        }
    }

    /// Recomputes every hash (and so the whole plain chain) after a change, as someone who can write the file would.
    fn rebuild_plain(v: &mut [AuditRecord]) {
        let mut prev = GENESIS.to_vec();
        for r in v.iter_mut() {
            r.prev_hash = prev.clone();
            r.hash = record_hash(r).to_vec();
            prev = r.hash.clone();
        }
    }

    #[test]
    fn valid_chain_verifies() {
        assert_eq!(verify(&chain(5)).unwrap(), 5);
        assert_eq!(verify(&[]).unwrap(), 0);
    }

    #[test]
    fn detects_edits_deletes_and_reordering() {
        let mut c = chain(5);
        c[2].decision = "deny".into();
        assert!(matches!(verify(&c), Err(PolicyError::AuditBroken { seq: 3, .. })));

        let mut c = chain(5);
        c.remove(2);
        assert!(matches!(verify(&c), Err(PolicyError::AuditBroken { seq: 3, .. })));

        let mut c = chain(5);
        c.swap(1, 2);
        assert!(verify(&c).is_err());

        // Rewriting a record *and* its hash still breaks the next link.
        let mut c = chain(5);
        c[2].decision = "deny".into();
        c[2].hash = record_hash(&c[2]).to_vec();
        assert!(matches!(verify(&c), Err(PolicyError::AuditBroken { seq: 4, .. })));
    }

    /// The version 1 hash is frozen: this is the original implementation, copied, and a record written the old way
    /// must hash exactly as it did.
    #[test]
    fn version_one_hash_is_unchanged() {
        fn original(r: &AuditRecord) -> [u8; 32] {
            let mut h = blake3::Hasher::new();
            h.update(b"proxymind-audit-v1");
            for f in [
                &r.seq.to_le_bytes()[..],
                &r.ts_ms.to_le_bytes()[..],
                r.actor.as_bytes(),
                r.action.as_bytes(),
                r.detail.as_bytes(),
                r.decision.as_bytes(),
                &r.prev_hash[..],
            ] {
                h.update(&(f.len() as u64).to_le_bytes());
                h.update(f);
            }
            *h.finalize().as_bytes()
        }
        let c = chain(4);
        for r in &c {
            assert_eq!(r.hash, original(r).to_vec());
        }
        assert_eq!(hex(&c[0].hash), "1cacddd879bc4fab240d249ab91aaccf6eb3ca288d9e7081a9df0322452e104f");
    }

    #[test]
    fn mixed_v1_then_v2_chains_verify() {
        let mut c = chain(3);
        push_v2(&mut c, 3, None);
        let v = verify_with(&c, VerifyOptions::default()).unwrap();
        assert_eq!((v.records, v.v1, v.v2, v.keyed), (6, 3, 3, 0));
        assert_eq!(v.key_check, KeyCheck::NotKeyed);
        assert_eq!(v.head, hex(&c[5].hash));
        // ... and the order cannot be reversed.
        let mut bad = Vec::new();
        push_v2(&mut bad, 1, None);
        let r = next_record(bad.last(), 5, "agent:a", "x", &json!({}), "allow");
        bad.push(r);
        assert!(matches!(verify(&bad), Err(PolicyError::AuditBroken { seq: 2, .. })));
    }

    #[test]
    fn any_changed_v2_field_fails() {
        let mut base = chain(2);
        push_v2(&mut base, 2, None);
        type Edit = (&'static str, fn(&mut AuditRecord));
        let edits: [Edit; 7] = [
            ("user_id", |r| r.user_id = Some("u_2".into())),
            ("token_id", |r| r.token_id = None),
            ("project_id", |r| r.project_id = Some("other".into())),
            ("client_addr", |r| r.client_addr = Some("6.6.6.6".into())),
            ("principal_kind", |r| r.principal_kind = Some("local".into())),
            ("session_id", |r| r.session_id = Some("00".into())),
            ("detail", |r| r.detail = "{}".into()),
        ];
        for (name, edit) in edits {
            let mut c = base.clone();
            edit(&mut c[2]);
            assert!(matches!(verify(&c), Err(PolicyError::AuditBroken { seq: 3, .. })), "{name}");
        }
        // Not set and set to the empty string are different.
        let mut c = base.clone();
        c[3].session_id = Some(String::new());
        assert!(verify(&c).is_err());
    }

    #[test]
    fn a_v1_record_cannot_smuggle_v2_fields() {
        let mut c = chain(2);
        c[1].user_id = Some("u_9".into());
        assert!(matches!(verify(&c), Err(PolicyError::AuditBroken { seq: 2, .. })));
        let mut c = chain(2);
        c[1].version = 3;
        assert!(verify(&c).is_err());
    }

    #[test]
    fn keyed_chain_detects_a_rebuilt_chain() {
        let k = key(7);
        let mut c = chain(2);
        push_v2(&mut c, 4, Some(&k));
        let opts = VerifyOptions { key: Some(&k), require_keyed: true };
        let v = verify_with(&c, opts).unwrap();
        assert_eq!((v.keyed, v.key_check), (4, KeyCheck::Verified));

        // Without the key: the plain chain is checked and the key check is reported as skipped.
        let v = verify_with(&c, VerifyOptions::default()).unwrap();
        assert_eq!(v.key_check, KeyCheck::Skipped);

        // Someone without the key edits record 5 and rebuilds every hash: the plain chain passes, the MACs do not.
        let mut t = c.clone();
        t[4].user_id = Some("u_evil".into());
        rebuild_plain(&mut t);
        assert_eq!(verify(&t).unwrap(), 6);
        assert!(matches!(verify_with(&t, opts), Err(PolicyError::AuditBroken { seq: 5, .. })));

        // Another key does not do either.
        let other = key(8);
        assert!(verify_with(&c, VerifyOptions { key: Some(&other), require_keyed: true }).is_err());
    }

    #[test]
    fn a_keyed_chain_cannot_be_downgraded() {
        let k = key(7);
        let mut c = Vec::new();
        push_v2(&mut c, 3, Some(&k));
        // The tail rewritten without MACs.
        let mut t = c.clone();
        t[2].mac = None;
        let opts = VerifyOptions { key: Some(&k), require_keyed: true };
        assert!(matches!(verify_with(&t, opts), Err(PolicyError::AuditBroken { seq: 3, .. })));
        assert!(verify(&t).is_err(), "caught even without the key");
        // The whole log rewritten as unkeyed records.
        let mut u = Vec::new();
        push_v2(&mut u, 3, None);
        assert!(verify_with(&u, opts).is_err());
        assert!(verify(&u).is_ok(), "a single-user log is fine when no key is required");
        assert_eq!(verify_with(&[], opts).unwrap().records, 0);
    }

    #[test]
    fn key_files_parse_hex_or_raw() {
        let hexed = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n";
        let a = HmacKey::from_file_bytes(hexed.as_bytes()).unwrap();
        let raw: Vec<u8> = (0..32).map(|i| (i * 0x11 % 256) as u8).collect();
        let _ = raw;
        assert_eq!(a.mac(b"x"), HmacKey::new(&unhex_test(hexed.trim())).unwrap().mac(b"x"));
        assert!(HmacKey::new(&[1; 8]).is_err());
    }

    fn unhex_test(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn signer() -> Vec<u8> {
        pm_tools::sign::generate().unwrap()
    }

    #[test]
    fn checkpoints_detect_truncation_rewrite_and_forgery() {
        let mut c = chain(2);
        push_v2(&mut c, 4, None);
        let sk = signer();
        let pk = pm_tools::sign::public_key(&sk).unwrap();
        let cp = Checkpoint::create(&sk, 5, &c[4].hash, 1234, Some("proj")).unwrap();
        assert!(cp.signature_valid());
        checkpoint::check(&cp, &c, Some(&pk), Some("proj")).unwrap();
        // Records after the checkpoint are fine.
        checkpoint::check(&cp, &c, None, None).unwrap();

        // Tail truncation: the newest records are cut off (the remaining chain still verifies).
        let cut = &c[..3];
        assert_eq!(verify(cut).unwrap(), 3);
        let e = checkpoint::check(&cp, cut, Some(&pk), Some("proj")).unwrap_err().to_string();
        assert!(e.contains("removed from the end"), "{e}");

        // Rewrite before the checkpoint, chain rebuilt: it verifies, the checkpoint does not match.
        let mut t = c.clone();
        t[1].decision = "deny".into();
        rebuild_plain(&mut t);
        assert_eq!(verify(&t).unwrap(), 6);
        let e = checkpoint::check(&cp, &t, Some(&pk), Some("proj")).unwrap_err().to_string();
        assert!(e.contains("rewritten"), "{e}");

        // Altering the checkpoint breaks its signature.
        let mut forged = cp.clone();
        forged.seq = 3;
        forged.head = hex(&c[2].hash);
        assert!(!forged.signature_valid());
        assert!(checkpoint::check(&forged, &c, None, None).is_err());

        // A forger's own checkpoint over the rebuilt chain is validly signed but by the wrong key.
        let evil = signer();
        let fake = Checkpoint::create(&evil, 5, &t[4].hash, 1234, Some("proj")).unwrap();
        assert!(fake.signature_valid());
        let e = checkpoint::check(&fake, &t, Some(&pk), Some("proj")).unwrap_err().to_string();
        assert!(e.contains("unexpected key"), "{e}");

        // Another project's checkpoint; an empty log has nothing to checkpoint.
        assert!(checkpoint::check(&cp, &c, None, Some("elsewhere")).is_err());
        assert!(Checkpoint::create(&sk, 0, &[], 1, None).is_err());
    }

    #[test]
    fn checkpoint_files_round_trip() {
        let sk = signer();
        let cp = Checkpoint::create(&sk, 2, &[7; 32], 9, None).unwrap();
        let one = serde_json::to_string_pretty(&cp).unwrap();
        assert_eq!(Checkpoint::parse_many(&one).unwrap(), vec![cp.clone()]);
        let many = serde_json::to_string(&vec![cp.clone(), cp.clone()]).unwrap();
        assert_eq!(Checkpoint::parse_many(&many).unwrap().len(), 2);
        assert!(Checkpoint::parse_many("nope").is_err());
        assert!(!one.contains("project_id"));
    }
}
