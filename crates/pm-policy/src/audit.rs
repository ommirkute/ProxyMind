//! Hash-chained audit log.
//!
//! Each record's hash covers its own fields and the previous record's hash,
//! so editing, deleting or reordering any record breaks the chain from that
//! point on. The database also refuses updates and deletes, but the chain is
//! what proves integrity if someone edits the file directly.

use pm_store::AuditRecord;

use crate::PolicyError;

pub const GENESIS: [u8; 32] = [0; 32];

/// Hex blake3 hash of arbitrary content (used to reference large audit details).
pub fn content_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn field(h: &mut blake3::Hasher, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

/// Hash of a record's contents (everything except `hash` itself).
pub fn record_hash(r: &AuditRecord) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"proxymind-audit-v1");
    field(&mut h, &r.seq.to_le_bytes());
    field(&mut h, &r.ts_ms.to_le_bytes());
    field(&mut h, r.actor.as_bytes());
    field(&mut h, r.action.as_bytes());
    field(&mut h, r.detail.as_bytes());
    field(&mut h, r.decision.as_bytes());
    field(&mut h, &r.prev_hash);
    *h.finalize().as_bytes()
}

/// Builds the next record in the chain after `prev`.
pub fn next_record(
    prev: Option<&AuditRecord>,
    ts_ms: i64,
    actor: &str,
    action: &str,
    detail: &serde_json::Value,
    decision: &str,
) -> AuditRecord {
    let mut r = AuditRecord {
        seq: prev.map_or(1, |p| p.seq + 1),
        ts_ms,
        actor: actor.to_string(),
        action: action.to_string(),
        detail: detail.to_string(),
        decision: decision.to_string(),
        prev_hash: prev.map_or(GENESIS.to_vec(), |p| p.hash.clone()),
        hash: Vec::new(),
    };
    r.hash = record_hash(&r).to_vec();
    r
}

/// Checks a full log. Returns the number of records on success, or the
/// first sequence number where the chain is broken.
pub fn verify(records: &[AuditRecord]) -> Result<usize, PolicyError> {
    let mut prev_hash = GENESIS.to_vec();
    for (i, r) in records.iter().enumerate() {
        let expected_seq = i as i64 + 1;
        if r.seq != expected_seq {
            return Err(PolicyError::AuditBroken { seq: expected_seq, why: "record missing or out of order" });
        }
        if r.prev_hash != prev_hash {
            return Err(PolicyError::AuditBroken { seq: r.seq, why: "previous-hash link does not match" });
        }
        if r.hash != record_hash(r) {
            return Err(PolicyError::AuditBroken { seq: r.seq, why: "record contents were changed" });
        }
        prev_hash = r.hash.clone();
    }
    Ok(records.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chain(n: usize) -> Vec<AuditRecord> {
        let mut v: Vec<AuditRecord> = Vec::new();
        for i in 0..n {
            let r = next_record(v.last(), i as i64, "agent:a", "replay_send", &json!({"i": i}), "allow");
            v.push(r);
        }
        v
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
}
