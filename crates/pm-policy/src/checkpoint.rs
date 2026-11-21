//! Signed checkpoints of the audit chain (ADR-0022 step 2, threat model F-6).
//!
//! A checkpoint says "at `ts_ms`, the log had `seq` records and the newest one's hash was `head`", signed with an
//! Ed25519 key (the same primitives as evidence packs, `pm_tools::sign`). Because the signing key is not the one that
//! writes the log, someone who can only write the project file can neither forge a checkpoint nor erase the proof that
//! records existed:
//!
//! * **Tail truncation:** records removed from the end leave a log shorter than the checkpoint's `seq`.
//! * **Rewriting:** a chain rebuilt from some earlier point has a different hash at the checkpoint's `seq`.
//! * **Forgery:** a checkpoint made with another key fails the signature, or (when the caller pins the signer's key)
//!   names the wrong key.
//!
//! A checkpoint only protects what existed when it was made, and only where its copy survives: one stored in the
//! project file can be deleted by whoever can edit the file, so the protection is an *exported* copy (a file kept
//! elsewhere, an evidence pack, a ticket). It also proves nothing about records added after it.
//!
//! # Signed message
//!
//! ```text
//! proxymind-audit-checkpoint-1\n
//! seq=<decimal>\n
//! head=<lower-case hex of the record hash>\n
//! ts_ms=<decimal>\n
//! project=<project id, or empty>\n
//! ```

use pm_store::AuditRecord;
use pm_tools::sign;
use serde::{Deserialize, Serialize};

use crate::PolicyError;
use crate::audit::hex;

pub const FORMAT: &str = "proxymind-audit-checkpoint-1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Checkpoint {
    pub format: String,
    /// How many records the log had (the newest one's sequence number).
    pub seq: i64,
    /// Hex of the newest record's hash.
    pub head: String,
    pub ts_ms: i64,
    /// The project the log belongs to (setting `project_id`), so a checkpoint cannot be moved to another project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Hex of the Ed25519 public key that signed it.
    pub public_key: String,
    /// Hex of the signature over [`Checkpoint::message`].
    pub signature: String,
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| s.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect()
}

impl Checkpoint {
    /// The bytes that are signed.
    pub fn message(&self) -> Vec<u8> {
        format!(
            "{FORMAT}\nseq={}\nhead={}\nts_ms={}\nproject={}\n",
            self.seq,
            self.head,
            self.ts_ms,
            self.project_id.as_deref().unwrap_or("")
        )
        .into_bytes()
    }

    /// Signs a checkpoint of a log whose newest record has hash `head` and sequence number `seq`.
    pub fn create(
        pkcs8: &[u8],
        seq: i64,
        head: &[u8],
        ts_ms: i64,
        project_id: Option<&str>,
    ) -> Result<Self, PolicyError> {
        if seq < 1 {
            return Err(PolicyError::Checkpoint("the log is empty: nothing to checkpoint".into()));
        }
        let public = sign::public_key(pkcs8).map_err(PolicyError::Checkpoint)?;
        let mut cp = Self {
            format: FORMAT.into(),
            seq,
            head: hex(head),
            ts_ms,
            project_id: project_id.map(str::to_string),
            public_key: hex(&public),
            signature: String::new(),
        };
        cp.signature = hex(&sign::sign(pkcs8, &cp.message()).map_err(PolicyError::Checkpoint)?);
        Ok(cp)
    }

    /// Whether the signature matches the key the checkpoint carries (says nothing about whose key that is).
    pub fn signature_valid(&self) -> bool {
        match (unhex(&self.public_key), unhex(&self.signature)) {
            (Some(k), Some(s)) => self.format == FORMAT && sign::verify(&k, &self.message(), &s),
            _ => false,
        }
    }

    /// The signer's key fingerprint (groups of four hex digits), empty if the key is not valid hex.
    pub fn fingerprint(&self) -> String {
        unhex(&self.public_key).map(|k| sign::fingerprint(&k)).unwrap_or_default()
    }

    /// Reads one checkpoint, or a JSON array of them.
    pub fn parse_many(text: &str) -> Result<Vec<Checkpoint>, PolicyError> {
        let text = text.trim();
        let bad = |e: serde_json::Error| PolicyError::Checkpoint(format!("not a checkpoint file: {e}"));
        if text.starts_with('[') {
            serde_json::from_str(text).map_err(bad)
        } else {
            serde_json::from_str(text).map(|c| vec![c]).map_err(bad)
        }
    }
}

/// Checks one checkpoint against the log as it is now.
///
/// * `trusted_key`: the signer's public key when the caller knows it (the key kept in the home folder or on the
///   server, or one the person pinned by fingerprint); a checkpoint signed by another key is refused. With `None`,
///   only "signed by the key it carries" is established.
/// * `project_id`: this project's id; a checkpoint that names another project is refused.
///
/// The log should already have passed [`crate::audit::verify`]; this compares the checkpoint with it.
pub fn check(
    cp: &Checkpoint,
    records: &[AuditRecord],
    trusted_key: Option<&[u8]>,
    project_id: Option<&str>,
) -> Result<(), PolicyError> {
    let fail = |m: String| Err(PolicyError::Checkpoint(m));
    if !cp.signature_valid() {
        return fail(format!("checkpoint at record {} has an invalid signature (forged or altered)", cp.seq));
    }
    if let Some(t) = trusted_key
        && unhex(&cp.public_key).as_deref() != Some(t)
    {
        return fail(format!("checkpoint at record {} was signed by an unexpected key ({})", cp.seq, cp.fingerprint()));
    }
    if let (Some(a), Some(b)) = (cp.project_id.as_deref(), project_id)
        && a != b
    {
        return fail(format!("checkpoint at record {} belongs to another project", cp.seq));
    }
    let n = records.len() as i64;
    if cp.seq < 1 || n < cp.seq {
        return fail(format!(
            "records were removed from the end: the log has {n} records but a signed checkpoint vouches for {}",
            cp.seq
        ));
    }
    let at = &records[(cp.seq - 1) as usize];
    if hex(&at.hash) != cp.head {
        return fail(format!("the log was rewritten: record {} no longer matches its signed checkpoint", cp.seq));
    }
    Ok(())
}
