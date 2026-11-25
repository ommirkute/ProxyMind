//! The audit log's security features (ADR-0022 step 2, threat model F-6): version 2 records with context, the keyed
//! chain, signed checkpoints, and the verification report that ties them together. The record format and its
//! canonical serialization are documented in `pm_policy::audit`; the checkpoint format in `pm_policy::checkpoint`.
//!
//! **Modes.** Single-user mode (the default) writes version 2 records with context `local` and no MAC, takes
//! checkpoints only on request and signs them with `<home>/audit-checkpoint-key.pk8` (0600, made on first use). The
//! server (ADR-0022 step 3 onward) calls [`Service::set_audit_security`] with the audit key derived from the server key,
//! a signing key kept in the server home, and an interval: the chain is then keyed and checkpointed every N records.
//! Until `pm-accounts` exists nothing in this repository turns that on except tests and the CLI's `--key-file`.
//!
//! **Where checkpoints live.** Every checkpoint is stored in the project's `audit_checkpoints` table (so verification
//! and evidence packs find them) and can be exported as a JSON file. The stored copy only helps against someone who does
//! not also rewrite that table; an exported copy kept elsewhere is what survives a writer of the file.
//!
//! **What this does not do in single-user mode.** The checkpoint key is a file the agent's OS user can read, so a same-user
//! attacker can sign a fresh checkpoint over a rebuilt log (threat model F-1). Single-user checkpoints protect against
//! accidents, other users and tools that cannot read the key, and against an attacker who has an exported copy they
//! cannot change; they do not turn the log into evidence against code running as you.

use std::path::Path;
use std::sync::Arc;

use pm_policy::Actor;
use pm_policy::audit::{self, AuditContext, AuditKey, Entry, KeyCheck, VerifyOptions};
use pm_policy::checkpoint::{self, Checkpoint};
use pm_store::{AuditRecord, Store};
use pm_tools::sign;
use serde::Serialize;
use serde_json::json;

use crate::access::Perm;
use crate::{Result, Service, ServiceError, now_ms};

/// The checkpoint signing key of single-user mode, in the home folder.
pub const CHECKPOINT_KEY_FILE: &str = "audit-checkpoint-key.pk8";

/// What the audit log does beyond the plain chain. The default (single-user mode) is none of it.
#[derive(Clone, Default)]
pub struct AuditSecurity {
    /// The key that MACs new records and checks old ones. `None`: the chain is not keyed.
    pub key: Option<Arc<dyn AuditKey>>,
    /// Verification fails when the log is not keyed (server mode).
    pub require_keyed: bool,
    /// PKCS#8 Ed25519 key that signs automatic checkpoints. `None`: the home folder's key is used on request.
    pub signing_key: Option<Arc<Vec<u8>>>,
    /// Write a checkpoint after every N records (needs `signing_key`).
    pub checkpoint_every: Option<u64>,
}

impl std::fmt::Debug for AuditSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditSecurity")
            .field("keyed", &self.key.is_some())
            .field("require_keyed", &self.require_keyed)
            .field("signing_key", &self.signing_key.is_some())
            .field("checkpoint_every", &self.checkpoint_every)
            .finish()
    }
}

/// What to check besides the plain chain.
#[derive(Clone, Default)]
pub struct AuditVerifyOptions {
    pub key: Option<Arc<dyn AuditKey>>,
    pub require_keyed: bool,
    /// Checkpoints from files, in addition to the ones stored in the project.
    pub checkpoints: Vec<Checkpoint>,
    /// The public key (raw bytes) that must have signed every checkpoint, when known.
    pub trusted_signer: Option<Vec<u8>>,
    /// Or: the fingerprint (hex, colons optional) every checkpoint's signer must have.
    pub pinned_fingerprint: Option<String>,
}

/// How the checkpoints fared.
#[derive(Debug, Clone, Default, Serialize, schemars::JsonSchema)]
pub struct AuditCheckpointStatus {
    /// `none` (no checkpoint to check), `ok` or `failed`.
    pub status: String,
    /// Checkpoints stored in the project, and checkpoints supplied from files.
    pub stored: usize,
    pub supplied: usize,
    /// The newest checkpoint's record count and time.
    pub latest_seq: Option<i64>,
    pub latest_ts_ms: Option<i64>,
    /// The newest checkpoint's signer.
    pub fingerprint: Option<String>,
    /// Whether the signer was tied to a known key (the home or server key, or a fingerprint you gave). When false the
    /// signatures only prove the checkpoint was not altered, not who made it.
    pub signer_pinned: bool,
    pub problems: Vec<String>,
}

/// The result of checking the audit log.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct AuditVerification {
    /// The chain, the key (when one applies) and the checkpoints all passed.
    pub intact: bool,
    pub records: usize,
    pub v1_records: usize,
    pub v2_records: usize,
    pub keyed_records: usize,
    /// Hex of the newest record's hash (note it: `proxymind audit verify --anchor` checks it later).
    pub head: String,
    /// `verified`, `skipped` (records are keyed, no key was given), `not_keyed` or `failed`.
    pub key_check: String,
    /// The key check in words.
    pub key_note: String,
    pub checkpoints: AuditCheckpointStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn normalize_fingerprint(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_ascii_lowercase()
}

/// Checks a project's audit log: the chain (versions 1 and 2), the keyed chain when a key applies, and the
/// checkpoints (stored and supplied). Never fails: a problem is the result.
pub fn verify_audit_report(store: &Store, opts: &AuditVerifyOptions) -> AuditVerification {
    let mut out = AuditVerification {
        intact: false,
        records: 0,
        v1_records: 0,
        v2_records: 0,
        keyed_records: 0,
        head: String::new(),
        key_check: "not_keyed".into(),
        key_note: String::new(),
        checkpoints: AuditCheckpointStatus { status: "none".into(), ..Default::default() },
        error: None,
    };
    let records = match store.audit_records() {
        Ok(r) => r,
        Err(e) => {
            out.error = Some(e.to_string());
            return out;
        }
    };
    out.records = records.len();
    let key = opts.key.as_deref();
    let chain = audit::verify_with(&records, VerifyOptions { key, require_keyed: opts.require_keyed });
    let mut problems: Vec<String> = Vec::new();
    match chain {
        Ok(v) => {
            out.v1_records = v.v1;
            out.v2_records = v.v2;
            out.keyed_records = v.keyed;
            out.head = v.head;
            let (kc, note) = match v.key_check {
                KeyCheck::Verified => ("verified", format!("all {} keyed records match the audit key", v.keyed)),
                KeyCheck::Skipped => (
                    "skipped",
                    format!(
                        "{} records are keyed but no audit key was given: only the plain hash chain was checked, so a rebuilt chain would not be noticed",
                        v.keyed
                    ),
                ),
                KeyCheck::NotKeyed => (
                    "not_keyed",
                    "no record is keyed (single-user mode): anyone who can write the file can rebuild the chain; checkpoints and a saved head hash are what detect that".to_string(),
                ),
            };
            out.key_check = kc.into();
            out.key_note = note;
        }
        Err(e) => {
            // Was it the key, or the chain itself?
            let plain = audit::verify_with(&records, VerifyOptions::default());
            match plain {
                Ok(v) if key.is_some() || opts.require_keyed => {
                    out.v1_records = v.v1;
                    out.v2_records = v.v2;
                    out.keyed_records = v.keyed;
                    out.head = v.head;
                    out.key_check = "failed".into();
                    out.key_note = e.to_string();
                }
                _ => {
                    out.key_check = "not_checked".into();
                    out.key_note = "the chain itself is broken".into();
                }
            }
            problems.push(e.to_string());
        }
    }
    let chain_ok = problems.is_empty();

    // Checkpoints: only worth comparing with a log whose chain holds.
    let project_id = store.get_setting("project_id").ok().flatten().filter(|s| !s.is_empty());
    let mut all: Vec<(Checkpoint, bool)> = Vec::new();
    let stored = store.audit_checkpoints().unwrap_or_default();
    out.checkpoints.stored = stored.len();
    for (seq, _, body) in &stored {
        match serde_json::from_str::<Checkpoint>(body) {
            Ok(cp) => all.push((cp, false)),
            Err(_) => problems.push(format!("the stored checkpoint at record {seq} is unreadable")),
        }
    }
    out.checkpoints.supplied = opts.checkpoints.len();
    all.extend(opts.checkpoints.iter().cloned().map(|c| (c, true)));
    let pinned_fp = opts.pinned_fingerprint.as_deref().map(normalize_fingerprint);
    out.checkpoints.signer_pinned = opts.trusted_signer.is_some() || pinned_fp.is_some();
    let mut cp_problems = Vec::new();
    for (cp, _) in &all {
        let mut res = checkpoint::check(cp, &records, opts.trusted_signer.as_deref(), project_id.as_deref());
        if res.is_ok()
            && let Some(want) = &pinned_fp
            && !normalize_fingerprint(&cp.fingerprint()).starts_with(want)
        {
            res = Err(pm_policy::PolicyError::Checkpoint(format!(
                "checkpoint at record {} was signed by an unexpected key ({})",
                cp.seq,
                cp.fingerprint()
            )));
        }
        if let Err(e) = res {
            cp_problems.push(e.to_string());
        }
    }
    if let Some((cp, _)) = all.iter().max_by_key(|(c, _)| (c.seq, c.ts_ms)) {
        out.checkpoints.latest_seq = Some(cp.seq);
        out.checkpoints.latest_ts_ms = Some(cp.ts_ms);
        out.checkpoints.fingerprint = Some(cp.fingerprint());
    }
    if !all.is_empty() {
        out.checkpoints.status = if cp_problems.is_empty() { "ok" } else { "failed" }.into();
    }
    problems.extend(cp_problems.iter().cloned());
    out.checkpoints.problems = cp_problems;

    out.intact = chain_ok && problems.is_empty();
    if !problems.is_empty() {
        out.error = Some(problems.join("; "));
    }
    out
}

/// The public key of the single-user checkpoint signing key in `home`, if one was made.
pub fn checkpoint_signer_public(home: &Path) -> Option<Vec<u8>> {
    let k = std::fs::read(home.join(CHECKPOINT_KEY_FILE)).ok()?;
    sign::public_key(&k).ok()
}

fn write_private_file(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| ServiceError::Invalid(e.to_string()))?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        f.write_all(data).map_err(|e| ServiceError::Invalid(e.to_string()))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| ServiceError::Invalid(e.to_string()))
}

impl Service {
    /// Turns on the server-mode features: the keyed chain, signed automatic checkpoints. Call once, before the first
    /// request is served. Single-user mode never calls it.
    pub fn set_audit_security(&self, security: AuditSecurity) {
        *self.audit_security.write() = security;
    }

    /// The key and checkpoint settings now in force.
    pub fn audit_security(&self) -> AuditSecurity {
        self.audit_security.read().clone()
    }

    /// Writes one audit record with `ctx` (who and where). `audit` is this with the single-user context.
    pub(crate) fn audit_with(
        &self,
        ctx: Option<&AuditContext>,
        actor: &str,
        action: &str,
        detail: serde_json::Value,
        decision: &str,
    ) -> Result<()> {
        let sec = self.audit_security.read().clone();
        // No context given: the request in scope (set by the API around a handler) or what the server registered for
        // this actor; in single-user mode `local`.
        let derived = if ctx.is_none() { self.audit_context_of(actor) } else { None };
        let ctx = ctx.or(derived.as_ref());
        // One write closure: the read of the last record and the append must not interleave with another audit.
        // Published after the write returned, i.e. after COMMIT.
        let seq = self.store.write(|store| {
            let prev = store.last_audit()?;
            let mut ctx = ctx.cloned().unwrap_or_else(|| AuditContext::local(None));
            if ctx.project_id.is_none() {
                ctx.project_id = store.get_setting("project_id")?.filter(|s| !s.is_empty());
            }
            let entry = Entry { actor, action, detail: &detail, decision };
            let rec = audit::next_record_v2(prev.as_ref(), now_ms(), &entry, &ctx, sec.key.as_deref());
            store.append_audit(&rec)?;
            if let (Some(sk), Some(every)) = (&sec.signing_key, sec.checkpoint_every)
                && every > 0
                && (rec.seq as u64).is_multiple_of(every)
                && let Err(e) = store_checkpoint(store, sk, &rec, ctx.project_id.as_deref())
            {
                // The record is written; a missed checkpoint must not lose it.
                tracing::warn!("audit checkpoint not written: {e}");
            }
            Ok::<u64, anyhow::Error>(rec.seq as u64)
        })?;
        self.publish(crate::events::Event::AuditAppended { seq });
        Ok(())
    }

    /// Writes one audit record for `principal`: the actor is `kind:name` as always and the record also names the
    /// account, token, session and address the principal carries (version 2). Single-user callers have none of
    /// those, so their records say `local`.
    pub fn audit_principal(
        &self,
        principal: &crate::access::Principal,
        action: &str,
        detail: serde_json::Value,
        decision: &str,
    ) -> Result<()> {
        self.audit_with(Some(&principal.audit_context()), &principal.actor.id(), action, detail, decision)
    }

    /// The Ed25519 key that signs checkpoints: the server's (when set), else the home folder's, made on first use
    /// when `create` is true.
    fn checkpoint_signing_key(&self, create: bool) -> Result<Vec<u8>> {
        if let Some(k) = self.audit_security.read().signing_key.clone() {
            return Ok(k.as_ref().clone());
        }
        let home = self.plugin_home.get().ok_or_else(|| {
            ServiceError::Invalid("no ProxyMind home directory in this process to keep the checkpoint key in".into())
        })?;
        let path = home.join(CHECKPOINT_KEY_FILE);
        if let Ok(k) = std::fs::read(&path) {
            return Ok(k);
        }
        if !create {
            return Err(ServiceError::NotFound("no checkpoint signing key yet".into()));
        }
        let k = sign::generate().map_err(ServiceError::Invalid)?;
        write_private_file(&path, &k)?;
        Ok(k)
    }

    /// The public key checkpoints must be signed with, when this process knows it.
    fn checkpoint_trusted_signer(&self) -> Option<Vec<u8>> {
        self.checkpoint_signing_key(false).ok().and_then(|k| sign::public_key(&k).ok())
    }

    /// Writes a signed checkpoint of the audit log as it is now, stores it in the project and returns it (export it
    /// with `serde_json` and keep the file somewhere the log's writers cannot reach). People only.
    pub fn audit_checkpoint(&self, actor: &Actor) -> Result<Checkpoint> {
        self.require_actor(actor, Perm::ExportEvidence)?;
        let key = self.checkpoint_signing_key(true)?;
        // Audit first, so the checkpoint covers this request too.
        self.audit(&actor.id(), "audit_checkpoint", json!({}), "ok")?;
        let cp = self.store.write(|store| -> anyhow::Result<Checkpoint> {
            let last = store.last_audit()?.ok_or_else(|| anyhow::anyhow!("the audit log is empty"))?;
            let project_id = store.get_setting("project_id")?.filter(|s| !s.is_empty());
            store_checkpoint(store, &key, &last, project_id.as_deref())
        })?;
        Ok(cp)
    }

    /// The checkpoints stored in the project, oldest first.
    pub fn audit_checkpoints(&self) -> Result<Vec<Checkpoint>> {
        let rows = self.store.read(|db| db.audit_checkpoints())?;
        Ok(rows.iter().filter_map(|(_, _, body)| serde_json::from_str(body).ok()).collect())
    }

    /// Checks the audit log with this process's key and checkpoint settings. `extra` are checkpoints from files;
    /// `pinned_fingerprint` is a signer the person trusts.
    pub fn audit_verify_report(&self, extra: Vec<Checkpoint>, pinned_fingerprint: Option<String>) -> AuditVerification {
        let sec = self.audit_security();
        let opts = AuditVerifyOptions {
            key: sec.key,
            require_keyed: sec.require_keyed,
            checkpoints: extra,
            trusted_signer: self.checkpoint_trusted_signer(),
            pinned_fingerprint,
        };
        self.store.read(|db| verify_audit_report(db, &opts))
    }

    /// The newest stored checkpoint's JSON, for evidence packs.
    pub(crate) fn latest_checkpoint_json(&self) -> Result<Option<(Checkpoint, String)>> {
        let rows = self.store.read(|db| db.audit_checkpoints())?;
        Ok(rows.iter().rev().find_map(|(_, _, body)| {
            let cp: Checkpoint = serde_json::from_str(body).ok()?;
            Some((cp, body.clone()))
        }))
    }
}

/// Signs and stores a checkpoint of `rec` (the newest record).
fn store_checkpoint(
    store: &mut Store,
    signing_key: &[u8],
    rec: &AuditRecord,
    project_id: Option<&str>,
) -> anyhow::Result<Checkpoint> {
    let cp = Checkpoint::create(signing_key, rec.seq, &rec.hash, now_ms(), project_id)?;
    store.append_audit_checkpoint(cp.seq, cp.ts_ms, &serde_json::to_string(&cp)?)?;
    Ok(cp)
}
