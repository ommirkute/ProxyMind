//! Verifiable evidence: a signed pack a client can check without trusting
//! the tester's word, and a coverage proof of what was and wasn't tested.
//!
//! The pack is a plain ZIP: the report, the exact request and response
//! bytes behind each finding, the proofs, the hash-chained audit log, the
//! rules of engagement and the coverage proof, plus `manifest.json` (every
//! file's SHA-256, every recorded exchange's metadata) signed with the
//! installation's Ed25519 key. `verify_evidence` checks the signature, every
//! file's hash, the audit chain, that every request ProxyMind's own tools
//! sent was inside the scope, and that each finding's evidence is in the
//! pack. What it proves: the pack wasn't changed after it was signed, and it
//! is consistent with itself. It can't prove the signer was honest; the
//! fingerprint tells the client whose key signed it.

use std::collections::{BTreeMap, BTreeSet};

use pm_policy::{Actor, ActorKind, Policy, Roe, Target};
use pm_tools::{sign, zip};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::findings::issue_key;
use crate::{Result, Service, ServiceError};

pub const PACK_FORMAT: &str = "proxymind-evidence-1";
const KEY_FILE: &str = "evidence-key.pk8";
/// Most exchanges listed in a manifest, and most included in full.
const MAX_LISTED: usize = 200_000;
const MAX_INCLUDED: usize = 5_000;

// ---------- coverage proof ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageCellProof {
    pub operation: String,
    pub vuln_class: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub param: String,
    /// vulnerable, tested, open (a hypothesis being worked on), untested
    pub status: String,
    /// Who tested it (people, agents, the scanner).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub by: Vec<String>,
    /// How: "scan_active: sql_error, sql_boolean", "authz_check", "proof_timing", "hypothesis #3 refuted"…
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub how: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageProof {
    pub operations: usize,
    pub cells: Vec<CoverageCellProof>,
    /// vulnerable / tested / open / untested counts.
    pub totals: BTreeMap<String, usize>,
    /// Share of cells tested (vulnerable or tested).
    pub percent_tested: f64,
}

/// Whether a request path fits an operation's template (`{x}` matches one segment).
fn path_fits(template: &str, path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let t: Vec<&str> = template.trim_end_matches('/').split('/').collect();
    let p: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    t.len() == p.len() && t.iter().zip(&p).all(|(a, b)| a == b || (a.starts_with('{') && a.ends_with('}')))
}

/// Same scheme, host and port.
fn same_origin(a: &str, b: &str) -> bool {
    match (url::Url::parse(a), url::Url::parse(b)) {
        (Ok(a), Ok(b)) => {
            a.scheme() == b.scheme()
                && a.host_str().map(str::to_ascii_lowercase) == b.host_str().map(str::to_ascii_lowercase)
                && a.port_or_known_default() == b.port_or_known_default()
        }
        _ => false,
    }
}

/// The vulnerability classes a gated action tests, by its audit record.
fn classes_tested(action: &str, detail: &Value, all_active: &BTreeSet<String>) -> (BTreeSet<String>, String) {
    let set = |v: &[&str]| v.iter().map(|c| issue_key(c)).collect::<BTreeSet<_>>();
    match action {
        "scan_active" => {
            let checks: Vec<String> = detail["params"]["extra"]["active_scan"]["checks"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect();
            let recorded = detail["params"]["extra"]["active_scan"].is_object();
            if checks.is_empty() && recorded {
                (all_active.clone(), "scan_active (all checks)".into())
            } else if checks.is_empty() {
                // The record doesn't say which checks ran: claim nothing.
                (BTreeSet::new(), String::new())
            } else {
                let how = format!("scan_active: {}", checks.join(", "));
                (checks.iter().map(|c| issue_key(c)).collect(), how)
            }
        }
        "authz_check" | "proof_run" => (set(&["idor", "bfla"]), action.to_string()),
        "proof_timing" => (set(&["sqli", "command_injection"]), action.to_string()),
        "proof_oast" => (set(&["ssrf"]), action.to_string()),
        "proof_reflection" => (set(&["xss"]), action.to_string()),
        _ => (BTreeSet::new(), String::new()),
    }
}

impl Service {
    /// What was tested, by whom and how, for every operation × relevant
    /// vulnerability class: from the scanner's runs, authorization checks
    /// and proofs (in the audit log), findings, and hypotheses.
    pub fn coverage_proof(&self) -> Result<CoverageProof> {
        let model = self.model()?;
        let base = self.coverage(false)?;
        let hyps = self.hypothesis_list(None)?;
        let findings: Vec<Value> =
            self.finding_list(None)?.into_iter().filter(|f| f["status"] != "false_positive").collect();
        let records = self.store.lock().audit_records()?;
        let all_active: BTreeSet<String> =
            pm_scan::active::CHECKS.iter().chain(pm_scan::oob::CHECKS).map(|c| issue_key(c)).collect();
        // What each allowed, targeted action tested: (origin+path, classes, how, actor).
        let tests: Vec<(String, BTreeSet<String>, String, String)> = records
            .iter()
            .filter(|r| r.decision == "allow")
            .filter_map(|r| {
                let d: Value = serde_json::from_str(&r.detail).ok()?;
                let target = d["target"].as_str()?.to_string();
                let (classes, how) = classes_tested(&r.action, &d, &all_active);
                (!classes.is_empty()).then(|| (target, classes, how, r.actor.clone()))
            })
            .collect();
        let mut cells = Vec::new();
        for c in &base.cells {
            let Some(op) = model.operations.iter().find(|o| o.key == c.operation) else { continue };
            let class = issue_key(&c.vuln_class);
            let fits = |url: &str| {
                url::Url::parse(url).is_ok_and(|u| path_fits(&op.template, u.path())) && same_origin(url, &op.origin)
            };
            let mut by = BTreeSet::new();
            let mut how = BTreeSet::new();
            for (target, classes, h, actor) in &tests {
                if classes.contains(&class) && fits(target) {
                    by.insert(actor.clone());
                    how.insert(h.clone());
                }
            }
            for h in hyps.iter().filter(|h| h.operation == c.operation && issue_key(&h.vuln_class) == class) {
                if matches!(h.status.as_str(), "confirmed" | "refuted") {
                    by.insert(h.actor.clone());
                    how.insert(format!("hypothesis #{} {}", h.id, h.status));
                }
            }
            let found: Vec<i64> = findings
                .iter()
                .filter(|f| issue_key(f["vuln_class"].as_str().unwrap_or("")) == class)
                .filter(|f| fits(f["url"].as_str().unwrap_or("")))
                .filter_map(|f| f["id"].as_i64())
                .collect();
            for f in findings.iter().filter(|f| found.contains(&f["id"].as_i64().unwrap_or(-1))) {
                by.insert(f["actor"].as_str().unwrap_or_default().to_string());
            }
            let status = if !found.is_empty() {
                "vulnerable"
            } else if !how.is_empty() {
                "tested"
            } else if matches!(c.status.as_str(), "open" | "testing") {
                "open"
            } else {
                "untested"
            };
            cells.push(CoverageCellProof {
                operation: c.operation.clone(),
                vuln_class: c.vuln_class.clone(),
                param: c.param.clone(),
                status: status.into(),
                by: by.into_iter().filter(|b| !b.is_empty()).collect(),
                how: how.into_iter().collect(),
                findings: found,
            });
        }
        let mut totals: BTreeMap<String, usize> =
            ["vulnerable", "tested", "open", "untested"].iter().map(|k| (k.to_string(), 0)).collect();
        for c in &cells {
            *totals.entry(c.status.clone()).or_default() += 1;
        }
        let done = totals["vulnerable"] + totals["tested"];
        let percent_tested =
            if cells.is_empty() { 0.0 } else { (done as f64 * 1000.0 / cells.len() as f64).round() / 10.0 };
        // Untested first, then open, tested, vulnerable.
        let rank = |s: &str| ["untested", "open", "tested", "vulnerable"].iter().position(|x| *x == s).unwrap_or(9);
        cells.sort_by(|a, b| rank(&a.status).cmp(&rank(&b.status)).then(a.operation.cmp(&b.operation)));
        Ok(CoverageProof { operations: model.operations.len(), cells, totals, percent_tested })
    }

    // ---------- evidence pack ----------

    fn evidence_key(&self) -> Result<Vec<u8>> {
        let home = self.plugin_home.get().ok_or_else(|| {
            ServiceError::Invalid("no ProxyMind home directory in this process to keep the signing key in".into())
        })?;
        let path = home.join(KEY_FILE);
        if let Ok(k) = std::fs::read(&path) {
            return Ok(k);
        }
        let k = sign::generate().map_err(ServiceError::Invalid)?;
        std::fs::create_dir_all(home).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp).map_err(|e| ServiceError::Invalid(e.to_string()))?;
            f.write_all(&k).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        Ok(k)
    }

    /// The fingerprint of the key that signs this installation's packs (give
    /// it to clients through another channel so they can check a pack's signer).
    pub fn evidence_fingerprint(&self) -> Result<String> {
        let k = self.evidence_key()?;
        Ok(sign::fingerprint(&sign::public_key(&k).map_err(ServiceError::Invalid)?))
    }

    /// Builds a signed evidence pack (ZIP bytes). People only. `all_in_scope`
    /// also includes the bytes of every in-scope exchange (up to 5000), not
    /// only those behind findings, proofs and attack paths.
    pub fn evidence_pack(&self, actor: &Actor, all_in_scope: bool) -> Result<(Vec<u8>, String)> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only people export evidence".into()));
        }
        let key = self.evidence_key()?;
        let public = sign::public_key(&key).map_err(ServiceError::Invalid)?;
        let roe = self.policy.roe();
        let roe_text = match self.roe_get()?.text {
            Some(t) if !t.trim().is_empty() => t,
            _ => {
                let list = |v: &[pm_policy::UrlPattern]| {
                    v.iter().map(|p| format!("{:?}", p.text)).collect::<Vec<_>>().join(", ")
                };
                format!(
                    "version: 1\nscope:\n  include: [{}]\n  exclude: [{}]\n",
                    list(&roe.include),
                    list(&roe.exclude)
                )
            }
        };
        let findings = self.finding_list(None)?;
        let mut files: Vec<(String, Vec<u8>)> = Vec::new();

        // Which exchanges go in whole: evidence, proofs, attack paths.
        let mut wanted: BTreeSet<i64> = BTreeSet::new();
        for f in &findings {
            for e in f["evidence"].as_array().into_iter().flatten().filter_map(Value::as_i64) {
                wanted.insert(e);
            }
            let id = f["id"].as_i64().unwrap_or(0);
            for p in self.proofs_for_finding(id)? {
                for e in p["exchange_ids"].as_array().into_iter().flatten().filter_map(Value::as_i64) {
                    wanted.insert(e);
                }
            }
        }
        for p in self.attack_path_list(None)? {
            wanted.extend(p.steps.iter().filter_map(|s| s.exchange_id));
        }
        let listed = self.store.lock().list_exchanges(MAX_LISTED, None)?;
        if all_in_scope {
            for s in &listed {
                if wanted.len() >= MAX_INCLUDED {
                    break;
                }
                let url = pm_core::url(&s.scheme, &s.host, s.port, &s.path);
                if Target::from_url(&url).is_ok_and(|t| self.policy.scope_check(&t).is_ok()) {
                    wanted.insert(s.id);
                }
            }
        }
        let mut exchanges = Vec::new();
        for s in listed.iter().rev() {
            let url = pm_core::url(&s.scheme, &s.host, s.port, &s.path);
            let mut e = json!({ "id": s.id, "ts_ms": s.ts_ms, "source": s.source, "actor": s.actor_id,
                                "method": s.method, "url": url, "status": s.status });
            if wanted.contains(&s.id)
                && let Some(ex) = self.store.lock().get_exchange(s.id)?
            {
                let req = format!("exchanges/{}.request.http", s.id);
                files.push((req.clone(), ex.request));
                e["request"] = json!(req);
                if let Some(r) = ex.response {
                    let resp = format!("exchanges/{}.response.http", s.id);
                    files.push((resp.clone(), r));
                    e["response"] = json!(resp);
                }
            }
            exchanges.push(e);
        }

        let records = self.store.lock().audit_records()?;
        let audit_lines: Vec<String> = records.iter().map(|r| serde_json::to_string(r).unwrap_or_default()).collect();
        let head = records.last().map(|r| r.hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
        let coverage = self.coverage_proof()?;
        let mut proofs = Vec::new();
        for f in &findings {
            proofs.extend(self.proofs_for_finding(f["id"].as_i64().unwrap_or(0))?);
        }
        let report_md = self.report_markdown()?;
        files.push(("report.html".into(), self.report_html()?.into_bytes()));
        files.push(("report.md".into(), report_md.into_bytes()));
        files.push(("findings.json".into(), serde_json::to_vec_pretty(&findings).unwrap_or_default()));
        files.push(("proofs.json".into(), serde_json::to_vec_pretty(&proofs).unwrap_or_default()));
        files.push((
            "attack_paths.json".into(),
            serde_json::to_vec_pretty(&self.attack_path_list(None)?).unwrap_or_default(),
        ));
        files.push(("coverage.json".into(), serde_json::to_vec_pretty(&coverage).unwrap_or_default()));
        files.push(("audit.jsonl".into(), (audit_lines.join("\n") + "\n").into_bytes()));
        files.push(("roe.yaml".into(), roe_text.into_bytes()));
        let fp = sign::fingerprint(&public);
        files.push((
            "README.txt".into(),
            format!(
                "ProxyMind evidence pack\n\nOpen report.html for the report. To check this pack:\n\n    proxymind verify <this file>\n\n\
                 or Settings > Verify evidence in ProxyMind. It checks the signature, every file's SHA-256, the audit\n\
                 log's hash chain, that every request ProxyMind's tools sent was inside roe.yaml, and that each\n\
                 finding's evidence is included. Signed by key {fp}: compare it with the fingerprint the tester gave you.\n"
            )
            .into_bytes(),
        ));

        let hashes: BTreeMap<&str, String> = files.iter().map(|(n, d)| (n.as_str(), sign::sha256_hex(d))).collect();
        let manifest = json!({
            "format": PACK_FORMAT,
            "created_ms": pm_core::now_ms(),
            "proxymind": env!("CARGO_PKG_VERSION"),
            "created_by": actor.id(),
            "engagement": { "name": roe.engagement.name, "client": roe.engagement.client },
            "files": hashes,
            "exchanges": exchanges,
            "audit": { "records": records.len(), "head": head },
            "findings": findings.len(),
            "coverage": { "percent_tested": coverage.percent_tested, "totals": coverage.totals },
            "public_key": public.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "fingerprint": fp,
        });
        let manifest = serde_json::to_vec_pretty(&manifest).unwrap_or_default();
        let sig = sign::sign(&key, &manifest).map_err(ServiceError::Invalid)?;
        let mut all = vec![("manifest.json".to_string(), manifest), ("manifest.sig".to_string(), sig)];
        all.extend(files);
        let bytes = zip::write(&all).map_err(ServiceError::Invalid)?;
        self.audit(
            &actor.id(),
            "evidence_export",
            json!({ "files": all.len(), "bytes": bytes.len(), "sha256": sign::sha256_hex(&bytes), "fingerprint": fp }),
            "ok",
        )?;
        Ok((bytes, fp))
    }
}

// ---------- verification ----------

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceVerification {
    /// Every check passed.
    pub ok: bool,
    /// Fingerprint of the key that signed the pack (compare it with the tester's).
    pub fingerprint: Option<String>,
    pub engagement: Value,
    pub checks: Vec<Check>,
    pub findings: usize,
    pub exchanges: usize,
    pub coverage: Value,
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Checks an evidence pack. Never panics on hostile input.
pub fn verify_evidence(bytes: &[u8]) -> EvidenceVerification {
    let mut v = EvidenceVerification {
        ok: false,
        fingerprint: None,
        engagement: Value::Null,
        checks: vec![],
        findings: 0,
        exchanges: 0,
        coverage: Value::Null,
    };
    let check = |v: &mut EvidenceVerification, name: &str, ok: bool, detail: String| {
        v.checks.push(Check { name: name.into(), ok, detail });
    };
    let entries = match zip::read(bytes) {
        Ok(e) => e,
        Err(e) => {
            check(&mut v, "archive", false, e);
            return v;
        }
    };
    let files: BTreeMap<&str, &[u8]> = entries.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect();
    let (Some(manifest_bytes), Some(sig)) = (files.get("manifest.json"), files.get("manifest.sig")) else {
        check(&mut v, "archive", false, "manifest.json or manifest.sig is missing".into());
        return v;
    };
    let manifest: Value = match serde_json::from_slice(manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            check(&mut v, "archive", false, format!("manifest.json isn't valid JSON: {e}"));
            return v;
        }
    };
    if manifest["format"] != PACK_FORMAT {
        check(&mut v, "archive", false, format!("unknown format {}", manifest["format"]));
        return v;
    }
    check(&mut v, "archive", true, format!("{} files", entries.len()));
    v.engagement = manifest["engagement"].clone();
    v.coverage = manifest["coverage"].clone();
    v.findings = manifest["findings"].as_u64().unwrap_or(0) as usize;

    // 1. Signature.
    let public = manifest["public_key"].as_str().and_then(hex_decode).unwrap_or_default();
    let signed = !public.is_empty() && sign::verify(&public, manifest_bytes, sig);
    if !public.is_empty() {
        v.fingerprint = Some(sign::fingerprint(&public));
    }
    let fp = v.fingerprint.clone().unwrap_or_default();
    check(
        &mut v,
        "signature",
        signed,
        if signed {
            format!("signed by key {fp}")
        } else {
            "the manifest's signature doesn't match: it was changed after signing".into()
        },
    );

    // 2. Every file listed, with the right hash; nothing extra.
    let listed: BTreeMap<String, String> = manifest["files"]
        .as_object()
        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect())
        .unwrap_or_default();
    let mut problems = Vec::new();
    for (name, hash) in &listed {
        match files.get(name.as_str()) {
            None => problems.push(format!("{name} is missing")),
            Some(d) if sign::sha256_hex(d) != *hash => problems.push(format!("{name} was changed")),
            _ => {}
        }
    }
    for name in files.keys() {
        if !matches!(*name, "manifest.json" | "manifest.sig") && !listed.contains_key(*name) {
            problems.push(format!("{name} isn't in the manifest"));
        }
    }
    check(
        &mut v,
        "files",
        problems.is_empty(),
        if problems.is_empty() { format!("{} files match their hashes", listed.len()) } else { problems.join("; ") },
    );

    // 3. Audit chain.
    let audit_text = files.get("audit.jsonl").map(|d| String::from_utf8_lossy(d).into_owned()).unwrap_or_default();
    let records: std::result::Result<Vec<pm_store::AuditRecord>, String> = audit_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<pm_store::AuditRecord>(l).map_err(|e| e.to_string()))
        .collect();
    let records = records.unwrap_or_default();
    match pm_policy::audit::verify(&records) {
        Ok(n) => {
            let head = records.last().map(|r| r.hash.iter().map(|b| format!("{b:02x}")).collect::<String>());
            let same = manifest["audit"]["head"].as_str().map(str::to_string) == head
                && manifest["audit"]["records"].as_u64() == Some(n as u64);
            check(
                &mut v,
                "audit log",
                same && n > 0,
                if same && n > 0 {
                    format!("{n} records, hash chain intact")
                } else if n == 0 {
                    "the audit log is empty or unreadable".into()
                } else {
                    "the audit log doesn't match the manifest".into()
                },
            );
        }
        Err(e) => check(&mut v, "audit log", false, e.to_string()),
    }

    // 4. Scope: every allowed action and every request ProxyMind's tools sent.
    let roe = files.get("roe.yaml").map(|d| String::from_utf8_lossy(d).into_owned()).unwrap_or_default();
    let exchanges = manifest["exchanges"].as_array().cloned().unwrap_or_default();
    v.exchanges = exchanges.len();
    match Roe::parse(&roe) {
        Err(e) => check(&mut v, "scope", false, format!("roe.yaml can't be read: {e}")),
        Ok(roe) => {
            let policy = Policy::new(roe);
            let in_scope = |url: &str| Target::from_url(url).is_ok_and(|t| policy.scope_check(&t).is_ok());
            let mut outside: Vec<String> = exchanges
                .iter()
                .filter(|e| e["source"].as_str().is_some_and(|s| s != "proxy" && s != "import"))
                .filter_map(|e| e["url"].as_str())
                .filter(|u| !in_scope(u))
                .map(str::to_string)
                .collect();
            for r in records.iter().filter(|r| r.decision == "allow") {
                if let Ok(d) = serde_json::from_str::<Value>(&r.detail)
                    && let Some(t) = d["target"].as_str()
                    && !in_scope(t)
                {
                    outside.push(format!("{t} ({})", r.action));
                }
            }
            outside.sort();
            outside.dedup();
            let changed = records.iter().filter(|r| r.action == "roe_change").count();
            let browsed = exchanges
                .iter()
                .filter(|e| e["source"] == "proxy")
                .filter(|e| e["url"].as_str().is_some_and(|u| !in_scope(u)))
                .count();
            let note = if browsed > 0 {
                format!(
                    " ({browsed} out-of-scope requests came from the tester's browser through the proxy, not from ProxyMind's tools)"
                )
            } else {
                String::new()
            };
            check(
                &mut v,
                "scope",
                outside.is_empty(),
                if outside.is_empty() {
                    format!("every request ProxyMind's tools sent was inside roe.yaml{note}")
                } else {
                    let first: Vec<String> = outside.iter().take(5).cloned().collect();
                    let roe_note = if changed > 0 {
                        format!(
                            " The rules changed {changed} time(s) during the engagement; earlier requests may have been in scope then."
                        )
                    } else {
                        String::new()
                    };
                    format!("{} sent outside roe.yaml, e.g. {}.{roe_note}", outside.len(), first.join(", "))
                },
            );
        }
    }

    // 5. Each finding's evidence is in the pack.
    let findings: Vec<Value> =
        files.get("findings.json").and_then(|d| serde_json::from_slice(d).ok()).unwrap_or_default();
    // An exchange counts as included only if its request file is really in the pack.
    let included: BTreeSet<i64> = exchanges
        .iter()
        .filter(|e| e["request"].as_str().is_some_and(|r| files.contains_key(r)))
        .filter_map(|e| e["id"].as_i64())
        .collect();
    let missing: Vec<String> = findings
        .iter()
        .flat_map(|f| {
            let id = f["id"].as_i64().unwrap_or(0);
            f["evidence"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_i64)
                .filter(|e| !included.contains(e))
                .map(move |e| format!("finding #{id}: exchange {e}"))
        })
        .collect();
    check(
        &mut v,
        "evidence",
        missing.is_empty(),
        if missing.is_empty() {
            format!("{} findings, all evidence included", findings.len())
        } else {
            format!("missing: {}", missing.join(", "))
        },
    );
    v.ok = v.checks.iter().all(|c| c.ok);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_fit_paths() {
        assert!(path_fits("/api/orders/{id}", "/api/orders/7?x=1"));
        assert!(!path_fits("/api/orders/{id}", "/api/orders/7/items"));
        assert!(path_fits("/", "/"));
        assert!(same_origin("http://a.test/x", "http://a.test:80"));
        assert!(!same_origin("http://a.test/x", "https://a.test"));
    }

    #[test]
    fn garbage_is_refused_not_panicked_on() {
        assert!(!verify_evidence(b"").ok);
        assert!(!verify_evidence(b"PK\x05\x06garbage").ok);
        let z = zip::write(&[("manifest.json".into(), b"{}".to_vec()), ("manifest.sig".into(), vec![1])]).unwrap();
        let v = verify_evidence(&z);
        assert!(!v.ok && v.checks[0].detail.contains("unknown format"));
    }
}
