//! Findings and the engagement report.
//!
//! Status flow: `suspected` → `proven` (only by a successful proof run) →
//! `confirmed` / `false_positive` / `reported` / `fixed` / `accepted_risk`
//! (humans only). A new finding with the same issue type and URL as an open
//! one is merged into it (its evidence added). Each finding is filled in
//! from the issue library (`pm_scan::library`) by its class.

use pm_policy::{Actor, ActorKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError, now_ms};

pub(crate) const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];

/// Statuses people may set.
pub const HUMAN_STATUSES: &[&str] = &["suspected", "confirmed", "false_positive", "reported", "fixed", "accepted_risk"];

/// Statuses that close a finding: new ones of the same kind aren't merged into it.
const CLOSED: &[&str] = &["false_positive", "fixed"];

/// What a finding's class means: the issue library's id, or the class as given.
pub(crate) fn issue_key(class: &str) -> String {
    pm_scan::library::lookup(class).map(|i| i.id.to_string()).unwrap_or_else(|| class.trim().to_ascii_lowercase())
}

/// A URL without its query and fragment, for spotting duplicates.
fn url_key(url: &str) -> &str {
    url.split(['?', '#']).next().unwrap_or(url)
}

/// What a retest found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Retest {
    pub finding_id: i64,
    /// proof (re-ran the proof), scan (re-ran the scanner check) or none.
    pub method: String,
    /// Whether the issue showed again; None when it couldn't be checked.
    pub reproduced: Option<bool>,
    pub summary: String,
    pub exchange_ids: Vec<i64>,
    pub ts_ms: i64,
    pub by: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewFinding {
    pub title: String,
    /// idor, bfla, sqli, ssrf, xss, …
    pub vuln_class: String,
    /// critical, high, medium, low or info
    pub severity: String,
    pub description: String,
    /// Affected URL; defaults to the first evidence exchange's URL.
    #[serde(default)]
    pub url: Option<String>,
    /// Exchange ids that show the issue.
    #[serde(default)]
    pub evidence: Vec<i64>,
    #[serde(default)]
    pub hypothesis_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FindingUpdate {
    pub id: i64,
    /// Humans: suspected, confirmed, false_positive, reported, fixed, accepted_risk. Agents: suspected.
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub add_evidence: Vec<i64>,
}

fn decode(row: &serde_json::Map<String, Value>) -> Value {
    let mut v = Value::Object(row.clone());
    if let Some(e) = row.get("evidence").and_then(Value::as_str) {
        v["evidence"] = serde_json::from_str(e).unwrap_or(json!([]));
    }
    v["retest"] = match row.get("retest").and_then(Value::as_str) {
        Some(t) if !t.is_empty() => serde_json::from_str(t).unwrap_or(Value::Null),
        _ => Value::Null,
    };
    if let Some(i) = row.get("vuln_class").and_then(Value::as_str).and_then(pm_scan::library::lookup) {
        v["issue"] = json!(i);
    }
    v
}

impl Service {
    pub fn finding_create(&self, actor: &Actor, f: NewFinding) -> Result<Value> {
        let severity = f.severity.to_ascii_lowercase();
        if !SEVERITIES.contains(&severity.as_str()) {
            return Err(ServiceError::Invalid(format!("severity must be one of {}", SEVERITIES.join(", "))));
        }
        let url = match (&f.url, f.evidence.first()) {
            (Some(u), _) => u.clone(),
            (None, Some(id)) => {
                let ex = self
                    .store
                    .lock()
                    .get_exchange(*id)?
                    .ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
                pm_core::url(&ex.summary.scheme, &ex.summary.host, ex.summary.port, &ex.summary.path)
            }
            (None, None) => return Err(ServiceError::Invalid("give url or at least one evidence exchange id".into())),
        };
        // The same issue at the same place: add to the open finding instead.
        let key = issue_key(&f.vuln_class);
        let open = self.finding_list(None)?.into_iter().find(|o| {
            !CLOSED.contains(&o["status"].as_str().unwrap_or(""))
                && issue_key(o["vuln_class"].as_str().unwrap_or("")) == key
                && url_key(o["url"].as_str().unwrap_or("")) == url_key(&url)
        });
        if let Some(o) = open {
            let id = o["id"].as_i64().unwrap_or(0);
            let mut ev: Vec<i64> = serde_json::from_value(o["evidence"].clone()).unwrap_or_default();
            for e in &f.evidence {
                if !ev.contains(e) {
                    ev.push(*e);
                }
            }
            let mut changes = serde_json::Map::new();
            changes.insert("evidence".into(), json!(serde_json::to_string(&ev).unwrap_or_default()));
            changes.insert("duplicates".into(), json!(o["duplicates"].as_i64().unwrap_or(0) + 1));
            let rank = |s: &str| SEVERITIES.iter().position(|x| *x == s).unwrap_or(9);
            if rank(&severity) < rank(o["severity"].as_str().unwrap_or("")) {
                changes.insert("severity".into(), json!(severity));
            }
            changes.insert("updated_ms".into(), json!(now_ms()));
            self.store.lock().update_row("findings", id, &changes)?;
            self.audit(
                &actor.id(),
                "finding_merge",
                json!({ "id": id, "title": f.title, "evidence": f.evidence }),
                "allow",
            )?;
            let mut v = self.finding_get(id)?;
            v["merged"] = json!(true);
            return Ok(v);
        }
        let now = now_ms();
        let mut row = serde_json::Map::new();
        for (k, v) in [
            ("title", json!(f.title)),
            ("vuln_class", json!(f.vuln_class.to_ascii_lowercase())),
            ("severity", json!(severity)),
            ("status", json!("suspected")),
            ("url", json!(url)),
            ("description", json!(f.description)),
            ("hypothesis_id", json!(f.hypothesis_id)),
            ("evidence", json!(serde_json::to_string(&f.evidence).unwrap_or_default())),
            ("actor", json!(actor.id())),
            ("created_ms", json!(now)),
            ("updated_ms", json!(now)),
        ] {
            row.insert(k.into(), v);
        }
        let id = self.store.lock().insert_row("findings", &row)?;
        self.audit(&actor.id(), "finding_create", json!({ "id": id, "title": f.title }), "allow")?;
        self.finding_get(id)
    }

    pub fn finding_get(&self, id: i64) -> Result<Value> {
        let row =
            self.store.lock().row("findings", id)?.ok_or_else(|| ServiceError::NotFound(format!("finding {id}")))?;
        let mut v = decode(&row);
        v["proofs"] = json!(self.proofs_for_finding(id)?);
        Ok(v)
    }

    pub fn finding_list(&self, status: Option<&str>) -> Result<Vec<Value>> {
        let filter = status.map(|s| json!(s));
        let rows = self.store.lock().rows("findings", filter.as_ref().map(|v| ("status", v)), 1000)?;
        Ok(rows.iter().map(decode).collect())
    }

    pub fn finding_update(&self, actor: &Actor, u: FindingUpdate) -> Result<Value> {
        let current = self.finding_get(u.id)?;
        let mut changes = serde_json::Map::new();
        if let Some(st) = &u.status {
            let allowed: &[&str] = if actor.kind == ActorKind::Human { HUMAN_STATUSES } else { &["suspected"] };
            if !allowed.contains(&st.as_str()) {
                return Err(ServiceError::Invalid(if st == "proven" {
                    "findings become proven only through a successful proof_run".into()
                } else {
                    format!("{} may set status to: {}", actor.id(), allowed.join(", "))
                }));
            }
            changes.insert("status".into(), json!(st));
        }
        if let Some(sev) = &u.severity {
            if !SEVERITIES.contains(&sev.as_str()) {
                return Err(ServiceError::Invalid(format!("severity must be one of {}", SEVERITIES.join(", "))));
            }
            changes.insert("severity".into(), json!(sev));
        }
        if let Some(d) = &u.description {
            changes.insert("description".into(), json!(d));
        }
        if !u.add_evidence.is_empty() {
            let mut ev: Vec<i64> = serde_json::from_value(current["evidence"].clone()).unwrap_or_default();
            for e in &u.add_evidence {
                if !ev.contains(e) {
                    ev.push(*e);
                }
            }
            changes.insert("evidence".into(), json!(serde_json::to_string(&ev).unwrap_or_default()));
        }
        changes.insert("updated_ms".into(), json!(now_ms()));
        self.store.lock().update_row("findings", u.id, &changes)?;
        self.audit(&actor.id(), "finding_update", json!(u), "allow")?;
        self.finding_get(u.id)
    }

    /// Checks whether a finding still reproduces: re-runs its proof if it
    /// has one, else the scanner checks for its issue type on the request
    /// that was scanned (a scanner lead's first evidence exchange). The
    /// result is kept on the finding; a proof that holds again marks it
    /// proven (reopening a fixed one), anything else leaves the status alone.
    pub async fn finding_retest(&self, actor: &Actor, id: i64) -> Result<Retest> {
        let f = self.finding_get(id)?;
        let mut r = Retest {
            finding_id: id,
            method: "none".into(),
            reproduced: None,
            summary: String::new(),
            exchange_ids: vec![],
            ts_ms: now_ms(),
            by: actor.id(),
        };
        let proofs = self.proofs_for_finding(id)?;
        let proof = proofs.iter().find(|p| p["proven"] == true).or(proofs.first());
        let key = issue_key(f["vuln_class"].as_str().unwrap_or(""));
        let checks: Vec<String> = pm_scan::active::CHECKS
            .iter()
            .chain(pm_scan::oob::CHECKS)
            .filter(|c| pm_scan::library::lookup(c).is_some_and(|i| i.id == key))
            .map(|c| c.to_string())
            .collect();
        let evidence: Vec<i64> = serde_json::from_value(f["evidence"].clone()).unwrap_or_default();
        if let Some(p) = proof {
            r.method = "proof".into();
            match self.proof_rerun(actor, p["proof_id"].as_i64().unwrap_or(0)).await? {
                crate::ProofResult::Completed { proven, reasons, exchange_ids, .. } => {
                    r.reproduced = Some(proven);
                    r.exchange_ids = exchange_ids;
                    r.summary = if proven {
                        "the proof still holds".into()
                    } else {
                        format!("the proof no longer holds: {}", reasons.join("; "))
                    };
                }
                crate::ProofResult::PendingApproval { approval_id, .. } => {
                    r.summary = format!("the proof needs approval {approval_id}; approve it and retest")
                }
                crate::ProofResult::Denied { reasons } => r.summary = format!("denied: {}", reasons.join("; ")),
            }
        } else if let (false, Some(&scanned)) = (checks.is_empty(), evidence.first()) {
            r.method = "scan".into();
            let req = crate::ActiveScanRequest {
                exchange_id: scanned,
                checks: checks.clone(),
                max_requests: Some(200),
                oob_wait_seconds: Some(5),
                ..Default::default()
            };
            match self.scan_active(actor, req).await {
                Err(e) => r.summary = format!("couldn't re-run the scan on #{scanned}: {e}"),
                Ok(crate::ActiveScanResult::Done { issues, .. }) => {
                    r.reproduced = Some(!issues.is_empty());
                    r.exchange_ids = issues.iter().map(|i| i.exchange_id).collect();
                    r.summary = match issues.first() {
                        Some(i) => format!("still there: {} ({})", i.issue.title, i.issue.point),
                        None => format!("not seen again ({} re-run on #{scanned})", checks.join(", ")),
                    };
                }
                Ok(crate::ActiveScanResult::PendingApproval { approval_id, .. }) => {
                    r.summary = format!("the scan needs approval {approval_id}; approve it and retest")
                }
                Ok(crate::ActiveScanResult::Denied { reasons }) => {
                    r.summary = format!("denied: {}", reasons.join("; "))
                }
            }
        } else {
            r.summary = "nothing to re-run: no proof, and no scanner check for this issue type".into();
        }
        let mut ch = serde_json::Map::new();
        ch.insert("retest".into(), json!(serde_json::to_string(&r).unwrap_or_default()));
        ch.insert("updated_ms".into(), json!(now_ms()));
        self.store.lock().update_row("findings", id, &ch)?;
        self.audit(
            &actor.id(),
            "finding_retest",
            json!({ "id": id, "method": r.method, "reproduced": r.reproduced }),
            "allow",
        )?;
        Ok(r)
    }

    /// A Markdown report of all findings (false positives excluded), with
    /// proofs and evidence, ready to edit and hand over.
    pub fn report_markdown(&self) -> Result<String> {
        let roe = self.policy.roe();
        let mut findings: Vec<Value> =
            self.finding_list(None)?.into_iter().filter(|f| f["status"] != "false_positive").collect();
        let rank = |s: &str| SEVERITIES.iter().position(|x| *x == s).unwrap_or(9);
        findings.sort_by_key(|f| rank(f["severity"].as_str().unwrap_or("")));
        let mut md = String::new();
        let title = roe.engagement.name.clone().unwrap_or_else(|| "Security assessment".into());
        md.push_str(&format!("# {title}\n\n"));
        if let Some(c) = &roe.engagement.client {
            md.push_str(&format!("**Client:** {c}  \n"));
        }
        if let (Some(s), Some(e)) = (roe.engagement.starts, roe.engagement.ends) {
            md.push_str(&format!("**Testing window:** {s} to {e}  \n"));
        }
        md.push_str(&format!(
            "**Scope:** {}  \n**Generated by:** ProxyMind {}\n\n",
            roe.include.iter().map(|p| format!("`{}`", p.text)).collect::<Vec<_>>().join(", "),
            env!("CARGO_PKG_VERSION")
        ));
        md.push_str("## Summary\n\n| # | Severity | Title | Status | Proof |\n|---|---|---|---|---|\n");
        for f in &findings {
            let proofs = self.proofs_for_finding(f["id"].as_i64().unwrap_or(0))?;
            let proven = proofs.iter().find(|p| p["proven"] == true);
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                f["id"],
                f["severity"].as_str().unwrap_or(""),
                f["title"].as_str().unwrap_or(""),
                f["status"].as_str().unwrap_or(""),
                proven.map_or("not proven".to_string(), |p| format!(
                    "{} ({})",
                    p["oracle"].as_str().unwrap_or(""),
                    p["confidence"].as_str().unwrap_or("")
                ))
            ));
        }
        if findings.is_empty() {
            md.push_str("| – | – | No findings recorded | – | – |\n");
        }
        for f in &findings {
            let id = f["id"].as_i64().unwrap_or(0);
            md.push_str(&format!(
                "\n## {}. {}\n\n**Severity:** {} · **Class:** {} · **Status:** {}  \n**Affected:** `{}`\n\n{}\n",
                id,
                f["title"].as_str().unwrap_or(""),
                f["severity"].as_str().unwrap_or(""),
                f["vuln_class"].as_str().unwrap_or(""),
                f["status"].as_str().unwrap_or(""),
                f["url"].as_str().unwrap_or(""),
                f["description"].as_str().unwrap_or("")
            ));
            if let Some(i) = f.get("issue") {
                let cwe: Vec<String> = i["cwe"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_u64)
                    .map(|n| format!("[CWE-{n}]({})", pm_scan::library::cwe_url(n as u32)))
                    .collect();
                md.push_str(&format!(
                    "\n**Classification:** {} · {}\n\n**Impact:** {}\n\n**Remediation:** {}\n",
                    cwe.join(", "),
                    i["owasp"].as_str().unwrap_or(""),
                    i["impact"].as_str().unwrap_or(""),
                    i["remediation"].as_str().unwrap_or("")
                ));
            }
            if let Some(t) = f["retest"]["summary"].as_str() {
                md.push_str(&format!("\n**Last retest:** {t}\n"));
            }
            for p in self.proofs_for_finding(id)?.iter().filter(|p| p["proven"] == true).take(1) {
                md.push_str(&format!(
                    "\n### Proof\n\nVerified automatically by the `{}` check ({} confidence):\n\n",
                    p["oracle"].as_str().unwrap_or(""),
                    p["confidence"].as_str().unwrap_or("")
                ));
                for r in p["reasons"].as_array().into_iter().flatten() {
                    md.push_str(&format!("- {}\n", r.as_str().unwrap_or("")));
                }
                md.push_str(&format!("\nRe-run: `proxymind proof rerun {}`\n", p["proof_id"]));
            }
            let evidence: Vec<i64> = serde_json::from_value(f["evidence"].clone()).unwrap_or_default();
            let proof_ids: Vec<i64> = self
                .proofs_for_finding(id)?
                .iter()
                .filter(|p| p["proven"] == true)
                .flat_map(|p| serde_json::from_value::<Vec<i64>>(p["exchange_ids"].clone()).unwrap_or_default())
                .collect();
            let shown: Vec<i64> = evidence.into_iter().chain(proof_ids).take(4).collect();
            if !shown.is_empty() {
                md.push_str("\n### Evidence\n");
            }
            for ex_id in shown {
                let Some(ex) = self.store.lock().get_exchange(ex_id)? else { continue };
                let who = ex.summary.identity.clone().map(|i| format!(" (as {i})")).unwrap_or_default();
                md.push_str(&format!("\nExchange {ex_id}{who}:\n\n```http\n{}\n```\n", excerpt(&ex.request, 1500)));
                if let Some(r) = &ex.response {
                    md.push_str(&format!("\n```http\n{}\n```\n", excerpt(r, 1500)));
                }
            }
        }
        let audit = crate::verify_audit(&self.store.lock());
        md.push_str(&format!(
            "\n---\n\nAudit log: {}. Every request in this engagement was checked against the rules of engagement and recorded.\n",
            match audit {
                Ok(n) => format!("{n} records, hash chain verified"),
                Err(e) => format!("**verification failed: {e}**"),
            }
        ));
        Ok(md)
    }
}

/// Start of a raw message for a report, with long bodies cut.
pub(crate) fn excerpt(raw: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(raw);
    let text = text.replace("\r\n", "\n");
    if text.len() <= max {
        return text.trim_end().to_string();
    }
    let mut cut = max;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}\n[… {} more bytes …]", &text[..cut], text.len() - cut)
}
