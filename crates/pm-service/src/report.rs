//! Report exports beyond Markdown: JSON (for tools), SARIF 2.1.0 (for code
//! scanning dashboards) and a self-contained HTML page for clients. All
//! three come from one structured report so they always agree.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::findings::{SEVERITIES, excerpt};
use crate::{Result, Service, ServiceError};

/// What the issue library says about a finding's kind of issue.
#[derive(Debug, Clone, Serialize)]
pub struct ReportIssue {
    pub id: String,
    pub name: String,
    pub cwe: Vec<u32>,
    pub owasp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp_api: Option<String>,
    pub background: String,
    pub impact: String,
    pub remediation: String,
    pub references: Vec<String>,
}

impl ReportIssue {
    pub(crate) fn from_library(i: &pm_scan::library::IssueType) -> Self {
        Self {
            id: i.id.into(),
            name: i.name.into(),
            cwe: i.cwe.to_vec(),
            owasp: i.owasp.into(),
            owasp_api: i.owasp_api.map(str::to_string),
            background: i.background.into(),
            impact: i.impact.into(),
            remediation: i.remediation.into(),
            references: i.references.iter().map(|r| r.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SeverityCount {
    pub severity: String,
    pub count: usize,
}

/// Findings of one issue type, with what to do about them.
#[derive(Debug, Clone, Serialize)]
pub struct ReportIssueGroup {
    pub id: String,
    pub name: String,
    /// The most severe of its findings.
    pub severity: String,
    pub count: usize,
    pub findings: Vec<i64>,
    pub cwe: Vec<u32>,
    pub owasp: String,
    pub remediation: String,
}

/// Findings under one OWASP Top 10 category.
#[derive(Debug, Clone, Serialize)]
pub struct ReportOwaspGroup {
    pub category: String,
    pub findings: Vec<ReportOwaspItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportOwaspItem {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub status: String,
    pub cwe: Vec<u32>,
}

/// Which findings go into a report.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReportOptions {
    /// Leave out findings below this severity.
    pub min_severity: Option<String>,
    /// Only these statuses (default: all but false_positive).
    pub statuses: Vec<String>,
    /// Include request/response evidence (default true).
    pub evidence: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportEvidence {
    pub exchange_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    pub request: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportProof {
    pub proof_id: i64,
    pub oracle: String,
    pub confidence: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportFinding {
    pub id: i64,
    pub title: String,
    pub severity: String,
    pub vuln_class: String,
    pub status: String,
    pub url: String,
    pub description: String,
    /// The proof that verified it, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<ReportProof>,
    pub evidence: Vec<ReportEvidence>,
    /// From the issue library, when the class is a known issue type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issue: Option<ReportIssue>,
    /// The last retest's summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retest: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<String>,
    pub scope: Vec<String>,
    pub generator: String,
    pub generated_at: String,
    pub findings: Vec<ReportFinding>,
    /// "N records, hash chain verified" or what failed.
    pub audit: String,
    pub audit_ok: bool,
    /// The most severe finding's severity, or "none".
    pub risk: String,
    /// Findings per severity, most severe first (every severity listed).
    pub severity_counts: Vec<SeverityCount>,
    /// Findings grouped by issue type, most severe first.
    pub issue_types: Vec<ReportIssueGroup>,
    /// Findings grouped by OWASP Top 10 2021 category.
    pub owasp: Vec<ReportOwaspGroup>,
}

impl Report {
    /// Fills in the summary fields from `findings`.
    pub fn summarise(&mut self) {
        let rank = |s: &str| SEVERITIES.iter().position(|x| *x == s).unwrap_or(9);
        self.risk = self.findings.iter().map(|f| f.severity.clone()).min_by_key(|s| rank(s)).unwrap_or("none".into());
        self.severity_counts = SEVERITIES
            .iter()
            .map(|s| SeverityCount {
                severity: s.to_string(),
                count: self.findings.iter().filter(|f| f.severity == *s).count(),
            })
            .collect();
        let mut groups: Vec<ReportIssueGroup> = Vec::new();
        let mut owasp: Vec<ReportOwaspGroup> = Vec::new();
        for f in &self.findings {
            let (id, name, cwe, cat, fix) = match &f.issue {
                Some(i) => (i.id.clone(), i.name.clone(), i.cwe.clone(), i.owasp.clone(), i.remediation.clone()),
                None => (f.vuln_class.clone(), f.vuln_class.clone(), vec![], "Not mapped".into(), String::new()),
            };
            match groups.iter_mut().find(|g| g.id == id) {
                Some(g) => {
                    g.count += 1;
                    g.findings.push(f.id);
                    if rank(&f.severity) < rank(&g.severity) {
                        g.severity = f.severity.clone();
                    }
                }
                None => groups.push(ReportIssueGroup {
                    id,
                    name,
                    severity: f.severity.clone(),
                    count: 1,
                    findings: vec![f.id],
                    cwe: cwe.clone(),
                    owasp: cat.clone(),
                    remediation: fix,
                }),
            }
            let item = ReportOwaspItem {
                id: f.id,
                title: f.title.clone(),
                severity: f.severity.clone(),
                status: f.status.clone(),
                cwe,
            };
            match owasp.iter_mut().find(|g| g.category == cat) {
                Some(g) => g.findings.push(item),
                None => owasp.push(ReportOwaspGroup { category: cat, findings: vec![item] }),
            }
        }
        groups.sort_by_key(|g| (rank(&g.severity), std::cmp::Reverse(g.count)));
        owasp.sort_by(|a, b| a.category.cmp(&b.category));
        self.issue_types = groups;
        self.owasp = owasp;
    }
}

impl Service {
    /// The findings (false positives left out), most severe first, with
    /// their proving proof and up to four evidence exchanges.
    pub fn report(&self) -> Result<Report> {
        self.report_with(&ReportOptions::default())
    }

    pub fn report_with(&self, opts: &ReportOptions) -> Result<Report> {
        let roe = self.policy.roe();
        let rank = |s: &str| SEVERITIES.iter().position(|x| *x == s).unwrap_or(9);
        let floor = match opts.min_severity.as_deref().filter(|s| !s.is_empty()) {
            Some(m) if SEVERITIES.contains(&m) => rank(m),
            Some(m) => return Err(ServiceError::Invalid(format!("unknown severity {m}"))),
            None => 9,
        };
        let mut findings: Vec<Value> = self
            .finding_list(None)?
            .into_iter()
            .filter(|f| {
                let st = f["status"].as_str().unwrap_or("");
                if opts.statuses.is_empty() { st != "false_positive" } else { opts.statuses.iter().any(|s| s == st) }
            })
            .filter(|f| rank(f["severity"].as_str().unwrap_or("")) <= floor)
            .collect();
        findings.sort_by_key(|f| rank(f["severity"].as_str().unwrap_or("")));
        let s = |v: &Value| v.as_str().unwrap_or("").to_string();
        let mut out = Vec::new();
        for f in &findings {
            let id = f["id"].as_i64().unwrap_or(0);
            let proofs = self.proofs_for_finding(id)?;
            let proven = proofs.iter().find(|p| p["proven"] == true);
            let evidence_ids: Vec<i64> = serde_json::from_value::<Vec<i64>>(f["evidence"].clone())
                .unwrap_or_default()
                .into_iter()
                .chain(
                    proven
                        .map(|p| serde_json::from_value::<Vec<i64>>(p["exchange_ids"].clone()).unwrap_or_default())
                        .unwrap_or_default(),
                )
                .take(4)
                .collect();
            let mut evidence = Vec::new();
            for ex_id in evidence_ids.into_iter().filter(|_| opts.evidence.unwrap_or(true)) {
                let Some(ex) = self.store.read(|db| db.get_exchange(ex_id))? else { continue };
                evidence.push(ReportEvidence {
                    exchange_id: ex_id,
                    identity: ex.summary.identity.clone(),
                    request: excerpt(&ex.request, 1500),
                    response: ex.response.as_deref().map(|r| excerpt(r, 1500)),
                });
            }
            out.push(ReportFinding {
                id,
                title: s(&f["title"]),
                severity: s(&f["severity"]),
                vuln_class: s(&f["vuln_class"]),
                status: s(&f["status"]),
                url: s(&f["url"]),
                description: s(&f["description"]),
                proof: proven.map(|p| ReportProof {
                    proof_id: p["proof_id"].as_i64().unwrap_or(0),
                    oracle: s(&p["oracle"]),
                    confidence: s(&p["confidence"]),
                    reasons: p["reasons"].as_array().into_iter().flatten().map(s).collect(),
                }),
                evidence,
                issue: pm_scan::library::lookup(&s(&f["vuln_class"])).map(ReportIssue::from_library),
                retest: f["retest"]["summary"].as_str().map(|r| {
                    let when = jiff::Timestamp::from_millisecond(f["retest"]["ts_ms"].as_i64().unwrap_or(0))
                        .map(|t| t.to_string())
                        .unwrap_or_default();
                    format!("{r} ({when})")
                }),
            });
        }
        let verified = self.store.read(crate::verify_audit);
        let (audit, audit_ok) = match verified {
            // The head hash lets anyone holding this report check later that
            // no records were cut off the end (`proxymind audit verify --anchor`).
            Ok(n) => {
                let head = self
                    .store
                    .read(|db| db.audit_records())?
                    .last()
                    .map(|r| r.hash.iter().take(12).map(|b| format!("{b:02x}")).collect::<String>());
                match head {
                    Some(h) => (format!("{n} records, hash chain verified, head {h}"), true),
                    None => (format!("{n} records, hash chain verified"), true),
                }
            }
            Err(e) => (format!("verification failed: {e}"), false),
        };
        let mut report = Report {
            title: roe.engagement.name.clone().unwrap_or_else(|| "Security assessment".into()),
            client: roe.engagement.client.clone(),
            window: match (roe.engagement.starts, roe.engagement.ends) {
                (Some(a), Some(b)) => Some(format!("{a} to {b}")),
                _ => None,
            },
            scope: roe.include.iter().map(|p| p.text.clone()).collect(),
            generator: format!("ProxyMind {}", env!("CARGO_PKG_VERSION")),
            generated_at: jiff::Timestamp::now().to_string(),
            findings: out,
            audit,
            audit_ok,
            risk: String::new(),
            severity_counts: vec![],
            issue_types: vec![],
            owasp: vec![],
        };
        report.summarise();
        Ok(report)
    }

    pub fn report_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&self.report()?).unwrap_or_default())
    }

    /// SARIF 2.1.0: one rule per vulnerability class, one result per finding.
    pub fn report_sarif(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(&sarif(&self.report()?)).unwrap_or_default())
    }

    pub fn report_html(&self) -> Result<String> {
        Ok(html(&self.report()?))
    }
}

pub fn sarif(r: &Report) -> Value {
    let mut classes: Vec<&str> = r.findings.iter().map(|f| f.vuln_class.as_str()).collect();
    classes.sort_unstable();
    classes.dedup();
    let rules: Vec<Value> = classes
        .iter()
        .map(|c| match pm_scan::library::lookup(c) {
            Some(i) => {
                let mut tags = vec!["security".to_string(), i.owasp.to_string()];
                tags.extend(i.cwe.iter().map(|n| format!("CWE-{n}")));
                json!({
                    "id": c, "name": i.name,
                    "shortDescription": { "text": i.name },
                    "fullDescription": { "text": i.background },
                    "help": { "text": i.remediation },
                    "helpUri": i.cwe.first().map(|n| pm_scan::library::cwe_url(*n)),
                    "properties": { "tags": tags },
                })
            }
            None => json!({ "id": c, "name": c, "shortDescription": { "text": c } }),
        })
        .collect();
    let results: Vec<Value> = r
        .findings
        .iter()
        .map(|f| {
            let level = match f.severity.as_str() {
                "critical" | "high" => "error",
                "medium" => "warning",
                _ => "note",
            };
            let mut text = f.title.clone();
            if let Some(p) = &f.proof {
                text.push_str(&format!(" (proven by {}, {} confidence)", p.oracle, p.confidence));
            }
            json!({
                "ruleId": f.vuln_class,
                "level": level,
                "message": { "text": text },
                "locations": [{ "physicalLocation": { "artifactLocation": { "uri": f.url } } }],
                "partialFingerprints": { "proxymindFinding": f.id.to_string() },
                "properties": {
                    "severity": f.severity, "status": f.status, "proven": f.proof.is_some(),
                    "proof": f.proof, "description": f.description,
                    "evidenceExchanges": f.evidence.iter().map(|e| e.exchange_id).collect::<Vec<_>>(),
                },
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "ProxyMind", "version": env!("CARGO_PKG_VERSION"),
                                   "informationUri": "https://github.com/ommirkute/proxymind", "rules": rules } },
            "results": results,
            "properties": { "engagement": r.title, "scope": r.scope, "audit": r.audit },
        }],
    })
}

/// Escapes text for HTML (everything in the report may come from the target).
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

pub fn html(r: &Report) -> String {
    let mut h = String::new();
    h.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
    h.push_str(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">",
    );
    h.push_str(&format!("<title>{}</title><style>{}</style></head><body>", esc(&r.title), CSS));
    h.push_str(&format!("<h1>{}</h1><dl>", esc(&r.title)));
    if let Some(c) = &r.client {
        h.push_str(&format!("<dt>Client</dt><dd>{}</dd>", esc(c)));
    }
    if let Some(w) = &r.window {
        h.push_str(&format!("<dt>Testing window</dt><dd>{}</dd>", esc(w)));
    }
    h.push_str(&format!(
        "<dt>Scope</dt><dd>{}</dd><dt>Generated</dt><dd>{} by {}</dd></dl>",
        r.scope.iter().map(|s| format!("<code>{}</code>", esc(s))).collect::<Vec<_>>().join(", "),
        esc(&r.generated_at),
        esc(&r.generator)
    ));
    h.push_str(&format!(
        "<h2>Summary</h2><p>Overall risk: <span class=\"sev {}\">{}</span> · {}</p>",
        esc(&r.risk),
        esc(&r.risk),
        r.severity_counts
            .iter()
            .filter(|c| c.count > 0)
            .map(|c| format!("{} {}", c.count, esc(&c.severity)))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    h.push_str("<table><tr><th>#</th><th>Severity</th><th>Title</th><th>Status</th><th>Proof</th></tr>");
    if r.findings.is_empty() {
        h.push_str("<tr><td colspan=5>No findings recorded.</td></tr>");
    }
    for f in &r.findings {
        h.push_str(&format!(
            "<tr><td><a href=\"#f{}\">{}</a></td><td><span class=\"sev {}\">{}</span></td><td>{}</td><td>{}</td><td>{}</td></tr>",
            f.id,
            f.id,
            esc(&f.severity),
            esc(&f.severity),
            esc(&f.title),
            esc(&f.status),
            f.proof.as_ref().map_or("not proven".into(), |p| format!("{} ({})", esc(&p.oracle), esc(&p.confidence)))
        ));
    }
    h.push_str("</table>");
    for f in &r.findings {
        h.push_str(&format!(
            "<section id=\"f{}\"><h2>{}. {}</h2><p class=\"meta\"><span class=\"sev {}\">{}</span> · {} · {} · <code>{}</code></p><p class=\"desc\">{}</p>",
            f.id,
            f.id,
            esc(&f.title),
            esc(&f.severity),
            esc(&f.severity),
            esc(&f.vuln_class),
            esc(&f.status),
            esc(&f.url),
            esc(&f.description)
        ));
        if let Some(i) = &f.issue {
            let cwe: Vec<String> =
                i.cwe.iter().map(|n| format!("<a href=\"{}\">CWE-{n}</a>", pm_scan::library::cwe_url(*n))).collect();
            h.push_str(&format!(
                "<p class=\"meta\">{} · {}{}</p><h3>Background</h3><p>{}</p><h3>Impact</h3><p>{}</p>\
                 <h3>Remediation</h3><p>{}</p>",
                cwe.join(", "),
                esc(&i.owasp),
                i.owasp_api.as_deref().map(|a| format!(" · {}", esc(a))).unwrap_or_default(),
                esc(&i.background),
                esc(&i.impact),
                esc(&i.remediation)
            ));
        }
        if let Some(t) = &f.retest {
            h.push_str(&format!("<p class=\"muted\">Last retest: {}</p>", esc(t)));
        }
        if let Some(p) = &f.proof {
            h.push_str(&format!(
                "<h3>Proof</h3><p>Verified automatically by the <code>{}</code> check ({} confidence):</p><ul>",
                esc(&p.oracle),
                esc(&p.confidence)
            ));
            for reason in &p.reasons {
                h.push_str(&format!("<li>{}</li>", esc(reason)));
            }
            h.push_str(&format!(
                "</ul><p class=\"muted\">Re-run: <code>proxymind proof rerun {}</code></p>",
                p.proof_id
            ));
        }
        if !f.evidence.is_empty() {
            h.push_str("<h3>Evidence</h3>");
        }
        for e in &f.evidence {
            let who = e.identity.as_deref().map(|i| format!(" (as {})", esc(i))).unwrap_or_default();
            h.push_str(&format!(
                "<p class=\"muted\">Exchange {}{who}</p><pre>{}</pre>",
                e.exchange_id,
                esc(&e.request)
            ));
            if let Some(resp) = &e.response {
                h.push_str(&format!("<pre>{}</pre>", esc(resp)));
            }
        }
        h.push_str("</section>");
    }
    h.push_str(&format!(
        "<footer>Audit log: {}. Every request in this engagement was checked against the rules of engagement and recorded.</footer></body></html>",
        esc(&r.audit)
    ));
    h
}

pub(crate) const CSS: &str = "body{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 16px;color:#1f2330}\
h1{font-size:26px}h2{font-size:20px;margin-top:32px;border-bottom:1px solid #e3e5ec;padding-bottom:4px}h3{font-size:16px}\
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #e3e5ec;padding:6px 8px;text-align:left}\
dt{font-weight:600;float:left;clear:left;width:140px}dd{margin-left:150px}\
pre{background:#f4f5f8;padding:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;font-size:12px}\
code{background:#f4f5f8;padding:1px 4px;border-radius:3px}.muted,.meta{color:#5b6070}.desc{white-space:pre-wrap}\
.sev{padding:1px 8px;border-radius:10px;font-size:12px;background:#eef}.critical,.high{background:#fde2e1;color:#9b1c1c}\
.medium{background:#fdf0d5;color:#8a5300}.low,.info{background:#e6f0fd;color:#1d4f91}footer{margin-top:40px;color:#5b6070;font-size:13px}";

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> Report {
        let mut r = Report {
            title: "Test <engagement>".into(),
            client: Some("ACME".into()),
            window: None,
            scope: vec!["https://app.test/".into()],
            generator: "ProxyMind test".into(),
            generated_at: "now".into(),
            findings: vec![ReportFinding {
                id: 1,
                title: "IDOR <script>alert(1)</script>".into(),
                severity: "high".into(),
                vuln_class: "idor".into(),
                status: "proven".into(),
                url: "https://app.test/api/orders/1".into(),
                description: "x".into(),
                proof: Some(ReportProof {
                    proof_id: 3,
                    oracle: "differential_authz".into(),
                    confidence: "high".into(),
                    reasons: vec!["bob got alice's order".into()],
                }),
                evidence: vec![ReportEvidence {
                    exchange_id: 9,
                    identity: None,
                    request: "GET / HTTP/1.1".into(),
                    response: Some("<img src=x onerror=alert(1)>".into()),
                }],
                issue: pm_scan::library::lookup("idor").map(ReportIssue::from_library),
                retest: None,
            }],
            audit: "3 records, hash chain verified".into(),
            audit_ok: true,
            risk: String::new(),
            severity_counts: vec![],
            issue_types: vec![],
            owasp: vec![],
        };
        r.summarise();
        r
    }

    #[test]
    fn html_escapes_everything_from_the_target() {
        let h = html(&report());
        assert!(!h.contains("<script>alert(1)") && !h.contains("<img src=x"));
        assert!(h.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(h.contains("default-src 'none'"), "no scripts can run even if escaping failed");
    }

    #[test]
    fn sarif_has_rules_and_levels() {
        let s = sarif(&report());
        assert_eq!(s["version"], "2.1.0");
        let run = &s["runs"][0];
        assert_eq!(run["tool"]["driver"]["rules"][0]["id"], "idor");
        assert!(run["tool"]["driver"]["rules"][0]["properties"]["tags"].to_string().contains("CWE-639"));
        assert_eq!(run["results"][0]["level"], "error");
        assert_eq!(run["results"][0]["properties"]["proven"], true);
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://app.test/api/orders/1"
        );
    }
}
