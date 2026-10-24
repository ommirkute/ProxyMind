//! Report exports beyond Markdown: JSON (for tools), SARIF 2.1.0 (for code
//! scanning dashboards) and a self-contained HTML page for clients. All
//! three come from one structured report so they always agree.

use serde::Serialize;
use serde_json::{Value, json};

use crate::findings::{SEVERITIES, excerpt};
use crate::{Result, Service};

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
}

impl Service {
    /// The findings (false positives left out), most severe first, with
    /// their proving proof and up to four evidence exchanges.
    pub fn report(&self) -> Result<Report> {
        let roe = self.policy.roe();
        let mut findings: Vec<Value> =
            self.finding_list(None)?.into_iter().filter(|f| f["status"] != "false_positive").collect();
        let rank = |s: &str| SEVERITIES.iter().position(|x| *x == s).unwrap_or(9);
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
            for ex_id in evidence_ids {
                let Some(ex) = self.store.lock().get_exchange(ex_id)? else { continue };
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
            });
        }
        let (audit, audit_ok) = match crate::verify_audit(&self.store.lock()) {
            Ok(n) => (format!("{n} records, hash chain verified"), true),
            Err(e) => (format!("verification failed: {e}"), false),
        };
        Ok(Report {
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
        })
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
    let rules: Vec<Value> =
        classes.iter().map(|c| json!({ "id": c, "name": c, "shortDescription": { "text": c } })).collect();
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
    h.push_str(
        "<h2>Summary</h2><table><tr><th>#</th><th>Severity</th><th>Title</th><th>Status</th><th>Proof</th></tr>",
    );
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

const CSS: &str = "body{font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:40px auto;padding:0 16px;color:#1f2330}\
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
        Report {
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
            }],
            audit: "3 records, hash chain verified".into(),
            audit_ok: true,
        }
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
        assert_eq!(run["results"][0]["level"], "error");
        assert_eq!(run["results"][0]["properties"]["proven"], true);
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "https://app.test/api/orders/1"
        );
    }
}
