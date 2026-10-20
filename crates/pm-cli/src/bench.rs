//! `proxymind bench score`: compare a project's findings with an app's
//! known vulnerabilities.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VULNSHOP_TRUTH: &str = include_str!("../../../bench/ground-truth/vulnshop.yaml");

/// Built-in ground truth by app name (`--truth` takes a file instead).
pub const BUILTIN: &[(&str, &str)] = &[
    ("vulnshop", VULNSHOP_TRUTH),
    ("vampi", include_str!("../../../bench/ground-truth/vampi.yaml")),
    ("juice-shop", include_str!("../../../bench/ground-truth/juice-shop.yaml")),
    ("crapi", include_str!("../../../bench/ground-truth/crapi.yaml")),
];

#[derive(Debug, Deserialize)]
pub struct Truth {
    pub app: String,
    pub vulns: Vec<TruthVuln>,
    #[serde(default)]
    pub secure: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct TruthVuln {
    pub id: String,
    pub class: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct VulnScore {
    pub id: String,
    pub class: String,
    pub endpoint: String,
    pub description: String,
    pub found: bool,
    pub proven: bool,
    pub findings: Vec<i64>,
}

#[derive(Debug, Serialize)]
pub struct Score {
    pub app: String,
    pub vulns: Vec<VulnScore>,
    /// Findings that match no known vulnerability (false positives unless
    /// the ground truth is incomplete). False-positive-marked findings are
    /// excluded.
    pub unmatched_findings: Vec<i64>,
    /// Findings on endpoints the ground truth lists as secure.
    pub findings_on_secure_endpoints: Vec<i64>,
    pub found: usize,
    pub proven: usize,
    pub total: usize,
}

/// Groups vulnerability class names that mean the same thing.
pub fn class_family(c: &str) -> &'static str {
    let c = c.to_ascii_lowercase();
    if c.contains("idor") || c.contains("bola") || c.contains("object") {
        "idor"
    } else if c.contains("bfla") || c.contains("function") || c.contains("privilege") || c.contains("role") {
        "bfla"
    } else if c.contains("sql") {
        "sqli"
    } else if c.contains("ssrf") {
        "ssrf"
    } else if c.contains("xss") {
        "xss"
    } else if c.contains("race") || c.contains("toctou") || c.contains("concurren") {
        "race"
    } else if c.contains("token") || c.contains("random") || c.contains("predictab") {
        "weak_token"
    } else if c.contains("redirect") {
        "open_redirect"
    } else if c.contains("traversal") || c.contains("lfi") || c.contains("file_inclusion") {
        "path_traversal"
    } else if c.contains("ssti") || c.contains("template") {
        "ssti"
    } else if c.contains("mass") || c.contains("assignment") {
        "mass_assignment"
    } else if c.contains("expos") || c.contains("leak") || c.contains("disclos") || c.contains("debug") {
        "exposure"
    } else if c.contains("enum") {
        "enumeration"
    } else if c.contains("redos") || c.contains("dos") || c.contains("rate") || c.contains("resource") {
        "resource"
    } else if c.contains("nosql") {
        "nosqli"
    } else if c.contains("auth")
        || c.contains("password")
        || c.contains("session")
        || c.contains("jwt")
        || c.contains("otp")
    {
        "authn"
    } else {
        "other"
    }
}

fn endpoint_of(f: &Value) -> (String, String) {
    let url = f["url"].as_str().unwrap_or("");
    let path = url::Url::parse(url).map(|u| u.path().to_string()).unwrap_or_else(|_| url.to_string());
    (pm_model::template_path(&path).0, path)
}

/// `/users/v1/{username}` matches `/users/v1/name1`: each `{…}` segment of
/// the ground truth matches any one non-empty segment.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or("");
    let (p, a): (Vec<&str>, Vec<&str>) = (pattern.split('/').collect(), path.split('/').collect());
    p.len() == a.len()
        && p.iter().zip(&a).all(|(p, a)| if p.starts_with('{') && p.ends_with('}') { !a.is_empty() } else { p == a })
}

pub fn score(truth: &Truth, findings: &[Value]) -> Score {
    let live: Vec<&Value> = findings.iter().filter(|f| f["status"] != "false_positive").collect();
    let mut matched = std::collections::BTreeSet::new();
    let mut vulns = Vec::new();
    for v in &truth.vulns {
        let mut ids = Vec::new();
        let mut proven = false;
        for f in &live {
            let (template, raw_path) = endpoint_of(f);
            let same_class = class_family(f["vuln_class"].as_str().unwrap_or("")) == class_family(&v.class);
            if same_class && (template == v.path || path_matches(&v.path, &raw_path)) {
                let id = f["id"].as_i64().unwrap_or(0);
                ids.push(id);
                matched.insert(id);
                proven |= matches!(f["status"].as_str(), Some("proven" | "confirmed" | "reported"));
            }
        }
        vulns.push(VulnScore {
            id: v.id.clone(),
            class: v.class.clone(),
            endpoint: format!("{} {}", v.method, v.path),
            description: v.description.clone(),
            found: !ids.is_empty(),
            proven,
            findings: ids,
        });
    }
    let unmatched_findings: Vec<i64> =
        live.iter().filter_map(|f| f["id"].as_i64()).filter(|id| !matched.contains(id)).collect();
    let findings_on_secure_endpoints: Vec<i64> = live
        .iter()
        .filter(|f| {
            let (template, raw_path) = endpoint_of(f);
            truth
                .secure
                .iter()
                .any(|s| s.split_once(' ').is_some_and(|(_, p)| p == template || path_matches(p, &raw_path)))
        })
        .filter_map(|f| f["id"].as_i64())
        .collect();
    Score {
        app: truth.app.clone(),
        found: vulns.iter().filter(|v| v.found).count(),
        proven: vulns.iter().filter(|v| v.proven).count(),
        total: vulns.len(),
        vulns,
        unmatched_findings,
        findings_on_secure_endpoints,
    }
}

pub fn load_truth(path: Option<&std::path::Path>) -> Result<Truth> {
    let text = match path {
        Some(p) => std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        None => VULNSHOP_TRUTH.to_string(),
    };
    serde_saphyr::from_str(&text).context("ground truth file is not valid")
}

/// Ground truth by built-in app name, e.g. "vampi".
pub fn builtin_truth(app: &str) -> Result<Truth> {
    let text = BUILTIN.iter().find(|(n, _)| *n == app).map(|(_, t)| *t).with_context(|| {
        format!(
            "no built-in ground truth for {app:?}; known: {}",
            BUILTIN.iter().map(|b| b.0).collect::<Vec<_>>().join(", ")
        )
    })?;
    serde_saphyr::from_str(text).context("built-in ground truth is not valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scores_found_proven_and_false_positives() {
        let truth = load_truth(None).unwrap();
        let findings = vec![
            json!({"id": 1, "vuln_class": "idor", "status": "proven", "url": "http://127.0.0.1:8899/api/orders/1001"}),
            json!({"id": 2, "vuln_class": "broken function level authz", "status": "suspected", "url": "http://x/api/admin/users"}),
            json!({"id": 3, "vuln_class": "idor", "status": "suspected", "url": "http://x/api/invoices/5001"}),
            json!({"id": 4, "vuln_class": "idor", "status": "false_positive", "url": "http://x/api/invoices/6001"}),
        ];
        let s = score(&truth, &findings);
        assert_eq!((s.found, s.proven, s.total), (2, 1, 12));
        assert_eq!(s.unmatched_findings, vec![3]);
        assert_eq!(s.findings_on_secure_endpoints, vec![3]);
        let race = vec![json!({"id": 9, "vuln_class": "race condition (TOCTOU)", "status": "proven",
            "url": "http://x/api/giftcard/redeem"})];
        assert_eq!(score(&truth, &race).proven, 1, "race findings match VS-5");
        let xss = vec![
            json!({"id": 10, "vuln_class": "Reflected XSS", "status": "proven", "url": "http://x/search?q=a"}),
            json!({"id": 11, "vuln_class": "xss", "status": "suspected", "url": "http://x/help?topic=a"}),
        ];
        let s = score(&truth, &xss);
        assert_eq!(s.proven, 1, "xss findings match VS-6");
        assert_eq!(s.findings_on_secure_endpoints, vec![11], "/help encodes its input");
    }

    #[test]
    fn named_segments_match_any_value_and_all_truth_files_load() {
        assert!(path_matches("/users/v1/{username}", "/users/v1/name1?x=1"));
        assert!(!path_matches("/users/v1/{username}", "/users/v1/name1/email"));
        assert!(!path_matches("/users/v1/{username}", "/users/v1/"));
        for (app, _) in BUILTIN {
            let t = builtin_truth(app).unwrap();
            assert!(!t.vulns.is_empty(), "{app}");
            for v in &t.vulns {
                assert_ne!(class_family(&v.class), "other", "{app} {}: class {} has no family", v.id, v.class);
            }
        }
        let vampi = builtin_truth("vampi").unwrap();
        let f = vec![
            json!({"id": 1, "vuln_class": "BOLA", "status": "proven", "url": "http://127.0.0.1:5002/books/v1/pmbook1"}),
        ];
        assert_eq!(score(&vampi, &f).proven, 1);
    }
}
