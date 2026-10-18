//! The hypothesis ledger and coverage map: the shared memory of an
//! engagement.
//!
//! Every test is run under a **hypothesis** ("`GET /api/orders/{id}` may not
//! check ownership"). Hypotheses move from `open` to `testing` to
//! `confirmed` or `refuted`. **Coverage** combines the app model's
//! operations with a checklist of vulnerability classes that apply to each,
//! so anyone (human or agent) can ask "what haven't we tested?".

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Vulnerability classes the ledger tracks. Free-form classes are allowed
/// too; these are the ones the checklist suggests.
pub const CLASSES: &[(&str, &str)] = &[
    ("idor", "Object-level authorization (IDOR/BOLA): can another user access this object?"),
    ("bfla", "Function-level authorization: can a lower-privileged role use this function?"),
    ("authn", "Authentication: does it work without credentials, or with expired ones?"),
    ("sqli", "SQL/NoSQL injection in parameters"),
    ("xss", "Cross-site scripting via reflected or stored input"),
    ("ssrf", "Server-side request forgery via URL-like parameters"),
    ("mass_assignment", "Extra fields accepted on create/update (role, owner, price)"),
    ("business_logic", "Negative quantities, skipped steps, replayed actions, race conditions"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Open,
    Testing,
    Confirmed,
    Refuted,
}

impl Status {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "open" => Status::Open,
            "testing" => Status::Testing,
            "confirmed" => Status::Confirmed,
            "refuted" => Status::Refuted,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Status::Open => "open",
            Status::Testing => "testing",
            Status::Confirmed => "confirmed",
            Status::Refuted => "refuted",
        }
    }

    /// Precedence when several hypotheses cover the same cell.
    fn rank(self) -> u8 {
        match self {
            Status::Confirmed => 4,
            Status::Testing => 3,
            Status::Refuted => 2,
            Status::Open => 1,
        }
    }
}

/// What the checklist expects to be tested for an operation.
#[derive(Debug, Clone)]
pub struct OperationInfo<'a> {
    pub key: &'a str,
    pub method: &'a str,
    pub template: &'a str,
    pub kind: &'a str,
    pub authenticated: bool,
    pub query_params: &'a [String],
    pub body_params: &'a [String],
}

/// Classes worth testing for an operation, with the parameter they apply to
/// (`""` = the operation as a whole).
pub fn checklist(op: &OperationInfo<'_>) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let lower = op.template.to_ascii_lowercase();
    if op.template.contains('{') && op.authenticated {
        out.push(("idor", String::new()));
    }
    if lower.contains("admin") || lower.contains("internal") || lower.contains("manage") {
        out.push(("bfla", String::new()));
    }
    if op.authenticated {
        out.push(("authn", String::new()));
    }
    for p in op.query_params.iter().chain(op.body_params) {
        let pl = p.to_ascii_lowercase();
        if ["url", "uri", "link", "callback", "webhook", "redirect", "next", "image", "src", "dest", "fetch"]
            .iter()
            .any(|w| pl.contains(w))
        {
            out.push(("ssrf", p.clone()));
        }
        out.push(("sqli", p.clone()));
        if op.method == "GET" {
            out.push(("xss", p.clone()));
        }
    }
    if matches!(op.kind, "create" | "update") {
        out.push(("mass_assignment", String::new()));
        out.push(("business_logic", String::new()));
    }
    out
}

/// A hypothesis as stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: i64,
    pub operation: String,
    #[serde(default)]
    pub param: String,
    pub vuln_class: String,
    pub rationale: String,
    pub status: String,
    pub actor: String,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub evidence: Vec<i64>,
    pub created_ms: i64,
    pub updated_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoverageCell {
    pub operation: String,
    pub vuln_class: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub param: String,
    /// untested, open, testing, confirmed, refuted
    pub status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hypotheses: Vec<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Coverage {
    pub cells: Vec<CoverageCell>,
    pub totals: BTreeMap<String, usize>,
    /// Share of checklist cells that are confirmed or refuted.
    pub percent_tested: f64,
}

/// Rough priority for untested work: authz on objects first, then
/// injection, then the rest.
fn priority(class: &str, op_key: &str) -> u8 {
    let state_changing = !op_key.starts_with("GET ") && !op_key.starts_with("HEAD ");
    match class {
        "idor" | "bfla" => 0,
        "sqli" | "ssrf" => 1,
        "authn" => 2,
        _ if state_changing => 2,
        _ => 3,
    }
}

/// Combines the checklist for each operation with recorded hypotheses.
pub fn coverage(ops: &[OperationInfo<'_>], hypotheses: &[Hypothesis]) -> Coverage {
    let mut cells: Vec<CoverageCell> = Vec::new();
    let mut index: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for op in ops {
        for (class, param) in checklist(op) {
            let key = (op.key.to_string(), class.to_string(), param.clone());
            if index.contains_key(&key) {
                continue;
            }
            index.insert(key, cells.len());
            cells.push(CoverageCell {
                operation: op.key.into(),
                vuln_class: class.into(),
                param,
                status: "untested".into(),
                hypotheses: vec![],
            });
        }
    }
    for h in hypotheses {
        let key = (h.operation.clone(), h.vuln_class.clone(), h.param.clone());
        let i = match index.get(&key) {
            Some(i) => *i,
            None => {
                index.insert(key, cells.len());
                cells.push(CoverageCell {
                    operation: h.operation.clone(),
                    vuln_class: h.vuln_class.clone(),
                    param: h.param.clone(),
                    status: "untested".into(),
                    hypotheses: vec![],
                });
                cells.len() - 1
            }
        };
        let cell = &mut cells[i];
        cell.hypotheses.push(h.id);
        let new = Status::parse(&h.status).unwrap_or(Status::Open);
        let cur = Status::parse(&cell.status);
        if cur.is_none_or(|c| new.rank() > c.rank()) {
            cell.status = new.as_str().into();
        }
    }
    cells.sort_by(|a, b| {
        let done = |c: &CoverageCell| matches!(c.status.as_str(), "confirmed" | "refuted") as u8;
        (done(a), priority(&a.vuln_class, &a.operation), &a.operation, &a.vuln_class).cmp(&(
            done(b),
            priority(&b.vuln_class, &b.operation),
            &b.operation,
            &b.vuln_class,
        ))
    });
    let mut totals = BTreeMap::new();
    for c in &cells {
        *totals.entry(c.status.clone()).or_insert(0) += 1;
    }
    let done = cells.iter().filter(|c| matches!(c.status.as_str(), "confirmed" | "refuted")).count();
    let percent_tested =
        if cells.is_empty() { 0.0 } else { (done as f64 * 1000.0 / cells.len() as f64).round() / 10.0 };
    Coverage { cells, totals, percent_tested }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op<'a>(key: &'a str, template: &'a str, q: &'a [String]) -> OperationInfo<'a> {
        OperationInfo {
            key,
            method: key.split(' ').next().unwrap(),
            template,
            kind: if template.ends_with('}') { "read_item" } else { "read_collection" },
            authenticated: true,
            query_params: q,
            body_params: &[],
        }
    }

    #[test]
    fn checklist_suggests_relevant_classes() {
        let q = vec!["url".to_string()];
        let c: Vec<_> = checklist(&op("GET /api/fetch", "/api/fetch", &q)).into_iter().map(|(c, _)| c).collect();
        assert!(c.contains(&"ssrf") && c.contains(&"sqli"));
        let c: Vec<_> =
            checklist(&op("GET /api/orders/{id}", "/api/orders/{id}", &[])).into_iter().map(|(c, _)| c).collect();
        assert!(c.contains(&"idor") && !c.contains(&"ssrf"));
    }

    #[test]
    fn coverage_merges_hypotheses_and_prioritises_untested() {
        let none: Vec<String> = vec![];
        let ops =
            [op("GET /api/orders/{id}", "/api/orders/{id}", &none), op("GET /api/products", "/api/products", &none)];
        let h = |id, status: &str| Hypothesis {
            id,
            operation: "GET /api/orders/{id}".into(),
            param: String::new(),
            vuln_class: "idor".into(),
            rationale: String::new(),
            status: status.into(),
            actor: "agent:a".into(),
            notes: vec![],
            evidence: vec![],
            created_ms: 0,
            updated_ms: 0,
        };
        let cov = coverage(&ops, &[h(1, "refuted"), h(2, "confirmed")]);
        let idor = cov.cells.iter().find(|c| c.vuln_class == "idor").unwrap();
        assert_eq!((idor.status.as_str(), idor.hypotheses.clone()), ("confirmed", vec![1, 2]));
        assert_eq!(cov.cells.last().unwrap().vuln_class, "idor", "finished work sorts last");
        assert!(cov.percent_tested > 0.0 && cov.percent_tested < 100.0);
    }
}
