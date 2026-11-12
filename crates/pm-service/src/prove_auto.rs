//! Automatic proving: pick an oracle by vulnerability class, rebuild the
//! request from a suspected finding's first evidence exchange, and run it
//! through `proof_run` (which gates the send, stores the proof and links it to
//! the finding on success). This is what turns the sweep's "suspected"
//! findings into "proven" ones; IDOR/BFLA are proven by the authorization
//! matrix instead (differential oracle) and reused here when a finding has the
//! identities for it.

use pm_policy::Actor;
use pm_scan::active::{Point, PointKind, inject, points};
use serde::Serialize;

use crate::{ProofRequest, ProofResult, Result, Service};

/// The result of trying to prove one finding.
#[derive(Debug, Clone, Serialize)]
pub struct FindingProve {
    pub finding_id: i64,
    pub vuln_class: String,
    pub proven: bool,
    /// Why, or why not (the winning oracle's reasons, else the last attempt's).
    pub reasons: Vec<String>,
    /// The oracle that proved it, when proven.
    pub oracle: Option<String>,
    pub proof_id: Option<i64>,
}

/// A run of [`Service::auto_prove`].
#[derive(Debug, Clone, Serialize, Default)]
pub struct ProveSweep {
    pub attempted: usize,
    pub proven: usize,
    pub results: Vec<FindingProve>,
}

/// An alnum sentinel that survives percent-encoding, so a placeholder can be
/// dropped into an injected request without the encoder mangling its braces.
const SENTINEL: &str = "pmproofzz";

/// Classes `auto_prove` tries. IDOR/BFLA/authn come from the matrix; a few
/// classes (stored/DOM XSS, XXE, CORS, mass assignment, …) have no automatic
/// oracle yet and stay suspected.
pub(crate) const AUTO_PROVE_CLASSES: &[&str] =
    &["xss", "sqli", "command_injection", "rce", "path_traversal", "open_redirect", "crlf", "ssrf"];

impl Service {
    /// Proves every suspected, unproven finding whose class has an oracle.
    /// Bounded so an automatic pass can't run unboundedly many sends.
    pub async fn auto_prove(&self, actor: &Actor) -> Result<ProveSweep> {
        let mut sweep = ProveSweep::default();
        let findings = self.finding_list(Some("suspected"))?;
        for f in findings.into_iter().take(80) {
            let class = f["vuln_class"].as_str().unwrap_or_default();
            if !AUTO_PROVE_CLASSES.contains(&class) && !matches!(class, "idor" | "bfla") {
                continue;
            }
            let Some(id) = f["id"].as_i64() else { continue };
            let r = self.finding_prove(actor, id).await?;
            sweep.attempted += 1;
            if r.proven {
                sweep.proven += 1;
            }
            sweep.results.push(r);
        }
        self.audit(
            &actor.id(),
            "auto_prove",
            serde_json::json!({ "attempted": sweep.attempted, "proven": sweep.proven }),
            "ok",
        )?;
        Ok(sweep)
    }

    /// Tries to prove one finding. Picks oracles by class, rebuilds the request
    /// at the finding's insertion point (from its title, else candidate
    /// points), and runs each until one proves. Returns the outcome; the proof
    /// and the finding's `proven` status are stored by `proof_run`.
    pub async fn finding_prove(&self, actor: &Actor, id: i64) -> Result<FindingProve> {
        let f = self.finding_get(id)?;
        let class = f["vuln_class"].as_str().unwrap_or_default().to_string();
        let mut out = FindingProve {
            finding_id: id,
            vuln_class: class.clone(),
            proven: false,
            reasons: vec![],
            oracle: None,
            proof_id: None,
        };
        if f["status"].as_str() == Some("proven") {
            out.proven = true;
            out.reasons = vec!["already proven".into()];
            return Ok(out);
        }
        let evidence: Vec<i64> = serde_json::from_value(f["evidence"].clone()).unwrap_or_default();
        let Some(&baseline) = evidence.first() else {
            out.reasons = vec!["the finding has no evidence exchange to work from".into()];
            return Ok(out);
        };

        // IDOR/BFLA use the differential oracle with another identity.
        if matches!(class.as_str(), "idor" | "bfla") {
            return self.prove_differential_finding(actor, id, baseline, &class).await;
        }

        let Ok(ex) = self.exchange_raw(baseline) else {
            out.reasons = vec![format!("evidence exchange {baseline} is gone")];
            return Ok(out);
        };
        let raw = String::from_utf8_lossy(&ex.request).into_owned();
        let all_points = points(&raw);
        // The exact point from the finding's title "(… (query q))", else a few
        // likely candidates the class can use.
        let label = f["title"].as_str().and_then(parse_point_label);
        let targeted: Vec<Point> = match label.as_deref().and_then(|l| find_point(&all_points, l)) {
            Some(p) => vec![p],
            None => candidate_points(&all_points),
        };

        let mut last = vec!["no oracle produced a proof".to_string()];
        for point in &targeted {
            for mut req in prove_requests(&class, baseline, &raw, point) {
                req.finding_id = Some(id);
                match self.proof_run(actor, req).await {
                    Ok(ProofResult::Completed { proven, reasons, proof_id, oracle, .. }) => {
                        if proven {
                            out.proven = true;
                            out.reasons = reasons;
                            out.oracle = Some(oracle);
                            out.proof_id = Some(proof_id);
                            return Ok(out);
                        }
                        last = reasons;
                    }
                    Ok(ProofResult::Denied { reasons }) | Ok(ProofResult::PendingApproval { reasons, .. }) => {
                        out.reasons = reasons;
                        return Ok(out);
                    }
                    // A bad template for this point (e.g. no insertion possible): try the next.
                    Err(_) => continue,
                }
            }
        }
        out.reasons = last;
        Ok(out)
    }

    /// Differential-oracle proof for an IDOR/BFLA finding: re-send the recorded
    /// request as the owner and as another, non-admin identity.
    async fn prove_differential_finding(
        &self,
        actor: &Actor,
        id: i64,
        baseline: i64,
        class: &str,
    ) -> Result<FindingProve> {
        let mut out = FindingProve {
            finding_id: id,
            vuln_class: class.into(),
            proven: false,
            reasons: vec![],
            oracle: None,
            proof_id: None,
        };
        let ex = self.exchange_raw(baseline);
        let owner = ex.ok().and_then(|e| e.summary.identity);
        let idents = self.identity_list().unwrap_or_default();
        let attacker = idents
            .iter()
            .find(|i| Some(i.name.as_str()) != owner.as_deref() && !i.role.to_ascii_lowercase().contains("admin"));
        let Some(attacker) = attacker else {
            out.reasons = vec!["no second, non-admin identity to try as the attacker".into()];
            return Ok(out);
        };
        let req = ProofRequest {
            oracle: "differential_authz".into(),
            exchange_id: Some(baseline),
            attacker: Some(attacker.name.clone()),
            owner,
            finding_id: Some(id),
            ..Default::default()
        };
        match self.proof_run(actor, req).await {
            Ok(ProofResult::Completed { proven, reasons, proof_id, oracle, .. }) => {
                out.proven = proven;
                out.reasons = reasons;
                if proven {
                    out.oracle = Some(oracle);
                    out.proof_id = Some(proof_id);
                }
            }
            Ok(ProofResult::Denied { reasons }) | Ok(ProofResult::PendingApproval { reasons, .. }) => {
                out.reasons = reasons
            }
            Err(e) => out.reasons = vec![e.to_string()],
        }
        Ok(out)
    }
}

/// The ordered oracle attempts for a class at one insertion point.
fn prove_requests(class: &str, baseline: i64, raw: &str, point: &Point) -> Vec<ProofRequest> {
    let base = ProofRequest { exchange_id: Some(baseline), ..Default::default() };
    let mut out = Vec::new();
    let orig = &point.original;
    match class {
        "xss" | "reflected_input" => {
            let placeholder = match point.kind {
                PointKind::Query | PointKind::Form | PointKind::Cookie | PointKind::Nested | PointKind::Name => {
                    "{{xss_url}}"
                }
                _ => "{{xss}}",
            };
            if let Some(raw) = tmpl(raw, point, placeholder) {
                out.push(ProofRequest { oracle: "reflection".into(), raw: Some(raw), ..base.clone() });
            }
        }
        "sqli" => {
            // Error-based first (one quote vs a benign change), then a boolean
            // true/false split, then time-based.
            if let (Some(q1), Some(q2), Some(benign)) = (
                value_raw(raw, point, &format!("{orig}'")),
                value_raw(raw, point, &format!("{orig}' -- ")),
                value_raw(raw, point, &format!("{orig}pmz")),
            ) {
                out.push(ProofRequest {
                    oracle: "sql_error".into(),
                    raws: vec![raw.to_string(), q1, q2, benign],
                    ..base.clone()
                });
            }
            for (t, f) in BOOLEAN_PAIRS {
                if let (Some(tr), Some(fr)) =
                    (value_raw(raw, point, &format!("{orig}{t}")), value_raw(raw, point, &format!("{orig}{f}")))
                {
                    out.push(ProofRequest {
                        oracle: "boolean_injection".into(),
                        raws: vec![raw.to_string(), tr, fr],
                        ..base.clone()
                    });
                }
            }
            for s in SQL_SLEEPS {
                if let Some(pr) = value_raw(raw, point, &format!("{orig}{s}")) {
                    out.push(ProofRequest {
                        oracle: "timing".into(),
                        baseline_raw: Some(raw.to_string()),
                        payload_raw: Some(pr),
                        samples: Some(6),
                        min_effect_ms: Some(2000.0),
                        ..base.clone()
                    });
                }
            }
        }
        "command_injection" | "rce" => {
            for s in CMD_SLEEPS {
                if let Some(pr) = value_raw(raw, point, &format!("{orig}{s}")) {
                    out.push(ProofRequest {
                        oracle: "timing".into(),
                        baseline_raw: Some(raw.to_string()),
                        payload_raw: Some(pr),
                        samples: Some(6),
                        min_effect_ms: Some(2000.0),
                        ..base.clone()
                    });
                }
            }
        }
        "path_traversal" => {
            let control = value_raw(raw, point, &format!("../../../../../../../../etc/pmnope{}", SENTINEL));
            let file = value_raw(raw, point, "../../../../../../../../etc/passwd");
            if let (Some(control), Some(file)) = (control, file) {
                out.push(ProofRequest {
                    oracle: "path_traversal".into(),
                    raws: vec![raw.to_string(), control, file],
                    markers: vec!["root:".into()],
                    ..base.clone()
                });
            }
        }
        "open_redirect" => {
            if let Some(raw) = tmpl(raw, point, "http://{{marker}}.proxymind-oast.invalid/") {
                out.push(ProofRequest {
                    oracle: "marker".into(),
                    raw: Some(raw),
                    marker_kind: Some("redirect".into()),
                    ..base.clone()
                });
            }
        }
        "crlf" => {
            if let Some(raw) = tmpl(raw, point, "a%0d%0aX-Pm-{{marker}}:%201") {
                out.push(ProofRequest {
                    oracle: "marker".into(),
                    raw: Some(raw),
                    marker_kind: Some("crlf".into()),
                    ..base.clone()
                });
            }
        }
        "ssrf" => {
            if let Some(raw) = tmpl(raw, point, "{{oast}}") {
                out.push(ProofRequest { oracle: "oast".into(), raw: Some(raw), ..base.clone() });
            }
        }
        _ => {}
    }
    out
}

/// (true, false) suffixes appended to the point's original value. Each closes
/// a different quoting/LIKE context so the condition reaches the WHERE clause.
const BOOLEAN_PAIRS: &[(&str, &str)] = &[
    ("%' AND '1'='1' -- ", "%' AND '1'='2' -- "),
    ("' AND '1'='1' -- ", "' AND '1'='2' -- "),
    (" AND 1=1 -- ", " AND 1=2 -- "),
    ("' AND '1'='1", "' AND '1'='2"),
];
/// Time-based payloads (suffixes); SLEEP(3) delays a vulnerable query ~3 s.
const SQL_SLEEPS: &[&str] =
    &["%' AND SLEEP(3) -- ", "' AND SLEEP(3) -- ", " AND SLEEP(3) -- ", "';SELECT SLEEP(3) -- "];
const CMD_SLEEPS: &[&str] = &["; sleep 3", "| sleep 3", "`sleep 3`", "$(sleep 3)", "& sleep 3"];

/// Injects a value at `point` and returns the request as a string (the value
/// is percent-encoded by `inject` where the context needs it).
fn value_raw(raw: &str, point: &Point, value: &str) -> Option<String> {
    inject(raw, point, value).map(|v| String::from_utf8_lossy(&v).into_owned())
}

/// Injects a sentinel at `point`, then replaces it with `placeholder` on the
/// whole request string, so braces in the placeholder survive encoding.
fn tmpl(raw: &str, point: &Point, placeholder: &str) -> Option<String> {
    let s = String::from_utf8_lossy(&inject(raw, point, SENTINEL)?).into_owned();
    s.contains(SENTINEL).then(|| s.replace(SENTINEL, placeholder))
}

/// The point named in parentheses at the end of a finding title, e.g.
/// "SQL injection in GET /x (query id)" → "query id". Spans nested parens too,
/// e.g. "(nested ctx.category (base64))" → "nested ctx.category (base64)".
fn parse_point_label(title: &str) -> Option<String> {
    let close = title.rfind(')')?;
    let open = title.find('(')?;
    (open < close).then(|| title[open + 1..close].to_ascii_lowercase())
}

/// The point whose "kind name" matches `label`.
fn find_point(all: &[Point], label: &str) -> Option<Point> {
    all.iter().find(|p| format!("{:?} {}", p.kind, p.name).to_ascii_lowercase() == label).cloned()
}

/// Likely insertion points to try when a finding names none: values of query,
/// form, JSON, path and nested parameters (not names or headers), capped.
fn candidate_points(all: &[Point]) -> Vec<Point> {
    all.iter()
        .filter(|p| {
            matches!(p.kind, PointKind::Query | PointKind::Form | PointKind::Json | PointKind::Path | PointKind::Nested)
        })
        .take(6)
        .cloned()
        .collect()
}
