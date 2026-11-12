//! Proof oracles: the checks that turn "the model thinks so" into "ProxyMind
//! verified it". A finding is only `proven` when an oracle says so.
//!
//! This crate holds the decision logic and statistics; the service layer
//! sends the requests and feeds the results in.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Verdict {
    pub proven: bool,
    /// high, medium or low
    pub confidence: &'static str,
    pub reasons: Vec<String>,
}

// ---------------------------------------------------------------- authz --

/// Inputs for the differential authorization oracle.
#[derive(Debug, Clone)]
pub struct DifferentialInputs {
    pub owner: String,
    pub attacker: String,
    pub attacker_role: String,
    pub owner_role: String,
    /// The owner's two baseline statuses.
    pub owner_statuses: [Option<u16>; 2],
    pub attacker_status: Option<u16>,
    pub anonymous_status: Option<u16>,
    /// Similarity of the attacker's response to the owner's (noise ignored).
    pub similarity: f64,
    /// Owner-identifying values (name, email) found in the attacker's response.
    pub markers_found: Vec<String>,
}

/// `Some(401)` → "401", `None` → "no response".
pub fn status_text(s: Option<u16>) -> String {
    s.map_or_else(|| "no response".to_string(), |x| x.to_string())
}

fn ok(s: Option<u16>) -> bool {
    s.is_some_and(|s| (200..300).contains(&s))
}

fn refused(s: Option<u16>) -> bool {
    s.is_some_and(|s| matches!(s, 401 | 403 | 404) || (300..400).contains(&s))
}

/// Proves broken access control (IDOR/BOLA or function-level) when:
/// the owner's request works; an anonymous request is refused (so the
/// resource *is* protected); the attacker, a different and not more
/// privileged identity, gets the same data.
pub fn differential_authz(i: &DifferentialInputs) -> Verdict {
    let mut reasons = Vec::new();
    let fail = |r: String, reasons: &mut Vec<String>| {
        reasons.push(r);
        false
    };
    let mut proven = true;
    if i.owner == i.attacker {
        proven = fail("owner and attacker are the same identity".into(), &mut reasons);
    }
    if i.attacker_role.to_ascii_lowercase().contains("admin") && !i.owner_role.to_ascii_lowercase().contains("admin") {
        proven = fail(format!("{} is an admin; access is expected", i.attacker), &mut reasons);
    }
    if !(ok(i.owner_statuses[0]) && ok(i.owner_statuses[1])) {
        proven = fail(
            format!(
                "owner request did not succeed twice ({}, {})",
                status_text(i.owner_statuses[0]),
                status_text(i.owner_statuses[1])
            ),
            &mut reasons,
        );
    }
    if !refused(i.anonymous_status) {
        proven = fail(
            format!("anonymous request was not refused ({}); the data may be public", status_text(i.anonymous_status)),
            &mut reasons,
        );
    }
    if !ok(i.attacker_status) {
        proven = fail(format!("{} was refused ({})", i.attacker, status_text(i.attacker_status)), &mut reasons);
    }
    if i.similarity < 0.9 {
        proven = fail(
            format!("{}'s response differs from the owner's ({:.0}% similar)", i.attacker, i.similarity * 100.0),
            &mut reasons,
        );
    }
    if proven {
        reasons.push(format!(
            "{} ({}) received {}'s data ({:.0}% similar, noise ignored) while anonymous access is refused ({})",
            i.attacker,
            i.attacker_role,
            i.owner,
            i.similarity * 100.0,
            status_text(i.anonymous_status)
        ));
        if !i.markers_found.is_empty() {
            reasons.push(format!(
                "the response contains {}'s identifying values: {}",
                i.owner,
                i.markers_found.join(", ")
            ));
        }
    }
    let confidence = if !proven {
        "low"
    } else if !i.markers_found.is_empty() || i.owner_role != i.attacker_role {
        "high"
    } else {
        "medium"
    };
    Verdict { proven, confidence, reasons }
}

// --------------------------------------------------------------- timing --

pub fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut v = xs.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    let n = v.len();
    if n % 2 == 1 { v[n / 2] } else { (v[n / 2 - 1] + v[n / 2]) / 2.0 }
}

/// Standard normal survival function (1 - CDF), via erfc.
fn normal_sf(z: f64) -> f64 {
    0.5 * erfc(z / std::f64::consts::SQRT_2)
}

/// Complementary error function (Numerical Recipes approximation,
/// fractional error < 1.2e-7).
fn erfc(x: f64) -> f64 {
    let z = x.abs();
    let t = 1.0 / (1.0 + 0.5 * z);
    let r = t
        * (-z * z - 1.265_512_23
            + t * (1.000_023_68
                + t * (0.374_091_96
                    + t * (0.096_784_18
                        + t * (-0.186_288_06
                            + t * (0.278_868_07
                                + t * (-1.135_203_98
                                    + t * (1.488_515_87 + t * (-0.822_152_23 + t * 0.170_872_77)))))))))
            .exp();
    if x >= 0.0 { r } else { 2.0 - r }
}

/// One-sided Mann-Whitney U test: p-value that `treated` is not larger than
/// `baseline`. Normal approximation with tie and continuity correction.
pub fn mann_whitney_greater(baseline: &[f64], treated: &[f64]) -> f64 {
    let (n1, n2) = (treated.len() as f64, baseline.len() as f64);
    if n1 == 0.0 || n2 == 0.0 {
        return 1.0;
    }
    let mut all: Vec<(f64, bool)> =
        treated.iter().map(|&x| (x, true)).chain(baseline.iter().map(|&x| (x, false))).collect();
    all.sort_by(|a, b| a.0.total_cmp(&b.0));
    let n = all.len();
    let mut ranks = vec![0.0; n];
    let mut tie_term = 0.0;
    let mut i = 0;
    while i < n {
        let mut j = i;
        while j + 1 < n && all[j + 1].0 == all[i].0 {
            j += 1;
        }
        let r = (i + j) as f64 / 2.0 + 1.0;
        for k in ranks.iter_mut().take(j + 1).skip(i) {
            *k = r;
        }
        let t = (j - i + 1) as f64;
        tie_term += t * t * t - t;
        i = j + 1;
    }
    let r1: f64 = all.iter().zip(&ranks).filter(|(x, _)| x.1).map(|(_, r)| r).sum();
    let u1 = r1 - n1 * (n1 + 1.0) / 2.0;
    let mean = n1 * n2 / 2.0;
    let nn = n1 + n2;
    let var = n1 * n2 / 12.0 * ((nn + 1.0) - tie_term / (nn * (nn - 1.0)));
    if var <= 0.0 {
        return 1.0;
    }
    let z = (u1 - mean - 0.5) / var.sqrt();
    normal_sf(z)
}

/// Time-based injection is proven when payload responses are slower than
/// baseline responses with p < 0.01 *and* the median slowdown is at least
/// `min_effect_ms` (so tiny but significant jitter doesn't count).
pub fn timing(baseline_ms: &[f64], payload_ms: &[f64], min_effect_ms: f64) -> (Verdict, f64, f64, f64) {
    let p = mann_whitney_greater(baseline_ms, payload_ms);
    let (mb, mp) = (median(baseline_ms), median(payload_ms));
    let effect = mp - mb;
    let enough = baseline_ms.len() >= 5 && payload_ms.len() >= 5;
    let proven = enough && p < 0.01 && effect >= min_effect_ms;
    let mut reasons = vec![format!(
        "median {mb:.0} ms baseline vs {mp:.0} ms with payload (+{effect:.0} ms); Mann-Whitney p = {p:.2e}; {} + {} samples, interleaved",
        baseline_ms.len(),
        payload_ms.len()
    )];
    if !enough {
        reasons.push("need at least 5 samples of each".into());
    } else if p >= 0.01 {
        reasons.push("difference is not statistically significant (p ≥ 0.01)".into());
    } else if effect < min_effect_ms {
        reasons.push(format!("slowdown is below the required {min_effect_ms:.0} ms"));
    }
    let confidence = if !proven {
        "low"
    } else if p < 1e-4 {
        "high"
    } else {
        "medium"
    };
    (Verdict { proven, confidence, reasons }, p, mb, mp)
}

// ----------------------------------------------------------------- oast --

pub fn oast(token: &str, interactions: usize, first: Option<&str>) -> Verdict {
    if interactions > 0 {
        Verdict {
            proven: true,
            confidence: "high",
            reasons: vec![format!(
                "the target made {interactions} out-of-band request(s) carrying the unique token {token}{}",
                first.map(|f| format!("; first: {f}")).unwrap_or_default()
            )],
        }
    } else {
        Verdict {
            proven: false,
            confidence: "low",
            reasons: vec![format!("no out-of-band interaction with token {token} was received in time")],
        }
    }
}

// ----------------------------------------------------------- reflection --

/// Name of the JavaScript function a reflection payload calls.
pub const XSS_BINDING: &str = "pmProof";

/// Placeholders a reflection request may contain.
pub const XSS_PLACEHOLDERS: [&str; 3] = ["{{xss}}", "{{xss_url}}", "{{token}}"];

/// The default payload: calls the binding with the token when it runs.
pub fn xss_payload(token: &str) -> String {
    format!("<img src=x onerror={XSS_BINDING}('{token}')>")
}

/// Percent-encodes everything but unreserved characters (RFC 3986).
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Fills a request template: `{{xss}}` → the default payload as is,
/// `{{xss_url}}` → the payload percent-encoded (for query strings and form
/// bodies), `{{token}}` → just the token, for a custom payload that calls
/// `pmProof('{{token}}')` or `alert('{{token}}')` itself.
pub fn fill_xss_template(raw: &str, token: &str) -> String {
    let payload = xss_payload(token);
    raw.replace("{{xss_url}}", &percent_encode(&payload)).replace("{{xss}}", &payload).replace("{{token}}", token)
}

/// What the reflection oracle saw.
#[derive(Debug, Clone, Default)]
pub struct ReflectionInputs {
    pub token: String,
    pub status: Option<u16>,
    pub content_type: Option<String>,
    /// The token appears in the (decoded) response body.
    pub token_in_body: bool,
    /// The response body contains the payload exactly as sent (unencoded).
    pub payload_in_body: bool,
    /// Arguments the page passed to the binding.
    pub binding_calls: Vec<String>,
    /// Messages of JavaScript dialogs the page opened.
    pub dialogs: Vec<String>,
    pub blocked_requests: usize,
    pub rendered: bool,
}

/// Cross-site scripting is proven only when script *ran* in a browser and
/// handed back the unique token: through the binding, or in a dialog.
/// Reflection alone (even unencoded) is never enough: CSP, the content type
/// or the HTML context may stop it from running.
pub fn reflection(i: &ReflectionInputs) -> Verdict {
    let by_binding = i.binding_calls.iter().any(|c| c == &i.token);
    let by_dialog = i.dialogs.iter().any(|d| d.contains(&i.token));
    // The content type comes from the target: keep it short and printable.
    let ct: String = match &i.content_type {
        Some(c) => c.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(80).collect(),
        None => "no content type".into(),
    };
    let mut reasons = Vec::new();
    if by_binding || by_dialog {
        reasons.push(format!(
            "a headless browser rendering the recorded response ({}, {ct}) ran the injected script: it {} with the \
             unique token {}",
            status_text(i.status),
            if by_binding { format!("called {XSS_BINDING}()") } else { "opened a dialog".into() },
            i.token
        ));
        reasons.push(format!(
            "rendered offline from the recorded response; {} other request(s) from the page were blocked",
            i.blocked_requests
        ));
        return Verdict { proven: true, confidence: "high", reasons };
    }
    if !i.rendered {
        reasons.push("the response could not be rendered".into());
    } else if !i.token_in_body {
        reasons.push(format!(
            "the token {} is not in the response ({}, {ct}); nothing reflected",
            i.token,
            status_text(i.status)
        ));
    } else if !i.payload_in_body {
        reasons.push(format!(
            "the token is reflected but the payload is not intact (encoded or filtered); no script ran ({ct})"
        ));
    } else {
        reasons.push(format!(
            "the payload is reflected unencoded but did not run in the browser ({ct}); check the content type, \
             Content-Security-Policy and the HTML context, or try a payload for that context with {{{{token}}}}"
        ));
    }
    if !i.binding_calls.is_empty() || !i.dialogs.is_empty() {
        reasons.push(format!(
            "the page ran script without the token ({} binding call(s), {} dialog(s)); ignored",
            i.binding_calls.len(),
            i.dialogs.len()
        ));
    }
    Verdict { proven: false, confidence: "low", reasons }
}

// ------------------------------------------------------- boolean inject --

/// Inputs for the boolean-condition oracle (blind SQL/NoSQL injection).
///
/// The service sends, twice, a request whose injected value asserts a
/// tautology (true) and one that asserts a contradiction (false), plus the
/// untouched baseline, and measures response similarity with noise ignored
/// (`pm_diff`). Injection is proven when the true condition returns the
/// normal page while the false condition returns a clearly different one,
/// and the pattern repeats.
#[derive(Debug, Clone, Default)]
pub struct BooleanInputs {
    /// Similarity of the true-condition response to the baseline.
    pub true_similarity: f64,
    /// Similarity of the false-condition response to the baseline.
    pub false_similarity: f64,
    /// Similarity of the true-condition response to the false-condition one.
    pub true_false_similarity: f64,
    pub status_true: Option<u16>,
    pub status_false: Option<u16>,
    /// A second round produced the same true/false split.
    pub repeated_consistent: bool,
}

/// Proven when a tautology returns the baseline page (the query ran and
/// matched) while a contradiction returns a clearly different page (it ran
/// and did not), consistently across two rounds. A page that echoes its
/// input but does not evaluate it fails: true and false then look alike.
pub fn boolean_injection(i: &BooleanInputs) -> Verdict {
    let mut reasons = Vec::new();
    let fail = |r: String, reasons: &mut Vec<String>| {
        reasons.push(r);
        false
    };
    let mut proven = true;
    if !ok(i.status_true) {
        proven =
            fail(format!("the true-condition request did not succeed ({})", status_text(i.status_true)), &mut reasons);
    }
    if i.true_similarity < 0.9 {
        proven = fail(
            format!("the true condition did not return the normal page ({:.0}% similar)", i.true_similarity * 100.0),
            &mut reasons,
        );
    }
    if i.true_false_similarity > 0.85 {
        proven = fail(
            format!(
                "true and false conditions returned near-identical pages ({:.0}% similar); the input is not evaluated",
                i.true_false_similarity * 100.0
            ),
            &mut reasons,
        );
    }
    if !i.repeated_consistent {
        proven = fail("the true/false split did not repeat; likely noise".into(), &mut reasons);
    }
    if proven {
        reasons.push(format!(
            "a tautology returned the normal page ({:.0}% similar to baseline) while a contradiction returned a \
             different page ({:.0}% similar to the tautology, noise ignored); repeated",
            i.true_similarity * 100.0,
            i.true_false_similarity * 100.0
        ));
    }
    let confidence = if !proven {
        "low"
    } else if i.true_false_similarity <= 0.6 && i.false_similarity < 0.9 {
        "high"
    } else {
        "medium"
    };
    Verdict { proven, confidence, reasons }
}

// ----------------------------------------------------- error-based inject --

/// Inputs for the error-based SQL-injection oracle. The service sends the
/// baseline, two different quote payloads and one benign (quote-free) change,
/// and reports whether each response carried a database error signature.
#[derive(Debug, Clone, Default)]
pub struct SqlErrorInputs {
    /// The untouched baseline shows no database error.
    pub control_clean: bool,
    /// A single quote produced a database error.
    pub quote_error: bool,
    /// A second, different quote payload also produced one (consistency).
    pub second_quote_error: bool,
    /// A benign, quote-free change did NOT: the error is tied to the quote,
    /// not to any change — so the endpoint does not just fail on everything.
    pub benign_clean: bool,
}

/// Proven when a quote (and only a quote) breaks the query into a database
/// error, consistently, while the baseline and a benign change stay clean.
pub fn sql_error(i: &SqlErrorInputs) -> Verdict {
    let mut reasons = Vec::new();
    let fail = |r: String, reasons: &mut Vec<String>| {
        reasons.push(r);
        false
    };
    let mut proven = true;
    if !i.control_clean {
        proven =
            fail("the baseline already shows a database error; the endpoint errors on its own".into(), &mut reasons);
    }
    if !(i.quote_error && i.second_quote_error) {
        proven = fail("a quote did not consistently produce a database error".into(), &mut reasons);
    }
    if !i.benign_clean {
        proven = fail("a quote-free change also errored; the error is not tied to the quote".into(), &mut reasons);
    }
    if proven {
        reasons.push(
            "a single quote broke the query into a database error (twice), while the baseline and a quote-free change \
             did not: the input is used inside a SQL statement"
                .into(),
        );
    }
    Verdict { proven, confidence: if proven { "high" } else { "low" }, reasons }
}

// --------------------------------------------------------- path traversal --

/// Inputs for the path-traversal oracle.
#[derive(Debug, Clone, Default)]
pub struct TraversalInputs {
    /// Known files whose expected marker appeared, e.g. "/etc/passwd: root:".
    pub markers_found: Vec<String>,
    /// A bogus file name (same request shape) did NOT return a file: the
    /// endpoint does not just echo whatever it is given.
    pub control_clean: bool,
    /// The traversal responses differ from the untouched baseline.
    pub differs_from_baseline: bool,
}

/// Proven when at least one known file is read back by its marker, a bogus
/// name reads nothing (so the endpoint is not echoing its input), and the
/// traversal response differs from the baseline. Two files raise confidence.
pub fn path_traversal(i: &TraversalInputs) -> Verdict {
    let mut reasons = Vec::new();
    let fail = |r: String, reasons: &mut Vec<String>| {
        reasons.push(r);
        false
    };
    let mut proven = true;
    if i.markers_found.is_empty() {
        proven = fail("no known file was read back".into(), &mut reasons);
    }
    if !i.control_clean {
        proven = fail(
            "a bogus file name also \"worked\"; the endpoint echoes its input, not file contents".into(),
            &mut reasons,
        );
    }
    if !i.differs_from_baseline {
        proven = fail("the traversal response matches the untouched baseline".into(), &mut reasons);
    }
    if proven {
        reasons.push(format!(
            "reading {} worked while a bogus file name did not: {}",
            if i.markers_found.len() == 1 { "a known file" } else { "two known files" },
            i.markers_found.join("; ")
        ));
    }
    let confidence = if !proven {
        "low"
    } else if i.markers_found.len() >= 2 {
        "high"
    } else {
        "medium"
    };
    Verdict { proven, confidence, reasons }
}

// --------------------------------------------------------------- marker ---

/// Inputs for the marker oracle: a fresh random value is injected and the
/// service decides whether it landed in the one dangerous place (the
/// redirect target's host, an injected response header, a reflected
/// absolute URL), and that it was not already there before injection.
#[derive(Debug, Clone, Default)]
pub struct MarkerInputs {
    /// What is being proven, e.g. "open redirect", "CRLF header injection".
    pub label: String,
    pub marker: String,
    /// The marker reached the dangerous place (service-decided).
    pub hit: bool,
    /// The marker was present without being injected (false-positive guard).
    pub control_hit: bool,
    /// Short, printable evidence from the target (untrusted).
    pub detail: String,
}

/// Proven when a fresh unique marker reaches the dangerous place and was not
/// already there in the control. Covers open redirect, CRLF header
/// injection and Host-header injection.
pub fn marker(i: &MarkerInputs) -> Verdict {
    let detail: String = i.detail.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(160).collect();
    if i.hit && !i.control_hit {
        return Verdict {
            proven: true,
            confidence: "high",
            reasons: vec![format!("{}: the unique marker {} reached the target: {detail}", i.label, i.marker)],
        };
    }
    let reason = if !i.hit {
        format!("{}: the marker {} did not reach the dangerous place ({detail})", i.label, i.marker)
    } else {
        format!("{}: the marker was already present without injection; inconclusive", i.label)
    };
    Verdict { proven: false, confidence: "low", reasons: vec![reason] }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> DifferentialInputs {
        DifferentialInputs {
            owner: "alice".into(),
            attacker: "bob".into(),
            attacker_role: "user".into(),
            owner_role: "user".into(),
            owner_statuses: [Some(200), Some(200)],
            attacker_status: Some(200),
            anonymous_status: Some(401),
            similarity: 1.0,
            markers_found: vec!["alice@x".into()],
        }
    }

    #[test]
    fn differential_proves_only_with_all_conditions() {
        assert!(differential_authz(&inputs()).proven);
        assert_eq!(differential_authz(&inputs()).confidence, "high");
        let public = DifferentialInputs { anonymous_status: Some(200), ..inputs() };
        assert!(!differential_authz(&public).proven, "public data is not a bug");
        let admin = DifferentialInputs { attacker: "root".into(), attacker_role: "admin".into(), ..inputs() };
        assert!(!differential_authz(&admin).proven, "admins may read");
        let refused = DifferentialInputs { attacker_status: Some(403), ..inputs() };
        assert!(!differential_authz(&refused).proven);
        let own_data = DifferentialInputs { similarity: 0.3, ..inputs() };
        assert!(!differential_authz(&own_data).proven);
    }

    #[test]
    fn mann_whitney_behaves() {
        let base = [100.0, 110.0, 95.0, 105.0, 102.0, 98.0, 101.0, 99.0];
        let slow = [1300.0, 1310.0, 1295.0, 1305.0, 1302.0, 1298.0, 1301.0, 1299.0];
        assert!(mann_whitney_greater(&base, &slow) < 0.001);
        assert!(mann_whitney_greater(&slow, &base) > 0.99);
        let same = mann_whitney_greater(&base, &base);
        assert!(same > 0.3, "{same}");
        assert!((erfc(0.0) - 1.0).abs() < 1e-7 && (erfc(1.0) - 0.157_299_2).abs() < 1e-6);
    }

    #[test]
    fn timing_needs_significance_and_effect() {
        let base = [100.0, 110.0, 95.0, 105.0, 102.0, 98.0];
        let slow = [1300.0, 1310.0, 1295.0, 1305.0, 1302.0, 1298.0];
        assert!(timing(&base, &slow, 500.0).0.proven);
        let jitter = [130.0, 140.0, 125.0, 135.0, 132.0, 128.0];
        assert!(!timing(&base, &jitter, 500.0).0.proven, "significant but tiny");
        assert!(!timing(&base[..3], &slow[..3], 500.0).0.proven, "too few samples");
    }

    #[test]
    fn xss_templates_fill_and_encode() {
        let t = "abc123";
        assert_eq!(xss_payload(t), "<img src=x onerror=pmProof('abc123')>");
        assert_eq!(
            fill_xss_template("GET /s?q={{xss_url}} HTTP/1.1", t),
            "GET /s?q=%3Cimg%20src%3Dx%20onerror%3DpmProof%28%27abc123%27%29%3E HTTP/1.1"
        );
        assert_eq!(fill_xss_template("q={{xss}}", t), "q=<img src=x onerror=pmProof('abc123')>");
        assert_eq!(fill_xss_template("\"><svg onload=alert('{{token}}')>", t), "\"><svg onload=alert('abc123')>");
        assert_eq!(percent_encode("a-b_c.d~e f/é"), "a-b_c.d~e%20f%2F%C3%A9");
    }

    #[test]
    fn reflection_needs_the_token_from_running_script() {
        let base = ReflectionInputs {
            token: "tok".into(),
            status: Some(200),
            content_type: Some("text/html".into()),
            token_in_body: true,
            payload_in_body: true,
            rendered: true,
            ..Default::default()
        };
        let ran = ReflectionInputs { binding_calls: vec!["tok".into()], ..base.clone() };
        assert!(reflection(&ran).proven);
        assert_eq!(reflection(&ran).confidence, "high");
        let dialog = ReflectionInputs { dialogs: vec!["tok".into()], ..base.clone() };
        assert!(reflection(&dialog).proven);

        // Reflected but not run (CSP, text/plain, wrong context): not proven.
        let v = reflection(&base);
        assert!(!v.proven && v.reasons[0].contains("did not run"), "{v:?}");
        // Encoded reflection.
        let enc = ReflectionInputs { payload_in_body: false, ..base.clone() };
        assert!(reflection(&enc).reasons[0].contains("encoded"));
        // The page's own script calling the binding or alert() with other values.
        let noise =
            ReflectionInputs { binding_calls: vec!["other".into()], dialogs: vec!["hi".into()], ..base.clone() };
        let v = reflection(&noise);
        assert!(!v.proven && v.reasons.iter().any(|r| r.contains("without the token")), "{v:?}");
        // A token prefix is not the token.
        let prefix = ReflectionInputs { binding_calls: vec!["to".into()], ..base };
        assert!(!reflection(&prefix).proven);
    }

    #[test]
    fn boolean_injection_needs_a_consistent_split() {
        let base = BooleanInputs {
            true_similarity: 0.99,
            false_similarity: 0.4,
            true_false_similarity: 0.4,
            status_true: Some(200),
            status_false: Some(200),
            repeated_consistent: true,
        };
        assert!(boolean_injection(&base).proven);
        assert_eq!(boolean_injection(&base).confidence, "high");
        // Echoes its input: true and false look alike → not evaluated.
        let echo = BooleanInputs { true_false_similarity: 0.98, false_similarity: 0.98, ..base.clone() };
        assert!(!boolean_injection(&echo).proven);
        // Did not repeat → noise.
        let flaky = BooleanInputs { repeated_consistent: false, ..base.clone() };
        assert!(!boolean_injection(&flaky).proven);
        // True condition did not return the normal page.
        let broken = BooleanInputs { true_similarity: 0.3, ..base };
        assert!(!boolean_injection(&broken).proven);
    }

    #[test]
    fn sql_error_needs_a_quote_specific_consistent_error() {
        let good =
            SqlErrorInputs { control_clean: true, quote_error: true, second_quote_error: true, benign_clean: true };
        assert!(sql_error(&good).proven);
        assert_eq!(sql_error(&good).confidence, "high");
        // Errors on its own.
        assert!(!sql_error(&SqlErrorInputs { control_clean: false, ..good.clone() }).proven);
        // Errors on a quote-free change too → not quote-specific.
        assert!(!sql_error(&SqlErrorInputs { benign_clean: false, ..good.clone() }).proven);
        // The quote didn't error consistently.
        assert!(!sql_error(&SqlErrorInputs { second_quote_error: false, ..good }).proven);
    }

    #[test]
    fn path_traversal_needs_a_file_and_a_clean_control() {
        let one = TraversalInputs {
            markers_found: vec!["/etc/passwd: root:".into()],
            control_clean: true,
            differs_from_baseline: true,
        };
        assert!(path_traversal(&one).proven);
        assert_eq!(path_traversal(&one).confidence, "medium");
        let two = TraversalInputs {
            markers_found: vec!["/etc/passwd: root:".into(), "/etc/hostname: host".into()],
            ..one.clone()
        };
        assert_eq!(path_traversal(&two).confidence, "high");
        // Echoes anything → control also "found".
        let echoes = TraversalInputs { control_clean: false, ..one.clone() };
        assert!(!path_traversal(&echoes).proven);
        // Nothing read back.
        let none = TraversalInputs { markers_found: vec![], ..one };
        assert!(!path_traversal(&none).proven);
    }

    #[test]
    fn marker_needs_a_fresh_hit() {
        let hit = MarkerInputs {
            label: "open redirect".into(),
            marker: "pmabc".into(),
            hit: true,
            control_hit: false,
            detail: "Location: http://pmabc.example/".into(),
        };
        assert!(marker(&hit).proven);
        assert_eq!(marker(&hit).confidence, "high");
        // Already present → inconclusive.
        let already = MarkerInputs { control_hit: true, ..hit.clone() };
        assert!(!marker(&already).proven);
        // Did not land anywhere dangerous.
        let miss = MarkerInputs { hit: false, ..hit };
        assert!(!marker(&miss).proven);
    }
}
