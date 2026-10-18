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
        proven = fail(format!("owner request did not succeed twice ({:?})", i.owner_statuses), &mut reasons);
    }
    if !refused(i.anonymous_status) {
        proven = fail(
            format!("anonymous request was not refused ({:?}); the data may be public", i.anonymous_status),
            &mut reasons,
        );
    }
    if !ok(i.attacker_status) {
        proven = fail(format!("{} was refused ({:?})", i.attacker, i.attacker_status), &mut reasons);
    }
    if i.similarity < 0.9 {
        proven = fail(
            format!("{}'s response differs from the owner's ({:.0}% similar)", i.attacker, i.similarity * 100.0),
            &mut reasons,
        );
    }
    if proven {
        reasons.push(format!(
            "{} ({}) received {}'s data ({:.0}% similar, noise ignored) while anonymous access is refused ({:?})",
            i.attacker,
            i.attacker_role,
            i.owner,
            i.similarity * 100.0,
            i.anonymous_status
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
}
