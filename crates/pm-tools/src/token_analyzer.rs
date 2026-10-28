//! How unpredictable is a sample of tokens (session ids, CSRF tokens,
//! reset codes)? The numbers here can show a token is weak; they can't
//! prove one is strong.
//!
//! - Per-position Shannon entropy over the characters seen, summed into
//!   an estimate of effective bits (capped by log2 of the sample size,
//!   the most a sample can show).
//! - Duplicates; constant positions; tokens that are numbers increasing by
//!   a steady step (counters or timestamps).

use std::collections::{BTreeMap, HashSet};

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Analysis {
    pub samples: usize,
    pub unique: usize,
    pub min_len: usize,
    pub max_len: usize,
    /// Characters seen across all tokens.
    pub alphabet: String,
    /// Sum of per-position entropy (bits): what the sample suggests.
    pub estimated_bits: f64,
    /// The most bits a sample this size can demonstrate (log2(n)·positions…).
    pub sample_limit_bits: f64,
    /// Positions whose character never changes.
    pub constant_positions: Vec<usize>,
    /// Numeric tokens increasing by a steady step (e.g. +1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequential_step: Option<i128>,
    /// poor, weak, reasonable (never "secure": a sample can't show that).
    pub rating: &'static str,
    pub notes: Vec<String>,
}

pub fn analyze(tokens: &[String]) -> Analysis {
    let n = tokens.len();
    let unique = tokens.iter().collect::<HashSet<_>>().len();
    let min_len = tokens.iter().map(|t| t.chars().count()).min().unwrap_or(0);
    let max_len = tokens.iter().map(|t| t.chars().count()).max().unwrap_or(0);
    let mut alphabet: Vec<char> = tokens.iter().flat_map(|t| t.chars()).collect::<HashSet<_>>().into_iter().collect();
    alphabet.sort_unstable();
    let chars: Vec<Vec<char>> = tokens.iter().map(|t| t.chars().collect()).collect();
    let mut bits = 0.0;
    let mut constant = Vec::new();
    for pos in 0..max_len {
        let mut counts: BTreeMap<char, usize> = BTreeMap::new();
        let mut total = 0;
        for c in chars.iter().filter_map(|t| t.get(pos)) {
            *counts.entry(*c).or_default() += 1;
            total += 1;
        }
        if total == 0 {
            continue;
        }
        if counts.len() == 1 && total == n {
            constant.push(pos);
        }
        let h: f64 = counts
            .values()
            .map(|&c| {
                let p = c as f64 / total as f64;
                -p * p.log2()
            })
            .sum();
        bits += h;
    }
    // A sample of n tokens can show at most log2(n) bits per position.
    let limit = if n > 1 { (n as f64).log2() * max_len as f64 } else { 0.0 };
    let sequential_step = {
        let nums: Option<Vec<i128>> = tokens.iter().map(|t| t.parse::<i128>().ok()).collect();
        nums.filter(|v| v.len() >= 3).and_then(|v| {
            let step = v[1] - v[0];
            (step != 0 && v.windows(2).all(|w| w[1] - w[0] == step)).then_some(step)
        })
    };
    let mut notes = Vec::new();
    if n < 20 {
        notes.push(format!("only {n} samples: collect at least 100 for a meaningful estimate"));
    }
    if unique < n {
        notes.push(format!("{} duplicate token(s)", n - unique));
    }
    if let Some(s) = sequential_step {
        notes.push(format!("tokens are numbers increasing by {s}: predictable"));
    }
    if !constant.is_empty() {
        notes.push(format!("{} of {max_len} positions never change", constant.len()));
    }
    if min_len != max_len {
        notes.push(format!("lengths vary ({min_len}–{max_len})"));
    }
    let rating = if sequential_step.is_some() || unique < n || bits < 32.0 {
        "poor"
    } else if bits < 64.0 {
        "weak"
    } else {
        "reasonable"
    };
    if rating == "reasonable" {
        notes.push("no weakness found in this sample; that is not proof the generator is secure".into());
    }
    Analysis {
        samples: n,
        unique,
        min_len,
        max_len,
        alphabet: alphabet.into_iter().collect(),
        estimated_bits: (bits * 10.0).round() / 10.0,
        sample_limit_bits: (limit * 10.0).round() / 10.0,
        constant_positions: constant,
        sequential_step,
        rating,
        notes,
    }
}

/// Finds a token in a response: a Set-Cookie value (`cookie:<name>`), a
/// header (`header:<name>`), a JSON pointer (`json:/data/token`) or the text
/// between two markers (`between:<start>|<end>`).
pub fn extract(response: &str, locator: &str) -> Option<String> {
    let (head, body) =
        response.split_once("\r\n\r\n").or_else(|| response.split_once("\n\n")).unwrap_or((response, ""));
    let (kind, arg) = locator.split_once(':')?;
    match kind {
        "cookie" => head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if !k.trim().eq_ignore_ascii_case("set-cookie") {
                return None;
            }
            let (name, value) = v.trim().split(';').next()?.split_once('=')?;
            (name.trim() == arg).then(|| value.trim().to_string())
        }),
        "header" => head.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(arg).then(|| v.trim().to_string())
        }),
        "json" => {
            let v: serde_json::Value = serde_json::from_str(body).ok()?;
            match v.pointer(arg)? {
                serde_json::Value::String(s) => Some(s.clone()),
                other => Some(other.to_string()),
            }
        }
        "between" => {
            let (start, end) = arg.split_once('|')?;
            let i = body.find(start)? + start.len();
            let j = body[i..].find(end)? + i;
            Some(body[i..j].to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spots_weak_tokens() {
        let counters: Vec<String> = (1000..1100).map(|i| i.to_string()).collect();
        let a = analyze(&counters);
        assert_eq!((a.sequential_step, a.rating), (Some(1), "poor"));

        // Pseudo-random 32-hex-char tokens (splitmix64), 200 samples.
        let mut x: u64 = 42;
        let mut next = || {
            x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let good: Vec<String> = (0..200).map(|_| format!("{:016x}{:016x}", next(), next())).collect();
        let a = analyze(&good);
        assert_eq!(a.rating, "reasonable", "{a:?}");
        assert!(a.estimated_bits > 100.0);
        assert!(a.constant_positions.is_empty());

        let prefixed: Vec<String> = good.iter().map(|t| format!("SESSION{}", &t[..6])).collect();
        let a = analyze(&prefixed);
        assert_eq!(a.constant_positions.len(), 7);
        assert_eq!(a.rating, "poor", "24 random bits: {a:?}");

        let dup = vec!["a1".to_string(), "a1".to_string(), "b2".to_string()];
        assert!(analyze(&dup).notes.iter().any(|n| n.contains("duplicate")));
    }

    #[test]
    fn extracts_tokens() {
        let r = "HTTP/1.1 200 OK\r\nSet-Cookie: other=1\r\nSet-Cookie: session=abc123; HttpOnly\r\nX-Token: t9\r\n\r\n{\"data\":{\"token\":\"j5\"}}<i>m7</i>";
        assert_eq!(extract(r, "cookie:session").as_deref(), Some("abc123"));
        assert_eq!(extract(r, "header:x-token").as_deref(), Some("t9"));
        assert_eq!(extract(r, "cookie:missing"), None);
        assert_eq!(
            extract("HTTP/1.1 200 OK\r\n\r\n{\"data\":{\"token\":\"j5\"}}", "json:/data/token").as_deref(),
            Some("j5")
        );
        assert_eq!(extract(r, "between:<i>|</i>").as_deref(), Some("m7"));
    }
}
