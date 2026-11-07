//! How unpredictable is a sample of tokens (session ids, CSRF tokens,
//! reset codes)? The numbers here can show a token is weak; they can't
//! prove one is strong.
//!
//! - Per-position Shannon entropy over the characters seen, summed into
//!   an estimate of effective bits (capped by log2 of the sample size,
//!   the most a sample can show).
//! - Duplicates; constant positions; tokens that are numbers increasing by
//!   a steady step (counters or timestamps).
//! - Bit-level tests when the alphabet maps to whole bits (hex, base32,
//!   base64…): NIST SP 800-22 frequency and runs tests at any length, and
//!   the four FIPS 140-2 tests (monobit, poker, runs, long run) once the
//!   sample holds 20 000 bits.

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
    /// Bit-level randomness tests, when the alphabet maps to whole bits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_tests: Option<BitTests>,
    /// poor, weak, reasonable (never "secure": a sample can't show that).
    pub rating: &'static str,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BitTests {
    /// Bits tested (each character gives `bits_per_char` bits).
    pub bits: usize,
    pub bits_per_char: u32,
    pub tests: Vec<BitTest>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BitTest {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// Bits per character when the alphabet seen is a power of two (2..=64
/// symbols); any other size can't be mapped to bits without bias.
fn bits_of(tokens: &[String], alphabet: &[char]) -> Option<(Vec<u8>, u32)> {
    let size = alphabet.len();
    if !(2..=64).contains(&size) {
        return None;
    }
    let per = (size as f64).log2().ceil() as u32;
    // Only exact power-of-two alphabets map without bias.
    if 1usize << per != size {
        return None;
    }
    let mut bits = Vec::new();
    for t in tokens {
        for c in t.chars() {
            let i = alphabet.binary_search(&c).ok()?;
            for b in (0..per).rev() {
                bits.push(((i >> b) & 1) as u8);
            }
        }
    }
    Some((bits, per))
}

/// Complementary error function (Numerical Recipes erfcc, error < 1.2e-7).
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

fn bit_tests(bits: &[u8], per: u32) -> BitTests {
    let n = bits.len();
    let mut tests = Vec::new();
    let ones = bits.iter().filter(|&&b| b == 1).count();
    // NIST SP 800-22 2.1: frequency (monobit).
    let s = (2 * ones) as f64 - n as f64;
    let p_freq = erfc(s.abs() / (n as f64).sqrt() / std::f64::consts::SQRT_2);
    tests.push(BitTest {
        name: "NIST frequency",
        passed: p_freq >= 0.01,
        detail: format!("{ones} ones of {n} bits, p = {p_freq:.4}"),
    });
    // NIST SP 800-22 2.3: runs.
    let pi = ones as f64 / n as f64;
    let runs = 1 + bits.windows(2).filter(|w| w[0] != w[1]).count();
    if (pi - 0.5).abs() >= 2.0 / (n as f64).sqrt() {
        tests.push(BitTest {
            name: "NIST runs",
            passed: false,
            detail: "not run: the frequency test fails by too much".into(),
        });
    } else {
        let num = (runs as f64 - 2.0 * n as f64 * pi * (1.0 - pi)).abs();
        let den = 2.0 * (2.0 * n as f64).sqrt() * pi * (1.0 - pi);
        let p = erfc(num / den);
        tests.push(BitTest { name: "NIST runs", passed: p >= 0.01, detail: format!("{runs} runs, p = {p:.4}") });
    }
    // FIPS 140-2 (section 4.9.1), on the first 20 000 bits.
    if n >= 20_000 {
        let b = &bits[..20_000];
        let ones = b.iter().filter(|&&x| x == 1).count();
        tests.push(BitTest {
            name: "FIPS monobit",
            passed: ones > 9725 && ones < 10275,
            detail: format!("{ones} ones (9726 to 10274 pass)"),
        });
        let mut f = [0u64; 16];
        for c in b.chunks(4) {
            f[usize::from(c[0] << 3 | c[1] << 2 | c[2] << 1 | c[3])] += 1;
        }
        let x = 16.0 / 5000.0 * f.iter().map(|&v| (v * v) as f64).sum::<f64>() - 5000.0;
        tests.push(BitTest {
            name: "FIPS poker",
            passed: x > 2.16 && x < 46.17,
            detail: format!("X = {x:.2} (2.16 to 46.17 pass)"),
        });
        // Runs of each length (1..=5, 6+) for zeros and ones, and the longest.
        let mut counts = [[0usize; 6]; 2];
        let mut longest = 0;
        let mut i = 0;
        while i < b.len() {
            let mut j = i;
            while j < b.len() && b[j] == b[i] {
                j += 1;
            }
            let len = j - i;
            longest = longest.max(len);
            counts[usize::from(b[i])][len.min(6) - 1] += 1;
            i = j;
        }
        const BOUNDS: [(usize, usize); 6] =
            [(2315, 2685), (1114, 1386), (527, 723), (240, 384), (103, 209), (103, 209)];
        let bad: Vec<String> = (0..2)
            .flat_map(|bit| {
                (0..6).filter_map(move |k| {
                    let (lo, hi) = BOUNDS[k];
                    let c = counts[bit][k];
                    (c < lo || c > hi).then(|| format!("{c} runs of {}{} {bit}s", k + 1, if k == 5 { "+" } else { "" }))
                })
            })
            .collect();
        tests.push(BitTest {
            name: "FIPS runs",
            passed: bad.is_empty(),
            detail: if bad.is_empty() {
                "all run counts in range".into()
            } else {
                format!("out of range: {}", bad.join(", "))
            },
        });
        tests.push(BitTest {
            name: "FIPS long run",
            passed: longest < 26,
            detail: format!("longest run {longest} bits (under 26 passes)"),
        });
    }
    BitTests { bits: n, bits_per_char: per, tests }
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
    let bit_tests = if n >= 2 { bits_of(tokens, &alphabet).map(|(b, per)| bit_tests(&b, per)) } else { None };
    match &bit_tests {
        Some(bt) => {
            for t in bt.tests.iter().filter(|t| !t.passed) {
                notes.push(format!("{} test failed: {}", t.name, t.detail));
            }
            if bt.bits < 20_000 {
                notes.push(format!("FIPS 140-2 tests need 20 000 bits; this sample has {}", bt.bits));
            }
        }
        None if n >= 2 => notes.push(format!(
            "bit-level tests skipped: an alphabet of {} characters doesn't map to whole bits",
            alphabet.len()
        )),
        None => {}
    }
    let bits_failed = bit_tests.as_ref().is_some_and(|b| b.tests.iter().any(|t| !t.passed));
    let rating = if sequential_step.is_some() || unique < n || bits < 32.0 {
        "poor"
    } else if bits < 64.0 || bits_failed {
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
        bit_tests,
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

        // Enough bits for FIPS 140-2, and all its tests pass on good tokens.
        let bt = analyze(&good).bit_tests.expect("hex maps to 4 bits");
        assert_eq!((bt.bits, bt.bits_per_char), (25_600, 4));
        assert_eq!(bt.tests.len(), 6, "{bt:?}");
        assert!(bt.tests.iter().all(|t| t.passed), "{bt:?}");

        // Hex whose last 24 characters are only 0-3: two of every four bits are zero.
        let biased: Vec<String> = (0..200)
            .map(|_| {
                let r = next();
                let low: String = (0..24).map(|i| char::from(b'0' + ((r >> (i * 2)) & 3) as u8)).collect();
                format!("{:08x}{low}", next() as u32)
            })
            .collect();
        let a = analyze(&biased);
        let bt = a.bit_tests.as_ref().unwrap();
        assert!(!bt.tests.iter().find(|t| t.name == "NIST frequency").unwrap().passed, "{bt:?}");
        assert_ne!(a.rating, "reasonable", "{a:?}");

        // Decimal digits don't map to whole bits.
        let digits: Vec<String> = (0..50).map(|_| format!("{:020}", next() % 10u64.pow(19))).collect();
        assert!(analyze(&digits).bit_tests.is_none());

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
