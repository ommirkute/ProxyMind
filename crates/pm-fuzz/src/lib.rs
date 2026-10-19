//! Intruder: send a request many times with payloads in marked positions,
//! then point out the responses that stand out.
//!
//! Positions are marked with `§`, as in Burp: `GET /orders/§1001§ HTTP/1.1`.
//! The text between the markers is the original value, used for the
//! baseline request. This crate is pure: it builds the requests and analyses
//! results; the service layer sends them through the policy gate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const MARKER: char = '§';
/// Most requests one attack may generate.
pub const MAX_REQUESTS: usize = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzError {
    NoPositions,
    UnbalancedMarkers,
    /// Pitchfork / cluster bomb need one payload set per position.
    SetCount {
        positions: usize,
        sets: usize,
    },
    TooMany(usize),
    EmptySet(usize),
    BadRange(String),
    UnknownBuiltin(String),
}

impl std::fmt::Display for FuzzError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FuzzError::NoPositions => write!(f, "mark at least one position with §…§"),
            FuzzError::UnbalancedMarkers => write!(f, "§ markers must come in pairs"),
            FuzzError::SetCount { positions, sets } => {
                write!(f, "this mode needs one payload set per position ({positions} positions, {sets} sets)")
            }
            FuzzError::TooMany(n) => write!(f, "the attack would send {n} requests; the limit is {MAX_REQUESTS}"),
            FuzzError::EmptySet(i) => write!(f, "payload set {} is empty", i + 1),
            FuzzError::BadRange(r) => write!(f, "bad number range: {r}"),
            FuzzError::UnknownBuiltin(b) => {
                write!(
                    f,
                    "unknown built-in list {b:?}; use one of {}",
                    BUILTINS.iter().map(|b| b.0).collect::<Vec<_>>().join(", ")
                )
            }
        }
    }
}

impl std::error::Error for FuzzError {}

/// How payloads are placed (Burp's four attack types).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// One position at a time, the others keep their original value.
    #[default]
    Sniper,
    /// The same payload in every position at once.
    BatteringRam,
    /// Set i in position i, advancing together (stops at the shortest set).
    Pitchfork,
    /// Every combination of the sets.
    ClusterBomb,
}

/// One payload set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadSet {
    /// Literal payloads.
    #[serde(default)]
    pub list: Vec<String>,
    /// Numbers "from-to" or "from-to:step", e.g. "1000-1010".
    #[serde(default)]
    pub numbers: Option<String>,
    /// A built-in list: see [`BUILTINS`].
    #[serde(default)]
    pub builtin: Option<String>,
    /// Percent-encode each payload (for query strings and form bodies).
    #[serde(default)]
    pub url_encode: bool,
}

/// Small built-in lists for common probes. They are starting points, not
/// complete wordlists.
pub const BUILTINS: &[(&str, &[&str])] = &[
    ("ids", &["0", "1", "2", "-1", "999999", "00001", "1.0", "null", "true", "[]", "{}"]),
    (
        "sqli",
        &["'", "\"", "' OR '1'='1", "' OR 1=1--", "1 AND 1=2", "1' AND SLEEP(2)--", "') OR ('1'='1", "1 ORDER BY 100"],
    ),
    (
        "xss",
        &["<b>pm</b>", "\"><svg onload=alert(1)>", "'><img src=x onerror=alert(1)>", "javascript:alert(1)", "{{7*7}}"],
    ),
    (
        "traversal",
        &[
            "../../../../etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "....//....//etc/passwd",
            "..\\..\\windows\\win.ini",
        ],
    ),
    ("ssti", &["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{'a'*3}}"]),
    ("methods_override", &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
];

impl PayloadSet {
    /// The payloads, expanded.
    pub fn expand(&self) -> Result<Vec<String>, FuzzError> {
        let mut out = self.list.clone();
        if let Some(r) = &self.numbers {
            out.extend(numbers(r)?);
        }
        if let Some(b) = &self.builtin {
            let list = BUILTINS.iter().find(|x| x.0 == b).ok_or_else(|| FuzzError::UnknownBuiltin(b.clone()))?.1;
            out.extend(list.iter().map(|s| s.to_string()));
        }
        if self.url_encode {
            out = out.iter().map(|p| percent_encode(p)).collect();
        }
        Ok(out)
    }
}

fn numbers(r: &str) -> Result<Vec<String>, FuzzError> {
    let bad = || FuzzError::BadRange(r.to_string());
    let (range, step) = r.split_once(':').map_or((r, "1"), |(a, b)| (a, b));
    // Allow a leading minus on the first number.
    let split = range.char_indices().skip(1).find(|&(_, c)| c == '-').map(|(i, _)| i).ok_or_else(bad)?;
    let from: i64 = range[..split].trim().parse().map_err(|_| bad())?;
    let to: i64 = range[split + 1..].trim().parse().map_err(|_| bad())?;
    let step: i64 = step.trim().parse().map_err(|_| bad())?;
    if step <= 0 {
        return Err(bad());
    }
    let count = (to - from).unsigned_abs() / step as u64 + 1;
    if count as usize > MAX_REQUESTS {
        return Err(FuzzError::TooMany(count as usize));
    }
    let dir = if to >= from { 1 } else { -1 };
    Ok((0..count as i64).map(|i| (from + dir * i * step).to_string()).collect())
}

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

/// A request template split at its positions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// Text around the positions: `parts.len() == originals.len() + 1`.
    parts: Vec<String>,
    /// The original value in each position.
    pub originals: Vec<String>,
}

impl Template {
    pub fn parse(raw: &str) -> Result<Template, FuzzError> {
        let pieces: Vec<&str> = raw.split(MARKER).collect();
        if pieces.len().is_multiple_of(2) {
            return Err(FuzzError::UnbalancedMarkers);
        }
        if pieces.len() == 1 {
            return Err(FuzzError::NoPositions);
        }
        let parts = pieces.iter().step_by(2).map(|s| s.to_string()).collect();
        let originals = pieces.iter().skip(1).step_by(2).map(|s| s.to_string()).collect();
        Ok(Template { parts, originals })
    }

    pub fn positions(&self) -> usize {
        self.originals.len()
    }

    /// The request with these values in the positions.
    pub fn fill(&self, values: &[&str]) -> String {
        let mut out = self.parts[0].clone();
        for (i, part) in self.parts[1..].iter().enumerate() {
            out.push_str(values.get(i).copied().unwrap_or(&self.originals[i]));
            out.push_str(part);
        }
        out
    }

    /// The request with the original values (the baseline).
    pub fn baseline(&self) -> String {
        let v: Vec<&str> = self.originals.iter().map(String::as_str).collect();
        self.fill(&v)
    }
}

/// One request of an attack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Planned {
    /// Payload per position (`None`: the original value).
    pub payloads: Vec<Option<String>>,
    pub raw: String,
}

/// Every request an attack sends, in order (the baseline not included).
pub fn plan(t: &Template, mode: Mode, sets: &[Vec<String>]) -> Result<Vec<Planned>, FuzzError> {
    let n = t.positions();
    if let Some(i) = sets.iter().position(Vec::is_empty) {
        return Err(FuzzError::EmptySet(i));
    }
    let originals: Vec<&str> = t.originals.iter().map(String::as_str).collect();
    let make = |vals: Vec<Option<&str>>| {
        let filled: Vec<&str> = vals.iter().zip(&originals).map(|(v, o)| v.unwrap_or(o)).collect();
        Planned { raw: t.fill(&filled), payloads: vals.iter().map(|v| v.map(str::to_string)).collect() }
    };
    let total = match mode {
        Mode::Sniper | Mode::BatteringRam => {
            if sets.len() != 1 {
                return Err(FuzzError::SetCount { positions: 1, sets: sets.len() });
            }
            if mode == Mode::Sniper { n * sets[0].len() } else { sets[0].len() }
        }
        Mode::Pitchfork | Mode::ClusterBomb => {
            if sets.len() != n {
                return Err(FuzzError::SetCount { positions: n, sets: sets.len() });
            }
            if mode == Mode::Pitchfork {
                sets.iter().map(Vec::len).min().unwrap_or(0)
            } else {
                sets.iter().try_fold(1usize, |acc, s| acc.checked_mul(s.len())).unwrap_or(usize::MAX)
            }
        }
    };
    if total > MAX_REQUESTS {
        return Err(FuzzError::TooMany(total));
    }
    let mut out = Vec::with_capacity(total);
    match mode {
        Mode::Sniper => {
            for pos in 0..n {
                for p in &sets[0] {
                    let mut vals = vec![None; n];
                    vals[pos] = Some(p.as_str());
                    out.push(make(vals));
                }
            }
        }
        Mode::BatteringRam => {
            for p in &sets[0] {
                out.push(make(vec![Some(p.as_str()); n]));
            }
        }
        Mode::Pitchfork => {
            for i in 0..total {
                out.push(make(sets.iter().map(|s| Some(s[i].as_str())).collect()));
            }
        }
        Mode::ClusterBomb => {
            let mut idx = vec![0usize; n];
            for _ in 0..total {
                out.push(make(idx.iter().enumerate().map(|(p, &i)| Some(sets[p][i].as_str())).collect()));
                // Odometer: the last position changes fastest.
                for p in (0..n).rev() {
                    idx[p] += 1;
                    if idx[p] < sets[p].len() {
                        break;
                    }
                    idx[p] = 0;
                }
            }
        }
    }
    Ok(out)
}

/// What came back for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub status: Option<u16>,
    pub body_length: usize,
    pub elapsed_ms: u64,
    /// Grep terms found in the response.
    pub matches: Vec<String>,
    pub reflected: bool,
}

/// Why a result stands out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Anomaly {
    /// Index into the results.
    pub index: usize,
    pub reasons: Vec<String>,
}

/// Points out results that differ from the baseline and from most others:
/// a different status, a body length well off the usual, much slower,
/// grep matches, or the payload reflected.
pub fn anomalies(baseline: Option<&Observed>, results: &[Observed]) -> Vec<Anomaly> {
    let mut status_count: BTreeMap<Option<u16>, usize> = BTreeMap::new();
    for r in results {
        *status_count.entry(r.status).or_default() += 1;
    }
    let mut lengths: Vec<usize> = results.iter().map(|r| r.body_length).collect();
    lengths.sort_unstable();
    let median_len = lengths.get(lengths.len() / 2).copied().unwrap_or(0);
    let mut times: Vec<u64> = results.iter().map(|r| r.elapsed_ms).collect();
    times.sort_unstable();
    let median_ms = times.get(times.len() / 2).copied().unwrap_or(0);
    let n = results.len();
    let mut out = Vec::new();
    for (index, r) in results.iter().enumerate() {
        let mut reasons = Vec::new();
        let rare = |c: usize| n >= 4 && c * 5 <= n; // at most a fifth of results
        if let Some(b) = baseline
            && r.status != b.status
        {
            reasons.push(format!(
                "status {} differs from the baseline's {}",
                fmt_status(r.status),
                fmt_status(b.status)
            ));
        } else if rare(status_count[&r.status]) {
            reasons.push(format!("unusual status {}", fmt_status(r.status)));
        }
        let off = |len: usize, base: usize| {
            let d = len.abs_diff(base);
            d > 32 && d * 10 > base.max(1)
        };
        if let Some(b) = baseline.filter(|b| b.status == r.status)
            && off(r.body_length, b.body_length)
        {
            reasons.push(format!("body length {} vs baseline {}", r.body_length, b.body_length));
        } else if n >= 4 && off(r.body_length, median_len) {
            reasons.push(format!("body length {} vs typical {median_len}", r.body_length));
        }
        if n >= 4 && r.elapsed_ms > 1000 && r.elapsed_ms > median_ms.saturating_mul(3) {
            reasons.push(format!("slow: {} ms vs typical {median_ms} ms", r.elapsed_ms));
        }
        if !r.matches.is_empty() {
            reasons.push(format!("matched {}", r.matches.join(", ")));
        }
        if r.reflected {
            reasons.push("payload reflected in the response".into());
        }
        if !reasons.is_empty() {
            out.push(Anomaly { index, reasons });
        }
    }
    out
}

fn fmt_status(s: Option<u16>) -> String {
    s.map_or_else(|| "error".into(), |s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn templates_parse_and_fill() {
        let t = Template::parse("GET /o/§1001§?x=§a§ HTTP/1.1").unwrap();
        assert_eq!(t.positions(), 2);
        assert_eq!(t.originals, vec!["1001", "a"]);
        assert_eq!(t.baseline(), "GET /o/1001?x=a HTTP/1.1");
        assert_eq!(t.fill(&["7", "b"]), "GET /o/7?x=b HTTP/1.1");
        assert_eq!(Template::parse("GET / HTTP/1.1"), Err(FuzzError::NoPositions));
        assert_eq!(Template::parse("GET /§x HTTP/1.1"), Err(FuzzError::UnbalancedMarkers));
        // Empty original value.
        assert_eq!(Template::parse("q=§§").unwrap().baseline(), "q=");
    }

    #[test]
    fn modes_place_payloads_like_burp() {
        let t = Template::parse("§a§-§b§").unwrap();
        let raws = |m, sets: &[Vec<String>]| plan(&t, m, sets).unwrap().into_iter().map(|p| p.raw).collect::<Vec<_>>();
        assert_eq!(raws(Mode::Sniper, &[set(&["1", "2"])]), ["1-b", "2-b", "a-1", "a-2"]);
        assert_eq!(raws(Mode::BatteringRam, &[set(&["1", "2"])]), ["1-1", "2-2"]);
        assert_eq!(raws(Mode::Pitchfork, &[set(&["1", "2", "3"]), set(&["x", "y"])]), ["1-x", "2-y"]);
        assert_eq!(raws(Mode::ClusterBomb, &[set(&["1", "2"]), set(&["x", "y"])]), ["1-x", "1-y", "2-x", "2-y"]);
        let p = plan(&t, Mode::Sniper, &[set(&["1"])]).unwrap();
        assert_eq!(p[1].payloads, vec![None, Some("1".to_string())]);
        assert!(matches!(plan(&t, Mode::Pitchfork, &[set(&["1"])]), Err(FuzzError::SetCount { .. })));
        assert_eq!(plan(&t, Mode::Sniper, &[vec![]]), Err(FuzzError::EmptySet(0)));
        let big: Vec<String> = (0..40).map(|i| i.to_string()).collect();
        assert_eq!(plan(&t, Mode::ClusterBomb, &[big.clone(), big]), Err(FuzzError::TooMany(1600)));
    }

    #[test]
    fn payload_sets_expand() {
        let s = PayloadSet { list: set(&["a b"]), numbers: Some("3-1".into()), builtin: None, url_encode: true };
        assert_eq!(s.expand().unwrap(), ["a%20b", "3", "2", "1"]);
        let s =
            PayloadSet { list: vec![], numbers: Some("-2-4:3".into()), builtin: Some("ids".into()), url_encode: false };
        let e = s.expand().unwrap();
        assert_eq!(&e[..3], ["-2", "1", "4"]);
        assert!(e.contains(&"999999".to_string()));
        assert!(matches!(
            PayloadSet { list: vec![], numbers: Some("1-x".into()), builtin: None, url_encode: false }.expand(),
            Err(FuzzError::BadRange(_))
        ));
        assert!(matches!(
            PayloadSet { list: vec![], numbers: Some("0-5000".into()), builtin: None, url_encode: false }.expand(),
            Err(FuzzError::TooMany(_))
        ));
        assert!(matches!(
            PayloadSet { list: vec![], numbers: None, builtin: Some("nope".into()), url_encode: false }.expand(),
            Err(FuzzError::UnknownBuiltin(_))
        ));
    }

    fn obs(status: u16, len: usize) -> Observed {
        Observed { status: Some(status), body_length: len, elapsed_ms: 20, matches: vec![], reflected: false }
    }

    #[test]
    fn anomalies_stand_out() {
        let base = obs(403, 30);
        let mut rs = vec![obs(403, 30); 8];
        rs[3] = obs(200, 900); // the IDOR
        rs[5].matches = vec!["alice@".into()];
        rs[6].elapsed_ms = 2500;
        let a = anomalies(Some(&base), &rs);
        let idx: Vec<usize> = a.iter().map(|x| x.index).collect();
        assert_eq!(idx, vec![3, 5, 6]);
        assert!(a[0].reasons[0].contains("differs from the baseline's 403"));
        assert!(a[2].reasons[0].starts_with("slow"));
        // Without a baseline, rare statuses and odd lengths still show.
        let mut rs = vec![obs(200, 100); 10];
        rs[2] = obs(500, 100);
        rs[7] = obs(200, 5000);
        let idx: Vec<usize> = anomalies(None, &rs).iter().map(|x| x.index).collect();
        assert_eq!(idx, vec![2, 7]);
        // Small jitter in length is not an anomaly.
        let rs: Vec<Observed> = (0..6).map(|i| obs(200, 1000 + i)).collect();
        assert!(anomalies(None, &rs).is_empty());
    }
}
