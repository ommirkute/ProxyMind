//! Fuzzer: send a request many times with payloads in marked positions,
//! then point out the responses that stand out.
//!
//! Positions are marked with `§`: `GET /orders/§1001§ HTTP/1.1`.
//! The text between the markers is the original value, used for the
//! baseline request. This crate is pure: it builds the requests and analyses
//! results; the service layer sends them through the policy gate.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const MARKER: char = '§';
/// Most requests one attack may generate.
pub const MAX_REQUESTS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzError {
    NoPositions,
    UnbalancedMarkers,
    /// Paired / all combinations need one payload set per position.
    SetCount {
        positions: usize,
        sets: usize,
    },
    TooMany(usize),
    EmptySet(usize),
    BadRange(String),
    UnknownBuiltin(String),
    BadRule(String),
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
            FuzzError::BadRule(r) => write!(f, "bad payload rule: {r}"),
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

/// How payloads are placed in the positions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// One position at a time, the others keep their original value.
    #[default]
    OneAtATime,
    /// The same payload in every position at once.
    SameEverywhere,
    /// Set i in position i, advancing together (stops at the shortest set).
    Paired,
    /// Every combination of the sets.
    AllCombinations,
}

impl Mode {
    /// The name people see, e.g. "one at a time".
    pub fn label(self) -> &'static str {
        match self {
            Mode::OneAtATime => "one at a time",
            Mode::SameEverywhere => "same everywhere",
            Mode::Paired => "paired",
            Mode::AllCombinations => "all combinations",
        }
    }
}

/// One payload set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Every string of `charset` from `min` to `max` characters long.
    #[serde(default)]
    pub brute: Option<BruteForce>,
    /// This many empty payloads (to repeat the base request).
    #[serde(default)]
    pub null_payloads: Option<usize>,
    /// Each word as written, lower case, UPPER case and Capitalised.
    #[serde(default)]
    pub case_variants: Vec<String>,
    /// Applied to each payload in order (payload processing).
    #[serde(default)]
    pub processing: Vec<Rule>,
    /// Percent-encode each payload (for query strings and form bodies),
    /// after the processing rules.
    #[serde(default)]
    pub url_encode: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BruteForce {
    pub charset: String,
    pub min: usize,
    pub max: usize,
}

/// One payload processing step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Rule {
    Prefix {
        value: String,
    },
    Suffix {
        value: String,
    },
    /// Replace every occurrence of `find` (literal text).
    Replace {
        find: String,
        with: String,
    },
    /// Percent-encode reserved characters only.
    UrlEncode,
    /// Percent-encode every byte.
    UrlEncodeAll,
    Base64,
    Hex,
    Lower,
    Upper,
    Reverse,
    Sha1,
    Sha256,
}

impl Rule {
    pub fn apply(&self, p: &str) -> String {
        match self {
            Rule::Prefix { value } => format!("{value}{p}"),
            Rule::Suffix { value } => format!("{p}{value}"),
            Rule::Replace { find, with } if !find.is_empty() => p.replace(find.as_str(), with),
            Rule::Replace { .. } => p.to_string(),
            Rule::UrlEncode => percent_encode(p),
            Rule::UrlEncodeAll => p.bytes().map(|b| format!("%{b:02X}")).collect(),
            Rule::Base64 => pm_core::base64(p.as_bytes()),
            Rule::Hex => p.bytes().map(|b| format!("{b:02x}")).collect(),
            Rule::Lower => p.to_lowercase(),
            Rule::Upper => p.to_uppercase(),
            Rule::Reverse => p.chars().rev().collect(),
            Rule::Sha1 => hex_digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, p),
            Rule::Sha256 => hex_digest(&ring::digest::SHA256, p),
        }
    }
}

fn hex_digest(alg: &'static ring::digest::Algorithm, p: &str) -> String {
    ring::digest::digest(alg, p.as_bytes()).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Every string over `charset` of each length from `min` to `max`, shortest first.
fn brute(b: &BruteForce) -> Result<Vec<String>, FuzzError> {
    let chars: Vec<char> = {
        let mut seen = std::collections::BTreeSet::new();
        b.charset.chars().filter(|c| seen.insert(*c)).collect()
    };
    if chars.is_empty() || b.min > b.max || b.max > 32 {
        return Err(FuzzError::BadRange(format!("brute force over {:?}, {}-{}", b.charset, b.min, b.max)));
    }
    let mut total: usize = 0;
    for len in b.min..=b.max {
        let n = chars.len().checked_pow(len as u32).unwrap_or(usize::MAX);
        total = total.saturating_add(n);
        if total > MAX_REQUESTS {
            return Err(FuzzError::TooMany(total));
        }
    }
    let mut out = Vec::with_capacity(total);
    for len in b.min..=b.max {
        let mut idx = vec![0usize; len];
        loop {
            out.push(idx.iter().map(|&i| chars[i]).collect());
            // Odometer over the charset.
            let mut p = len;
            loop {
                if p == 0 {
                    break;
                }
                p -= 1;
                idx[p] += 1;
                if idx[p] < chars.len() {
                    break;
                }
                idx[p] = 0;
                if p == 0 {
                    p = usize::MAX;
                    break;
                }
            }
            if p == usize::MAX || len == 0 {
                break;
            }
        }
    }
    Ok(out)
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
        if let Some(b) = &self.brute {
            out.extend(brute(b)?);
        }
        if let Some(n) = self.null_payloads {
            if n > MAX_REQUESTS {
                return Err(FuzzError::TooMany(n));
            }
            out.extend(std::iter::repeat_n(String::new(), n));
        }
        for w in &self.case_variants {
            let mut cap = w.to_lowercase();
            if let Some(f) = cap.get(..1).map(str::to_uppercase) {
                cap.replace_range(..1, &f);
            }
            for v in [w.clone(), w.to_lowercase(), w.to_uppercase(), cap] {
                if !out.contains(&v) {
                    out.push(v);
                }
            }
        }
        if out.len() > MAX_REQUESTS {
            return Err(FuzzError::TooMany(out.len()));
        }
        for r in &self.processing {
            out = out.iter().map(|p| r.apply(p)).collect();
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
    let count = (to.abs_diff(from) / step as u64).saturating_add(1);
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
        Mode::OneAtATime | Mode::SameEverywhere => {
            if sets.len() != 1 {
                return Err(FuzzError::SetCount { positions: 1, sets: sets.len() });
            }
            if mode == Mode::OneAtATime { n * sets[0].len() } else { sets[0].len() }
        }
        Mode::Paired | Mode::AllCombinations => {
            if sets.len() != n {
                return Err(FuzzError::SetCount { positions: n, sets: sets.len() });
            }
            if mode == Mode::Paired {
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
        Mode::OneAtATime => {
            for pos in 0..n {
                for p in &sets[0] {
                    let mut vals = vec![None; n];
                    vals[pos] = Some(p.as_str());
                    out.push(make(vals));
                }
            }
        }
        Mode::SameEverywhere => {
            for p in &sets[0] {
                out.push(make(vec![Some(p.as_str()); n]));
            }
        }
        Mode::Paired => {
            for i in 0..total {
                out.push(make(sets.iter().map(|s| Some(s[i].as_str())).collect()));
            }
        }
        Mode::AllCombinations => {
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

/// Pulls a value out of each response for its own results column
/// (extract): text between two markers, or a regex's first
/// group (or whole match).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Extract {
    pub start: Option<String>,
    pub end: Option<String>,
    pub regex: Option<String>,
}

/// Longest extracted value kept.
const EXTRACT_MAX: usize = 200;

impl Extract {
    pub fn compile(&self) -> Result<Option<regex::Regex>, FuzzError> {
        self.regex
            .as_deref()
            .filter(|r| !r.is_empty())
            .map(|r| {
                regex::RegexBuilder::new(r)
                    .size_limit(1 << 20)
                    .build()
                    .map_err(|e| FuzzError::BadRule(format!("extract regex: {e}")))
            })
            .transpose()
    }

    /// The value in `text`, if found.
    pub fn find(&self, re: Option<&regex::Regex>, text: &str) -> Option<String> {
        let v = if let Some(re) = re {
            let c = re.captures(text)?;
            c.get(1).or_else(|| c.get(0))?.as_str().to_string()
        } else {
            let start = self.start.as_deref().filter(|s| !s.is_empty())?;
            let from = text.find(start)? + start.len();
            let rest = &text[from..];
            let to = match self.end.as_deref().filter(|e| !e.is_empty()) {
                Some(e) => rest.find(e)?,
                None => rest.find(['\r', '\n']).unwrap_or(rest.len()),
            };
            rest[..to].to_string()
        };
        Some(v.chars().take(EXTRACT_MAX).collect())
    }
}

/// Which grep terms match a response: case-insensitive text, or regexes.
pub struct Grep {
    terms: Vec<(String, Option<regex::Regex>)>,
}

impl Grep {
    pub fn new(terms: &[String], as_regex: bool) -> Result<Self, FuzzError> {
        let terms = terms
            .iter()
            .filter(|t| !t.is_empty())
            .map(|t| {
                let re = as_regex
                    .then(|| {
                        regex::RegexBuilder::new(t)
                            .case_insensitive(true)
                            .size_limit(1 << 20)
                            .build()
                            .map_err(|e| FuzzError::BadRule(format!("grep regex {t:?}: {e}")))
                    })
                    .transpose()?;
                Ok((t.clone(), re))
            })
            .collect::<Result<_, FuzzError>>()?;
        Ok(Self { terms })
    }

    /// The terms found; `lower` is `text` lower-cased (done once by the caller).
    pub fn matches(&self, text: &str, lower: &str) -> Vec<String> {
        self.terms
            .iter()
            .filter(|(t, re)| match re {
                Some(re) => re.is_match(text),
                None => lower.contains(&t.to_lowercase()),
            })
            .map(|(t, _)| t.clone())
            .collect()
    }
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
    fn modes_place_payloads() {
        let t = Template::parse("§a§-§b§").unwrap();
        let raws = |m, sets: &[Vec<String>]| plan(&t, m, sets).unwrap().into_iter().map(|p| p.raw).collect::<Vec<_>>();
        assert_eq!(raws(Mode::OneAtATime, &[set(&["1", "2"])]), ["1-b", "2-b", "a-1", "a-2"]);
        assert_eq!(raws(Mode::SameEverywhere, &[set(&["1", "2"])]), ["1-1", "2-2"]);
        assert_eq!(raws(Mode::Paired, &[set(&["1", "2", "3"]), set(&["x", "y"])]), ["1-x", "2-y"]);
        assert_eq!(raws(Mode::AllCombinations, &[set(&["1", "2"]), set(&["x", "y"])]), ["1-x", "1-y", "2-x", "2-y"]);
        let p = plan(&t, Mode::OneAtATime, &[set(&["1"])]).unwrap();
        assert_eq!(p[1].payloads, vec![None, Some("1".to_string())]);
        assert!(matches!(plan(&t, Mode::Paired, &[set(&["1"])]), Err(FuzzError::SetCount { .. })));
        assert_eq!(plan(&t, Mode::OneAtATime, &[vec![]]), Err(FuzzError::EmptySet(0)));
        let big: Vec<String> = (0..120).map(|i| i.to_string()).collect();
        assert_eq!(plan(&t, Mode::AllCombinations, &[big.clone(), big]), Err(FuzzError::TooMany(14400)));
    }

    #[test]
    fn payload_sets_expand() {
        let s = PayloadSet {
            list: set(&["a b"]),
            numbers: Some("3-1".into()),
            builtin: None,
            url_encode: true,
            ..Default::default()
        };
        assert_eq!(s.expand().unwrap(), ["a%20b", "3", "2", "1"]);
        let s = PayloadSet {
            list: vec![],
            numbers: Some("-2-4:3".into()),
            builtin: Some("ids".into()),
            url_encode: false,
            ..Default::default()
        };
        let e = s.expand().unwrap();
        assert_eq!(&e[..3], ["-2", "1", "4"]);
        assert!(e.contains(&"999999".to_string()));
        assert!(matches!(numbers("-9223372036854775808-9223372036854775807"), Err(FuzzError::TooMany(_))));
        assert_eq!(numbers("9223372036854775806-9223372036854775807").unwrap().len(), 2);
        assert!(matches!(
            PayloadSet {
                list: vec![],
                numbers: Some("1-x".into()),
                builtin: None,
                url_encode: false,
                ..Default::default()
            }
            .expand(),
            Err(FuzzError::BadRange(_))
        ));
        assert!(matches!(
            PayloadSet {
                list: vec![],
                numbers: Some("0-50000".into()),
                builtin: None,
                url_encode: false,
                ..Default::default()
            }
            .expand(),
            Err(FuzzError::TooMany(_))
        ));
        assert!(matches!(
            PayloadSet {
                list: vec![],
                numbers: None,
                builtin: Some("nope".into()),
                url_encode: false,
                ..Default::default()
            }
            .expand(),
            Err(FuzzError::UnknownBuiltin(_))
        ));
    }

    fn obs(status: u16, len: usize) -> Observed {
        Observed { status: Some(status), body_length: len, elapsed_ms: 20, matches: vec![], reflected: false }
    }

    #[test]
    fn new_payload_types_and_processing() {
        let b = PayloadSet { brute: Some(BruteForce { charset: "ab".into(), min: 1, max: 2 }), ..empty() };
        assert_eq!(b.expand().unwrap(), ["a", "b", "aa", "ab", "ba", "bb"]);
        let too = PayloadSet { brute: Some(BruteForce { charset: "0123456789".into(), min: 5, max: 5 }), ..empty() };
        assert!(matches!(too.expand(), Err(FuzzError::TooMany(_))));
        assert_eq!(PayloadSet { null_payloads: Some(3), ..empty() }.expand().unwrap(), ["", "", ""]);
        assert_eq!(
            PayloadSet { case_variants: vec!["admin".into()], ..empty() }.expand().unwrap(),
            ["admin", "ADMIN", "Admin"]
        );
        let rules = PayloadSet {
            list: vec!["a b".into()],
            processing: vec![
                Rule::Prefix { value: "x".into() },
                Rule::Replace { find: " ".into(), with: "+".into() },
                Rule::Upper,
                Rule::Suffix { value: "!".into() },
            ],
            ..empty()
        };
        assert_eq!(rules.expand().unwrap(), ["XA+B!"]);
        assert_eq!(Rule::Base64.apply("pm"), "cG0=");
        assert_eq!(Rule::Hex.apply("A"), "41");
        assert_eq!(Rule::UrlEncodeAll.apply("a/"), "%61%2F");
        assert_eq!(Rule::Sha256.apply(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let r: Rule = serde_json::from_str(r#"{"op":"prefix","value":"p"}"#).unwrap();
        assert_eq!(r, Rule::Prefix { value: "p".into() });
    }

    #[test]
    fn grep_and_extract() {
        let g = Grep::new(&["Admin".into(), "".into()], false).unwrap();
        let text = "Welcome ADMIN\r\nX-Csrf: tok123\r\n\r\n{\"id\":42}";
        assert_eq!(g.matches(text, &text.to_lowercase()), ["Admin"]);
        let r = Grep::new(&[r"id.:\d+".into()], true).unwrap();
        assert_eq!(r.matches(text, &text.to_lowercase()).len(), 1);
        assert!(Grep::new(&["(".into()], true).is_err());
        let between = Extract { start: Some("X-Csrf: ".into()), ..Default::default() };
        assert_eq!(between.find(None, text).as_deref(), Some("tok123"));
        let re = Extract { regex: Some(r#""id":(\d+)"#.into()), ..Default::default() };
        let c = re.compile().unwrap();
        assert_eq!(re.find(c.as_ref(), text).as_deref(), Some("42"));
        assert_eq!(Extract { start: Some("nope".into()), ..Default::default() }.find(None, text), None);
    }

    fn empty() -> PayloadSet {
        PayloadSet::default()
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
