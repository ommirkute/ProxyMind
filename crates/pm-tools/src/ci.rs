//! `proxymind ci`, the parts without I/O: finding fingerprints, baselines, the pass/fail rule, and the SARIF, JUnit,
//! JSON and plain-text outputs. The service (`pm-service/src/ci.rs`) runs the scan and fills in a [`CiSummary`];
//! everything here only turns it into files and an exit code.
//!
//! # Fingerprint (version 1)
//!
//! A finding is identified by what it is and where, never by when it was found or which database row holds it:
//!
//! ```text
//! v1|<issue>|<METHOD>|<path>|<point>
//! ```
//!
//! - `issue`: the issue library's id for the finding's class (`sqli`, `xss`, `idor`, …), else the class lower-cased.
//! - `METHOD`: the method of the request the finding is about (its first evidence exchange), upper-case; empty when
//!   there is none.
//! - `path`: the URL path without scheme, host, query or fragment, with repeated slashes collapsed and no trailing
//!   slash, and with identifier segments folded into placeholders (`/orders/1001` → `/orders/{id}`; numbers, UUIDs,
//!   long hex strings, e-mail addresses and long random tokens). The host is left out on purpose, so a preview
//!   environment per pull request matches the baseline made against staging.
//! - `point`: the insertion point the scanner found it at (`query q`, `json /user/name`, `header user-agent`,
//!   `cookie session`), lower-case; empty for findings that are about a whole operation (exposed files,
//!   authorization).
//!
//! The finding's id in the project, its title, severity, status, evidence and the time are not part of it, so a
//! suspected finding that a later run proves keeps its fingerprint. The fingerprint is the first 32 hex characters
//! of the SHA-256 of that text. Changing the definition means a new version number (and `Baseline::parse` refuses
//! versions it doesn't know).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Format of `--json` output.
pub const SUMMARY_FORMAT: &str = "proxymind-ci-1";
/// Format of baseline files.
pub const BASELINE_FORMAT: &str = "proxymind-ci-baseline-1";
/// The fingerprint definition this build writes and reads.
pub const FINGERPRINT_VERSION: u32 = 1;

/// Statuses that count as proven.
pub const PROVEN_STATUSES: &[&str] = &["proven", "confirmed", "reported"];
const SEVERITIES: &[&str] = &["critical", "high", "medium", "low", "info"];

/// 0 for critical … 4 for info; anything else sorts last.
pub fn severity_rank(s: &str) -> usize {
    SEVERITIES.iter().position(|x| x.eq_ignore_ascii_case(s)).unwrap_or(SEVERITIES.len())
}

/// Whether `severity` is `floor` or worse.
pub fn at_least(severity: &str, floor: &str) -> bool {
    severity_rank(severity) <= severity_rank(floor)
}

/// Whether `s` names a severity.
pub fn valid_severity(s: &str) -> bool {
    SEVERITIES.contains(&s)
}

/// Text from the target or the scanner made safe to print and to put into XML: control characters (including escape
/// sequences and line breaks) become spaces and the length is capped.
pub fn clean(s: &str, max_chars: usize) -> String {
    let mut out: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).take(max_chars + 1).collect();
    if out.chars().count() > max_chars {
        out = out.chars().take(max_chars).collect();
        out.push('…');
    }
    out
}

/// The path of a URL (or of a path with a query), without query and fragment, repeated slashes collapsed and no
/// trailing slash (the root stays `/`).
pub fn path_of(url_or_path: &str) -> String {
    let rest = match url_or_path.find("://") {
        Some(i) => {
            let after = &url_or_path[i + 3..];
            after.find(['/', '?', '#']).map_or("", |j| &after[j..])
        }
        None => url_or_path,
    };
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    let mut path = String::from("/");
    for seg in rest.split('/').filter(|s| !s.is_empty()) {
        if !path.ends_with('/') {
            path.push('/');
        }
        path.push_str(seg);
    }
    path
}

/// The insertion point named by a scanner finding's title, which reads `<issue> in <METHOD> <operation> (<point>)`.
/// Other titles (exposed files, authorization findings) name none.
pub fn point_of_title(title: &str) -> String {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"(?s)^.* in (?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) \S+ \((.+)\)$").expect("static regex")
    });
    re.captures(title.trim()).and_then(|c| c.get(1)).map(|m| m.as_str().trim().to_ascii_lowercase()).unwrap_or_default()
}

/// The text a fingerprint is made from (see the module documentation). `path` must already be normalised.
pub fn fingerprint_key(issue: &str, method: &str, path: &str, point: &str) -> String {
    format!(
        "v{FINGERPRINT_VERSION}|{}|{}|{}|{}",
        issue.trim().to_ascii_lowercase(),
        method.trim().to_ascii_uppercase(),
        path,
        point.trim().to_ascii_lowercase()
    )
}

/// The fingerprint for a key: 32 hex characters.
pub fn fingerprint_id(key: &str) -> String {
    crate::sign::sha256_hex(key.as_bytes()).chars().take(32).collect()
}

/// Replaces `${NAME}` in `text` with the value `lookup` gives (`$$` is a literal `$`), so files that name credentials
/// can be committed while the values come from the pipeline's secrets. An unset name is an error. Every value used
/// is added to `used`, so the caller can keep it out of anything it prints.
pub fn expand_env(
    text: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
    used: &mut Vec<String>,
) -> Result<String, String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find('$') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        if let Some(a) = after.strip_prefix('$') {
            out.push('$');
            rest = a;
        } else if let Some(a) = after.strip_prefix('{') {
            let end = a.find('}').ok_or_else(|| "an unclosed ${ in a credentials file".to_string())?;
            let name = &a[..end];
            let valid = !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !valid {
                return Err(format!("{:?} is not a variable name", clean(name, 40)));
            }
            let v = lookup(name).ok_or_else(|| format!("the environment variable {name} is not set"))?;
            if !v.is_empty() {
                used.push(v.clone());
            }
            out.push_str(&v);
            rest = &a[end + 1..];
        } else {
            out.push('$');
            rest = after;
        }
    }
    out.push_str(rest);
    Ok(out)
}

/// How a proof verified a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiProof {
    pub oracle: String,
    pub confidence: String,
}

/// One finding of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiFinding {
    pub fingerprint: String,
    /// What the fingerprint was made from (readable).
    pub key: String,
    pub issue: String,
    pub method: String,
    pub path: String,
    pub point: String,
    pub severity: String,
    /// `proven` or `suspected`.
    pub status: String,
    pub title: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<CiProof>,
    /// The row in the project (informational: it is not stable between runs).
    pub finding_id: i64,
    /// `new` (not in the baseline) or `unchanged`.
    pub state: String,
    /// Whether this finding fails the run.
    pub fails: bool,
}

impl CiFinding {
    pub fn proven(&self) -> bool {
        self.status == "proven"
    }
}

/// A finding recorded in a baseline file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    pub fingerprint: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub issue: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub point: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub title: String,
}

impl From<&CiFinding> for BaselineEntry {
    fn from(f: &CiFinding) -> Self {
        Self {
            fingerprint: f.fingerprint.clone(),
            key: f.key.clone(),
            issue: f.issue.clone(),
            method: f.method.clone(),
            path: f.path.clone(),
            point: f.point.clone(),
            severity: f.severity.clone(),
            status: f.status.clone(),
            title: f.title.clone(),
        }
    }
}

/// Known findings. Review it like code: removing an entry makes that finding "new" again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    pub format: String,
    pub fingerprint_version: u32,
    #[serde(default)]
    pub generated_at: String,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub target: String,
    pub findings: Vec<BaselineEntry>,
}

impl Baseline {
    /// A baseline of this run's findings: the proven ones, and the suspected ones when asked.
    pub fn from_findings(
        findings: &[CiFinding],
        include_suspected: bool,
        target: &str,
        tool: &str,
        generated_at: &str,
    ) -> Self {
        let mut entries: Vec<BaselineEntry> =
            findings.iter().filter(|f| f.proven() || include_suspected).map(BaselineEntry::from).collect::<Vec<_>>();
        entries.sort_by(|a, b| {
            (&a.issue, &a.method, &a.path, &a.point, &a.fingerprint).cmp(&(
                &b.issue,
                &b.method,
                &b.path,
                &b.point,
                &b.fingerprint,
            ))
        });
        entries.dedup_by(|a, b| a.fingerprint == b.fingerprint);
        Self {
            format: BASELINE_FORMAT.into(),
            fingerprint_version: FINGERPRINT_VERSION,
            generated_at: generated_at.into(),
            tool: tool.into(),
            target: target.into(),
            findings: entries,
        }
    }

    /// Reads a baseline file. A different format or fingerprint version is an error: comparing against fingerprints
    /// made another way would call every finding new (or, worse, hide some).
    pub fn parse(text: &str) -> Result<Self, String> {
        let b: Baseline = serde_json::from_str(text).map_err(|e| format!("not a ProxyMind baseline file: {e}"))?;
        if b.format != BASELINE_FORMAT {
            return Err(format!("unknown baseline format {:?} (expected {BASELINE_FORMAT})", b.format));
        }
        if b.fingerprint_version != FINGERPRINT_VERSION {
            return Err(format!(
                "the baseline uses fingerprint version {}, this ProxyMind uses {FINGERPRINT_VERSION}: write it again \
                 with --write-baseline",
                b.fingerprint_version
            ));
        }
        if let Some(e) = b.findings.iter().find(|e| e.fingerprint.trim().is_empty()) {
            return Err(format!("a baseline entry has no fingerprint ({})", clean(&e.title, 80)));
        }
        Ok(b)
    }

    pub fn to_json(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).unwrap_or_default();
        s.push('\n');
        s
    }
}

/// What makes a new finding fail the run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailOn {
    /// Only proven findings.
    Proven,
    /// Proven and suspected findings.
    Suspected,
    /// Never (the run still exits 2 when it could not finish).
    None,
}

impl FailOn {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "proven" => Some(Self::Proven),
            "suspected" => Some(Self::Suspected),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// The pass/fail rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gate {
    pub fail_on: FailOn,
    pub min_severity: String,
}

impl Gate {
    /// Whether a finding fails the run: new, severe enough, and proven (or suspected, when asked).
    pub fn fails(&self, f: &CiFinding) -> bool {
        f.state == "new"
            && at_least(&f.severity, &self.min_severity)
            && match self.fail_on {
                FailOn::None => false,
                FailOn::Proven => f.proven(),
                FailOn::Suspected => true,
            }
    }
}

/// Keeps one finding per fingerprint (proven beats suspected, then the worse severity), most severe first.
pub fn dedupe(findings: Vec<CiFinding>) -> Vec<CiFinding> {
    let mut by_fp: BTreeMap<String, CiFinding> = BTreeMap::new();
    for f in findings {
        match by_fp.get(&f.fingerprint) {
            Some(old)
                if (old.proven(), std::cmp::Reverse(severity_rank(&old.severity)))
                    >= (f.proven(), std::cmp::Reverse(severity_rank(&f.severity))) => {}
            _ => {
                by_fp.insert(f.fingerprint.clone(), f);
            }
        }
    }
    let mut out: Vec<CiFinding> = by_fp.into_values().collect();
    out.sort_by(|a, b| {
        (severity_rank(&a.severity), !a.proven(), &a.issue, &a.path, &a.point).cmp(&(
            severity_rank(&b.severity),
            !b.proven(),
            &b.issue,
            &b.path,
            &b.point,
        ))
    });
    out
}

/// Marks each finding new or unchanged against `baseline` (none: everything is new) and decides which fail the run.
/// Returns the baseline entries this run did not find again ("fixed").
pub fn classify(findings: &mut [CiFinding], baseline: Option<&Baseline>, gate: &Gate) -> Vec<BaselineEntry> {
    let known: BTreeSet<&str> =
        baseline.map(|b| b.findings.iter().map(|e| e.fingerprint.as_str()).collect()).unwrap_or_default();
    for f in findings.iter_mut() {
        f.state = if known.contains(f.fingerprint.as_str()) { "unchanged" } else { "new" }.into();
        f.fails = gate.fails(f);
    }
    let now: BTreeSet<&str> = findings.iter().map(|f| f.fingerprint.as_str()).collect();
    let mut fixed: Vec<BaselineEntry> = baseline
        .map(|b| b.findings.iter().filter(|e| !now.contains(e.fingerprint.as_str())).cloned().collect())
        .unwrap_or_default();
    fixed.sort_by(|a, b| (&a.issue, &a.path, &a.point).cmp(&(&b.issue, &b.path, &b.point)));
    fixed.dedup_by(|a, b| a.fingerprint == b.fingerprint);
    fixed
}

/// One step or condition of the run, for the JUnit file and the summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiCheck {
    pub name: String,
    /// `passed`, `skipped` or `error`.
    pub outcome: String,
    pub detail: String,
}

impl CiCheck {
    pub fn new(name: &str, outcome: &str, detail: impl Into<String>) -> Self {
        Self { name: name.into(), outcome: outcome.into(), detail: detail.into() }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiCounts {
    pub total: usize,
    pub proven: usize,
    pub suspected: usize,
    pub new: usize,
    pub unchanged: usize,
    pub fixed: usize,
    /// New findings that fail the run.
    pub failing: usize,
    pub by_severity: BTreeMap<String, usize>,
}

/// The result of a run: what `--json` writes and the other outputs are made from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiSummary {
    pub format: String,
    pub tool: String,
    pub target: String,
    pub profile: String,
    pub actor: String,
    pub started_at: String,
    pub duration_ms: u64,
    /// Requests sent to the target (the cap counts these).
    pub requests: u64,
    /// Whether the target's TLS certificate was verified (off only with `--insecure`).
    pub tls_verified: bool,
    pub fail_on: FailOn,
    pub min_severity: String,
    pub baseline: Option<String>,
    pub baseline_written: Option<String>,
    /// True when the scan ran to the end: no reason in `incomplete`.
    pub complete: bool,
    /// Why the run could not finish (an unreachable target, a failed login, a spent budget, …). Never "clean".
    pub incomplete: Vec<String>,
    /// Things the rules of engagement did not let CI do (needing approval, or refused); reported, never granted.
    pub skipped: Vec<String>,
    pub checks: Vec<CiCheck>,
    pub counts: CiCounts,
    pub findings: Vec<CiFinding>,
    /// In the baseline, not found now. Only a report: it never fails a run (and is unreliable when `complete` is false).
    pub fixed: Vec<BaselineEntry>,
    pub exit_code: i32,
}

/// 1 when a new finding fails the run (a real problem outranks an unfinished run), else 2 when the run could not
/// finish, else 0.
pub fn exit_code(failing: usize, complete: bool) -> i32 {
    if failing > 0 {
        1
    } else if !complete {
        2
    } else {
        0
    }
}

impl CiSummary {
    /// Recomputes the counts, `complete` and the exit code from the findings and reasons.
    pub fn finish(&mut self) {
        let mut c = CiCounts { total: self.findings.len(), fixed: self.fixed.len(), ..Default::default() };
        for f in &self.findings {
            if f.proven() {
                c.proven += 1;
            } else {
                c.suspected += 1;
            }
            if f.state == "new" {
                c.new += 1;
            } else {
                c.unchanged += 1;
            }
            if f.fails {
                c.failing += 1;
            }
            *c.by_severity.entry(f.severity.clone()).or_default() += 1;
        }
        self.complete = self.incomplete.is_empty();
        self.exit_code = exit_code(c.failing, self.complete);
        self.counts = c;
    }

    pub fn json(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).unwrap_or_default();
        s.push('\n');
        s
    }

    /// The short summary printed to stdout.
    pub fn text(&self) -> String {
        let c = &self.counts;
        let mut o = String::new();
        o.push_str(&format!("ProxyMind CI: {}  (profile {})\n", clean(&self.target, 200), clean(&self.profile, 40)));
        o.push_str(&format!(
            "  TLS verification: {}\n",
            if self.tls_verified { "on" } else { "OFF (--insecure): the target's certificate was not checked" }
        ));
        o.push_str(&format!(
            "  requests sent: {}   duration: {:.1}s\n",
            self.requests,
            self.duration_ms as f64 / 1000.0
        ));
        let sev: Vec<String> = SEVERITIES
            .iter()
            .filter_map(|s| c.by_severity.get(*s).filter(|n| **n > 0).map(|n| format!("{n} {s}")))
            .collect();
        o.push_str(&format!(
            "  findings: {} ({} proven, {} suspected){}\n",
            c.total,
            c.proven,
            c.suspected,
            if sev.is_empty() { String::new() } else { format!("   by severity: {}", sev.join(", ")) }
        ));
        o.push_str(&format!(
            "  against the baseline: {} new, {} unchanged, {} fixed{}\n",
            c.new,
            c.unchanged,
            c.fixed,
            if self.baseline.is_none() { " (no baseline: everything is new)" } else { "" }
        ));
        for f in &self.findings {
            o.push_str(&format!(
                "  {} [{}] {}  {} {}{}  ({}, {})\n",
                if f.fails { "FAIL" } else { "    " },
                f.severity,
                f.status,
                f.method,
                f.path,
                if f.point.is_empty() { String::new() } else { format!(" ({})", f.point) },
                f.issue,
                f.state
            ));
        }
        for f in &self.fixed {
            o.push_str(&format!("  fixed? {} {} {} ({})\n", f.method, f.path, f.point, f.issue));
        }
        for s in &self.skipped {
            o.push_str(&format!("  skipped by the rules of engagement: {s}\n"));
        }
        for r in &self.incomplete {
            o.push_str(&format!("  INCOMPLETE: {r}\n"));
        }
        if let Some(p) = &self.baseline_written {
            o.push_str(&format!("  baseline written to {p}\n"));
        }
        let verdict = match self.exit_code {
            0 => "PASS: no new findings at or above the threshold".to_string(),
            1 => format!("FAIL: {} new finding(s) at or above the threshold", c.failing),
            _ => "NOT CLEAN: the run could not finish, so it says nothing about the target".to_string(),
        };
        o.push_str(&format!("  {verdict}\n  exit code {}\n", self.exit_code));
        o
    }

    /// JUnit XML: one test case per finding (a failure when it fails the run) and per step of the run (an error when
    /// the run could not finish there), plus one passing case per finding the baseline has and this run did not see.
    pub fn junit(&self) -> String {
        let mut cases = String::new();
        let (mut tests, mut failures, mut errors, mut skipped) = (0usize, 0usize, 0usize, 0usize);
        for ch in &self.checks {
            tests += 1;
            cases.push_str(&format!(
                "    <testcase classname=\"proxymind.run\" name=\"{}\" time=\"0\">",
                attr(&ch.name)
            ));
            match ch.outcome.as_str() {
                "error" => {
                    errors += 1;
                    cases.push_str(&format!("<error type=\"incomplete\" message=\"{}\"/>", attr(&ch.detail)));
                }
                "skipped" => {
                    skipped += 1;
                    cases.push_str(&format!("<skipped message=\"{}\"/>", attr(&ch.detail)));
                }
                _ => {}
            }
            cases.push_str("</testcase>\n");
        }
        for f in &self.findings {
            tests += 1;
            let name = format!(
                "{} {}{} [{}]",
                f.method,
                f.path,
                if f.point.is_empty() { String::new() } else { format!(" ({})", f.point) },
                &f.fingerprint[..f.fingerprint.len().min(8)]
            );
            cases.push_str(&format!(
                "    <testcase classname=\"proxymind.{}\" name=\"{}\" time=\"0\">",
                attr(&f.issue),
                attr(name.trim())
            ));
            let detail = format!(
                "{} severity, {}, {}\nfingerprint {}\n{}\n",
                f.severity, f.status, f.state, f.fingerprint, f.url
            );
            if f.fails {
                failures += 1;
                cases.push_str(&format!(
                    "<failure type=\"{}\" message=\"{}\">{}</failure>",
                    attr(&f.severity),
                    attr(&format!("new {} finding: {}", f.status, f.title)),
                    text(&detail)
                ));
            } else {
                cases.push_str(&format!("<system-out>{}</system-out>", text(&detail)));
            }
            cases.push_str("</testcase>\n");
        }
        for f in &self.fixed {
            tests += 1;
            cases.push_str(&format!(
                "    <testcase classname=\"proxymind.fixed\" name=\"{}\" time=\"0\"><system-out>{}</system-out></testcase>\n",
                attr(&format!("{} {} {} [{}]", f.method, f.path, f.point, &f.fingerprint[..f.fingerprint.len().min(8)])),
                text("in the baseline, not found in this run")
            ));
        }
        let time = format!("{:.3}", self.duration_ms as f64 / 1000.0);
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuites name=\"ProxyMind CI\" tests=\"{tests}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\" time=\"{time}\">\n  <testsuite name=\"proxymind\" tests=\"{tests}\" failures=\"{failures}\" errors=\"{errors}\" skipped=\"{skipped}\" time=\"{time}\">\n    <properties><property name=\"target\" value=\"{}\"/><property name=\"profile\" value=\"{}\"/><property name=\"exit_code\" value=\"{}\"/></properties>\n{cases}  </testsuite>\n</testsuites>\n",
            attr(&self.target),
            attr(&self.profile),
            self.exit_code
        )
    }
}

/// Escapes text for an XML attribute; characters XML cannot hold become spaces.
fn attr(s: &str) -> String {
    escape(s, true)
}

fn text(s: &str) -> String {
    escape(s, false)
}

fn escape(s: &str, attribute: bool) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' if attribute => o.push_str("&quot;"),
            '\'' if attribute => o.push_str("&apos;"),
            '\n' | '\t' if !attribute => o.push(c),
            c if c.is_control() => o.push(' '),
            // U+FFFE and U+FFFF are not XML characters.
            '\u{FFFE}' | '\u{FFFF}' => o.push(' '),
            c => o.push(c),
        }
    }
    o
}

fn level_of(severity: &str) -> &'static str {
    match severity {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// Turns the report's SARIF (one result per finding, `partialFingerprints.proxymindFinding` = the project's finding
/// id) into CI's: the stable fingerprint as the only partial fingerprint (so GitHub code scanning matches results
/// between runs), `baselineState` new or unchanged, target text and proof details left out, results for baseline
/// findings not seen now (`baselineState: absent`), and an `invocation` that says whether the run finished.
pub fn annotate_sarif(sarif: &mut Value, s: &CiSummary) {
    let by_id: BTreeMap<i64, &CiFinding> = s.findings.iter().map(|f| (f.finding_id, f)).collect();
    let Some(run) = sarif.pointer_mut("/runs/0") else { return };
    let mut results: Vec<Value> = Vec::new();
    let mut rules: Vec<Value> =
        run.pointer("/tool/driver/rules").and_then(Value::as_array).cloned().unwrap_or_default();
    for r in run["results"].as_array().cloned().unwrap_or_default() {
        let id = r["partialFingerprints"]["proxymindFinding"].as_str().and_then(|i| i.parse::<i64>().ok());
        let Some(f) = id.and_then(|i| by_id.get(&i)) else { continue };
        let mut message = format!("{} ({})", f.title, f.status);
        if let Some(p) = &f.proof {
            message = format!("{} (proven by {}, {} confidence)", f.title, p.oracle, p.confidence);
        }
        results.push(json!({
            "ruleId": r["ruleId"],
            "level": level_of(&f.severity),
            "message": { "text": message },
            "locations": [{ "physicalLocation": { "artifactLocation": { "uri": f.url } } }],
            "partialFingerprints": { "proxymindFingerprint/v1": f.fingerprint },
            "baselineState": f.state,
            "properties": {
                "severity": f.severity, "status": f.status, "proven": f.proven(), "method": f.method,
                "path": f.path, "point": f.point, "failsRun": f.fails, "findingId": f.finding_id,
                "proof": f.proof,
            },
        }));
    }
    for e in &s.fixed {
        let rule = if e.issue.is_empty() { "unknown".to_string() } else { e.issue.clone() };
        if !rules.iter().any(|r| r["id"] == json!(rule)) {
            rules.push(json!({ "id": rule, "name": rule, "shortDescription": { "text": rule } }));
        }
        results.push(json!({
            "ruleId": rule,
            "level": level_of(&e.severity),
            "message": { "text": format!("Not found in this run (in the baseline): {}", clean(&e.title, 200)) },
            "locations": [{ "physicalLocation": { "artifactLocation": { "uri": e.path } } }],
            "partialFingerprints": { "proxymindFingerprint/v1": e.fingerprint },
            "baselineState": "absent",
            "properties": { "severity": e.severity, "status": e.status, "method": e.method, "path": e.path, "point": e.point },
        }));
    }
    run["results"] = Value::Array(results);
    run["tool"]["driver"]["rules"] = Value::Array(rules);
    let notifications: Vec<Value> = s
        .incomplete
        .iter()
        .map(|m| json!({ "level": "error", "message": { "text": clean(m, 400) } }))
        .chain(s.skipped.iter().map(|m| json!({ "level": "warning", "message": { "text": clean(m, 400) } })))
        .collect();
    run["invocations"] = json!([{
        "executionSuccessful": s.complete,
        "exitCode": s.exit_code,
        "toolExecutionNotifications": notifications,
    }]);
    run["properties"] = json!({
        "target": s.target, "profile": s.profile, "complete": s.complete, "requests": s.requests,
        "tlsVerified": s.tls_verified, "counts": s.counts, "fingerprintVersion": FINGERPRINT_VERSION,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(issue: &str, method: &str, path: &str, point: &str, sev: &str, status: &str, id: i64) -> CiFinding {
        let key = fingerprint_key(issue, method, path, point);
        CiFinding {
            fingerprint: fingerprint_id(&key),
            key,
            issue: issue.into(),
            method: method.into(),
            path: path.into(),
            point: point.into(),
            severity: sev.into(),
            status: status.into(),
            title: format!("{issue} at {path}"),
            url: format!("https://app.test{path}"),
            proof: (status == "proven").then(|| CiProof { oracle: "sql_error".into(), confidence: "high".into() }),
            finding_id: id,
            state: String::new(),
            fails: false,
        }
    }

    #[test]
    fn fingerprint_is_stable_and_ignores_case_and_ids() {
        let a = fingerprint_key("SQLi", "get", "/api/orders/{id}", "Query q");
        assert_eq!(a, "v1|sqli|GET|/api/orders/{id}|query q");
        assert_eq!(fingerprint_id(&a), fingerprint_id(&a));
        assert_eq!(fingerprint_id(&a).len(), 32);
        assert_ne!(fingerprint_id(&a), fingerprint_id(&fingerprint_key("sqli", "POST", "/api/orders/{id}", "query q")));
        // The text is the contract: this pins the definition.
        assert_eq!(fingerprint_id("v1|sqli|GET|/search|query q"), "dca873609be3562defc28b956a660255");
    }

    #[test]
    fn paths_lose_scheme_host_query_and_extra_slashes() {
        assert_eq!(path_of("https://app.test:8443/api//orders/?a=1#x"), "/api/orders");
        assert_eq!(path_of("/search?q=1"), "/search");
        assert_eq!(path_of("https://app.test"), "/");
        assert_eq!(path_of("https://app.test?x=1"), "/");
        assert_eq!(path_of(""), "/");
    }

    #[test]
    fn points_come_from_scanner_titles_only() {
        assert_eq!(
            point_of_title("SQL injection (error-based) in GET /api/recommend (query ctx (base64))"),
            "query ctx (base64)"
        );
        assert_eq!(point_of_title("Reflected input in GET /search (Query q)"), "query q");
        assert_eq!(point_of_title("Exposed file: http://x/.git/config (source control metadata)"), "");
        assert_eq!(point_of_title("bob (not an admin) can call GET /api/admin/users"), "");
        assert_eq!(point_of_title("no parens in GET /x"), "");
    }

    #[test]
    fn env_references_expand_and_unset_ones_fail() {
        let env = |k: &str| (k == "PW").then(|| "s3cret".to_string());
        let mut used = Vec::new();
        assert_eq!(expand_env("pw=${PW} cost $$5 and $x", &env, &mut used).unwrap(), "pw=s3cret cost $5 and $x");
        assert_eq!(used, vec!["s3cret".to_string()]);
        assert!(expand_env("${NOPE}", &env, &mut used).unwrap_err().contains("NOPE is not set"));
        assert!(expand_env("${PW", &env, &mut used).is_err());
        assert!(expand_env("${a b}", &env, &mut used).is_err());
    }

    #[test]
    fn clean_removes_escapes_and_caps_length() {
        assert_eq!(clean("a\x1b[31mred\r\nb", 100), "a [31mred  b");
        assert_eq!(clean("abcdef", 3), "abc…");
    }

    #[test]
    fn classify_marks_new_unchanged_and_fixed() {
        let gate = Gate { fail_on: FailOn::Proven, min_severity: "low".into() };
        let mut now = vec![
            finding("sqli", "GET", "/a", "query q", "high", "proven", 1),
            finding("xss", "GET", "/b", "query q", "medium", "suspected", 2),
            finding("sqli", "GET", "/c", "query q", "high", "proven", 3),
        ];
        let base_findings = vec![
            finding("sqli", "GET", "/a", "query q", "high", "suspected", 10),
            finding("idor", "GET", "/gone/{id}", "", "high", "proven", 11),
        ];
        let baseline = Baseline::from_findings(&base_findings, true, "t", "x", "now");
        let fixed = classify(&mut now, Some(&baseline), &gate);
        assert_eq!(now[0].state, "unchanged", "status is not part of the fingerprint");
        assert!(!now[0].fails);
        assert_eq!(now[1].state, "new");
        assert!(!now[1].fails, "a suspected finding doesn't fail with --fail-on proven");
        assert!(now[2].fails);
        assert_eq!(fixed.len(), 1);
        assert_eq!(fixed[0].issue, "idor");
        let suspected = Gate { fail_on: FailOn::Suspected, min_severity: "medium".into() };
        classify(&mut now, Some(&baseline), &suspected);
        assert!(now[1].fails && now[2].fails && !now[0].fails);
        let high = Gate { fail_on: FailOn::Suspected, min_severity: "high".into() };
        classify(&mut now, None, &high);
        assert!(now[0].fails && !now[1].fails && now[2].fails, "without a baseline everything is new");
        let none = Gate { fail_on: FailOn::None, min_severity: "low".into() };
        classify(&mut now, None, &none);
        assert!(now.iter().all(|f| !f.fails));
    }

    #[test]
    fn baseline_round_trips_and_refuses_unknown_versions() {
        let f = vec![
            finding("sqli", "GET", "/a", "query q", "high", "proven", 1),
            finding("xss", "GET", "/b", "query q", "medium", "suspected", 2),
        ];
        let proven_only = Baseline::from_findings(&f, false, "https://t/", "ProxyMind 1", "2026-01-01T00:00:00Z");
        assert_eq!(proven_only.findings.len(), 1);
        let both = Baseline::from_findings(&f, true, "https://t/", "ProxyMind 1", "2026-01-01T00:00:00Z");
        assert_eq!(both.findings.len(), 2);
        assert_eq!(Baseline::parse(&both.to_json()).unwrap(), both);
        assert!(Baseline::parse("{}").is_err());
        assert!(Baseline::parse("[]").is_err());
        let wrong = both.to_json().replace("proxymind-ci-baseline-1", "other");
        assert!(Baseline::parse(&wrong).unwrap_err().contains("unknown baseline format"));
        let old = both.to_json().replace("\"fingerprint_version\": 1", "\"fingerprint_version\": 2");
        assert!(Baseline::parse(&old).unwrap_err().contains("fingerprint version 2"));
    }

    #[test]
    fn dedupe_prefers_proven_then_severity() {
        let a = finding("sqli", "GET", "/a", "query q", "medium", "suspected", 1);
        let mut b = a.clone();
        b.status = "proven".into();
        b.severity = "low".into();
        b.finding_id = 2;
        let out = dedupe(vec![a, b]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].finding_id, 2);
    }

    fn summary(findings: Vec<CiFinding>, fixed: Vec<BaselineEntry>, incomplete: Vec<String>) -> CiSummary {
        let mut s = CiSummary {
            format: SUMMARY_FORMAT.into(),
            tool: "ProxyMind test".into(),
            target: "https://app.test/".into(),
            profile: "light".into(),
            actor: "ci:ci".into(),
            started_at: "now".into(),
            duration_ms: 1500,
            requests: 42,
            tls_verified: true,
            fail_on: FailOn::Proven,
            min_severity: "low".into(),
            baseline: None,
            baseline_written: None,
            complete: true,
            incomplete,
            skipped: vec![],
            checks: vec![
                CiCheck::new("target reachable", "passed", ""),
                CiCheck::new("scan", "error", "budget \"spent\" <b>"),
                CiCheck::new("approval checks", "skipped", "needs approval"),
            ],
            counts: CiCounts::default(),
            findings,
            fixed,
            exit_code: 0,
        };
        s.finish();
        s
    }

    #[test]
    fn exit_codes_put_findings_before_incomplete_runs() {
        assert_eq!(exit_code(0, true), 0);
        assert_eq!(exit_code(1, true), 1);
        assert_eq!(exit_code(0, false), 2, "an unfinished run is never clean");
        assert_eq!(exit_code(2, false), 1);
    }

    #[test]
    fn junit_is_well_formed_and_escapes_target_text() {
        let gate = Gate { fail_on: FailOn::Proven, min_severity: "low".into() };
        let mut f = vec![finding("sqli", "GET", "/a<b>", "query \"q\"", "high", "proven", 1)];
        f[0].title = "evil </failure><x a=\"1\"> \u{1b}[31m".into();
        let fixed = classify(&mut f, None, &gate);
        let s = summary(f, fixed, vec!["budget exhausted".into()]);
        let x = s.junit();
        assert!(x.starts_with("<?xml"));
        assert!(!x.contains("</failure><x"), "{x}");
        assert!(!x.contains('\u{1b}'));
        assert!(x.contains("failures=\"1\"") && x.contains("errors=\"1\"") && x.contains("skipped=\"1\""), "{x}");
        assert!(x.contains("&lt;b&gt;") && x.contains("&quot;q&quot;"), "{x}");
        assert_eq!(x.matches("<testcase ").count(), 4);
        assert_eq!(x.matches("<testcase ").count(), x.matches("</testcase>").count());
    }

    #[test]
    fn sarif_gets_fingerprints_baseline_state_and_absent_results() {
        let gate = Gate { fail_on: FailOn::Proven, min_severity: "low".into() };
        let mut f = vec![finding("sqli", "GET", "/a", "query q", "high", "proven", 7)];
        let base = Baseline::from_findings(
            &[
                finding("sqli", "GET", "/a", "query q", "high", "proven", 1),
                finding("xss", "GET", "/gone", "query x", "medium", "proven", 2),
            ],
            true,
            "t",
            "x",
            "now",
        );
        let fixed = classify(&mut f, Some(&base), &gate);
        let s = summary(f, fixed, vec![]);
        let mut sarif = json!({"version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "ProxyMind", "rules": [{"id": "sqli"}]}},
            "results": [{"ruleId": "sqli", "level": "error", "message": {"text": "x"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "https://app.test/a"}}}],
                "partialFingerprints": {"proxymindFinding": "7"},
                "properties": {"description": "secret from the target"}}]}]});
        annotate_sarif(&mut sarif, &s);
        let results = sarif["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["baselineState"], "unchanged");
        assert_eq!(results[0]["partialFingerprints"]["proxymindFingerprint/v1"], json!(s.findings[0].fingerprint));
        assert!(results[0]["partialFingerprints"].get("proxymindFinding").is_none());
        assert!(!results[0].to_string().contains("secret from the target"));
        assert_eq!(results[1]["baselineState"], "absent");
        assert_eq!(results[1]["ruleId"], "xss");
        assert!(sarif["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().iter().any(|r| r["id"] == "xss"));
        assert_eq!(sarif["runs"][0]["invocations"][0]["executionSuccessful"], true);
    }

    #[test]
    fn text_summary_states_the_verdict() {
        let gate = Gate { fail_on: FailOn::Proven, min_severity: "low".into() };
        let mut f = vec![finding("sqli", "GET", "/a", "query q", "high", "proven", 1)];
        let fixed = classify(&mut f, None, &gate);
        let t = summary(f, fixed, vec![]).text();
        assert!(t.contains("FAIL: 1 new finding") && t.contains("exit code 1") && t.contains("1 proven"), "{t}");
        let t = summary(vec![], vec![], vec!["target unreachable".into()]).text();
        assert!(
            t.contains("INCOMPLETE: target unreachable") && t.contains("NOT CLEAN") && t.contains("exit code 2"),
            "{t}"
        );
        let t = summary(vec![], vec![], vec![]).text();
        assert!(t.contains("PASS") && t.contains("exit code 0"), "{t}");
    }
}
