//! Plugins: extend ProxyMind without touching its core.
//!
//! Two kinds, both outside the trust boundary of the core:
//!
//! - **Acting plugins** use the MCP tools as `plugin:<name>` actors
//!   (`proxymind mcp --actor plugin:<name>`). The policy gate treats them
//!   more strictly than agents. Nothing in this crate is needed for them.
//! - **Passive-check plugins** (this crate) analyse recorded traffic. They
//!   are any executable: ProxyMind writes one JSON line per exchange to its
//!   stdin, closes it, and reads one JSON line per issue from its stdout.
//!   They send nothing themselves; what they report is untrusted input that
//!   is validated, clipped and labelled with the plugin's name.
//! - **Active-check plugins** ([`active`]) propose requests for one recorded
//!   exchange; ProxyMind sends them through the policy gate and gives the
//!   responses back to the plugin, which reports issues. They never touch
//!   the network themselves.
//!
//! Every plugin process runs in a [`sandbox`]: a clean environment, no
//! network where the OS allows it (Linux user namespaces), memory and CPU
//! limits, a timeout and capped output.
//!
//! Plugins are installed per user (a registry in the ProxyMind home
//! directory), never per project: a project file handed over by someone
//! else must not decide what runs on your machine.

pub mod active;
pub mod sandbox;

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub const MANIFEST: &str = "proxymind-plugin.yaml";
pub const REGISTRY: &str = "plugins.json";
/// Most output read from a plugin (bytes).
pub const MAX_OUTPUT: usize = 8 * 1024 * 1024;
pub const MAX_ISSUES: usize = 2000;

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("{0}")]
    Invalid(String),
    #[error("plugin {name}: {why}")]
    Run { name: String, why: String },
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, PluginError>;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Lowercase letters, digits and dashes.
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub passive: Option<Passive>,
    #[serde(default)]
    pub active: Option<active::Active>,
}

impl Manifest {
    /// "passive", "active" or both.
    pub fn kinds(&self) -> Vec<&'static str> {
        let mut k = Vec::new();
        if self.passive.is_some() {
            k.push("passive");
        }
        if self.active.is_some() {
            k.push("active");
        }
        k
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Passive {
    /// Program and arguments, run in the plugin's directory. A first
    /// element starting with `./` is relative to that directory.
    pub command: Vec<String>,
    /// Seconds before the plugin is stopped (default 60, max 600).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// An installed plugin.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Installed {
    pub dir: PathBuf,
    pub manifest: Manifest,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 40 && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Reads and checks `dir/proxymind-plugin.yaml`.
pub fn load_manifest(dir: &Path) -> Result<Manifest> {
    let path = dir.join(MANIFEST);
    let text =
        std::fs::read_to_string(&path).map_err(|e| PluginError::Invalid(format!("reading {}: {e}", path.display())))?;
    let m: Manifest =
        serde_saphyr::from_str(&text).map_err(|e| PluginError::Invalid(format!("{}: {e}", path.display())))?;
    if !valid_name(&m.name) {
        return Err(PluginError::Invalid(format!(
            "plugin name {:?}: use lowercase letters, digits and dashes",
            m.name
        )));
    }
    if m.passive.is_none() && m.active.is_none() {
        return Err(PluginError::Invalid("the plugin declares nothing to run (add `passive:` or `active:`)".into()));
    }
    if m.passive.as_ref().is_some_and(|p| p.command.is_empty()) {
        return Err(PluginError::Invalid("passive.command is empty".into()));
    }
    if let Some(a) = &m.active {
        if a.command.is_empty() {
            return Err(PluginError::Invalid("active.command is empty".into()));
        }
        if a.max_requests.is_some_and(|n| n == 0 || n > active::MAX_PROBES) {
            return Err(PluginError::Invalid(format!("active.max_requests must be 1 to {}", active::MAX_PROBES)));
        }
    }
    Ok(m)
}

/// The user's plugin registry (`<home>/plugins.json`).
pub struct Registry {
    path: PathBuf,
    pub plugins: Vec<Installed>,
}

impl Registry {
    pub fn load(home: &Path) -> Result<Self> {
        let path = home.join(REGISTRY);
        let plugins = match std::fs::read_to_string(&path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| PluginError::Invalid(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Registry { path, plugins })
    }

    pub fn save(&self) -> Result<()> {
        if let Some(d) = self.path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let text = serde_json::to_string_pretty(&self.plugins).map_err(|e| PluginError::Invalid(e.to_string()))?;
        std::fs::write(&self.path, text)?;
        Ok(())
    }

    /// Installs (or updates) the plugin in `dir`.
    pub fn add(&mut self, dir: &Path) -> Result<&Installed> {
        let dir = dir.canonicalize()?;
        let manifest = load_manifest(&dir)?;
        let name = manifest.name.clone();
        self.plugins.retain(|p| p.manifest.name != manifest.name);
        self.plugins.push(Installed { dir, manifest, enabled: true });
        self.plugins.sort_by(|a, b| a.manifest.name.cmp(&b.manifest.name));
        self.plugins
            .iter()
            .find(|p| p.manifest.name == name)
            .ok_or_else(|| PluginError::Invalid("plugin vanished after install".into()))
    }

    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.plugins.len();
        self.plugins.retain(|p| p.manifest.name != name);
        before != self.plugins.len()
    }

    pub fn enabled(&self) -> Vec<Installed> {
        self.plugins.iter().filter(|p| p.enabled).cloned().collect()
    }

    /// Turns a plugin on or off. Returns false if there is no such plugin.
    pub fn set_enabled(&mut self, name: &str, enabled: bool) -> bool {
        match self.plugins.iter_mut().find(|p| p.manifest.name == name) {
            Some(p) => {
                p.enabled = enabled;
                true
            }
            None => false,
        }
    }
}

/// One exchange as sent to a passive plugin.
#[derive(Debug, Clone, Serialize)]
pub struct ExchangeLine {
    pub exchange_id: i64,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Raw bytes, base64.
    pub request: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
}

/// An issue reported by a plugin, after validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginIssue {
    pub plugin: String,
    pub exchange_id: i64,
    pub check: String,
    pub title: String,
    /// info, low, medium or high
    pub severity: String,
    pub evidence: String,
}

#[derive(Deserialize)]
struct RawIssue {
    exchange_id: i64,
    check: String,
    title: String,
    severity: String,
    #[serde(default)]
    evidence: String,
}

fn clip(s: &str, n: usize) -> String {
    let s: String = s.chars().filter(|c| !c.is_control() || *c == ' ').collect();
    if s.chars().count() <= n { s } else { format!("{}…", s.chars().take(n).collect::<String>()) }
}

/// Parses a plugin's output. Bad lines and issues about exchanges it wasn't
/// given are dropped (and counted).
pub fn parse_issues(plugin: &str, output: &str, known: &std::collections::HashSet<i64>) -> (Vec<PluginIssue>, usize) {
    let mut issues = Vec::new();
    let mut rejected = 0;
    for line in output.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(r) = serde_json::from_str::<RawIssue>(line) else {
            rejected += 1;
            continue;
        };
        let severity = r.severity.to_ascii_lowercase();
        let check_ok = valid_name(&r.check.replace('_', "-"));
        if !known.contains(&r.exchange_id)
            || !check_ok
            || !["info", "low", "medium", "high"].contains(&severity.as_str())
            || issues.len() >= MAX_ISSUES
        {
            rejected += 1;
            continue;
        }
        issues.push(PluginIssue {
            plugin: plugin.to_string(),
            exchange_id: r.exchange_id,
            check: r.check,
            title: clip(&r.title, 120),
            severity,
            evidence: clip(&r.evidence, 300),
        });
    }
    (issues, rejected)
}

/// Runs a passive plugin over `exchanges` and returns its issues and how
/// many output lines were rejected.
pub fn run_passive(p: &Installed, exchanges: &[ExchangeLine]) -> Result<(Vec<PluginIssue>, usize)> {
    let spec = p.manifest.passive.as_ref().ok_or_else(|| run_err(p, "not a passive plugin".into()))?;
    let input: Vec<u8> =
        exchanges.iter().filter_map(|x| serde_json::to_string(x).ok()).flat_map(|l| (l + "\n").into_bytes()).collect();
    let out = run(p, &spec.command, spec.timeout_seconds.unwrap_or(60), input)?;
    let known = exchanges.iter().map(|x| x.exchange_id).collect();
    Ok(parse_issues(&p.manifest.name, &String::from_utf8_lossy(&out), &known))
}

fn run_err(p: &Installed, why: String) -> PluginError {
    PluginError::Run { name: p.manifest.name.clone(), why }
}

/// Runs one plugin command in the sandbox: writes `input` to its stdin and
/// returns its stdout (at most [`MAX_OUTPUT`] bytes).
pub(crate) fn run(p: &Installed, command: &[String], timeout_seconds: u64, input: Vec<u8>) -> Result<Vec<u8>> {
    let timeout = Duration::from_secs(timeout_seconds.clamp(1, 600));
    let mut cmd = sandbox::command(&p.dir, command, timeout).map_err(|why| run_err(p, why))?;
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| run_err(p, format!("could not start {}: {e}", command[0])))?;
    let mut stdin = child.stdin.take().ok_or_else(|| run_err(p, "no stdin".into()))?;
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let stdout = child.stdout.take().ok_or_else(|| run_err(p, "no stdout".into()))?;
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut r = BufReader::new(stdout);
        let _ = (&mut r).take(MAX_OUTPUT as u64).read_to_end(&mut out);
        // Keep draining past the limit so the plugin isn't blocked writing.
        let _ = std::io::copy(&mut r, &mut std::io::sink());
        out
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(run_err(p, format!("stopped after {} s", timeout.as_secs())));
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = writer.join();
    let out = reader.join().unwrap_or_default();
    if !status.success() {
        return Err(run_err(p, format!("exited with {status}")));
    }
    Ok(out)
}

/// Reads JSON lines from a plugin's stdin (for plugins written in Rust and
/// for tests).
pub fn read_lines(r: impl Read) -> impl Iterator<Item = String> {
    BufReader::new(r).lines().map_while(std::result::Result::ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_are_checked() {
        let dir = std::env::temp_dir().join(format!("pm-plugin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let write = |s: &str| std::fs::write(dir.join(MANIFEST), s).unwrap();
        write("name: jwt-alg\nversion: 0.1.0\npassive:\n  command: [\"python3\", \"check.py\"]\n");
        assert_eq!(load_manifest(&dir).unwrap().name, "jwt-alg");
        write("name: Bad Name\nversion: 1\npassive:\n  command: [x]\n");
        assert!(load_manifest(&dir).is_err());
        write("name: x\nversion: 1\n");
        assert!(load_manifest(&dir).is_err(), "nothing to run");
        write("name: x\nversion: 1\npassive:\n  command: [x]\nextra: 1\n");
        assert!(load_manifest(&dir).is_err(), "unknown fields");

        write("name: jwt-alg\nversion: 0.1.0\npassive:\n  command: [\"python3\", \"check.py\"]\n");
        let home = dir.join("home");
        let mut r = Registry::load(&home).unwrap();
        r.add(&dir).unwrap();
        r.add(&dir).unwrap();
        r.save().unwrap();
        let r2 = Registry::load(&home).unwrap();
        assert_eq!(r2.plugins.len(), 1, "re-adding updates");
        let mut r2 = r2;
        assert!(r2.remove("jwt-alg") && !r2.remove("jwt-alg"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn plugin_output_is_validated() {
        let known: std::collections::HashSet<i64> = [1, 2].into();
        let out = concat!(
            "{\"exchange_id\":1,\"check\":\"jwt_none\",\"title\":\"JWT alg none\",\"severity\":\"HIGH\",\"evidence\":\"a\\u0007b\"}\n",
            "{\"exchange_id\":9,\"check\":\"x\",\"title\":\"not given\",\"severity\":\"low\"}\n",
            "{\"exchange_id\":2,\"check\":\"Bad Check\",\"title\":\"t\",\"severity\":\"low\"}\n",
            "{\"exchange_id\":2,\"check\":\"x\",\"title\":\"t\",\"severity\":\"critical!\"}\n",
            "not json\n\n"
        );
        let (issues, rejected) = parse_issues("jwt-alg", out, &known);
        assert_eq!(rejected, 4);
        assert_eq!(issues.len(), 1);
        assert_eq!((issues[0].severity.as_str(), issues[0].evidence.as_str()), ("high", "ab"));
    }
}
