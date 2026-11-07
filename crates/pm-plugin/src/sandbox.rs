//! How plugin processes run.
//!
//! - **Environment:** cleared, so a plugin doesn't inherit API keys, tokens
//!   or proxy settings. It gets `PATH`, a locale, `HOME` set to its own
//!   directory and `PROXYMIND_PLUGIN=1` (plus what Windows needs to start
//!   programs).
//! - **Network (Linux):** the process runs in new user and network
//!   namespaces (`unshare --user --net`), which have no interfaces but
//!   loopback, so it can't reach anything. Active plugins don't need the
//!   network: ProxyMind sends their requests through the policy gate.
//! - **Limits (Linux):** `prlimit` caps CPU time, writable memory, file
//!   size and open files.
//! - Everywhere: a timeout and capped output (see [`crate::run`]).
//!
//! Where namespaces or `prlimit` aren't available (macOS, Windows, some
//! containers), [`status`] says so and plugins run with your permissions;
//! install only plugins you trust.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

use serde::Serialize;

/// What the sandbox can do on this machine.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Status {
    /// Plugins can't reach the network.
    pub network_isolated: bool,
    /// CPU, memory, file size and open-file limits apply.
    pub limits: bool,
    /// One line for people.
    pub summary: String,
}

struct Tools {
    /// Arguments to `unshare` that work here, if any.
    unshare: Option<Vec<&'static str>>,
    prlimit: bool,
}

fn base_env(cmd: &mut Command) {
    cmd.env_clear();
    let path = std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into());
    cmd.env("PATH", path);
    cmd.env("LANG", "C.UTF-8").env("PROXYMIND_PLUGIN", "1");
    // Windows can't start most programs without these; macOS keeps a
    // per-user temp directory.
    for k in ["SYSTEMROOT", "SYSTEMDRIVE", "PATHEXT", "TEMP", "TMP", "TMPDIR", "COMSPEC"] {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
}

fn works(program: &str, args: &[&str]) -> bool {
    let mut c = Command::new(program);
    base_env(&mut c);
    c.args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    c.status().is_ok_and(|s| s.success())
}

fn tools() -> &'static Tools {
    static T: OnceLock<Tools> = OnceLock::new();
    T.get_or_init(|| {
        if !cfg!(target_os = "linux") || std::env::var("PROXYMIND_PLUGIN_SANDBOX").is_ok_and(|v| v == "off") {
            return Tools { unshare: None, prlimit: false };
        }
        let unshare = [vec!["--user", "--map-current-user", "--net"], vec!["--user", "--map-root-user", "--net"]]
            .into_iter()
            .find(|args| {
                let mut probe = args.clone();
                probe.extend(["--", "true"]);
                works("unshare", &probe)
            });
        let prlimit = works("prlimit", &["--nofile=512", "--", "true"]);
        Tools { unshare, prlimit }
    })
}

/// What the sandbox does on this machine.
pub fn status() -> Status {
    let t = tools();
    let network_isolated = t.unshare.is_some();
    let summary = match (network_isolated, t.prlimit) {
        (true, true) => "no network access, CPU/memory/file limits, clean environment".to_string(),
        (true, false) => "no network access, clean environment (prlimit not found: no resource limits)".to_string(),
        (false, true) => {
            "clean environment and resource limits, but plugins CAN reach the network (user namespaces unavailable)"
                .to_string()
        }
        (false, false) => {
            "clean environment only: plugins run with your permissions and CAN reach the network".to_string()
        }
    };
    Status { network_isolated, limits: t.prlimit, summary }
}

/// The command that runs `command` (program and arguments) for a plugin
/// in `dir`, inside the sandbox. A program starting with `./` is in `dir`.
pub fn command(dir: &Path, command: &[String], timeout: Duration) -> Result<Command, String> {
    let (first, rest) = command.split_first().ok_or("the plugin's command is empty")?;
    let program = match first.strip_prefix("./") {
        Some(local) => {
            if local.split(['/', '\\']).any(|part| part == "..") {
                return Err(format!("{first}: a plugin's program must be inside its directory"));
            }
            dir.join(local).to_string_lossy().into_owned()
        }
        None => first.clone(),
    };
    let t = tools();
    let mut argv: Vec<String> = Vec::new();
    if let Some(args) = &t.unshare {
        argv.push("unshare".into());
        argv.extend(args.iter().map(|a| a.to_string()));
        argv.push("--".into());
    }
    if t.prlimit {
        argv.extend([
            "prlimit".to_string(),
            format!("--cpu={}", timeout.as_secs() + 5),
            "--data=4294967296".into(),  // 4 GiB of writable memory
            "--fsize=1073741824".into(), // 1 GiB per file written
            "--nofile=512".into(),
            "--".into(),
        ]);
    }
    argv.push(program);
    argv.extend(rest.iter().cloned());
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).current_dir(dir);
    base_env(&mut cmd);
    cmd.env("HOME", dir);
    Ok(cmd)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only the Unix tests run commands.
    #[cfg(unix)]
    fn run(cmd: &mut Command) -> (bool, String) {
        let out = cmd.stdin(Stdio::null()).output().unwrap();
        (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
    }

    #[test]
    fn programs_stay_in_their_directory() {
        let dir = std::env::temp_dir();
        assert!(command(&dir, &["./../x".into()], Duration::from_secs(1)).is_err());
        assert!(command(&dir, &[], Duration::from_secs(1)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn the_environment_is_clean() {
        let dir = std::env::temp_dir();
        let mut c = command(&dir, &["sh".into(), "-c".into(), "env".into()], Duration::from_secs(5)).unwrap();
        let (ok, env) = run(&mut c);
        assert!(ok);
        assert!(env.contains("PROXYMIND_PLUGIN=1") && env.contains("PATH="), "{env}");
        // Whatever this process has (CI tokens, proxies, model keys) stays out.
        for secret in ["ANTHROPIC_API_KEY", "HTTPS_PROXY", "GITHUB_TOKEN"] {
            assert!(!env.contains(&format!("{secret}=")), "{secret} leaked");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn no_network_where_namespaces_work() {
        if !status().network_isolated {
            return; // not available on this machine
        }
        let dir = std::env::temp_dir();
        // Only the loopback interface exists in the plugin's network namespace.
        let mut c = command(&dir, &["cat".into(), "/proc/net/dev".into()], Duration::from_secs(5)).unwrap();
        let (ok, dev) = run(&mut c);
        assert!(ok);
        let ifaces: Vec<&str> = dev.lines().skip(2).filter_map(|l| l.split(':').next()).map(str::trim).collect();
        assert_eq!(ifaces, ["lo"], "{dev}");
    }
}
