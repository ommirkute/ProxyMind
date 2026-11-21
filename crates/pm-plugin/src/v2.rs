//! Plugin API v2 (ADR-0020): declared permissions, traffic hooks, and the per-user state that goes with them.
//!
//! A manifest with `api: 2` lists the things the plugin may do under `permissions:` and uses only those. The
//! registry keeps the permission list a person accepted next to the plugin ([`State`]); a plugin whose manifest
//! asks for something else than what was accepted stays off until the person accepts the new list. Manifests
//! without `api` are version 1 and behave as before: no permissions, nothing to accept.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{Manifest, PluginError, Result};

/// The file next to the registry that holds accepted permissions and hook settings.
pub const STATE_FILE: &str = "plugin-state.json";

pub const HOOKS_REQUEST: &str = "hooks.request";
pub const HOOKS_RESPONSE: &str = "hooks.response";
pub const CHECKS_PASSIVE: &str = "checks.passive";
pub const CHECKS_ACTIVE: &str = "checks.active";
pub const PANELS: &str = "panels";
pub const HISTORY_READ: &str = "history.read";

/// Every permission a v2 manifest may declare.
pub const PERMISSIONS: [&str; 6] = [HOOKS_REQUEST, HOOKS_RESPONSE, CHECKS_PASSIVE, CHECKS_ACTIVE, PANELS, HISTORY_READ];

/// Slowest a hook call may be allowed to run (milliseconds).
pub const MAX_HOOK_TIMEOUT_MS: u64 = 2000;
/// Default deadline of a hook call (milliseconds).
pub const DEFAULT_HOOK_TIMEOUT_MS: u64 = 200;

/// What the proxy does with a message when its hook fails.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnError {
    /// Forward the original message (fail open). The default.
    #[default]
    Pass,
    /// Drop the message: a request gets ProxyMind's 403, a response a 502 (fail closed).
    Drop,
}

/// Which messages a hook sees. Empty lists match everything.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HookMatch {
    /// Host patterns; `*` matches any run of characters (`*.example.com`).
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Path prefixes (`/api/`).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Request methods.
    #[serde(default)]
    pub methods: Vec<String>,
    /// Media types of the message's own `Content-Type` (`application/json`, or `text/*`).
    #[serde(default)]
    pub content_types: Vec<String>,
}

/// One hook of a v2 plugin: a long-lived command that gets messages and answers.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HookSpec {
    /// Program and arguments, run in the plugin's directory (as for passive plugins).
    pub command: Vec<String>,
    #[serde(default, rename = "match")]
    pub matcher: HookMatch,
    /// Deadline of one call (default 200, at most 2000).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub on_error: OnError,
}

impl HookSpec {
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms.unwrap_or(DEFAULT_HOOK_TIMEOUT_MS).clamp(1, MAX_HOOK_TIMEOUT_MS)
    }
}

/// The `hooks:` section of a v2 manifest.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Hooks {
    #[serde(default)]
    pub request: Option<HookSpec>,
    #[serde(default)]
    pub response: Option<HookSpec>,
}

/// Request hook or response hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookKind {
    Request,
    Response,
}

impl HookKind {
    pub const ALL: [HookKind; 2] = [HookKind::Request, HookKind::Response];

    pub fn as_str(self) -> &'static str {
        match self {
            HookKind::Request => "request",
            HookKind::Response => "response",
        }
    }

    pub fn parse(s: &str) -> Option<HookKind> {
        HookKind::ALL.into_iter().find(|k| k.as_str() == s)
    }

    /// The permission a hook of this kind needs.
    pub fn permission(self) -> &'static str {
        match self {
            HookKind::Request => HOOKS_REQUEST,
            HookKind::Response => HOOKS_RESPONSE,
        }
    }
}

/// The id of a hook: `<plugin>/<kind>`.
pub fn hook_id(plugin: &str, kind: HookKind) -> String {
    format!("{plugin}/{}", kind.as_str())
}

impl Manifest {
    /// The plugin API version: 1 unless the manifest says `api: 2`.
    pub fn api_version(&self) -> u32 {
        self.api.unwrap_or(1)
    }

    pub fn is_v2(&self) -> bool {
        self.api_version() == 2
    }

    /// The hook of this kind, if the manifest declares one.
    pub fn hook(&self, kind: HookKind) -> Option<&HookSpec> {
        let h = self.hooks.as_ref()?;
        match kind {
            HookKind::Request => h.request.as_ref(),
            HookKind::Response => h.response.as_ref(),
        }
    }

    /// The permissions this manifest declares, sorted and without repeats.
    pub fn declared_permissions(&self) -> Vec<String> {
        let mut p = self.permissions.clone();
        p.sort();
        p.dedup();
        p
    }
}

/// Checks the v2 parts of a manifest (the version, the permission names, and that everything the plugin uses is
/// declared). Version 1 manifests must not use v2 sections.
pub(crate) fn validate(m: &Manifest) -> Result<()> {
    match m.api {
        None | Some(1) => {
            if !m.permissions.is_empty() || m.hooks.is_some() {
                return Err(PluginError::Invalid("`permissions:` and `hooks:` need `api: 2` in the manifest".into()));
            }
            return Ok(());
        }
        Some(2) => {}
        Some(n) => return Err(PluginError::Invalid(format!("unknown plugin api version {n} (use 1 or 2)"))),
    }
    for p in &m.permissions {
        if !PERMISSIONS.contains(&p.as_str()) {
            return Err(PluginError::Invalid(format!("unknown permission {p:?} (known: {})", PERMISSIONS.join(", "))));
        }
    }
    let declared = m.declared_permissions();
    let has = |p: &str| declared.iter().any(|d| d == p);
    let need = |used: bool, what: &str, perm: &str| -> Result<()> {
        if used && !has(perm) {
            return Err(PluginError::Invalid(format!(
                "the plugin uses {what} but doesn't declare the `{perm}` permission"
            )));
        }
        Ok(())
    };
    need(m.passive.is_some(), "`passive:`", CHECKS_PASSIVE)?;
    need(m.active.is_some(), "`active:`", CHECKS_ACTIVE)?;
    need(!m.panels.is_empty(), "`panels:`", PANELS)?;
    for kind in HookKind::ALL {
        need(m.hook(kind).is_some(), &format!("a {} hook", kind.as_str()), kind.permission())?;
    }
    for kind in HookKind::ALL {
        let Some(h) = m.hook(kind) else { continue };
        if h.command.is_empty() {
            return Err(PluginError::Invalid(format!("hooks.{}.command is empty", kind.as_str())));
        }
        if h.timeout_ms.is_some_and(|t| t == 0 || t > MAX_HOOK_TIMEOUT_MS) {
            return Err(PluginError::Invalid(format!(
                "hooks.{}.timeout_ms must be 1 to {MAX_HOOK_TIMEOUT_MS}",
                kind.as_str()
            )));
        }
        for method in &h.matcher.methods {
            if method.is_empty() || !method.chars().all(|c| c.is_ascii_alphabetic()) {
                return Err(PluginError::Invalid(format!(
                    "hooks.{}.match.methods: {method:?} is not a method",
                    kind.as_str()
                )));
            }
        }
        for ct in &h.matcher.content_types {
            if !ct.contains('/') {
                return Err(PluginError::Invalid(format!(
                    "hooks.{}.match.content_types: {ct:?} is not a media type (like application/json)",
                    kind.as_str()
                )));
            }
        }
    }
    Ok(())
}

/// Per-user state kept beside the registry: accepted permissions and how hooks are set up.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    /// Plugin name -> the permission list a person accepted (v2 plugins only).
    #[serde(default)]
    pub accepted: BTreeMap<String, Vec<String>>,
    /// Hook ids (`<plugin>/<kind>`) in the order the person set; hooks not listed come after, in registry order.
    #[serde(default)]
    pub hook_order: Vec<String>,
    /// Hook ids a person turned on.
    #[serde(default)]
    pub hooks_on: Vec<String>,
}

impl State {
    pub fn load(path: &Path) -> Result<State> {
        match std::fs::read_to_string(path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| PluginError::Invalid(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn is_empty(&self) -> bool {
        *self == State::default()
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if self.is_empty() && !path.exists() {
            return Ok(());
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| PluginError::Invalid(e.to_string()))?;
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Forgets everything about a plugin (it was removed or reinstalled as version 1).
    pub fn forget(&mut self, plugin: &str) {
        self.accepted.remove(plugin);
        let prefix = format!("{plugin}/");
        self.hook_order.retain(|h| !h.starts_with(&prefix));
        self.hooks_on.retain(|h| !h.starts_with(&prefix));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MANIFEST, load_manifest};

    fn load(text: &str) -> Result<Manifest> {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("pm-plugin-v2-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(MANIFEST), text).unwrap();
        let r = load_manifest(&dir);
        let _ = std::fs::remove_dir_all(&dir);
        r
    }

    const HOOK: &str = "name: signer\nversion: 1\napi: 2\npermissions: [hooks.request]\nhooks:\n  request:\n    command: [python3, hook.py]\n";

    #[test]
    fn v1_manifests_stay_v1() {
        let m = load("name: a\nversion: 1\npassive:\n  command: [x]\n").unwrap();
        assert_eq!((m.api_version(), m.is_v2(), m.permissions.len()), (1, false, 0));
        assert!(load("name: a\nversion: 1\napi: 1\npassive:\n  command: [x]\n").is_ok());
        assert!(
            load("name: a\nversion: 1\npassive:\n  command: [x]\npermissions: [panels]\n").is_err(),
            "v1 can't declare"
        );
        assert!(load("name: a\nversion: 1\napi: 3\npassive:\n  command: [x]\n").is_err(), "unknown version");
    }

    #[test]
    fn a_v2_hook_manifest_parses_with_defaults_and_matchers() {
        let m = load(HOOK).unwrap();
        assert!(m.is_v2());
        let h = m.hook(HookKind::Request).unwrap();
        assert_eq!((h.timeout_ms(), h.on_error), (200, OnError::Pass));
        assert!(m.hook(HookKind::Response).is_none());

        let full = format!(
            "{HOOK}    match: {{ hosts: [\"*.example.com\"], paths: [\"/api/\"], methods: [POST], content_types: [application/json] }}\n    timeout_ms: 500\n    on_error: drop\n"
        );
        let h = load(&full).unwrap().hook(HookKind::Request).cloned().unwrap();
        assert_eq!((h.timeout_ms(), h.on_error), (500, OnError::Drop));
        assert_eq!(h.matcher.hosts, ["*.example.com"]);
        assert_eq!((h.matcher.paths.len(), h.matcher.methods.len(), h.matcher.content_types.len()), (1, 1, 1));
    }

    #[test]
    fn permissions_are_validated() {
        assert!(load(&HOOK.replace("hooks.request", "hooks.everything")).is_err(), "unknown permission");
        // Using a feature without declaring it is refused at install.
        assert!(load(&HOOK.replace("[hooks.request]", "[panels]")).is_err(), "hook without hooks.request");
        let active = "name: a\nversion: 1\napi: 2\npermissions: [checks.passive]\nactive:\n  command: [x]\n";
        let e = load(active).unwrap_err().to_string();
        assert!(e.contains("checks.active"), "{e}");
        let panel = "name: a\nversion: 1\napi: 2\npermissions: [checks.active]\npanels:\n  - id: p\n    title: P\n    command: [x]\n";
        assert!(load(panel).unwrap_err().to_string().contains("panels"));
        // Declared and used is fine, and so is declaring more than is used.
        assert!(
            load(
                "name: a\nversion: 1\napi: 2\npermissions: [checks.passive, history.read]\npassive:\n  command: [x]\n"
            )
            .is_ok()
        );
    }

    #[test]
    fn hook_limits_are_checked() {
        assert!(load(&format!("{HOOK}    timeout_ms: 2001\n")).is_err());
        assert!(load(&format!("{HOOK}    timeout_ms: 0\n")).is_err());
        assert!(load(&format!("{HOOK}    on_error: explode\n")).is_err());
        assert!(load(&format!("{HOOK}    match: {{ content_types: [json] }}\n")).is_err());
        assert!(load(&HOOK.replace("[python3, hook.py]", "[]")).is_err());
        assert!(load(&format!("{HOOK}    bogus: 1\n")).is_err(), "unknown fields");
    }

    #[test]
    fn state_round_trips_and_forgets() {
        let mut s = State::default();
        s.accepted.insert("a".into(), vec!["panels".into()]);
        s.hook_order = vec!["a/request".into(), "b/request".into()];
        s.hooks_on = vec!["a/request".into(), "b/request".into()];
        let path = std::env::temp_dir().join(format!("pm-plugin-state-{}.json", std::process::id()));
        s.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap(), s);
        s.forget("a");
        assert_eq!(
            (s.accepted.len(), s.hook_order.clone(), s.hooks_on.clone()),
            (0, vec!["b/request".to_string()], vec!["b/request".to_string()])
        );
        let _ = std::fs::remove_file(&path);
    }
}
