//! Scan profiles: named sets of checks and limits for crawl-and-audit tasks.
//! Four are built in; people can save their own (project setting
//! `scan_profiles`). A task's own settings win over its profile's.

use pm_policy::{Actor, ActorKind};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Result, ScanTaskRequest, Service, ServiceError};

/// Project setting that holds the saved (not built-in) profiles as JSON.
pub const PROFILES_SETTING: &str = "scan_profiles";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanProfile {
    pub name: String,
    pub description: String,
    /// Checks to run; empty: every check except those that need approval.
    pub checks: Vec<String>,
    /// Also run the checks that need approval (request smuggling, file
    /// upload, race conditions) when `checks` is empty.
    pub approval_checks: bool,
    pub crawl: Option<bool>,
    pub max_pages: Option<usize>,
    pub browser: Option<bool>,
    pub max_targets: Option<usize>,
    pub max_requests: Option<usize>,
    /// Set by the service for the built-in profiles (they can't be changed).
    pub builtin: bool,
}

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// The profiles every project has.
pub fn builtin_profiles() -> Vec<ScanProfile> {
    vec![
        ScanProfile {
            name: "light".into(),
            description: "Quick look: a few fast checks, a short crawl, 60 requests per operation.".into(),
            checks: strs(&["reflected_input", "sql_error", "open_redirect", "path_traversal", "ssti", "cors"]),
            max_pages: Some(15),
            max_targets: Some(15),
            max_requests: Some(60),
            builtin: true,
            ..Default::default()
        },
        ScanProfile {
            name: "default".into(),
            description: "Every check that doesn't need approval, with the usual limits.".into(),
            builtin: true,
            ..Default::default()
        },
        ScanProfile {
            name: "thorough".into(),
            description: "Every check, including those that need approval (smuggling, uploads, races); a long crawl \
                          and a large budget."
                .into(),
            approval_checks: true,
            max_pages: Some(150),
            max_targets: Some(100),
            max_requests: Some(400),
            builtin: true,
            ..Default::default()
        },
        ScanProfile {
            name: "api-only".into(),
            description: "APIs from history or an imported description: no crawl, no browser-based checks.".into(),
            checks: strs(&[
                "sql_error",
                "sql_boolean",
                "sql_time",
                "nosql_operator",
                "cmd_injection",
                "cmd_time",
                "ssti",
                "path_traversal",
                "auth_bypass",
                "hidden_params",
                "cors",
                "jwt",
                "graphql",
                "mass_assignment",
                "proto_pollution",
                "deserialization",
                "ssrf_oob",
                "xxe_oob",
            ]),
            crawl: Some(false),
            browser: Some(false),
            max_targets: Some(60),
            builtin: true,
            ..Default::default()
        },
    ]
}

fn known_check(c: &str) -> bool {
    pm_scan::active::CHECKS.contains(&c) || pm_scan::oob::CHECKS.contains(&c)
}

impl ScanProfile {
    fn validate(&self) -> std::result::Result<(), String> {
        let n = self.name.trim();
        if n.is_empty() || n.len() > 40 || !n.chars().all(|c| c.is_ascii_alphanumeric() || "-_ ".contains(c)) {
            return Err("profile names are 1-40 letters, digits, spaces, - or _".into());
        }
        if builtin_profiles().iter().any(|b| b.name.eq_ignore_ascii_case(n)) {
            return Err(format!("{n} is a built-in profile; save yours under another name"));
        }
        if let Some(bad) = self.checks.iter().find(|c| !known_check(c)) {
            return Err(format!("unknown check {bad}"));
        }
        Ok(())
    }

    /// Fills the settings `req` leaves open from this profile.
    pub fn apply(&self, req: &mut ScanTaskRequest) {
        if req.checks.is_empty() {
            req.checks = if self.checks.is_empty() && self.approval_checks {
                pm_scan::active::CHECKS.iter().chain(pm_scan::oob::CHECKS).map(|c| c.to_string()).collect()
            } else {
                self.checks.clone()
            };
        }
        req.crawl = req.crawl.or(self.crawl);
        req.max_pages = req.max_pages.or(self.max_pages);
        req.browser = req.browser.or(self.browser);
        req.max_targets = req.max_targets.or(self.max_targets);
        req.max_requests = req.max_requests.or(self.max_requests);
    }
}

fn load_saved(store: &pm_store::Store) -> Result<Vec<ScanProfile>> {
    let mut saved: Vec<ScanProfile> = match store.get_setting(PROFILES_SETTING)? {
        Some(t) => serde_json::from_str(&t)
            .map_err(|e| ServiceError::Invalid(format!("saved scan profiles are unreadable: {e}")))?,
        None => Vec::new(),
    };
    for p in &mut saved {
        p.builtin = false;
    }
    Ok(saved)
}

impl Service {
    /// Built-in profiles first, then saved ones.
    pub fn scan_profiles(&self) -> Result<Vec<ScanProfile>> {
        let mut all = builtin_profiles();
        all.extend(load_saved(&self.store.lock())?);
        Ok(all)
    }

    pub fn scan_profile(&self, name: &str) -> Result<ScanProfile> {
        self.scan_profiles()?
            .into_iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| ServiceError::NotFound(format!("scan profile {name}")))
    }

    /// Saves (adds or replaces) a profile. Humans only.
    pub fn scan_profile_save(&self, actor: &Actor, mut p: ScanProfile) -> Result<Vec<ScanProfile>> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change scan profiles".into()));
        }
        p.name = p.name.trim().to_string();
        p.builtin = false;
        p.validate().map_err(ServiceError::Invalid)?;
        {
            let mut store = self.store.lock();
            let mut saved = load_saved(&store)?;
            saved.retain(|s| !s.name.eq_ignore_ascii_case(&p.name));
            saved.push(p.clone());
            if saved.len() > 50 {
                return Err(ServiceError::Invalid("at most 50 saved profiles".into()));
            }
            let text = serde_json::to_string(&saved).map_err(|e| ServiceError::Invalid(e.to_string()))?;
            store.set_setting(PROFILES_SETTING, &text)?;
        }
        self.audit(&actor.id(), "scan_profile_save", json!(p), "allow")?;
        self.scan_profiles()
    }

    pub fn scan_profile_delete(&self, actor: &Actor, name: &str) -> Result<bool> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change scan profiles".into()));
        }
        let removed = {
            let mut store = self.store.lock();
            let mut saved = load_saved(&store)?;
            let before = saved.len();
            saved.retain(|s| !s.name.eq_ignore_ascii_case(name));
            let text = serde_json::to_string(&saved).map_err(|e| ServiceError::Invalid(e.to_string()))?;
            store.set_setting(PROFILES_SETTING, &text)?;
            saved.len() < before
        };
        self.audit(
            &actor.id(),
            "scan_profile_delete",
            json!({ "name": name }),
            if removed { "allow" } else { "noop" },
        )?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_are_valid_and_fill_only_open_settings() {
        for p in builtin_profiles() {
            assert!(p.checks.iter().all(|c| known_check(c)), "{}", p.name);
        }
        let thorough = builtin_profiles().into_iter().find(|p| p.name == "thorough").unwrap();
        let mut req = ScanTaskRequest { max_requests: Some(10), ..Default::default() };
        thorough.apply(&mut req);
        assert_eq!(req.max_requests, Some(10), "the task's own setting wins");
        assert_eq!(req.max_pages, Some(150));
        assert!(req.checks.iter().any(|c| c == "request_smuggling"));
        let mut named = ScanTaskRequest { checks: vec!["sql_error".into()], ..Default::default() };
        thorough.apply(&mut named);
        assert_eq!(named.checks, vec!["sql_error"]);
    }

    #[test]
    fn saved_profiles_need_new_names_and_known_checks() {
        let p =
            |name: &str, checks: &[&str]| ScanProfile { name: name.into(), checks: strs(checks), ..Default::default() };
        assert!(p("nightly", &["sql_error"]).validate().is_ok());
        assert!(p("Default", &[]).validate().is_err());
        assert!(p("x", &["nope"]).validate().is_err());
        assert!(p("bad/name", &[]).validate().is_err());
    }
}
