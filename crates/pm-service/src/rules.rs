//! Match-and-replace rules, stored in the project and applied by the proxy.

use std::sync::Arc;

use pm_policy::{Actor, ActorKind, Policy, Target};
use pm_proxy::Rewriter;
use pm_proxy::rewrite::{self, Rule};
use pm_store::Store;
use serde_json::json;

use crate::{Result, Service, ServiceError};

/// Project setting that holds the rules as JSON.
pub const RULES_SETTING: &str = "match_replace_rules";

/// Reads the saved rules (none if never set).
pub fn load_rules(store: &Store) -> Result<Vec<Rule>> {
    match store.get_setting(RULES_SETTING)? {
        Some(text) => serde_json::from_str(&text)
            .map_err(|e| ServiceError::Invalid(format!("saved match-and-replace rules are unreadable: {e}"))),
        None => Ok(vec![]),
    }
}

/// Loads the saved rules into `r` if they differ from what it has.
/// Returns true when the rules changed.
pub fn sync_rules(store: &Store, r: &Rewriter) -> Result<bool> {
    let rules = load_rules(store)?;
    if rules == r.rules() {
        return Ok(false);
    }
    r.set_rules(rules).map_err(ServiceError::Invalid)?;
    Ok(true)
}

impl Service {
    /// Connects the proxy's rewriter: in-scope-only rules use this
    /// project's rules of engagement, and saved rules are loaded now.
    pub fn attach_rewriter(&self, r: Arc<Rewriter>) -> Result<()> {
        let policy = Arc::new(Policy::new(self.policy.roe().clone()));
        r.set_scope(Arc::new(move |scheme, host, port, path| {
            Target::from_parts(scheme, host, port, path).is_ok_and(|t| policy.scope_check(&t).is_ok())
        }));
        sync_rules(&self.store.lock(), &r)?;
        let _ = self.rewriter.set(r);
        Ok(())
    }

    pub fn match_replace_rules(&self) -> Result<Vec<Rule>> {
        load_rules(&self.store.lock())
    }

    /// Replaces the rules. Humans only: rules change every request the
    /// browser sends, which is not an agent's call to make.
    pub fn set_match_replace_rules(&self, actor: &Actor, rules: Vec<Rule>) -> Result<Vec<Rule>> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change match-and-replace rules".into()));
        }
        rewrite::validate(&rules).map_err(ServiceError::Invalid)?;
        let text = serde_json::to_string(&rules).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.lock().set_setting(RULES_SETTING, &text)?;
        self.audit(&actor.id(), "match_replace_rules", json!({ "rules": rules }), "allow")?;
        if let Some(r) = self.rewriter.get() {
            r.set_rules(rules.clone()).map_err(ServiceError::Invalid)?;
        }
        Ok(rules)
    }
}
