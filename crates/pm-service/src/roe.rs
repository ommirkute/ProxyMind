//! The rules of engagement: read by anyone, changed only by humans. A change
//! is audited and applies at once to the gate, the rate limits and the
//! proxy's scope checks; other processes on the same project pick it up
//! within seconds (`watch_roe`).

use std::sync::Arc;

use pm_policy::{Actor, ActorKind, Roe, Tier};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError};

/// Project setting holding the ROE YAML.
pub const ROE_SETTING: &str = "roe";

/// The rules as text plus what they mean.
#[derive(Debug, Clone, Serialize)]
pub struct RoeView {
    /// The YAML as saved (None when the project has none saved).
    pub text: Option<String>,
    pub summary: Value,
}

fn tier_name(t: Tier) -> String {
    serde_json::to_value(t).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

/// What a ROE allows, in plain fields.
pub fn summarize(roe: &Roe) -> Value {
    let kinds = [
        ("human", ActorKind::Human),
        ("agent", ActorKind::Agent),
        ("plugin", ActorKind::Plugin),
        ("scanner", ActorKind::Scanner),
    ];
    let tiers = [Tier::Read, Tier::Passive, Tier::ActiveSafe, Tier::ActiveIntrusive, Tier::Destructive];
    let permissions: serde_json::Map<String, Value> = kinds
        .iter()
        .map(|(name, kind)| {
            let row: serde_json::Map<String, Value> =
                tiers.iter().map(|t| (tier_name(*t), json!(roe.tier_decision(*kind, *t).as_str()))).collect();
            (name.to_string(), Value::Object(row))
        })
        .collect();
    json!({
        "engagement": {
            "name": roe.engagement.name,
            "starts": roe.engagement.starts.map(|d| d.to_string()),
            "ends": roe.engagement.ends.map(|d| d.to_string()),
        },
        "in_scope": roe.include.iter().map(|p| &p.text).collect::<Vec<_>>(),
        "excluded": roe.exclude.iter().map(|p| &p.text).collect::<Vec<_>>(),
        "denied_networks": roe.deny_networks.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "timezone": roe.timezone.iana_name(),
        "windows": roe.windows.len(),
        "limits": {
            "max_requests_per_second_per_host": roe.limits.max_rps_per_host,
            "max_concurrency": roe.limits.max_concurrency,
        },
        "data": {
            "redact_before_llm": roe.data.redact_before_llm,
            "allow_cloud_models": roe.data.allow_cloud_models,
        },
        "permissions": permissions,
    })
}

impl Service {
    /// The rules in force and their saved text.
    pub fn roe_get(&self) -> Result<RoeView> {
        let text = self.store.lock().get_setting(ROE_SETTING)?;
        Ok(RoeView { text, summary: summarize(&self.policy.roe()) })
    }

    /// Validates a ROE without saving it.
    pub fn roe_check(&self, text: &str) -> Result<Value> {
        let roe = Roe::parse(text).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        Ok(summarize(&roe))
    }

    /// Replaces the rules. Humans only: agents work inside the rules and can never change them.
    pub fn roe_set(&self, actor: &Actor, text: &str) -> Result<RoeView> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change the rules of engagement".into()));
        }
        if text.len() > 1024 * 1024 {
            return Err(ServiceError::Invalid("ROE larger than 1 MB".into()));
        }
        let roe = Roe::parse(text).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let old = self.store.lock().get_setting(ROE_SETTING)?.unwrap_or_default();
        self.store.lock().set_setting(ROE_SETTING, text)?;
        self.apply_roe(roe, text);
        self.audit(
            &actor.id(),
            "roe_change",
            json!({ "old_blake3": pm_policy::audit::content_hash(old.as_bytes()), "new_blake3": pm_policy::audit::content_hash(text.as_bytes()), "summary": self.roe_get()?.summary }),
            "ok",
        )?;
        self.roe_get()
    }

    fn apply_roe(&self, roe: Roe, text: &str) {
        self.limiter.set_limits(roe.limits.max_rps_per_host, roe.limits.max_concurrency);
        self.policy.set_roe(roe);
        *self.roe_text.lock() = Some(text.to_string());
    }

    /// Applies the saved ROE if another process changed it. Returns whether it changed.
    /// A saved ROE that no longer parses is ignored (the rules in force stay).
    pub fn sync_roe(&self) -> Result<bool> {
        let Some(text) = self.store.lock().get_setting(ROE_SETTING)? else { return Ok(false) };
        if self.roe_text.lock().as_deref() == Some(text.as_str()) {
            return Ok(false);
        }
        let first = self.roe_text.lock().is_none();
        match Roe::parse(&text) {
            Ok(roe) => {
                self.apply_roe(roe, &text);
                Ok(!first)
            }
            Err(e) => Err(ServiceError::Invalid(format!("saved ROE not applied: {e}"))),
        }
    }
}

/// Checks every two seconds for ROE changes saved by another process.
pub fn watch_roe(service: Arc<Service>) {
    if let Err(e) = service.sync_roe() {
        tracing::warn!("{e}");
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            match service.sync_roe() {
                Ok(true) => eprintln!("Rules of engagement changed; now in force."),
                Ok(false) => {}
                Err(e) => tracing::warn!("{e}"),
            }
        }
    });
}
