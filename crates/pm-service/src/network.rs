//! Network settings (upstream proxy, client certificates), stored in the
//! project and used by every sender: proxy, Repeater, agents and proofs.

use pm_policy::{Actor, ActorKind};
use pm_replay::{NetConfig, Network};
use pm_store::Store;
use serde_json::json;

use crate::{Result, Service, ServiceError};

/// Project setting that holds the network settings as JSON.
pub const NETWORK_SETTING: &str = "network";

pub fn load_network(store: &Store) -> Result<NetConfig> {
    match store.get_setting(NETWORK_SETTING)? {
        Some(text) => serde_json::from_str(&text)
            .map_err(|e| ServiceError::Invalid(format!("saved network settings are unreadable: {e}"))),
        None => Ok(NetConfig::default()),
    }
}

/// Applies the saved settings to `net` if they changed; true when they did.
pub fn sync_network(store: &Store, net: &Network) -> Result<bool> {
    let cfg = load_network(store)?;
    if cfg == net.config() {
        return Ok(false);
    }
    net.set(cfg).map_err(|e| ServiceError::Invalid(format!("{e:#}")))?;
    Ok(true)
}

impl Service {
    /// The live network settings this service sends with; share it with
    /// the proxy so both use the same upstream proxy and certificates.
    pub fn network(&self) -> &Network {
        self.sender.network()
    }

    /// Current settings, with the proxy password hidden.
    pub fn network_get(&self) -> Result<NetConfig> {
        Ok(load_network(&self.store.lock())?.masked())
    }

    /// Replaces the settings. Humans only. A password of `********` keeps
    /// the saved one, so a masked value can be sent back unchanged.
    pub fn network_set(&self, actor: &Actor, mut cfg: NetConfig) -> Result<NetConfig> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change network settings".into()));
        }
        let saved = load_network(&self.store.lock())?;
        if let (Some(new), Some(old)) = (cfg.upstream.as_mut(), saved.upstream.as_ref())
            && new.password == "********"
        {
            new.password = old.password.clone();
        }
        self.network().set(cfg.clone()).map_err(|e| ServiceError::Invalid(format!("{e:#}")))?;
        let text = serde_json::to_string(&cfg).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.lock().set_setting(NETWORK_SETTING, &text)?;
        self.audit(&actor.id(), "network_settings", json!(cfg.masked()), "allow")?;
        Ok(cfg.masked())
    }
}
/// Keeps match-and-replace rules and network settings in step with the
/// project, so changes from the CLI or another UI apply without a restart.
pub fn watch_project(
    project: &std::path::Path,
    rewriter: Option<std::sync::Arc<pm_proxy::Rewriter>>,
    network: pm_replay::Network,
) -> anyhow::Result<()> {
    let store = pm_store::Store::open(project)?;
    if let Some(r) = &rewriter {
        if let Err(e) = crate::sync_rules(&store, r) {
            eprintln!("Match-and-replace rules not loaded: {e}");
        }
        let n = r.rules().iter().filter(|r| r.enabled).count();
        if n > 0 {
            eprintln!("{n} match-and-replace rule(s) active");
        }
    }
    if let Err(e) = crate::sync_network(&store, &network) {
        eprintln!("Network settings not applied: {e}");
    }
    let net = network.config();
    if let Some(u) = &net.upstream {
        eprintln!("Upstream proxy: {:?} {}:{}", u.kind, u.host, u.port);
    }
    if !net.client_certs.is_empty() {
        eprintln!("{} client certificate(s) configured", net.client_certs.len());
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Some(r) = &rewriter {
                match crate::sync_rules(&store, r) {
                    Ok(true) => eprintln!("Match-and-replace rules reloaded"),
                    Ok(false) => {}
                    Err(e) => tracing::warn!("match-and-replace rules: {e}"),
                }
            }
            match crate::sync_network(&store, &network) {
                Ok(true) => eprintln!("Network settings reloaded"),
                Ok(false) => {}
                Err(e) => tracing::warn!("network settings: {e}"),
            }
        }
    });
    Ok(())
}
