//! Network settings (upstream proxy, client certificates), stored in the
//! project and used by every sender: proxy, Replay, agents and proofs.

use std::sync::Arc;

use pm_policy::{Actor, ActorKind};
use pm_proxy::{ListenerConfig, ListenerStatus, Listeners};
use pm_replay::{NetConfig, Network};
use pm_store::Store;
use serde::Serialize;
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

/// Project setting that holds the extra proxy listeners as JSON.
pub const LISTENERS_SETTING: &str = "proxy_listeners";

pub fn load_listeners(store: &Store) -> Result<Vec<ListenerConfig>> {
    match store.get_setting(LISTENERS_SETTING)? {
        Some(text) => serde_json::from_str(&text)
            .map_err(|e| ServiceError::Invalid(format!("saved proxy listeners are unreadable: {e}"))),
        None => Ok(Vec::new()),
    }
}

/// Starts and stops listeners to match the project (inside the runtime).
pub fn sync_listeners(store: &Store, listeners: &Listeners) -> Result<()> {
    listeners.sync(&load_listeners(store)?);
    Ok(())
}

/// Extra proxy listeners and whether each is running in this process.
#[derive(Debug, Clone, Serialize)]
pub struct ListenersView {
    /// The proxy's main listener (from the command line), if this process runs one.
    pub primary: Option<String>,
    pub listeners: Vec<ListenerConfig>,
    /// Empty when this process doesn't run the proxy.
    pub status: Vec<ListenerStatus>,
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
        Ok(self.store.read(load_network)?.masked())
    }

    /// Replaces the settings. Humans only. A password of `********` keeps
    /// the saved one, so a masked value can be sent back unchanged.
    pub fn network_set(&self, actor: &Actor, mut cfg: NetConfig) -> Result<NetConfig> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change network settings".into()));
        }
        let saved = self.store.read(load_network)?;
        if let (Some(new), Some(old)) = (cfg.upstream.as_mut(), saved.upstream.as_ref())
            && new.password == "********"
        {
            new.password = old.password.clone();
        }
        self.network().set(cfg.clone()).map_err(|e| ServiceError::Invalid(format!("{e:#}")))?;
        let text = serde_json::to_string(&cfg).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.write(|db| db.set_setting(NETWORK_SETTING, &text))?;
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
    listeners: Option<Arc<Listeners>>,
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
    if let Some(l) = &listeners {
        sync_listeners(&store, l)?;
        for st in l.status() {
            match st.error {
                Some(e) => eprintln!("Extra proxy listener {}: {e}", st.bind),
                None => eprintln!("Extra proxy listener on http://{}", st.bind),
            }
        }
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
            if let Some(l) = &listeners
                && let Err(e) = sync_listeners(&store, l)
            {
                tracing::warn!("proxy listeners: {e}");
            }
        }
    });
    Ok(())
}

impl Service {
    /// Lets the service start, stop and report the proxy's extra listeners.
    pub fn attach_listeners(&self, l: Arc<Listeners>) -> Result<()> {
        self.store.read(|db| sync_listeners(db, &l))?;
        let _ = self.listeners.set(l);
        Ok(())
    }

    pub fn listeners_get(&self) -> Result<ListenersView> {
        let listeners = self.store.read(load_listeners)?;
        let (primary, status) = match self.listeners.get() {
            Some(l) => (l.primary().map(str::to_string), l.status()),
            None => (None, vec![]),
        };
        Ok(ListenersView { primary, listeners, status })
    }

    /// Replaces the extra listeners. Humans only: a listener on a public
    /// interface lets other machines use the proxy.
    pub fn listeners_set(&self, actor: &Actor, list: Vec<ListenerConfig>) -> Result<ListenersView> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change proxy listeners".into()));
        }
        pm_proxy::listeners::validate(&list).map_err(|e| ServiceError::Invalid(format!("{e:#}")))?;
        let text = serde_json::to_string(&list).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.write(|db| db.set_setting(LISTENERS_SETTING, &text))?;
        if let Some(l) = self.listeners.get() {
            l.sync(&list);
        }
        self.audit(&actor.id(), "proxy_listeners", json!(list), "allow")?;
        self.listeners_get()
    }
}

/// Project setting: what the proxy records in history.
pub const RECORDING_SETTING: &str = "history_recording";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RecordingSettings {
    /// Keep only exchanges whose target is in the rules of engagement's
    /// scope (everything else is still proxied, just not recorded).
    pub in_scope_only: bool,
}

fn load_recording(store: &Store) -> Result<RecordingSettings> {
    match store.get_setting(RECORDING_SETTING)? {
        Some(t) => serde_json::from_str(&t)
            .map_err(|e| ServiceError::Invalid(format!("saved recording settings are unreadable: {e}"))),
        None => Ok(RecordingSettings::default()),
    }
}

impl Service {
    pub fn recording_get(&self) -> Result<RecordingSettings> {
        self.store.read(load_recording)
    }

    /// Changes what the proxy records. Humans only.
    pub fn recording_set(&self, actor: &Actor, s: RecordingSettings) -> Result<RecordingSettings> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change what is recorded".into()));
        }
        let text = serde_json::to_string(&s).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.write(|db| db.set_setting(RECORDING_SETTING, &text))?;
        self.record_in_scope_only.store(s.in_scope_only, std::sync::atomic::Ordering::Relaxed);
        self.audit(&actor.id(), "history_recording", json!(s), "allow")?;
        Ok(s)
    }

    /// Re-reads the recording settings (changes from another process).
    pub fn sync_recording(&self) -> Result<()> {
        let s = self.store.read(load_recording)?;
        self.record_in_scope_only.store(s.in_scope_only, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Whether the proxy should record this exchange.
    pub fn should_record(&self, ex: &pm_store::NewExchange) -> bool {
        !self.record_in_scope_only.load(std::sync::atomic::Ordering::Relaxed)
            || pm_policy::Target::from_parts(&ex.scheme, &ex.host, ex.port, &ex.path)
                .is_ok_and(|t| self.policy.scope_check(&t).is_ok())
    }

    /// Makes the proxy's recorder follow these settings.
    pub fn attach_recorder(self: &Arc<Self>, recorder: &pm_proxy::Recorder) -> Result<()> {
        self.sync_recording()?;
        let me = Arc::downgrade(self);
        recorder.set_filter(Some(Arc::new(move |ex| me.upgrade().is_none_or(|s| s.should_record(ex)))));
        Ok(())
    }
}
