//! Network settings (upstream proxy, client certificates), stored in the
//! project and used by every sender: proxy, Replay, agents and proofs.

use std::sync::Arc;

use pm_policy::{Actor, ActorKind};
use pm_proxy::{ListenerConfig, ListenerStatus, Listeners};
use pm_replay::{NetConfig, Network};
use pm_store::Store;
use serde::Serialize;
use serde_json::json;

use crate::api_types::{UpstreamResolution, UpstreamResolveRequest};
use crate::{Result, Service, ServiceError};

/// Project setting that holds the network settings as JSON.
pub const NETWORK_SETTING: &str = "network";

/// The saved network settings. A project saved with the older single `upstream` loads as a list of upstream rules.
pub fn load_network(store: &Store) -> Result<NetConfig> {
    match store.get_setting(NETWORK_SETTING)? {
        Some(text) => serde_json::from_str::<NetConfig>(&text)
            .map_err(|e| ServiceError::Invalid(format!("saved network settings are unreadable: {e}")))?
            .normalized()
            .map_err(|e| ServiceError::Invalid(format!("saved network settings are unreadable: {e:#}"))),
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
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ListenersView {
    /// The proxy's main listener (from the command line), if this process runs one.
    pub primary: Option<String>,
    /// The saved listeners; SOCKS5 passwords show as `********`.
    pub listeners: Vec<ListenerConfig>,
    /// Empty when this process doesn't run the proxy.
    pub status: Vec<ListenerStatus>,
    /// This build can take traffic the operating system redirected (`transparent` listeners): Linux only.
    pub transparent_supported: bool,
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

    /// Replaces the settings. Humans only. A password of `********` keeps the saved one (of the upstream rule with
    /// the same `via` and username), so a masked value can be sent back unchanged.
    pub fn network_set(&self, actor: &Actor, cfg: NetConfig) -> Result<NetConfig> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change network settings".into()));
        }
        let saved = self.store.read(load_network)?;
        let mut cfg = cfg;
        // The older single `upstream` keeps its masked password whatever else changed (as it always did).
        if let Some(u) = cfg.upstream.as_mut()
            && u.password == "********"
            && let Some(old) = saved.upstream_rules.iter().rev().find(|r| r.via != "direct" && r.username == u.username)
        {
            u.password.clone_from(&old.password);
        }
        let mut cfg = cfg.normalized().map_err(|e| ServiceError::Invalid(format!("{e:#}")))?;
        for r in cfg.upstream_rules.iter_mut().filter(|r| r.password == "********") {
            let old = saved.upstream_rules.iter().find(|o| o.via == r.via && o.username == r.username);
            match old {
                Some(o) => r.password.clone_from(&o.password),
                None => {
                    return Err(ServiceError::Invalid(format!(
                        "no saved password for {} (user {:?}): type it again",
                        r.via, r.username
                    )));
                }
            }
        }
        self.network().set(cfg.clone()).map_err(|e| ServiceError::Invalid(format!("{e:#}")))?;
        let text = serde_json::to_string(&cfg).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.write(|db| db.set_setting(NETWORK_SETTING, &text))?;
        self.audit(&actor.id(), "network_settings", json!(cfg.masked()), "allow")?;
        Ok(cfg.masked())
    }

    /// Which upstream rule decides how `host` is reached: the saved rules, or `rules` when given (to try a draft
    /// before saving it). Sends nothing.
    pub fn network_resolve(&self, req: &UpstreamResolveRequest) -> Result<UpstreamResolution> {
        let host = req.host.trim().trim_matches(['[', ']']);
        if host.is_empty() || host.len() > 253 || host.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ServiceError::Invalid("give a host name or IP address".into()));
        }
        let cfg = match &req.rules {
            Some(rules) => {
                let cfg = NetConfig { upstream_rules: rules.clone(), ..Default::default() };
                for (i, r) in cfg.upstream_rules.iter().enumerate() {
                    r.validate().map_err(|e| ServiceError::Invalid(format!("upstream rule {}: {e:#}", i + 1)))?;
                }
                cfg
            }
            None => self.store.read(load_network)?,
        };
        Ok(match cfg.resolve(host) {
            Some((i, pattern)) => {
                let r = &cfg.upstream_rules[i];
                UpstreamResolution {
                    rule_index: Some(i),
                    pattern,
                    direct: r.via.trim().eq_ignore_ascii_case("direct"),
                    via: r.via.clone(),
                    remote_dns: r.remote_dns,
                }
            }
            None => UpstreamResolution {
                rule_index: None,
                pattern: None,
                direct: true,
                via: "direct".into(),
                remote_dns: false,
            },
        })
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
    for (i, r) in net.upstream_rules.iter().enumerate() {
        // Never the login: only where traffic goes.
        let who = if r.matches.is_empty() { "all other hosts".to_string() } else { r.matches.join(", ") };
        eprintln!("Upstream rule {}: {who} via {}", i + 1, r.via);
    }
    if !net.client_certs.is_empty() {
        eprintln!("{} client certificate(s) configured", net.client_certs.len());
    }
    if let Some(l) = &listeners {
        sync_listeners(&store, l)?;
        for st in l.status() {
            match st.error {
                Some(e) => eprintln!("Extra proxy listener {}: {e}", st.bind),
                None => match (st.kind, st.transparent) {
                    (pm_proxy::ListenerKind::Socks5, _) => eprintln!("SOCKS5 listener on socks5://{}", st.bind),
                    (_, true) => eprintln!("Transparent listener on {} (redirected traffic)", st.bind),
                    _ => eprintln!("Extra proxy listener on http://{}", st.bind),
                },
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
        let listeners = self.store.read(load_listeners)?.iter().map(ListenerConfig::masked).collect();
        let (primary, status) = match self.listeners.get() {
            Some(l) => (l.primary().map(str::to_string), l.status()),
            None => (None, vec![]),
        };
        Ok(ListenersView { primary, listeners, status, transparent_supported: pm_proxy::transparent::SUPPORTED })
    }

    /// Replaces the extra listeners. Humans only: a listener on a public
    /// interface lets other machines use the proxy.
    pub fn listeners_set(&self, actor: &Actor, mut list: Vec<ListenerConfig>) -> Result<ListenersView> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change proxy listeners".into()));
        }
        // A masked password keeps the one saved for the same address.
        let saved = self.store.read(load_listeners)?;
        for l in list.iter_mut().filter(|l| l.password == pm_proxy::listeners::MASKED_PASSWORD) {
            let old = saved.iter().find(|o| o.bind.trim() == l.bind.trim() && o.username == l.username);
            match old {
                Some(o) => l.password.clone_from(&o.password),
                None => {
                    return Err(ServiceError::Invalid(format!(
                        "no saved password for the listener on {}: type it again",
                        l.bind
                    )));
                }
            }
        }
        pm_proxy::listeners::validate(&list).map_err(|e| ServiceError::Invalid(format!("{e:#}")))?;
        let text = serde_json::to_string(&list).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.write(|db| db.set_setting(LISTENERS_SETTING, &text))?;
        if let Some(l) = self.listeners.get() {
            l.sync(&list);
        }
        let shown: Vec<ListenerConfig> = list.iter().map(ListenerConfig::masked).collect();
        self.audit(&actor.id(), "proxy_listeners", json!(shown), "allow")?;
        self.listeners_get()
    }
}

/// Project setting: what the proxy records in history.
pub const RECORDING_SETTING: &str = "history_recording";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, serde::Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RecordingSettings {
    /// Keep only exchanges whose target is in the rules of engagement's
    /// scope (everything else is still proxied, just not recorded).
    pub in_scope_only: bool,
    /// Keep only traffic from these client IP addresses, e.g. one phone (empty: record every client). Other
    /// clients are still proxied, just not recorded. Combines with `in_scope_only`: both must hold.
    pub record_devices: Vec<String>,
}

/// Most devices `record_devices` can name.
pub const MAX_RECORD_DEVICES: usize = 64;

/// Checks and normalises an IP address (no port) typed or sent for a client: IPv4-mapped IPv6 becomes IPv4.
pub(crate) fn normalize_client_ip(text: &str) -> Result<String> {
    let t = text.trim().trim_matches(['[', ']']);
    t.parse::<std::net::IpAddr>()
        .map(|ip| ip.to_canonical().to_string())
        .map_err(|_| ServiceError::Invalid(format!("{text:?} is not an IP address (e.g. 192.168.1.23)")))
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
        if s.record_devices.len() > MAX_RECORD_DEVICES {
            return Err(ServiceError::Invalid(format!("at most {MAX_RECORD_DEVICES} devices")));
        }
        let mut s = s;
        let mut devices = Vec::new();
        for d in &s.record_devices {
            let ip = normalize_client_ip(d)?;
            if !devices.contains(&ip) {
                devices.push(ip);
            }
        }
        s.record_devices = devices;
        let text = serde_json::to_string(&s).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.write(|db| db.set_setting(RECORDING_SETTING, &text))?;
        self.apply_recording(&s);
        self.audit(&actor.id(), "history_recording", json!(s), "allow")?;
        Ok(s)
    }

    fn apply_recording(&self, s: &RecordingSettings) {
        self.record_in_scope_only.store(s.in_scope_only, std::sync::atomic::Ordering::Relaxed);
        *self.record_devices.write() = s.record_devices.iter().cloned().collect();
    }

    /// Re-reads the recording settings (changes from another process).
    pub fn sync_recording(&self) -> Result<()> {
        let s = self.store.read(load_recording)?;
        self.apply_recording(&s);
        Ok(())
    }

    /// Whether the proxy should record this exchange.
    pub fn should_record(&self, ex: &pm_store::NewExchange) -> bool {
        {
            let only = self.record_devices.read();
            if !only.is_empty() && !ex.client_addr.as_deref().is_some_and(|a| only.contains(a)) {
                return false;
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn project(name: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("pm-net-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Store::open(&dir.join("p.pmproj")).unwrap()
    }

    /// A project saved before upstream rules existed: one `upstream` with a bypass list.
    const OLD: &str = r#"{"upstream":{"kind":"http","host":"proxy.corp.test","port":3128,"username":"u","password":"pw","remote_dns":false,"bypass":["localhost","*.lan"]},"client_certs":[],"hosts":[],"tls_passthrough":["pinned.test"]}"#;

    #[test]
    fn a_project_with_the_old_single_upstream_loads_as_rules() {
        let mut store = project("old");
        store.set_setting(NETWORK_SETTING, OLD).unwrap();
        let cfg = load_network(&store).unwrap();
        assert!(cfg.upstream.is_none());
        assert_eq!(cfg.tls_passthrough, ["pinned.test"]);
        assert_eq!(cfg.upstream_rules.len(), 2);
        assert_eq!(cfg.upstream_rules[0].via, "direct");
        assert_eq!(cfg.upstream_rules[0].matches, ["localhost", "*.lan"]);
        let proxy = &cfg.upstream_rules[1];
        assert_eq!(
            (proxy.via.as_str(), proxy.username.as_str(), proxy.password.as_str()),
            ("http://proxy.corp.test:3128", "u", "pw")
        );
        assert!(proxy.matches.is_empty());
        // The same hosts go the same ways as before: bypassed hosts direct, everything else through the proxy.
        let net = Network::new();
        assert!(sync_network(&store, &net).unwrap());
        assert_eq!(net.resolve("localhost").map(|r| r.0), Some(0));
        assert_eq!(net.resolve("printer.lan").map(|r| r.0), Some(0));
        assert_eq!(net.resolve("shop.test").map(|r| r.0), Some(1));
        assert!(!sync_network(&store, &net).unwrap(), "unchanged settings are not re-applied");
        // Without bypass hosts it is one rule.
        let bare = r#"{"upstream":{"kind":"socks5","host":"127.0.0.1","port":1080}}"#;
        store.set_setting(NETWORK_SETTING, bare).unwrap();
        let cfg = load_network(&store).unwrap();
        assert_eq!(cfg.upstream_rules.len(), 1);
        assert_eq!(cfg.upstream_rules[0].via, "socks5://127.0.0.1:1080");
        // Saving writes the new form only.
        let text = serde_json::to_string(&cfg).unwrap();
        assert!(text.contains("upstream_rules") && !text.contains("\"upstream\":"), "{text}");
        // Empty and new-form settings load too.
        store.set_setting(NETWORK_SETTING, "{}").unwrap();
        assert_eq!(load_network(&store).unwrap(), NetConfig::default());
        // Unknown fields are still refused (a typo is not silently ignored).
        store.set_setting(NETWORK_SETTING, r#"{"upstream_rule":[]}"#).unwrap();
        assert!(load_network(&store).is_err());
    }

    #[test]
    fn old_listeners_load_as_http_listeners() {
        let mut store = project("old-listeners");
        store
            .set_setting(
                LISTENERS_SETTING,
                r#"[{"bind":"127.0.0.1:8081","enabled":true,"redirect_host":"","redirect_port":0,"force_tls":false}]"#,
            )
            .unwrap();
        let l = load_listeners(&store).unwrap();
        assert_eq!(l.len(), 1);
        assert_eq!(l[0].kind, pm_proxy::ListenerKind::Http);
        assert!(!l[0].transparent && l[0].username.is_empty());
    }
}
