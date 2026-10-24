//! Extra proxy listeners, configured in the project: more ports, other
//! interfaces (e.g. for a phone on the LAN), and per-listener redirects for
//! clients that can't be told where to go.
//!
//! Every listener accepts both normal proxy clients (absolute-form requests
//! and CONNECT) and invisible ones (origin-form requests routed by their
//! Host header, TLS routed by its server name).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Result, bail, ensure};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::Proxy;

/// Most extra listeners a project can have.
pub const MAX_LISTENERS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerConfig {
    /// Address and port, e.g. `127.0.0.1:8081` or `0.0.0.0:8082`.
    pub bind: String,
    pub enabled: bool,
    /// Send every request to this host instead of where the client asked
    /// (empty: no redirect). The Host header is left as the client sent it.
    pub redirect_host: String,
    pub redirect_port: u16,
    /// With a redirect: connect to it with TLS even for plain-HTTP clients.
    pub force_tls: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self { bind: String::new(), enabled: true, redirect_host: String::new(), redirect_port: 0, force_tls: false }
    }
}

/// Where a listener sends every request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    pub host: String,
    pub port: u16,
    pub force_tls: bool,
}

impl ListenerConfig {
    pub fn addr(&self) -> Result<SocketAddr> {
        match self.bind.trim().parse() {
            Ok(a) => Ok(a),
            Err(_) => bail!("listener address {:?} is not ip:port (e.g. 127.0.0.1:8081)", self.bind),
        }
    }

    pub fn redirect(&self) -> Option<Redirect> {
        let host = self.redirect_host.trim();
        (!host.is_empty()).then(|| Redirect {
            host: host.trim_matches(['[', ']']).to_string(),
            port: self.redirect_port,
            force_tls: self.force_tls,
        })
    }
}

/// Checks a list of listener settings.
pub fn validate(list: &[ListenerConfig]) -> Result<()> {
    ensure!(list.len() <= MAX_LISTENERS, "at most {MAX_LISTENERS} extra listeners");
    let mut seen = std::collections::HashSet::new();
    for l in list {
        let addr = l.addr()?;
        ensure!(addr.port() != 0, "listener {}: pick a port", l.bind);
        ensure!(seen.insert(addr), "listener {} is listed twice", l.bind);
        if let Some(r) = l.redirect() {
            ensure!(r.port != 0, "listener {}: the redirect needs a port", l.bind);
            ensure!(
                r.host.len() <= 253
                    && r.host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':')),
                "listener {}: bad redirect host {:?}",
                l.bind,
                r.host
            );
        } else {
            ensure!(!l.force_tls, "listener {}: force TLS needs a redirect host", l.bind);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListenerStatus {
    pub bind: String,
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct Running {
    task: Option<JoinHandle<()>>,
    redirect: Arc<RwLock<Option<Redirect>>>,
    error: Option<String>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(t) = &self.task {
            t.abort();
        }
    }
}

/// Starts and stops extra listeners to match the project's settings.
pub struct Listeners {
    proxy: Arc<Proxy>,
    /// The listener given on the command line, shown for reference.
    primary: Option<String>,
    running: Mutex<HashMap<String, Running>>,
}

impl Listeners {
    pub fn new(proxy: Arc<Proxy>, primary: Option<SocketAddr>) -> Arc<Self> {
        Arc::new(Self { proxy, primary: primary.map(|a| a.to_string()), running: Mutex::default() })
    }

    pub fn primary(&self) -> Option<&str> {
        self.primary.as_deref()
    }

    /// Binds new listeners, stops removed or disabled ones, and updates
    /// redirects in place. Must run inside the Tokio runtime. A listener
    /// that can't bind is retried on the next call.
    pub fn sync(&self, wanted: &[ListenerConfig]) {
        let mut running = self.running.lock();
        let keys: HashMap<String, &ListenerConfig> =
            wanted.iter().filter(|l| l.enabled).filter_map(|l| l.addr().ok().map(|a| (a.to_string(), l))).collect();
        running.retain(|k, _| keys.contains_key(k));
        for (key, cfg) in keys {
            let redirect = cfg.redirect();
            if let Some(r) = running.get_mut(&key)
                && r.task.is_some()
            {
                *r.redirect.write() = redirect;
                continue;
            }
            let shared = Arc::new(RwLock::new(redirect));
            let entry = match bind(&key) {
                Ok(l) => {
                    tracing::info!(listener = %key, "proxy listener started");
                    let task = tokio::spawn({
                        let proxy = self.proxy.clone();
                        let shared = shared.clone();
                        async move {
                            if let Err(e) = proxy.run_with(l, shared).await {
                                tracing::warn!(error = %e, "proxy listener stopped");
                            }
                        }
                    });
                    Running { task: Some(task), redirect: shared, error: None }
                }
                Err(e) => Running { task: None, redirect: shared, error: Some(format!("{e:#}")) },
            };
            running.insert(key, entry);
        }
    }

    pub fn status(&self) -> Vec<ListenerStatus> {
        let mut out: Vec<ListenerStatus> = self
            .running
            .lock()
            .iter()
            .map(|(k, r)| ListenerStatus {
                bind: k.clone(),
                running: r.task.as_ref().is_some_and(|t| !t.is_finished()),
                error: r.error.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.bind.cmp(&b.bind));
        out
    }
}

fn bind(addr: &str) -> Result<tokio::net::TcpListener> {
    let l = std::net::TcpListener::bind(addr).map_err(|e| anyhow::anyhow!("cannot listen on {addr}: {e}"))?;
    l.set_nonblocking(true)?;
    Ok(tokio::net::TcpListener::from_std(l)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        let ok = ListenerConfig { bind: "127.0.0.1:18081".into(), ..Default::default() };
        assert!(validate(std::slice::from_ref(&ok)).is_ok());
        assert!(validate(&[ok.clone(), ok.clone()]).is_err());
        let bad = ListenerConfig { bind: "localhost".into(), ..Default::default() };
        assert!(validate(&[bad]).is_err());
        let tls_only = ListenerConfig { force_tls: true, ..ok.clone() };
        assert!(validate(&[tls_only]).is_err());
        let redirect = ListenerConfig { redirect_host: "api.test".into(), redirect_port: 443, force_tls: true, ..ok };
        assert!(validate(std::slice::from_ref(&redirect)).is_ok());
        assert_eq!(redirect.redirect(), Some(Redirect { host: "api.test".into(), port: 443, force_tls: true }));
    }
}
