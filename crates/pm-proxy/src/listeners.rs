//! Extra proxy listeners, configured in the project: more ports, other
//! interfaces (e.g. for a phone on the LAN), and per-listener redirects for
//! clients that can't be told where to go.
//!
//! Every HTTP listener accepts both normal proxy clients (absolute-form requests
//! and CONNECT) and invisible ones (origin-form requests routed by their
//! Host header, TLS routed by its server name). A listener can instead be a
//! SOCKS5 server (`kind: socks5`) or take traffic the operating system
//! redirected to it (`transparent`, Linux).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Result, bail, ensure};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::Proxy;
use crate::capture::SocksLogin;
use crate::transparent::{self, SystemOriginalDst};

/// Most extra listeners a project can have.
pub const MAX_LISTENERS: usize = 16;

/// What a listener speaks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ListenerKind {
    /// An HTTP proxy (also takes clients that don't know about the proxy: see `transparent`).
    #[default]
    Http,
    /// A SOCKS5 server (CONNECT only, no UDP), with an optional username and password.
    Socks5,
}

/// Longest SOCKS5 username or password (the protocol's limit).
pub const MAX_LOGIN_LEN: usize = 255;
/// A password shown instead of the saved one; sending it back keeps the saved password.
pub const MASKED_PASSWORD: &str = "********";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerConfig {
    /// Address and port, e.g. `127.0.0.1:8081` or `0.0.0.0:8082`.
    pub bind: String,
    /// `http` (default) or `socks5`.
    pub kind: ListenerKind,
    /// `http` listeners only, Linux only: take connections that the operating system redirected here
    /// (iptables or nftables `REDIRECT`/`TPROXY`) and send them to where each client was really going, so a
    /// device without proxy settings works. See docs/capture.md.
    pub transparent: bool,
    /// `socks5` listeners: ask clients for this username (empty: no login). Max 255 bytes.
    pub username: String,
    /// `socks5` listeners: the password for `username`. Hidden as `********` when settings are shown; send
    /// that value back to keep the saved password. Max 255 bytes.
    pub password: String,
    /// Listen on this address (false: configured but off).
    pub enabled: bool,
    /// Send every request to this host instead of where the client asked
    /// (empty: no redirect). The Host header is left as the client sent it.
    pub redirect_host: String,
    /// Port to send requests to with `redirect_host`.
    pub redirect_port: u16,
    /// With a redirect: connect to it with TLS even for plain-HTTP clients.
    pub force_tls: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind: String::new(),
            kind: ListenerKind::Http,
            transparent: false,
            username: String::new(),
            password: String::new(),
            enabled: true,
            redirect_host: String::new(),
            redirect_port: 0,
            force_tls: false,
        }
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

    /// The login SOCKS5 clients must give, if one is set.
    pub fn login(&self) -> Option<(String, String)> {
        (self.kind == ListenerKind::Socks5 && !self.username.is_empty())
            .then(|| (self.username.clone(), self.password.clone()))
    }

    /// The settings with the password hidden, for display and logs.
    pub fn masked(&self) -> Self {
        let mut c = self.clone();
        if !c.password.is_empty() {
            c.password = MASKED_PASSWORD.into();
        }
        c
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
        ensure!(
            l.username.len() <= MAX_LOGIN_LEN && l.password.len() <= MAX_LOGIN_LEN,
            "listener {}: the username and password are at most {MAX_LOGIN_LEN} bytes",
            l.bind
        );
        match l.kind {
            ListenerKind::Socks5 => {
                ensure!(!l.transparent, "listener {}: transparent mode is for http listeners", l.bind);
                ensure!(
                    !l.username.is_empty() || l.password.is_empty(),
                    "listener {}: a password needs a username",
                    l.bind
                );
            }
            ListenerKind::Http => {
                ensure!(
                    l.username.is_empty() && l.password.is_empty(),
                    "listener {}: a login is only for socks5 listeners",
                    l.bind
                );
            }
        }
        if l.transparent {
            ensure!(
                transparent::SUPPORTED,
                "listener {}: transparent mode needs Linux (macOS and Windows are not supported yet)",
                l.bind
            );
            ensure!(l.redirect().is_none(), "listener {}: transparent mode and a redirect cannot be combined", l.bind);
        }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct ListenerStatus {
    pub bind: String,
    /// `http` or `socks5`.
    pub kind: ListenerKind,
    /// Redirected traffic is accepted (see `ListenerConfig::transparent`).
    pub transparent: bool,
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

struct Running {
    task: Option<JoinHandle<()>>,
    redirect: Arc<RwLock<Option<Redirect>>>,
    login: SocksLogin,
    kind: ListenerKind,
    transparent: bool,
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
                && r.kind == cfg.kind
                && r.transparent == cfg.transparent
            {
                *r.redirect.write() = redirect;
                *r.login.write() = cfg.login();
                continue;
            }
            let shared = Arc::new(RwLock::new(redirect));
            let login: SocksLogin = Arc::new(RwLock::new(cfg.login()));
            let bound = if cfg.transparent { bind_transparent(&key) } else { bind(&key) };
            let (kind, transparent) = (cfg.kind, cfg.transparent);
            let entry = match bound {
                Ok(l) => {
                    tracing::info!(listener = %key, ?kind, transparent, "proxy listener started");
                    let task = tokio::spawn({
                        let proxy = self.proxy.clone();
                        let shared = shared.clone();
                        let login = login.clone();
                        async move {
                            let result = match (kind, transparent) {
                                (ListenerKind::Socks5, _) => proxy.run_socks5(l, shared, login).await,
                                (ListenerKind::Http, true) => {
                                    let provider = l.local_addr().map(SystemOriginalDst::new);
                                    match provider {
                                        Ok(p) => proxy.run_transparent(l, shared, Arc::new(p)).await,
                                        Err(e) => Err(e.into()),
                                    }
                                }
                                (ListenerKind::Http, false) => proxy.run_with(l, shared).await,
                            };
                            if let Err(e) = result {
                                tracing::warn!(error = %e, "proxy listener stopped");
                            }
                        }
                    });
                    Running { task: Some(task), redirect: shared, login, kind, transparent, error: None }
                }
                Err(e) => {
                    Running { task: None, redirect: shared, login, kind, transparent, error: Some(format!("{e:#}")) }
                }
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
                kind: r.kind,
                transparent: r.transparent,
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
    if let Ok(a) = l.local_addr() {
        warn_if_exposed(a);
    }
    Ok(tokio::net::TcpListener::from_std(l)?)
}

/// Like [`bind`], for a transparent listener: also lets the socket accept `TPROXY` connections (needs
/// `CAP_NET_ADMIN`; without it `REDIRECT` still works).
fn bind_transparent(addr: &str) -> Result<tokio::net::TcpListener> {
    let l = std::net::TcpListener::bind(addr).map_err(|e| anyhow::anyhow!("cannot listen on {addr}: {e}"))?;
    l.set_nonblocking(true)?;
    if let Err(e) = transparent::allow_tproxy(&l) {
        tracing::info!(listener = %addr, "IP_TRANSPARENT not set ({e}); iptables REDIRECT works, TPROXY needs CAP_NET_ADMIN");
    }
    if let Ok(a) = l.local_addr() {
        warn_if_exposed(a);
    }
    Ok(tokio::net::TcpListener::from_std(l)?)
}

/// A proxy reachable from other machines lets them use it, including to
/// reach services on this one. That can be intended; say so either way.
pub fn warn_if_exposed(addr: std::net::SocketAddr) {
    if !addr.ip().is_loopback() {
        tracing::warn!(%addr, "the proxy listens beyond this machine: anyone who can reach it can send traffic through it");
        eprintln!(
            "warning: the proxy on {addr} is reachable from other machines; anyone who can reach it can send traffic \
             through it (and to services on this machine)"
        );
    }
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

    #[test]
    fn socks5_and_transparent_settings() {
        let base = ListenerConfig { bind: "127.0.0.1:1080".into(), kind: ListenerKind::Socks5, ..Default::default() };
        assert!(validate(std::slice::from_ref(&base)).is_ok());
        assert_eq!(base.login(), None);
        let login = ListenerConfig { username: "u".into(), password: "p".into(), ..base.clone() };
        assert!(validate(std::slice::from_ref(&login)).is_ok());
        assert_eq!(login.login(), Some(("u".into(), "p".into())));
        assert_eq!(login.masked().password, "********");
        assert_eq!(base.masked().password, "", "nothing to hide");
        // A password needs a username; a login is only for SOCKS5; both are at most 255 bytes.
        assert!(validate(&[ListenerConfig { password: "p".into(), ..base.clone() }]).is_err());
        let http_login = ListenerConfig { bind: "127.0.0.1:1081".into(), username: "u".into(), ..Default::default() };
        assert!(validate(&[http_login]).is_err());
        assert!(validate(&[ListenerConfig { username: "u".repeat(256), ..base.clone() }]).is_err());
        assert!(
            validate(&[ListenerConfig { username: "u".repeat(255), password: "p".repeat(255), ..base.clone() }])
                .is_ok()
        );
        // Transparent mode: http listeners on Linux only, and not with a redirect.
        assert!(validate(&[ListenerConfig { transparent: true, ..base.clone() }]).is_err());
        let t = ListenerConfig { bind: "127.0.0.1:1082".into(), transparent: true, ..Default::default() };
        assert_eq!(validate(std::slice::from_ref(&t)).is_ok(), transparent::SUPPORTED);
        let with_redirect = ListenerConfig { redirect_host: "x.test".into(), redirect_port: 80, ..t };
        assert!(validate(&[with_redirect]).is_err());
        // Old settings (no kind) are HTTP listeners.
        let old: ListenerConfig = serde_json::from_str(r#"{"bind":"127.0.0.1:9"}"#).unwrap();
        assert_eq!(old.kind, ListenerKind::Http);
        assert!(serde_json::from_str::<ListenerConfig>(r#"{"bind":"127.0.0.1:9","kind":"socks4"}"#).is_err());
    }
}
