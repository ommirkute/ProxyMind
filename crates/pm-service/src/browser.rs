//! The built-in browser: a Chromium window for manual testing, sent
//! through this process's proxy and trusting only ProxyMind's CA (pinned
//! by its public key, so nothing is installed system-wide).

use pm_policy::{Actor, ActorKind};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Result, Service, ServiceError};

/// Where this process's proxy listens, and what the browser needs to use it.
#[derive(Debug, Clone)]
pub struct ProxyInfo {
    /// e.g. `127.0.0.1:8080`
    pub addr: String,
    pub ca_pem: String,
    /// The browser profile, kept between launches (e.g. next to the project).
    pub profile_dir: std::path::PathBuf,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrowserOpenRequest {
    /// Page to open (default: the first URL in scope).
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BrowserOpened {
    pub url: String,
    pub proxy: String,
    pub pid: Option<u32>,
    pub profile: String,
}

impl Service {
    /// Tells the service where this process's proxy runs (the `ui` command does).
    pub fn attach_proxy_info(&self, info: ProxyInfo) {
        let _ = self.proxy_info.set(info);
    }

    /// Whether a browser can be opened here: a proxy in this process and a Chromium.
    pub fn browser_available(&self) -> bool {
        self.proxy_info.get().is_some() && pm_browser::find_chromium().is_some()
    }

    /// Opens a browser window for a person to test with.
    pub async fn browser_open(&self, actor: &Actor, req: BrowserOpenRequest) -> Result<BrowserOpened> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only a person can open a browser window".into()));
        }
        let info = self.proxy_info.get().ok_or_else(|| {
            ServiceError::Invalid("no proxy runs in this process: start ProxyMind with `proxymind ui`".into())
        })?;
        let chromium = pm_browser::find_chromium().ok_or_else(|| {
            ServiceError::Invalid(format!(
                "no Chromium or Chrome found: install one, or set {} to its path",
                pm_browser::ENV_CHROMIUM
            ))
        })?;
        let url = match req.url.filter(|u| !u.trim().is_empty()) {
            Some(u) => {
                let parsed = url::Url::parse(u.trim()).map_err(|e| ServiceError::Invalid(format!("bad url: {e}")))?;
                if !matches!(parsed.scheme(), "http" | "https") {
                    return Err(ServiceError::Invalid("the browser opens http(s) URLs only".into()));
                }
                parsed.to_string()
            }
            None => self
                .policy
                .roe()
                .include
                .iter()
                .map(|p| p.text.clone())
                .find(|t| (t.starts_with("http://") || t.starts_with("https://")) && !t.contains('*'))
                .unwrap_or_else(|| "about:blank".into()),
        };
        let spki = pm_tls::spki_sha256(&info.ca_pem).ok().map(|h| pm_core::base64(&h));
        let opts = pm_browser::WindowOptions {
            proxy: info.addr.clone(),
            ca_spki: spki,
            profile_dir: info.profile_dir.clone(),
            url: url.clone(),
        };
        let w = pm_browser::open_window(&chromium, &opts)
            .await
            .map_err(|e| ServiceError::Invalid(format!("the browser did not start: {e}")))?;
        self.audit(&actor.id(), "browser_open", json!({ "url": url, "proxy": info.addr }), "allow")?;
        Ok(BrowserOpened { url, proxy: info.addr.clone(), pid: w.pid, profile: w.profile_dir.display().to_string() })
    }
}
