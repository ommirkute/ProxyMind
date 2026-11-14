//! Update check: asks GitHub's releases API whether a newer ProxyMind is
//! out. Off by default (a pentest tool shouldn't call home unasked): the
//! user turns on a daily check, or asks once ("Check now",
//! `proxymind update check`). Nothing about the user or the project is
//! sent; the only request is a GET of the public releases list, through the
//! user's upstream proxy settings. Every check is audited.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError};

/// Where releases are listed.
const RELEASES: &str = "https://api.github.com/repos/ommirkute/ProxyMind/releases?per_page=5";
/// A daily check reuses a result younger than this.
const MAX_AGE: Duration = Duration::from_secs(24 * 3600);
/// The preference and last result, in the user's home (all projects share it).
const FILE: &str = "update-check.json";
/// Fallback when no home directory is attached: a project setting.
const SETTING: &str = "update_check";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct UpdateState {
    /// Check once a day when the UI is open.
    pub enabled: bool,
    /// Unix seconds of the last check that got an answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<u64>,
    /// The newest release seen then (e.g. "v0.2.0") and its page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateStatus {
    pub current: &'static str,
    #[serde(flatten)]
    pub state: UpdateState,
    /// The newest release is newer than this build.
    pub available: bool,
}

/// `v1.2.3` or `1.2.3-beta` → (1, 2, 3); `None` for anything else.
fn version(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.trim().trim_start_matches('v').split(['-', '+']).next()?;
    let mut parts = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((parts.next()??, parts.next().flatten().unwrap_or(0), parts.next().flatten().unwrap_or(0)))
}

/// Whether `latest` is newer than `current`.
pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((version(latest), version(current)), (Some(l), Some(c)) if l > c)
}

/// The newest non-draft release in a GitHub releases list: (tag, page URL).
fn newest(list: &Value) -> Option<(String, String)> {
    list.as_array()?
        .iter()
        .filter(|r| !r["draft"].as_bool().unwrap_or(false))
        .filter_map(|r| Some((r["tag_name"].as_str()?.to_string(), r["html_url"].as_str()?.to_string())))
        .filter(|(tag, _)| version(tag).is_some())
        .max_by_key(|(tag, _)| version(tag))
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Service {
    fn update_state(&self) -> Result<UpdateState> {
        let text = match self.plugin_home.get() {
            Some(home) => std::fs::read_to_string(home.join(FILE)).ok(),
            None => self.store.read(|db| db.get_setting(SETTING))?,
        };
        Ok(text.and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default())
    }

    fn save_update_state(&self, s: &UpdateState) -> Result<()> {
        let text = serde_json::to_string(s).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        match self.plugin_home.get() {
            Some(home) => std::fs::write(home.join(FILE), text).map_err(|e| ServiceError::Invalid(e.to_string())),
            None => Ok(self.store.write(|db| db.set_setting(SETTING, &text))?),
        }
    }

    fn status(state: UpdateState) -> UpdateStatus {
        let current = env!("CARGO_PKG_VERSION");
        let available = state.latest.as_deref().is_some_and(|l| is_newer(l, current));
        UpdateStatus { current, state, available }
    }

    /// The preference and the last result. Sends nothing.
    pub fn update_get(&self) -> Result<UpdateStatus> {
        Ok(Self::status(self.update_state()?))
    }

    /// Turns the daily check on or off.
    pub fn update_set(&self, actor: &pm_policy::Actor, enabled: bool) -> Result<UpdateStatus> {
        let mut s = self.update_state()?;
        s.enabled = enabled;
        self.save_update_state(&s)?;
        self.audit(&actor.id(), "update_check_setting", json!({ "enabled": enabled }), "ok")?;
        Ok(Self::status(s))
    }

    /// Checks for a newer release. `force` asks now; otherwise it asks only
    /// when the daily check is on and the last answer is older than a day.
    pub async fn update_check(&self, actor: &pm_policy::Actor, force: bool) -> Result<UpdateStatus> {
        let mut s = self.update_state()?;
        let fresh = s.checked_at.is_some_and(|t| now().saturating_sub(t) < MAX_AGE.as_secs());
        if !force && (!s.enabled || fresh) {
            return Ok(Self::status(s));
        }
        let url = url::Url::parse(RELEASES).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let ep = pm_replay::Endpoint::new("https", url.host_str().unwrap_or_default(), 443);
        let target = format!("{}?{}", url.path(), url.query().unwrap_or_default());
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: api.github.com\r\nUser-Agent: ProxyMind/{}\r\n\
             Accept: application/vnd.github+json\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );
        let sender = pm_replay::Sender::new(true)
            .map_err(|e| ServiceError::Invalid(format!("{e:#}")))?
            .with_network(self.network().clone())
            .with_timeouts(Duration::from_secs(10), Duration::from_secs(20));
        let result = sender.send(&ep, request.as_bytes(), "GET", None).await;
        let outcome = match &result {
            Ok(r) if r.head.status == 200 => "ok",
            _ => "failed",
        };
        self.audit(&actor.id(), "update_check", json!({ "url": RELEASES, "forced": force }), outcome)?;
        let r = result.map_err(|e| ServiceError::Invalid(format!("couldn't reach GitHub: {e:#}")))?;
        if r.head.status != 200 {
            return Err(ServiceError::Invalid(format!("GitHub answered {}", r.head.status)));
        }
        let (_, body) = pm_http::split_message(&r.raw);
        let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
        let list: Value =
            serde_json::from_slice(&body).map_err(|e| ServiceError::Invalid(format!("unexpected answer: {e}")))?;
        let (tag, page) = newest(&list).ok_or_else(|| ServiceError::Invalid("no releases listed".into()))?;
        s.checked_at = Some(now());
        s.latest = Some(tag);
        s.url = Some(page);
        self.save_update_state(&s)?;
        Ok(Self::status(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(is_newer("0.1.1-beta", "0.1.0"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.0.9", "0.1.0"));
        assert!(!is_newer("nightly", "0.1.0"));
    }

    #[test]
    fn newest_release_skips_drafts_and_odd_tags() {
        let list = json!([
            {"tag_name": "v0.3.0", "html_url": "u3", "draft": true},
            {"tag_name": "v0.2.0", "html_url": "u2", "draft": false},
            {"tag_name": "latest", "html_url": "x", "draft": false},
            {"tag_name": "v0.1.0", "html_url": "u1", "draft": false}
        ]);
        assert_eq!(newest(&list), Some(("v0.2.0".into(), "u2".into())));
        assert_eq!(newest(&json!({"message": "rate limited"})), None);
    }
}
