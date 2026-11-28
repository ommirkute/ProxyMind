//! Integrations (roadmap 3.5): named connections to Jira, GitHub, GitLab, Slack and generic webhooks.
//!
//! This file holds the configuration, the secrets and the rules about who may do what; `integration_send.rs` talks
//! to the providers and `integration_events.rs` reacts to the event bus.
//!
//! **Where things live**
//! - The non-secret configuration is the project setting `integrations` ([`Integration`]).
//! - Secrets (API tokens, a Slack webhook URL, a webhook's signing secret and header values) are never in the project
//!   file. A secret is either an environment variable reference (`env:NAME`, read when it is used) or saved in
//!   `<home>/integration-secrets.json` (mode 0600, written atomically like `model-keys.json`) together with the
//!   server it was saved for: a secret is only ever sent to that server. The OS keychain is not used (see
//!   `docs/integrations.md`: the `keyring` crate needs a Secret Service/D-Bus daemon that headless Linux, containers
//!   and CI don't have, and it would add a large platform-specific dependency tree for a fallback we need anyway).
//! - Whether an integration may send anything *in this installation* is decided by `<home>/integration-trust.json`,
//!   not by the project file: a project opened from elsewhere can name integrations (even as `enabled`), but they
//!   stay off until a person enables them here, and any change to what they point at turns them off again
//!   (threat model F-2).
//!
//! **Who may do what.** People configure integrations, enable them, test them and send findings. Agents, plugins,
//! scanners and CI can only list the names and kinds (`integration_names`); an attempt to do more is audited as a
//! denial. Notifications go out from the event bus as the `scanner:integrations` actor, for integrations a person
//! enabled.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use pm_core::now_ms;
use pm_policy::Actor;
use ring::digest;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use crate::access::{Denial, Perm};
use crate::{Result, Service, ServiceError};

/// The project setting holding the integrations' configuration (no secrets).
pub const INTEGRATIONS_SETTING: &str = "integrations";
const SECRETS_FILE: &str = "integration-secrets.json";
const TRUST_FILE: &str = "integration-trust.json";
/// Most integrations in a project.
pub const MAX_INTEGRATIONS: usize = 20;
/// Default and largest notifications per minute and integration.
pub const DEFAULT_RATE: u32 = 20;
pub const MAX_RATE: u32 = 60;
/// Largest secret value (a long PAT or a webhook URL).
const MAX_SECRET: usize = 4096;
/// Most custom headers on a webhook.
const MAX_HEADERS: usize = 10;

/// What an integration talks to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationKind {
    /// Jira (Cloud, Server or Data Center), REST API v2: create issues.
    Jira,
    /// GitHub or GitHub Enterprise Server: create issues.
    Github,
    /// GitLab.com or self-managed GitLab: create issues.
    Gitlab,
    /// A Slack incoming webhook (or a compatible one): notifications.
    Slack,
    /// Any HTTPS endpoint: notifications as signed JSON.
    Webhook,
}

impl IntegrationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Jira => "jira",
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Slack => "slack",
            Self::Webhook => "webhook",
        }
    }

    /// Jira, GitHub and GitLab create issues; Slack and webhooks receive notifications.
    pub fn is_tracker(self) -> bool {
        matches!(self, Self::Jira | Self::Github | Self::Gitlab)
    }
}

/// What a notification integration can subscribe to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationEvent {
    /// A proof run proved a finding.
    FindingProven,
    /// A finding's status changed to anything but `proven` (that has its own event).
    FindingStatusChanged,
    /// A scan task ended (done, failed or cancelled).
    ScanFinished,
    /// A summary of the project's findings, sent when a scan task ends.
    CiSummary,
}

impl IntegrationEvent {
    pub const ALL: [Self; 4] = [Self::FindingProven, Self::FindingStatusChanged, Self::ScanFinished, Self::CiSummary];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FindingProven => "finding_proven",
            Self::FindingStatusChanged => "finding_status_changed",
            Self::ScanFinished => "scan_finished",
            Self::CiSummary => "ci_summary",
        }
    }
}

/// One configured integration, as stored in the project. It holds no secret: `secrets` says where each one is kept.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Integration {
    /// Its name (letters, digits, `-`, `_`, `.`), unique in the project.
    pub name: String,
    pub kind: IntegrationKind,
    /// A person turned it on. Whether it can send also depends on `needs_review` (see `IntegrationView`): an
    /// integration that came with a project file stays off until a person enables it in this installation.
    pub enabled: bool,
    /// Jira and GitLab: the server (`https://example.atlassian.net`, `https://gitlab.example.com`; GitLab defaults to
    /// gitlab.com). GitHub: the API base, only for Enterprise (`https://ghe.example.com/api/v3`; default
    /// `https://api.github.com`). Webhook: the URL to post to. Slack: filled in from the webhook URL (its origin).
    pub base_url: String,
    /// Jira: the project key (`SEC`). GitHub: `owner/repo`. GitLab: the numeric project id or `group/project`.
    pub project: String,
    /// Jira: the issue type's name (default `Bug`).
    pub issue_type: String,
    /// Jira: the account's email. With an email the token is an API token (Basic auth); without one it is a personal
    /// access token (Bearer), as Jira Server and Data Center use.
    pub email: String,
    /// Labels put on created issues (none by default: Jira refuses a label when its create screen has no label
    /// field, and GitHub creates missing labels only for people with push access).
    pub labels: Vec<String>,
    /// Slack and webhook: the events to send.
    pub events: Vec<IntegrationEvent>,
    /// Allow a destination that resolves to a private or loopback address (a Jira on the office network, a test
    /// server). Off by default so a project file cannot point an integration at an internal service. Link-local
    /// addresses (cloud metadata) are refused either way.
    pub allow_private: bool,
    /// Most notifications per minute (1 to 60, default 20); more are skipped and logged.
    pub rate_per_minute: u32,
    /// Where each secret is kept: slot (`token`, `webhook_url`, `signing_secret`, `header:<Name>`) to `saved` or
    /// `env:NAME`. Never the secret itself.
    pub secrets: BTreeMap<String, String>,
    /// Names of the webhook's custom headers (their values are secrets, kept like the others).
    pub header_names: Vec<String>,
    /// Who saved it last and when.
    pub updated_by: String,
    pub updated_ms: i64,
}

impl Default for Integration {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: IntegrationKind::Webhook,
            enabled: false,
            base_url: String::new(),
            project: String::new(),
            issue_type: String::new(),
            email: String::new(),
            labels: vec![],
            events: vec![],
            allow_private: false,
            rate_per_minute: DEFAULT_RATE,
            secrets: BTreeMap::new(),
            header_names: vec![],
            updated_by: String::new(),
            updated_ms: 0,
        }
    }
}

/// A custom header of a webhook, as sent to `PUT /integrations/{name}`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HeaderInput {
    /// The header's name.
    pub name: String,
    /// Its value, or `env:NAME` to read it from an environment variable when used. Leave it out to keep the saved
    /// value of a header with this name. Values are write-only: they are never returned.
    #[serde(default)]
    pub value: Option<String>,
}

/// Body of `PUT /integrations/{name}`: the configuration plus the secrets, which are write-only.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationInput {
    /// The integration's name; it must be the same as the name in the path.
    pub name: String,
    pub kind: IntegrationKind,
    /// Turn it on (default true). Saving it here, as a person, is what enables it in this installation.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// See `Integration.base_url`.
    #[serde(default)]
    pub base_url: String,
    /// See `Integration.project`.
    #[serde(default)]
    pub project: String,
    /// See `Integration.issue_type`.
    #[serde(default)]
    pub issue_type: String,
    /// See `Integration.email`.
    #[serde(default)]
    pub email: String,
    /// See `Integration.labels`.
    #[serde(default)]
    pub labels: Vec<String>,
    /// See `Integration.events`.
    #[serde(default)]
    pub events: Vec<IntegrationEvent>,
    /// See `Integration.allow_private`.
    #[serde(default)]
    pub allow_private: bool,
    /// See `Integration.rate_per_minute` (0 or absent: the default).
    #[serde(default)]
    pub rate_per_minute: u32,
    /// The API token or personal access token (Jira, GitHub, GitLab), or `env:NAME`. Write-only. Leave it out to keep
    /// the saved one; an empty string removes it.
    #[serde(default)]
    pub token: Option<String>,
    /// Slack: the incoming webhook URL, or `env:NAME`. Write-only (the URL is the credential).
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Webhook: the HMAC-SHA256 signing secret, or `env:NAME`. Write-only.
    #[serde(default)]
    pub signing_secret: Option<String>,
    /// Webhook: custom headers. Absent: keep the saved set; present: replace it.
    #[serde(default)]
    pub headers: Option<Vec<HeaderInput>>,
}

fn yes() -> bool {
    true
}

impl Default for IntegrationInput {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: IntegrationKind::Webhook,
            enabled: true,
            base_url: String::new(),
            project: String::new(),
            issue_type: String::new(),
            email: String::new(),
            labels: vec![],
            events: vec![],
            allow_private: false,
            rate_per_minute: 0,
            token: None,
            webhook_url: None,
            signing_secret: None,
            headers: None,
        }
    }
}

/// Where one secret comes from, never the secret itself.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct SecretStatus {
    /// `saved`, `environment` (a `env:NAME` reference whose variable is set) or `missing`.
    pub source: String,
    /// For an environment reference: `env:NAME`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// The last four characters of a long secret, e.g. `…a1b2`; absent for short ones.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

/// The last delivery's failure, when the last delivery failed.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct LastError {
    pub ts_ms: i64,
    pub message: String,
}

/// An integration as the API shows it: its configuration, the state of its secrets, and how it is doing.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct IntegrationView {
    #[serde(flatten)]
    pub config: Integration,
    /// Per secret slot: where it comes from. Values are never returned.
    pub secret_status: BTreeMap<String, SecretStatus>,
    /// Enabled in the file but not by a person in this installation (it came with the project, or what it points at
    /// changed since a person enabled it). It sends nothing until it is enabled here.
    pub needs_review: bool,
    /// It will send (enabled and trusted here, with every required secret present).
    pub active: bool,
    /// What is missing for it to work, in words.
    pub problems: Vec<String>,
    /// The last delivery, when it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<LastError>,
}

/// An integration's name and kind: all an agent may learn.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct IntegrationName {
    pub name: String,
    pub kind: IntegrationKind,
    /// It will send (enabled and trusted in this installation).
    pub enabled: bool,
}

/// An issue created for a finding in another system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IssueLink {
    /// The integration that created it.
    pub integration: String,
    pub kind: IntegrationKind,
    /// `PROJ-12` (Jira), `#34` (GitHub) or `#7` (GitLab).
    pub key: String,
    /// The issue's page.
    pub url: String,
    /// The provider's id for updates: the Jira key, the GitHub number, the GitLab iid.
    pub id: String,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub by: String,
}

/// Body of `POST /findings/{id}/issue`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SendFindingBody {
    /// The Jira, GitHub or GitLab integration to create the issue in.
    pub integration: String,
    /// When the finding already has an issue there: update it instead of refusing. Default false.
    #[serde(default)]
    pub update: bool,
}

/// Body of `PUT /integrations/{name}/enabled`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IntegrationEnabledBody {
    /// Turn it on or off. Turning it on here, as a person, is what makes an integration from a project file send.
    pub enabled: bool,
}

/// Query of `GET /integrations/{name}/deliveries`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct DeliveriesQuery {
    /// How many (default 50, at most 200).
    pub limit: Option<usize>,
}

/// Timing of retries and the largest number of attempts (tests make it fast; the defaults are for people).
#[derive(Debug, Clone, Copy)]
pub struct IntegrationTuning {
    /// Attempts per notification, the first included.
    pub max_attempts: u32,
    /// Wait before the second attempt; it doubles each time up to `backoff_cap_ms`.
    pub backoff_base_ms: u64,
    pub backoff_cap_ms: u64,
}

impl Default for IntegrationTuning {
    fn default() -> Self {
        Self { max_attempts: 4, backoff_base_ms: 1000, backoff_cap_ms: 8000 }
    }
}

pub(crate) struct Bucket {
    pub tokens: f64,
    pub at: std::time::Instant,
}

/// Process state of the integrations: trust when no home is attached, rate buckets, sends in flight.
#[derive(Default)]
pub(crate) struct Runtime {
    pub trust_mem: HashMap<String, String>,
    pub buckets: HashMap<String, Bucket>,
    pub in_flight: HashSet<String>,
    pub tuning: Option<IntegrationTuning>,
    pub sender: Option<std::sync::Arc<pm_replay::Sender>>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
struct SecretEntry {
    value: String,
    /// The server it was saved for (`https://host:port`): sent nowhere else.
    origin: String,
}

// ---- validation and pure helpers -----------------------------------------------------------------------------

fn invalid<T>(msg: impl Into<String>) -> Result<T> {
    Err(ServiceError::Invalid(msg.into()))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 40 && name.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

fn valid_env_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && !n.starts_with(|c: char| c.is_ascii_digit())
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn valid_header_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.chars().all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
        && !matches!(
            n.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "content-type" | "transfer-encoding" | "connection" | "x-proxymind-signature"
        )
}

/// A secret or header value that is safe to put in a header: no line breaks or control characters.
pub(crate) fn clean_secret(v: &str) -> bool {
    !v.is_empty() && v.len() <= MAX_SECRET && !v.chars().any(|c| c.is_control())
}

/// Parses an integration URL: http(s), a host, no credentials in it.
pub(crate) fn parse_url(s: &str) -> Result<Url> {
    let u = Url::parse(s.trim()).map_err(|e| ServiceError::Invalid(format!("not a URL: {e}")))?;
    if !matches!(u.scheme(), "http" | "https") {
        return invalid("the URL must start with https:// (or http:// for a private address you allow)");
    }
    if u.host_str().is_none_or(str::is_empty) {
        return invalid("the URL needs a host name");
    }
    if !u.username().is_empty() || u.password().is_some() {
        return invalid("put credentials in the token fields, not in the URL");
    }
    Ok(u)
}

/// `https://host:port` of a URL, the unit a secret is bound to.
pub(crate) fn origin_of(u: &Url) -> String {
    format!("{}://{}", u.scheme(), u.authority())
}

/// The URL a tracker's API lives at (the default for GitHub and GitLab when none is given).
pub(crate) fn base_of(i: &Integration) -> Result<Url> {
    let default = match i.kind {
        IntegrationKind::Github => "https://api.github.com",
        IntegrationKind::Gitlab => "https://gitlab.com",
        _ => "",
    };
    let s = if i.base_url.trim().is_empty() { default } else { i.base_url.trim() };
    if s.is_empty() {
        return invalid(format!("{} needs a URL", i.name));
    }
    parse_url(s)
}

/// The secret slots an integration kind uses, and whether sending needs them.
fn required_slots(k: IntegrationKind) -> &'static [&'static str] {
    match k {
        IntegrationKind::Jira | IntegrationKind::Github | IntegrationKind::Gitlab => &["token"],
        IntegrationKind::Slack => &["webhook_url"],
        IntegrationKind::Webhook => &[],
    }
}

fn validate(i: &Integration) -> Result<()> {
    if !valid_name(&i.name) {
        return invalid("the name is 1 to 40 letters, digits, '-', '_' or '.'");
    }
    if i.rate_per_minute == 0 || i.rate_per_minute > MAX_RATE {
        return invalid(format!("rate_per_minute must be 1 to {MAX_RATE}"));
    }
    if i.labels.len() > 10 || i.labels.iter().any(|l| l.is_empty() || l.len() > 50 || l.chars().any(char::is_control)) {
        return invalid("at most 10 labels of up to 50 characters");
    }
    if i.kind.is_tracker() && !i.events.is_empty() {
        return invalid("Jira, GitHub and GitLab create issues on request; they take no event subscriptions");
    }
    let project_ok = |chars: &str, s: &str| {
        !s.is_empty() && s.len() <= 200 && s.chars().all(|c| c.is_ascii_alphanumeric() || chars.contains(c))
    };
    match i.kind {
        IntegrationKind::Jira => {
            base_of(i)?;
            if !project_ok("_", &i.project) {
                return invalid("Jira: the project key is letters, digits and '_' (for example SEC)");
            }
            if i.issue_type.len() > 60 || i.issue_type.chars().any(char::is_control) {
                return invalid("Jira: the issue type is a short name such as Bug");
            }
            if i.email.chars().any(|c| c.is_control() || c.is_whitespace() || c == ':') || i.email.len() > 200 {
                return invalid("Jira: the email is the account's address");
            }
        }
        IntegrationKind::Github => {
            if !i.base_url.trim().is_empty() {
                base_of(i)?;
            }
            let ok = i.project.split_once('/').is_some_and(|(o, r)| {
                !o.contains('/') && !r.contains('/') && project_ok("-_.", o) && project_ok("-_.", r)
            });
            if !ok {
                return invalid("GitHub: the repository is owner/repo");
            }
        }
        IntegrationKind::Gitlab => {
            if !i.base_url.trim().is_empty() {
                base_of(i)?;
            }
            if !project_ok("-_./", &i.project) || i.project.starts_with('/') || i.project.contains("..") {
                return invalid("GitLab: the project is its numeric id or group/project");
            }
        }
        IntegrationKind::Slack => {
            if !i.base_url.is_empty() {
                parse_url(&i.base_url)?;
            }
        }
        IntegrationKind::Webhook => {
            parse_url(&i.base_url)?;
            if i.header_names.len() > MAX_HEADERS || !i.header_names.iter().all(|n| valid_header_name(n)) {
                return invalid(format!(
                    "at most {MAX_HEADERS} custom headers, with plain names (not Host, Content-Type…)"
                ));
            }
        }
    }
    Ok(())
}

/// SHA-256 over what the integration points at and does (everything but who saved it, when, and whether it is on).
pub(crate) fn digest_of(i: &Integration) -> String {
    let mut c = i.clone();
    c.enabled = true;
    c.updated_by.clear();
    c.updated_ms = 0;
    let bytes = serde_json::to_vec(&c).unwrap_or_default();
    digest::digest(&digest::SHA256, &bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn hint(v: &str) -> Option<String> {
    (v.chars().count() >= 16).then(|| {
        let tail: String = v.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
        format!("…{tail}")
    })
}

/// Writes a private file atomically (mode 0600 where the OS has modes).
fn write_private(path: &std::path::Path, text: &str) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).map_err(|e| ServiceError::Invalid(format!("saving: {e}")))?;
        std::io::Write::write_all(&mut f, text.as_bytes())
            .map_err(|e| ServiceError::Invalid(format!("saving: {e}")))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| ServiceError::Invalid(format!("saving: {e}")))
}

// ---- the service ---------------------------------------------------------------------------------------------

impl Service {
    /// A random id for this project, kept in the project file; secrets and trust are filed under it. The project
    /// server (ADR-0022) files memberships under it too: it survives renaming or moving the file.
    pub fn project_id(&self) -> Result<String> {
        self.store
            .write(|db| -> anyhow::Result<String> {
                if let Some(id) = db.get_setting("project_id")?.filter(|s| !s.is_empty()) {
                    return Ok(id);
                }
                let mut b = [0u8; 12];
                ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b)
                    .map_err(|_| anyhow::anyhow!("no randomness"))?;
                let id: String = b.iter().map(|x| format!("{x:02x}")).collect();
                db.set_setting("project_id", &id)?;
                Ok(id)
            })
            .map_err(Into::into)
    }

    fn home_file(&self, name: &str) -> Option<PathBuf> {
        self.plugin_home.get().map(|h| h.join(name))
    }

    /// The configured integrations, as stored.
    pub(crate) fn integrations_load(&self) -> Result<Vec<Integration>> {
        match self.store.read(|db| db.get_setting(INTEGRATIONS_SETTING))? {
            Some(t) if !t.trim().is_empty() => serde_json::from_str(&t)
                .map_err(|e| ServiceError::Invalid(format!("the saved integrations are unreadable: {e}"))),
            _ => Ok(vec![]),
        }
    }

    fn integrations_save(&self, list: &[Integration]) -> Result<()> {
        let text = serde_json::to_string(list).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        Ok(self.store.write(|db| db.set_setting(INTEGRATIONS_SETTING, &text))?)
    }

    /// One integration by name.
    pub(crate) fn integration_find(&self, name: &str) -> Result<Integration> {
        self.integrations_load()?
            .into_iter()
            .find(|i| i.name == name)
            .ok_or_else(|| ServiceError::NotFound(format!("integration {name}")))
    }

    // -- secrets --

    fn secret_key(pid: &str, name: &str, slot: &str) -> String {
        format!("{pid}/{name}/{slot}")
    }

    fn secrets_read(&self) -> BTreeMap<String, SecretEntry> {
        self.home_file(SECRETS_FILE)
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn secrets_write(&self, m: &BTreeMap<String, SecretEntry>) -> Result<()> {
        let path = self.home_file(SECRETS_FILE).ok_or_else(|| {
            ServiceError::Invalid(
                "this process has no ProxyMind home directory to save secrets in; use an env:NAME reference".into(),
            )
        })?;
        write_private(&path, &serde_json::to_string_pretty(m).map_err(|e| ServiceError::Invalid(e.to_string()))?)
    }

    /// The value of one secret, for the code that sends: from the environment, or the saved one when it was saved for
    /// the server the integration points at now. Never returned by an API.
    pub(crate) fn integration_secret(&self, i: &Integration, slot: &str) -> Result<Option<String>> {
        match i.secrets.get(slot).map(String::as_str) {
            None | Some("") => Ok(None),
            Some(r) if r.starts_with("env:") => {
                Ok(std::env::var(&r[4..]).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty()))
            }
            Some(_) => {
                let pid = self.project_id()?;
                let Some(e) = self.secrets_read().remove(&Self::secret_key(&pid, &i.name, slot)) else {
                    return Ok(None);
                };
                let now = base_of_or_own(i).map(|u| origin_of(&u)).unwrap_or_default();
                if e.origin != now {
                    return invalid(format!(
                        "the {slot} of {} was saved for {}, not {now}: enter it again for the new address",
                        i.name, e.origin
                    ));
                }
                Ok(Some(e.value))
            }
        }
    }

    /// Every secret value of an integration, to scrub them out of anything that is stored or returned.
    pub(crate) fn integration_secret_values(&self, i: &Integration) -> Vec<String> {
        i.secrets.keys().filter_map(|s| self.integration_secret(i, s).ok().flatten()).collect()
    }

    fn secret_status(&self, i: &Integration) -> BTreeMap<String, SecretStatus> {
        let mut slots: Vec<String> = required_slots(i.kind).iter().map(|s| s.to_string()).collect();
        if i.kind == IntegrationKind::Webhook {
            slots.push("signing_secret".into());
            slots.extend(i.header_names.iter().map(|n| format!("header:{n}")));
        }
        slots
            .into_iter()
            .map(|slot| {
                let reference = i.secrets.get(&slot).filter(|r| r.starts_with("env:")).cloned();
                let value = self.integration_secret(i, &slot).ok().flatten();
                let source = match (&reference, &value) {
                    (Some(_), Some(_)) => "environment",
                    (None, Some(_)) => "saved",
                    _ => "missing",
                };
                let hint = value.as_deref().and_then(hint);
                (slot, SecretStatus { source: source.into(), reference, hint })
            })
            .collect()
    }

    // -- trust (threat model F-2) --

    fn trust_get(&self, pid: &str, name: &str) -> Option<String> {
        let key = format!("{pid}/{name}");
        match self.home_file(TRUST_FILE) {
            Some(p) => {
                let m: BTreeMap<String, String> =
                    std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
                m.get(&key).cloned()
            }
            None => self.integrations.lock().trust_mem.get(&key).cloned(),
        }
    }

    fn trust_set(&self, pid: &str, name: &str, digest: Option<&str>) -> Result<()> {
        let key = format!("{pid}/{name}");
        match self.home_file(TRUST_FILE) {
            Some(p) => {
                let mut m: BTreeMap<String, String> =
                    std::fs::read_to_string(&p).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
                match digest {
                    Some(d) => m.insert(key, d.to_string()),
                    None => m.remove(&key),
                };
                write_private(&p, &serde_json::to_string_pretty(&m).map_err(|e| ServiceError::Invalid(e.to_string()))?)
            }
            None => {
                let mut rt = self.integrations.lock();
                match digest {
                    Some(d) => rt.trust_mem.insert(key, d.to_string()),
                    None => rt.trust_mem.remove(&key),
                };
                Ok(())
            }
        }
    }

    /// Whether a person enabled exactly this configuration in this installation.
    pub(crate) fn integration_trusted(&self, i: &Integration) -> bool {
        self.project_id().ok().and_then(|pid| self.trust_get(&pid, &i.name)).is_some_and(|d| d == digest_of(i))
    }

    /// Enabled in the file and trusted here: it may send.
    pub(crate) fn integration_active(&self, i: &Integration) -> bool {
        i.enabled && self.integration_trusted(i)
    }

    fn problems(&self, i: &Integration, status: &BTreeMap<String, SecretStatus>) -> Vec<String> {
        let mut p = vec![];
        if let Err(e) = validate(i) {
            p.push(e.to_string());
        }
        for slot in required_slots(i.kind) {
            if status.get(*slot).is_none_or(|s| s.source == "missing") {
                p.push(format!("the {slot} is not set (or its environment variable is empty)"));
            }
        }
        if matches!(i.kind, IntegrationKind::Webhook | IntegrationKind::Slack) && i.events.is_empty() {
            p.push("no events selected: nothing will be sent automatically".into());
        }
        p
    }

    fn view(&self, i: Integration) -> IntegrationView {
        let secret_status = self.secret_status(&i);
        let trusted = self.integration_trusted(&i);
        let problems = self.problems(&i, &secret_status);
        let blocking = problems.iter().any(|p| !p.starts_with("no events"));
        let last_error = self
            .store
            .read(|db| db.last_delivery_error(&i.name))
            .ok()
            .flatten()
            .map(|d| LastError { ts_ms: d.ts_ms, message: d.detail });
        IntegrationView {
            needs_review: i.enabled && !trusted,
            active: i.enabled && trusted && !blocking,
            problems,
            secret_status,
            last_error,
            config: i,
        }
    }

    /// Every integration with its state. People only (agents use [`Service::integration_names`]).
    pub fn integration_list(&self, actor: &Actor) -> Result<Vec<IntegrationView>> {
        self.require_actor_with(
            actor,
            Perm::IntegrationsRead,
            Denial::message("only people can read integration settings (agents can list names with integration_list)"),
        )?;
        Ok(self.integrations_load()?.into_iter().map(|i| self.view(i)).collect())
    }

    pub fn integration_get(&self, actor: &Actor, name: &str) -> Result<IntegrationView> {
        self.require_actor(actor, Perm::IntegrationsRead)?;
        Ok(self.view(self.integration_find(name)?))
    }

    /// Names, kinds and whether each will send: what an agent may know. No URL, no project, no secret.
    pub fn integration_names(&self) -> Result<Vec<IntegrationName>> {
        Ok(self
            .integrations_load()?
            .into_iter()
            .map(|i| IntegrationName { enabled: self.integration_active(&i), name: i.name, kind: i.kind })
            .collect())
    }

    /// Creates or replaces an integration. People only; audited (names and where secrets are kept, never values).
    /// Saving it enabled, here, is what makes it send in this installation; saving it changed turns that off until
    /// it is saved or enabled again by a person.
    pub fn integration_set(&self, actor: &Actor, name: &str, input: IntegrationInput) -> Result<IntegrationView> {
        self.require_actor_with(
            actor,
            Perm::IntegrationsWrite,
            Denial::message("only people can set").and_audit("integration_set", json!({ "name": name })),
        )?;
        if input.name != name {
            return invalid("the name in the body and in the path must be the same");
        }
        let list = self.integrations_load()?;
        let old = list.iter().find(|i| i.name == name).cloned();
        if old.is_none() && list.len() >= MAX_INTEGRATIONS {
            return invalid(format!("at most {MAX_INTEGRATIONS} integrations"));
        }
        let pid = self.project_id()?;
        let mut cfg = Integration {
            name: name.to_string(),
            kind: input.kind,
            enabled: input.enabled,
            base_url: input.base_url.trim().to_string(),
            project: input.project.trim().to_string(),
            issue_type: input.issue_type.trim().to_string(),
            email: input.email.trim().to_string(),
            labels: input.labels.iter().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
            events: dedup(input.events),
            allow_private: input.allow_private,
            rate_per_minute: if input.rate_per_minute == 0 { DEFAULT_RATE } else { input.rate_per_minute },
            secrets: old.as_ref().filter(|o| o.kind == input.kind).map(|o| o.secrets.clone()).unwrap_or_default(),
            header_names: old
                .as_ref()
                .filter(|o| o.kind == input.kind)
                .map(|o| o.header_names.clone())
                .unwrap_or_default(),
            updated_by: actor.id(),
            updated_ms: now_ms(),
        };
        if cfg.kind == IntegrationKind::Jira && cfg.issue_type.is_empty() {
            cfg.issue_type = "Bug".into();
        }
        if cfg.kind != IntegrationKind::Jira {
            cfg.issue_type.clear();
            cfg.email.clear();
        }
        // Secrets: validate and stage every change, then apply them together with the configuration.
        let mut saved = self.secrets_read();
        let original = saved.clone();
        let mut touched: Vec<String> = vec![];
        let kind = cfg.kind;
        let slot_ok = |slot: &str| -> bool {
            match kind {
                IntegrationKind::Jira | IntegrationKind::Github | IntegrationKind::Gitlab => slot == "token",
                IntegrationKind::Slack => slot == "webhook_url",
                IntegrationKind::Webhook => slot == "signing_secret" || slot.starts_with("header:"),
            }
        };
        let mut changes: Vec<(String, Option<String>)> = vec![];
        if let Some(v) = &input.token {
            if !slot_ok("token") {
                return invalid("this kind of integration has no token");
            }
            changes.push(("token".into(), Some(v.clone())));
        }
        if let Some(v) = &input.webhook_url {
            if !slot_ok("webhook_url") {
                return invalid("only Slack integrations have a webhook URL");
            }
            changes.push(("webhook_url".into(), Some(v.clone())));
        }
        if let Some(v) = &input.signing_secret {
            if !slot_ok("signing_secret") {
                return invalid("only webhooks have a signing secret");
            }
            changes.push(("signing_secret".into(), Some(v.clone())));
        }
        if let Some(headers) = &input.headers {
            if cfg.kind != IntegrationKind::Webhook {
                return invalid("only webhooks have custom headers");
            }
            let mut names: Vec<String> = vec![];
            for h in headers {
                let n = h.name.trim().to_string();
                if !valid_header_name(&n) {
                    return invalid(format!("'{n}' is not an allowed header name"));
                }
                if names.iter().any(|x| x.eq_ignore_ascii_case(&n)) {
                    return invalid(format!("header {n} is listed twice"));
                }
                if let Some(v) = &h.value {
                    changes.push((format!("header:{n}"), Some(v.clone())));
                }
                names.push(n);
            }
            // Headers no longer listed lose their secret.
            for gone in cfg.header_names.iter().filter(|o| !names.contains(o)) {
                changes.push((format!("header:{gone}"), Some(String::new())));
            }
            cfg.header_names = names;
        }
        // Where the secrets are bound to: the server the integration points at, or (Slack) the webhook URL's server.
        let mut slack_origin: Option<String> = None;
        for (slot, value) in &changes {
            let Some(v) = value else { continue };
            let v = v.trim();
            let key = Self::secret_key(&pid, name, slot);
            if v.is_empty() {
                cfg.secrets.remove(slot);
                if saved.remove(&key).is_some() {
                    touched.push(slot.clone());
                }
            } else if let Some(var) = v.strip_prefix("env:") {
                if !valid_env_name(var) {
                    return invalid("an environment reference is env:NAME (letters, digits, '_')");
                }
                cfg.secrets.insert(slot.clone(), format!("env:{var}"));
                saved.remove(&key);
            } else {
                if !clean_secret(v) {
                    return invalid(format!("the {slot} must be one line of at most {MAX_SECRET} characters"));
                }
                let origin = if slot == "webhook_url" {
                    let u = parse_url(v)?;
                    let o = origin_of(&u);
                    slack_origin = Some(o.clone());
                    o
                } else {
                    String::new() // filled below, once the configuration is final
                };
                saved.insert(key, SecretEntry { value: v.to_string(), origin });
                cfg.secrets.insert(slot.clone(), "saved".into());
                touched.push(slot.clone());
            }
        }
        if cfg.kind == IntegrationKind::Slack
            && let Some(o) = slack_origin
        {
            cfg.base_url = o;
        }
        validate(&cfg)?;
        // Saved secrets that were not just re-entered follow the configuration only if it still points at the same
        // server; otherwise the old value would be sent somewhere new, so it is dropped and must be entered again.
        let origin_now = base_of_or_own(&cfg).map(|u| origin_of(&u)).unwrap_or_default();
        for (slot, r) in cfg.secrets.clone() {
            if r != "saved" {
                continue;
            }
            let key = Self::secret_key(&pid, name, &slot);
            if let Some(e) = saved.get_mut(&key) {
                if e.origin.is_empty() {
                    e.origin = origin_now.clone();
                } else if e.origin != origin_now {
                    saved.remove(&key);
                    cfg.secrets.remove(&slot);
                    touched.push(format!("{slot} (dropped: the address changed)"));
                }
            } else {
                cfg.secrets.remove(&slot);
            }
        }
        // Writing secrets needs the home directory; do it before the configuration so a failure changes nothing.
        if saved != original {
            self.secrets_write(&saved)?;
        }
        let mut list = list;
        match list.iter_mut().find(|i| i.name == name) {
            Some(slot) => *slot = cfg.clone(),
            None => list.push(cfg.clone()),
        }
        self.integrations_save(&list)?;
        if cfg.enabled {
            self.trust_set(&pid, name, Some(&digest_of(&cfg)))?;
        } else {
            self.trust_set(&pid, name, None)?;
        }
        self.audit(
            &actor.id(),
            "integration_set",
            json!({
                "name": name,
                "kind": cfg.kind.as_str(),
                "enabled": cfg.enabled,
                "host": base_of_or_own(&cfg).ok().map(|u| u.host_str().unwrap_or_default().to_string()),
                "project": cfg.project,
                "events": cfg.events.iter().map(|e| e.as_str()).collect::<Vec<_>>(),
                "allow_private": cfg.allow_private,
                "secrets": cfg.secrets,
                "secrets_changed": touched.iter().map(|t| t.split(' ').next().unwrap_or("").to_string()).collect::<Vec<_>>(),
            }),
            "allow",
        )?;
        Ok(self.view(cfg))
    }

    /// Turns an integration on or off. Turning one on here, as a person, trusts its current configuration in this
    /// installation: the way an integration that came with a project file starts to send.
    pub fn integration_enable(&self, actor: &Actor, name: &str, enabled: bool) -> Result<IntegrationView> {
        self.require_actor_with(
            actor,
            Perm::IntegrationsWrite,
            Denial::message("only people can enable").and_audit("integration_enable", json!({ "name": name })),
        )?;
        let mut list = self.integrations_load()?;
        let Some(i) = list.iter_mut().find(|i| i.name == name) else {
            return Err(ServiceError::NotFound(format!("integration {name}")));
        };
        i.enabled = enabled;
        i.updated_by = actor.id();
        i.updated_ms = now_ms();
        validate(i)?;
        let cfg = i.clone();
        self.integrations_save(&list)?;
        let pid = self.project_id()?;
        self.trust_set(&pid, name, enabled.then(|| digest_of(&cfg)).as_deref())?;
        self.audit(
            &actor.id(),
            "integration_enable",
            json!({ "name": name, "enabled": enabled, "kind": cfg.kind.as_str(), "host": base_of_or_own(&cfg).ok().map(|u| u.host_str().unwrap_or_default().to_string()) }),
            "allow",
        )?;
        Ok(self.view(cfg))
    }

    /// Deletes an integration, its saved secrets, its trust and its delivery log. People only; audited.
    pub fn integration_delete(&self, actor: &Actor, name: &str) -> Result<()> {
        self.require_actor_with(
            actor,
            Perm::IntegrationsWrite,
            Denial::message("only people can delete").and_audit("integration_delete", json!({ "name": name })),
        )?;
        let mut list = self.integrations_load()?;
        let before = list.len();
        list.retain(|i| i.name != name);
        if list.len() == before {
            return Err(ServiceError::NotFound(format!("integration {name}")));
        }
        self.integrations_save(&list)?;
        let pid = self.project_id()?;
        let prefix = format!("{pid}/{name}/");
        if self.home_file(SECRETS_FILE).is_some() {
            let mut saved = self.secrets_read();
            let n = saved.len();
            saved.retain(|k, _| !k.starts_with(&prefix));
            if saved.len() != n {
                self.secrets_write(&saved)?;
            }
        }
        self.trust_set(&pid, name, None)?;
        self.store.write(|db| db.delete_deliveries_of(name))?;
        self.audit(&actor.id(), "integration_delete", json!({ "name": name }), "allow")?;
        Ok(())
    }

    /// The last deliveries of an integration, newest first. People only.
    pub fn integration_deliveries(
        &self,
        actor: &Actor,
        name: &str,
        limit: usize,
    ) -> Result<Vec<pm_store::DeliveryRow>> {
        self.require_actor_with(
            actor,
            Perm::IntegrationsRead,
            Denial::message("only people can read the delivery log"),
        )?;
        self.integration_find(name)?;
        Ok(self.store.read(|db| db.list_deliveries(Some(name), limit.clamp(1, 200)))?)
    }

    /// Sets how retries are timed (tests and unusual servers). The defaults are 4 attempts, 1 s, 2 s, 4 s.
    pub fn integration_tuning_set(&self, t: IntegrationTuning) {
        self.integrations.lock().tuning = Some(t);
    }

    pub(crate) fn integration_tuning(&self) -> IntegrationTuning {
        self.integrations.lock().tuning.unwrap_or_default()
    }
}

fn dedup(events: Vec<IntegrationEvent>) -> Vec<IntegrationEvent> {
    let mut out = vec![];
    for e in events {
        if !out.contains(&e) {
            out.push(e);
        }
    }
    out
}

/// The server an integration's secrets are bound to: its URL, or for Slack the origin saved with the webhook URL.
fn base_of_or_own(i: &Integration) -> Result<Url> {
    match i.kind {
        IntegrationKind::Slack => parse_url(&i.base_url),
        _ => base_of(i),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jira() -> Integration {
        Integration {
            name: "jira".into(),
            kind: IntegrationKind::Jira,
            base_url: "https://x.atlassian.net".into(),
            project: "SEC".into(),
            issue_type: "Bug".into(),
            ..Default::default()
        }
    }

    #[test]
    fn validation_rejects_bad_names_urls_and_projects() {
        assert!(validate(&jira()).is_ok());
        let mut i = jira();
        i.name = "a b".into();
        assert!(validate(&i).is_err());
        let mut i = jira();
        i.base_url = "https://user:pw@x.atlassian.net".into();
        assert!(validate(&i).is_err(), "credentials in the URL");
        let mut i = jira();
        i.base_url = "ftp://x".into();
        assert!(validate(&i).is_err());
        let mut i = jira();
        i.project = "SEC/../x".into();
        assert!(validate(&i).is_err());
        let mut i = jira();
        i.events = vec![IntegrationEvent::FindingProven];
        assert!(validate(&i).is_err(), "trackers take no event subscriptions");
        let g = Integration {
            name: "gh".into(),
            kind: IntegrationKind::Github,
            project: "acme/app".into(),
            ..Default::default()
        };
        assert!(validate(&g).is_ok());
        let g = Integration { project: "acme".into(), ..g };
        assert!(validate(&g).is_err());
    }

    #[test]
    fn digest_ignores_who_and_when_but_not_where() {
        let a = jira();
        let mut b = jira();
        b.updated_by = "human:x".into();
        b.updated_ms = 5;
        b.enabled = true;
        assert_eq!(digest_of(&a), digest_of(&b));
        b.base_url = "https://evil.test".into();
        assert_ne!(digest_of(&a), digest_of(&b));
        let mut c = jira();
        c.allow_private = true;
        assert_ne!(digest_of(&a), digest_of(&c));
    }

    #[test]
    fn hints_only_for_long_secrets() {
        assert_eq!(hint("short"), None);
        assert_eq!(hint("ghp_abcdefghijklmnop1234").as_deref(), Some("…1234"));
    }

    #[test]
    fn header_names_exclude_framing_and_the_signature() {
        for bad in ["Host", "content-length", "X-ProxyMind-Signature", "a b", ""] {
            assert!(!valid_header_name(bad), "{bad}");
        }
        assert!(valid_header_name("X-Api-Key"));
    }
}
