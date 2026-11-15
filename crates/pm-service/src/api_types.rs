//! Request bodies and query strings of the REST API that are small enough not to belong to one service module
//! (ADR-0019). They used to be private to `pm-api`; they live here so the API, the OpenAPI document and (later) the
//! SDKs name the same types. The serde attributes are the wire format: change them only on purpose, the golden
//! tests in `tests/wire_contract.rs` pin them.

use pm_proxy::{ListenerConfig, RewriteRule as Rule};
use pm_tools::codegen::Lang;
use pm_tools::engage::CsrfTechnique;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// `?status=`: filter a list by status (`all` or empty means no filter where the route says so).
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct StatusQuery {
    /// Only rows with this status.
    pub status: Option<String>,
}

/// Body of `POST /identities/capture`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct CaptureBody {
    /// Name of the identity to create or refresh.
    pub name: String,
    /// Role label (default `user`).
    #[serde(default)]
    pub role: Option<String>,
    /// The recorded exchange whose credentials (cookies, Authorization header) are captured.
    pub exchange_id: i64,
}

/// Body of `POST /identities/record-login`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct RecordLoginBody {
    /// Name of the identity to create or refresh.
    pub name: String,
    /// Role label (default `user`).
    #[serde(default)]
    pub role: Option<String>,
    /// The recorded login exchange.
    pub from: i64,
    /// The last exchange of the login flow (default: the same as `from`).
    #[serde(default)]
    pub to: Option<i64>,
}

/// Body of `POST /model/snapshots`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBody {
    /// Name for the snapshot.
    pub name: String,
}

/// Query of `GET /model/changes`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangesQuery {
    /// Snapshot id to compare the current model with.
    pub snapshot: i64,
}

/// Query of `GET /authz/results`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct ExchangeQuery {
    /// Only results for this exchange.
    pub exchange_id: Option<i64>,
}

/// Query of `GET /coverage`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct CoverageQuery {
    /// List every operation, not only the untested ones.
    pub all: Option<bool>,
}

/// Query of `GET /collaborator/probes`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ProbesQuery {
    /// Most rows to return (default 200).
    pub limit: Option<usize>,
}

/// Body of `POST /collaborator/listener`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListenBody {
    /// Address to listen on, `host:port`.
    pub listen: String,
    /// The URL targets should call, when it differs from the listen address.
    pub public_url: Option<String>,
}

/// Body of `POST /collaborator/smtp`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SmtpBody {
    /// Address to listen on, `host:port`.
    pub listen: String,
}

/// Body of `POST /collaborator/payloads`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PayloadBody {
    /// A note to remember what the payload was planted for.
    pub note: String,
}

/// Query of `GET /organizer`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default)]
pub struct OrganizerQuery {
    /// Only items with this status (empty: all).
    pub status: Option<String>,
}

/// Body of `POST /organizer`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizerAdd {
    /// The recorded exchange to keep.
    pub exchange_id: i64,
    /// A note about it.
    #[serde(default)]
    pub note: String,
}

/// Query of `GET /collaborator/payloads` (`limit` only) and `GET /collaborator/interactions`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct CollabQuery {
    /// Most rows to return (default 100 for payloads, 200 for interactions).
    pub limit: Option<usize>,
    /// Interactions only: show only interactions with this payload token.
    pub token: Option<String>,
}

/// Body of `PUT /update`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateSet {
    /// Check for new versions once a day.
    pub enabled: bool,
}

/// Body of `POST /update/check`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UpdateCheck {
    /// Ask now even if the daily check is off or the last answer is fresh.
    pub force: bool,
}

/// Body of `POST /recon/dns`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconDns {
    /// Host name to look up.
    pub host: String,
    /// DNS server to ask, `ip:port` (default: the system resolver).
    #[serde(default)]
    pub resolver: Option<std::net::SocketAddr>,
}

/// Body of `POST /recon/wayback`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconWayback {
    /// Host name to look up in the web archive.
    pub host: String,
    /// Most captures to return (default 500).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Body of `POST /traffic/triage`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TriageBody {
    /// Only exchanges whose host contains this.
    pub host: Option<String>,
    /// Only exchanges in (true) or out of (false) scope.
    pub in_scope: Option<bool>,
    /// Most rows to return (default 100).
    pub limit: Option<usize>,
}

/// Query of `GET /memory`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HostQuery {
    /// Only memories about this host.
    pub host: Option<String>,
}

/// Body of `POST /engage/references`, `/engage/csrf` and `/engage/clickjacking`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngageExchange {
    /// The recorded exchange to work on.
    pub exchange_id: i64,
    /// CSRF only: how the proof of concept submits the request (default `auto`).
    #[serde(default)]
    pub technique: CsrfTechnique,
    /// CSRF only: submit the form when the page loads.
    #[serde(default)]
    pub auto_submit: bool,
}

/// Body of `PUT /plugins/{name}`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PluginSet {
    /// Turn the plugin on or off.
    pub enabled: bool,
}

/// Query of `GET /plugins/{name}/panels/{panel}`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct PanelQuery {
    /// Most rows to return.
    pub limit: Option<usize>,
}

/// Body of `POST /scan/custom-checks`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CheckYaml {
    /// The check, as YAML.
    pub yaml: String,
}

/// Query of `GET /audit`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct LimitQuery {
    /// Most records to return (default 200, at most 5000).
    pub limit: Option<usize>,
}

/// Query of `GET /report`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct ReportQuery {
    /// `md`, `html` or another format the template supports (default `md`).
    pub format: Option<String>,
    /// Name of a report template (default: the built-in one for the format).
    pub template: Option<String>,
    /// Only findings at least this severe.
    pub min_severity: Option<String>,
    /// Comma-separated statuses to include.
    pub statuses: Option<String>,
    /// Embed the evidence (requests and responses) of each finding.
    pub evidence: Option<bool>,
}

/// Query of `GET /evidence/pack`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PackQuery {
    /// Include all in-scope traffic, not only the evidence of findings.
    pub all: bool,
}

/// Body of `POST /intercept/{id}/forward`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct ForwardBody {
    /// The edited message as text (default: forward it unchanged).
    #[serde(default)]
    pub raw: Option<String>,
    /// Fix the Content-Length header to match an edited body (default true).
    #[serde(default)]
    pub fix_content_length: Option<bool>,
}

/// Query of `GET /exchanges/{id}/ws`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct WsQuery {
    /// Only messages after this message id.
    pub after_id: Option<i64>,
    /// Most messages to return (default 200).
    pub limit: Option<usize>,
}

/// Query of `GET /sitemap`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct SiteQuery {
    /// Only this host (empty: all).
    pub host: Option<String>,
}

/// Body of `PUT /roe` and `POST /roe/check`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct RoeBody {
    /// The rules of engagement, as YAML.
    pub text: String,
}

/// Body of `PUT /exchanges/{id}/annotation`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct AnnotationBody {
    /// Highlight colour (empty or missing clears it).
    #[serde(default)]
    pub highlight: Option<String>,
    /// A comment (empty or missing clears it).
    #[serde(default)]
    pub comment: Option<String>,
}

/// Query of `GET /ws/history`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct WsHistoryQuery {
    /// Only connections to this host (empty: all).
    pub host: Option<String>,
    /// Only messages before this message id (for paging back).
    pub before_id: Option<i64>,
    /// Most messages to return (default 500).
    pub limit: Option<usize>,
}

/// Query of `GET /exchanges/{id}/code`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct CodeQuery {
    /// Language of the snippet.
    pub lang: Lang,
}

/// Body of `POST /tools/code`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeBody {
    /// Full URL the request goes to.
    pub url: String,
    /// The request as text.
    pub raw: String,
    /// Language of the snippet.
    pub lang: Lang,
}

/// Body of `POST /tools/curl`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct CurlBody {
    /// A cURL command line.
    pub command: String,
}

/// Body of `POST /tools/compare`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct CompareBody {
    /// First exchange id.
    pub a: i64,
    /// Second exchange id.
    pub b: i64,
}

/// Body of `POST /tools/token-analyzer/analyze`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TokensBody {
    /// Tokens to analyze (session ids, CSRF tokens, ...).
    pub tokens: Vec<String>,
}

/// Query of `GET /fuzzer/attacks/{id}`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
pub struct FromQuery {
    /// Only result rows from this index on (default 0).
    pub from: Option<usize>,
}

/// Body of `PUT /assistant/key`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct KeyBody {
    /// Name of the environment variable that holds the key.
    pub name: String,
    /// The API key. It is stored in the vault, never returned.
    pub key: String,
}

/// Body of `POST /findings/{id}/explain`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ExplainBody {
    /// A framework to map the finding to (for example OWASP).
    pub framework: Option<String>,
}

/// Body of `POST /assistant/send`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SendBody {
    /// Continue this chat (default: start a new one).
    pub chat_id: Option<i64>,
    /// The message. Must not be empty.
    pub text: String,
}

/// Body of `POST /ai-scan/{id}/message`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AiScanMessage {
    /// The message for the running scan.
    pub text: String,
}

/// Query of `GET /attack-paths` and `GET /attack-graph`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ScanQuery {
    /// Only paths from this AI scan.
    pub scan: Option<i64>,
}

/// Body of `PUT /proxy/listeners`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct ListenersBody {
    /// The complete list of proxy listeners.
    pub listeners: Vec<ListenerConfig>,
}

/// Body of `PUT /match-replace`.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct RulesBody {
    /// The complete list of match-and-replace rules.
    pub rules: Vec<Rule>,
}
