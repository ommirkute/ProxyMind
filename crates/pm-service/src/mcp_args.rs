//! Arguments of the MCP tools that have no service request type of their own (ADR-0019 step 7). The MCP server
//! deserializes a tool call's `arguments` into these types and generates each tool's `inputSchema` from them, so the
//! schema a model reads and the input the server accepts cannot drift. Every type denies unknown fields.

use pm_ai::View;
use pm_tools::engage::CsrfTechnique;
use schemars::JsonSchema;
use serde::Deserialize;

/// A tool that takes no arguments.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

/// `site_map`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SiteMapArgs {
    /// Only hosts containing this text.
    pub host: Option<String>,
}

/// `exchange_get`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExchangeGetArgs {
    /// Id of the recorded exchange.
    pub id: i64,
    /// summary (default): key headers and a short body preview. headers: all headers. full: everything within
    /// max_tokens.
    pub view: Option<View>,
    /// Token budget of the returned view (default 1500; at least 200).
    #[schemars(range(min = 200))]
    pub max_tokens: Option<usize>,
}

/// `exchange_raw_request`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExchangeIdArgs {
    /// Id of the recorded exchange.
    pub id: i64,
}

/// `engage_references`, `engage_clickjacking`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRefArgs {
    /// Id of the recorded exchange.
    pub exchange_id: i64,
}

/// `ws_messages`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WsMessagesArgs {
    /// Id of the upgraded exchange (status 101).
    pub exchange_id: i64,
    /// Continue after this message id (next_after_id).
    pub after_id: Option<i64>,
    /// Most messages to return (default 50, max 200).
    #[schemars(range(min = 1, max = 200))]
    pub limit: Option<usize>,
    /// Longest payload text per message (default 2000, from 100 to 20000).
    #[schemars(range(min = 100, max = 20000))]
    pub max_chars: Option<usize>,
}

/// `stream_get`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamGetArgs {
    /// Id of the recorded stream (see stream_list).
    pub id: i64,
    /// Continue after this chunk id (next_after_id of the previous page).
    pub after: Option<i64>,
    /// Most chunks to return (default 50, max 200).
    #[schemars(range(min = 1, max = 200))]
    pub limit: Option<usize>,
    /// Longest text preview per chunk (default 2000, from 100 to 20000).
    #[schemars(range(min = 100, max = 20000))]
    pub max_chars: Option<usize>,
}

/// `curl_parse`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurlParseArgs {
    /// The curl command line, e.g. from a browser's Copy as cURL.
    pub command: String,
}

/// `compare_exchanges`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CompareExchangesArgs {
    /// Id of the first exchange.
    pub a: i64,
    /// Id of the second exchange.
    pub b: i64,
}

/// `scan_task_status`, `scan_task_pause`, `scan_task_resume`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskIdArgs {
    /// Id of the scan task, as returned by scan_task_start.
    pub task_id: String,
}

/// `identity_capture`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityCaptureArgs {
    /// Short name, e.g. alice or admin.
    pub name: String,
    /// e.g. user, admin, guest (default user).
    pub role: Option<String>,
    /// Recorded request that carries the identity's cookies and auth headers.
    pub exchange_id: i64,
}

/// `identity_check`, `identity_learn_logged_out`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdentityNameArgs {
    /// Name of the identity (see identity_list).
    pub name: String,
}

/// `authz_results`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthzResultsArgs {
    /// Only this exchange.
    pub exchange_id: Option<i64>,
}

/// `collaborator_payload`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CollaboratorPayloadArgs {
    /// What you're testing, shown with its interactions.
    pub note: String,
}

/// `collaborator_interactions`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CollaboratorInteractionsArgs {
    /// Only callbacks that carry this token (default: all).
    pub token: Option<String>,
    /// Most callbacks to return (default 50).
    pub limit: Option<usize>,
}

/// `skill_get`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillGetArgs {
    /// Name of the skill, from skills_list.
    pub name: String,
    /// What to focus on, e.g. "the /api/orders endpoints".
    pub focus: Option<String>,
}

/// `attack_path_list`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttackPathListArgs {
    /// Only the paths of this AI scan.
    pub scan_id: Option<i64>,
}

/// `model_changes`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ModelChangesArgs {
    /// Snapshot to compare with. Without it, the saved snapshots are listed.
    pub snapshot_id: Option<i64>,
}

/// `traffic_triage`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrafficTriageArgs {
    /// Only hosts containing this text.
    pub host: Option<String>,
    /// Only in-scope exchanges.
    pub in_scope: Option<bool>,
    /// Most entries to return (default 40).
    pub limit: Option<usize>,
}

/// `memory_save`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemorySaveArgs {
    /// login, endpoint, dead_end, technique or note.
    #[schemars(extend("enum" = ["login", "endpoint", "dead_end", "technique", "note"]))]
    pub kind: String,
    /// The note. Never a password or other secret.
    pub text: String,
    /// Host in scope the note is about (an AI scan's agents default to the scan's host).
    pub host: Option<String>,
}

/// `memory_list`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryListArgs {
    /// Host to list the notes and verdicts of.
    pub host: String,
}

/// `recon_dns`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconDnsArgs {
    /// A host in scope, or a parent domain of one.
    pub host: String,
}

/// `recon_wayback`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReconWaybackArgs {
    /// A host in scope.
    pub host: String,
    /// Most URLs to return (default 200).
    pub limit: Option<usize>,
}

/// `organizer_add`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizerAddArgs {
    /// Id of the exchange to keep.
    pub exchange_id: i64,
    /// A note for whoever comes back to it (at most 10000 bytes).
    #[serde(default)]
    #[schemars(length(max = 10000))]
    pub note: String,
}

/// `organizer_list`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizerListArgs {
    /// Only items with this status: new, in_progress, postponed, done or ignored.
    #[schemars(extend("enum" = ["new", "in_progress", "postponed", "done", "ignored"]))]
    pub status: Option<String>,
}

/// `organizer_update`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganizerUpdateArgs {
    /// Id of the Organizer item.
    pub id: i64,
    /// New status: new, in_progress, postponed, done or ignored.
    #[schemars(extend("enum" = ["new", "in_progress", "postponed", "done", "ignored"]))]
    pub status: Option<String>,
    /// New note (replaces the old one; at most 10000 bytes).
    #[schemars(length(max = 10000))]
    pub note: Option<String>,
}

/// `engage_csrf_poc`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CsrfPocArgs {
    /// Id of the recorded request.
    pub exchange_id: i64,
    /// How the page submits the request (default auto).
    #[serde(default)]
    pub technique: CsrfTechnique,
    /// Submit the form as soon as the page loads (default false).
    #[serde(default)]
    pub auto_submit: bool,
}

/// `hypothesis_list`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HypothesisListArgs {
    /// Only hypotheses with this status: open, testing, confirmed or refuted.
    pub status: Option<String>,
}

/// `coverage`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageArgs {
    /// Only untested/open cells (default true).
    pub untested_only: Option<bool>,
}

/// `proof_get`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProofGetArgs {
    /// Id of the stored proof (proof_id of a proof_run result).
    pub proof_id: i64,
}

/// `finding_retest`, `finding_prove`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingIdArgs {
    /// Id of the finding.
    pub id: i64,
}

/// `issue_library`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IssueLibraryArgs {
    /// A finding class or scanner check, e.g. sqli, reflected_input, idor. Without it, every entry's id and name is
    /// listed.
    pub class: Option<String>,
}

/// `finding_list`
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FindingListArgs {
    /// Only findings with this status: suspected, proven, confirmed, false_positive or reported.
    pub status: Option<String>,
}

/// `approval_status`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ApprovalStatusArgs {
    /// Id of the approval (approval_id of a pending_approval result).
    pub approval_id: String,
}

/// `workflow_get`
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRefArgs {
    /// The workflow's name or id (from workflow_list).
    pub workflow: String,
}
