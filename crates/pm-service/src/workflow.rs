//! Workflows (roadmap 2.2): saved, named chains of steps that work on "the current exchange".
//!
//! This file is the model and the engine, with no storage and no gate: the definition types (what is saved and what
//! the API and the UI edit), their validation, the pure pieces of each step (conditions, extraction, templates,
//! request edits) and [`execute`], which walks the steps against a [`Host`]. `workflow_service.rs` supplies the real
//! host: sends go through the same gate as Replay (scope, tier from the payload classifier, approvals, rate limits,
//! identity, audit) and are recorded in history with source `workflow`.
//!
//! Steps: `match` (stop here when the exchange does not fit), `extract` (a value into a variable), `transform`
//! (encode, decode or hash a variable, or build one from a template), `send` (a request built from a template or
//! from the current exchange with edits; its response becomes the current exchange) and `assert` (a failed check
//! marks the run failed but the run goes on). There are no loops, branches or jumps: steps run once, in order, which
//! is what makes the limits below a real bound.
//!
//! Values that come out of responses are target content. A variable never holds a carriage return, a line feed or
//! a NUL (so a value cannot add a header or a second request), a send's target cannot contain variables, and every
//! request is classified and gated at the moment it is built, so a value that turns a request destructive needs the
//! approval a destructive request needs.

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use pm_replay::Endpoint;
use pm_store::ExchangeSummary;
use pm_tools::hql;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::session::{self, ExtractKind, Extraction};

/// Project setting that holds the saved workflows (a JSON list).
pub const WORKFLOWS_SETTING: &str = "workflows";
/// Most workflows in a project.
pub const MAX_WORKFLOWS: usize = 100;
/// Most steps in a workflow.
pub const MAX_STEPS: usize = 50;
/// Most sends in one run (and in one workflow: there are no loops, so the count is known when it is saved).
pub const MAX_SENDS: usize = 20;
/// Longest a run may take, not counting the time it waits for an approval.
pub const MAX_RUN_SECS: u64 = 120;
/// Most variables a run holds.
pub const MAX_VARS: usize = 100;
/// Longest variable value, in bytes.
pub const MAX_VALUE_LEN: usize = 16 * 1024;
/// Per-minute cap of a per-exchange trigger: default and largest.
pub const DEFAULT_TRIGGER_RATE: u32 = 6;
pub const MAX_TRIGGER_RATE: u32 = 60;

/// Variables every run has, set from the current exchange and updated by each send. User variables cannot start
/// with `current_`.
const BUILTINS: &[&str] = &[
    "current_exchange",
    "current_scheme",
    "current_host",
    "current_port",
    "current_method",
    "current_path",
    "current_status",
];

// ---------------------------------------------------------------- definition

/// A saved workflow.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Workflow {
    /// Assigned when the workflow is first saved.
    pub id: i64,
    /// A unique name, 1 to 64 characters.
    pub name: String,
    pub description: String,
    /// Up to 50 steps, run in order. No loops.
    pub steps: Vec<Step>,
    /// Whether the workflow runs by itself on new proxied exchanges (off until a person turns it on).
    pub trigger: Trigger,
    /// Who saved it last.
    pub updated_by: String,
    pub updated_ms: i64,
}

/// What a person edits: a workflow without the fields the service manages.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct WorkflowInput {
    pub name: String,
    pub description: String,
    pub steps: Vec<Step>,
}

/// The per-exchange trigger of a workflow: run it on each new proxied exchange that fits its first `match` step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Trigger {
    /// Off by default. Only a person turns it on; editing the steps turns it off again.
    pub enabled: bool,
    /// At most this many automatic runs per minute (1 to 60, default 6); exchanges past it are skipped, not queued.
    pub max_per_minute: u32,
    /// Who turned it on. Runs go through the gate as this person.
    pub enabled_by: String,
    pub enabled_ms: i64,
    /// Exchanges skipped because of the rate cap or because other runs were busy, since this process started.
    pub skipped: u64,
}

impl Default for Trigger {
    fn default() -> Self {
        Self {
            enabled: false,
            max_per_minute: DEFAULT_TRIGGER_RATE,
            enabled_by: String::new(),
            enabled_ms: 0,
            skipped: 0,
        }
    }
}

/// One step of a workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Step {
    /// Stop the run (status `stopped`) unless the current exchange fits the condition.
    Match(Condition),
    /// Check the current exchange or a variable. A failed check marks the run `failed`; the run goes on.
    Assert(Condition),
    /// Read a value out of the current request or response into a variable.
    Extract(ExtractStep),
    /// Set a variable from a template, then apply encodings, decodings or hashes to it.
    Transform(TransformStep),
    /// Send a request through the policy gate; its response becomes the current exchange.
    Send(SendStep),
}

impl Step {
    pub fn kind(&self) -> &'static str {
        match self {
            Step::Match(_) => "match",
            Step::Assert(_) => "assert",
            Step::Extract(_) => "extract",
            Step::Transform(_) => "transform",
            Step::Send(_) => "send",
        }
    }
}

/// Which message of the current exchange a test or extraction looks at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Request,
    #[default]
    Response,
}

/// A test of the current exchange or of variables. Every test that is set must hold; `negate` flips the result.
/// At least one test is needed. `{{variable}}` works in the text values (not in regular expressions or HQL).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Condition {
    /// A history query (HQL) the current exchange must match, e.g. `status:200 resp:"token"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hql: Option<String>,
    /// Methods the request may have, separated by commas: `POST` or `GET,HEAD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Text the request path (with its query) must contain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_contains: Option<String>,
    /// Statuses the response may have: `200`, `2xx`, `200..299`, or a comma-separated list such as `200,302,4xx`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// A header that must be present (by name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// With `header`: text one of its values must contain (case-insensitive).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_contains: Option<String>,
    /// Text the body must contain (decoded: de-chunked and decompressed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_contains: Option<String>,
    /// A regular expression the body must match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_regex: Option<String>,
    /// Whether `header`, `body_contains` and `body_regex` look at the request or the response (default response).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<Side>,
    /// A variable to test. Alone: it must be set and not empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub var: Option<String>,
    /// With `var`: the exact value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub var_equals: Option<String>,
    /// With `var`: text the value must contain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub var_contains: Option<String>,
    /// With `var`: a regular expression the value must match.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub var_matches: Option<String>,
    /// Pass when the tests do NOT all hold.
    pub negate: bool,
    /// What a failed `assert` says, or why a `match` stopped the run (default: what failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl Condition {
    fn is_empty(&self) -> bool {
        self.hql.is_none()
            && self.method.is_none()
            && self.path_contains.is_none()
            && self.status.is_none()
            && self.header.is_none()
            && self.body_contains.is_none()
            && self.body_regex.is_none()
            && self.var.is_none()
    }
}

/// How an extraction reads its source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExtractType {
    /// A capture group of a regular expression over the head and the decoded body (`group`, default 1, else the whole
    /// match).
    #[default]
    Regex,
    /// A JSON pointer into the body, e.g. `/data/token`.
    Json,
    /// A header's value.
    Header,
    /// A cookie: from `Set-Cookie` in a response, from `Cookie` in a request.
    Cookie,
    /// The `value` of an HTML `<input>` found by its `name` (or `id`), entities decoded: the hidden CSRF field.
    HtmlInput,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ExtractStep {
    /// The variable to set: letters, digits and `_`, not starting with a digit or `current_`.
    pub name: String,
    pub kind: ExtractType,
    /// The regular expression, JSON pointer, header name, cookie name or input name.
    pub expr: String,
    /// For `regex`: which capture group (0 is the whole match). Default: group 1 if the pattern has one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<usize>,
    /// Read the request or the response (default response; `html_input` reads responses only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side: Option<Side>,
    /// When nothing is found: leave the variable unset and go on (default: the run fails here).
    pub optional: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TransformStep {
    /// The variable to set.
    pub name: String,
    /// The starting text, with `{{variable}}` replaced: `{{token}}`, or `user:{{name}}`.
    pub value: String,
    /// Operations applied to it in order (the editor's inline transforms): url_encode, url_decode, url_encode_full,
    /// url_decode_full, base64_encode, base64_decode, base64url_encode, base64url_decode, html_encode, html_decode,
    /// hex_encode, hex_decode, unicode_encode, unicode_encode_all, unicode_decode, json_escape, json_unescape, md5,
    /// sha1, sha256. None: the variable is just the template.
    pub ops: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SendStep {
    /// Where to send, as scheme://host[:port]. Default: the current exchange's server. No variables here: a
    /// response cannot choose where the next request goes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// A whole request as text, with `{{variable}}` and `{{secret:NAME}}` placeholders. Default: the current
    /// exchange's request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// Changes made to the request after the template is filled in, in order.
    pub edits: Vec<Edit>,
    /// Send with this test identity's credentials ("anonymous" for none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    /// Update Content-Length to match the body (default true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_content_length: Option<bool>,
}

/// A change to a request. `{{variable}}` works in the values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Edit {
    /// Replace a header's value, or add the header.
    SetHeader {
        name: String,
        value: String,
    },
    RemoveHeader {
        name: String,
    },
    /// Set a query, URL-encoded form or top-level JSON parameter; added when the request does not have it.
    SetParam {
        name: String,
        value: String,
    },
    /// Replace text anywhere in the request. Fails when nothing matches, so a typo is not a silent no-op.
    ReplaceText {
        find: String,
        replace: String,
        /// `find` is a regular expression and `replace` may use `$1`.
        #[serde(default)]
        regex: bool,
    },
}

// ---------------------------------------------------------------- run record

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    /// Every step ran and every assertion held.
    Ok,
    /// An assertion failed, a step could not run (nothing extracted, a send error) or a limit was reached.
    Failed,
    /// A `match` step did not fit: the exchange is not one this workflow is for.
    Stopped,
    /// The policy gate refused a send (scope, tier, actor).
    Denied,
    /// A send waits for a person's approval; run it again with `approval_id` to continue from that step.
    PendingApproval,
}

impl RunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Ok => "ok",
            RunStatus::Failed => "failed",
            RunStatus::Stopped => "stopped",
            RunStatus::Denied => "denied",
            RunStatus::PendingApproval => "pending_approval",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Ok,
    Failed,
    Stopped,
    Denied,
    PendingApproval,
}

/// What one step did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StepRun {
    /// Position in the workflow, from 1.
    pub step: usize,
    /// `match`, `assert`, `extract`, `transform` or `send`.
    pub kind: String,
    pub status: StepStatus,
    /// What happened, without target content.
    pub message: String,
    /// For a send: the recorded exchange (also when it failed on the wire).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange_id: Option<i64>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AssertionResult {
    pub step: usize,
    pub ok: bool,
    pub message: String,
}

/// Where a run waits for an approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Pending {
    /// The send step (from 1) that needs the approval.
    pub step: usize,
    pub approval_id: String,
    pub summary: String,
    pub reasons: Vec<String>,
    /// The exchange that was current, and what the run had used up, so it continues exactly from here.
    pub current_exchange: Option<i64>,
    pub sends: usize,
    pub elapsed_ms: u64,
    /// The definition's digest when the run paused: a run does not continue on a workflow edited since.
    pub digest: String,
}

/// One run of a workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WorkflowRun {
    pub id: i64,
    pub workflow_id: i64,
    pub workflow_name: String,
    /// Who ran it, e.g. `human:local` or `agent:claude`.
    pub actor: String,
    /// How it started: `manual` (API, UI, CLI, MCP), `exchange` (the per-exchange trigger) or `fuzzer`.
    pub trigger: String,
    /// The exchange it started on, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_exchange: Option<i64>,
    pub status: RunStatus,
    /// Why it did not finish `ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub started_ms: i64,
    pub duration_ms: u64,
    /// The steps that ran, in order.
    pub steps: Vec<StepRun>,
    /// Variables at the end of the run. For agents, values are hidden or marked as target content.
    pub variables: BTreeMap<String, String>,
    /// Every exchange the run sent, in order.
    pub exchanges: Vec<i64>,
    pub assertions: Vec<AssertionResult>,
    pub sends: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
}

impl WorkflowRun {
    pub(crate) fn new(wf: &Workflow, actor: &str, trigger: &str, start_exchange: Option<i64>, now_ms: i64) -> Self {
        Self {
            id: 0,
            workflow_id: wf.id,
            workflow_name: wf.name.clone(),
            actor: actor.into(),
            trigger: trigger.into(),
            start_exchange,
            status: RunStatus::Running,
            reason: None,
            started_ms: now_ms,
            duration_ms: 0,
            steps: vec![],
            variables: BTreeMap::new(),
            exchanges: vec![],
            assertions: vec![],
            sends: 0,
            pending: None,
        }
    }
}

// ---------------------------------------------------------------- validation

/// Whether `name` can be a variable name.
pub fn valid_var(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit())
}

fn user_var(name: &str) -> Result<(), String> {
    if !valid_var(name) {
        return Err(format!("{name:?} is not a variable name (letters, digits and _; not starting with a digit)"));
    }
    if name.starts_with("current_") {
        return Err(format!("{name}: names starting with current_ are set by the workflow itself"));
    }
    Ok(())
}

fn var_re() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\{\{([A-Za-z_][A-Za-z0-9_]{0,63})\}\}").expect("valid regex"))
}

/// The variables a template names (`{{secret:…}}` placeholders are not variables).
fn refs(text: &str) -> Vec<String> {
    var_re().captures_iter(text).map(|c| c[1].to_string()).collect()
}

/// Fills `{{variable}}` in. An unknown variable is an error: a half-filled request must never be sent.
pub(crate) fn render(text: &str, vars: &Vars) -> Result<String, String> {
    let mut missing: Option<String> = None;
    let out = var_re().replace_all(text, |c: &regex::Captures| match vars.get(&c[1]) {
        Some(v) => v.clone(),
        None => {
            missing.get_or_insert_with(|| c[1].to_string());
            String::new()
        }
    });
    match missing {
        Some(m) => Err(format!("variable {{{{{m}}}}} is not set")),
        None => Ok(out.into_owned()),
    }
}

pub(crate) type Vars = BTreeMap<String, String>;

fn compile(re: &str) -> Result<regex::Regex, String> {
    regex::RegexBuilder::new(re).size_limit(1 << 20).build().map_err(|e| format!("bad regular expression {re:?}: {e}"))
}

/// Parses a status spec: `200`, `2xx`, `200..299`, `200-299`, or a comma list. Inclusive ranges.
pub(crate) fn parse_status(spec: &str) -> Result<Vec<(u16, u16)>, String> {
    let mut out = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let one = |s: &str| s.trim().parse::<u16>().ok().filter(|n| (100..=599).contains(n));
        let range = if let Some(h) = part.strip_suffix("xx").filter(|h| h.len() == 1) {
            h.parse::<u16>().ok().filter(|d| (1..=5).contains(d)).map(|d| (d * 100, d * 100 + 99))
        } else if let Some((a, b)) = part.split_once("..").or_else(|| part.split_once('-')) {
            one(a).zip(one(b)).filter(|(a, b)| a <= b)
        } else {
            one(part).map(|n| (n, n))
        };
        out.push(range.ok_or_else(|| format!("bad status {part:?}: use 200, 2xx, 200..299 or a list"))?);
    }
    if out.is_empty() {
        return Err("status is empty".into());
    }
    Ok(out)
}

fn header_token(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

impl Workflow {
    /// What the save checks: shape, limits, regular expressions, HQL, variable names, and that every `{{variable}}`
    /// is set by an earlier step. (A trigger needs more: see `Workflow::check_trigger`.)
    pub fn validate(&self) -> Result<(), String> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 64 || name.chars().any(char::is_control) {
            return Err("a workflow needs a name of 1 to 64 characters".into());
        }
        if self.description.chars().count() > 500 {
            return Err("the description is longer than 500 characters".into());
        }
        if self.steps.is_empty() || self.steps.len() > MAX_STEPS {
            return Err(format!(
                "a workflow has 1 to {MAX_STEPS} steps (there are no loops: repeat a step by writing it again)"
            ));
        }
        let sends = self.steps.iter().filter(|s| matches!(s, Step::Send(_))).count();
        if sends > MAX_SENDS {
            return Err(format!("a workflow may send at most {MAX_SENDS} requests ({sends} send steps)"));
        }
        let mut defined: HashSet<String> = BUILTINS.iter().map(|s| s.to_string()).collect();
        for (i, step) in self.steps.iter().enumerate() {
            let at = |e: String| format!("step {} ({}): {e}", i + 1, step.kind());
            let uses = |text: &str, defined: &HashSet<String>| -> Result<(), String> {
                match refs(text).into_iter().find(|r| !defined.contains(r)) {
                    Some(r) => Err(at(format!("{{{{{r}}}}} is used before any step sets it"))),
                    None => Ok(()),
                }
            };
            match step {
                Step::Match(c) | Step::Assert(c) => {
                    validate_condition(c).map_err(&at)?;
                    for t in [&c.path_contains, &c.header_contains, &c.body_contains, &c.var_equals, &c.var_contains]
                        .into_iter()
                        .flatten()
                    {
                        uses(t, &defined)?;
                    }
                    if let Some(v) = &c.var
                        && !defined.contains(v)
                    {
                        return Err(at(format!("variable {v} is tested before any step sets it")));
                    }
                }
                Step::Extract(x) => {
                    user_var(&x.name).map_err(&at)?;
                    validate_extract(x).map_err(&at)?;
                    defined.insert(x.name.clone());
                }
                Step::Transform(t) => {
                    user_var(&t.name).map_err(&at)?;
                    if t.value.is_empty() && t.ops.is_empty() {
                        return Err(at("give a value or an operation".into()));
                    }
                    if t.ops.len() > 20 {
                        return Err(at("at most 20 operations".into()));
                    }
                    if let Some(op) = t.ops.iter().find(|o| !pm_tools::transform::OPS.contains(&o.as_str())) {
                        return Err(at(format!(
                            "unknown operation {op}; use one of {}",
                            pm_tools::transform::OPS.join(", ")
                        )));
                    }
                    uses(&t.value, &defined)?;
                    defined.insert(t.name.clone());
                }
                Step::Send(s) => {
                    validate_send(s).map_err(&at)?;
                    let mut texts: Vec<&str> = s.raw.iter().map(String::as_str).collect();
                    for e in &s.edits {
                        match e {
                            Edit::SetHeader { value, .. } | Edit::SetParam { value, .. } => texts.push(value),
                            Edit::ReplaceText { replace, .. } => texts.push(replace),
                            Edit::RemoveHeader { .. } => {}
                        }
                    }
                    for t in texts {
                        uses(t, &defined)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// What turning the per-exchange trigger on needs: the first step is a `match` with a test of the exchange (so the
    /// workflow does not run on everything), and the workflow does not need a starting exchange of its own choosing.
    pub fn check_trigger(&self) -> Result<(), String> {
        match self.steps.first() {
            Some(Step::Match(c)) if c.hql.is_some() || c.method.is_some() || c.path_contains.is_some() || c.status.is_some()
                || c.header.is_some() || c.body_contains.is_some() || c.body_regex.is_some() => Ok(()),
            Some(Step::Match(_)) => Err("the first match step tests only variables; it must test the exchange (path, status, header, body or HQL)".into()),
            _ => Err("a workflow with a trigger starts with a match step that says which exchanges it is for".into()),
        }
    }

    /// The first step as a condition on new exchanges, for the trigger.
    pub(crate) fn trigger_match(&self) -> Option<&Condition> {
        match self.steps.first() {
            Some(Step::Match(c)) => Some(c),
            _ => None,
        }
    }
}

fn validate_condition(c: &Condition) -> Result<(), String> {
    if c.is_empty() {
        return Err("a condition needs at least one test".into());
    }
    if let Some(q) = &c.hql {
        hql::Query::parse(q).map_err(|e| format!("hql: {e}"))?;
    }
    if let Some(m) = &c.method
        && m.split(',').map(str::trim).any(|x| x.is_empty() || !header_token(x))
    {
        return Err(format!("bad method list {m:?}"));
    }
    if let Some(s) = &c.status {
        parse_status(s)?;
    }
    if c.header_contains.is_some() && c.header.is_none() {
        return Err("header_contains needs header".into());
    }
    if let Some(h) = &c.header
        && !header_token(h)
    {
        return Err(format!("bad header name {h:?}"));
    }
    if let Some(r) = &c.body_regex {
        compile(r)?;
    }
    if let Some(r) = &c.var_matches {
        compile(r)?;
    }
    if c.var.is_none() && (c.var_equals.is_some() || c.var_contains.is_some() || c.var_matches.is_some()) {
        return Err("var_equals, var_contains and var_matches need var".into());
    }
    if let Some(v) = &c.var
        && !valid_var(v)
    {
        return Err(format!("{v:?} is not a variable name"));
    }
    Ok(())
}

fn validate_extract(x: &ExtractStep) -> Result<(), String> {
    if x.expr.is_empty() {
        return Err("expr is empty".into());
    }
    match x.kind {
        ExtractType::Regex => {
            compile(&x.expr)?;
        }
        ExtractType::Json if !x.expr.starts_with('/') => {
            return Err(format!("JSON pointers start with / ({:?})", x.expr));
        }
        ExtractType::Header if !header_token(&x.expr) => return Err(format!("bad header name {:?}", x.expr)),
        ExtractType::HtmlInput if x.side == Some(Side::Request) => {
            return Err("html_input reads responses".into());
        }
        _ => {}
    }
    if x.group.is_some() && x.kind != ExtractType::Regex {
        return Err("group is for regex extractions".into());
    }
    Ok(())
}

fn validate_send(s: &SendStep) -> Result<(), String> {
    if let Some(u) = &s.url {
        if u.contains("{{") {
            return Err(
                "the target can't contain variables: a response must not choose where the next request goes".into()
            );
        }
        crate::replay::parse_url_endpoint(u).map_err(|e| e.to_string())?;
    }
    if let Some(raw) = &s.raw {
        // The template with every variable filled in must be a request.
        let probe = var_re().replace_all(raw, "x");
        let head = pm_http::split_message(probe.as_bytes()).0;
        if pm_http::parse_request_head(&crlf(head)).is_err() {
            return Err("raw is not a valid HTTP request".into());
        }
    }
    for e in &s.edits {
        match e {
            Edit::SetHeader { name, value } => {
                if !header_token(name) {
                    return Err(format!("bad header name {name:?}"));
                }
                if value.contains(['\r', '\n', '\0']) {
                    return Err("a header value can't contain line breaks".into());
                }
            }
            Edit::RemoveHeader { name } if !header_token(name) => return Err(format!("bad header name {name:?}")),
            Edit::SetParam { name, .. } if name.is_empty() || name.contains(['\r', '\n', '&', '=', '#']) => {
                return Err(format!("bad parameter name {name:?}"));
            }
            Edit::ReplaceText { find, regex, .. } => {
                if find.is_empty() {
                    return Err("replace_text needs text to find".into());
                }
                if *regex {
                    compile(find)?;
                }
            }
            _ => {}
        }
    }
    if let Some(i) = &s.identity
        && i.trim().is_empty()
    {
        return Err("identity is empty".into());
    }
    Ok(())
}

/// Bare line feeds in a head become CR LF, as `Service::outgoing` does, so validation sees what will be sent.
fn crlf(head: &[u8]) -> Vec<u8> {
    crate::replay::crlf_head(head)
}

// ---------------------------------------------------------------- what an agent sees of a definition

/// Whether a value is only template references (`{{token}}`, `Bearer {{token}}`), which hold no secret themselves.
fn only_refs(v: &str) -> bool {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^\s*(?:[A-Za-z]+ )?\{\{[^{}]+\}\}\s*$").expect("valid regex")).is_match(v)
}

fn mask(v: &str) -> String {
    if only_refs(v) { v.to_string() } else { "[hidden]".into() }
}

/// A request template with its header values, query values and body hidden, for agents: login steps hold passwords.
fn mask_raw(raw: &str) -> String {
    let (head, body) = match raw.find("\n\n").map(|i| (i, 2)).or_else(|| raw.find("\r\n\r\n").map(|i| (i, 4))) {
        Some((i, n)) => (&raw[..i], &raw[i + n..]),
        None => (raw, ""),
    };
    let mut out = Vec::new();
    for (i, line) in head.lines().enumerate() {
        if i == 0 {
            out.push(match line.split_once('?') {
                Some((a, rest)) => {
                    format!("{a}?[hidden]{}", rest.rsplit_once(' ').map(|(_, v)| format!(" {v}")).unwrap_or_default())
                }
                None => line.to_string(),
            });
        } else {
            match line.split_once(':') {
                Some((n, v)) => out.push(format!("{n}: {}", mask(v.trim()))),
                None => out.push(line.to_string()),
            }
        }
    }
    let mut text = out.join("\n");
    if !body.trim().is_empty() {
        text.push_str(&format!("\n\n[body hidden, {} bytes]", body.len()));
    }
    text
}

impl Workflow {
    /// The definition as an agent may see it: secrets can be typed into request templates and values, so those are
    /// hidden unless they are only references to variables. Names, steps, tests and extraction rules stay.
    pub fn for_agent(&self) -> Workflow {
        let mut w = self.clone();
        for step in &mut w.steps {
            match step {
                Step::Send(s) => {
                    s.raw = s.raw.as_deref().map(mask_raw);
                    for e in &mut s.edits {
                        match e {
                            Edit::SetHeader { value, .. } | Edit::SetParam { value, .. } => *value = mask(value),
                            Edit::ReplaceText { find, replace, .. } => {
                                *find = mask(find);
                                *replace = mask(replace);
                            }
                            Edit::RemoveHeader { .. } => {}
                        }
                    }
                }
                Step::Transform(t) => t.value = mask(&t.value),
                _ => {}
            }
        }
        w
    }

    /// A short, stable identifier of the definition (what an approval or the audit log names).
    pub fn digest(&self) -> String {
        let text = serde_json::to_string(&(&self.name, &self.steps)).unwrap_or_default();
        pm_policy::audit::content_hash(text.as_bytes())
    }

    /// What the audit log keeps of a definition: names and step kinds, never request text (it can hold passwords).
    pub fn for_audit(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "name": self.name,
            "steps": self.steps.iter().map(Step::kind).collect::<Vec<_>>(),
            "digest": self.digest(),
            "trigger": { "enabled": self.trigger.enabled, "max_per_minute": self.trigger.max_per_minute },
        })
    }
}

// ---------------------------------------------------------------- the current exchange and the host

/// The exchange steps read: a recorded one (the start, or the last send's).
#[derive(Debug, Clone)]
pub(crate) struct Current {
    pub summary: ExchangeSummary,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
}

impl Current {
    pub fn endpoint(&self) -> Endpoint {
        Endpoint::new(&self.summary.scheme, &self.summary.host, self.summary.port)
    }
}

/// A request a send step built, for the host to gate and send.
#[derive(Debug, Clone)]
pub(crate) struct SendRequest {
    /// The send step's number, from 1.
    pub step: usize,
    pub endpoint: Endpoint,
    pub raw: Vec<u8>,
    pub identity: Option<String>,
    pub fix_content_length: bool,
    /// An approval to run this request with (only for the step a paused run continues from).
    pub approval_id: Option<String>,
}

pub(crate) enum SendOutcome {
    /// Sent and recorded; the response is the new current exchange.
    Sent(Box<Current>),
    /// Nothing usable came back (connection refused, timeout); recorded as `exchange_id` when it was.
    Failed {
        exchange_id: Option<i64>,
        error: String,
    },
    Denied(Vec<String>),
    Pending {
        approval_id: String,
        summary: String,
        reasons: Vec<String>,
    },
}

/// What the engine needs from its surroundings: scope, and the gated send.
pub(crate) trait Host {
    fn in_scope(&self, c: &Current) -> bool;
    async fn send(&self, req: SendRequest) -> SendOutcome;
}

// ---------------------------------------------------------------- conditions

fn body_of(raw: &[u8]) -> String {
    let (head, body) = pm_http::split_message(raw);
    let headers = pm_http::parse_request_head(head)
        .map(|h| h.headers)
        .or_else(|_| pm_http::parse_response_head(head).map(|h| h.headers))
        .unwrap_or_default();
    String::from_utf8_lossy(&pm_ai::body::decode(&headers, body).bytes).into_owned()
}

fn headers_of(raw: &[u8], side: Side) -> Vec<pm_http::Header> {
    let head = pm_http::split_message(raw).0;
    match side {
        Side::Request => pm_http::parse_request_head(head).map(|h| h.headers).unwrap_or_default(),
        Side::Response => pm_http::parse_response_head(head).map(|h| h.headers).unwrap_or_default(),
    }
}

struct HqlFetch {
    req: Vec<u8>,
    resp: Option<Vec<u8>>,
    scope: bool,
}

impl hql::Fetch for HqlFetch {
    fn request(&mut self) -> &[u8] {
        &self.req
    }
    fn response(&mut self) -> Option<&[u8]> {
        self.resp.as_deref()
    }
    fn in_scope(&mut self) -> bool {
        self.scope
    }
}

/// Whether every test of `c` holds for the current exchange and variables. `Err` says which one failed, without
/// quoting target content.
pub(crate) fn check_condition(
    c: &Condition,
    cur: Option<&Current>,
    vars: &Vars,
    in_scope: impl Fn(&Current) -> bool,
) -> Result<(), String> {
    let held = all_tests_hold(c, cur, vars, in_scope);
    match (held, c.negate) {
        (Ok(()), false) | (Err(_), true) => Ok(()),
        (Err(why), false) => Err(why),
        (Ok(()), true) => Err("the tests all held, and this condition needs them not to".into()),
    }
}

fn all_tests_hold(
    c: &Condition,
    cur: Option<&Current>,
    vars: &Vars,
    in_scope: impl Fn(&Current) -> bool,
) -> Result<(), String> {
    let needs_exchange = c.hql.is_some()
        || c.method.is_some()
        || c.path_contains.is_some()
        || c.status.is_some()
        || c.header.is_some()
        || c.body_contains.is_some()
        || c.body_regex.is_some();
    let cur = match (needs_exchange, cur) {
        (true, None) => {
            return Err("there is no current exchange (start the run on an exchange, or send a request first)".into());
        }
        (_, c) => c,
    };
    let side = c.side.unwrap_or_default();
    if let Some(cur) = cur {
        if let Some(q) = &c.hql {
            let query = hql::Query::parse(q).map_err(|e| format!("hql: {e}"))?;
            let names = BTreeMap::new();
            let meta = crate::history::meta(&cur.summary, &names);
            let mut fetch = HqlFetch {
                req: crate::search::searchable(&cur.request),
                resp: cur.response.as_deref().map(crate::search::searchable),
                scope: in_scope(cur),
            };
            if !query.matches(&meta, &mut fetch) {
                return Err("the exchange does not match the HQL query".into());
            }
        }
        if let Some(m) = &c.method
            && !m.split(',').any(|x| x.trim().eq_ignore_ascii_case(&cur.summary.method))
        {
            return Err(format!("the method is {}, not {m}", cur.summary.method));
        }
        if let Some(p) = &c.path_contains {
            let p = render(p, vars)?;
            if !cur.summary.path.contains(&p) {
                return Err(format!("the path does not contain {p:?}"));
            }
        }
        if let Some(spec) = &c.status {
            let ranges = parse_status(spec)?;
            match cur.summary.status {
                Some(s) if ranges.iter().any(|(a, b)| (*a..=*b).contains(&s)) => {}
                Some(s) => return Err(format!("the status is {s}, expected {spec}")),
                None => return Err(format!("there is no response (expected status {spec})")),
            }
        }
        let message = match side {
            Side::Request => Some(cur.request.as_slice()),
            Side::Response => cur.response.as_deref(),
        };
        if let Some(name) = &c.header {
            let raw = message.ok_or("there is no response to look at")?;
            let want = c.header_contains.as_deref().map(|t| render(t, vars)).transpose()?;
            let found = headers_of(raw, side).into_iter().filter(|h| h.name.eq_ignore_ascii_case(name)).any(|h| {
                want.as_deref()
                    .is_none_or(|w| String::from_utf8_lossy(&h.value).to_lowercase().contains(&w.to_lowercase()))
            });
            if !found {
                return Err(match want {
                    Some(w) => format!("header {name} is missing or does not contain {w:?}"),
                    None => format!("header {name} is missing"),
                });
            }
        }
        if c.body_contains.is_some() || c.body_regex.is_some() {
            let raw = message.ok_or("there is no response to look at")?;
            let body = body_of(raw);
            if let Some(t) = &c.body_contains {
                let t = render(t, vars)?;
                if !body.contains(&t) {
                    return Err(format!("the body does not contain {t:?}"));
                }
            }
            if let Some(r) = &c.body_regex
                && !compile(r)?.is_match(&body)
            {
                return Err(format!("the body does not match /{r}/"));
            }
        }
    }
    if let Some(name) = &c.var {
        let value = vars.get(name);
        let Some(value) = value.filter(|v| !v.is_empty()) else {
            return Err(format!("variable {name} is not set or is empty"));
        };
        if let Some(e) = &c.var_equals
            && *value != render(e, vars)?
        {
            return Err(format!("variable {name} does not have the expected value"));
        }
        if let Some(t) = &c.var_contains
            && !value.contains(&render(t, vars)?)
        {
            return Err(format!("variable {name} does not contain {t:?}"));
        }
        if let Some(r) = &c.var_matches
            && !compile(r)?.is_match(value)
        {
            return Err(format!("variable {name} does not match /{r}/"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- extraction

/// Reads one value out of the current exchange. `Ok(None)`: nothing found.
pub(crate) fn extract_value(x: &ExtractStep, cur: &Current) -> Result<Option<String>, String> {
    let side = x.side.unwrap_or_default();
    let raw: &[u8] = match side {
        Side::Request => &cur.request,
        Side::Response => cur.response.as_deref().ok_or("there is no response to read")?,
    };
    // Head plus decoded body: what the person saw, so a gzip or chunked response reads like plain text.
    let text = crate::search::searchable(raw);
    let found = match x.kind {
        ExtractType::Regex => {
            let re = compile(&x.expr)?;
            match x.group {
                None => session::extract(
                    &Extraction { name: String::new(), kind: ExtractKind::Regex, expr: x.expr.clone() },
                    &text,
                ),
                Some(g) => {
                    let hay = String::from_utf8_lossy(&text);
                    re.captures(&hay).and_then(|c| c.get(g)).map(|m| m.as_str().to_string())
                }
            }
        }
        ExtractType::Json => match side {
            Side::Response => session::extract(
                &Extraction { name: String::new(), kind: ExtractKind::Json, expr: x.expr.clone() },
                &text,
            ),
            Side::Request => {
                let v: serde_json::Value =
                    serde_json::from_str(&body_of(raw)).map_err(|_| "the request body is not JSON")?;
                v.pointer(&x.expr).map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
            }
        },
        ExtractType::Header => match side {
            Side::Response => session::extract(
                &Extraction { name: String::new(), kind: ExtractKind::Header, expr: x.expr.clone() },
                &text,
            ),
            Side::Request => headers_of(raw, side)
                .into_iter()
                .find(|h| h.name.eq_ignore_ascii_case(&x.expr))
                .map(|h| String::from_utf8_lossy(&h.value).trim().to_string()),
        },
        ExtractType::Cookie => match side {
            Side::Response => session::extract(
                &Extraction { name: String::new(), kind: ExtractKind::Cookie, expr: x.expr.clone() },
                &text,
            ),
            Side::Request => headers_of(raw, side)
                .into_iter()
                .filter(|h| h.name.eq_ignore_ascii_case("cookie"))
                .flat_map(|h| {
                    String::from_utf8_lossy(&h.value).split(';').map(|p| p.trim().to_string()).collect::<Vec<_>>()
                })
                .find_map(|p| p.split_once('=').filter(|(k, _)| *k == x.expr).map(|(_, v)| v.to_string())),
        },
        ExtractType::HtmlInput => {
            let html = body_of(raw);
            pm_crawl::input_value(&html, &x.expr).map(|v| pm_tools::transform::apply("html_decode", &v).unwrap_or(v))
        }
    };
    Ok(found)
}

/// Whether a value may become a variable: no line breaks or NUL (it ends up in requests), and not huge.
pub(crate) fn check_value(name: &str, v: &str) -> Result<(), String> {
    if v.contains(['\r', '\n', '\0']) {
        return Err(format!("the value for {name} has a line break or NUL, which a variable may not hold"));
    }
    if v.len() > MAX_VALUE_LEN {
        return Err(format!("the value for {name} is longer than {MAX_VALUE_LEN} bytes"));
    }
    Ok(())
}

fn set_var(vars: &mut Vars, name: &str, value: String) -> Result<(), String> {
    check_value(name, &value)?;
    let user = vars.keys().filter(|k| !k.starts_with("current_")).count();
    if !vars.contains_key(name) && user >= MAX_VARS {
        return Err(format!("a run holds at most {MAX_VARS} variables"));
    }
    vars.insert(name.to_string(), value);
    Ok(())
}

fn refresh_builtins(vars: &mut Vars, cur: Option<&Current>) {
    vars.retain(|k, _| !k.starts_with("current_"));
    let Some(c) = cur else { return };
    let s = &c.summary;
    let mut put = |k: &str, v: String| {
        if check_value(k, &v).is_ok() {
            vars.insert(k.to_string(), v);
        }
    };
    put("current_exchange", s.id.to_string());
    put("current_scheme", s.scheme.clone());
    put("current_host", s.host.clone());
    put("current_port", s.port.to_string());
    put("current_method", s.method.clone());
    put("current_path", s.path.clone());
    if let Some(st) = s.status {
        put("current_status", st.to_string());
    }
}

// ---------------------------------------------------------------- building a send

fn apply_edit(raw: Vec<u8>, e: &Edit, vars: &Vars) -> Result<Vec<u8>, String> {
    match e {
        Edit::SetHeader { name, value } => {
            let v = render(value, vars)?;
            if !session::header_safe(&v) {
                return Err(format!("the value for header {name} has a line break"));
            }
            Ok(session::set_header(&raw, name, &v))
        }
        Edit::RemoveHeader { name } => {
            let (mut lines, eol, body) = session::split_lines(&raw).ok_or("the request has no complete head")?;
            let before = lines.len();
            let mut first = true;
            lines.retain(|l| {
                let keep = first || session::header_name(l).is_none_or(|n| !n.eq_ignore_ascii_case(name.as_bytes()));
                first = false;
                keep
            });
            if lines.len() == before {
                return Err(format!("the request has no header {name}"));
            }
            Ok(session::join_lines(&lines, eol, body))
        }
        Edit::SetParam { name, value } => upsert_param(&raw, name, &render(value, vars)?),
        Edit::ReplaceText { find, replace, regex } => {
            let text =
                String::from_utf8(raw).map_err(|_| "the request is not text, so text cannot be replaced in it")?;
            let replace = render(replace, vars)?;
            let out = if *regex {
                let re = compile(find)?;
                if !re.is_match(&text) {
                    return Err(format!("replace_text: /{find}/ matched nothing"));
                }
                re.replace_all(&text, replace.as_str()).into_owned()
            } else {
                if !text.contains(find.as_str()) {
                    return Err(format!("replace_text: {find:?} was not found in the request"));
                }
                text.replace(find.as_str(), &replace)
            };
            Ok(out.into_bytes())
        }
    }
}

/// Sets a query, form or JSON parameter, adding it when the request does not have it: to the form body of a form
/// request, as a top-level key of a JSON object body, else to the query string.
pub(crate) fn upsert_param(raw: &[u8], name: &str, value: &str) -> Result<Vec<u8>, String> {
    let (changed, did) = session::set_param(raw, name, value);
    if did || changed != raw {
        return Ok(changed);
    }
    let (mut lines, eol, body) = session::split_lines(raw).ok_or("the request has no complete head")?;
    let ctype = lines
        .iter()
        .skip(1)
        .find(|l| session::header_name(l).is_some_and(|n| n.eq_ignore_ascii_case(b"content-type")))
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .unwrap_or_default();
    let enc = session::form_encode(value);
    let key = session::form_encode(name);
    let text = String::from_utf8_lossy(body).into_owned();
    if !body.is_empty() && ctype.contains("x-www-form-urlencoded") {
        let sep = if text.is_empty() { "" } else { "&" };
        let new_body = format!("{text}{sep}{key}={enc}");
        return Ok(pm_http::fix_content_length(&session::join_lines(&lines, eol, new_body.as_bytes())));
    }
    if !body.is_empty() && ctype.contains("json") {
        let t = text.trim_end();
        let inner =
            t.strip_suffix('}').filter(|_| t.trim_start().starts_with('{')).ok_or("the JSON body is not an object")?;
        let v = serde_json::to_string(value).map_err(|e| e.to_string())?;
        let k = serde_json::to_string(name).map_err(|e| e.to_string())?;
        let comma = if inner.trim_end().ends_with('{') { "" } else { "," };
        let new_body = format!("{}{comma}{k}:{v}}}", inner.trim_end());
        return Ok(pm_http::fix_content_length(&session::join_lines(&lines, eol, new_body.as_bytes())));
    }
    // Into the query string of the request line.
    let first = String::from_utf8_lossy(&lines[0]).into_owned();
    let parts: Vec<&str> = first.split(' ').collect();
    if parts.len() < 3 {
        return Err("the request line is not METHOD target VERSION".into());
    }
    let target = parts[1..parts.len() - 1].join(" ");
    let (path, frag) = match target.split_once('#') {
        Some((p, f)) => (p.to_string(), format!("#{f}")),
        None => (target.clone(), String::new()),
    };
    let sep = if path.contains('?') { if path.ends_with('?') || path.ends_with('&') { "" } else { "&" } } else { "?" };
    lines[0] = format!("{} {path}{sep}{key}={enc}{frag} {}", parts[0], parts[parts.len() - 1]).into_bytes();
    Ok(session::join_lines(&lines, eol, body))
}

/// The target and bytes of a send step. The template's variables are filled in, then the edits are applied.
pub(crate) fn build_send(s: &SendStep, cur: Option<&Current>, vars: &Vars) -> Result<(Endpoint, Vec<u8>), String> {
    let endpoint = match (&s.url, cur) {
        (Some(u), _) => crate::replay::parse_url_endpoint(u).map_err(|e| e.to_string())?,
        (None, Some(c)) => c.endpoint(),
        (None, None) => return Err("there is no current exchange, so give the send step a url".into()),
    };
    let mut raw = match (&s.raw, cur) {
        (Some(t), _) => render(t, vars)?.into_bytes(),
        (None, Some(c)) => c.request.clone(),
        (None, None) => {
            return Err("there is no current exchange to resend, so give the send step a raw request".into());
        }
    };
    for e in &s.edits {
        raw = apply_edit(raw, e, vars)?;
    }
    if raw.len() > 8 << 20 {
        return Err("the request is larger than 8 MB".into());
    }
    Ok((endpoint, raw))
}

// ---------------------------------------------------------------- the engine

/// Where a paused run continues.
pub(crate) struct Resume {
    /// The step to run next, from 0 (the send that needed the approval).
    pub next: usize,
    pub current: Option<Current>,
    pub sends: usize,
    pub elapsed_ms: u64,
}

fn fail_step(rec: &mut StepRun, msg: impl Into<String>) -> (RunStatus, String) {
    let m = msg.into();
    rec.status = StepStatus::Failed;
    rec.message = m.clone();
    (RunStatus::Failed, format!("step {}: {m}", rec.step))
}

/// Runs the workflow's steps, one after another, updating `run` in place. `progress` is called after each step.
/// `start` is the current exchange to begin with; `resume` continues a run that paused for an approval, with
/// `approval_id` for the send that waits. Nothing here fails: whatever goes wrong ends up in the run's status.
pub(crate) async fn execute<H: Host>(
    host: &H,
    wf: &Workflow,
    run: &mut WorkflowRun,
    start: Option<Current>,
    resume: Option<Resume>,
    approval_id: Option<String>,
    progress: &(dyn Fn(&WorkflowRun) + Sync),
) {
    let clock = Instant::now();
    let (mut next, mut sends, base_ms, mut cur) = match resume {
        Some(r) => (r.next, r.sends, r.elapsed_ms, r.current),
        None => (0, 0, 0, start),
    };
    let elapsed = |clock: &Instant| base_ms + clock.elapsed().as_millis() as u64;
    let budget = Duration::from_secs(MAX_RUN_SECS);
    let mut vars: Vars = run.variables.clone();
    refresh_builtins(&mut vars, cur.as_ref());
    let mut approval = approval_id;
    run.status = RunStatus::Running;
    run.pending = None;
    run.reason = None;
    let mut halt: Option<(RunStatus, String)> = None;

    while next < wf.steps.len() && halt.is_none() {
        if Duration::from_millis(elapsed(&clock)) >= budget {
            halt = Some((RunStatus::Failed, format!("time limit: a run may take at most {MAX_RUN_SECS} s")));
            break;
        }
        let step = &wf.steps[next];
        let t0 = Instant::now();
        let n = next + 1;
        let mut rec = StepRun {
            step: n,
            kind: step.kind().into(),
            status: StepStatus::Ok,
            message: String::new(),
            exchange_id: None,
            elapsed_ms: 0,
        };
        match step {
            Step::Match(c) => match check_condition(c, cur.as_ref(), &vars, |x| host.in_scope(x)) {
                Ok(()) => rec.message = "matched".into(),
                Err(why) => {
                    let msg = c.message.clone().unwrap_or(why);
                    rec.status = StepStatus::Stopped;
                    rec.message = msg.clone();
                    halt = Some((RunStatus::Stopped, format!("step {n}: {msg}")));
                }
            },
            Step::Assert(c) => {
                let result = check_condition(c, cur.as_ref(), &vars, |x| host.in_scope(x));
                let ok = result.is_ok();
                let message = match result {
                    Ok(()) => c.message.clone().map(|m| format!("held ({m})")).unwrap_or_else(|| "held".into()),
                    Err(why) => c.message.clone().map(|m| format!("{m} ({why})")).unwrap_or(why),
                };
                if !ok {
                    rec.status = StepStatus::Failed;
                }
                rec.message = message.clone();
                run.assertions.push(AssertionResult { step: n, ok, message });
            }
            Step::Extract(x) => match cur.as_ref() {
                None => {
                    halt = Some(fail_step(
                        &mut rec,
                        "there is no current exchange to read (start on an exchange or send first)",
                    ));
                }
                Some(c) => match extract_value(x, c) {
                    Err(e) => halt = Some(fail_step(&mut rec, e)),
                    Ok(None) if x.optional => rec.message = format!("{}: nothing found, left unset", x.name),
                    Ok(None) => halt = Some(fail_step(&mut rec, format!("{}: nothing found for {:?}", x.name, x.expr))),
                    Ok(Some(v)) => {
                        let len = v.len();
                        match set_var(&mut vars, &x.name, v) {
                            Ok(()) => rec.message = format!("{} set ({len} bytes)", x.name),
                            Err(e) => halt = Some(fail_step(&mut rec, e)),
                        }
                    }
                },
            },
            Step::Transform(t) => {
                let result = render(&t.value, &vars)
                    .and_then(|v| pm_tools::transform::chain(&t.ops, &v).map_err(|e| e.to_string()))
                    .and_then(|v| {
                        let len = v.len();
                        set_var(&mut vars, &t.name, v).map(|()| len)
                    });
                match result {
                    Ok(len) => rec.message = format!("{} set ({len} bytes)", t.name),
                    Err(e) => halt = Some(fail_step(&mut rec, e)),
                }
            }
            Step::Send(s) => {
                if sends >= MAX_SENDS {
                    halt =
                        Some(fail_step(&mut rec, format!("send limit: a run may send at most {MAX_SENDS} requests")));
                } else {
                    match build_send(s, cur.as_ref(), &vars) {
                        Err(e) => halt = Some(fail_step(&mut rec, e)),
                        Ok((endpoint, raw)) => {
                            let req = SendRequest {
                                step: n,
                                endpoint,
                                raw,
                                identity: s.identity.clone(),
                                fix_content_length: s.fix_content_length.unwrap_or(true),
                                approval_id: approval.take(),
                            };
                            let left = budget.saturating_sub(Duration::from_millis(elapsed(&clock)));
                            let outcome = tokio::time::timeout(left, host.send(req)).await;
                            match outcome {
                                Err(_) => {
                                    halt = Some(fail_step(
                                        &mut rec,
                                        format!("time limit: a run may take at most {MAX_RUN_SECS} s"),
                                    ));
                                }
                                Ok(SendOutcome::Sent(c)) => {
                                    sends += 1;
                                    rec.exchange_id = Some(c.summary.id);
                                    rec.message = match c.summary.status {
                                        Some(st) => format!("sent, status {st}"),
                                        None => "sent, no status".into(),
                                    };
                                    run.exchanges.push(c.summary.id);
                                    cur = Some(*c);
                                    refresh_builtins(&mut vars, cur.as_ref());
                                }
                                Ok(SendOutcome::Failed { exchange_id, error }) => {
                                    sends += 1;
                                    rec.exchange_id = exchange_id;
                                    run.exchanges.extend(exchange_id);
                                    halt = Some(fail_step(&mut rec, format!("the send failed: {error}")));
                                }
                                Ok(SendOutcome::Denied(reasons)) => {
                                    rec.status = StepStatus::Denied;
                                    rec.message = format!("denied: {}", reasons.join("; "));
                                    halt = Some((RunStatus::Denied, format!("step {n}: {}", rec.message)));
                                }
                                Ok(SendOutcome::Pending { approval_id, summary, reasons }) => {
                                    rec.status = StepStatus::PendingApproval;
                                    rec.message = format!("waiting for approval {approval_id}");
                                    run.pending = Some(Pending {
                                        step: n,
                                        approval_id: approval_id.clone(),
                                        summary,
                                        reasons,
                                        current_exchange: cur.as_ref().map(|c| c.summary.id),
                                        sends,
                                        elapsed_ms: elapsed(&clock),
                                        digest: wf.digest(),
                                    });
                                    halt = Some((
                                        RunStatus::PendingApproval,
                                        format!("step {n} waits for approval {approval_id}"),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
        rec.elapsed_ms = t0.elapsed().as_millis() as u64;
        run.steps.push(rec);
        run.sends = sends;
        run.variables =
            vars.iter().filter(|(k, _)| !k.starts_with("current_")).map(|(k, v)| (k.clone(), v.clone())).collect();
        run.duration_ms = elapsed(&clock);
        progress(run);
        next += 1;
    }

    run.duration_ms = elapsed(&clock);
    run.variables = vars.into_iter().filter(|(k, _)| !k.starts_with("current_")).collect();
    let failed = run.assertions.iter().filter(|a| !a.ok).count();
    match halt {
        Some((status, reason)) => {
            run.status = status;
            run.reason = Some(reason);
        }
        None if failed > 0 => {
            run.status = RunStatus::Failed;
            run.reason = Some(format!("{failed} assertion(s) failed"));
        }
        None => run.status = RunStatus::Ok,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn summary(id: i64, method: &str, path: &str, status: Option<u16>) -> ExchangeSummary {
        ExchangeSummary {
            id,
            ts_ms: 0,
            duration_ms: Some(1),
            source: "proxy".into(),
            actor_id: "human:t".into(),
            scheme: "http".into(),
            host: "shop.test".into(),
            port: 80,
            method: method.into(),
            path: path.into(),
            status,
            req_len: 0,
            resp_len: None,
            error: None,
            identity: None,
            hypothesis_id: None,
            highlight: None,
            comment: None,
            client_addr: None,
            modified: false,
        }
    }

    fn current(
        id: i64,
        method: &str,
        path: &str,
        req_extra: &str,
        status: u16,
        resp_head: &str,
        body: &str,
    ) -> Current {
        let request = format!("{method} {path} HTTP/1.1\r\nHost: shop.test\r\n{req_extra}\r\n").into_bytes();
        let response =
            format!("HTTP/1.1 {status} X\r\n{resp_head}Content-Length: {}\r\n\r\n{body}", body.len()).into_bytes();
        Current { summary: summary(id, method, path, Some(status)), request, response: Some(response) }
    }

    /// A host whose server answers by request line; records what was sent.
    struct Fake {
        sent: Mutex<Vec<String>>,
        next_id: Mutex<i64>,
        pending_on: Option<usize>,
        deny_on: Option<usize>,
        /// Delay of every send.
        delay: Duration,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                sent: Mutex::default(),
                next_id: Mutex::new(100),
                pending_on: None,
                deny_on: None,
                delay: Duration::ZERO,
            }
        }
        fn sent(&self) -> Vec<String> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl Host for Fake {
        fn in_scope(&self, c: &Current) -> bool {
            c.summary.host == "shop.test"
        }
        async fn send(&self, req: SendRequest) -> SendOutcome {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.deny_on == Some(req.step) {
                return SendOutcome::Denied(vec!["out of scope".into()]);
            }
            if self.pending_on == Some(req.step) && req.approval_id.is_none() {
                return SendOutcome::Pending { approval_id: "ap1".into(), summary: "send".into(), reasons: vec![] };
            }
            let text = String::from_utf8_lossy(&req.raw).into_owned();
            self.sent.lock().unwrap().push(text.clone());
            let id = {
                let mut n = self.next_id.lock().unwrap();
                *n += 1;
                *n
            };
            let line = text.lines().next().unwrap_or_default().to_string();
            let (status, body) = if line.starts_with("POST /login") {
                (200, r#"{"token":"tok123","csrf":"a&amp;b"}"#.to_string())
            } else if line.contains("/me") && text.contains("Bearer tok123") {
                (200, r#"{"user":"alice"}"#.to_string())
            } else if line.contains("/me") {
                (401, "{}".to_string())
            } else {
                (200, "ok".to_string())
            };
            let m = line.split(' ').next().unwrap_or("GET").to_string();
            let p = line.split(' ').nth(1).unwrap_or("/").to_string();
            let mut c = current(id, &m, &p, "", status, "Set-Cookie: sid=cookieval\r\n", &body);
            c.request = req.raw;
            SendOutcome::Sent(Box::new(c))
        }
    }

    fn wf(steps: Vec<Step>) -> Workflow {
        Workflow { id: 1, name: "t".into(), steps, ..Default::default() }
    }

    fn cond() -> Condition {
        Condition::default()
    }

    fn extract(name: &str, kind: ExtractType, expr: &str) -> Step {
        Step::Extract(ExtractStep { name: name.into(), kind, expr: expr.into(), ..Default::default() })
    }

    fn send_raw(raw: &str) -> Step {
        Step::Send(SendStep { url: Some("http://shop.test".into()), raw: Some(raw.into()), ..Default::default() })
    }

    async fn run_with(host: &Fake, w: &Workflow, start: Option<Current>) -> WorkflowRun {
        let mut run = WorkflowRun::new(w, "human:t", "manual", start.as_ref().map(|c| c.summary.id), 0);
        execute(host, w, &mut run, start, None, None, &|_| {}).await;
        run
    }

    #[tokio::test]
    async fn login_extract_send_assert() {
        let host = Fake::new();
        let w = wf(vec![
            send_raw("POST /login HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 0\r\n\r\n"),
            extract("token", ExtractType::Json, "/token"),
            send_raw("GET /me HTTP/1.1\r\nHost: shop.test\r\nAuthorization: Bearer {{token}}\r\n\r\n"),
            Step::Assert(Condition { status: Some("200".into()), body_contains: Some("alice".into()), ..cond() }),
        ]);
        w.validate().unwrap();
        let run = run_with(&host, &w, None).await;
        assert_eq!(run.status, RunStatus::Ok, "{run:?}");
        assert_eq!(run.variables["token"], "tok123");
        assert_eq!(run.sends, 2);
        assert_eq!(run.exchanges, [101, 102]);
        assert!(host.sent()[1].contains("Authorization: Bearer tok123"));
        assert_eq!(run.assertions.len(), 1);
        assert!(run.assertions[0].ok);
        assert_eq!(
            run.steps.iter().map(|s| s.kind.as_str()).collect::<Vec<_>>(),
            ["send", "extract", "send", "assert"]
        );
    }

    #[tokio::test]
    async fn a_failed_assert_marks_the_run_failed_but_the_run_goes_on() {
        let host = Fake::new();
        let w = wf(vec![
            send_raw("GET /me HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
            Step::Assert(Condition { status: Some("2xx".into()), message: Some("me must work".into()), ..cond() }),
            send_raw("GET /after HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
        ]);
        let run = run_with(&host, &w, None).await;
        assert_eq!(run.status, RunStatus::Failed);
        assert_eq!(run.sends, 2, "the step after the failed assert still ran");
        assert!(!run.assertions[0].ok && run.assertions[0].message.starts_with("me must work"), "{run:?}");
        assert_eq!(run.steps[1].status, StepStatus::Failed);
        assert!(run.reason.as_deref().unwrap().contains("1 assertion"));
    }

    #[tokio::test]
    async fn a_match_that_does_not_fit_stops_the_run_with_a_reason() {
        let host = Fake::new();
        let start = current(7, "GET", "/api/orders/5", "", 404, "", "nope");
        let w = wf(vec![
            Step::Match(Condition { status: Some("200".into()), ..cond() }),
            send_raw("GET /never HTTP/1.1\r\nHost: shop.test\r\n\r\n"),
        ]);
        let run = run_with(&host, &w, Some(start.clone())).await;
        assert_eq!(run.status, RunStatus::Stopped);
        assert!(run.reason.as_deref().unwrap().contains("status is 404"), "{run:?}");
        assert!(host.sent().is_empty());
        // Fits: runs on.
        let w = wf(vec![Step::Match(Condition {
            method: Some("GET,HEAD".into()),
            path_contains: Some("/orders/".into()),
            ..cond()
        })]);
        assert_eq!(run_with(&host, &w, Some(start)).await.status, RunStatus::Ok);
    }

    #[tokio::test]
    async fn steps_that_need_an_exchange_fail_without_one() {
        let host = Fake::new();
        let w = wf(vec![extract("x", ExtractType::Regex, "a")]);
        let run = run_with(&host, &w, None).await;
        assert_eq!(run.status, RunStatus::Failed);
        assert!(run.reason.as_deref().unwrap().contains("no current exchange"));
        let w = wf(vec![Step::Send(SendStep::default())]);
        assert_eq!(run_with(&host, &w, None).await.status, RunStatus::Failed);
    }

    #[test]
    fn conditions_cover_every_test_and_negate() {
        let c = current(
            1,
            "POST",
            "/api/x?y=1",
            "Cookie: a=b\r\n",
            302,
            "Location: /next\r\nSet-Cookie: s=1\r\n",
            "Hello <b>World</b> 42",
        );
        let vars: Vars = BTreeMap::from([("who".into(), "World".into()), ("n".into(), "42".into())]);
        let ok = |cd: Condition| check_condition(&cd, Some(&c), &vars, |_| true);
        assert!(ok(Condition { method: Some("post".into()), ..cond() }).is_ok());
        assert!(ok(Condition { method: Some("GET".into()), ..cond() }).is_err());
        assert!(ok(Condition { path_contains: Some("y=1".into()), ..cond() }).is_ok());
        assert!(ok(Condition { status: Some("3xx".into()), ..cond() }).is_ok());
        assert!(ok(Condition { status: Some("200,301..303".into()), ..cond() }).is_ok());
        assert!(ok(Condition { status: Some("2xx".into()), ..cond() }).is_err());
        assert!(
            ok(Condition { header: Some("location".into()), header_contains: Some("NEXT".into()), ..cond() }).is_ok()
        );
        assert!(
            ok(Condition { header: Some("location".into()), header_contains: Some("login".into()), ..cond() }).is_err()
        );
        assert!(ok(Condition { header: Some("set-cookie".into()), ..cond() }).is_ok());
        assert!(ok(Condition { header: Some("cookie".into()), side: Some(Side::Request), ..cond() }).is_ok());
        assert!(ok(Condition { body_contains: Some("Hello {{who}}".into()), ..cond() }).is_err(), "markup in between");
        assert!(ok(Condition { body_contains: Some("<b>{{who}}</b> {{n}}".into()), ..cond() }).is_ok());
        assert!(ok(Condition { body_regex: Some(r"\d{2}$".into()), ..cond() }).is_ok());
        assert!(ok(Condition { body_regex: Some(r"^\d+".into()), ..cond() }).is_err());
        assert!(ok(Condition { var: Some("who".into()), ..cond() }).is_ok());
        assert!(ok(Condition { var: Some("nope".into()), ..cond() }).is_err());
        assert!(
            ok(Condition {
                var: Some("n".into()),
                var_equals: Some("42".into()),
                var_matches: Some("^4".into()),
                ..cond()
            })
            .is_ok()
        );
        assert!(ok(Condition { var: Some("n".into()), var_contains: Some("9".into()), ..cond() }).is_err());
        assert!(ok(Condition { hql: Some("method:POST status:302 resp:World".into()), ..cond() }).is_ok());
        assert!(ok(Condition { hql: Some("status:200".into()), ..cond() }).is_err());
        assert!(ok(Condition { hql: Some("is:inscope".into()), ..cond() }).is_ok());
        // Several tests: all must hold; negate flips the whole.
        assert!(ok(Condition { method: Some("POST".into()), status: Some("200".into()), ..cond() }).is_err());
        assert!(
            ok(Condition { method: Some("POST".into()), status: Some("200".into()), negate: true, ..cond() }).is_ok()
        );
        assert!(ok(Condition { status: Some("3xx".into()), negate: true, ..cond() }).is_err());
        // Without an exchange only variable tests can hold.
        assert!(check_condition(&Condition { var: Some("n".into()), ..cond() }, None, &vars, |_| true).is_ok());
        assert!(check_condition(&Condition { status: Some("200".into()), ..cond() }, None, &vars, |_| true).is_err());
    }

    #[test]
    fn failure_messages_never_quote_the_target() {
        let c = current(1, "GET", "/p", "", 200, "X-Secret: s3cr3t-value\r\n", "the body says hunter2");
        let vars = Vars::new();
        for cd in [
            Condition { body_contains: Some("absent".into()), ..cond() },
            Condition { header: Some("x-secret".into()), header_contains: Some("nope".into()), ..cond() },
        ] {
            let why = check_condition(&cd, Some(&c), &vars, |_| true).unwrap_err();
            assert!(!why.contains("hunter2") && !why.contains("s3cr3t"), "{why}");
        }
    }

    #[test]
    fn extraction_kinds() {
        let c = current(
            1,
            "GET",
            "/p",
            "Cookie: sid=reqcookie; theme=dark\r\nX-Req: rh\r\n",
            200,
            "X-Token: H1\r\nSet-Cookie: s=C1; Path=/\r\nContent-Type: text/html\r\n",
            r#"<form><input type="hidden" name="csrf" value="a&amp;b&quot;"><p id=n>count: 17, next: 18</p></form>"#,
        );
        let x = |kind, expr: &str, group: Option<usize>, side: Option<Side>| {
            extract_value(&ExtractStep { name: "v".into(), kind, expr: expr.into(), group, side, optional: false }, &c)
        };
        assert_eq!(x(ExtractType::Regex, r"count: (\d+)", None, None).unwrap().as_deref(), Some("17"));
        assert_eq!(x(ExtractType::Regex, r"count: (\d+), next: (\d+)", Some(2), None).unwrap().as_deref(), Some("18"));
        assert_eq!(x(ExtractType::Regex, r"count: \d+", Some(0), None).unwrap().as_deref(), Some("count: 17"));
        assert_eq!(
            x(ExtractType::Regex, r"count: \d+", None, None).unwrap().as_deref(),
            Some("count: 17"),
            "no group: whole match"
        );
        assert_eq!(x(ExtractType::Regex, "absent", None, None).unwrap(), None);
        assert_eq!(x(ExtractType::Header, "x-token", None, None).unwrap().as_deref(), Some("H1"));
        assert_eq!(x(ExtractType::Header, "x-req", None, Some(Side::Request)).unwrap().as_deref(), Some("rh"));
        assert_eq!(x(ExtractType::Cookie, "s", None, None).unwrap().as_deref(), Some("C1"));
        assert_eq!(x(ExtractType::Cookie, "theme", None, Some(Side::Request)).unwrap().as_deref(), Some("dark"));
        assert_eq!(
            x(ExtractType::HtmlInput, "csrf", None, None).unwrap().as_deref(),
            Some("a&b\""),
            "entities decoded"
        );
        assert_eq!(x(ExtractType::HtmlInput, "missing", None, None).unwrap(), None);
        let j = current(
            2,
            "POST",
            "/j",
            "",
            200,
            "Content-Type: application/json\r\n",
            r#"{"data":{"token":"J1","n":5,"list":[1,2]}}"#,
        );
        let xj = |expr: &str| {
            extract_value(
                &ExtractStep { name: "v".into(), kind: ExtractType::Json, expr: expr.into(), ..Default::default() },
                &j,
            )
        };
        assert_eq!(xj("/data/token").unwrap().as_deref(), Some("J1"));
        assert_eq!(xj("/data/n").unwrap().as_deref(), Some("5"));
        assert_eq!(xj("/data/list/1").unwrap().as_deref(), Some("2"));
        assert_eq!(xj("/data/none").unwrap(), None);
    }

    #[test]
    fn extraction_reads_gzip_and_chunked_bodies_like_plain_text() {
        use std::io::Write;
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(br#"{"token":"zipped"}"#).unwrap();
        let body = gz.finish().unwrap();
        let mut resp =
            format!("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        resp.extend_from_slice(&body);
        let mut c = current(1, "GET", "/", "", 200, "", "");
        c.response = Some(resp);
        let step =
            ExtractStep { name: "t".into(), kind: ExtractType::Json, expr: "/token".into(), ..Default::default() };
        assert_eq!(extract_value(&step, &c).unwrap().as_deref(), Some("zipped"));
        c.response = Some(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"tok\r\n9\r\nen\":\"c1\"}\r\n0\r\n\r\n"
                .to_vec(),
        );
        assert_eq!(extract_value(&step, &c).unwrap().as_deref(), Some("c1"));
    }

    #[tokio::test]
    async fn extraction_that_finds_nothing_fails_the_run_unless_optional() {
        let host = Fake::new();
        let start = current(1, "GET", "/", "", 200, "", "no token here");
        let w = wf(vec![extract("t", ExtractType::Regex, r"token=(\w+)")]);
        let run = run_with(&host, &w, Some(start.clone())).await;
        assert_eq!(run.status, RunStatus::Failed);
        assert!(run.reason.as_deref().unwrap().contains("nothing found"));
        let w = wf(vec![Step::Extract(ExtractStep {
            name: "t".into(),
            expr: "token=(\\w+)".into(),
            optional: true,
            ..Default::default()
        })]);
        let run = run_with(&host, &w, Some(start)).await;
        assert_eq!(run.status, RunStatus::Ok);
        assert!(!run.variables.contains_key("t"));
    }

    #[tokio::test]
    async fn transforms_chain_and_templates_fill_variables() {
        let host = Fake::new();
        let start = current(1, "GET", "/p", "", 200, "", "user=al ice");
        let w = wf(vec![
            extract("u", ExtractType::Regex, r"user=([\w ]+)"),
            Step::Transform(TransformStep {
                name: "b".into(),
                value: "{{u}}:pw".into(),
                ops: vec!["base64_encode".into()],
            }),
            Step::Transform(TransformStep { name: "e".into(), value: "{{u}}".into(), ops: vec!["url_encode".into()] }),
            Step::Transform(TransformStep { name: "h".into(), value: "abc".into(), ops: vec!["md5".into()] }),
            Step::Transform(TransformStep {
                name: "plain".into(),
                value: "{{e}}-{{current_method}}-{{current_status}}".into(),
                ops: vec![],
            }),
            Step::Transform(TransformStep {
                name: "round".into(),
                value: "{{b}}".into(),
                ops: vec!["base64_decode".into()],
            }),
        ]);
        w.validate().unwrap();
        let run = run_with(&host, &w, Some(start)).await;
        assert_eq!(run.status, RunStatus::Ok, "{run:?}");
        assert_eq!(run.variables["b"], "YWwgaWNlOnB3");
        assert_eq!(run.variables["e"], "al%20ice");
        assert_eq!(run.variables["h"], "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(run.variables["plain"], "al%20ice-GET-200");
        assert_eq!(run.variables["round"], "al ice:pw");
        assert!(!run.variables.keys().any(|k| k.starts_with("current_")), "built-ins are not part of the result");
    }

    #[tokio::test]
    async fn a_failing_transform_fails_the_run_and_line_breaks_never_become_values() {
        let host = Fake::new();
        let w = wf(vec![Step::Transform(TransformStep {
            name: "x".into(),
            value: "not base64!".into(),
            ops: vec!["base64_decode".into()],
        })]);
        let run = run_with(&host, &w, None).await;
        assert_eq!(run.status, RunStatus::Failed);
        // Decoding can produce a line break from harmless text: refused.
        let w = wf(vec![Step::Transform(TransformStep {
            name: "x".into(),
            value: "a%0d%0aSet-Cookie: x=1".into(),
            ops: vec!["url_decode".into()],
        })]);
        let run = run_with(&host, &w, None).await;
        assert_eq!(run.status, RunStatus::Failed);
        assert!(run.reason.as_deref().unwrap().contains("line break"), "{run:?}");
        assert!(!run.variables.contains_key("x"));
        // And a response cannot extract one either.
        let start = current(1, "GET", "/", "", 200, "", "a\r\nb");
        let w =
            wf(vec![Step::Extract(ExtractStep { name: "m".into(), expr: "(?s)(a.b)".into(), ..Default::default() })]);
        assert_eq!(run_with(&host, &w, Some(start)).await.status, RunStatus::Failed);
    }

    #[tokio::test]
    async fn send_edits_change_the_current_request() {
        let host = Fake::new();
        let start = current(
            1,
            "POST",
            "/api/cart?id=7",
            "Content-Type: application/x-www-form-urlencoded\r\nX-Old: 1\r\nContent-Length: 11\r\n",
            200,
            "",
            "ok",
        );
        let mut start = start;
        start.request = b"POST /api/cart?id=7 HTTP/1.1\r\nHost: shop.test\r\nContent-Type: application/x-www-form-urlencoded\r\nX-Old: 1\r\nContent-Length: 11\r\n\r\nqty=1&sku=a".to_vec();
        let w = wf(vec![
            Step::Transform(TransformStep { name: "v".into(), value: "new value".into(), ops: vec![] }),
            Step::Send(SendStep {
                edits: vec![
                    Edit::SetHeader { name: "X-Token".into(), value: "t-{{v}}".into() },
                    Edit::RemoveHeader { name: "x-old".into() },
                    Edit::SetParam { name: "id".into(), value: "{{v}}".into() },
                    Edit::SetParam { name: "extra".into(), value: "a&b".into() },
                    Edit::ReplaceText { find: "sku=a".into(), replace: "sku=zz".into(), regex: false },
                    Edit::ReplaceText { find: r"qty=(\d)".into(), replace: "qty=${1}0".into(), regex: true },
                ],
                ..Default::default()
            }),
        ]);
        w.validate().unwrap();
        let run = run_with(&host, &w, Some(start)).await;
        assert_eq!(run.status, RunStatus::Ok, "{run:?}");
        let sent = &host.sent()[0];
        assert!(sent.starts_with("POST /api/cart?id=new+value HTTP/1.1\r\n"), "{sent}");
        assert!(sent.contains("X-Token: t-new value\r\n") && !sent.contains("X-Old"), "{sent}");
        assert!(sent.ends_with("\r\n\r\nqty=10&sku=zz&extra=a%26b"), "{sent}");
    }

    #[test]
    fn param_edits_add_what_is_missing_where_it_belongs() {
        let get = b"GET /a?x=1 HTTP/1.1\r\nHost: h\r\n\r\n";
        assert_eq!(upsert_param(get, "y", "2 3").unwrap(), b"GET /a?x=1&y=2+3 HTTP/1.1\r\nHost: h\r\n\r\n");
        let bare = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n";
        assert_eq!(upsert_param(bare, "y", "2").unwrap(), b"GET /a?y=2 HTTP/1.1\r\nHost: h\r\n\r\n");
        let json = b"POST /a HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 8\r\n\r\n{\"a\":\"1\"}";
        let out = String::from_utf8(upsert_param(json, "b", "x\"y").unwrap()).unwrap();
        assert!(out.ends_with("{\"a\":\"1\",\"b\":\"x\\\"y\"}") && out.contains("Content-Length: 20\r\n"), "{out}");
        let empty = b"POST /a HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert!(String::from_utf8(upsert_param(empty, "b", "1").unwrap()).unwrap().ends_with("{\"b\":\"1\"}"));
        let form =
            b"POST /a HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\n\r\na=1";
        assert!(String::from_utf8(upsert_param(form, "b", "2").unwrap()).unwrap().ends_with("\r\n\r\na=1&b=2"));
        let existing = upsert_param(get, "x", "9").unwrap();
        assert_eq!(existing, b"GET /a?x=9 HTTP/1.1\r\nHost: h\r\n\r\n");
    }

    #[tokio::test]
    async fn edits_that_change_nothing_are_errors_not_silent_no_ops() {
        let host = Fake::new();
        let mut start = current(1, "GET", "/", "", 200, "", "ok");
        start.request = b"GET / HTTP/1.1\r\nHost: shop.test\r\n\r\n".to_vec();
        for e in [
            Edit::ReplaceText { find: "zzz".into(), replace: "y".into(), regex: false },
            Edit::ReplaceText { find: "z+".into(), replace: "y".into(), regex: true },
            Edit::RemoveHeader { name: "X-None".into() },
        ] {
            let w = wf(vec![Step::Send(SendStep { edits: vec![e], ..Default::default() })]);
            let run = run_with(&host, &w, Some(start.clone())).await;
            assert_eq!(run.status, RunStatus::Failed, "{run:?}");
        }
        assert!(host.sent().is_empty(), "nothing was sent for a failed edit");
        // A variable that is not set never reaches a request.
        let w = wf(vec![Step::Send(SendStep {
            raw: Some("GET /{{nope}} HTTP/1.1\r\nHost: x\r\n\r\n".into()),
            ..Default::default()
        })]);
        let run = run_with(&host, &w, Some(start)).await;
        assert!(run.reason.as_deref().unwrap().contains("not set"), "{run:?}");
        assert!(host.sent().is_empty());
    }

    #[tokio::test]
    async fn denied_and_pending_sends_end_the_run_and_a_resume_continues_there() {
        let mut host = Fake::new();
        host.deny_on = Some(1);
        let w = wf(vec![send_raw("GET /a HTTP/1.1\r\nHost: shop.test\r\n\r\n")]);
        let run = run_with(&host, &w, None).await;
        assert_eq!(run.status, RunStatus::Denied);
        assert!(run.reason.as_deref().unwrap().contains("out of scope"));

        let mut host = Fake::new();
        host.pending_on = Some(3);
        let w = wf(vec![
            send_raw("POST /login HTTP/1.1\r\nHost: shop.test\r\nContent-Length: 0\r\n\r\n"),
            extract("token", ExtractType::Json, "/token"),
            send_raw("GET /me HTTP/1.1\r\nHost: shop.test\r\nAuthorization: Bearer {{token}}\r\n\r\n"),
            Step::Assert(Condition { body_contains: Some("alice".into()), ..cond() }),
        ]);
        let mut run = run_with(&host, &w, None).await;
        assert_eq!(run.status, RunStatus::PendingApproval, "{run:?}");
        let p = run.pending.clone().unwrap();
        assert_eq!((p.step, p.approval_id.as_str(), p.sends, p.current_exchange), (3, "ap1", 1, Some(101)));
        assert_eq!(host.sent().len(), 1, "only the login went out");
        // Resume: the login is not sent again, the token is still there.
        let cur = current_for_login(); // the recorded login response is the current exchange again
        assert_eq!(cur.summary.id, p.current_exchange.unwrap());
        run.steps.pop();
        let resume = Resume { next: p.step - 1, current: Some(cur), sends: p.sends, elapsed_ms: p.elapsed_ms };
        execute(&host, &w, &mut run, None, Some(resume), Some("ap1".into()), &|_| {}).await;
        assert_eq!(run.status, RunStatus::Ok, "{run:?}");
        assert_eq!(host.sent().len(), 2);
        assert!(host.sent()[1].contains("Bearer tok123"));
        assert!(run.pending.is_none());
        assert_eq!(run.steps.len(), 4);
    }

    fn current_for_login() -> Current {
        current(101, "POST", "/login", "", 200, "", r#"{"token":"tok123"}"#)
    }

    #[tokio::test]
    async fn limits_stop_runs_that_would_send_too_much_or_take_too_long() {
        // The send limit is also enforced at run time (a definition edited by hand in the project file).
        let host = Fake::new();
        let steps = (0..MAX_SENDS + 3).map(|_| send_raw("GET /a HTTP/1.1\r\nHost: shop.test\r\n\r\n")).collect();
        let w = wf(steps);
        assert!(w.validate().unwrap_err().contains("at most 20"));
        let run = run_with(&host, &w, None).await;
        assert_eq!(run.status, RunStatus::Failed);
        assert_eq!(run.sends, MAX_SENDS);
        assert!(run.reason.as_deref().unwrap().contains("send limit"));

        // The time limit covers a send that is still waiting (a hung server) and counts earlier time.
        let mut slow = Fake::new();
        slow.delay = Duration::from_secs(5);
        let w = wf(vec![send_raw("GET /a HTTP/1.1\r\nHost: shop.test\r\n\r\n")]);
        let mut run = WorkflowRun::new(&w, "human:t", "manual", None, 0);
        let resume = Resume { next: 0, current: None, sends: 0, elapsed_ms: MAX_RUN_SECS * 1000 - 200 };
        execute(&slow, &w, &mut run, None, Some(resume), None, &|_| {}).await;
        assert_eq!(run.status, RunStatus::Failed);
        assert!(run.reason.as_deref().unwrap().contains("time limit"), "{run:?}");
        assert!(slow.sent().is_empty());
        // Already used up: no step starts.
        let mut run = WorkflowRun::new(&w, "human:t", "manual", None, 0);
        let resume = Resume { next: 0, current: None, sends: 0, elapsed_ms: MAX_RUN_SECS * 1000 };
        execute(&slow, &w, &mut run, None, Some(resume), None, &|_| {}).await;
        assert!(run.steps.is_empty() && run.reason.as_deref().unwrap().contains("time limit"));
    }

    #[test]
    fn validation_catches_what_would_fail_at_run_time() {
        let ok = wf(vec![
            send_raw("GET /a HTTP/1.1\r\nHost: x\r\n\r\n"),
            extract("t", ExtractType::Json, "/t"),
            send_raw("GET /b?t={{t}}&h={{current_host}} HTTP/1.1\r\nHost: x\r\n\r\n"),
        ]);
        assert!(ok.validate().is_ok());
        let bad = |steps: Vec<Step>| wf(steps).validate().unwrap_err();
        assert!(bad(vec![]).contains("1 to 50 steps"));
        assert!(bad(vec![send_raw("GET /{{t}} HTTP/1.1\r\nHost: x\r\n\r\n")]).contains("before any step sets it"));
        assert!(bad(vec![Step::Match(cond())]).contains("at least one test"));
        assert!(bad(vec![Step::Match(Condition { status: Some("abc".into()), ..cond() })]).contains("bad status"));
        assert!(bad(vec![Step::Match(Condition { hql: Some("status:(".into()), ..cond() })]).contains("hql"));
        assert!(
            bad(vec![Step::Match(Condition { body_regex: Some("(".into()), ..cond() })]).contains("regular expression")
        );
        assert!(bad(vec![Step::Match(Condition { var: Some("zz".into()), ..cond() })]).contains("before any step"));
        assert!(bad(vec![Step::Match(Condition { var_equals: Some("a".into()), ..cond() })]).contains("at least one"));
        assert!(bad(vec![extract("1x", ExtractType::Regex, "a")]).contains("not a variable name"));
        assert!(bad(vec![extract("current_x", ExtractType::Regex, "a")]).contains("current_"));
        assert!(bad(vec![extract("x", ExtractType::Json, "token")]).contains("start with /"));
        assert!(bad(vec![extract("x", ExtractType::Regex, "(")]).contains("regular expression"));
        assert!(
            bad(vec![Step::Extract(ExtractStep {
                name: "x".into(),
                kind: ExtractType::HtmlInput,
                expr: "a".into(),
                side: Some(Side::Request),
                ..Default::default()
            })])
            .contains("responses")
        );
        assert!(
            bad(vec![Step::Transform(TransformStep {
                name: "x".into(),
                value: "a".into(),
                ops: vec!["rot13".into()]
            })])
            .contains("unknown operation")
        );
        assert!(
            bad(vec![Step::Transform(TransformStep { name: "x".into(), ..Default::default() })])
                .contains("value or an operation")
        );
        assert!(
            bad(vec![Step::Send(SendStep { url: Some("http://{{host}}".into()), ..Default::default() })])
                .contains("variables")
        );
        assert!(
            bad(vec![Step::Send(SendStep { raw: Some("nonsense".into()), ..Default::default() })])
                .contains("valid HTTP")
        );
        assert!(
            bad(vec![Step::Send(SendStep {
                edits: vec![Edit::SetHeader { name: "A:b".into(), value: "x".into() }],
                ..Default::default()
            })])
            .contains("header name")
        );
        assert!(
            bad(vec![Step::Send(SendStep {
                edits: vec![Edit::SetHeader { name: "A".into(), value: "x\r\nB: y".into() }],
                ..Default::default()
            })])
            .contains("line breaks")
        );
        let mut w = ok.clone();
        w.name = "  ".into();
        assert!(w.validate().is_err());
        // The trigger needs a first match step that looks at the exchange.
        assert!(ok.check_trigger().is_err());
        let m = wf(vec![Step::Match(Condition { path_contains: Some("/api".into()), ..cond() })]);
        assert!(m.check_trigger().is_ok());
        let v =
            wf(vec![extract("t", ExtractType::Regex, "a"), Step::Match(Condition { var: Some("t".into()), ..cond() })]);
        assert!(v.check_trigger().is_err());
        let v = wf(vec![Step::Match(Condition { var: Some("current_host".into()), ..cond() })]);
        assert!(v.check_trigger().unwrap_err().contains("must test the exchange"));
    }

    #[test]
    fn definitions_round_trip_and_reject_unknown_fields() {
        let w = wf(vec![
            Step::Match(Condition { status: Some("2xx".into()), hql: Some("path:/api".into()), ..cond() }),
            extract("t", ExtractType::HtmlInput, "csrf"),
            Step::Transform(TransformStep { name: "b".into(), value: "{{t}}".into(), ops: vec!["sha256".into()] }),
            Step::Send(SendStep {
                edits: vec![
                    Edit::ReplaceText { find: "a".into(), replace: "b".into(), regex: false },
                    Edit::RemoveHeader { name: "X".into() },
                ],
                ..Default::default()
            }),
            Step::Assert(Condition { body_contains: Some("ok".into()), ..cond() }),
        ]);
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(serde_json::from_str::<Workflow>(&json).unwrap(), w);
        assert!(
            json.contains(r#""type":"match""#)
                && json.contains(r#""op":"replace_text""#)
                && json.contains(r#""kind":"html_input""#)
        );
        assert!(serde_json::from_str::<Step>(r#"{"type":"extract","name":"a","expr":"x","bogus":1}"#).is_err());
        assert!(serde_json::from_str::<Step>(r#"{"type":"match","statuss":"200"}"#).is_err());
        assert!(serde_json::from_str::<Step>(r#"{"type":"loop"}"#).is_err(), "loops do not exist");
        assert!(serde_json::from_str::<Edit>(r#"{"op":"set_header","name":"a","value":"b","x":1}"#).is_err());
    }

    #[test]
    fn agents_do_not_see_secrets_typed_into_templates() {
        let w = wf(vec![
            Step::Send(SendStep {
                url: Some("http://shop.test".into()),
                raw: Some("POST /login?next=s3cret HTTP/1.1\r\nHost: shop.test\r\nAuthorization: Bearer hunter2\r\nX-Token: {{t}}\r\nContent-Type: application/json\r\n\r\n{\"password\":\"hunter2\"}".into()),
                edits: vec![Edit::SetHeader { name: "X-Key".into(), value: "hunter2".into() }, Edit::SetHeader { name: "Authorization".into(), value: "Bearer {{t}}".into() }],
                ..Default::default()
            }),
            Step::Transform(TransformStep { name: "t".into(), value: "hunter2".into(), ops: vec![] }),
        ]);
        let shown = serde_json::to_string(&w.for_agent()).unwrap();
        assert!(!shown.contains("hunter2") && !shown.contains("s3cret"), "{shown}");
        assert!(shown.contains("Bearer {{t}}") && shown.contains("X-Token: {{t}}"), "references stay: {shown}");
        assert!(shown.contains("POST /login?[hidden] HTTP/1.1") && shown.contains("[body hidden"), "{shown}");
        assert_eq!(w.for_audit()["steps"], serde_json::json!(["send", "transform"]));
        assert!(!w.for_audit().to_string().contains("hunter2"));
    }
}
