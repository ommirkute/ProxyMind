//! The service layer: the one place where actions happen (ADR-0005).
//!
//! REST, MCP, the CLI and the UI all call this crate. Every action is
//! checked by the policy gate and written to the audit log, whether it is
//! allowed, sent for approval or denied.

mod ai_scan;
mod approvals;
mod assistant;
mod attack_paths;
mod authz;
mod authz_matrix;
mod auto;
mod browser;
mod changes;
mod collaborator;
mod crawl;
mod custom_checks;
mod discover;
mod dom_test;
mod engage;
mod events;
mod evidence;
mod findings;
mod fuzzer;
mod graphql;
mod graphql_authz;
mod group;
mod hidden_paths;
mod history;
mod identity;
mod intercept;
mod login_record;
mod memory;
mod model;
mod network;
mod openapi;
mod organizer;
mod plugins;
mod proof;
mod prove_auto;
mod race;
mod recon;
mod regress;
mod replay;
mod report;
mod report_template;
mod roe;
mod rules;
mod scan;
mod scan_profile;
mod scan_schedule;
mod scan_task;
mod search;
mod session;
mod skills;
mod tools;
mod traffic;
mod update;
mod write_checks;
mod ws;
mod ws_replay;

pub use ai_scan::{AiScan, AiScanLog, AiScanRequest, ai_scan_tool_definitions, scan_actor, scan_of, worker_actor};
pub use assistant::{AssistantConfig, Chat, ChatSummary, KeyStatus, ProviderKind, ToolProfile};
pub use attack_paths::{AttackGraph, AttackPath, AttackStep, GraphEdge, GraphNode, NewAttackPath};
pub use authz::{AuthzCheckRequest, AuthzReport};
pub use authz_matrix::{AuthzMatrix, AuthzMatrixRequest, MatrixCell, MatrixFlag, MatrixRow};
pub use auto::{AutoProven, AutoReport, DiscoverSweep, ScanLead, ScanSweep};
pub use browser::{BrowserOpenRequest, BrowserOpened, ProxyInfo};
pub use changes::{ModelChanges, OpChange, OpShape, RetestItem, SnapshotInfo};
pub use collaborator::{CollaboratorInteraction, CollaboratorPayload, CollaboratorProbe, CollaboratorStatus};
pub use crawl::{CrawlRequest, CrawlResult};
pub use custom_checks::{CustomFinding, CustomScanRequest, CustomScanResult, SavedCustomCheck};
pub use discover::{DiscoverRequest, DiscoverResult, Found};
pub use dom_test::{DomTestRequest, DomTestResult};
pub use engage::{EngageFilter, FoundComment, FoundEndpoint, FoundScript, LogicReport, TargetAnalysis, TriageItem};
pub use events::{CounterTracker, Delivery, EVENT_BUFFER, Event, Published, Subscription, Topic};
pub use evidence::{Check, CoverageCellProof, CoverageProof, EvidenceVerification, PACK_FORMAT, verify_evidence};
pub use findings::{FindingUpdate, HUMAN_STATUSES, NewFinding, Retest};
pub use fuzzer::{AttackStatus, AttackSummary, AttackView, FuzzerRequest, FuzzerResult, FuzzerRow, FuzzerStart};
pub use graphql::{GraphQlImportRequest, GraphQlImportResult, GraphQlOperation};
pub use group::{GroupItem, GroupItemResult, GroupMode, GroupRequest, GroupResult, MAX_GROUP};
pub use hidden_paths::JsSweep;
pub use history::{ExchangePage, UI_STATE_MAX};
pub use identity::{IdentityCheck, IdentityInfo};
pub use intercept::InterceptState;
pub use login_record::{LoggedOutLearned, LoginRecording, RecordedStep};
pub use memory::{FindingVerdict, MEMORY_KINDS, Memory};
pub use model::{HypothesisUpdate, ModelFilter, NewHypothesis};
pub use network::{
    LISTENERS_SETTING, ListenersView, NETWORK_SETTING, RECORDING_SETTING, RecordingSettings, load_listeners,
    load_network, sync_listeners, sync_network, watch_project,
};
pub use openapi::{OpenApiImportRequest, OpenApiImportResult, SentExample};
pub use organizer::{ORGANIZER_STATUSES, OrganizerItem, OrganizerUpdate};
pub use plugins::{PluginCheckIssue, PluginCheckRequest, PluginCheckResult, PluginInfo, PluginsView};
pub use pm_store::ApprovalRow;
pub use proof::{ProofRequest, ProofResult};
pub use prove_auto::{FindingProve, ProveSweep};
pub use race::{RaceGroup, RaceModeChoice, RaceRequest, RaceResult};
pub use recon::{DnsReport, WaybackCapture, WaybackReport};
pub use regress::{RegressionExport, RegressionResult, Skipped, junit, run_regression};
pub use replay::{ReplayRequest, ReplayResult};
pub use report::{
    Report, ReportEvidence, ReportFinding, ReportIssue, ReportIssueGroup, ReportOptions, ReportOwaspGroup, ReportProof,
    SeverityCount,
};
pub use report_template::{Rendered, ReportTemplate, TEMPLATES_SETTING, builtin_templates};
pub use roe::{ROE_SETTING, RoeView, watch_roe};
pub use rules::{RULES_SETTING, load_rules, sync_rules};
pub use scan::{ActiveFinding, ActiveScanRequest, ActiveScanResult, ScanFilter, ScanIssue};
pub use scan_profile::{PROFILES_SETTING, ScanProfile, builtin_profiles};
pub use scan_schedule::{Every, ScanSchedule, next_run_after};
pub use scan_task::{ScanTaskIssue, ScanTaskRequest, ScanTaskStatus, ScanTaskView};
pub use search::{
    MAX_SCAN, SearchHit, SearchRequest, SearchResult, SiteView, WsSearchHit, WsSearchRequest, WsSearchResult,
    searchable,
};
pub use session::{
    ExtractKind, Extraction, JarCookie, Macro, MacroRun, MacroStep, RunWhen, SESSION_SETTING, SessionConfig,
    SessionRule, SessionView, SetValue, SetWhere, Validity,
};
pub use skills::Skill;
pub use tools::{DecodeRequest, RequestTransform, TokenAnalyzerRequest, TokenAnalyzerResult};
pub use traffic::{CurlParsed, ExportRequest, ImportRequest, ImportResult, MAX_IMPORT_BYTES};
pub use update::{UpdateState, UpdateStatus};
pub use write_checks::WriteSweep;
pub use ws::{WsHistoryItem, WsHistoryPage, WsMessageView, WsPage};
pub use ws_replay::{WsOut, WsReplayRequest, WsReplayResult};

use pm_ai::Redactor;
use pm_core::now_ms;
use pm_policy::{ActionRequest, Actor, Decision, Policy, RateLimiter, Verdict, audit};
use pm_replay::Sender;
use pm_store::{Store, StoreHandle};
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

pub use {
    pm_ai, pm_browser, pm_crawl, pm_diff, pm_fuzz, pm_identity, pm_ledger, pm_model, pm_oast, pm_openapi, pm_plugin,
    pm_policy, pm_proof, pm_proxy, pm_replay, pm_scan, pm_store, pm_tools,
};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    Approval(String),
    #[error("approval {0} is not approved, was already used, or does not cover these parameters")]
    ApprovalMismatch(String),
    #[error("{0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0:#}")]
    Store(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, ServiceError>;

/// Outcome of asking to run an action.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Authorization {
    /// Go ahead.
    Allowed { reasons: Vec<String> },
    /// Waiting for a human. Retry with `run_approved` once approved.
    PendingApproval { approval_id: String, summary: String, reasons: Vec<String> },
    /// Refused.
    Denied { reasons: Vec<String> },
}

pub struct Service {
    /// Shared with the proxy's scope checks, so ROE changes reach them too.
    policy: std::sync::Arc<Policy>,
    store: std::sync::Arc<StoreHandle>,
    sender: Sender,
    limiter: RateLimiter,
    redactor: Redactor,
    intercept: std::sync::OnceLock<std::sync::Arc<pm_proxy::InterceptQueue>>,
    rewriter: std::sync::OnceLock<std::sync::Arc<pm_proxy::Rewriter>>,
    /// The ROE text in force (to notice changes saved by other processes).
    roe_text: parking_lot::Mutex<Option<String>>,
    /// Passive-check plugins the user installed (never from the project).
    plugins: parking_lot::RwLock<Vec<pm_plugin::Installed>>,
    /// The Collaborator callback listener this process runs, if any.
    oast_listening: std::sync::OnceLock<std::net::SocketAddr>,
    smtp_listening: std::sync::OnceLock<std::net::SocketAddr>,
    /// The user's home directory, whose plugin registry is read when used.
    plugin_home: std::sync::OnceLock<std::path::PathBuf>,
    /// Recent Fuzzer attacks (running ones keep going in the background).
    attacks: parking_lot::Mutex<Vec<std::sync::Arc<fuzzer::Attack>>>,
    /// This process's proxy, for the built-in browser.
    proxy_info: std::sync::OnceLock<browser::ProxyInfo>,
    /// Recent crawl-and-audit tasks.
    scan_tasks: parking_lot::Mutex<Vec<std::sync::Arc<scan_task::ScanTask>>>,
    /// Extra proxy listeners, when this process runs the proxy.
    listeners: std::sync::OnceLock<std::sync::Arc<pm_proxy::Listeners>>,
    /// Session handling: cookie jar, macro variables.
    session: parking_lot::Mutex<session::SessionState>,
    /// One macro run at a time.
    session_lock: tokio::sync::Mutex<()>,
    /// Automatic logins after an identity looked logged out, per identity.
    relogins: parking_lot::Mutex<std::collections::HashMap<String, replay::Relogins>>,
    /// The proxy records only in-scope exchanges.
    record_in_scope_only: std::sync::atomic::AtomicBool,
    /// Typed events published after writes commit (ADR-0018).
    bus: std::sync::Arc<events::Bus>,
}

/// Keeps the full-text index current and checkpoints the WAL (ADR-0017). A project file gets one long-lived
/// thread that writes through the shared handle, like the recorder and every `Service` write: it indexes the tail
/// the recorder wrote (the recorder doesn't index), then a batch of the old backlog, checkpoints about every
/// 200 ms, sleeps, and repeats. Batches are small and the thread yields between them, so the recorder's
/// transactions interleave. It holds only a `Weak` handle and exits when the last `Arc` is gone. Returns false if
/// the thread could not start. An in-memory store indexes inline, so only its backlog needs a synchronous pass.
/// Errors only leave search on the slower path.
fn start_text_indexer(handle: &std::sync::Arc<StoreHandle>, file_project: bool) -> bool {
    /// First batch size, adjusted to `TARGET` of lock time per batch.
    const BATCH: usize = 100;
    const TARGET: std::time::Duration = std::time::Duration::from_millis(3);
    const CYCLE: std::time::Duration = std::time::Duration::from_millis(200);
    const YIELD: std::time::Duration = std::time::Duration::from_millis(2);
    if !file_project {
        while !matches!(handle.write(|s| s.text_index_backfill(500)), Ok(true) | Err(_)) {}
        return false;
    }
    let weak = std::sync::Arc::downgrade(handle);
    let path = handle.read(|s| s.path());
    let spawned = std::thread::Builder::new().name("text-indexer".into()).spawn(move || {
        let mut last_checkpoint = std::time::Instant::now();
        let mut batch = BATCH;
        let mut checkpointer = path.as_deref().and_then(|p| match Store::open_checkpointer(p) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!("checkpoints will run on the shared write connection: {e:#}");
                None
            }
        });
        loop {
            let pause = {
                let Some(h) = weak.upgrade() else { return };
                let mut step = || -> anyhow::Result<()> {
                    // Each batch holds the write lock, so its size follows how long the last one took (debug
                    // builds and big bodies are slow): about `TARGET` of lock time, then the recorder gets a turn.
                    let timed = |batch: &mut usize, run: &dyn Fn(usize) -> anyhow::Result<usize>| {
                        let t = std::time::Instant::now();
                        let n = run(*batch)?;
                        let took = t.elapsed().as_secs_f64().max(1e-4);
                        // Only a batch that did work says how long a row takes (an idle poll takes microseconds).
                        if n > 0 {
                            *batch = ((n as f64) * TARGET.as_secs_f64() / took).clamp(5.0, 500.0) as usize;
                        }
                        Ok::<usize, anyhow::Error>(n)
                    };
                    // Checkpoints run in this thread's turn but on their own connection: a PASSIVE checkpoint
                    // takes SQLite's checkpoint lock, not its write lock, so the recorder keeps inserting while
                    // pages are copied and synced (done under the shared mutex, it stalled the recorder ~80 ms).
                    let mut checkpoint = |last: &mut std::time::Instant| -> anyhow::Result<()> {
                        if last.elapsed() >= CYCLE {
                            match checkpointer.as_mut() {
                                Some(c) => c.checkpoint_passive()?,
                                None => h.write(|s| s.checkpoint_passive())?,
                            }
                            *last = std::time::Instant::now();
                        }
                        Ok(())
                    };
                    while timed(&mut batch, &|n| h.write(|s| s.text_index_catch_up(n)))? > 0 {
                        checkpoint(&mut last_checkpoint)?;
                        std::thread::sleep(YIELD);
                    }
                    if !h.read(|s| s.text_index_complete())? {
                        loop {
                            let finished = std::cell::Cell::new(false);
                            timed(&mut batch, &|n| {
                                let done = h.write(|s| s.text_index_backfill(n))?;
                                finished.set(done);
                                Ok(if done { 0 } else { n })
                            })?;
                            if finished.get() {
                                break;
                            }
                            checkpoint(&mut last_checkpoint)?;
                            std::thread::sleep(YIELD);
                            // New traffic comes first: the tail is what searches need soonest.
                            if timed(&mut batch, &|n| h.write(|s| s.text_index_catch_up(n)))? > 0 {
                                std::thread::sleep(YIELD);
                            }
                        }
                    }
                    checkpoint(&mut last_checkpoint)
                };
                match step() {
                    Ok(()) => CYCLE,
                    Err(e) => {
                        tracing::warn!("full-text indexing failed (will retry): {e:#}");
                        std::time::Duration::from_secs(2)
                    }
                }
            }; // the Arc is released before sleeping, so a dropped Service closes its connections promptly
            std::thread::sleep(pause);
        }
    });
    match spawned {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("full-text indexer not started: {e}");
            false
        }
    }
}

impl Service {
    pub fn new(store: Store, policy: Policy) -> Result<Self> {
        Self::with_sender(store, policy, Sender::new(false)?)
    }

    pub fn with_sender(mut store: Store, policy: Policy, sender: Sender) -> Result<Self> {
        store.set_text_extractor(search::searchable);
        let file_project = store.path().is_some();
        if file_project {
            // Checkpoints happen in the indexer's turn, never inside a recorder insert (ADR-0017). Only this one
            // write connection stops auto-checkpointing, and only while the indexer thread runs (below).
            if let Err(e) = store.set_wal_autocheckpoint(false) {
                tracing::warn!("could not move WAL checkpoints to the indexer: {e}");
            }
        }
        let limits = policy.roe().limits;
        // Saved network settings apply from the start; a bad entry (say, a
        // moved certificate file) is reported but doesn't stop the project opening.
        if let Err(e) = network::sync_network(&store, sender.network()) {
            tracing::warn!("network settings not applied: {e}");
        }
        let store = std::sync::Arc::new(StoreHandle::new(store));
        if file_project && !start_text_indexer(&store, true) {
            // Nobody would checkpoint: go back to SQLite's automatic checkpoints.
            if let Err(e) = store.write(|s| s.set_wal_autocheckpoint(true)) {
                tracing::warn!("could not restore automatic WAL checkpoints: {e}");
            }
        } else if !file_project {
            start_text_indexer(&store, false);
        }
        // Exchanges committed through the shared handle (service inserts and the proxy recorder) publish one event
        // per row, in commit order. The observer only touches the bus, which never blocks.
        let bus = std::sync::Arc::new(events::Bus::new(EVENT_BUFFER));
        let observer_bus = bus.clone();
        store.set_on_exchanges(Box::new(move |rows| observer_bus.publish_exchanges(rows)));
        let svc = Self {
            limiter: RateLimiter::new(limits.max_rps_per_host, limits.max_concurrency),
            policy: std::sync::Arc::new(policy),
            store,
            sender,
            redactor: Redactor::new(),
            intercept: std::sync::OnceLock::new(),
            rewriter: std::sync::OnceLock::new(),
            roe_text: parking_lot::Mutex::new(None),
            plugins: parking_lot::RwLock::new(Vec::new()),
            plugin_home: std::sync::OnceLock::new(),
            oast_listening: std::sync::OnceLock::new(),
            smtp_listening: std::sync::OnceLock::new(),
            attacks: parking_lot::Mutex::new(Vec::new()),
            scan_tasks: parking_lot::Mutex::new(Vec::new()),
            proxy_info: std::sync::OnceLock::new(),
            listeners: std::sync::OnceLock::new(),
            session: parking_lot::Mutex::default(),
            session_lock: tokio::sync::Mutex::new(()),
            relogins: Default::default(),
            record_in_scope_only: std::sync::atomic::AtomicBool::new(false),
            bus,
        };
        svc.load_scan_tasks();
        Ok(svc)
    }

    /// The project's shared write connection (ADR-0017), for the proxy's recorder to write through
    /// (`pm_proxy::Recorder::spawn_shared`) so that recording, indexing and service writes take turns on one lock.
    /// This is wiring only: clients (API, MCP, CLI, UI) still act through `Service` methods, so every action goes
    /// through `pm-policy` (ADR-0005).
    pub fn store_handle(&self) -> std::sync::Arc<StoreHandle> {
        self.store.clone()
    }

    /// Sets the passive-check plugins to run with the passive scan. Callers
    /// pass the user's registry (`pm_plugin::Registry`), never the project's.
    pub fn set_plugins(&self, plugins: Vec<pm_plugin::Installed>) {
        *self.plugins.write() = plugins;
    }

    /// Whether content shown to this actor should have secrets replaced.
    /// Agents follow the ROE setting; humans see real values.
    pub fn redacts_for(&self, actor: &Actor) -> bool {
        actor.kind != pm_policy::ActorKind::Human && self.policy.roe().data.redact_before_llm
    }

    fn redactor_for(&self, actor: &Actor) -> Option<&Redactor> {
        self.redacts_for(actor).then_some(&self.redactor)
    }

    /// A stored result (finding, proof) as `actor` may see it: for agents,
    /// secrets in every string are replaced by placeholders and evidence
    /// fields are tagged as untrusted target content.
    pub fn json_for(&self, actor: &Actor, mut v: serde_json::Value) -> serde_json::Value {
        fn walk(v: &mut serde_json::Value, r: Option<&Redactor>, wrap: bool, key: &str) {
            match v {
                serde_json::Value::String(s) => {
                    if let Some(r) = r {
                        *s = r.redact(s);
                    }
                    if wrap && key == "evidence" && !s.is_empty() && !s.starts_with("<untrusted_target_content>") {
                        *s = pm_ai::wrap_untrusted(s);
                    }
                }
                serde_json::Value::Array(a) => a.iter_mut().for_each(|x| walk(x, r, wrap, key)),
                serde_json::Value::Object(o) => o.iter_mut().for_each(|(k, x)| walk(x, r, wrap, k)),
                _ => {}
            }
        }
        let wrap = actor.kind == pm_policy::ActorKind::Agent;
        walk(&mut v, self.redactor_for(actor), wrap, "");
        v
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Evaluates without recording anything. For "what would happen if"
    /// questions from the UI or CLI.
    pub fn dry_run(&self, req: &ActionRequest) -> Verdict {
        self.policy.evaluate(req, jiff::Timestamp::now())
    }

    fn audit(&self, actor: &str, action: &str, detail: Value, decision: &str) -> Result<()> {
        // One write closure: the read of the last record and the append must not interleave with another audit.
        // Published after the write returned, i.e. after COMMIT.
        let seq = self.store.write(|store| {
            let prev = store.last_audit()?;
            let rec = audit::next_record(prev.as_ref(), now_ms(), actor, action, &detail, decision);
            store.append_audit(&rec)?;
            Ok::<u64, anyhow::Error>(rec.seq as u64)
        })?;
        self.publish(Event::AuditAppended { seq });
        Ok(())
    }

    fn detail(req: &ActionRequest, params: &Value, verdict: &Verdict) -> Value {
        // Keep audit records small: large parameters (e.g. request bodies)
        // are cut, and the full hash is kept so they can still be matched.
        let text = params.to_string();
        let params = if text.len() > 4096 {
            let cut = text.char_indices().take_while(|(i, _)| *i < 4096).map(|(_, c)| c).collect::<String>();
            // What the action was asked to do (e.g. a scan's checks) stays whole: coverage reads it.
            let extra = params.get("extra").filter(|e| e.to_string().len() <= 4096).cloned();
            json!({ "preview": cut, "blake3": blake3_hex(&text), "extra": extra })
        } else {
            params.clone()
        };
        json!({
            "tier": req.tier,
            "target": req.target.as_ref().map(|t| format!("{}://{}:{}{}", t.scheme, t.host, t.port, t.path)),
            "summary": req.summary,
            "params": params,
            "reasons": verdict.reasons,
        })
    }

    /// Asks to run an action with these exact parameters. Always audited.
    pub fn authorize(&self, req: ActionRequest, params: &Value) -> Result<Authorization> {
        let verdict = self.policy.evaluate(&req, jiff::Timestamp::now());
        let detail = Self::detail(&req, params, &verdict);
        let actor = req.actor.id();
        let action = req.action.clone();
        let auth = match verdict.decision {
            Decision::Allow => Authorization::Allowed { reasons: verdict.reasons },
            Decision::Deny => Authorization::Denied { reasons: verdict.reasons },
            Decision::Approve => {
                let id = self.submit_approval(&req, params)?;
                Authorization::PendingApproval {
                    approval_id: id,
                    summary: req.summary.clone(),
                    reasons: verdict.reasons,
                }
            }
        };
        let decision = match &auth {
            Authorization::Allowed { .. } => "allow".to_string(),
            Authorization::Denied { .. } => "deny".to_string(),
            Authorization::PendingApproval { approval_id, .. } => format!("pending:{approval_id}"),
        };
        self.audit(&actor, &action, detail, &decision)?;
        Ok(auth)
    }
}

/// Counters the UI watches for live updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct Counters {
    pub exchanges: i64,
    pub last_exchange_id: i64,
    pub pending_approvals: usize,
    pub findings: usize,
    pub audit_records: usize,
    pub intercepted: usize,
}

impl Service {
    pub fn counters(&self) -> Result<Counters> {
        // COUNT and MAX queries only: no rows are loaded.
        self.store.read(|store| {
            Ok(Counters {
                exchanges: store.count_exchanges()?,
                last_exchange_id: store.last_exchange_id()?,
                pending_approvals: store.count_approvals(Some("pending"))? as usize,
                findings: store.count_rows("findings", None)? as usize,
                audit_records: store.last_audit_seq()? as usize,
                intercepted: self.intercept_held_count(),
            })
        })
    }

    /// Audit records, newest first.
    pub fn audit_list(&self, limit: usize) -> Result<Vec<pm_store::AuditRecord>> {
        let mut r = self.store.read(|db| db.audit_records())?;
        r.reverse();
        r.truncate(limit);
        Ok(r)
    }

    pub fn audit_verify(&self) -> Result<usize> {
        self.store.read(verify_audit)
    }

    /// The raw bytes of an exchange as text, for humans (no redaction).
    pub fn exchange_raw(&self, id: i64) -> Result<pm_store::Exchange> {
        self.store.read(|db| db.get_exchange(id))?.ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))
    }
}

fn blake3_hex(s: &str) -> String {
    pm_policy::audit::content_hash(s.as_bytes())
}

/// Checks the audit chain of a project. Returns the number of records.
pub fn verify_audit(store: &Store) -> Result<usize> {
    let records = store.audit_records()?;
    audit::verify(&records).map_err(|e| ServiceError::Store(anyhow::anyhow!(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pm_policy::{Roe, Target, Tier};

    const ROE: &str = r#"
version: 1
scope:
  include: ["https://app.example.com/"]
"#;

    fn service() -> Service {
        Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap()
    }

    fn req(actor: &str, tier: Tier, url: &str) -> ActionRequest {
        ActionRequest {
            actor: Actor::parse(actor).unwrap(),
            action: "replay_send".into(),
            tier,
            target: Some(Target::from_url(url).unwrap()),
            summary: format!("send to {url}"),
        }
    }

    #[test]
    fn approval_flow_is_enforced_and_audited() {
        let s = service();
        let params = json!({"raw": "POST /x HTTP/1.1"});
        let auth = s.authorize(req("agent:a", Tier::ActiveIntrusive, "https://app.example.com/x"), &params).unwrap();
        let Authorization::PendingApproval { approval_id, .. } = auth else { panic!("expected pending: {auth:?}") };
        let agent_a = Actor::parse("agent:a").unwrap();

        // Not approved yet.
        assert!(s.run_approved(&agent_a, "replay_send", &approval_id, &params).is_err());
        // Agents can't approve.
        assert!(s.decide_approval(&approval_id, &Actor::parse("agent:a").unwrap(), true).is_err());
        s.decide_approval(&approval_id, &Actor::parse("human:alice").unwrap(), true).unwrap();
        // Another actor, or another action, can't use it.
        assert!(s.run_approved(&Actor::parse("agent:b").unwrap(), "replay_send", &approval_id, &params).is_err());
        assert!(s.run_approved(&agent_a, "race_send", &approval_id, &params).is_err());
        // Changed parameters are not covered by the approval.
        assert!(s.run_approved(&agent_a, "replay_send", &approval_id, &json!({"raw": "DELETE /x HTTP/1.1"})).is_err());
        assert!(matches!(
            s.run_approved(&agent_a, "replay_send", &approval_id, &params).unwrap(),
            Authorization::Allowed { .. }
        ));
        // Single use.
        assert!(s.run_approved(&agent_a, "replay_send", &approval_id, &params).is_err());

        // authorize, run(not approved), decide(rejected), decide(approved), run(other actor), run(other action),
        // run(mismatch), run(ok), run(used)
        assert_eq!(s.store.read(verify_audit).unwrap(), 9);
    }

    #[test]
    fn agent_results_are_redacted_and_tagged() {
        let s = service();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";
        let v = json!({ "evidence": format!("token {jwt}"), "proofs": [{ "note": jwt }], "id": 3 });
        let agent = s.json_for(&Actor::parse("agent:a").unwrap(), v.clone());
        let text = agent.to_string();
        assert!(!text.contains(jwt), "{text}");
        assert!(agent["evidence"].as_str().unwrap().starts_with("<untrusted_target_content>"));
        assert_eq!(s.json_for(&Actor::parse("agent:a").unwrap(), agent.clone()), agent, "applied once");
        assert_eq!(s.json_for(&Actor::parse("human:h").unwrap(), v.clone()), v);
    }

    #[test]
    fn denials_are_audited_too() {
        let s = service();
        let auth = s.authorize(req("agent:a", Tier::ActiveSafe, "https://evil.com/"), &json!({})).unwrap();
        assert!(matches!(auth, Authorization::Denied { .. }));
        let auth = s.authorize(req("agent:a", Tier::Destructive, "https://app.example.com/x"), &json!({})).unwrap();
        assert!(matches!(auth, Authorization::Denied { .. }));
        let records = s.store.read(|db| db.audit_records()).unwrap();
        assert_eq!(records.iter().map(|r| r.decision.as_str()).collect::<Vec<_>>(), ["deny", "deny"]);
    }

    #[test]
    fn direct_file_tampering_is_detected() {
        let path = std::env::temp_dir().join(format!("pm-service-tamper-{}.pmproj", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let s = Service::new(Store::open(&path).unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap();
            for url in ["https://app.example.com/a", "https://evil.com/", "https://app.example.com/b"] {
                s.authorize(req("agent:a", Tier::ActiveSafe, url), &json!({})).unwrap();
            }
            assert_eq!(s.store.read(verify_audit).unwrap(), 3);
        }
        // Someone edits the file outside ProxyMind: removes the guard
        // triggers and flips the denial to an allow.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("DROP TRIGGER audit_log_no_update; UPDATE audit_log SET decision = 'allow' WHERE seq = 2;")
            .unwrap();
        drop(conn);
        let err = verify_audit(&Store::open(&path).unwrap()).unwrap_err().to_string();
        assert!(err.contains("record 2"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn approvals_are_shared_between_processes() {
        let path = std::env::temp_dir().join(format!("pm-service-shared-{}.pmproj", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let open = || Service::new(Store::open(&path).unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap();
        let (mcp, cli) = (open(), open());
        let params = json!({"raw": "POST /x"});
        let auth = mcp.authorize(req("agent:a", Tier::ActiveIntrusive, "https://app.example.com/x"), &params).unwrap();
        let Authorization::PendingApproval { approval_id, .. } = auth else { panic!("{auth:?}") };

        assert_eq!(cli.approvals(Some("pending"), 10).unwrap()[0].id, approval_id);
        cli.decide_approval(&approval_id, &Actor::parse("human:omkar").unwrap(), true).unwrap();
        assert!(cli.decide_approval(&approval_id, &Actor::parse("human:other").unwrap(), false).is_err());
        assert!(matches!(
            mcp.run_approved(&Actor::parse("agent:a").unwrap(), "replay_send", &approval_id, &params).unwrap(),
            Authorization::Allowed { .. }
        ));
        assert_eq!(cli.approval(&approval_id).unwrap().unwrap().status, "used");
        drop((mcp, cli));
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
    }
}
