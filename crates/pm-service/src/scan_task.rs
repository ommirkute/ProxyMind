//! Crawl and audit as one background task: crawl from a start URL, then run
//! the active scanner over each operation recorded for that origin (the
//! same selection as the automatic sweep), with live progress. Every crawl
//! and scan still goes through the gate; strong issues are recorded as
//! suspected findings.
//!
//! Tasks are saved in the project (`scan_tasks`) after each operation, so a
//! paused task, or one that was running when ProxyMind stopped, resumes
//! where it left off: operations already scanned are skipped.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pm_policy::{Actor, ActorKind};
use serde::{Deserialize, Serialize};

use crate::{
    ActiveFinding, ActiveScanRequest, ActiveScanResult, CrawlRequest, CrawlResult, Result, Service, ServiceError,
};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanTaskRequest {
    /// Where to start, e.g. https://app.example.com/ (its origin is audited).
    pub url: String,
    /// A scan profile (light, default, thorough, api-only or a saved one)
    /// that fills in the settings left out here.
    pub profile: Option<String>,
    /// Crawl first (default true); without it, only what history holds.
    pub crawl: Option<bool>,
    /// Most pages to crawl (default 30, max 500).
    pub max_pages: Option<usize>,
    /// Crawl in a headless browser that runs the app's JavaScript (default:
    /// yes when a Chromium is installed).
    pub browser: Option<bool>,
    /// Most operations to scan (default 30, max 200).
    pub max_targets: Option<usize>,
    /// Most requests per operation (default 150, max 2000).
    pub max_requests: Option<usize>,
    /// Checks to run (default all; submissions only get stored_xss and csrf).
    pub checks: Vec<String>,
    /// Record strong issues as suspected findings (default true).
    pub record_findings: Option<bool>,
    pub identity: Option<String>,
    /// Approval for the crawl, if the gate asked for one.
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTaskStatus {
    Crawling,
    Auditing,
    /// Stopped part way; `scan_task_resume` continues it.
    Paused,
    Done,
    Cancelled,
    Failed,
}

impl ScanTaskStatus {
    pub fn running(self) -> bool {
        matches!(self, Self::Crawling | Self::Auditing)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Crawling => "crawling",
            Self::Auditing => "auditing",
            Self::Paused => "paused",
            Self::Done => "done",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

/// One issue a task found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTaskIssue {
    pub operation: String,
    pub check: String,
    pub title: String,
    pub severity: String,
    pub point: String,
    pub payload: String,
    /// What was seen (from the target: untrusted).
    pub evidence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prove_with: Option<String>,
    pub exchange_id: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<i64>,
}

impl ScanTaskIssue {
    fn new(operation: &str, f: ActiveFinding, finding_id: Option<i64>) -> Self {
        let i = f.issue;
        Self {
            operation: operation.to_string(),
            check: i.check.into(),
            title: i.title.into(),
            severity: i.severity.into(),
            point: i.point,
            payload: i.payload,
            evidence: i.evidence,
            prove_with: i.prove_with,
            exchange_id: f.exchange_id,
            finding_id,
        }
    }
}

/// A task's progress and issues so far.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTaskView {
    pub task_id: String,
    pub url: String,
    pub actor: String,
    pub created_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// The schedule that started it, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule_id: Option<i64>,
    pub status: ScanTaskStatus,
    pub pages_crawled: usize,
    pub targets_total: usize,
    pub targets_done: usize,
    pub requests: usize,
    /// Times the identity looked logged out and was logged in again.
    #[serde(default)]
    pub relogins: usize,
    /// The operation being scanned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    pub issues: Vec<ScanTaskIssue>,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// What a task needs to carry on after a pause or a restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Progress {
    request: ScanTaskRequest,
    /// Operations already scanned.
    done: Vec<String>,
    crawled: bool,
}

#[derive(Serialize, Deserialize)]
struct Saved {
    view: ScanTaskView,
    progress: Progress,
}

pub(crate) struct ScanTask {
    id: String,
    actor: String,
    cancelled: AtomicBool,
    paused: AtomicBool,
    view: parking_lot::Mutex<ScanTaskView>,
    progress: parking_lot::Mutex<Progress>,
}

/// Tasks kept in memory and loaded when a project opens.
const KEEP_TASKS: usize = 20;

/// A running task is saved at least this often, so other processes that
/// open the project can tell it is still running.
const HEARTBEAT_MS: i64 = 20_000;

impl ScanTask {
    fn update(&self, f: impl FnOnce(&mut ScanTaskView)) {
        f(&mut self.view.lock());
    }

    fn note(&self, n: String) {
        self.update(|v| {
            if !v.notes.contains(&n) {
                v.notes.push(n);
            }
        });
    }

    fn stopping(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed) || self.paused.load(Ordering::Relaxed)
    }
}

impl Service {
    /// Starts a crawl-and-audit task in the background; poll it with
    /// `scan_task_status`.
    pub fn scan_task_start(self: &Arc<Self>, actor: &Actor, req: ScanTaskRequest) -> Result<ScanTaskView> {
        self.scan_task_start_from(actor, req, None)
    }

    pub(crate) fn scan_task_start_from(
        self: &Arc<Self>,
        actor: &Actor,
        mut req: ScanTaskRequest,
        schedule_id: Option<i64>,
    ) -> Result<ScanTaskView> {
        crate::replay::parse_url_endpoint(&req.url)?;
        if let Some(name) = req.profile.clone().filter(|p| !p.trim().is_empty()) {
            let p = self.scan_profile(&name)?;
            p.apply(&mut req);
            req.profile = Some(p.name);
        }
        let known = |c: &str| pm_scan::active::CHECKS.contains(&c) || pm_scan::oob::CHECKS.contains(&c);
        if let Some(bad) = req.checks.iter().find(|c| !known(c)) {
            return Err(ServiceError::Invalid(format!("unknown check {bad}")));
        }
        let task = Arc::new(ScanTask {
            id: pm_oast::new_token()[..12].to_string(),
            actor: actor.id(),
            cancelled: AtomicBool::new(false),
            paused: AtomicBool::new(false),
            view: parking_lot::Mutex::new(ScanTaskView {
                task_id: String::new(),
                url: req.url.clone(),
                actor: actor.id(),
                created_ms: pm_core::now_ms(),
                profile: req.profile.clone(),
                schedule_id,
                status: if req.crawl.unwrap_or(true) { ScanTaskStatus::Crawling } else { ScanTaskStatus::Auditing },
                pages_crawled: 0,
                targets_total: 0,
                targets_done: 0,
                requests: 0,
                relogins: 0,
                current: None,
                issues: Vec::new(),
                notes: Vec::new(),
                error: None,
            }),
            progress: parking_lot::Mutex::new(Progress { request: req, done: Vec::new(), crawled: false }),
        });
        task.update(|v| v.task_id = task.id.clone());
        self.keep_task(task.clone());
        self.save_task(&task);
        self.spawn_task(task.clone(), actor.clone());
        Ok(task.view.lock().clone())
    }

    fn keep_task(&self, task: Arc<ScanTask>) {
        let mut tasks = self.scan_tasks.lock();
        tasks.push(task);
        while tasks.len() > KEEP_TASKS {
            match tasks.iter().position(|t| !t.view.lock().status.running()) {
                Some(i) => tasks.remove(i),
                None => break,
            };
        }
    }

    /// Writes the task to the project (errors are logged: progress isn't
    /// worth stopping a scan for).
    fn save_task(&self, task: &ScanTask) {
        let view = task.view.lock().clone();
        let saved = Saved { view, progress: task.progress.lock().clone() };
        let row = pm_store::ScanTaskRow {
            id: task.id.clone(),
            actor: task.actor.clone(),
            status: saved.view.status.as_str().into(),
            data: serde_json::to_string(&saved).unwrap_or_default(),
            created_ms: saved.view.created_ms,
            updated_ms: pm_core::now_ms(),
        };
        if let Err(e) = self.store.lock().upsert_scan_task(&row) {
            tracing::warn!(task = %task.id, error = %e, "scan task not saved");
        }
    }

    /// Loads recent tasks when the project opens. Tasks that were running
    /// when ProxyMind stopped come back paused.
    pub(crate) fn load_scan_tasks(&self) {
        let rows = match self.store.lock().list_scan_tasks(KEEP_TASKS) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("scan tasks not loaded: {e}");
                return;
            }
        };
        let mut loaded = Vec::new();
        for row in rows.into_iter().rev() {
            let Ok(saved) = serde_json::from_str::<Saved>(&row.data) else { continue };
            let task = Arc::new(ScanTask {
                id: row.id,
                actor: row.actor,
                cancelled: AtomicBool::new(false),
                paused: AtomicBool::new(false),
                view: parking_lot::Mutex::new(saved.view),
                progress: parking_lot::Mutex::new(saved.progress),
            });
            let running = task.view.lock().status.running();
            if running && pm_core::now_ms() - row.updated_ms < 3 * HEARTBEAT_MS {
                // Another ProxyMind process (the UI server, the desktop app)
                // is running it right now: leave it alone.
                task.note("running in another ProxyMind process".into());
            } else if running {
                task.update(|v| {
                    v.status = ScanTaskStatus::Paused;
                    v.current = None;
                });
                task.note("interrupted: ProxyMind stopped while this ran; resume to continue".into());
                self.save_task(&task);
            }
            loaded.push(task);
        }
        *self.scan_tasks.lock() = loaded;
    }

    fn spawn_task(self: &Arc<Self>, task: Arc<ScanTask>, actor: Actor) {
        let svc = self.clone();
        let heartbeat = {
            let (svc, task) = (self.clone(), task.clone());
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(HEARTBEAT_MS as u64)).await;
                    if !task.view.lock().status.running() {
                        break;
                    }
                    svc.save_task(&task);
                }
            })
        };
        tokio::spawn(async move {
            let r = svc.scan_task_run(&actor, &task).await;
            heartbeat.abort();
            task.update(|v| {
                v.current = None;
                match r {
                    Err(e) => {
                        v.status = ScanTaskStatus::Failed;
                        v.error = Some(e.to_string());
                    }
                    Ok(()) if v.status != ScanTaskStatus::Failed => {
                        v.status = if task.cancelled.load(Ordering::Relaxed) {
                            ScanTaskStatus::Cancelled
                        } else if task.paused.load(Ordering::Relaxed) {
                            ScanTaskStatus::Paused
                        } else {
                            ScanTaskStatus::Done
                        };
                    }
                    Ok(()) => {}
                }
            });
            svc.save_task(&task);
        });
    }

    async fn scan_task_run(&self, actor: &Actor, task: &ScanTask) -> Result<()> {
        let (req, crawled) = {
            let p = task.progress.lock();
            (p.request.clone(), p.crawled)
        };
        let endpoint = crate::replay::parse_url_endpoint(&req.url)?;
        let origin = pm_core::url(&endpoint.scheme, &endpoint.host, endpoint.port, "");
        let origin = origin.as_str();
        if req.crawl.unwrap_or(true) && !crawled {
            let have_browser = pm_browser::find_chromium().is_some();
            if req.browser == Some(true) && !have_browser {
                task.note("no Chromium found: crawled links only, without running the app's JavaScript".into());
            }
            let crawl = CrawlRequest {
                url: req.url.clone(),
                max_pages: Some(req.max_pages.unwrap_or(30).clamp(1, 500)),
                identity: req.identity.clone(),
                approval_id: req.approval_id.clone(),
                // Run the app's JavaScript when a browser is there, unless asked not to.
                browser: Some(req.browser.unwrap_or(true) && have_browser),
                ..Default::default()
            };
            match self.crawl(actor, crawl).await? {
                CrawlResult::Done { pages, .. } => task.update(|v| v.pages_crawled = pages.len()),
                CrawlResult::PendingApproval { approval_id, .. } => {
                    task.update(|v| {
                        v.status = ScanTaskStatus::Failed;
                        v.error = Some(format!(
                            "the crawl needs approval {approval_id}: approve it, then start again with that approval_id"
                        ));
                    });
                    return Ok(());
                }
                CrawlResult::Denied { reasons } => {
                    task.update(|v| {
                        v.status = ScanTaskStatus::Failed;
                        v.error = Some(format!("the crawl was denied: {}", reasons.join("; ")));
                    });
                    return Ok(());
                }
            }
            task.progress.lock().crawled = true;
            self.save_task(task);
        }
        if task.stopping() {
            return Ok(());
        }
        let max_targets = req.max_targets.unwrap_or(30).clamp(1, 200);
        let mut targets = self.scan_targets(Some(origin), max_targets, max_targets / 2 + 1, 10)?;
        // Every check on GETs (only strong ones become findings); submissions
        // only get the checks made for them, since each probe re-sends them.
        let all: Vec<String> = pm_scan::active::CHECKS
            .iter()
            .chain(pm_scan::oob::CHECKS)
            .map(|c| c.to_string())
            // The approval-only checks run when asked for by name.
            .filter(|c| {
                if req.checks.is_empty() {
                    !pm_scan::active::APPROVAL_CHECKS.contains(&c.as_str())
                } else {
                    req.checks.contains(c)
                }
            })
            .collect();
        for t in &mut targets {
            if t.submission {
                t.checks.retain(|c| all.contains(c));
            } else {
                t.checks = all
                    .iter()
                    .filter(|c| {
                        !matches!(
                            c.as_str(),
                            "stored_xss"
                                | "csrf"
                                | "mass_assignment"
                                | "proto_pollution"
                                | "file_upload"
                                | "race_condition"
                        )
                    })
                    .cloned()
                    .collect();
            }
        }
        targets.retain(|t| !t.checks.is_empty());
        targets.truncate(max_targets);
        let done: Vec<String> = task.progress.lock().done.clone();
        let skipped = targets.iter().filter(|t| done.contains(&t.operation)).count();
        task.update(|v| {
            v.status = ScanTaskStatus::Auditing;
            v.targets_total = targets.len();
            v.targets_done = skipped;
        });
        if skipped > 0 {
            task.note(format!("resumed: skipped {skipped} operation(s) already scanned"));
        }
        if targets.is_empty() {
            task.note(format!("nothing recorded for {origin} to scan: browse or crawl it first"));
        }
        self.save_task(task);
        let start_relogins = req.identity.as_deref().map(|i| self.relogins(i)).unwrap_or_default();
        let base_relogins = task.view.lock().relogins;
        for t in targets.iter().filter(|t| !done.contains(&t.operation)) {
            if task.stopping() {
                break;
            }
            if let Some(name) = req.identity.as_deref() {
                let now = self.relogins(name);
                task.update(|v| v.relogins = base_relogins + now.ok - start_relogins.ok);
                // Scanning logged out finds nothing and looks clean: stop instead.
                if now.failed - start_relogins.failed >= 2 && now.failed_in_row >= 2 {
                    return Err(ServiceError::Invalid(format!(
                        "session lost: {name} looked logged out and logging in again failed twice; fix its login \
                         (proxymind identity check {name}) and resume the scan"
                    )));
                }
            }
            task.update(|v| v.current = Some(t.operation.clone()));
            let r = self
                .scan_active(
                    actor,
                    ActiveScanRequest {
                        exchange_id: t.exchange_id,
                        checks: t.checks.clone(),
                        max_requests: Some(req.max_requests.unwrap_or(150)),
                        oob_wait_seconds: Some(3),
                        identity: req.identity.clone(),
                        ..Default::default()
                    },
                )
                .await;
            match r {
                Ok(ActiveScanResult::Done { requests, issues, notes, .. }) => {
                    let leads = if req.record_findings.unwrap_or(true) {
                        self.record_scan_leads(actor, t, &issues)?
                    } else {
                        Vec::new()
                    };
                    for n in notes.into_iter().filter(|n| !n.starts_with("none of the requested")) {
                        task.note(n);
                    }
                    task.update(|v| {
                        v.requests += requests;
                        for f in issues {
                            let finding_id = leads.iter().find(|l| l.check == f.issue.check).map(|l| l.finding_id);
                            v.issues.push(ScanTaskIssue::new(&t.operation, f, finding_id));
                        }
                    });
                }
                Ok(ActiveScanResult::PendingApproval { approval_id, .. }) => {
                    task.note(format!("{}: needs approval {approval_id}", t.operation));
                }
                Ok(ActiveScanResult::Denied { reasons }) => {
                    task.note(format!("{}: denied ({})", t.operation, reasons.join("; ")));
                }
                // No insertion points, or the example vanished: nothing to scan.
                Err(_) => {}
            }
            task.update(|v| v.targets_done += 1);
            task.progress.lock().done.push(t.operation.clone());
            self.save_task(task);
        }
        if let Some(name) = req.identity.as_deref() {
            let n = self.relogins(name).ok - start_relogins.ok;
            task.update(|v| v.relogins = base_relogins + n);
            if n > 0 {
                task.note(format!("{name} looked logged out {n} time(s) and was logged in again"));
            }
        }
        Ok(())
    }

    fn scan_task(&self, actor: &Actor, id: &str) -> Result<Arc<ScanTask>> {
        let t = self
            .scan_tasks
            .lock()
            .iter()
            .find(|t| t.id == id)
            .cloned()
            .ok_or_else(|| ServiceError::NotFound(format!("scan task {id}")))?;
        // People see every task; agents and plugins only their own.
        if actor.kind != ActorKind::Human && t.actor != actor.id() {
            return Err(ServiceError::NotFound(format!("scan task {id}")));
        }
        Ok(t)
    }

    pub fn scan_task_status(&self, actor: &Actor, id: &str) -> Result<ScanTaskView> {
        let mut v = self.scan_task(actor, id)?.view.lock().clone();
        if actor.kind == ActorKind::Agent {
            for i in &mut v.issues {
                i.evidence = pm_ai::wrap_untrusted(&i.evidence);
            }
        }
        Ok(v)
    }

    /// Stops the task after the operation being scanned.
    pub fn scan_task_cancel(&self, actor: &Actor, id: &str) -> Result<ScanTaskView> {
        let t = self.scan_task(actor, id)?;
        t.cancelled.store(true, Ordering::Relaxed);
        if t.view.lock().status == ScanTaskStatus::Paused {
            t.update(|v| v.status = ScanTaskStatus::Cancelled);
            self.save_task(&t);
        }
        Ok(t.view.lock().clone())
    }

    /// Pauses the task after the operation being scanned; resume continues
    /// with the operations not yet scanned.
    pub fn scan_task_pause(&self, actor: &Actor, id: &str) -> Result<ScanTaskView> {
        let t = self.scan_task(actor, id)?;
        if !t.view.lock().status.running() {
            return Err(ServiceError::Invalid(format!("scan task {id} isn't running")));
        }
        t.paused.store(true, Ordering::Relaxed);
        t.note("pausing after the current operation".into());
        Ok(t.view.lock().clone())
    }

    /// Continues a paused, cancelled or failed task as the actor that
    /// started it, skipping the operations it already scanned.
    pub fn scan_task_resume(self: &Arc<Self>, actor: &Actor, id: &str) -> Result<ScanTaskView> {
        let t = self.scan_task(actor, id)?;
        let status = t.view.lock().status;
        if status.running() || status == ScanTaskStatus::Done {
            return Err(ServiceError::Invalid(format!("scan task {id} is {}; nothing to resume", status.as_str())));
        }
        let owner = Actor::parse(&t.actor).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        t.cancelled.store(false, Ordering::Relaxed);
        t.paused.store(false, Ordering::Relaxed);
        let (crawl, crawled) = {
            let p = t.progress.lock();
            (p.request.crawl.unwrap_or(true), p.crawled)
        };
        t.update(|v| {
            v.status = if crawl && !crawled { ScanTaskStatus::Crawling } else { ScanTaskStatus::Auditing };
            v.error = None;
            v.notes.retain(|n| n != "pausing after the current operation");
        });
        self.save_task(&t);
        self.audit(&actor.id(), "scan_task_resume", serde_json::json!({ "task": id }), "allow")?;
        self.spawn_task(t.clone(), owner);
        Ok(t.view.lock().clone())
    }

    /// Recent tasks, newest first (issues left out; see `scan_task_status`).
    pub fn scan_task_list(&self, actor: &Actor) -> Vec<ScanTaskView> {
        self.scan_tasks
            .lock()
            .iter()
            .rev()
            .filter(|t| actor.kind == ActorKind::Human || t.actor == actor.id())
            .map(|t| {
                let mut v = t.view.lock().clone();
                v.issues.clear();
                v
            })
            .collect()
    }

    /// Whether the task is still crawling or auditing.
    pub(crate) fn scan_task_running(&self, id: &str) -> bool {
        self.scan_tasks.lock().iter().any(|t| t.id == id && t.view.lock().status.running())
    }
}
