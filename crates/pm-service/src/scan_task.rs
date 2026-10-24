//! Crawl and audit as one background task: crawl from a start URL, then run
//! the active scanner over each operation recorded for that origin (the
//! same selection as the automatic sweep), with live progress. Every crawl
//! and scan still goes through the gate; strong issues are recorded as
//! suspected findings.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTaskStatus {
    Crawling,
    Auditing,
    Done,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanTaskIssue {
    pub operation: String,
    #[serde(flatten)]
    pub finding: ActiveFinding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<i64>,
}

/// A task's progress and issues so far.
#[derive(Debug, Clone, Serialize)]
pub struct ScanTaskView {
    pub task_id: String,
    pub url: String,
    pub actor: String,
    pub created_ms: i64,
    pub status: ScanTaskStatus,
    pub pages_crawled: usize,
    pub targets_total: usize,
    pub targets_done: usize,
    pub requests: usize,
    /// The operation being scanned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    pub issues: Vec<ScanTaskIssue>,
    pub notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub(crate) struct ScanTask {
    id: String,
    actor: String,
    cancelled: AtomicBool,
    view: parking_lot::Mutex<ScanTaskView>,
}

/// Tasks kept in memory (their requests and findings are stored either way).
const KEEP_TASKS: usize = 20;

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
}

impl Service {
    /// Starts a crawl-and-audit task in the background; poll it with
    /// `scan_task_status`.
    pub fn scan_task_start(self: &Arc<Self>, actor: &Actor, req: ScanTaskRequest) -> Result<ScanTaskView> {
        let endpoint = crate::replay::parse_url_endpoint(&req.url)?;
        let known = |c: &str| pm_scan::active::CHECKS.contains(&c) || pm_scan::oob::CHECKS.contains(&c);
        if let Some(bad) = req.checks.iter().find(|c| !known(c)) {
            return Err(ServiceError::Invalid(format!("unknown check {bad}")));
        }
        let task = Arc::new(ScanTask {
            id: pm_oast::new_token()[..12].to_string(),
            actor: actor.id(),
            cancelled: AtomicBool::new(false),
            view: parking_lot::Mutex::new(ScanTaskView {
                task_id: String::new(),
                url: req.url.clone(),
                actor: actor.id(),
                created_ms: pm_core::now_ms(),
                status: if req.crawl.unwrap_or(true) { ScanTaskStatus::Crawling } else { ScanTaskStatus::Auditing },
                pages_crawled: 0,
                targets_total: 0,
                targets_done: 0,
                requests: 0,
                current: None,
                issues: Vec::new(),
                notes: Vec::new(),
                error: None,
            }),
        });
        task.update(|v| v.task_id = task.id.clone());
        {
            let mut tasks = self.scan_tasks.lock();
            tasks.push(task.clone());
            let running =
                |t: &Arc<ScanTask>| matches!(t.view.lock().status, ScanTaskStatus::Crawling | ScanTaskStatus::Auditing);
            while tasks.len() > KEEP_TASKS {
                match tasks.iter().position(|t| !running(t)) {
                    Some(i) => tasks.remove(i),
                    None => break,
                };
            }
        }
        let origin = pm_core::url(&endpoint.scheme, &endpoint.host, endpoint.port, "");
        let (svc, actor2, t2) = (self.clone(), actor.clone(), task.clone());
        tokio::spawn(async move {
            let r = svc.scan_task_run(&actor2, &req, &origin, &t2).await;
            t2.update(|v| {
                v.current = None;
                match r {
                    Err(e) => {
                        v.status = ScanTaskStatus::Failed;
                        v.error = Some(e.to_string());
                    }
                    Ok(()) if v.status != ScanTaskStatus::Failed => {
                        v.status = if t2.cancelled.load(Ordering::Relaxed) {
                            ScanTaskStatus::Cancelled
                        } else {
                            ScanTaskStatus::Done
                        };
                    }
                    Ok(()) => {}
                }
            });
        });
        Ok(task.view.lock().clone())
    }

    async fn scan_task_run(&self, actor: &Actor, req: &ScanTaskRequest, origin: &str, task: &ScanTask) -> Result<()> {
        if req.crawl.unwrap_or(true) {
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
        }
        if task.cancelled.load(Ordering::Relaxed) {
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
        task.update(|v| {
            v.status = ScanTaskStatus::Auditing;
            v.targets_total = targets.len();
        });
        if targets.is_empty() {
            task.note(format!("nothing recorded for {origin} to scan: browse or crawl it first"));
        }
        for t in &targets {
            if task.cancelled.load(Ordering::Relaxed) {
                break;
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
                            v.issues.push(ScanTaskIssue { operation: t.operation.clone(), finding: f, finding_id });
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
                i.finding.issue.evidence = pm_ai::wrap_untrusted(&i.finding.issue.evidence);
            }
        }
        Ok(v)
    }

    /// Stops the task after the operation being scanned.
    pub fn scan_task_cancel(&self, actor: &Actor, id: &str) -> Result<ScanTaskView> {
        let t = self.scan_task(actor, id)?;
        t.cancelled.store(true, Ordering::Relaxed);
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
}
