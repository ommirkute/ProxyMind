//! Workflows in the service layer (roadmap 2.2): saving, running and watching them.
//!
//! - **Storage.** Definitions are one project setting (`workflows`, a JSON list: small, edited by people, saved as a
//!   whole like session rules and custom checks, no migration). Runs are rows in `workflow_runs` (migration 24):
//!   they pile up, they must survive a restart, and a run that paused for an approval is resumed from its row.
//! - **Who.** People create, edit, delete and switch triggers (all audited; an agent's attempt is audited as a
//!   denial). Agents may list, read and run workflows, and read runs; what they read hides secrets typed into
//!   request templates and variable values.
//! - **Sends.** Every send step is one gated send: `gate_send_with` with action `workflow_send` (scope, tier from
//!   the method and the payload classifier, approvals, rate limits, DNS check, identity, audit), recorded in history
//!   with source `workflow`. A send that needs an approval pauses the run; the approval covers those exact bytes, and
//!   running again with `approval_id` continues from that step with the saved variables instead of sending earlier
//!   steps twice.
//! - **Triggers.** [`Service::run_workflow_triggers`] listens to the event bus (ADR-0018) for newly recorded
//!   proxied exchanges. The proxy only publishes an event after the exchange is committed and never waits for this
//!   task, so a trigger cannot delay traffic. Matching, rate caps and the runs themselves happen here.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pm_policy::{Actor, ActorKind, Target};
use pm_store::{NewWorkflowRun, Store, WorkflowRunRow};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::events::{Delivery, Event, Rate};
use crate::workflow::{
    self, Current, Host, MAX_RUN_SECS, MAX_TRIGGER_RATE, MAX_WORKFLOWS, Resume, RunStatus, SendOutcome, SendRequest,
    StepStatus, Trigger, WORKFLOWS_SETTING, Workflow, WorkflowInput, WorkflowRun,
};
use crate::{Authorization, Result, Service, ServiceError, now_ms};

/// Runs kept in the project (the newest).
pub const KEEP_RUNS: usize = 200;
/// A run paused for an approval can be continued for this long.
const PAUSE_TTL_MS: i64 = 24 * 3600 * 1000;
/// Per-exchange runs going at once; exchanges that arrive while all are busy are skipped.
const MAX_TRIGGER_RUNS: usize = 4;
/// Exchanges checked against triggers at once; the rest are skipped (best effort, never a queue).
const MAX_TRIGGER_CHECKS: usize = 8;
/// How long the list of workflows with a trigger is reused before the project is read again.
const TRIGGER_CACHE: Duration = Duration::from_secs(1);

/// A workflow to run, by id or name. `approval_id` continues a run that paused for an approval.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
// `default` makes every field optional to serde; the schema still lists what a call needs.
#[schemars(extend("required" = ["workflow"]))]
pub struct WorkflowRunRequest {
    /// The workflow's name or id (from workflow_list).
    pub workflow: String,
    /// Run it on this recorded exchange: the first steps read it and a send without a template resends it. Leave it
    /// out only when the workflow's first step is a send with its own url and request.
    pub exchange_id: Option<i64>,
    /// Continue a run that is waiting for this approval. Give the same `workflow` and `exchange_id` as before.
    pub approval_id: Option<String>,
}

/// One row of the workflow list for agents: what a workflow is for, without its steps' details.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct WorkflowSummary {
    pub id: i64,
    pub name: String,
    pub description: String,
    /// The kinds of its steps, in order.
    pub steps: Vec<String>,
    /// Whether it runs by itself on new proxied exchanges.
    pub trigger_enabled: bool,
    pub updated_by: String,
}

/// What a fuzzer result got from the workflow attached to the attack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FuzzerWorkflow {
    pub run_id: i64,
    pub status: RunStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The run's variables (hidden or marked as target content for agents): what the workflow extracted from this
    /// result's response.
    pub variables: BTreeMap<String, String>,
}

/// In-memory state of the per-exchange triggers.
#[derive(Default)]
pub(crate) struct Runtime {
    cache: Option<(Instant, Arc<Vec<Workflow>>)>,
    windows: HashMap<i64, VecDeque<Instant>>,
    skipped: HashMap<i64, u64>,
    running: usize,
    checking: usize,
}

fn people_only(actor: &Actor) -> bool {
    actor.kind == ActorKind::Human
}

fn load(store: &Store) -> Result<Vec<Workflow>> {
    match store.get_setting(WORKFLOWS_SETTING)? {
        Some(t) => serde_json::from_str(&t)
            .map_err(|e| ServiceError::Invalid(format!("the saved workflows are unreadable: {e}"))),
        None => Ok(vec![]),
    }
}

fn save(store: &mut Store, list: &[Workflow]) -> Result<()> {
    let text = serde_json::to_string(list).map_err(|e| ServiceError::Invalid(e.to_string()))?;
    store.set_setting(WORKFLOWS_SETTING, &text)?;
    Ok(())
}

fn find<'a>(list: &'a [Workflow], key: &str) -> Option<&'a Workflow> {
    let key = key.trim();
    match key.parse::<i64>() {
        Ok(id) => list.iter().find(|w| w.id == id),
        Err(_) => list.iter().find(|w| w.name.eq_ignore_ascii_case(key)),
    }
}

/// Names that hide a value from agents even when it is short.
fn secretish(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "token", "secret", "pass", "key", "session", "auth", "jwt", "csrf", "xsrf", "cookie", "bearer", "sid", "otp",
        "code",
    ]
    .iter()
    .any(|w| n.contains(w))
}

fn row_to_run(row: &WorkflowRunRow) -> Result<WorkflowRun> {
    let mut run: WorkflowRun = serde_json::from_str(&row.record)
        .map_err(|e| ServiceError::Invalid(format!("run {} is unreadable: {e}", row.id)))?;
    // The columns are the truth for what changes after the record was written.
    run.id = row.id;
    Ok(run)
}

fn from_exchange(ex: pm_store::Exchange) -> Current {
    Current { summary: ex.summary, request: ex.request, response: ex.response }
}

fn state_of(run: &WorkflowRun) -> String {
    run.status.as_str().into()
}

impl Service {
    // ---- definitions ------------------------------------------------------

    fn workflow_deny(&self, actor: &Actor, action: &str, what: &str) -> ServiceError {
        let _ = self.audit(&actor.id(), action, json!({ "workflow": what }), "deny");
        ServiceError::Invalid("only people can create, change or delete workflows and switch their triggers".into())
    }

    fn workflow_invalidate(&self) {
        self.workflows.lock().cache = None;
    }

    fn workflow_view(&self, actor: &Actor, mut w: Workflow) -> Workflow {
        w.trigger.skipped = self.workflows.lock().skipped.get(&w.id).copied().unwrap_or(0);
        if people_only(actor) { w } else { w.for_agent() }
    }

    /// The saved workflows. For agents, secrets typed into request templates are hidden.
    pub fn workflow_list(&self, actor: &Actor) -> Result<Vec<Workflow>> {
        let list = self.store.read(load)?;
        Ok(list.into_iter().map(|w| self.workflow_view(actor, w)).collect())
    }

    pub fn workflow_summaries(&self, actor: &Actor) -> Result<Vec<WorkflowSummary>> {
        let _ = actor;
        Ok(self
            .store
            .read(load)?
            .into_iter()
            .map(|w| WorkflowSummary {
                id: w.id,
                name: w.name,
                description: w.description,
                steps: w.steps.iter().map(|s| s.kind().to_string()).collect(),
                trigger_enabled: w.trigger.enabled,
                updated_by: w.updated_by,
            })
            .collect())
    }

    fn workflow_find(&self, key: &str) -> Result<Workflow> {
        let list = self.store.read(load)?;
        find(&list, key).cloned().ok_or_else(|| ServiceError::NotFound(format!("workflow {key}")))
    }

    pub fn workflow_get(&self, actor: &Actor, key: &str) -> Result<Workflow> {
        Ok(self.workflow_view(actor, self.workflow_find(key)?))
    }

    /// Saves a new workflow. People only; audited.
    pub fn workflow_create(&self, actor: &Actor, input: WorkflowInput) -> Result<Workflow> {
        if !people_only(actor) {
            return Err(self.workflow_deny(actor, "workflow_save", &input.name));
        }
        let wf = self.store.write(|db| -> Result<Workflow> {
            let mut list = load(db)?;
            if list.len() >= MAX_WORKFLOWS {
                return Err(ServiceError::Invalid(format!("a project holds at most {MAX_WORKFLOWS} workflows")));
            }
            let wf = Workflow {
                id: list.iter().map(|w| w.id).max().unwrap_or(0) + 1,
                name: input.name.trim().to_string(),
                description: input.description,
                steps: input.steps,
                trigger: Trigger::default(),
                updated_by: actor.id(),
                updated_ms: now_ms(),
            };
            wf.validate().map_err(ServiceError::Invalid)?;
            if list.iter().any(|w| w.name.eq_ignore_ascii_case(&wf.name)) {
                return Err(ServiceError::Invalid(format!("there is already a workflow named {:?}", wf.name)));
            }
            list.push(wf.clone());
            save(db, &list)?;
            Ok(wf)
        })?;
        self.audit(&actor.id(), "workflow_save", wf.for_audit(), "allow")?;
        self.workflow_invalidate();
        self.publish(Event::WorkflowChanged { id: wf.id, what: "saved".into() });
        Ok(wf)
    }

    /// Replaces a workflow's name, description and steps. A workflow whose steps changed loses its trigger: a person
    /// turned it on for the steps they had read. People only; audited.
    pub fn workflow_update(&self, actor: &Actor, key: &str, input: WorkflowInput) -> Result<Workflow> {
        if !people_only(actor) {
            return Err(self.workflow_deny(actor, "workflow_save", key));
        }
        let (wf, trigger_cleared) = self.store.write(|db| -> Result<(Workflow, bool)> {
            let mut list = load(db)?;
            let id = find(&list, key).map(|w| w.id).ok_or_else(|| ServiceError::NotFound(format!("workflow {key}")))?;
            let at = list.iter().position(|w| w.id == id).expect("found above");
            let old = list[at].clone();
            let mut wf = Workflow {
                name: input.name.trim().to_string(),
                description: input.description,
                steps: input.steps,
                updated_by: actor.id(),
                updated_ms: now_ms(),
                ..old.clone()
            };
            wf.validate().map_err(ServiceError::Invalid)?;
            if list.iter().any(|w| w.id != wf.id && w.name.eq_ignore_ascii_case(&wf.name)) {
                return Err(ServiceError::Invalid(format!("there is already a workflow named {:?}", wf.name)));
            }
            let mut cleared = false;
            if wf.trigger.enabled && (old.steps != wf.steps || wf.check_trigger().is_err()) {
                wf.trigger.enabled = false;
                cleared = true;
            }
            list[at] = wf.clone();
            save(db, &list)?;
            Ok((wf, cleared))
        })?;
        let mut detail = wf.for_audit();
        detail["trigger_turned_off_by_edit"] = json!(trigger_cleared);
        self.audit(&actor.id(), "workflow_save", detail, "allow")?;
        self.workflow_invalidate();
        self.publish(Event::WorkflowChanged { id: wf.id, what: "saved".into() });
        Ok(self.workflow_view(actor, wf))
    }

    /// Deletes a workflow and its runs. People only; audited.
    pub fn workflow_delete(&self, actor: &Actor, key: &str) -> Result<()> {
        if !people_only(actor) {
            return Err(self.workflow_deny(actor, "workflow_delete", key));
        }
        let gone = self.store.write(|db| -> Result<Workflow> {
            let mut list = load(db)?;
            let id = find(&list, key).map(|w| w.id).ok_or_else(|| ServiceError::NotFound(format!("workflow {key}")))?;
            let at = list.iter().position(|w| w.id == id).expect("found above");
            let gone = list.remove(at);
            save(db, &list)?;
            db.delete_workflow_runs_of(id)?;
            Ok(gone)
        })?;
        self.audit(&actor.id(), "workflow_delete", gone.for_audit(), "allow")?;
        self.workflow_invalidate();
        self.publish(Event::WorkflowChanged { id: gone.id, what: "deleted".into() });
        Ok(())
    }

    /// Turns the per-exchange trigger on or off. Only a person can, and it is audited. The workflow must begin with
    /// a `match` step that looks at the exchange. Automatic runs go through the gate as this person.
    pub fn workflow_trigger_set(
        &self,
        actor: &Actor,
        key: &str,
        enabled: bool,
        max_per_minute: Option<u32>,
    ) -> Result<Workflow> {
        if !people_only(actor) {
            return Err(self.workflow_deny(actor, "workflow_trigger", key));
        }
        if let Some(n) = max_per_minute
            && !(1..=MAX_TRIGGER_RATE).contains(&n)
        {
            return Err(ServiceError::Invalid(format!("max_per_minute is 1 to {MAX_TRIGGER_RATE}")));
        }
        let wf = self.store.write(|db| -> Result<Workflow> {
            let mut list = load(db)?;
            let id = find(&list, key).map(|w| w.id).ok_or_else(|| ServiceError::NotFound(format!("workflow {key}")))?;
            let w = list.iter_mut().find(|w| w.id == id).expect("found above");
            if enabled {
                w.validate().map_err(ServiceError::Invalid)?;
                w.check_trigger().map_err(ServiceError::Invalid)?;
            }
            if let Some(n) = max_per_minute {
                w.trigger.max_per_minute = n;
            }
            if enabled != w.trigger.enabled {
                w.trigger.enabled = enabled;
                w.trigger.enabled_by = if enabled { actor.id() } else { String::new() };
                w.trigger.enabled_ms = if enabled { now_ms() } else { 0 };
            }
            let w = w.clone();
            save(db, &list)?;
            Ok(w)
        })?;
        let mut detail = wf.for_audit();
        detail["trigger"]["enabled_by"] = json!(wf.trigger.enabled_by);
        self.audit(&actor.id(), "workflow_trigger", detail, "allow")?;
        self.workflow_invalidate();
        self.publish(Event::WorkflowChanged {
            id: wf.id,
            what: if enabled { "trigger_enabled" } else { "trigger_disabled" }.into(),
        });
        Ok(self.workflow_view(actor, wf))
    }

    // ---- runs -------------------------------------------------------------

    /// A run as `actor` may see it. Agents get variable values hidden when their names suggest a secret and the rest
    /// marked as target content: a value came out of a response.
    pub fn workflow_run_for(&self, actor: &Actor, mut run: WorkflowRun) -> WorkflowRun {
        if people_only(actor) {
            return run;
        }
        let redact = self.redacts_for(actor);
        for (name, v) in run.variables.iter_mut() {
            *v = if secretish(name) {
                format!("[hidden: {} bytes]", v.len())
            } else {
                let shown = if redact { self.redactor.redact(v) } else { v.clone() };
                pm_ai::wrap_untrusted(&shown)
            };
        }
        run
    }

    fn workflow_fix_stale(&self, row: WorkflowRunRow) -> WorkflowRunRow {
        let stale = row.status == "running" && now_ms() - row.started_ms > (MAX_RUN_SECS as i64 + 60) * 1000;
        if !stale {
            return row;
        }
        let Ok(mut run) = row_to_run(&row) else { return row };
        run.status = RunStatus::Failed;
        run.reason = Some("interrupted: the process that ran it stopped".into());
        let record = serde_json::to_string(&run).unwrap_or_default();
        let dur = Some(run.duration_ms as i64);
        match self.store.write(|db| db.update_workflow_run(row.id, "failed", dur, None, &record)) {
            Ok(()) => WorkflowRunRow { status: "failed".into(), record, ..row },
            Err(_) => row,
        }
    }

    /// Recent runs, newest first; of one workflow (id or name) or all.
    pub fn workflow_runs(&self, actor: &Actor, workflow: Option<&str>, limit: usize) -> Result<Vec<WorkflowRun>> {
        let id = match workflow {
            Some(k) => Some(self.workflow_find(k)?.id),
            None => None,
        };
        let rows = self.store.read(|db| db.list_workflow_runs(id, limit.clamp(1, 200)))?;
        let mut out = Vec::new();
        for row in rows {
            let row = self.workflow_fix_stale(row);
            if !people_only(actor) && row.actor != actor.id() {
                continue;
            }
            out.push(self.workflow_run_for(actor, row_to_run(&row)?));
        }
        Ok(out)
    }

    pub fn workflow_run_get(&self, actor: &Actor, id: i64) -> Result<WorkflowRun> {
        let row = self
            .store
            .read(|db| db.get_workflow_run(id))?
            .filter(|r| people_only(actor) || r.actor == actor.id())
            .ok_or_else(|| ServiceError::NotFound(format!("workflow run {id}")))?;
        Ok(self.workflow_run_for(actor, row_to_run(&self.workflow_fix_stale(row))?))
    }

    fn workflow_current(&self, id: i64) -> Result<Current> {
        let ex = self
            .store
            .read(|db| db.get_exchange(id))?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
        Ok(from_exchange(ex))
    }

    fn workflow_event(&self, run: &WorkflowRun, rate: Rate) {
        let e = Event::WorkflowRunChanged {
            run_id: run.id,
            workflow_id: run.workflow_id,
            state: state_of(run),
            steps: run.steps.len(),
        };
        self.publish_rated(&format!("workflow_run:{}", run.id), e, Some(&run.actor), rate);
    }

    /// Runs a workflow (or continues a paused run) as `actor`. Sends are gated one by one; see the module docs. The
    /// run is returned as stored (secrets included): callers show it through [`Service::workflow_run_for`].
    pub(crate) async fn workflow_execute(
        &self,
        actor: &Actor,
        wf: &Workflow,
        exchange_id: Option<i64>,
        approval_id: Option<String>,
        trigger: &str,
    ) -> Result<WorkflowRun> {
        wf.validate().map_err(ServiceError::Invalid)?;
        let resumed = approval_id.is_some();
        let (mut run, start, resume) = match &approval_id {
            Some(ap) => {
                let row = self
                    .store
                    .read(|db| db.find_workflow_run_by_approval(ap))?
                    .ok_or_else(|| ServiceError::NotFound(format!("no run waits for approval {ap}")))?;
                let mut run = row_to_run(&row)?;
                let pending = run.pending.clone().filter(|_| run.status == RunStatus::PendingApproval);
                let pending = pending
                    .ok_or_else(|| ServiceError::Invalid(format!("the run for approval {ap} is not waiting")))?;
                if row.actor != actor.id() || run.workflow_id != wf.id {
                    return Err(ServiceError::Invalid(format!("approval {ap} belongs to another run")));
                }
                if exchange_id.is_some() && exchange_id != run.start_exchange {
                    return Err(ServiceError::Invalid(format!(
                        "approval {ap} is for a run that started on exchange {:?}",
                        run.start_exchange
                    )));
                }
                if pending.digest != wf.digest() {
                    return Err(ServiceError::Invalid(
                        "the workflow was edited since this run paused; start a new run".into(),
                    ));
                }
                if now_ms() - row.started_ms > PAUSE_TTL_MS {
                    return Err(ServiceError::Invalid("this run paused more than a day ago; start a new run".into()));
                }
                let current = pending.current_exchange.map(|id| self.workflow_current(id)).transpose()?;
                if run.steps.last().is_some_and(|s| s.status == StepStatus::PendingApproval) {
                    run.steps.pop();
                }
                let resume =
                    Resume { next: pending.step - 1, current, sends: pending.sends, elapsed_ms: pending.elapsed_ms };
                (run, None, Some(resume))
            }
            None => {
                let start = match exchange_id {
                    Some(id) => {
                        let c = self.workflow_current(id)?;
                        // What an agent runs a workflow on, it may read back out of the run.
                        if !people_only(actor) {
                            let t =
                                Target::from_parts(&c.summary.scheme, &c.summary.host, c.summary.port, &c.summary.path)
                                    .map_err(|e| ServiceError::Invalid(e.to_string()))?;
                            if let Err(why) = self.policy.scope_check(&t) {
                                return Err(ServiceError::Invalid(format!("exchange {id} is out of scope ({why})")));
                            }
                        }
                        Some(c)
                    }
                    None => None,
                };
                let run = WorkflowRun::new(wf, &actor.id(), trigger, exchange_id, now_ms());
                (run, start, None)
            }
        };
        if resume.is_none() {
            let record = serde_json::to_string(&run).map_err(|e| ServiceError::Invalid(e.to_string()))?;
            run.id = self.store.write(|db| {
                db.insert_workflow_run(&NewWorkflowRun {
                    workflow_id: wf.id,
                    workflow_name: wf.name.clone(),
                    actor: actor.id(),
                    trigger: trigger.into(),
                    start_exchange: exchange_id,
                    status: "running".into(),
                    started_ms: run.started_ms,
                    record,
                })
            })?;
        }
        self.workflow_event(&run, Rate::Always);

        let host = ServiceHost { svc: self, actor, wf };
        let progress = |r: &WorkflowRun| self.workflow_event(r, Rate::Limited);
        workflow::execute(&host, wf, &mut run, start, resume, approval_id, &progress).await;

        let record = serde_json::to_string(&run).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let pending_id = run.pending.as_ref().map(|p| p.approval_id.clone());
        self.store.write(|db| -> anyhow::Result<()> {
            db.update_workflow_run(
                run.id,
                run.status.as_str(),
                Some(run.duration_ms as i64),
                pending_id.as_deref(),
                &record,
            )?;
            db.prune_workflow_runs(KEEP_RUNS)?;
            Ok(())
        })?;
        self.workflow_event(&run, if run.status == RunStatus::PendingApproval { Rate::Always } else { Rate::Last });
        self.audit(
            &actor.id(),
            "workflow_run",
            json!({
                "workflow": wf.for_audit(), "run": run.id, "trigger": trigger, "start_exchange": run.start_exchange,
                "status": run.status, "reason": run.reason, "sends": run.sends, "exchanges": run.exchanges,
                "resumed": resumed,
            }),
            "allow",
        )?;
        Ok(run)
    }

    /// Runs a workflow on request (API, MCP, CLI, UI). Every send is gated as `actor`.
    pub async fn workflow_run(&self, actor: &Actor, req: WorkflowRunRequest) -> Result<WorkflowRun> {
        let wf = self.workflow_find(&req.workflow)?;
        let run = self.workflow_execute(actor, &wf, req.exchange_id, req.approval_id, "manual").await?;
        Ok(self.workflow_run_for(actor, run))
    }

    // ---- the fuzzer -------------------------------------------------------

    /// The workflow an attack runs on each result, by id or name.
    pub(crate) fn workflow_for_fuzzer(&self, key: &str) -> Result<Workflow> {
        self.workflow_find(key)
    }

    /// Runs the attack's workflow on one result. A run that cannot finish is reported in the row, never as an error
    /// of the attack.
    pub(crate) async fn workflow_on_result(&self, actor: &Actor, wf: &Workflow, exchange_id: i64) -> FuzzerWorkflow {
        match self.workflow_execute(actor, wf, Some(exchange_id), None, "fuzzer").await {
            Ok(run) => {
                let run = self.workflow_run_for(actor, run);
                FuzzerWorkflow { run_id: run.id, status: run.status, reason: run.reason, variables: run.variables }
            }
            Err(e) => FuzzerWorkflow {
                run_id: 0,
                status: RunStatus::Failed,
                reason: Some(e.to_string()),
                variables: BTreeMap::new(),
            },
        }
    }

    // ---- per-exchange triggers --------------------------------------------

    fn triggered_workflows(&self) -> Arc<Vec<Workflow>> {
        {
            let rt = self.workflows.lock();
            if let Some((at, list)) = &rt.cache
                && at.elapsed() < TRIGGER_CACHE
            {
                return list.clone();
            }
        }
        let list: Vec<Workflow> =
            self.store.read(load).map(|l| l.into_iter().filter(|w| w.trigger.enabled).collect()).unwrap_or_default();
        let list = Arc::new(list);
        self.workflows.lock().cache = Some((Instant::now(), list.clone()));
        list
    }

    /// Whether a run may start now: under the workflow's per-minute cap and with a free slot. Counts what it skips.
    fn trigger_admit(&self, wf: &Workflow) -> bool {
        let mut rt = self.workflows.lock();
        let now = Instant::now();
        let window = rt.windows.entry(wf.id).or_default();
        while window.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(60)) {
            window.pop_front();
        }
        let cap = wf.trigger.max_per_minute.clamp(1, MAX_TRIGGER_RATE) as usize;
        if window.len() >= cap || rt.running >= MAX_TRIGGER_RUNS {
            *rt.skipped.entry(wf.id).or_default() += 1;
            return false;
        }
        rt.windows.entry(wf.id).or_default().push_back(now);
        rt.running += 1;
        true
    }

    /// Looks at one newly recorded exchange: which triggered workflows is it for? Starts their runs.
    async fn trigger_on_exchange(self: Arc<Self>, id: i64) {
        let list = self.triggered_workflows();
        if list.is_empty() {
            return;
        }
        let Some(ex) = self.store.read(|db| db.get_exchange(id)).ok().flatten() else { return };
        // Only traffic from the proxy: what workflows, replays and scans send never starts a workflow, so a trigger
        // cannot feed itself.
        if ex.summary.source != "proxy" {
            return;
        }
        let cur = from_exchange(ex);
        let in_scope = |c: &Current| {
            Target::from_parts(&c.summary.scheme, &c.summary.host, c.summary.port, &c.summary.path)
                .is_ok_and(|t| self.policy.scope_check(&t).is_ok())
        };
        if !in_scope(&cur) {
            return;
        }
        for wf in list.iter() {
            let Some(m) = wf.trigger_match() else { continue };
            if workflow::check_condition(m, Some(&cur), &workflow::Vars::new(), in_scope).is_err() {
                continue;
            }
            let Ok(actor) = Actor::parse(&wf.trigger.enabled_by) else { continue };
            if !people_only(&actor) || !self.trigger_admit(wf) {
                continue;
            }
            let (svc, wf) = (self.clone(), wf.clone());
            tokio::spawn(async move {
                if let Err(e) = svc.workflow_execute(&actor, &wf, Some(id), None, "exchange").await {
                    tracing::warn!(workflow = %wf.name, error = %e, "workflow trigger run failed");
                }
                svc.workflows.lock().running -= 1;
            });
        }
    }

    /// Runs triggered workflows for as long as the service lives: start it once next to the proxy (`proxymind ui`
    /// and the desktop app do). It reacts to exchange events from the bus (ADR-0018); the proxy publishes them after
    /// the commit and does not wait, so traffic is never delayed. Events dropped while this task is busy or lagging
    /// are not replayed: a trigger is best effort.
    pub async fn run_workflow_triggers(self: Arc<Self>) {
        let mut sub = self.subscribe();
        loop {
            let Some(delivery) = sub.recv().await else { return };
            let Delivery::Event(p) = delivery else { continue };
            let Event::ExchangeRecorded { id, .. } = p.event else { continue };
            if self.triggered_workflows().is_empty() {
                continue;
            }
            {
                let mut rt = self.workflows.lock();
                if rt.checking >= MAX_TRIGGER_CHECKS {
                    continue;
                }
                rt.checking += 1;
            }
            let svc = self.clone();
            tokio::spawn(async move {
                svc.clone().trigger_on_exchange(id).await;
                svc.workflows.lock().checking -= 1;
            });
        }
    }
}

// ---- the engine's host -------------------------------------------------------

struct ServiceHost<'a> {
    svc: &'a Service,
    actor: &'a Actor,
    wf: &'a Workflow,
}

impl Host for ServiceHost<'_> {
    fn in_scope(&self, c: &Current) -> bool {
        Target::from_parts(&c.summary.scheme, &c.summary.host, c.summary.port, &c.summary.path)
            .is_ok_and(|t| self.svc.policy.scope_check(&t).is_ok())
    }

    async fn send(&self, req: SendRequest) -> SendOutcome {
        let svc = self.svc;
        let failed = |error: String| SendOutcome::Failed { exchange_id: None, error };
        let out = match svc.outgoing(req.endpoint.clone(), &req.raw, true) {
            Ok(o) => o,
            Err(e) => return failed(e.to_string()),
        };
        if let Some(name) = &req.identity
            && let Err(e) = svc.load_identity(name)
        {
            return failed(e.to_string());
        }
        // The approval binds these exact bytes (and the workflow and step), like a Replay approval does.
        let extra = json!({ "workflow": { "id": self.wf.id, "name": self.wf.name, "step": req.step } });
        let auth = svc.gate_send_with(
            self.actor,
            "workflow_send",
            &out,
            req.identity.as_deref(),
            req.fix_content_length,
            req.approval_id.as_deref(),
            None,
            extra,
        );
        match auth {
            Ok(Authorization::Allowed { .. }) => {}
            Ok(Authorization::Denied { reasons }) => return SendOutcome::Denied(reasons),
            Ok(Authorization::PendingApproval { approval_id, summary, reasons }) => {
                return SendOutcome::Pending { approval_id, summary, reasons };
            }
            // A resume with an approval that is not (or no longer) usable: the run stays paused on the same approval.
            Err(e @ (ServiceError::Approval(_) | ServiceError::ApprovalMismatch(_))) => {
                if let Some(id) = req.approval_id {
                    return SendOutcome::Pending {
                        approval_id: id,
                        summary: format!("{} {}", out.method, out.url()),
                        reasons: vec![e.to_string()],
                    };
                }
                return failed(e.to_string());
            }
            Err(e) => return failed(e.to_string()),
        }
        let sent =
            match svc.send_as(self.actor, &out, req.identity.as_deref(), req.fix_content_length, "workflow").await {
                Ok((s, _notes)) => s,
                Err(e) => return failed(e.to_string()),
            };
        if let Some(error) = sent.error {
            return SendOutcome::Failed { exchange_id: Some(sent.exchange_id), error };
        }
        match svc.workflow_current(sent.exchange_id) {
            Ok(c) => SendOutcome::Sent(Box::new(c)),
            Err(e) => SendOutcome::Failed { exchange_id: Some(sent.exchange_id), error: e.to_string() },
        }
    }
}
