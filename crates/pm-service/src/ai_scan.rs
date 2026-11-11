//! AI scan state: an agent assesses the target on its own, from recon to
//! chained proofs, acting as `agent:ai-scan-<id>` through the same tools and
//! policy gate as any agent (scope enforced, risky actions wait for
//! approval, everything audited). The loop that talks to the model lives in
//! `pm-assistant`; this keeps the run (status, phase, progress log, report)
//! and the system prompt.

use pm_policy::Actor;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError};

/// The built-in system prompt. A user's `<home>/ai-scan-prompt.md` replaces it.
const PROMPT: &str = include_str!("../prompts/ai_scan.md");
const PROMPT_FILE: &str = "ai-scan-prompt.md";

/// Phases, in order.
pub const PHASES: &[&str] = &["recon", "scanning", "exploitation", "chaining", "report"];

/// Budget limits.
pub const DEFAULT_STEPS: u32 = 150;
pub const MAX_STEPS: u32 = 1000;
pub const DEFAULT_MINUTES: u32 = 60;
pub const MAX_MINUTES: u32 = 24 * 60;
/// Log entries kept per run (older ones are dropped).
const MAX_LOG: usize = 2000;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiScanRequest {
    /// The target URL; defaults to the first URL in the scope. Must be in scope.
    pub target: Option<String>,
    /// What to concentrate on (optional).
    pub focus: Option<String>,
    /// Most model calls (default 150, max 1000).
    pub max_steps: Option<u32>,
    /// Longest run in minutes (default 60, max 1440).
    pub max_minutes: Option<u32>,
    /// Most it may spend in USD (needs prices in the assistant settings).
    pub max_cost: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiScanLog {
    pub ts_ms: i64,
    /// phase, tool, note, loopback, recon, approval, out_of_scope, model, stop, error, user, chain, verify
    pub kind: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiScan {
    pub id: i64,
    pub target: String,
    pub focus: String,
    /// running, stopping, stopped, done, failed
    pub status: String,
    pub phase: String,
    pub chat_id: Option<i64>,
    pub model: String,
    pub steps: i64,
    pub max_steps: i64,
    pub deadline_ms: i64,
    /// The agent acting for this scan (`agent:ai-scan-<id>`).
    pub actor: String,
    pub started_by: String,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub error: String,
    /// The final report (Markdown), once the agent submits it.
    pub report: String,
    /// Findings this scan's agent created.
    pub findings: usize,
    /// Tokens used so far, and their cost in USD (0 when no price is set).
    pub tokens_in: i64,
    pub tokens_out: i64,
    pub cost: f64,
    /// The cost budget in USD (0: none).
    pub max_cost: f64,
    pub log: Vec<AiScanLog>,
}

/// The actor for scan `id`.
pub fn scan_actor(id: i64) -> Actor {
    Actor::parse(&format!("agent:ai-scan-{id}")).expect("valid actor id")
}

/// The actor for worker `n` of scan `id`.
pub fn worker_actor(id: i64, n: usize) -> Actor {
    Actor::parse(&format!("agent:ai-scan-{id}-w{n}")).expect("valid actor id")
}

/// The scan an actor works for, if it is an AI scan agent or one of its workers.
pub fn scan_of(actor: &Actor) -> Option<i64> {
    let rest = actor.id().strip_prefix("agent:ai-scan-")?.to_string();
    rest.split("-w").next()?.parse().ok()
}

/// Whether `actor_id` is scan `id`'s agent or one of its workers.
fn of_scan(actor_id: &str, id: i64) -> bool {
    let lead = format!("agent:ai-scan-{id}");
    actor_id == lead || actor_id.strip_prefix(&format!("{lead}-w")).is_some_and(|n| n.parse::<usize>().is_ok())
}

fn s(r: &serde_json::Map<String, Value>, k: &str) -> String {
    r.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}
fn n(r: &serde_json::Map<String, Value>, k: &str) -> i64 {
    r.get(k).and_then(Value::as_i64).unwrap_or_default()
}

impl Service {
    fn ai_row(&self, id: i64) -> Result<serde_json::Map<String, Value>> {
        self.store
            .lock()
            .rows("ai_scans", Some(("id", &json!(id))), 1)?
            .into_iter()
            .next()
            .ok_or_else(|| ServiceError::NotFound(format!("AI scan {id}")))
    }

    fn ai_update(&self, id: i64, changes: Vec<(&str, Value)>) -> Result<()> {
        let mut m = serde_json::Map::new();
        for (k, v) in changes {
            m.insert(k.into(), v);
        }
        m.insert("updated_ms".into(), json!(pm_core::now_ms()));
        self.store.lock().update_row("ai_scans", id, &m)?;
        Ok(())
    }

    /// The system prompt for a scan: the user's file if there is one, else the built-in.
    pub fn ai_scan_prompt(&self, target: &str, focus: &str) -> Result<String> {
        let template = self
            .plugin_home
            .get()
            .and_then(|h| std::fs::read_to_string(h.join(PROMPT_FILE)).ok())
            .filter(|t| t.trim().len() > 20)
            .unwrap_or_else(|| PROMPT.to_string());
        let roe = self.policy.roe();
        let scope = format!(
            "include {}{}",
            roe.include.iter().map(|p| p.text.as_str()).collect::<Vec<_>>().join(", "),
            if roe.exclude.is_empty() {
                String::new()
            } else {
                format!("; exclude {}", roe.exclude.iter().map(|p| p.text.as_str()).collect::<Vec<_>>().join(", "))
            }
        );
        let focus = if focus.trim().is_empty() { String::new() } else { format!("- Focus: {}", focus.trim()) };
        Ok(template.replace("{{target}}", target).replace("{{scope}}", &scope).replace("{{focus}}", &focus))
    }

    /// Creates a scan (status `running`). People only: it starts an agent.
    pub fn ai_scan_create(&self, actor: &Actor, req: &AiScanRequest, model: &str) -> Result<AiScan> {
        if actor.kind != pm_policy::ActorKind::Human {
            return Err(ServiceError::Invalid("only people can start an AI scan".into()));
        }
        let roe = self.policy.roe();
        let target = match req.target.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
            Some(t) => t.to_string(),
            None => roe
                .include
                .first()
                .map(|p| p.text.clone())
                .ok_or_else(|| ServiceError::Invalid("the rules of engagement have no scope".into()))?,
        };
        let t = pm_policy::Target::from_url(&target).map_err(|e| ServiceError::Invalid(format!("target: {e}")))?;
        self.policy.scope_check(&t).map_err(|e| ServiceError::Invalid(format!("target out of scope: {e}")))?;
        let running = self.store.lock().rows("ai_scans", Some(("status", &json!("running"))), 1)?.into_iter().next();
        if let Some(r) = running {
            return Err(ServiceError::Invalid(format!("AI scan {} is still running; stop it first", n(&r, "id"))));
        }
        let steps = req.max_steps.unwrap_or(DEFAULT_STEPS).clamp(1, MAX_STEPS);
        let minutes = req.max_minutes.unwrap_or(DEFAULT_MINUTES).clamp(1, MAX_MINUTES);
        let now = pm_core::now_ms();
        let mut row = serde_json::Map::new();
        for (k, v) in [
            ("target", json!(target)),
            ("focus", json!(req.focus.clone().unwrap_or_default())),
            ("status", json!("running")),
            ("phase", json!("recon")),
            ("model", json!(model)),
            ("max_steps", json!(steps)),
            ("deadline_ms", json!(now + i64::from(minutes) * 60_000)),
            (
                "max_cost_micros",
                json!(
                    req.max_cost.filter(|c| c.is_finite() && *c > 0.0).map_or(0, |c| (c.min(100_000.0) * 1e6) as i64)
                ),
            ),
            ("actor", json!(actor.id())),
            ("created_ms", json!(now)),
            ("updated_ms", json!(now)),
        ] {
            row.insert(k.into(), v);
        }
        let id = self.store.lock().insert_row("ai_scans", &row)?;
        self.audit(
            &actor.id(),
            "ai_scan_start",
            json!({ "scan": id, "target": target, "max_steps": steps, "max_minutes": minutes, "model": model,
                    "max_cost": req.max_cost }),
            "allow",
        )?;
        self.ai_scan_get(id)
    }

    /// Findings created by scan `id`'s agent and workers, newest first.
    fn scan_findings(&self, id: i64) -> Result<Vec<serde_json::Map<String, Value>>> {
        Ok(self
            .store
            .lock()
            .rows("findings", None, 10_000)?
            .into_iter()
            .filter(|r| of_scan(&s(r, "actor"), id))
            .collect())
    }

    pub fn ai_scan_get(&self, id: i64) -> Result<AiScan> {
        let r = self.ai_row(id)?;
        let log: Vec<AiScanLog> = serde_json::from_str(&s(&r, "log")).unwrap_or_default();
        let agent = scan_actor(id).id();
        let findings = self.scan_findings(id).map(|v| v.len()).unwrap_or(0);
        Ok(AiScan {
            id,
            target: s(&r, "target"),
            focus: s(&r, "focus"),
            status: s(&r, "status"),
            phase: s(&r, "phase"),
            chat_id: r.get("chat_id").and_then(Value::as_i64),
            model: s(&r, "model"),
            steps: n(&r, "steps"),
            max_steps: n(&r, "max_steps"),
            deadline_ms: n(&r, "deadline_ms"),
            actor: agent,
            started_by: s(&r, "actor"),
            created_ms: n(&r, "created_ms"),
            updated_ms: n(&r, "updated_ms"),
            error: s(&r, "error"),
            report: s(&r, "report"),
            findings,
            tokens_in: n(&r, "tokens_in"),
            tokens_out: n(&r, "tokens_out"),
            cost: n(&r, "cost_micros") as f64 / 1e6,
            max_cost: n(&r, "max_cost_micros") as f64 / 1e6,
            log,
        })
    }

    /// Scans, newest first, without their logs and reports.
    pub fn ai_scan_list(&self, limit: usize) -> Result<Vec<AiScan>> {
        let ids: Vec<i64> =
            self.store.lock().rows("ai_scans", None, limit.clamp(1, 200))?.iter().map(|r| n(r, "id")).collect();
        let mut out = Vec::new();
        for id in ids {
            let mut sc = self.ai_scan_get(id)?;
            sc.log.clear();
            sc.report = if sc.report.is_empty() { String::new() } else { "(report ready)".into() };
            out.push(sc);
        }
        Ok(out)
    }

    pub fn ai_scan_log(&self, id: i64, kind: &str, text: &str) -> Result<()> {
        let r = self.ai_row(id)?;
        let mut log: Vec<AiScanLog> = serde_json::from_str(&s(&r, "log")).unwrap_or_default();
        log.push(AiScanLog { ts_ms: pm_core::now_ms(), kind: kind.into(), text: text.chars().take(2000).collect() });
        if log.len() > MAX_LOG {
            log.drain(..log.len() - MAX_LOG);
        }
        self.ai_update(id, vec![("log", json!(serde_json::to_string(&log).unwrap_or_default()))])
    }

    pub fn ai_scan_set_phase(&self, id: i64, phase: &str, notes: &str) -> Result<()> {
        if !PHASES.contains(&phase) {
            return Err(ServiceError::Invalid(format!("phase must be one of {}", PHASES.join(", "))));
        }
        self.ai_update(id, vec![("phase", json!(phase))])?;
        let text = if notes.trim().is_empty() { phase.to_string() } else { format!("{phase}: {}", notes.trim()) };
        self.ai_scan_log(id, "phase", &text)
    }

    pub fn ai_scan_set_report(&self, id: i64, markdown: &str) -> Result<()> {
        if markdown.trim().len() < 20 {
            return Err(ServiceError::Invalid("the report is empty".into()));
        }
        self.ai_update(id, vec![("report", json!(markdown)), ("phase", json!("report"))])?;
        self.ai_scan_log(id, "phase", "report submitted")
    }

    /// Adds a model call's tokens and cost to the scan's totals.
    pub fn ai_scan_usage(&self, id: i64, tokens_in: u64, tokens_out: u64, cost_micros: i64) -> Result<()> {
        let r = self.ai_row(id)?;
        self.ai_update(
            id,
            vec![
                ("tokens_in", json!(n(&r, "tokens_in") + tokens_in as i64)),
                ("tokens_out", json!(n(&r, "tokens_out") + tokens_out as i64)),
                ("cost_micros", json!(n(&r, "cost_micros") + cost_micros.max(0))),
            ],
        )
    }

    pub fn ai_scan_progress(&self, id: i64, steps: i64, chat_id: i64) -> Result<()> {
        self.ai_update(id, vec![("steps", json!(steps)), ("chat_id", json!(chat_id))])
    }

    /// Ends a scan: done, stopped or failed.
    pub fn ai_scan_finish(&self, id: i64, status: &str, error: &str) -> Result<()> {
        self.ai_update(id, vec![("status", json!(status)), ("error", json!(error))])?;
        self.audit(&scan_actor(id).id(), "ai_scan_end", json!({ "scan": id, "status": status, "error": error }), "ok")?;
        Ok(())
    }

    /// Asks a running scan to stop after its current step.
    pub fn ai_scan_stop(&self, actor: &Actor, id: i64) -> Result<AiScan> {
        let sc = self.ai_scan_get(id)?;
        if sc.status == "running" {
            self.ai_update(id, vec![("status", json!("stopping"))])?;
            self.ai_scan_log(id, "stop", &format!("stop requested by {}", actor.id()))?;
            self.audit(&actor.id(), "ai_scan_stop", json!({ "scan": id }), "allow")?;
        }
        self.ai_scan_get(id)
    }

    /// A message from a person to a running scan ("focus on checkout", "why
    /// did you try that?"). It reaches the agent with its next step.
    pub fn ai_scan_message(&self, actor: &Actor, id: i64, text: &str) -> Result<AiScan> {
        if actor.kind != pm_policy::ActorKind::Human {
            return Err(ServiceError::Invalid("only people send messages to an AI scan".into()));
        }
        let text = text.trim();
        if text.is_empty() {
            return Err(ServiceError::Invalid("the message is empty".into()));
        }
        let r = self.ai_row(id)?;
        if s(&r, "status") != "running" {
            return Err(ServiceError::Invalid(format!("AI scan {id} isn't running")));
        }
        let mut inbox: Vec<String> = serde_json::from_str(&s(&r, "inbox")).unwrap_or_default();
        if inbox.len() >= 20 {
            return Err(ServiceError::Invalid("20 messages are already waiting for the agent".into()));
        }
        let text: String = text.chars().take(2000).collect();
        inbox.push(text.clone());
        self.ai_update(id, vec![("inbox", json!(serde_json::to_string(&inbox).unwrap_or_default()))])?;
        self.ai_scan_log(id, "user", &format!("{}: {text}", actor.id()))?;
        self.audit(&actor.id(), "ai_scan_message", json!({ "scan": id, "chars": text.len() }), "allow")?;
        self.ai_scan_get(id)
    }

    /// Messages waiting for the agent; empties the inbox.
    pub fn ai_scan_take_messages(&self, id: i64) -> Result<Vec<String>> {
        let r = self.ai_row(id)?;
        let inbox: Vec<String> = serde_json::from_str(&s(&r, "inbox")).unwrap_or_default();
        if !inbox.is_empty() {
            self.ai_update(id, vec![("inbox", json!("[]"))])?;
        }
        Ok(inbox)
    }

    /// Retests what the scan's agent found (its proofs or scanner checks,
    /// at most 30 findings), logs each result and adds a "Verification"
    /// section to the report, so a finding that doesn't reproduce is marked
    /// before a person reads it.
    pub async fn ai_scan_verify(&self, id: i64) -> Result<Vec<crate::Retest>> {
        let actor = scan_actor(id);
        let mut rows = self.scan_findings(id)?;
        rows.truncate(30);
        let mut out = Vec::new();
        let mut lines = Vec::new();
        for r in rows.iter().rev() {
            let fid = n(r, "id");
            let title = s(r, "title");
            let rt = match self.finding_retest(&actor, fid).await {
                Ok(rt) => rt,
                Err(e) => {
                    self.ai_scan_log(id, "verify", &format!("#{fid} {title}: couldn't retest ({e})"))?;
                    lines.push(format!("- #{fid} {title}: couldn't retest ({e})"));
                    continue;
                }
            };
            let verdict = match rt.reproduced {
                Some(true) => "reproduced",
                Some(false) => "NOT reproduced",
                None => "not checked",
            };
            self.ai_scan_log(id, "verify", &format!("#{fid} {title}: {verdict} ({})", rt.summary))?;
            lines.push(format!("- #{fid} {title}: **{verdict}** ({})", rt.summary));
            out.push(rt);
        }
        if !lines.is_empty() {
            let report = self.ai_scan_get(id)?.report;
            let section = format!(
                "\n\n## Verification by ProxyMind\n\nEach finding was retested after the scan (its proof re-run, or its \
                 scanner check). Findings marked NOT reproduced need a person's look before they are reported.\n\n{}\n",
                lines.join("\n")
            );
            self.ai_update(id, vec![("report", json!(format!("{}{section}", report.trim_end())))])?;
        }
        Ok(out)
    }

    /// Whether the scan should keep going (not stopped, within its budget).
    pub fn ai_scan_should_stop(&self, id: i64) -> Result<Option<&'static str>> {
        let r = self.ai_row(id)?;
        Ok(match s(&r, "status").as_str() {
            "stopping" => Some("stopped by a person"),
            "running" if pm_core::now_ms() > n(&r, "deadline_ms") => Some("time budget used up"),
            "running" if n(&r, "steps") >= n(&r, "max_steps") => Some("step budget used up"),
            "running" if n(&r, "max_cost_micros") > 0 && n(&r, "cost_micros") >= n(&r, "max_cost_micros") => {
                Some("cost budget used up")
            }
            "running" => None,
            _ => Some("not running"),
        })
    }

    /// Runs left `running` by a process that ended (marked failed on open).
    pub fn ai_scan_recover(&self) -> Result<()> {
        let stale = self.store.lock().rows("ai_scans", Some(("status", &json!("running"))), 100)?;
        for r in stale {
            // A run updates its row every step; one quiet for 10 minutes has no process behind it.
            if pm_core::now_ms() - n(&r, "updated_ms") > 10 * 60_000 {
                self.ai_scan_finish(n(&r, "id"), "failed", "the process running it ended")?;
            }
        }
        Ok(())
    }

    /// Handles the scan agent's own tools: `ai_scan_phase`, `ai_scan_note`,
    /// `ai_scan_report`. `None` for any other tool.
    pub fn ai_scan_tool(&self, actor: &Actor, name: &str, input: &Value) -> Option<std::result::Result<Value, String>> {
        if !matches!(name, "ai_scan_phase" | "ai_scan_note" | "ai_scan_report") {
            return None;
        }
        let Some(id) = scan_of(actor) else {
            return Some(Err(format!("{name} is only for the AI scan agent")));
        };
        let str_of = |k: &str| input.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let r = match name {
            "ai_scan_phase" => self.ai_scan_set_phase(id, &str_of("phase"), &str_of("notes")),
            "ai_scan_note" => {
                let kind = str_of("kind");
                let kind = if ["recon", "loopback", "approval", "out_of_scope", "note"].contains(&kind.as_str()) {
                    kind
                } else {
                    "note".into()
                };
                self.ai_scan_log(id, &kind, &str_of("text"))
            }
            _ => self.ai_scan_set_report(id, &str_of("markdown")),
        };
        Some(r.map(|()| json!({ "ok": true })).map_err(|e| e.to_string()))
    }
}

/// Tool definitions for the scan agent's own tools (MCP shape).
pub fn ai_scan_tool_definitions() -> Vec<Value> {
    let t = |name: &str, description: &str, props: Value, required: &[&str]| {
        json!({ "name": name, "description": description,
                "inputSchema": { "type": "object", "properties": props, "required": required } })
    };
    vec![
        t(
            "ai_scan_phase",
            "Move the scan to a phase (recon, scanning, exploitation, chaining, report) once its gate is met; notes say \
             what the gate check found.",
            json!({ "phase": {"type":"string","enum": PHASES}, "notes": {"type":"string"} }),
            &["phase"],
        ),
        t(
            "ai_scan_note",
            "Record progress: kind recon (an asset), loopback (returning to an earlier phase and why), approval (a step \
             waiting for a person), out_of_scope (something you won't touch), or note.",
            json!({ "kind": {"type":"string","enum":["recon","loopback","approval","out_of_scope","note"]},
                    "text": {"type":"string"} }),
            &["kind", "text"],
        ),
        t(
            "ai_scan_report",
            "Submit the final report (Markdown, in the required format). Call it once, at the end.",
            json!({ "markdown": {"type":"string"} }),
            &["markdown"],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actors_name_their_scan() {
        let a = scan_actor(42);
        assert_eq!(a.id(), "agent:ai-scan-42");
        assert_eq!(scan_of(&a), Some(42));
        assert_eq!(scan_of(&Actor::parse("agent:claude").unwrap()), None);
        assert_eq!(scan_of(&worker_actor(42, 3)), Some(42));
        assert!(of_scan("agent:ai-scan-42-w3", 42) && of_scan("agent:ai-scan-42", 42));
        assert!(!of_scan("agent:ai-scan-421", 42) && !of_scan("agent:ai-scan-42-wx", 42));
    }

    #[test]
    fn the_prompt_names_the_tools_it_maps_to() {
        for t in [
            "ai_scan_phase",
            "ai_scan_note",
            "ai_scan_report",
            "scan_active",
            "engage_js_endpoints",
            "ai_scan_delegate",
            "memory_save",
            "traffic_triage",
        ] {
            assert!(PROMPT.contains(t), "{t}");
        }
        assert!(PROMPT.contains("{{target}}") && PROMPT.contains("{{scope}}"));
    }
}
