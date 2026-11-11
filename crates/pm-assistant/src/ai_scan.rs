//! The AI scan loop: the configured model (cloud or local) assesses the
//! target on its own as `agent:ai-scan-<id>`, through ProxyMind's tools and
//! policy gate, from recon to chained proofs and a report. The run's state
//! (status, phase, log, report) lives in the service (`ai_scans`); the
//! transcript is an assistant chat.

use std::sync::Arc;

use pm_service::{AiScan, AiScanRequest, AssistantConfig, ai_scan_tool_definitions, scan_actor};
use serde_json::{Value, json};

use crate::llm::{self, Block, Call, Message, Role};
use crate::{Assistant, AssistantError, Result, cut, host_of, is_local_url, provider_name};

/// The newest messages are kept whole; older tool results are cut to this
/// many bytes so a long scan fits the model's context.
const KEEP_WHOLE: usize = 24;
const OLD_RESULT: usize = 400;
/// Reports are long: at least this many output tokens per call.
const MIN_TOKENS: u32 = 8192;
/// Times the agent may stop talking without a report before the run ends.
const MAX_NUDGES: u32 = 3;

fn short(v: &Value) -> String {
    let s = v.to_string();
    if s.len() <= 160 { s } else { format!("{}…", &s[..s.char_indices().nth(160).map_or(s.len(), |(i, _)| i)]) }
}

/// Cuts old tool results (pairs stay intact: only their text shrinks).
fn compact(all: &mut [Message]) {
    let keep_from = all.len().saturating_sub(KEEP_WHOLE);
    for m in all.iter_mut().take(keep_from).skip(1) {
        for b in &mut m.content {
            if let Block::ToolResult { content, .. } = b
                && content.len() > OLD_RESULT
            {
                let mut end = OLD_RESULT;
                while !content.is_char_boundary(end) {
                    end -= 1;
                }
                *content = format!("{}… [older result shortened]", &content[..end]);
            }
        }
    }
}

impl Assistant {
    /// Starts an AI scan in the background and returns it. People only;
    /// the model settings are the assistant's (cloud models need
    /// `data.allow_cloud_models` in the rules of engagement).
    pub fn start_ai_scan(self: &Arc<Self>, human: &pm_service::pm_policy::Actor, req: AiScanRequest) -> Result<AiScan> {
        let cfg = self.service.assistant_config()?;
        let key = self.check(&cfg)?;
        let scan = self.service.ai_scan_create(human, &req, &cfg.model)?;
        let me = self.clone();
        let id = scan.id;
        tokio::spawn(async move {
            let (status, error) = match me.run_ai_scan(id, &cfg, key.as_deref()).await {
                Ok(status) => (status, String::new()),
                Err(e) => ("failed", e.to_string()),
            };
            if let Err(e) = me.service.ai_scan_finish(id, status, &error) {
                tracing::warn!("could not finish AI scan {id}: {e}");
            }
        });
        Ok(scan)
    }

    /// Runs scan `id` to the end; returns its final status.
    pub async fn run_ai_scan(&self, id: i64, cfg: &AssistantConfig, key: Option<&str>) -> Result<&'static str> {
        let svc = &self.service;
        let scan = svc.ai_scan_get(id)?;
        let actor = scan_actor(id);
        let system = format!("{}\n\n{}", svc.ai_scan_prompt(&scan.target, &scan.focus)?, pm_mcp::INSTRUCTIONS);
        let mut tools = pm_mcp::tool_definitions();
        tools.extend(ai_scan_tool_definitions());
        let chat_id = svc.chat_create(&format!("AI scan #{id}: {}", scan.target))?;
        let minutes = (scan.deadline_ms - scan.created_ms) / 60_000;
        let mut all = vec![Message::user_text(&format!(
            "Start the assessment of {}. Work through the phases with ProxyMind's tools, recording progress with \
             ai_scan_phase and ai_scan_note. When every phase is done, or the budget is nearly used, submit the full \
             report with ai_scan_report. Budget: {} model calls and {minutes} minutes.",
            scan.target, scan.max_steps
        ))];
        svc.ai_scan_log(id, "phase", &format!("recon: started on {}", scan.target))?;
        let sender = if is_local_url(&cfg.base_url) { &self.local } else { &self.sender };
        let max_tokens = cfg.max_tokens.max(MIN_TOKENS);
        let mut steps: i64 = 0;
        let mut nudges = 0;
        let mut warned = false;
        loop {
            if let Some(why) = svc.ai_scan_should_stop(id)? {
                svc.ai_scan_log(id, "stop", why)?;
                let wants_report = why.contains("budget") && svc.ai_scan_get(id)?.report.is_empty();
                if wants_report {
                    // One last call, for the report only.
                    all.push(Message::user_text(
                        "The budget is used up. Submit the report now with ai_scan_report (what you tested, what you \
                         found, what is left); call no other tool.",
                    ));
                    let call = Call { model: &cfg.model, max_tokens, system: &system, tools: &tools, messages: &all };
                    if let Ok(sent) = llm::call(sender, cfg.provider, &cfg.base_url, key, &call).await {
                        for (_, name, input) in sent.reply.tool_uses() {
                            if name == "ai_scan_report" {
                                let _ = svc.ai_scan_tool(&actor, name, input);
                            }
                        }
                        all.push(sent.reply);
                    }
                    svc.chat_save(chat_id, &json!(all))?;
                }
                return Ok(if why.contains("person") { "stopped" } else { "done" });
            }
            let call = Call { model: &cfg.model, max_tokens, system: &system, tools: &tools, messages: &all };
            let sent = match llm::call(sender, cfg.provider, &cfg.base_url, key, &call).await {
                Ok(s) => s,
                Err(e) => {
                    svc.chat_save(chat_id, &json!(all))?;
                    svc.ai_scan_log(id, "error", &format!("model call failed: {e:#}"))?;
                    return Err(AssistantError::Model(e));
                }
            };
            steps += 1;
            svc.audit_model_call(
                &actor,
                json!({ "ai_scan": id, "provider": provider_name(cfg.provider), "host": host_of(&cfg.base_url),
                        "model": cfg.model, "bytes_sent": sent.bytes_sent }),
                "allow",
            )?;
            let reply = sent.reply;
            let said: String = reply
                .content
                .iter()
                .filter_map(|b| match b {
                    Block::Text { text } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(" ");
            if !said.trim().is_empty() {
                svc.ai_scan_log(id, "model", said.trim())?;
            }
            let uses: Vec<(String, String, Value)> =
                reply.tool_uses().map(|(i, n, v)| (i.to_string(), n.to_string(), v.clone())).collect();
            all.push(reply);
            if uses.is_empty() {
                if !svc.ai_scan_get(id)?.report.is_empty() {
                    svc.ai_scan_progress(id, steps, chat_id)?;
                    svc.chat_save(chat_id, &json!(all))?;
                    return Ok("done");
                }
                nudges += 1;
                if nudges > MAX_NUDGES {
                    svc.ai_scan_log(id, "stop", "the agent stopped without submitting a report")?;
                    svc.chat_save(chat_id, &json!(all))?;
                    return Ok("done");
                }
                all.push(Message::user_text(
                    "Continue the assessment. You haven't submitted the report (ai_scan_report) yet: if every gate is \
                     met, write it now; otherwise keep testing.",
                ));
            } else {
                let mut results = Vec::new();
                for (tool_id, name, input) in uses {
                    let outcome = match svc.ai_scan_tool(&actor, &name, &input) {
                        Some(r) => r,
                        None => pm_mcp::call_tool(svc, &actor, &name, input.clone()).await,
                    };
                    let (content, is_error) = match outcome {
                        Ok(v) => (v.to_string(), false),
                        Err(e) => (e, true),
                    };
                    if !name.starts_with("ai_scan_") {
                        let kind = if content.contains("pending_approval") { "approval" } else { "tool" };
                        let mark = if is_error { " ✗" } else { "" };
                        svc.ai_scan_log(id, kind, &format!("{name} {}{mark}", short(&input)))?;
                    }
                    results.push(Block::ToolResult { tool_use_id: tool_id, content: cut(&content), is_error });
                }
                let left = svc.ai_scan_get(id)?.max_steps - steps;
                if left <= 5 && !warned {
                    warned = true;
                    results.push(Block::Text {
                        text: format!(
                            "Budget: {left} model calls left. Wrap up and submit the report with ai_scan_report."
                        ),
                    });
                }
                all.push(Message { role: Role::User, content: results });
            }
            compact(&mut all);
            svc.ai_scan_progress(id, steps, chat_id)?;
            svc.chat_save(chat_id, &json!(all))?;
        }
    }
}
