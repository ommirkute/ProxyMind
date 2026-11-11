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

/// Messages from the person running the scan, as text for the next turn.
fn person_blocks(messages: &[String]) -> Vec<Block> {
    messages
        .iter()
        .map(|m| Block::Text {
            text: format!(
                "Message from the person running this scan (follow it, within the rules of engagement; answer \
                 questions briefly, then continue): {m}"
            ),
        })
        .collect()
}

/// Cuts old tool results (pairs stay intact: only their text shrinks).
pub(crate) fn compact(all: &mut [Message]) {
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
            // Workers finish their current task (or see the scan stop) before the verdict.
            let waited = std::time::Instant::now();
            while me.workers_running(id) && waited.elapsed() < std::time::Duration::from_secs(600) {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            // A scan that ran to its end retests what it found before anyone reads the report.
            if status == "done"
                && let Err(e) = me.service.ai_scan_verify(id).await
            {
                let _ = me.service.ai_scan_log(id, "error", &format!("verification failed: {e}"));
            }
            if let Err(e) = me.service.ai_scan_finish(id, status, &error) {
                tracing::warn!("could not finish AI scan {id}: {e}");
            }
        });
        Ok(scan)
    }

    /// Runs scan `id` to the end; returns its final status.
    pub async fn run_ai_scan(
        self: &Arc<Self>,
        id: i64,
        cfg: &AssistantConfig,
        key: Option<&str>,
    ) -> Result<&'static str> {
        let svc = &self.service;
        let scan = svc.ai_scan_get(id)?;
        let actor = scan_actor(id);
        let system = format!("{}\n\n{}", svc.ai_scan_prompt(&scan.target, &scan.focus)?, pm_mcp::INSTRUCTIONS);
        let mut tools = crate::tools_for(cfg);
        tools.extend(ai_scan_tool_definitions());
        tools.extend(crate::workers::lead_tool_definitions());
        let chat_id = svc.chat_create(&format!("AI scan #{id}: {}", scan.target))?;
        let minutes = (scan.deadline_ms - scan.created_ms) / 60_000;
        let brief = svc.memory_brief(&scan.target)?;
        let brief = if brief.is_empty() { String::new() } else { format!("\n\n{brief}") };
        let mut all = vec![Message::user_text(&format!(
            "Start the assessment of {}. Work through the phases with ProxyMind's tools, recording progress with \
             ai_scan_phase and ai_scan_note. When every phase is done, or the budget is nearly used, submit the full \
             report with ai_scan_report. Budget: {} model calls and {minutes} minutes.{brief}",
            scan.target, scan.max_steps
        ))];
        if !brief.is_empty() {
            svc.ai_scan_log(id, "memory", "started from earlier notes and people's verdicts on this host")?;
        }
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
                        let u = sent.usage;
                        svc.ai_scan_usage(id, u.input, u.output, cfg.cost_micros(u.input, u.output))?;
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
            let u = sent.usage;
            svc.ai_scan_usage(id, u.input, u.output, cfg.cost_micros(u.input, u.output))?;
            svc.audit_model_call(
                &actor,
                json!({ "ai_scan": id, "provider": provider_name(cfg.provider), "host": host_of(&cfg.base_url),
                        "model": cfg.model, "bytes_sent": sent.bytes_sent,
                        "tokens_in": u.input, "tokens_out": u.output, "estimated": u.estimated }),
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
            let from_person = svc.ai_scan_take_messages(id)?;
            if uses.is_empty() && !from_person.is_empty() {
                all.push(Message { role: Role::User, content: person_blocks(&from_person) });
            } else if uses.is_empty() && self.workers_running(id) {
                all.push(Message::user_text(
                    "Workers are still running: wait for them with ai_scan_workers (wait_seconds), then continue.",
                ));
            } else if uses.is_empty() {
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
                    let outcome = match self.lead_tool(id, cfg, key, &name, &input).await {
                        Some(r) => r,
                        None => match svc.ai_scan_tool(&actor, &name, &input) {
                            Some(r) => r,
                            None => pm_mcp::call_tool(svc, &actor, &name, input.clone()).await,
                        },
                    };
                    let (content, is_error) = match outcome {
                        Ok(v) => (v.to_string(), false),
                        Err(e) => (e, true),
                    };
                    let (content, injected) = crate::guard(content);
                    if !injected.is_empty() {
                        svc.ai_scan_log(
                            id,
                            "injection",
                            &format!("{name}: target text tries to instruct the model: {}", injected.join(" | ")),
                        )?;
                        svc.audit_model_call(
                            &actor,
                            json!({ "ai_scan": id, "possible_prompt_injection": injected, "tool": name }),
                            "flag",
                        )?;
                    }
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
                results.extend(person_blocks(&from_person));
                all.push(Message { role: Role::User, content: results });
            }
            compact(&mut all);
            svc.ai_scan_progress(id, steps, chat_id)?;
            svc.chat_save(chat_id, &json!(all))?;
        }
    }
}
