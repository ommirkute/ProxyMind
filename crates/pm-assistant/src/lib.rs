//! The assistant built into ProxyMind. It is an agent like any other: it
//! acts as `agent:assistant`, uses the same tools as MCP clients, and goes
//! through the same policy gate (scope, approvals, rate limits, redaction,
//! audit). Models run locally by default; cloud models need
//! `allow_cloud_models: true` in the rules of engagement.

pub mod ai_scan;
pub mod llm;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use llm::{Block, Call, Message, Role};
use pm_service::pm_policy::Actor;
use pm_service::pm_replay::Sender;
use pm_service::{AssistantConfig, ProviderKind, Service, ServiceError};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

/// Tool results longer than this are cut before going to the model.
const MAX_TOOL_RESULT: usize = 16_000;

const ROLE: &str = "\n\nYou are the assistant built into ProxyMind, working with a human pentester in the same \
window. Be brief and concrete: say what you looked at, what you found and what you suggest next. Use the tools \
to look at real traffic instead of guessing. When a step needs approval, say what you want to do and why, and \
ask the human to approve it in the Approvals page, then continue when they say so.";

#[derive(Debug, thiserror::Error)]
pub enum AssistantError {
    #[error("{0}")]
    Refused(String),
    #[error("{0}")]
    Setup(String),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error("{0:#}")]
    Model(anyhow::Error),
}

pub type Result<T> = std::result::Result<T, AssistantError>;

/// What one user message produced.
#[derive(Debug, Clone, Serialize)]
pub struct Turn {
    pub chat_id: i64,
    /// Messages added in this turn (user, assistant and tool results).
    pub messages: Vec<Message>,
    /// Set when the turn ended early (step limit).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub struct Assistant {
    service: Arc<Service>,
    actor: Actor,
    /// Cloud APIs: through the project's network settings (upstream proxy).
    sender: Sender,
    /// Local model servers: always direct.
    local: Sender,
    /// One conversation step at a time.
    busy: Mutex<()>,
}

/// True for loopback, private and link-local addresses and `localhost`
/// names: models served there count as local.
pub fn is_local_url(base_url: &str) -> bool {
    let Ok(u) = url::Url::parse(base_url) else { return false };
    let Some(host) = u.host_str() else { return false };
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private() || ip.is_link_local(),
        Ok(IpAddr::V6(ip)) => {
            ip.is_loopback()
                || (ip.segments()[0] & 0xfe00) == 0xfc00
                || (ip.segments()[0] & 0xffc0) == 0xfe80
                || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback() || v4.is_private())
        }
        Err(_) => false,
    }
}

impl Assistant {
    pub fn new(service: Arc<Service>) -> Result<Self> {
        let new = || {
            Sender::new(true)
                .map(|s| s.with_timeouts(Duration::from_secs(15), Duration::from_secs(300)))
                .map_err(|e| AssistantError::Setup(format!("{e:#}")))
        };
        let sender = new()?.with_network(service.network().clone());
        let local = new()?;
        let actor = Actor::parse("agent:assistant").map_err(|e| AssistantError::Setup(e.to_string()))?;
        Ok(Self { service, actor, sender, local, busy: Mutex::new(()) })
    }

    pub fn actor(&self) -> &Actor {
        &self.actor
    }

    /// Checks the settings without calling the model.
    pub fn check(&self, cfg: &AssistantConfig) -> Result<Option<String>> {
        if cfg.model.trim().is_empty() {
            return Err(AssistantError::Setup("choose a model in the assistant settings".into()));
        }
        if !is_local_url(&cfg.base_url) && !self.service.cloud_models_allowed() {
            return Err(AssistantError::Refused(format!(
                "{} is not a local model server, and the rules of engagement don't allow cloud models \
                 (data.allow_cloud_models). Use a local server such as Ollama, or ask the engagement owner to allow cloud models.",
                cfg.base_url
            )));
        }
        if cfg.api_key_env.is_empty() {
            return Ok(None);
        }
        match self.service.model_key(&cfg.api_key_env) {
            Some(k) => Ok(Some(k)),
            None => Err(AssistantError::Setup(format!(
                "add the API key ({}) in the assistant settings, or set that environment variable before starting \
                 ProxyMind (keys are never stored in the project)",
                cfg.api_key_env
            ))),
        }
    }

    /// Sends `text` in chat `chat_id` (a new chat if None) and runs the tool
    /// loop until the model answers without calling a tool.
    pub async fn send(&self, chat_id: Option<i64>, text: &str) -> Result<Turn> {
        let _turn = self.busy.lock().await;
        let cfg = self.service.assistant_config()?;
        let key = match self.check(&cfg) {
            Ok(k) => k,
            Err(e) => {
                let detail = json!({ "host": host_of(&cfg.base_url), "model": cfg.model, "reason": e.to_string() });
                self.service.audit_model_call(&self.actor, detail, "deny")?;
                return Err(e);
            }
        };
        let chat_id = match chat_id {
            Some(id) => id,
            None => self.service.chat_create(text.lines().next().unwrap_or("Chat"))?,
        };
        let mut all: Vec<Message> =
            serde_json::from_value(self.service.chat_get(chat_id)?.messages).unwrap_or_default();
        let start = all.len();
        all.push(Message::user_text(text));
        let system = format!("{}{ROLE}", pm_mcp::INSTRUCTIONS);
        let tools = pm_mcp::tool_definitions();
        let mut note = None;

        for step in 0..cfg.max_steps {
            let call =
                Call { model: &cfg.model, max_tokens: cfg.max_tokens, system: &system, tools: &tools, messages: &all };
            let sender = if is_local_url(&cfg.base_url) { &self.local } else { &self.sender };
            let sent = llm::call(sender, cfg.provider, &cfg.base_url, key.as_deref(), &call).await;
            let sent = match sent {
                Ok(s) => s,
                Err(e) => {
                    self.service.chat_save(chat_id, &json!(all))?;
                    return Err(AssistantError::Model(e));
                }
            };
            self.service.audit_model_call(
                &self.actor,
                json!({ "chat": chat_id, "provider": provider_name(cfg.provider), "host": sent.host,
                        "model": cfg.model, "bytes_sent": sent.bytes_sent }),
                "allow",
            )?;
            let reply = sent.reply;
            let uses: Vec<(String, String, Value)> =
                reply.tool_uses().map(|(i, n, v)| (i.to_string(), n.to_string(), v.clone())).collect();
            all.push(reply);
            if uses.is_empty() {
                break;
            }
            let mut results = Vec::new();
            for (id, name, input) in uses {
                let (content, is_error) = match pm_mcp::call_tool(&self.service, &self.actor, &name, input).await {
                    Ok(v) => (v.to_string(), false),
                    Err(e) => (e, true),
                };
                results.push(Block::ToolResult { tool_use_id: id, content: cut(&content), is_error });
            }
            all.push(Message { role: Role::User, content: results });
            self.service.chat_save(chat_id, &json!(all))?;
            if step + 1 == cfg.max_steps {
                note = Some(format!("Stopped after {} model calls; send a message to continue.", cfg.max_steps));
            }
        }
        self.service.chat_save(chat_id, &json!(all))?;
        Ok(Turn { chat_id, messages: all.split_off(start), note })
    }
}

pub(crate) fn cut(s: &str) -> String {
    if s.len() <= MAX_TOOL_RESULT {
        return s.to_string();
    }
    let mut end = MAX_TOOL_RESULT;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [cut: {} more bytes; ask for less, e.g. a smaller view or limit]", &s[..end], s.len() - end)
}

pub(crate) fn host_of(base_url: &str) -> String {
    url::Url::parse(base_url).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default()
}

pub(crate) fn provider_name(p: ProviderKind) -> &'static str {
    match p {
        ProviderKind::Anthropic => "anthropic",
        ProviderKind::Openai => "openai-compatible",
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn local_urls() {
        for u in [
            "http://127.0.0.1:11434/v1",
            "http://localhost:1234",
            "http://10.0.0.5/v1",
            "http://[::1]:8000",
            "http://gpu.localhost",
        ] {
            assert!(super::is_local_url(u), "{u}");
        }
        for u in ["https://api.anthropic.com/v1", "https://api.openai.com/v1", "http://8.8.8.8", "nonsense"] {
            assert!(!super::is_local_url(u), "{u}");
        }
    }
}
