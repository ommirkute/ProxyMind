//! Storage and settings for the built-in assistant. The conversation loop
//! itself lives in `pm-assistant`, above the MCP tools it uses.

use pm_core::now_ms;
use pm_policy::{Actor, ActorKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError};

pub const ASSISTANT_SETTING: &str = "assistant";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    /// Anthropic Messages API.
    Anthropic,
    /// OpenAI Chat Completions, and compatible servers (Ollama, LM Studio, vLLM).
    #[default]
    Openai,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AssistantConfig {
    pub provider: ProviderKind,
    /// API base, e.g. `https://api.anthropic.com/v1` or `http://127.0.0.1:11434/v1`.
    pub base_url: String,
    pub model: String,
    /// Name of the environment variable holding the API key (the key itself
    /// is never stored in the project). Empty: no key (local servers).
    pub api_key_env: String,
    /// Most model calls per message, so a confused model can't loop forever.
    pub max_steps: u32,
    pub max_tokens: u32,
}

impl Default for AssistantConfig {
    fn default() -> Self {
        // Local by default: Ollama's OpenAI-compatible endpoint.
        Self {
            provider: ProviderKind::Openai,
            base_url: "http://127.0.0.1:11434/v1".into(),
            model: String::new(),
            api_key_env: String::new(),
            max_steps: 12,
            max_tokens: 2048,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatSummary {
    pub id: i64,
    pub title: String,
    pub updated_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Chat {
    pub id: i64,
    pub title: String,
    pub created_ms: i64,
    pub updated_ms: i64,
    /// The assistant's own message format (see pm-assistant).
    pub messages: Value,
}

impl Service {
    pub fn assistant_config(&self) -> Result<AssistantConfig> {
        match self.store.lock().get_setting(ASSISTANT_SETTING)? {
            Some(t) => serde_json::from_str(&t)
                .map_err(|e| ServiceError::Invalid(format!("saved assistant settings are unreadable: {e}"))),
            None => Ok(AssistantConfig::default()),
        }
    }

    /// Humans only; audited.
    pub fn assistant_config_set(&self, actor: &Actor, cfg: AssistantConfig) -> Result<AssistantConfig> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can change the assistant settings".into()));
        }
        let url = url::Url::parse(&cfg.base_url).map_err(|e| ServiceError::Invalid(format!("base URL: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ServiceError::Invalid("the base URL must be http(s)".into()));
        }
        if cfg.model.trim().is_empty() {
            return Err(ServiceError::Invalid("choose a model".into()));
        }
        if !cfg.api_key_env.is_empty() && !cfg.api_key_env.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(ServiceError::Invalid(
                "api_key_env is the NAME of an environment variable, not the key".into(),
            ));
        }
        let cfg = AssistantConfig {
            max_steps: cfg.max_steps.clamp(1, 50),
            max_tokens: cfg.max_tokens.clamp(256, 32000),
            ..cfg
        };
        let text = serde_json::to_string(&cfg).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.lock().set_setting(ASSISTANT_SETTING, &text)?;
        self.audit(&actor.id(), "assistant_settings", json!(cfg), "allow")?;
        Ok(cfg)
    }

    /// Whether the rules of engagement allow sending data to cloud models.
    pub fn cloud_models_allowed(&self) -> bool {
        self.policy.roe().data.allow_cloud_models
    }

    /// Records a call to a language model in the audit log (what was sent
    /// where, never the content).
    pub fn audit_model_call(&self, actor: &Actor, detail: Value, decision: &str) -> Result<()> {
        self.audit(&actor.id(), "assistant_model_call", detail, decision)
    }

    pub fn chat_create(&self, title: &str) -> Result<i64> {
        let title: String = title.chars().take(80).collect();
        Ok(self.store.lock().create_chat(&title, now_ms())?)
    }

    pub fn chat_save(&self, id: i64, messages: &Value) -> Result<()> {
        Ok(self.store.lock().save_chat(id, &messages.to_string(), now_ms())?)
    }

    pub fn chat_get(&self, id: i64) -> Result<Chat> {
        let (title, messages, created_ms, updated_ms) =
            self.store.lock().get_chat(id)?.ok_or_else(|| ServiceError::NotFound(format!("chat {id}")))?;
        let messages = serde_json::from_str(&messages).unwrap_or(Value::Array(vec![]));
        Ok(Chat { id, title, created_ms, updated_ms, messages })
    }

    pub fn chat_list(&self, limit: usize) -> Result<Vec<ChatSummary>> {
        Ok(self
            .store
            .lock()
            .list_chats(limit)?
            .into_iter()
            .map(|(id, title, updated_ms)| ChatSummary { id, title, updated_ms })
            .collect())
    }
}
