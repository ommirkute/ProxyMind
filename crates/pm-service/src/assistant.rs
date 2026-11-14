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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// USD per million input and output tokens, for the cost meter (0:
    /// unknown, only tokens are shown). Prices change: copy them from the
    /// provider's pricing page.
    pub price_input: f64,
    pub price_output: f64,
    /// `full` (every tool) or `compact` (a core set, for small local models
    /// that struggle with a long tool list).
    pub tools: ToolProfile,
    /// Model for an AI scan's worker agents (empty: the same model), e.g. a
    /// cheaper one for focused tasks.
    pub worker_model: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolProfile {
    #[default]
    Full,
    Compact,
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
            price_input: 0.0,
            price_output: 0.0,
            tools: ToolProfile::Full,
            worker_model: String::new(),
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

/// Saved model API keys, in the user's home.
const KEYS_FILE: &str = "model-keys.json";

/// Where a model API key comes from (never the key itself).
#[derive(Debug, Clone, Serialize)]
pub struct KeyStatus {
    /// environment, saved or none
    pub source: String,
    /// The last four characters, e.g. "…a1b2".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

fn valid_key_name(name: &str) -> Result<()> {
    let ok = !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(ServiceError::Invalid(
            "the key's name is a variable-style NAME such as ANTHROPIC_API_KEY, not the key itself".into(),
        ))
    }
}

impl Service {
    pub fn assistant_config(&self) -> Result<AssistantConfig> {
        match self.store.read(|db| db.get_setting(ASSISTANT_SETTING))? {
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
        if !cfg.api_key_env.is_empty() {
            valid_key_name(&cfg.api_key_env)?;
        }
        let cfg = AssistantConfig {
            max_steps: cfg.max_steps.clamp(1, 50),
            max_tokens: cfg.max_tokens.clamp(256, 32000),
            price_input: if cfg.price_input.is_finite() { cfg.price_input.clamp(0.0, 10_000.0) } else { 0.0 },
            price_output: if cfg.price_output.is_finite() { cfg.price_output.clamp(0.0, 10_000.0) } else { 0.0 },
            ..cfg
        };
        let text = serde_json::to_string(&cfg).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        self.store.write(|db| db.set_setting(ASSISTANT_SETTING, &text))?;
        self.audit(&actor.id(), "assistant_settings", json!(cfg), "allow")?;
        Ok(cfg)
    }

    /// Saves a model API key under `name` (e.g. ANTHROPIC_API_KEY) in the
    /// user's home (`model-keys.json`, readable by the owner only): never in
    /// the project, never sent back by the API, never visible to agents. An
    /// environment variable of the same name still wins. People only; the
    /// audit log records that it changed, not the value.
    pub fn model_key_set(&self, actor: &Actor, name: &str, key: &str) -> Result<KeyStatus> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only people can set model API keys".into()));
        }
        valid_key_name(name)?;
        let key = key.trim();
        if key.is_empty() || key.len() > 1024 || key.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ServiceError::Invalid("paste the API key itself (no spaces or line breaks)".into()));
        }
        let mut keys = self.model_keys()?;
        keys.insert(name.to_string(), key.to_string());
        self.save_model_keys(&keys)?;
        self.audit(&actor.id(), "model_key_set", json!({ "name": name }), "allow")?;
        Ok(self.model_key_status(name))
    }

    /// Removes a saved key. People only.
    pub fn model_key_remove(&self, actor: &Actor, name: &str) -> Result<KeyStatus> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only people can remove model API keys".into()));
        }
        let mut keys = self.model_keys()?;
        if keys.remove(name).is_some() {
            self.save_model_keys(&keys)?;
            self.audit(&actor.id(), "model_key_remove", json!({ "name": name }), "allow")?;
        }
        Ok(self.model_key_status(name))
    }

    /// The key to use for `name`: the environment variable, else the saved
    /// key. For the code that calls the model only; never returned by the API.
    pub fn model_key(&self, name: &str) -> Option<String> {
        if name.is_empty() {
            return None;
        }
        std::env::var(name)
            .ok()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
            .or_else(|| self.model_keys().ok()?.remove(name))
    }

    /// Where the key for `name` comes from, with its last four characters.
    pub fn model_key_status(&self, name: &str) -> KeyStatus {
        let hint = |k: &str| {
            let tail: String = k.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
            format!("…{tail}")
        };
        if name.is_empty() {
            return KeyStatus { source: "none".into(), hint: None };
        }
        if let Ok(k) = std::env::var(name)
            && !k.trim().is_empty()
        {
            return KeyStatus { source: "environment".into(), hint: Some(hint(k.trim())) };
        }
        match self.model_keys().ok().and_then(|mut m| m.remove(name)) {
            Some(k) => KeyStatus { source: "saved".into(), hint: Some(hint(&k)) },
            None => KeyStatus { source: "none".into(), hint: None },
        }
    }

    fn model_keys_path(&self) -> Result<std::path::PathBuf> {
        self.plugin_home
            .get()
            .map(|h| h.join(KEYS_FILE))
            .ok_or_else(|| ServiceError::Invalid("no ProxyMind home directory in this process to save keys in".into()))
    }

    fn model_keys(&self) -> Result<std::collections::BTreeMap<String, String>> {
        let Ok(path) = self.model_keys_path() else { return Ok(Default::default()) };
        match std::fs::read_to_string(&path) {
            Ok(t) => Ok(serde_json::from_str(&t).unwrap_or_default()),
            Err(_) => Ok(Default::default()),
        }
    }

    fn save_model_keys(&self, keys: &std::collections::BTreeMap<String, String>) -> Result<()> {
        let path = self.model_keys_path()?;
        let text = serde_json::to_string_pretty(keys).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let tmp = path.with_extension("json.tmp");
        {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp).map_err(|e| ServiceError::Invalid(format!("saving the key: {e}")))?;
            std::io::Write::write_all(&mut f, text.as_bytes())
                .map_err(|e| ServiceError::Invalid(format!("saving the key: {e}")))?;
        }
        std::fs::rename(&tmp, &path).map_err(|e| ServiceError::Invalid(format!("saving the key: {e}")))?;
        Ok(())
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
        Ok(self.store.write(|db| db.create_chat(&title, now_ms()))?)
    }

    pub fn chat_save(&self, id: i64, messages: &Value) -> Result<()> {
        Ok(self.store.write(|db| db.save_chat(id, &messages.to_string(), now_ms()))?)
    }

    pub fn chat_get(&self, id: i64) -> Result<Chat> {
        let (title, messages, created_ms, updated_ms) =
            self.store.read(|db| db.get_chat(id))?.ok_or_else(|| ServiceError::NotFound(format!("chat {id}")))?;
        let messages = serde_json::from_str(&messages).unwrap_or(Value::Array(vec![]));
        Ok(Chat { id, title, created_ms, updated_ms, messages })
    }

    pub fn chat_list(&self, limit: usize) -> Result<Vec<ChatSummary>> {
        Ok(self
            .store
            .read(|db| db.list_chats(limit))?
            .into_iter()
            .map(|(id, title, updated_ms)| ChatSummary { id, title, updated_ms })
            .collect())
    }
}

impl AssistantConfig {
    /// The cost of a call in millionths of a dollar (0 when no price is set).
    pub fn cost_micros(&self, tokens_in: u64, tokens_out: u64) -> i64 {
        (tokens_in as f64 * self.price_input + tokens_out as f64 * self.price_output).round() as i64
    }
}
