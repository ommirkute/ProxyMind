//! Talking to language models: a provider-neutral message format, the
//! Anthropic and OpenAI-compatible wire formats, and the HTTP call itself
//! (through ProxyMind's own sender, so network settings apply).

use anyhow::{Context, Result, anyhow, bail};
use pm_service::ProviderKind;
use pm_service::pm_replay::{Endpoint, Sender};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    User,
    Assistant,
}

/// One piece of a message. The shape matches Anthropic's content blocks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Block {
    Text { text: String },
    ToolUse { id: String, name: String, input: Value },
    ToolResult { tool_use_id: String, content: String, is_error: bool },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Vec<Block>,
}

impl Message {
    pub fn user_text(text: &str) -> Self {
        Self { role: Role::User, content: vec![Block::Text { text: text.to_string() }] }
    }

    pub fn tool_uses(&self) -> impl Iterator<Item = (&str, &str, &Value)> {
        self.content.iter().filter_map(|b| match b {
            Block::ToolUse { id, name, input } => Some((id.as_str(), name.as_str(), input)),
            _ => None,
        })
    }
}

/// What to send: everything a provider needs for one call.
pub struct Call<'a> {
    pub model: &'a str,
    pub max_tokens: u32,
    pub system: &'a str,
    /// MCP tool definitions (`name`, `description`, `inputSchema`).
    pub tools: &'a [Value],
    pub messages: &'a [Message],
}

pub fn anthropic_body(c: &Call<'_>) -> Value {
    let tools: Vec<Value> = c
        .tools
        .iter()
        .map(|t| json!({ "name": t["name"], "description": t["description"], "input_schema": t["inputSchema"] }))
        .collect();
    let mut body = json!({
        "model": c.model,
        "max_tokens": c.max_tokens,
        "system": c.system,
        "messages": c.messages,
    });
    if !tools.is_empty() {
        body["tools"] = json!(tools);
    }
    body
}

pub fn parse_anthropic(v: &Value) -> Result<Message> {
    let blocks = v["content"].as_array().ok_or_else(|| anyhow!("no content in the model's reply"))?;
    let content = blocks
        .iter()
        .filter_map(|b| match b["type"].as_str() {
            Some("text") => Some(Block::Text { text: b["text"].as_str().unwrap_or_default().to_string() }),
            Some("tool_use") => Some(Block::ToolUse {
                id: b["id"].as_str().unwrap_or_default().to_string(),
                name: b["name"].as_str().unwrap_or_default().to_string(),
                input: b["input"].clone(),
            }),
            _ => None, // thinking and other block types aren't kept
        })
        .collect();
    Ok(Message { role: Role::Assistant, content })
}

pub fn openai_body(c: &Call<'_>) -> Value {
    let tools: Vec<Value> = c
        .tools
        .iter()
        .map(|t| {
            json!({ "type": "function", "function": {
                "name": t["name"], "description": t["description"], "parameters": t["inputSchema"] } })
        })
        .collect();
    let mut messages = vec![json!({ "role": "system", "content": c.system })];
    for m in c.messages {
        let text: Vec<&str> = m
            .content
            .iter()
            .filter_map(|b| match b {
                Block::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .collect();
        match m.role {
            Role::User => {
                for b in &m.content {
                    if let Block::ToolResult { tool_use_id, content, .. } = b {
                        messages.push(json!({ "role": "tool", "tool_call_id": tool_use_id, "content": content }));
                    }
                }
                if !text.is_empty() {
                    messages.push(json!({ "role": "user", "content": text.join("\n\n") }));
                }
            }
            Role::Assistant => {
                let calls: Vec<Value> = m
                    .tool_uses()
                    .map(|(id, name, input)| {
                        json!({ "id": id, "type": "function",
                                "function": { "name": name, "arguments": input.to_string() } })
                    })
                    .collect();
                let mut msg = json!({ "role": "assistant", "content": if text.is_empty() { Value::Null } else { json!(text.join("\n\n")) } });
                if !calls.is_empty() {
                    msg["tool_calls"] = json!(calls);
                }
                messages.push(msg);
            }
        }
    }
    let mut body = json!({ "model": c.model, "max_tokens": c.max_tokens, "messages": messages });
    // OpenAI refuses an empty tool list.
    if !tools.is_empty() {
        body["tools"] = json!(tools);
    }
    body
}

pub fn parse_openai(v: &Value) -> Result<Message> {
    let m = &v["choices"][0]["message"];
    if m.is_null() {
        bail!("no choices in the model's reply");
    }
    let mut content = Vec::new();
    if let Some(t) = m["content"].as_str().filter(|t| !t.trim().is_empty()) {
        content.push(Block::Text { text: t.to_string() });
    }
    for (i, c) in m["tool_calls"].as_array().into_iter().flatten().enumerate() {
        let args = c["function"]["arguments"].as_str().unwrap_or("{}");
        // Some servers send arguments as an object instead of a string.
        let input = serde_json::from_str(args).unwrap_or_else(|_| {
            if c["function"]["arguments"].is_object() { c["function"]["arguments"].clone() } else { json!({}) }
        });
        let id = c["id"].as_str().map_or_else(|| format!("call_{i}"), str::to_string);
        content.push(Block::ToolUse {
            id,
            name: c["function"]["name"].as_str().unwrap_or_default().to_string(),
            input,
        });
    }
    Ok(Message { role: Role::Assistant, content })
}

/// Where to send, and what was sent (for the audit log).
pub struct Sent {
    pub reply: Message,
    pub bytes_sent: usize,
    pub host: String,
    pub usage: Usage,
}

/// Tokens a call used, as the API reported them (or estimated from sizes,
/// about 4 bytes a token, when it didn't).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub input: u64,
    pub output: u64,
    pub estimated: bool,
}

/// Reads the usage block of an Anthropic or OpenAI-style reply.
pub fn usage_of(v: &Value) -> Option<Usage> {
    let u = &v["usage"];
    let n = |k: &str| u[k].as_u64();
    if let (Some(i), Some(o)) = (n("input_tokens"), n("output_tokens")) {
        let cached = n("cache_read_input_tokens").unwrap_or(0) + n("cache_creation_input_tokens").unwrap_or(0);
        return Some(Usage { input: i + cached, output: o, estimated: false });
    }
    if let (Some(i), Some(o)) = (n("prompt_tokens"), n("completion_tokens")) {
        return Some(Usage { input: i, output: o, estimated: false });
    }
    None
}

/// One model call.
pub async fn call(
    sender: &Sender,
    provider: ProviderKind,
    base_url: &str,
    api_key: Option<&str>,
    c: &Call<'_>,
) -> Result<Sent> {
    let url = url::Url::parse(base_url).context("assistant base URL")?;
    let host = url.host_str().ok_or_else(|| anyhow!("the base URL has no host"))?.trim_matches(['[', ']']).to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let base_path = url.path().trim_end_matches('/');
    let (path, body) = match provider {
        ProviderKind::Anthropic => (format!("{base_path}/messages"), anthropic_body(c)),
        ProviderKind::Openai => (format!("{base_path}/chat/completions"), openai_body(c)),
    };
    let body = body.to_string();
    let authority = pm_core::authority(url.scheme(), &host, port);
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nAccept: application/json\r\n\
         User-Agent: ProxyMind/{}\r\nConnection: close\r\nContent-Length: {}\r\n",
        env!("CARGO_PKG_VERSION"),
        body.len()
    );
    match provider {
        ProviderKind::Anthropic => {
            req.push_str("anthropic-version: 2023-06-01\r\n");
            if let Some(k) = api_key {
                req.push_str(&format!("x-api-key: {k}\r\n"));
            }
        }
        ProviderKind::Openai => {
            if let Some(k) = api_key {
                req.push_str(&format!("Authorization: Bearer {k}\r\n"));
            }
        }
    }
    req.push_str("\r\n");
    req.push_str(&body);
    let ep = Endpoint::new(url.scheme(), &host, port);
    let resp = sender.send(&ep, req.as_bytes(), "POST", None).await.with_context(|| format!("calling {authority}"))?;
    let mut data = pm_http::split_message(&resp.raw).1.to_vec();
    let chunked = pm_http::header(&resp.head.headers, "transfer-encoding")
        .is_some_and(|v| String::from_utf8_lossy(v).to_ascii_lowercase().contains("chunked"));
    if chunked && let Some(d) = pm_http::decode_chunked(&data) {
        data = d;
    }
    if !(200..300).contains(&resp.head.status) {
        let text: String = String::from_utf8_lossy(&data).chars().take(400).collect();
        bail!("the model API answered {}: {text}", resp.head.status);
    }
    let v: Value = serde_json::from_slice(&data).context("the model API sent invalid JSON")?;
    let reply = match provider {
        ProviderKind::Anthropic => parse_anthropic(&v)?,
        ProviderKind::Openai => parse_openai(&v)?,
    };
    let usage = usage_of(&v).unwrap_or(Usage {
        input: body.len() as u64 / 4,
        output: serde_json::to_string(&reply.content).map_or(0, |t| t.len() as u64 / 4),
        estimated: true,
    });
    Ok(Sent { reply, bytes_sent: body.len(), host, usage })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn convo() -> Vec<Message> {
        vec![
            Message::user_text("What is in scope?"),
            Message {
                role: Role::Assistant,
                content: vec![
                    Block::Text { text: "Let me check.".into() },
                    Block::ToolUse { id: "t1".into(), name: "roe_get".into(), input: json!({}) },
                ],
            },
            Message {
                role: Role::User,
                content: vec![Block::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "{\"in_scope\":[]}".into(),
                    is_error: false,
                }],
            },
        ]
    }

    fn call_of<'a>(m: &'a [Message], tools: &'a [Value]) -> Call<'a> {
        Call { model: "m", max_tokens: 100, system: "sys", tools, messages: m }
    }

    #[test]
    fn anthropic_round_trip() {
        let m = convo();
        let tools = vec![json!({"name":"roe_get","description":"d","inputSchema":{"type":"object"}})];
        let body = anthropic_body(&call_of(&m, &tools));
        assert_eq!(body["system"], "sys");
        assert_eq!(body["tools"][0]["input_schema"]["type"], "object");
        assert_eq!(body["messages"][1]["content"][1]["type"], "tool_use");
        assert_eq!(body["messages"][2]["content"][0]["tool_use_id"], "t1");
        let reply = json!({"content":[{"type":"thinking","thinking":"x"},{"type":"text","text":"Done"},
            {"type":"tool_use","id":"t2","name":"history_search","input":{"limit":5}}],"stop_reason":"tool_use"});
        let msg = parse_anthropic(&reply).unwrap();
        assert_eq!(msg.content.len(), 2);
        assert_eq!(msg.tool_uses().next().unwrap(), ("t2", "history_search", &json!({"limit":5})));
    }

    #[test]
    fn openai_round_trip() {
        let m = convo();
        let tools = vec![json!({"name":"roe_get","description":"d","inputSchema":{"type":"object"}})];
        let body = openai_body(&call_of(&m, &tools));
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0], json!({"role":"system","content":"sys"}));
        assert_eq!(msgs[2]["tool_calls"][0]["function"]["name"], "roe_get");
        assert_eq!(msgs[2]["content"], "Let me check.");
        assert_eq!(msgs[3], json!({"role":"tool","tool_call_id":"t1","content":"{\"in_scope\":[]}"}));
        assert_eq!(body["tools"][0]["function"]["parameters"]["type"], "object");
        let reply = json!({"choices":[{"message":{"role":"assistant","content":null,
            "tool_calls":[{"id":"c1","type":"function","function":{"name":"history_search","arguments":"{\"limit\":3}"}}]}}]});
        let msg = parse_openai(&reply).unwrap();
        assert_eq!(msg.tool_uses().next().unwrap(), ("c1", "history_search", &json!({"limit":3})));
        let ollama = json!({"choices":[{"message":{"content":"","tool_calls":[{"function":{"name":"roe_get","arguments":{}}}]}}]});
        assert_eq!(parse_openai(&ollama).unwrap().tool_uses().next().unwrap().0, "call_0");
    }
}
