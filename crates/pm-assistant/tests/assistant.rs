//! The assistant against scripted mock model servers.

use std::sync::{Arc, Mutex};

use pm_assistant::llm::{Block, Role};
use pm_assistant::{Assistant, AssistantError};
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{AssistantConfig, ProviderKind, Service};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A model server that answers with `replies` in order (the last one
/// repeats) and records each request (head, JSON body).
async fn mock_model(replies: Vec<Value>) -> (u16, Arc<Mutex<Vec<(String, Value)>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<(String, Value)>>> = Arc::default();
    let seen2 = seen.clone();
    tokio::spawn(async move {
        let mut n = 0;
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 8192];
            let (head, body) = loop {
                let k = s.read(&mut tmp).await.unwrap();
                buf.extend_from_slice(&tmp[..k]);
                if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let len: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    while buf.len() < end + 4 + len {
                        let k = s.read(&mut tmp).await.unwrap();
                        buf.extend_from_slice(&tmp[..k]);
                    }
                    break (head, serde_json::from_slice::<Value>(&buf[end + 4..end + 4 + len]).unwrap());
                }
            };
            seen2.lock().unwrap().push((head, body));
            let reply = replies[n.min(replies.len() - 1)].to_string();
            n += 1;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            s.write_all(resp.as_bytes()).await.unwrap();
        }
    });
    (port, seen)
}

fn service(allow_cloud: bool) -> Arc<Service> {
    let roe =
        format!("version: 1\nscope:\n  include: [\"http://shop.test/\"]\ndata:\n  allow_cloud_models: {allow_cloud}\n");
    Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap())
}

fn configure(svc: &Service, provider: ProviderKind, base_url: String, key_env: &str, max_steps: u32) {
    let human = Actor::parse("human:tester").unwrap();
    let cfg = AssistantConfig {
        provider,
        base_url,
        model: "test-model".into(),
        api_key_env: key_env.into(),
        max_steps,
        max_tokens: 1000,
    };
    svc.assistant_config_set(&human, cfg).unwrap();
}

fn openai_tool_call(name: &str, args: Value) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[
        {"id":"call_1","type":"function","function":{"name":name,"arguments":args.to_string()}}]}}]})
}

fn openai_text(t: &str) -> Value {
    json!({"choices":[{"message":{"role":"assistant","content":t}}]})
}

#[tokio::test]
async fn openai_compatible_tool_loop() {
    let svc = service(false);
    let (port, seen) =
        mock_model(vec![openai_tool_call("roe_get", json!({})), openai_text("Only http://shop.test/ is in scope.")])
            .await;
    configure(&svc, ProviderKind::Openai, format!("http://127.0.0.1:{port}/v1"), "", 12);
    let a = Assistant::new(svc.clone()).unwrap();
    let turn = a.send(None, "What is in scope?").await.unwrap();

    let roles: Vec<Role> = turn.messages.iter().map(|m| m.role).collect();
    assert_eq!(roles, [Role::User, Role::Assistant, Role::User, Role::Assistant]);
    let Block::ToolResult { content, is_error, .. } = &turn.messages[2].content[0] else { panic!("no tool result") };
    assert!(!is_error && content.contains("shop.test"), "{content}");
    assert!(matches!(&turn.messages[3].content[0], Block::Text { text } if text.contains("in scope")));

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].0.starts_with("POST /v1/chat/completions HTTP/1.1"));
    assert!(!seen[0].0.contains("Authorization"), "no key configured");
    assert_eq!(seen[0].1["model"], "test-model");
    assert!(seen[0].1["tools"].as_array().unwrap().iter().any(|t| t["function"]["name"] == "replay_send"));
    let second = seen[1].1["messages"].as_array().unwrap();
    assert!(second.iter().any(|m| m["role"] == "tool" && m["content"].as_str().unwrap().contains("shop.test")));
    drop(seen);

    // Persisted, and every model call audited.
    let chat = svc.chat_get(turn.chat_id).unwrap();
    assert_eq!(chat.title, "What is in scope?");
    assert_eq!(chat.messages.as_array().unwrap().len(), 4);
    let audit = svc.audit_list(50).unwrap();
    assert_eq!(audit.iter().filter(|r| r.action == "assistant_model_call" && r.decision == "allow").count(), 2);
}

#[tokio::test]
async fn anthropic_format_key_from_env_and_policy_applies_to_tools() {
    let svc = service(false);
    let (port, seen) = mock_model(vec![
        json!({"content":[{"type":"tool_use","id":"tu_1","name":"replay_send",
            "input":{"url":"https://evil.example","raw":"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"}}],"stop_reason":"tool_use"}),
        json!({"content":[{"type":"text","text":"That host is out of scope."}],"stop_reason":"end_turn"}),
    ])
    .await;
    // PATH exists everywhere; it stands in for an API key variable.
    configure(&svc, ProviderKind::Anthropic, format!("http://localhost:{port}/v1"), "PATH", 12);
    let a = Assistant::new(svc).unwrap();
    let turn = a.send(None, "Try evil.example").await.unwrap();
    let Block::ToolResult { content, .. } = &turn.messages[2].content[0] else { panic!("no tool result") };
    assert!(content.contains("denied"), "the policy gate refused the out-of-scope send: {content}");

    let seen = seen.lock().unwrap();
    let head = &seen[0].0;
    assert!(head.starts_with("POST /v1/messages HTTP/1.1") && head.contains("anthropic-version: 2023-06-01"));
    assert!(head.contains(&format!("x-api-key: {}", std::env::var("PATH").unwrap().trim())));
    assert_eq!(seen[1].1["messages"][2]["content"][0]["type"], "tool_result");
}

#[tokio::test]
async fn cloud_models_need_permission_and_keys_must_be_set() {
    let svc = service(false);
    configure(&svc, ProviderKind::Anthropic, "https://api.anthropic.com/v1".into(), "", 12);
    let a = Assistant::new(svc.clone()).unwrap();
    let e = a.send(None, "hi").await.err().unwrap();
    assert!(matches!(e, AssistantError::Refused(_)), "{e}");
    assert!(svc.audit_list(10).unwrap().iter().any(|r| r.action == "assistant_model_call" && r.decision == "deny"));
    assert!(svc.chat_list(10).unwrap().is_empty(), "nothing was started");

    let allowed = service(true);
    configure(
        &allowed,
        ProviderKind::Anthropic,
        "https://api.anthropic.com/v1".into(),
        "PM_TEST_KEY_THAT_IS_NOT_SET",
        12,
    );
    let e = Assistant::new(allowed).unwrap().send(None, "hi").await.err().unwrap();
    assert!(e.to_string().contains("PM_TEST_KEY_THAT_IS_NOT_SET"), "{e}");

    let human = Actor::parse("human:x").unwrap();
    let bad = AssistantConfig { api_key_env: "sk-live-1234".into(), ..AssistantConfig::default() };
    assert!(svc.assistant_config_set(&human, bad).is_err(), "a key pasted as the variable name is refused");
}

#[tokio::test]
async fn step_limit_stops_a_looping_model() {
    let svc = service(false);
    let (port, seen) = mock_model(vec![openai_tool_call("roe_get", json!({}))]).await;
    configure(&svc, ProviderKind::Openai, format!("http://127.0.0.1:{port}/v1"), "", 3);
    let turn = Assistant::new(svc).unwrap().send(None, "loop").await.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 3);
    assert!(turn.note.unwrap().contains("Stopped after 3"));
}

#[tokio::test]
async fn a_key_saved_in_proxymind_is_used_and_never_shown() {
    let svc = service(false);
    let home = std::env::temp_dir().join(format!("pm-keys-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    svc.attach_plugin_home(home.clone());
    let (port, seen) =
        mock_model(vec![json!({"content":[{"type":"text","text":"Hello."}],"stop_reason":"end_turn"})]).await;
    // A variable name nobody sets: the key has to come from ProxyMind's own store.
    let name = "PM_TEST_SAVED_KEY_ONLY";
    configure(&svc, ProviderKind::Anthropic, format!("http://localhost:{port}/v1"), name, 4);
    let a = Assistant::new(svc.clone()).unwrap();
    let err = a.send(None, "hi").await.unwrap_err();
    assert!(err.to_string().contains("assistant settings"), "{err}");

    let agent = Actor::parse("agent:claude").unwrap();
    assert!(svc.model_key_set(&agent, name, "sk-test-123456").is_err(), "agents can't set keys");
    assert!(svc.model_key_set(&Actor::parse("human:tester").unwrap(), "not a name!", "k").is_err());
    let st = svc.model_key_set(&Actor::parse("human:tester").unwrap(), name, "sk-test-123456").unwrap();
    assert_eq!((st.source.as_str(), st.hint.as_deref()), ("saved", Some("…3456")));
    a.send(None, "hi").await.unwrap();
    let seen = seen.lock().unwrap();
    assert!(seen[0].0.to_ascii_lowercase().contains("x-api-key: sk-test-123456"), "{}", seen[0].0);
    drop(seen);

    // On disk in the home folder, owner-only, never in the project or the audit log.
    let path = home.join("model-keys.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let audit = serde_json::to_string(&svc.audit_list(100).unwrap()).unwrap();
    assert!(!audit.contains("sk-test-123456"));
    svc.model_key_remove(&Actor::parse("human:tester").unwrap(), name).unwrap();
    assert_eq!(svc.model_key_status(name).source, "none");
    let _ = std::fs::remove_dir_all(&home);
}
