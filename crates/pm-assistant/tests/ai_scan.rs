//! The AI scan loop against a scripted mock model: phases, notes, findings,
//! the report, budgets and stopping, all as agent:ai-scan-<id> through the
//! policy gate.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pm_assistant::Assistant;
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{AiScan, AiScanRequest, AssistantConfig, ProviderKind, Service};
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

async fn finished(svc: &Service, id: i64) -> AiScan {
    for _ in 0..200 {
        let sc = svc.ai_scan_get(id).unwrap();
        if !matches!(sc.status.as_str(), "running" | "stopping") {
            return sc;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the scan didn't finish: {:?}", svc.ai_scan_get(id).unwrap().status);
}

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

#[tokio::test]
async fn a_scan_runs_through_phases_to_a_report() {
    let svc = service(false);
    let (port, seen) = mock_model(vec![
        openai_tool_call("ai_scan_phase", json!({"phase": "recon", "notes": "starting"})),
        openai_tool_call("roe_get", json!({})),
        openai_tool_call(
            "ai_scan_note",
            json!({"kind": "loopback", "text": "LOOPBACK: returning to phase 1 because /api appeared"}),
        ),
        openai_tool_call(
            "finding_create",
            json!({"title": "Server version disclosed", "vuln_class": "exposure",
            "severity": "low", "description": "The Server header names the version.", "url": "http://shop.test/"}),
        ),
        openai_tool_call("ai_scan_report", json!({"markdown": "# Report\n\n## Executive summary\nOne low finding."})),
        openai_text("Done."),
    ])
    .await;
    configure(&svc, ProviderKind::Openai, format!("http://127.0.0.1:{port}/v1"), "", 12);
    let a = Arc::new(Assistant::new(svc.clone()).unwrap());
    let scan =
        a.start_ai_scan(&human(), AiScanRequest { focus: Some("the API".into()), ..Default::default() }).unwrap();
    assert_eq!(scan.target, "http://shop.test/");
    let sc = finished(&svc, scan.id).await;

    assert_eq!(sc.status, "done", "{}", sc.error);
    assert_eq!(sc.phase, "report");
    assert!(sc.report.starts_with("# Report"));
    assert_eq!(sc.findings, 1, "the finding is the scan agent's: {:?}", sc.log);
    assert_eq!(sc.steps, 6);
    let kinds: Vec<&str> = sc.log.iter().map(|l| l.kind.as_str()).collect();
    assert!(kinds.contains(&"loopback") && kinds.contains(&"tool"), "{kinds:?}");
    // The system prompt is the AI scan prompt with the target, scope and focus filled in.
    let seen = seen.lock().unwrap();
    let system = seen[0].1["messages"][0]["content"].as_str().unwrap();
    assert!(system.contains("AI scan agent") && system.contains("Target: http://shop.test/"));
    assert!(system.contains("Focus: the API"));
    assert!(["{{target}}", "{{scope}}", "{{focus}}"].iter().all(|t| !system.contains(t)), "every field is filled");
    assert!(seen[0].1["tools"].as_array().unwrap().iter().any(|t| t["function"]["name"] == "ai_scan_report"));
    drop(seen);
    // Everything ran as the scan's own agent.
    let audit = svc.audit_list(200).unwrap();
    assert!(
        audit.iter().any(|r| r.actor == format!("agent:ai-scan-{}", scan.id) && r.action == "assistant_model_call")
    );
    assert_eq!(svc.finding_list(None).unwrap()[0]["actor"], format!("agent:ai-scan-{}", scan.id));
}

#[tokio::test]
async fn budgets_end_a_scan_with_a_last_call_for_the_report() {
    let svc = service(false);
    let (port, seen) = mock_model(vec![openai_tool_call("roe_get", json!({}))]).await;
    configure(&svc, ProviderKind::Openai, format!("http://127.0.0.1:{port}/v1"), "", 12);
    let a = Arc::new(Assistant::new(svc.clone()).unwrap());
    let scan = a.start_ai_scan(&human(), AiScanRequest { max_steps: Some(3), ..Default::default() }).unwrap();
    let sc = finished(&svc, scan.id).await;
    assert_eq!(sc.status, "done");
    assert!(sc.log.iter().any(|l| l.kind == "stop" && l.text.contains("step budget")), "{:?}", sc.log);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 4, "three steps and one last call for the report");
    let last = seen[3].1["messages"].as_array().unwrap();
    assert!(last.last().unwrap()["content"].as_str().unwrap().contains("budget is used up"));
    // The warning near the end of the budget rode along with the tool results.
    assert!(
        seen[1].1["messages"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["content"].as_str().is_some_and(|c| c.contains("model calls left")))
    );
}

#[tokio::test]
async fn a_person_can_stop_a_scan_and_only_people_start_one() {
    let svc = service(false);
    let (port, _) = mock_model(vec![openai_tool_call("roe_get", json!({}))]).await;
    configure(&svc, ProviderKind::Openai, format!("http://127.0.0.1:{port}/v1"), "", 12);
    let a = Arc::new(Assistant::new(svc.clone()).unwrap());
    let agent = Actor::parse("agent:claude").unwrap();
    assert!(a.start_ai_scan(&agent, AiScanRequest::default()).is_err(), "agents can't start one");
    let out_of_scope = AiScanRequest { target: Some("https://evil.example/".into()), ..Default::default() };
    assert!(a.start_ai_scan(&human(), out_of_scope).is_err(), "the target must be in scope");
    let scan = a.start_ai_scan(&human(), AiScanRequest { max_steps: Some(1000), ..Default::default() }).unwrap();
    assert!(a.start_ai_scan(&human(), AiScanRequest::default()).is_err(), "one at a time");
    tokio::time::sleep(Duration::from_millis(150)).await;
    svc.ai_scan_stop(&human(), scan.id).unwrap();
    let sc = finished(&svc, scan.id).await;
    assert_eq!(sc.status, "stopped");
    assert!(sc.steps < 1000);
}

#[tokio::test]
async fn cloud_models_need_the_rules_of_engagement() {
    let svc = service(false);
    configure(&svc, ProviderKind::Anthropic, "https://api.anthropic.com/v1".into(), "", 12);
    let a = Arc::new(Assistant::new(svc.clone()).unwrap());
    let e = a.start_ai_scan(&human(), AiScanRequest::default()).unwrap_err();
    assert!(e.to_string().contains("allow_cloud_models"), "{e}");
    assert!(svc.ai_scan_list(10).unwrap().is_empty(), "nothing was started");
}
