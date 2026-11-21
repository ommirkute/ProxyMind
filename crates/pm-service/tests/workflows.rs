//! Workflows (roadmap 2.2) against the demo shop: a login chain, the policy gate (scope, approvals, agents), the
//! per-exchange trigger (rate cap, off the proxy path), the fuzzer option, events and secrets for agents.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_proxy::{Proxy, Recorder};
use pm_service::pm_store::{NewExchange, Store};
use pm_service::{
    Condition, Delivery, Edit, Event, ExtractStep, ExtractType, FuzzerRequest, FuzzerResult, RunStatus, SendStep,
    Service, Step, StepStatus, TransformStep, WorkflowInput, WorkflowRunRequest,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

fn agent() -> Actor {
    Actor::parse("agent:claude").unwrap()
}

fn service(extra_scope: &[u16]) -> Arc<Service> {
    let inc: Vec<String> = extra_scope.iter().map(|p| format!("\"http://127.0.0.1:{p}/\"")).collect();
    let roe = format!(
        "version: 1\nscope:\n  include: [{}]\nlimits:\n  max_rps_per_host: 50\n  max_concurrency: 8\n",
        inc.join(", ")
    );
    Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap())
}

async fn shop() -> (Arc<Service>, u16) {
    let port = pm_demo::VulnShop::start_local().await.unwrap().port();
    (service(&[port]), port)
}

fn cond() -> Condition {
    Condition::default()
}

fn send(port: u16, raw: &str) -> Step {
    Step::Send(SendStep {
        url: Some(format!("http://127.0.0.1:{port}")),
        raw: Some(raw.replace("HOST", &format!("127.0.0.1:{port}"))),
        ..Default::default()
    })
}

const LOGIN: &str = "POST /api/login HTTP/1.1\r\nHost: HOST\r\nContent-Type: application/json\r\n\r\n\
                     {\"username\":\"alice\",\"password\":\"alice123\"}";

fn login_chain(port: u16) -> WorkflowInput {
    WorkflowInput {
        name: "login-and-orders".into(),
        description: "Log in as alice, read an order with the token, check the answer".into(),
        steps: vec![
            send(port, LOGIN),
            Step::Assert(Condition { status: Some("200".into()), ..cond() }),
            Step::Extract(ExtractStep {
                name: "token".into(),
                kind: ExtractType::Json,
                expr: "/token".into(),
                ..Default::default()
            }),
            Step::Transform(TransformStep { name: "auth".into(), value: "Bearer {{token}}".into(), ops: vec![] }),
            send(port, "GET /api/orders/1001 HTTP/1.1\r\nHost: HOST\r\nAuthorization: {{auth}}\r\n\r\n"),
            Step::Assert(Condition {
                status: Some("200".into()),
                body_contains: Some("alice".into()),
                message: Some("alice reads her own order".into()),
                ..cond()
            }),
        ],
    }
}

fn run_req(workflow: &str) -> WorkflowRunRequest {
    WorkflowRunRequest { workflow: workflow.into(), ..Default::default() }
}

fn raw_request(svc: &Service, id: i64) -> String {
    String::from_utf8_lossy(&svc.exchange_raw(id).unwrap().request).into_owned()
}

#[tokio::test]
async fn a_login_chain_extracts_a_token_sends_with_it_and_asserts_on_the_answer() {
    let (svc, port) = shop().await;
    let wf = svc.workflow_create(&human(), login_chain(port)).unwrap();
    assert_eq!(wf.id, 1);
    let run = svc.workflow_run(&human(), run_req("login-and-orders")).await.unwrap();
    assert_eq!(run.status, RunStatus::Ok, "{run:#?}");
    assert_eq!(run.sends, 2);
    assert_eq!(run.exchanges.len(), 2);
    assert_eq!(run.steps.len(), 6);
    assert!(run.assertions.iter().all(|a| a.ok) && run.assertions.len() == 2);
    let token = run.variables["token"].clone();
    assert!(token.len() > 10, "{token}");
    assert_eq!(run.variables["auth"], format!("Bearer {token}"));

    // Both requests are in history as workflow sends by the person who ran it, the second with the token.
    for id in &run.exchanges {
        let ex = svc.exchange_raw(*id).unwrap();
        assert_eq!((ex.summary.source.as_str(), ex.summary.actor_id.as_str()), ("workflow", "human:tester"));
    }
    assert!(raw_request(&svc, run.exchanges[1]).contains(&format!("Authorization: Bearer {token}\r\n")));
    assert!(run.steps[4].exchange_id == Some(run.exchanges[1]));

    // The run is kept, found by id and by workflow, and each send was gated and audited.
    assert_eq!(svc.workflow_run_get(&human(), run.id).unwrap().status, RunStatus::Ok);
    assert_eq!(svc.workflow_runs(&human(), Some("login-and-orders"), 10).unwrap()[0].id, run.id);
    assert_eq!(svc.workflow_runs(&human(), Some("1"), 10).unwrap().len(), 1);
    let audit = svc.audit_list(100).unwrap();
    assert_eq!(audit.iter().filter(|r| r.action == "workflow_send" && r.decision == "allow").count(), 2);
    assert!(audit.iter().any(|r| r.action == "workflow_run"));
    assert!(audit.iter().any(|r| r.action == "workflow_save"));
    assert!(svc.audit_verify().is_ok());
}

#[tokio::test]
async fn a_workflow_can_start_on_an_exchange_and_edit_its_request() {
    let (svc, port) = shop().await;
    let me = human();
    // The chain's login makes an exchange to start from, then a workflow resends the order request as bob's.
    let login = svc.workflow_create(&me, login_chain(port)).unwrap();
    let first = svc.workflow_run(&me, run_req(&login.name)).await.unwrap();
    let order = first.exchanges[1];
    let wf = svc
        .workflow_create(
            &me,
            WorkflowInput {
                name: "resend-order".into(),
                steps: vec![
                    Step::Match(Condition {
                        method: Some("GET".into()),
                        path_contains: Some("/api/orders/".into()),
                        ..cond()
                    }),
                    Step::Extract(ExtractStep {
                        name: "who".into(),
                        kind: ExtractType::Json,
                        expr: "/owner".into(),
                        ..Default::default()
                    }),
                    Step::Send(SendStep {
                        edits: vec![
                            Edit::ReplaceText {
                                find: "/orders/1001".into(),
                                replace: "/orders/1002".into(),
                                regex: false,
                            },
                            Edit::SetHeader { name: "X-Workflow".into(), value: "{{who}}".into() },
                        ],
                        ..Default::default()
                    }),
                    Step::Assert(Condition { var: Some("who".into()), var_equals: Some("alice".into()), ..cond() }),
                ],
                ..Default::default()
            },
        )
        .unwrap();
    let run = svc
        .workflow_run(
            &me,
            WorkflowRunRequest { workflow: wf.name.clone(), exchange_id: Some(order), ..Default::default() },
        )
        .await
        .unwrap();
    assert_eq!(run.status, RunStatus::Ok, "{run:#?}");
    assert_eq!(run.start_exchange, Some(order));
    let sent = raw_request(&svc, run.exchanges[0]);
    assert!(sent.starts_with("GET /api/orders/1002 HTTP/1.1\r\n") && sent.contains("X-Workflow: alice\r\n"), "{sent}");
    assert!(sent.contains("Authorization: Bearer "), "the rest of the request is the recorded one");

    // On an exchange that does not fit the match, the run stops with the reason and sends nothing.
    let other = first.exchanges[0];
    let run = svc
        .workflow_run(
            &me,
            WorkflowRunRequest { workflow: wf.name.clone(), exchange_id: Some(other), ..Default::default() },
        )
        .await
        .unwrap();
    assert_eq!(run.status, RunStatus::Stopped);
    assert!(run.reason.as_deref().unwrap().contains("method is POST"), "{run:?}");
    assert_eq!(run.sends, 0);
    // A workflow that needs an exchange says so.
    assert!(
        svc.workflow_run(
            &me,
            WorkflowRunRequest { workflow: wf.name.clone(), exchange_id: Some(9999), ..Default::default() }
        )
        .await
        .is_err()
    );
    let none = svc.workflow_run(&me, run_req(&wf.name)).await.unwrap();
    assert_eq!(none.status, RunStatus::Stopped, "no current exchange: the match cannot hold: {none:?}");
}

#[tokio::test]
async fn a_send_to_a_target_out_of_scope_is_denied_and_the_run_says_so() {
    let (svc, port) = shop().await;
    // Something that is listening, but not in the rules of engagement.
    let outside = pm_demo::VulnShop::start_local().await.unwrap().port();
    let input = WorkflowInput {
        name: "wander".into(),
        steps: vec![
            send(port, "GET /api/products HTTP/1.1\r\nHost: HOST\r\n\r\n"),
            Step::Send(SendStep {
                url: Some(format!("http://127.0.0.1:{outside}")),
                raw: Some(format!("GET /api/products HTTP/1.1\r\nHost: 127.0.0.1:{outside}\r\n\r\n")),
                ..Default::default()
            }),
            send(port, "GET /never HTTP/1.1\r\nHost: HOST\r\n\r\n"),
        ],
        ..Default::default()
    };
    svc.workflow_create(&human(), input).unwrap();
    let before = svc.counters().unwrap().exchanges;
    let run = svc.workflow_run(&human(), run_req("wander")).await.unwrap();
    assert_eq!(run.status, RunStatus::Denied, "{run:#?}");
    assert_eq!(run.steps.last().unwrap().status, StepStatus::Denied);
    assert_eq!(run.steps.len(), 2, "the third step never ran");
    assert!(run.reason.as_deref().unwrap().to_lowercase().contains("scope"), "{:?}", run.reason);
    assert_eq!(svc.counters().unwrap().exchanges, before + 1, "only the allowed send went out");
    let audit = svc.audit_list(50).unwrap();
    assert!(audit.iter().any(|r| r.action == "workflow_send" && r.decision == "deny"));

    // The target of a send cannot come from a response.
    let bad = WorkflowInput {
        name: "ssrf".into(),
        steps: vec![Step::Send(SendStep { url: Some("http://{{host}}".into()), ..Default::default() })],
        ..Default::default()
    };
    assert!(svc.workflow_create(&human(), bad).is_err());
}

#[tokio::test]
async fn an_agents_run_that_needs_approval_pauses_and_continues_from_that_step() {
    let (svc, port) = shop().await;
    let mut input = login_chain(port);
    input.name = "agent-flow".into();
    // A plain GET first (allowed for agents), then the POST login (needs approval by default).
    input.steps.insert(0, send(port, "GET /api/products HTTP/1.1\r\nHost: HOST\r\n\r\n"));
    svc.workflow_create(&human(), input).unwrap();

    let a = agent();
    let run = svc.workflow_run(&a, run_req("agent-flow")).await.unwrap();
    assert_eq!(run.status, RunStatus::PendingApproval, "{run:#?}");
    let p = run.pending.clone().unwrap();
    assert_eq!((p.step, p.sends), (2, 1));
    assert_eq!(run.steps.last().unwrap().status, StepStatus::PendingApproval);
    assert_eq!(run.sends, 1, "only the GET went out");

    // Not approved yet: the run stays paused on the same approval, and nothing was sent.
    let req = |id: &str| WorkflowRunRequest {
        workflow: "agent-flow".into(),
        approval_id: Some(id.into()),
        ..Default::default()
    };
    let again = svc.workflow_run(&a, req(&p.approval_id)).await.unwrap();
    assert_eq!(again.status, RunStatus::PendingApproval);
    assert_eq!(again.id, run.id, "the same run");
    assert!(again.pending.as_ref().unwrap().reasons.iter().any(|r| r.contains("not approved")), "{again:?}");
    assert!(svc.workflow_run(&a, req("nope")).await.is_err());
    // Another actor cannot use it.
    assert!(svc.workflow_run(&Actor::parse("agent:other").unwrap(), req(&p.approval_id)).await.is_err());
    assert_eq!(svc.counters().unwrap().exchanges, 1);

    svc.decide_approval(&p.approval_id, &human(), true).unwrap();
    let done = svc.workflow_run(&a, req(&p.approval_id)).await.unwrap();
    assert_eq!(done.status, RunStatus::Ok, "{done:#?}");
    assert_eq!(done.id, run.id);
    assert!(done.pending.is_none());
    assert_eq!(done.steps.len(), 7);
    assert_eq!(done.sends, 3);
    // The first GET was not sent a second time: one products request, one login, one order.
    let products = svc
        .history_search(
            &human(),
            &pm_service::pm_store::HistoryFilter { path: Some("/api/products".into()), ..Default::default() },
        )
        .unwrap();
    assert_eq!(products.exchanges.len(), 1);
    // The approval is used up.
    assert!(svc.workflow_run(&a, req(&p.approval_id)).await.is_err());
    // The stored run is the finished one.
    assert_eq!(svc.workflow_run_get(&human(), run.id).unwrap().status, RunStatus::Ok);
}

#[tokio::test]
async fn agents_may_run_but_not_create_edit_delete_or_switch_triggers() {
    let (svc, port) = shop().await;
    let me = human();
    let wf = svc
        .workflow_create(
            &me,
            WorkflowInput {
                name: "m".into(),
                steps: vec![Step::Match(Condition { path_contains: Some("/x".into()), ..cond() })],
                ..Default::default()
            },
        )
        .unwrap();
    let a = agent();
    let input = || WorkflowInput {
        name: "evil".into(),
        steps: vec![send(port, "GET / HTTP/1.1\r\nHost: HOST\r\n\r\n")],
        ..Default::default()
    };
    assert!(svc.workflow_create(&a, input()).is_err());
    assert!(svc.workflow_update(&a, "m", input()).is_err());
    assert!(svc.workflow_trigger_set(&a, "m", true, None).is_err());
    assert!(svc.workflow_delete(&a, "m").is_err());
    assert!(svc.workflow_get(&me, "m").unwrap().steps.len() == 1, "nothing changed");
    assert!(!svc.workflow_get(&me, "m").unwrap().trigger.enabled);
    // Each attempt is audited as a denial.
    let denied: Vec<String> =
        svc.audit_list(50).unwrap().into_iter().filter(|r| r.decision == "deny").map(|r| r.action).collect();
    assert_eq!(denied.iter().filter(|a| *a == "workflow_save").count(), 2);
    assert!(
        denied.contains(&"workflow_trigger".to_string()) && denied.contains(&"workflow_delete".to_string()),
        "{denied:?}"
    );
    // They can list, read and run.
    assert_eq!(svc.workflow_summaries(&a).unwrap()[0].name, "m");
    assert_eq!(svc.workflow_get(&a, &wf.id.to_string()).unwrap().name, "m");
    let run = svc.workflow_run(&a, run_req("m")).await.unwrap();
    assert_eq!(run.status, RunStatus::Stopped);
}

#[tokio::test]
async fn secrets_are_hidden_from_agents_in_definitions_and_runs() {
    let (svc, port) = shop().await;
    let me = human();
    // Free of approval for this test: a GET login keeps the agent's run in one piece.
    let wf = WorkflowInput {
        name: "secretive".into(),
        steps: vec![
            send(port, "GET /api/products?password=hunter2 HTTP/1.1\r\nHost: HOST\r\nX-Api-Key: hunter2\r\n\r\n"),
            Step::Extract(ExtractStep {
                name: "session_token".into(),
                kind: ExtractType::Regex,
                expr: r#""name":"([^"]+)""#.into(),
                optional: true,
                ..Default::default()
            }),
            Step::Extract(ExtractStep {
                name: "first_product".into(),
                kind: ExtractType::Regex,
                expr: r#""name":"([^"]+)""#.into(),
                ..Default::default()
            }),
        ],
        ..Default::default()
    };
    svc.workflow_create(&me, wf).unwrap();
    let shown = serde_json::to_string(&svc.workflow_get(&agent(), "secretive").unwrap()).unwrap();
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(serde_json::to_string(&svc.workflow_get(&me, "secretive").unwrap()).unwrap().contains("hunter2"));

    let run = svc.workflow_run(&agent(), run_req("secretive")).await.unwrap();
    assert_eq!(run.status, RunStatus::Ok, "{run:#?}");
    assert!(
        run.variables["session_token"].starts_with("[hidden:"),
        "a secret-looking name hides the value: {:?}",
        run.variables
    );
    assert!(run.variables["first_product"].starts_with("<untrusted_target_content>"), "{:?}", run.variables);
    // People get the real values, from the same stored run.
    let real = svc.workflow_run_get(&me, run.id).unwrap();
    assert!(!real.variables["session_token"].starts_with('['));
    assert!(!real.variables["first_product"].contains("untrusted"));
    // An agent does not see another actor's runs.
    assert!(svc.workflow_run_get(&Actor::parse("agent:other").unwrap(), run.id).is_err());
    assert!(svc.workflow_runs(&Actor::parse("agent:other").unwrap(), None, 10).unwrap().is_empty());
    assert_eq!(svc.workflow_runs(&agent(), None, 10).unwrap().len(), 1);

    // A placeholder the project does not know is refused before anything is sent.
    svc.workflow_create(
        &me,
        WorkflowInput {
            name: "unknown-secret".into(),
            steps: vec![send(port, "GET / HTTP/1.1\r\nHost: HOST\r\nX-K: {{secret:nope}}\r\n\r\n")],
            ..Default::default()
        },
    )
    .unwrap();
    let before = svc.counters().unwrap().exchanges;
    let r = svc.workflow_run(&me, run_req("unknown-secret")).await.unwrap();
    assert_eq!(r.status, RunStatus::Failed);
    assert!(r.reason.as_deref().unwrap().contains("unknown secret"), "{r:?}");
    assert_eq!(svc.counters().unwrap().exchanges, before);
}

#[tokio::test]
async fn a_value_from_a_response_that_makes_a_request_destructive_needs_what_destructive_needs() {
    let (svc, port) = shop().await;
    // A server that answers with a payload in its body: the workflow puts it into the next request.
    let evil = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let evil_port = evil.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = evil.accept().await {
            let mut b = [0u8; 2048];
            let _ = c.read(&mut b).await;
            let body = "{\"next\":\"1; DROP TABLE users\"}";
            let _ = c
                .write_all(
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
                        .as_bytes(),
                )
                .await;
        }
    });
    let svc2 = service(&[port, evil_port]);
    svc2.workflow_create(
        &human(),
        WorkflowInput {
            name: "follow".into(),
            steps: vec![
                Step::Send(SendStep {
                    url: Some(format!("http://127.0.0.1:{evil_port}")),
                    raw: Some(format!("GET /a HTTP/1.1\r\nHost: 127.0.0.1:{evil_port}\r\n\r\n")),
                    ..Default::default()
                }),
                Step::Extract(ExtractStep {
                    name: "next".into(),
                    kind: ExtractType::Json,
                    expr: "/next".into(),
                    ..Default::default()
                }),
                Step::Transform(TransformStep {
                    name: "q".into(),
                    value: "{{next}}".into(),
                    ops: vec!["url_encode".into()],
                }),
                Step::Send(SendStep {
                    url: Some(format!("http://127.0.0.1:{evil_port}")),
                    raw: Some(format!("GET /b?q={{{{q}}}} HTTP/1.1\r\nHost: 127.0.0.1:{evil_port}\r\n\r\n")),
                    ..Default::default()
                }),
            ],
            ..Default::default()
        },
    )
    .unwrap();
    let _ = svc;
    // The classifier looks at the finished request (here: percent-encoded SQL), as it would for Replay: for an
    // agent a destructive payload is refused outright, not merely approved.
    let run = svc2.workflow_run(&agent(), run_req("follow")).await.unwrap();
    assert!(matches!(run.status, RunStatus::Denied | RunStatus::PendingApproval), "{run:#?}");
    assert_eq!(run.steps.len(), 4);
    assert_eq!(run.sends, 1, "the second request was gated and not sent");
}

#[tokio::test]
async fn editing_the_steps_turns_the_trigger_off_and_a_trigger_needs_a_match_first() {
    let (svc, port) = shop().await;
    let me = human();
    let plain = svc
        .workflow_create(
            &me,
            WorkflowInput {
                name: "plain".into(),
                steps: vec![send(port, "GET / HTTP/1.1\r\nHost: HOST\r\n\r\n")],
                ..Default::default()
            },
        )
        .unwrap();
    let err = svc.workflow_trigger_set(&me, &plain.name, true, None).unwrap_err().to_string();
    assert!(err.contains("starts with a match step"), "{err}");
    let vars_only = WorkflowInput {
        name: "vars".into(),
        steps: vec![
            Step::Transform(TransformStep { name: "a".into(), value: "x".into(), ops: vec![] }),
            Step::Match(Condition { var: Some("a".into()), ..cond() }),
        ],
        ..Default::default()
    };
    let w = svc.workflow_create(&me, vars_only).unwrap();
    assert!(svc.workflow_trigger_set(&me, &w.name, true, None).is_err());

    let input = |extra: &str| WorkflowInput {
        name: "on-products".into(),
        steps: vec![
            Step::Match(Condition { path_contains: Some("/api/products".into()), ..cond() }),
            send(port, &format!("GET /{extra} HTTP/1.1\r\nHost: HOST\r\n\r\n")),
        ],
        ..Default::default()
    };
    svc.workflow_create(&me, input("a")).unwrap();
    assert!(svc.workflow_trigger_set(&me, "on-products", true, Some(0)).is_err());
    assert!(svc.workflow_trigger_set(&me, "on-products", true, Some(61)).is_err());
    let on = svc.workflow_trigger_set(&me, "on-products", true, Some(3)).unwrap();
    assert!(
        (on.trigger.enabled, on.trigger.max_per_minute, on.trigger.enabled_by.as_str()) == (true, 3, "human:tester")
    );
    assert!(svc.audit_list(50).unwrap().iter().any(|r| r.action == "workflow_trigger" && r.actor == "human:tester"));
    // Same steps, new description: the trigger stays. Changed steps: it is switched off.
    let kept =
        svc.workflow_update(&me, "on-products", WorkflowInput { description: "d".into(), ..input("a") }).unwrap();
    assert!(kept.trigger.enabled);
    let off = svc.workflow_update(&me, "on-products", input("b")).unwrap();
    assert!(!off.trigger.enabled, "a person turned it on for other steps");
    assert!(svc.workflow_trigger_set(&me, "on-products", false, None).is_ok());
}

/// A proxied exchange as the recorder stores it.
fn proxied(port: u16, path: &str, source: &str) -> NewExchange {
    NewExchange {
        ts_ms: 1,
        duration_ms: Some(1),
        source: source.into(),
        actor_id: "human:local".into(),
        scheme: "http".into(),
        host: "127.0.0.1".into(),
        port,
        method: "GET".into(),
        path: path.into(),
        status: Some(200),
        request: format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").into_bytes(),
        response: Some(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec()),
        ..Default::default()
    }
}

async fn until<F: FnMut() -> bool>(what: &str, mut f: F) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn the_per_exchange_trigger_runs_matching_proxied_exchanges_up_to_its_rate_cap() {
    let (svc, port) = shop().await;
    let me = human();
    svc.workflow_create(
        &me,
        WorkflowInput {
            name: "on-products".into(),
            steps: vec![
                Step::Match(Condition {
                    path_contains: Some("/api/products".into()),
                    status: Some("2xx".into()),
                    ..cond()
                }),
                send(port, "GET /api/products?from=trigger HTTP/1.1\r\nHost: HOST\r\n\r\n"),
                Step::Assert(Condition { status: Some("200".into()), ..cond() }),
            ],
            ..Default::default()
        },
    )
    .unwrap();
    tokio::spawn(svc.clone().run_workflow_triggers());
    tokio::time::sleep(Duration::from_millis(50)).await;
    let store = svc.store_handle();
    let record = |p: &str, source: &str| store.write(|db| db.insert_exchange(&proxied(port, p, source))).unwrap();

    // Off by default: nothing runs.
    record("/api/products?a=1", "proxy");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(svc.workflow_runs(&me, None, 10).unwrap().is_empty(), "triggers are off until a person turns one on");

    svc.workflow_trigger_set(&me, "on-products", true, Some(2)).unwrap();
    // These must not start it: another source (a loop guard), a path that doesn't fit, a target out of scope.
    record("/api/products?b=1", "replay");
    record("/api/products?c=1", "workflow");
    record("/api/orders/1", "proxy");
    let mut other = proxied(port, "/api/products", "proxy");
    other.host = "elsewhere.test".into();
    store.write(|db| db.insert_exchange(&other)).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(svc.workflow_runs(&me, None, 10).unwrap().is_empty(), "{:?}", svc.workflow_runs(&me, None, 10).unwrap());

    // Five matching exchanges within the minute: two runs, three skipped.
    let ids: Vec<i64> = (0..5).map(|i| record(&format!("/api/products?n={i}"), "proxy")).collect();
    until("two runs", || {
        svc.workflow_runs(&me, None, 10).unwrap().iter().filter(|r| r.status == RunStatus::Ok).count() == 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let runs = svc.workflow_runs(&me, None, 10).unwrap();
    assert_eq!(runs.len(), 2, "{runs:#?}");
    for r in &runs {
        assert_eq!((r.trigger.as_str(), r.actor.as_str()), ("exchange", "human:tester"));
        assert!(ids.contains(&r.start_exchange.unwrap()));
        assert_eq!(r.sends, 1);
    }
    let wf = svc.workflow_get(&me, "on-products").unwrap();
    assert_eq!(wf.trigger.skipped, 3, "three exchanges past the cap were skipped, not queued");
    // The runs' own sends are workflow exchanges: they did not start more runs.
    assert_eq!(svc.workflow_runs(&me, None, 10).unwrap().len(), 2);
}

/// A server that answers after `delay`.
async fn slow_server(delay: Duration) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 4096];
                let _ = c.read(&mut b).await;
                tokio::time::sleep(delay).await;
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow").await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_trigger_never_delays_the_traffic_it_reacts_to() {
    // Browser traffic goes through the real proxy to a fast backend; the workflow it triggers sends to a server
    // that takes 2.5 s. The browser's answer comes back at once, the run finishes later.
    let fast = slow_server(Duration::ZERO).await;
    let slow = slow_server(Duration::from_millis(2500)).await;
    let dir = std::env::temp_dir().join(format!("pm-wf-proxy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let roe = format!("version: 1\nscope:\n  include: [\"http://127.0.0.1:{fast}/\", \"http://127.0.0.1:{slow}/\"]\n");
    let svc = Arc::new(
        Service::new(Store::open(&dir.join("p.pmproj")).unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap(),
    );
    let (recorder, _join) = Recorder::spawn_shared(svc.store_handle());
    let ca = Arc::new(pm_service::pm_tls::CertAuthority::load_or_create(&dir).unwrap());
    let proxy = Proxy::new(ca, recorder, false).unwrap();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = l.local_addr().unwrap().port();
    tokio::spawn(proxy.run(l));

    let me = human();
    svc.workflow_create(
        &me,
        WorkflowInput {
            name: "slow-follow-up".into(),
            steps: vec![
                Step::Match(Condition { path_contains: Some("/watch".into()), ..cond() }),
                Step::Send(SendStep {
                    url: Some(format!("http://127.0.0.1:{slow}")),
                    raw: Some(format!("GET /slow HTTP/1.1\r\nHost: 127.0.0.1:{slow}\r\n\r\n")),
                    ..Default::default()
                }),
                Step::Assert(Condition { body_contains: Some("slow".into()), ..cond() }),
            ],
            ..Default::default()
        },
    )
    .unwrap();
    svc.workflow_trigger_set(&me, "slow-follow-up", true, None).unwrap();
    tokio::spawn(svc.clone().run_workflow_triggers());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let t0 = Instant::now();
    let mut c = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    c.write_all(
        format!("GET http://127.0.0.1:{fast}/watch HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).await.unwrap();
    let answered_in = t0.elapsed();
    assert!(out.ends_with("slow"), "{out}");
    assert!(
        answered_in < Duration::from_millis(1500),
        "the proxy answered in {answered_in:?}, the workflow takes 2.5 s"
    );

    // The run started after the exchange was recorded and is still going, then finishes.
    until("the run to start", || !svc.workflow_runs(&me, None, 10).unwrap().is_empty()).await;
    assert_ne!(
        svc.workflow_runs(&me, None, 10).unwrap()[0].status,
        RunStatus::Ok,
        "still in flight when the browser had its answer"
    );
    until("the run to end", || svc.workflow_runs(&me, None, 10).unwrap()[0].status == RunStatus::Ok).await;
    let run = &svc.workflow_runs(&me, None, 10).unwrap()[0];
    assert!(run.duration_ms >= 2400, "{run:?}");
    let _ = std::fs::remove_dir_all(dir);
}

/// A server that answers `{"echo":"<path>"}`.
async fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let n = c.read(&mut b).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&b[..n]).into_owned();
                let path = head.split(' ').nth(1).unwrap_or("/").to_string();
                let body = format!("{{\"echo\":\"{path}\"}}");
                let _ = c.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await;
            });
        }
    });
    port
}

#[tokio::test]
async fn the_fuzzer_can_run_a_workflow_on_each_result() {
    let port = echo_server().await;
    let svc = service(&[port]);
    let me = human();
    svc.workflow_create(
        &me,
        WorkflowInput {
            name: "per-result".into(),
            steps: vec![
                Step::Extract(ExtractStep {
                    name: "e".into(),
                    kind: ExtractType::Json,
                    expr: "/echo".into(),
                    ..Default::default()
                }),
                Step::Assert(Condition { var: Some("e".into()), var_contains: Some("/item/".into()), ..cond() }),
                Step::Assert(Condition {
                    var: Some("e".into()),
                    var_matches: Some("/item/(apple|cherry)$".into()),
                    message: Some("only apple and cherry".into()),
                    ..cond()
                }),
            ],
            ..Default::default()
        },
    )
    .unwrap();
    let req = |workflow: Option<&str>| FuzzerRequest {
        url: Some(format!("http://127.0.0.1:{port}")),
        raw: "GET /item/§apple§ HTTP/1.1\r\nHost: x\r\n\r\n".into(),
        payload_sets: vec![pm_service::pm_fuzz::PayloadSet {
            list: vec!["apple".into(), "banana".into(), "cherry".into()],
            ..Default::default()
        }],
        workflow: workflow.map(String::from),
        ..Default::default()
    };
    let FuzzerResult::Done { results, baseline, .. } = svc.fuzzer_run(&me, req(Some("per-result"))).await.unwrap()
    else {
        panic!()
    };
    assert!(baseline.workflow.is_none(), "the baseline is not a result");
    assert_eq!(results.len(), 3);
    let by_payload =
        |p: &str| results.iter().find(|r| r.payloads[0].as_deref() == Some(p)).unwrap().workflow.clone().unwrap();
    assert_eq!(by_payload("apple").status, RunStatus::Ok);
    assert_eq!(by_payload("apple").variables["e"], "/item/apple");
    assert_eq!(by_payload("cherry").status, RunStatus::Ok);
    let banana = by_payload("banana");
    assert_eq!(banana.status, RunStatus::Failed);
    assert!(banana.reason.as_deref().unwrap().contains("assertion"), "{banana:?}");
    // Each result's run is a stored run with the fuzzer as its trigger and the result as its start.
    let runs = svc.workflow_runs(&me, Some("per-result"), 10).unwrap();
    assert_eq!(runs.len(), 3);
    assert!(runs.iter().all(|r| r.trigger == "fuzzer" && r.start_exchange.is_some()));
    // Without the option the rows carry nothing, and an unknown workflow is refused before anything is sent.
    let FuzzerResult::Done { results, .. } = svc.fuzzer_run(&me, req(None)).await.unwrap() else { panic!() };
    assert!(results.iter().all(|r| r.workflow.is_none()));
    assert!(svc.fuzzer_run(&me, req(Some("nope"))).await.is_err());
}

#[tokio::test]
async fn run_events_reach_the_workflows_topic_and_only_the_owner_agent_sees_them() {
    let (svc, port) = shop().await;
    svc.workflow_create(
        &human(),
        WorkflowInput {
            name: "w".into(),
            steps: vec![send(port, "GET /api/products HTTP/1.1\r\nHost: HOST\r\n\r\n")],
            ..Default::default()
        },
    )
    .unwrap();
    let mut sub = svc.subscribe();
    let run = svc.workflow_run(&agent(), run_req("w")).await.unwrap();
    assert_eq!(run.status, RunStatus::Ok);
    let mut got = Vec::new();
    while let Ok(Some(Delivery::Event(p))) = tokio::time::timeout(Duration::from_millis(100), sub.recv()).await {
        if p.topic.as_str() == "workflows" {
            got.push(p);
        }
    }
    let states: Vec<String> = got
        .iter()
        .filter_map(|p| match &p.event {
            Event::WorkflowRunChanged { run_id, state, .. } if *run_id == run.id => Some(state.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(states.first().map(String::as_str), Some("running"));
    assert_eq!(states.last().map(String::as_str), Some("ok"), "{states:?}");
    assert!(got.iter().all(|p| svc.event_for(&human(), p).is_some()));
    assert!(got.iter().all(|p| svc.event_for(&agent(), p).is_some()), "the agent that ran it");
    assert!(
        got.iter().all(|p| svc.event_for(&Actor::parse("agent:other").unwrap(), p).is_none()),
        "someone else's run"
    );
    let text = serde_json::to_string(&svc.event_for(&human(), &got[0]).unwrap()).unwrap();
    assert!(text.contains("\"topic\":\"workflows\"") && text.contains("workflow_run_changed"), "{text}");
    // Saving announces itself too.
    let mut sub = svc.subscribe();
    svc.workflow_delete(&human(), "w").unwrap();
    let p = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match sub.recv().await {
                Some(Delivery::Event(p)) if p.topic.as_str() == "workflows" => return p,
                Some(_) => {}
                None => panic!("the bus closed"),
            }
        }
    })
    .await
    .unwrap();
    assert!(matches!(p.event, Event::WorkflowChanged { ref what, .. } if what == "deleted"));
    assert!(svc.workflow_run_get(&human(), run.id).is_err(), "a deleted workflow's runs go with it");
}

#[tokio::test]
async fn saving_checks_names_and_limits_and_only_the_newest_runs_are_kept() {
    let (svc, port) = shop().await;
    let me = human();
    let one = || WorkflowInput {
        name: "One".into(),
        steps: vec![send(port, "GET /api/products HTTP/1.1\r\nHost: HOST\r\n\r\n")],
        ..Default::default()
    };
    svc.workflow_create(&me, one()).unwrap();
    assert!(
        svc.workflow_create(&me, WorkflowInput { name: "one".into(), ..one() }).is_err(),
        "names are unique, case aside"
    );
    assert!(svc.workflow_create(&me, WorkflowInput { steps: vec![], ..one() }).is_err());
    let many: Vec<Step> = (0..21).map(|_| send(port, "GET / HTTP/1.1\r\nHost: HOST\r\n\r\n")).collect();
    let e = svc
        .workflow_create(&me, WorkflowInput { name: "many".into(), steps: many, ..Default::default() })
        .unwrap_err()
        .to_string();
    assert!(e.contains("at most 20"), "{e}");
    let two = svc.workflow_create(&me, WorkflowInput { name: "Two".into(), ..one() }).unwrap();
    assert_eq!(two.id, 2);
    assert!(svc.workflow_update(&me, "Two", WorkflowInput { name: "ONE".into(), ..one() }).is_err());
    assert_eq!(
        svc.workflow_update(&me, "2", WorkflowInput { name: "Renamed".into(), ..one() }).unwrap().name,
        "Renamed"
    );
    assert!(svc.workflow_get(&me, "nope").is_err());
    // Only the newest runs are kept.
    let total = pm_service::KEEP_RUNS + 5;
    let mut last = 0;
    for _ in 0..total {
        last = svc.workflow_run(&me, run_req("One")).await.unwrap().id;
    }
    let kept = svc.workflow_runs(&me, None, 200).unwrap();
    assert_eq!(kept.len(), pm_service::KEEP_RUNS);
    assert_eq!(kept[0].id, last);
    assert_eq!(kept.last().unwrap().id, last - pm_service::KEEP_RUNS as i64 + 1, "the oldest five are gone");
}
