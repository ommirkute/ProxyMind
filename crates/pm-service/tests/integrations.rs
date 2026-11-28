//! Integrations (roadmap 3.5) against in-process mock servers: the API shape and credentials each provider expects,
//! what leaves the machine (redaction), where secrets live, the destination guard, retries and the rate limit, the
//! project-file rule (F-2) and who may do what.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use parking_lot::Mutex;
use pm_demo::VulnShop;
use pm_service::pm_identity::{AuthMaterial, Identity, LoginRecipe, LoginStep};
use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{NewExchange, Store};
use pm_service::{
    IntegrationEvent, IntegrationInput, IntegrationKind, IntegrationTuning, NewFinding, ProofRequest, ProofResult,
    ReplayRequest, ReplayResult, ScanTaskRequest, ScanTaskStatus, SendFindingBody, Service,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn human() -> Actor {
    Actor::parse("human:tester").unwrap()
}

const TOKEN: &str = "ghp_SECRETTOKEN0123456789abcdef";
const COOKIE: &str = "session=c0ffee-session-cookie-9876543210";
const BEARER: &str = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJlc2lnbg";
const PASSWORD: &str = "hunter2hunter2";

// ---- a recording mock server --------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Got {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Got {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&self.body)))
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

struct Mock {
    addr: SocketAddr,
    log: Arc<Mutex<Vec<Got>>>,
}

impl Mock {
    /// `handler(n, request)` answers the n-th request (from 0) with a status and a body.
    async fn start(handler: impl Fn(usize, &Got) -> (u16, String) + Send + Sync + 'static) -> Mock {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let log: Arc<Mutex<Vec<Got>>> = Arc::default();
        let (handler, seen, count) = (Arc::new(handler), log.clone(), Arc::new(AtomicUsize::new(0)));
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                let (handler, seen, count) = (handler.clone(), seen.clone(), count.clone());
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 8192];
                    let head_end = loop {
                        let n = c.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break p + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                    let mut lines = head.lines();
                    let first = lines.next().unwrap_or_default().to_string();
                    let headers: Vec<(String, String)> = lines
                        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
                        .collect();
                    let len = headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                        .and_then(|(_, v)| v.parse::<usize>().ok())
                        .unwrap_or(0);
                    while buf.len() < head_end + len {
                        let n = c.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let mut parts = first.split(' ');
                    let got = Got {
                        method: parts.next().unwrap_or_default().to_string(),
                        path: parts.next().unwrap_or_default().to_string(),
                        headers,
                        body: buf[head_end..].to_vec(),
                    };
                    let n = count.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = handler(n, &got);
                    seen.lock().push(got);
                    let answer = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = c.write_all(answer.as_bytes()).await;
                });
            }
        });
        Mock { addr, log }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn got(&self) -> Vec<Got> {
        self.log.lock().clone()
    }

    async fn wait(&self, n: usize) -> Vec<Got> {
        for _ in 0..200 {
            if self.log.lock().len() >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.got()
    }
}

// ---- helpers ------------------------------------------------------------------------------------------------

static N: AtomicUsize = AtomicUsize::new(0);

fn home() -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pm-integ-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const ROE: &str = "version: 1\nscope:\n  include: [\"https://app.test/\"]\n";

fn service() -> (Arc<Service>, std::path::PathBuf) {
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap());
    let h = home();
    s.attach_plugin_home(h.clone());
    s.integration_tuning_set(IntegrationTuning { max_attempts: 3, backoff_base_ms: 5, backoff_cap_ms: 20 });
    (s, h)
}

fn input(name: &str, kind: IntegrationKind, url: &str) -> IntegrationInput {
    IntegrationInput { name: name.into(), kind, base_url: url.into(), allow_private: true, ..Default::default() }
}

fn jira(url: &str, email: &str) -> IntegrationInput {
    IntegrationInput {
        project: "SEC".into(),
        email: email.into(),
        token: Some("jira-api-token-ABCDEFGHIJKL".into()),
        ..input("jira", IntegrationKind::Jira, url)
    }
}

fn github(url: &str) -> IntegrationInput {
    IntegrationInput {
        project: "acme/app".into(),
        token: Some(TOKEN.into()),
        ..input("gh", IntegrationKind::Github, url)
    }
}

/// A finding whose evidence request carries a session cookie, a bearer token and a password.
fn leaky_finding(s: &Service) -> i64 {
    let raw = format!(
        "POST /api/orders/1 HTTP/1.1\r\nHost: app.test\r\nCookie: {COOKIE}\r\nAuthorization: {BEARER}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password={PASSWORD}&note=hello"
    );
    let ex = s
        .store_handle()
        .write(|db| {
            db.insert_exchange(&NewExchange {
                ts_ms: 1,
                source: "proxy".into(),
                actor_id: "human:local".into(),
                scheme: "https".into(),
                host: "app.test".into(),
                port: 443,
                method: "POST".into(),
                path: "/api/orders/1".into(),
                status: Some(200),
                request: raw.into_bytes(),
                response: Some(b"HTTP/1.1 200 OK\r\n\r\n{\"order\":1}".to_vec()),
                identity: Some("alice".into()),
                ..Default::default()
            })
        })
        .unwrap();
    let f = s
        .finding_create(
            &human(),
            NewFinding {
                title: "IDOR on orders".into(),
                vuln_class: "idor".into(),
                severity: "high".into(),
                // The description also repeats a secret, as a careless note would.
                description: format!("Any user reads any order. Seen with {COOKIE} and password={PASSWORD}."),
                url: Some("https://app.test/api/orders/1?token=querysecret123456".into()),
                evidence: vec![ex],
                hypothesis_id: None,
            },
        )
        .unwrap();
    f["id"].as_i64().unwrap()
}

fn assert_clean(text: &str, what: &str) {
    for secret in
        [COOKIE, "c0ffee-session-cookie-9876543210", BEARER, "eyJhbGciOiJIUzI1NiJ9", PASSWORD, "querysecret123456"]
    {
        assert!(!text.contains(secret), "{what} leaks {secret}:\n{text}");
    }
}

fn send(finding: i64, integration: &str) -> SendFindingBody {
    let _ = finding;
    SendFindingBody { integration: integration.into(), update: false }
}

// ---- trackers -----------------------------------------------------------------------------------------------

#[tokio::test]
async fn jira_issue_has_the_rest_v2_shape_basic_auth_and_no_secrets() {
    let mock = Mock::start(|_, r| match r.method.as_str() {
        "POST" => (201, r#"{"id":"10001","key":"SEC-12","self":"x"}"#.into()),
        _ => (204, String::new()),
    })
    .await;
    let (s, _) = service();
    let mut inp = jira(&mock.url(), "pentest@example.com");
    inp.labels = vec!["proxy mind".into()];
    s.integration_set(&human(), "jira", inp).unwrap();
    let fid = leaky_finding(&s);
    let link = s.integration_send_finding(&human(), fid, send(fid, "jira")).await.unwrap();
    assert_eq!((link.key.as_str(), link.url.as_str()), ("SEC-12", format!("{}/browse/SEC-12", mock.url()).as_str()));

    let got = &mock.got()[0];
    assert_eq!((got.method.as_str(), got.path.as_str()), ("POST", "/rest/api/2/issue"));
    let basic = format!("Basic {}", pm_core::base64(b"pentest@example.com:jira-api-token-ABCDEFGHIJKL"));
    assert_eq!(got.header("authorization"), Some(basic.as_str()));
    assert_eq!(got.header("content-type"), Some("application/json"));
    let body = got.json();
    let f = &body["fields"];
    assert_eq!(f["project"]["key"], "SEC");
    assert_eq!(f["issuetype"]["name"], "Bug");
    assert_eq!(f["labels"], json!(["proxy-mind"]));
    assert!(f["summary"].as_str().unwrap().starts_with("[High] IDOR on orders"));
    let d = f["description"].as_str().unwrap();
    for want in [
        format!("#{fid}"),
        "CWE-639".into(),
        "A01:2021".into(),
        "Exchange #".into(),
        "{noformat}".into(),
        "POST /api/orders/1".into(),
    ] {
        let want: String = want;
        assert!(d.contains(&want), "{want} in {d}");
    }
    assert_clean(&got.text(), "the Jira issue");

    // The finding keeps the link, and sending again is refused.
    let f = s.finding_get(fid).unwrap();
    assert_eq!(f["issue_links"][0]["key"], "SEC-12");
    let err = s.integration_send_finding(&human(), fid, send(fid, "jira")).await.unwrap_err().to_string();
    assert!(err.contains("already has issue SEC-12"), "{err}");
    assert_eq!(mock.got().len(), 1, "a refused duplicate sends nothing");
    // With update it refreshes the same issue (PUT, no new issue).
    let link = s
        .integration_send_finding(&human(), fid, SendFindingBody { integration: "jira".into(), update: true })
        .await
        .unwrap();
    assert_eq!(link.key, "SEC-12");
    let put = &mock.got()[1];
    assert_eq!((put.method.as_str(), put.path.as_str()), ("PUT", "/rest/api/2/issue/SEC-12"));
    assert_eq!(s.finding_get(fid).unwrap()["issue_links"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn jira_personal_access_tokens_use_bearer_auth() {
    let mock = Mock::start(|_, _| (200, r#"{"key":"SEC"}"#.into())).await;
    let (s, _) = service();
    s.integration_set(&human(), "jira", jira(&mock.url(), "")).unwrap();
    let row = s.integration_test(&human(), "jira").await.unwrap();
    assert_eq!(row.status, "ok", "{row:?}");
    let got = &mock.got()[0];
    assert_eq!((got.method.as_str(), got.path.as_str()), ("GET", "/rest/api/2/project/SEC"));
    assert_eq!(got.header("authorization"), Some("Bearer jira-api-token-ABCDEFGHIJKL"));
}

#[tokio::test]
async fn github_issue_has_the_rest_shape_headers_and_no_secrets() {
    let mock = Mock::start(|_, r| match r.method.as_str() {
        "POST" => (201, r#"{"number":34,"html_url":"https://github.com/acme/app/issues/34"}"#.into()),
        _ => (200, r#"{"number":34,"html_url":"https://github.com/acme/app/issues/34"}"#.into()),
    })
    .await;
    let (s, _) = service();
    let mut inp = github(&mock.url());
    inp.labels = vec!["security".into()];
    s.integration_set(&human(), "gh", inp).unwrap();
    let fid = leaky_finding(&s);
    let link = s.integration_send_finding(&human(), fid, send(fid, "gh")).await.unwrap();
    assert_eq!((link.key.as_str(), link.url.as_str()), ("#34", "https://github.com/acme/app/issues/34"));
    let got = &mock.got()[0];
    assert_eq!((got.method.as_str(), got.path.as_str()), ("POST", "/repos/acme/app/issues"));
    assert_eq!(got.header("authorization"), Some(format!("Bearer {TOKEN}").as_str()));
    assert_eq!(got.header("accept"), Some("application/vnd.github+json"));
    assert_eq!(got.header("x-github-api-version"), Some("2022-11-28"));
    assert!(got.header("user-agent").unwrap().starts_with("ProxyMind/"));
    let b = got.json();
    assert_eq!(b["labels"], json!(["security"]));
    assert!(b["title"].as_str().unwrap().starts_with("[High] IDOR on orders"));
    let md = b["body"].as_str().unwrap();
    for want in [
        "**Severity:** High",
        "CWE-639",
        "OWASP A01:2021",
        "### Reproduction",
        "```http",
        "Exchange #",
        "Check ownership",
    ] {
        // The remediation text is the library's; look for the heading instead of its words.
        if want == "Check ownership" {
            assert!(md.contains("### Remediation"), "{md}");
        } else {
            assert!(md.contains(want), "{want} in\n{md}");
        }
    }
    assert!(md.contains("{{secret:"), "secrets are replaced by placeholders:\n{md}");
    assert_clean(&got.text(), "the GitHub issue");

    let up = s
        .integration_send_finding(&human(), fid, SendFindingBody { integration: "gh".into(), update: true })
        .await
        .unwrap();
    assert_eq!(up.key, "#34");
    let patch = &mock.got()[1];
    assert_eq!((patch.method.as_str(), patch.path.as_str()), ("PATCH", "/repos/acme/app/issues/34"));
}

#[tokio::test]
async fn gitlab_issue_uses_private_token_and_an_encoded_project_path() {
    let mock =
        Mock::start(|_, _| (201, r#"{"iid":7,"web_url":"https://gitlab.example.com/acme/app/-/issues/7"}"#.into()))
            .await;
    let (s, _) = service();
    let inp = IntegrationInput {
        project: "acme/app".into(),
        token: Some("glpat-SECRETTOKEN0123456789".into()),
        labels: vec!["a".into(), "b".into()],
        ..input("gl", IntegrationKind::Gitlab, &mock.url())
    };
    s.integration_set(&human(), "gl", inp).unwrap();
    let fid = leaky_finding(&s);
    let link = s.integration_send_finding(&human(), fid, send(fid, "gl")).await.unwrap();
    assert_eq!(link.key, "#7");
    let got = &mock.got()[0];
    assert_eq!((got.method.as_str(), got.path.as_str()), ("POST", "/api/v4/projects/acme%2Fapp/issues"));
    assert_eq!(got.header("private-token"), Some("glpat-SECRETTOKEN0123456789"));
    assert!(got.header("authorization").is_none());
    let b = got.json();
    assert_eq!(b["labels"], "a,b");
    assert!(b["description"].as_str().unwrap().contains("**ProxyMind finding:** #"));
    assert_clean(&got.text(), "the GitLab issue");
    let up = s
        .integration_send_finding(&human(), fid, SendFindingBody { integration: "gl".into(), update: true })
        .await
        .unwrap();
    assert_eq!(up.key, "#7");
    let put = &mock.got()[1];
    assert_eq!((put.method.as_str(), put.path.as_str()), ("PUT", "/api/v4/projects/acme%2Fapp/issues/7"));
}

#[tokio::test]
async fn a_tracker_that_answers_with_a_hostile_link_cannot_plant_a_script_url() {
    let mock = Mock::start(|_, _| (201, r#"{"number":1,"html_url":"javascript:alert(1)"}"#.into())).await;
    let (s, _) = service();
    s.integration_set(&human(), "gh", github(&mock.url())).unwrap();
    let fid = leaky_finding(&s);
    let link = s.integration_send_finding(&human(), fid, send(fid, "gh")).await.unwrap();
    assert!(link.url.starts_with("https://"), "{}", link.url);
}

#[tokio::test]
async fn a_failed_issue_is_reported_without_the_token_and_leaves_no_link() {
    let mock = Mock::start(|_, _| (401, format!("{{\"message\":\"Bad credentials for {TOKEN}\"}}"))).await;
    let (s, _) = service();
    s.integration_set(&human(), "gh", github(&mock.url())).unwrap();
    let fid = leaky_finding(&s);
    let err = s.integration_send_finding(&human(), fid, send(fid, "gh")).await.unwrap_err().to_string();
    assert!(err.contains("401") && !err.contains(TOKEN), "{err}");
    assert!(s.finding_get(fid).unwrap()["issue_links"].as_array().unwrap().is_empty());
    assert_eq!(mock.got().len(), 1, "an issue is never retried automatically");
    let log = s.integration_deliveries(&human(), "gh", 10).unwrap();
    assert_eq!((log[0].status.as_str(), log[0].http_status, log[0].kind.as_str()), ("failed", Some(401), "issue"));
    assert!(!serde_json::to_string(&log).unwrap().contains(TOKEN));
    // The list shows the last error.
    let v = s.integration_list(&human()).unwrap();
    assert!(v[0].last_error.as_ref().unwrap().message.contains("401"));
}

// ---- notifications -------------------------------------------------------------------------------------------

#[tokio::test]
async fn slack_gets_text_and_blocks_for_a_status_change() {
    let mock = Mock::start(|_, _| (200, "ok".into())).await;
    let (s, _) = service();
    let hook = format!("{}/services/T000/B000/SLACKSECRETPATH123456", mock.url());
    let inp = IntegrationInput {
        webhook_url: Some(hook.clone()),
        events: vec![IntegrationEvent::FindingStatusChanged],
        ..input("slack", IntegrationKind::Slack, "")
    };
    let v = s.integration_set(&human(), "slack", inp).unwrap();
    assert_eq!(v.config.base_url, mock.url(), "the origin is kept, the URL (the secret) is not");
    tokio::spawn(s.clone().run_integration_notifier());
    tokio::time::sleep(Duration::from_millis(100)).await;

    let fid = leaky_finding(&s);
    s.finding_update(
        &human(),
        pm_service::FindingUpdate {
            id: fid,
            status: Some("confirmed".into()),
            severity: None,
            description: None,
            add_evidence: vec![],
        },
    )
    .unwrap();
    let got = mock.wait(1).await;
    assert_eq!(got.len(), 1, "creating a finding is not a status change; confirming it is");
    assert_eq!((got[0].method.as_str(), got[0].path.as_str()), ("POST", "/services/T000/B000/SLACKSECRETPATH123456"));
    let b = got[0].json();
    assert!(b["text"].as_str().unwrap().contains("Finding status: confirmed"), "{b}");
    assert!(b["text"].as_str().unwrap().contains("IDOR on orders"));
    assert!(b["blocks"].as_array().unwrap().len() >= 2);
    assert_clean(&got[0].text(), "the Slack message");
    // `<`, `>` and `&` from target text cannot make a Slack mention.
    s.finding_update(
        &human(),
        pm_service::FindingUpdate {
            id: fid,
            status: Some("reported".into()),
            severity: None,
            description: Some("<!channel> a&b".into()),
            add_evidence: vec![],
        },
    )
    .unwrap();
    mock.wait(2).await;
}

#[tokio::test]
async fn a_slack_test_message_posts_and_the_webhook_url_stays_out_of_the_log() {
    let mock = Mock::start(|_, _| (404, "no_service".into())).await;
    let (s, _) = service();
    let hook = format!("{}/services/T1/B1/SLACKSECRETPATH123456", mock.url());
    let inp = IntegrationInput {
        webhook_url: Some(hook),
        events: vec![IntegrationEvent::ScanFinished],
        ..input("slack", IntegrationKind::Slack, "")
    };
    s.integration_set(&human(), "slack", inp).unwrap();
    let row = s.integration_test(&human(), "slack").await.unwrap();
    assert_eq!((row.status.as_str(), row.http_status), ("failed", Some(404)));
    assert!(!serde_json::to_string(&row).unwrap().contains("SLACKSECRETPATH"));
    assert!(mock.got()[0].json()["text"].as_str().unwrap().contains("test message"));
}

#[tokio::test]
async fn webhook_payload_is_versioned_redacted_and_signed_with_hmac_sha256() {
    let mock = Mock::start(|_, _| (200, "{}".into())).await;
    let (s, _) = service();
    let inp = IntegrationInput {
        signing_secret: Some("whsec_signing_secret_value".into()),
        headers: Some(vec![pm_service::HeaderInput {
            name: "X-Team".into(),
            value: Some("red-team-token-0123456789".into()),
        }]),
        events: vec![IntegrationEvent::FindingStatusChanged],
        ..input("hook", IntegrationKind::Webhook, &format!("{}/in", mock.url()))
    };
    s.integration_set(&human(), "hook", inp).unwrap();
    tokio::spawn(s.clone().run_integration_notifier());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let fid = leaky_finding(&s);
    s.finding_update(
        &human(),
        pm_service::FindingUpdate {
            id: fid,
            status: Some("confirmed".into()),
            severity: None,
            description: None,
            add_evidence: vec![],
        },
    )
    .unwrap();
    let got = mock.wait(1).await;
    let r = &got[0];
    assert_eq!((r.method.as_str(), r.path.as_str()), ("POST", "/in"));
    assert_eq!(r.header("content-type"), Some("application/json"));
    assert_eq!(r.header("x-proxymind-event"), Some("finding_status_changed"));
    assert_eq!(r.header("x-team"), Some("red-team-token-0123456789"));
    // The signature is HMAC-SHA256 of the exact body bytes with the secret, as hex.
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"whsec_signing_secret_value");
    let want: String = ring::hmac::sign(&key, &r.body).as_ref().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(r.header("x-proxymind-signature"), Some(format!("sha256={want}").as_str()));
    let p = r.json();
    assert_eq!(p["v"], 1);
    assert_eq!(p["event"], "finding_status_changed");
    assert_eq!(p["id"].as_str().unwrap(), r.header("x-proxymind-delivery").unwrap());
    assert_eq!(p["ts"].as_str().unwrap(), r.header("x-proxymind-timestamp").unwrap());
    assert_eq!(p["data"]["previous_status"], "suspected");
    let f = &p["data"]["finding"];
    assert_eq!(
        (f["id"].as_i64().unwrap(), f["status"].as_str().unwrap(), f["severity"].as_str().unwrap()),
        (fid, "confirmed", "high")
    );
    assert_eq!(f["issue"]["cwe"], json!(["CWE-639"]));
    assert!(f.get("request").is_none() && f["exchange_ids"].as_array().unwrap().len() == 1);
    assert_clean(&r.text(), "the webhook payload");
    // The payload parses as the documented type.
    let typed: pm_service::WebhookPayload = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(typed.v, pm_service::WEBHOOK_VERSION);
}

#[tokio::test]
async fn a_signature_is_only_sent_when_a_secret_is_set() {
    let mock = Mock::start(|_, _| (200, "{}".into())).await;
    let (s, _) = service();
    s.integration_set(&human(), "hook", input("hook", IntegrationKind::Webhook, &mock.url())).unwrap();
    s.integration_test(&human(), "hook").await.unwrap();
    let r = &mock.got()[0];
    assert!(r.header("x-proxymind-signature").is_none());
    assert_eq!(r.json()["event"], "test");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proven_findings_scan_endings_and_summaries_reach_a_webhook() {
    let mock = Mock::start(|_, _| (200, "{}".into())).await;
    let shop = VulnShop::start_local().await.unwrap();
    let url = format!("http://127.0.0.1:{}", shop.port());
    let roe = format!("version: 1\nscope:\n  include: [\"{url}/\"]\n");
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    s.attach_plugin_home(home());
    let inp = IntegrationInput {
        events: IntegrationEvent::ALL.to_vec(),
        ..input("hook", IntegrationKind::Webhook, &format!("{}/in", mock.url()))
    };
    s.integration_set(&human(), "hook", inp).unwrap();
    tokio::spawn(s.clone().run_integration_notifier());
    tokio::time::sleep(Duration::from_millis(100)).await;

    for user in ["alice", "bob"] {
        let body = format!("{{\"username\":\"{user}\",\"password\":\"{user}123\"}}");
        s.identity_set(
            &human(),
            Identity {
                name: user.into(),
                role: "user".into(),
                auth: AuthMaterial::default(),
                health: None,
                logged_out: None,
                login: Some(LoginRecipe {
                    steps: vec![LoginStep {
                        url: url.clone(),
                        request: format!(
                            "POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{body}"
                        ),
                        ..Default::default()
                    }],
                }),
            },
        )
        .unwrap();
        s.identity_login(user).await.unwrap();
    }
    let r = s
        .replay_send(
            &human(),
            ReplayRequest {
                url: Some(url.clone()),
                raw: Some("GET /api/orders/1001 HTTP/1.1\r\nHost: x\r\n\r\n".into()),
                identity: Some("alice".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let ReplayResult::Sent { exchange_id, .. } = r else { panic!("{r:?}") };
    let f = s
        .finding_create(
            &human(),
            NewFinding {
                title: "IDOR on orders".into(),
                vuln_class: "idor".into(),
                severity: "high".into(),
                description: "Any user reads any order.".into(),
                url: None,
                evidence: vec![exchange_id],
                hypothesis_id: None,
            },
        )
        .unwrap();
    let fid = f["id"].as_i64().unwrap();
    let proof = s
        .proof_run(
            &human(),
            ProofRequest {
                oracle: "differential_authz".into(),
                exchange_id: Some(exchange_id),
                attacker: Some("bob".into()),
                finding_id: Some(fid),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(matches!(proof, ProofResult::Completed { proven: true, .. }), "{proof:?}");
    let got = mock.wait(1).await;
    let events: Vec<String> = got.iter().map(|g| g.json()["event"].as_str().unwrap().to_string()).collect();
    assert_eq!(events, ["finding_proven"], "proving sends one event, not also a status change");
    let p = got[0].json();
    assert_eq!(p["data"]["finding"]["status"], "proven");
    assert_eq!(p["data"]["finding"]["proof"]["oracle"], "differential_authz");
    // The session credentials of the evidence request never go out.
    let evidence = String::from_utf8_lossy(&s.exchange_raw(exchange_id).unwrap().request).into_owned();
    for line in evidence.lines().filter(|l| {
        l.to_ascii_lowercase().starts_with("cookie:") || l.to_ascii_lowercase().starts_with("authorization:")
    }) {
        let value = line.split_once(':').unwrap().1.trim();
        assert!(!got[0].text().contains(value), "{value}");
    }

    // A scan ends: scan_finished and ci_summary (the finding above is in the summary).
    let task = s
        .scan_task_start(
            &human(),
            ScanTaskRequest {
                url: format!("{url}/"),
                max_pages: Some(5),
                browser: Some(false),
                checks: vec!["reflected_input".into()],
                record_findings: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    loop {
        let v = s.scan_task_status(&human(), &task.task_id).unwrap();
        if !matches!(v.status, ScanTaskStatus::Crawling | ScanTaskStatus::Auditing) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let got = mock.wait(3).await;
    let by_event =
        |e: &str| got.iter().map(|g| g.json()).find(|p| p["event"] == e).unwrap_or_else(|| panic!("{e} in {got:?}"));
    let scan = by_event("scan_finished");
    assert_eq!(scan["data"]["scan"]["state"], "done");
    assert!(scan["data"]["scan"]["url"].as_str().unwrap().starts_with("http://127.0.0.1"));
    let sum = by_event("ci_summary");
    assert_eq!(
        (sum["data"]["summary"]["findings"].as_u64(), sum["data"]["summary"]["proven"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(sum["data"]["summary"]["top"][0]["id"].as_i64(), Some(fid));
    assert_eq!(sum["data"]["summary"]["by_severity"][1], json!({"name": "high", "count": 1}));
}

// ---- retries, rate limit ---------------------------------------------------------------------------------------

#[tokio::test]
async fn notifications_retry_5xx_with_backoff_but_only_a_bounded_number_of_times() {
    // Always failing: exactly `max_attempts` requests, then a failed delivery.
    let always = Mock::start(|_, _| (503, "down".into())).await;
    let (s, _) = service();
    s.integration_set(&human(), "hook", input("hook", IntegrationKind::Webhook, &always.url())).unwrap();
    let integ = s.integration_get(&human(), "hook").unwrap().config;
    let data = pm_service::WebhookData { message: Some("x".into()), ..Default::default() };
    s.integration_notify_for_test(&integ, "test", "x", &data).await;
    assert_eq!(always.got().len(), 3);
    let log = s.integration_deliveries(&human(), "hook", 5).unwrap();
    assert_eq!((log[0].status.as_str(), log[0].attempts, log[0].http_status), ("failed", 3, Some(503)));

    // Two failures then success: delivered on the third attempt.
    let flaky = Mock::start(|n, _| if n < 2 { (500, "oops".into()) } else { (200, "{}".into()) }).await;
    s.integration_set(&human(), "flaky", input("flaky", IntegrationKind::Webhook, &flaky.url())).unwrap();
    let integ = s.integration_get(&human(), "flaky").unwrap().config;
    s.integration_notify_for_test(&integ, "test", "x", &data).await;
    assert_eq!(flaky.got().len(), 3);
    let log = s.integration_deliveries(&human(), "flaky", 5).unwrap();
    assert_eq!((log[0].status.as_str(), log[0].attempts), ("ok", 3));

    // A 4xx is the end: no retry.
    let bad = Mock::start(|_, _| (400, "bad".into())).await;
    s.integration_set(&human(), "bad", input("bad", IntegrationKind::Webhook, &bad.url())).unwrap();
    let integ = s.integration_get(&human(), "bad").unwrap().config;
    s.integration_notify_for_test(&integ, "test", "x", &data).await;
    assert_eq!(bad.got().len(), 1);
}

#[tokio::test]
async fn retries_wait_longer_each_time() {
    let times = Arc::new(Mutex::new(Vec::<std::time::Instant>::new()));
    let t = times.clone();
    let mock = Mock::start(move |_, _| {
        t.lock().push(std::time::Instant::now());
        (500, String::new())
    })
    .await;
    let (s, _) = service();
    s.integration_tuning_set(IntegrationTuning { max_attempts: 4, backoff_base_ms: 40, backoff_cap_ms: 1000 });
    s.integration_set(&human(), "hook", input("hook", IntegrationKind::Webhook, &mock.url())).unwrap();
    let integ = s.integration_get(&human(), "hook").unwrap().config;
    let data = pm_service::WebhookData::default();
    s.integration_notify_for_test(&integ, "test", "x", &data).await;
    let t = times.lock().clone();
    assert_eq!(t.len(), 4);
    let gaps: Vec<u128> = t.windows(2).map(|w| w[1].duration_since(w[0]).as_millis()).collect();
    assert!(gaps[0] >= 40 && gaps[1] >= 80 && gaps[2] >= 160, "{gaps:?}");
}

#[tokio::test]
async fn the_rate_limit_skips_the_excess_and_logs_it() {
    let mock = Mock::start(|_, _| (200, "{}".into())).await;
    let (s, _) = service();
    let inp = IntegrationInput { rate_per_minute: 3, ..input("hook", IntegrationKind::Webhook, &mock.url()) };
    s.integration_set(&human(), "hook", inp).unwrap();
    let integ = s.integration_get(&human(), "hook").unwrap().config;
    let data = pm_service::WebhookData::default();
    for _ in 0..8 {
        s.integration_notify_for_test(&integ, "finding_proven", "x", &data).await;
    }
    assert_eq!(mock.got().len(), 3, "a burst is capped at the per-minute rate");
    let log = s.integration_deliveries(&human(), "hook", 20).unwrap();
    assert_eq!(log.iter().filter(|d| d.status == "skipped").count(), 5);
    assert!(log.iter().any(|d| d.detail.contains("rate limited")));
}

// ---- destinations -----------------------------------------------------------------------------------------------

#[tokio::test]
async fn private_destinations_are_refused_unless_allowed_per_integration() {
    let mock = Mock::start(|_, _| (200, "{}".into())).await;
    let (s, _) = service();
    // Without the allow, a loopback server is refused before any connection is made.
    let mut inp = input("hook", IntegrationKind::Webhook, &mock.url());
    inp.allow_private = false;
    s.integration_set(&human(), "hook", inp.clone()).unwrap();
    let row = s.integration_test(&human(), "hook").await.unwrap();
    assert_eq!(row.status, "failed");
    assert!(row.detail.contains("private or loopback"), "{}", row.detail);
    assert!(mock.got().is_empty(), "nothing reached the server");
    // The allow is per integration and part of what a person reviews.
    inp.allow_private = true;
    s.integration_set(&human(), "hook", inp).unwrap();
    assert_eq!(s.integration_test(&human(), "hook").await.unwrap().status, "ok");
    assert_eq!(mock.got().len(), 1);
    // The cloud metadata address is refused even with the allow.
    let meta = input("meta", IntegrationKind::Webhook, "http://169.254.169.254/latest/meta-data/");
    s.integration_set(&human(), "meta", meta).unwrap();
    let row = s.integration_test(&human(), "meta").await.unwrap();
    assert!(row.status == "failed" && row.detail.contains("never allowed"), "{row:?}");
    // A name that points at loopback is refused the same way (localhost).
    let mut local = input("local", IntegrationKind::Webhook, &format!("http://localhost:{}/", mock.addr.port()));
    local.allow_private = false;
    s.integration_set(&human(), "local", local).unwrap();
    let row = s.integration_test(&human(), "local").await.unwrap();
    assert!(row.status == "failed" && row.detail.contains("private"), "{row:?}");
    // Every refusal is in the audit log with the host and no body.
    let audit = serde_json::to_string(&s.audit_list(1000).unwrap()).unwrap();
    assert!(audit.contains("integration_send") && audit.contains("169.254.169.254"));
}

#[tokio::test]
async fn plain_http_is_not_allowed_to_a_public_address() {
    let (s, _) = service();
    // 192.0.2.1 is documentation space, treated as private; a public literal needs https.
    s.integration_set(&human(), "hook", input("hook", IntegrationKind::Webhook, "http://93.184.216.34/hook")).unwrap();
    let row = s.integration_test(&human(), "hook").await.unwrap();
    assert!(row.status == "failed" && row.detail.contains("plain http"), "{row:?}");
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let target = Mock::start(|_, _| (200, "{}".into())).await;
    let t = target.url();
    let mock = Mock::start(move |_, _| (302, format!("{t}/elsewhere"))).await;
    let (s, _) = service();
    s.integration_set(&human(), "hook", input("hook", IntegrationKind::Webhook, &mock.url())).unwrap();
    let row = s.integration_test(&human(), "hook").await.unwrap();
    assert!(row.status == "failed" && row.detail.contains("redirect"), "{row:?}");
    assert!(target.got().is_empty());
}

#[tokio::test]
async fn tls_is_verified_so_an_untrusted_certificate_fails() {
    // A TLS server whose certificate is signed by a CA nobody trusts (ProxyMind's own CA for this test).
    let ca = pm_service::pm_tls::CertAuthority::load_or_create(&home()).unwrap();
    let cfg = ca.server_config("localhost").unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let acceptor = tokio_rustls_acceptor(cfg);
    tokio::spawn(async move {
        while let Ok((c, _)) = l.accept().await {
            let a = acceptor.clone();
            tokio::spawn(async move {
                let _ = a.accept(c).await;
            });
        }
    });
    let (s, _) = service();
    s.integration_set(&human(), "hook", input("hook", IntegrationKind::Webhook, &format!("https://localhost:{port}/")))
        .unwrap();
    let row = s.integration_test(&human(), "hook").await.unwrap();
    assert_eq!(row.status, "failed", "{row:?}");
    assert_eq!(row.attempts, 1, "a certificate error is not retried");
}

fn tokio_rustls_acceptor(cfg: Arc<tokio_rustls::rustls::ServerConfig>) -> tokio_rustls::TlsAcceptor {
    tokio_rustls::TlsAcceptor::from(cfg)
}

// ---- secrets ------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn secrets_live_outside_the_project_in_a_private_file_and_are_never_returned_or_audited() {
    let mock = Mock::start(|_, _| (200, "{}".into())).await;
    let (s, home) = service();
    let v = s.integration_set(&human(), "gh", github(&mock.url())).unwrap();
    // The API view: where the secret is and a hint, never the value.
    let json = serde_json::to_string(&v).unwrap();
    assert!(!json.contains(TOKEN), "{json}");
    assert_eq!(v.secret_status["token"].source, "saved");
    assert_eq!(v.secret_status["token"].hint.as_deref(), Some("…cdef"));
    assert_eq!(v.config.secrets["token"], "saved");
    // Not in the project's settings.
    let setting = s.store_handle().read(|db| db.get_setting("integrations")).unwrap().unwrap();
    assert!(!setting.contains(TOKEN) && !setting.contains("SECRETTOKEN"), "{setting}");
    // In the user's secrets file, readable by the owner only.
    let file = std::fs::read_to_string(home.join("integration-secrets.json")).unwrap();
    assert!(file.contains(TOKEN));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(home.join("integration-secrets.json")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    // Used for sending, then absent from every API view, the audit log and the delivery log.
    let fid = leaky_finding(&s);
    s.integration_test(&human(), "gh").await.unwrap();
    let _ = s.integration_send_finding(&human(), fid, send(fid, "gh")).await;
    for (what, text) in [
        ("list", serde_json::to_string(&s.integration_list(&human()).unwrap()).unwrap()),
        ("get", serde_json::to_string(&s.integration_get(&human(), "gh").unwrap()).unwrap()),
        ("audit", serde_json::to_string(&s.audit_list(1000).unwrap()).unwrap()),
        ("deliveries", serde_json::to_string(&s.integration_deliveries(&human(), "gh", 50).unwrap()).unwrap()),
        ("names", serde_json::to_string(&s.integration_names().unwrap()).unwrap()),
        ("finding", s.finding_get(fid).unwrap().to_string()),
    ] {
        assert!(!text.contains(TOKEN) && !text.contains("SECRETTOKEN"), "{what}: {text}");
    }
    assert!(serde_json::to_string(&s.audit_list(1000).unwrap()).unwrap().contains("integration_set"));
    // Omitting the token on a later save keeps it; an empty one removes it.
    let mut again = github(&mock.url());
    again.token = None;
    again.labels = vec!["x".into()];
    let v = s.integration_set(&human(), "gh", again.clone()).unwrap();
    assert_eq!(v.secret_status["token"].source, "saved");
    again.token = Some(String::new());
    let v = s.integration_set(&human(), "gh", again).unwrap();
    assert_eq!(v.secret_status["token"].source, "missing");
    assert!(!std::fs::read_to_string(home.join("integration-secrets.json")).unwrap().contains(TOKEN));
}

#[tokio::test]
async fn a_saved_secret_is_only_sent_to_the_server_it_was_saved_for() {
    let a = Mock::start(|_, _| (200, "{}".into())).await;
    let b = Mock::start(|_, _| (200, "{}".into())).await;
    let (s, home) = service();
    s.integration_set(&human(), "gh", github(&a.url())).unwrap();
    // Editing the address (say, a changed project file) without re-entering the token drops the saved one.
    let mut moved = github(&b.url());
    moved.token = None;
    let v = s.integration_set(&human(), "gh", moved).unwrap();
    assert_eq!(v.secret_status["token"].source, "missing", "{v:?}");
    assert!(v.problems.iter().any(|p| p.contains("token")));
    assert!(!std::fs::read_to_string(home.join("integration-secrets.json")).unwrap().contains(TOKEN));
    let err = s.integration_test(&human(), "gh").await.unwrap_err().to_string();
    assert!(err.contains("no token"), "{err}");
    assert!(b.got().is_empty());

    // Even if a hostile project file rewrites the address behind our back, the secret saved for the old
    // address is refused for the new one.
    s.integration_set(&human(), "gh2", IntegrationInput { name: "gh2".into(), ..github(&a.url()) }).unwrap();
    let mut list: Vec<Value> =
        serde_json::from_str(&s.store_handle().read(|db| db.get_setting("integrations")).unwrap().unwrap()).unwrap();
    for i in &mut list {
        if i["name"] == "gh2" {
            i["base_url"] = json!(b.url());
        }
    }
    s.store_handle().write(|db| db.set_setting("integrations", &serde_json::to_string(&list).unwrap())).unwrap();
    // (it also needs review now, so enabling it by a person is what would let it send; the secret still refuses)
    s.integration_enable(&human(), "gh2", true).unwrap();
    let err = s.integration_test(&human(), "gh2").await.unwrap_err().to_string();
    assert!(err.contains("was saved for"), "{err}");
    assert!(b.got().is_empty(), "the token never went to the other server");
}

#[tokio::test]
async fn environment_references_are_read_when_used_and_never_shown() {
    let mock = Mock::start(|_, _| (200, "{}".into())).await;
    let (s, home) = service();
    let mut inp = github(&mock.url());
    inp.token = Some("env:PATH".into());
    let v = s.integration_set(&human(), "gh", inp).unwrap();
    assert_eq!(v.config.secrets["token"], "env:PATH");
    assert_eq!(v.secret_status["token"].source, "environment");
    assert_eq!(v.secret_status["token"].reference.as_deref(), Some("env:PATH"));
    assert!(
        !home.join("integration-secrets.json").exists()
            || !std::fs::read_to_string(home.join("integration-secrets.json")).unwrap().contains("bin")
    );
    s.integration_test(&human(), "gh").await.unwrap();
    let path = std::env::var("PATH").unwrap();
    assert_eq!(mock.got()[0].header("authorization"), Some(format!("Bearer {}", path.trim()).as_str()));
    assert!(!serde_json::to_string(&s.integration_get(&human(), "gh").unwrap()).unwrap().contains(path.trim()));
    // A variable that is not set is reported, not sent as an empty token.
    let mut inp = github(&mock.url());
    inp.token = Some("env:PM_TEST_NO_SUCH_VARIABLE_42".into());
    let v = s.integration_set(&human(), "gh", inp).unwrap();
    assert_eq!(v.secret_status["token"].source, "missing");
    assert!(s.integration_test(&human(), "gh").await.is_err());
    // A reference must look like a variable name.
    let mut inp = github(&mock.url());
    inp.token = Some("env:not a name".into());
    assert!(s.integration_set(&human(), "gh", inp).is_err());
}

#[tokio::test]
async fn without_a_home_directory_saved_secrets_are_refused_but_references_work() {
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap();
    let err = s.integration_set(&human(), "gh", github("https://api.github.com")).unwrap_err().to_string();
    assert!(err.contains("home directory"), "{err}");
    let mut inp = github("https://api.github.com");
    inp.token = Some("env:PATH".into());
    assert!(s.integration_set(&human(), "gh", inp).is_ok());
}

// ---- project files (F-2) and who may do what ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integrations_from_a_project_file_stay_off_until_a_person_enables_them_here() {
    let mock = Mock::start(|_, _| (200, "{}".into())).await;
    let (s, _) = service();
    // A foreign project file names an enabled webhook with every event and a private destination allowed.
    let foreign = json!([{
        "name": "exfil", "kind": "webhook", "enabled": true, "base_url": mock.url(), "allow_private": true,
        "events": ["finding_status_changed", "finding_proven", "scan_finished", "ci_summary"],
        "rate_per_minute": 20, "secrets": {}, "header_names": [], "labels": []
    }]);
    s.store_handle().write(|db| db.set_setting("integrations", &foreign.to_string())).unwrap();
    let v = s.integration_list(&human()).unwrap();
    assert!(v[0].config.enabled && v[0].needs_review && !v[0].active, "{:?}", v[0]);
    assert!(!s.integration_names().unwrap()[0].enabled, "agents see it as off");
    tokio::spawn(s.clone().run_integration_notifier());
    tokio::time::sleep(Duration::from_millis(100)).await;
    let fid = leaky_finding(&s);
    s.finding_update(
        &human(),
        pm_service::FindingUpdate {
            id: fid,
            status: Some("confirmed".into()),
            severity: None,
            description: None,
            add_evidence: vec![],
        },
    )
    .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(mock.got().is_empty(), "nothing is sent automatically");
    let err = s.integration_test(&human(), "exfil").await.unwrap_err().to_string();
    assert!(err.contains("not been enabled in this installation"), "{err}");
    assert!(mock.got().is_empty());

    // A person reviews and enables it here: now it sends.
    let v = s.integration_enable(&human(), "exfil", true).unwrap();
    assert!(!v.needs_review && v.active);
    assert_eq!(s.integration_test(&human(), "exfil").await.unwrap().status, "ok");

    // If the project file later points it somewhere else, it is off again until reviewed.
    let moved = json!([{
        "name": "exfil", "kind": "webhook", "enabled": true, "base_url": "http://127.0.0.1:9/elsewhere", "allow_private": true,
        "events": ["finding_status_changed"], "rate_per_minute": 20, "secrets": {}, "header_names": [], "labels": []
    }]);
    s.store_handle().write(|db| db.set_setting("integrations", &moved.to_string())).unwrap();
    let v = s.integration_list(&human()).unwrap();
    assert!(v[0].needs_review && !v[0].active);
    assert!(s.integration_test(&human(), "exfil").await.is_err());
}

#[tokio::test]
async fn trust_is_kept_in_the_home_directory_not_the_project() {
    let (s, home) = service();
    s.integration_set(&human(), "hook", input("hook", IntegrationKind::Webhook, "http://127.0.0.1:1/")).unwrap();
    let trust = std::fs::read_to_string(home.join("integration-trust.json")).unwrap();
    assert!(trust.contains("hook"));
    // A second installation (another home) opening the same project file does not trust it.
    let setting = s.store_handle().read(|db| db.get_setting("integrations")).unwrap().unwrap();
    let pid = s.store_handle().read(|db| db.get_setting("project_id")).unwrap().unwrap();
    let other = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap();
    other.attach_plugin_home(self::home());
    other
        .store_handle()
        .write(|db| {
            db.set_setting("integrations", &setting)?;
            db.set_setting("project_id", &pid)
        })
        .unwrap();
    let v = other.integration_list(&human()).unwrap();
    assert!(v[0].needs_review && !v[0].active);
}

#[tokio::test]
async fn only_people_configure_enable_test_or_send_and_agents_see_names_only() {
    let mock = Mock::start(|_, _| (201, r#"{"number":1,"html_url":"https://github.com/a/b/issues/1"}"#.into())).await;
    let (s, _) = service();
    s.integration_set(&human(), "gh", github(&mock.url())).unwrap();
    let fid = leaky_finding(&s);
    for who in ["agent:claude", "plugin:p", "scanner:s", "ci:pipeline"] {
        let a = Actor::parse(who).unwrap();
        assert!(s.integration_set(&a, "x", input("x", IntegrationKind::Webhook, &mock.url())).is_err(), "{who} set");
        assert!(s.integration_enable(&a, "gh", false).is_err(), "{who} enable");
        assert!(s.integration_delete(&a, "gh").is_err(), "{who} delete");
        assert!(s.integration_test(&a, "gh").await.is_err(), "{who} test");
        assert!(s.integration_send_finding(&a, fid, send(fid, "gh")).await.is_err(), "{who} send");
        assert!(s.integration_list(&a).is_err(), "{who} list");
        assert!(s.integration_get(&a, "gh").is_err(), "{who} get");
        assert!(s.integration_deliveries(&a, "gh", 5).is_err(), "{who} deliveries");
    }
    assert!(mock.got().is_empty(), "no agent action reached the server");
    assert_eq!(s.integration_list(&human()).unwrap().len(), 1, "nothing was changed or removed");
    // The denials are audited.
    let audit = s.audit_list(1000).unwrap();
    assert!(audit.iter().any(|r| r.action == "integration_set" && r.decision == "deny" && r.actor == "agent:claude"));
    assert!(audit.iter().any(|r| r.action == "integration_send_finding" && r.decision == "deny"));
    // What an agent may learn: names, kinds and whether each is on. No address, project or secret.
    let names = serde_json::to_string(&s.integration_names().unwrap()).unwrap();
    assert!(names.contains("\"gh\"") && names.contains("github"));
    assert!(!names.contains("acme") && !names.contains(&mock.url()) && !names.contains("token"), "{names}");
}

#[tokio::test]
async fn deleting_an_integration_removes_its_secrets_trust_and_log() {
    let mock = Mock::start(|_, _| (200, "{}".into())).await;
    let (s, home) = service();
    s.integration_set(&human(), "gh", github(&mock.url())).unwrap();
    s.integration_test(&human(), "gh").await.unwrap();
    s.integration_delete(&human(), "gh").unwrap();
    assert!(s.integration_list(&human()).unwrap().is_empty());
    assert!(!std::fs::read_to_string(home.join("integration-secrets.json")).unwrap().contains(TOKEN));
    assert!(!std::fs::read_to_string(home.join("integration-trust.json")).unwrap().contains("gh"));
    assert!(s.integration_deliveries(&human(), "gh", 5).is_err(), "gone");
}

#[tokio::test]
async fn configuration_is_validated() {
    let (s, _) = service();
    let bad = |i: IntegrationInput| s.integration_set(&human(), &i.name.clone(), i).is_err();
    assert!(bad(input("a b", IntegrationKind::Webhook, "https://x.test")), "name");
    assert!(bad(input("w", IntegrationKind::Webhook, "ftp://x.test")), "scheme");
    assert!(bad(input("w", IntegrationKind::Webhook, "https://user:pw@x.test")), "credentials in the URL");
    assert!(
        bad(IntegrationInput { project: "no-slash".into(), ..input("g", IntegrationKind::Github, "") }),
        "owner/repo"
    );
    assert!(
        bad(IntegrationInput {
            project: "SEC".into(),
            events: vec![IntegrationEvent::FindingProven],
            ..input("j", IntegrationKind::Jira, "https://j.test")
        }),
        "events on a tracker"
    );
    assert!(
        bad(IntegrationInput { rate_per_minute: 500, ..input("w", IntegrationKind::Webhook, "https://x.test") }),
        "rate"
    );
    assert!(
        bad(IntegrationInput {
            headers: Some(vec![pm_service::HeaderInput { name: "Host".into(), value: Some("x".into()) }]),
            ..input("w", IntegrationKind::Webhook, "https://x.test")
        }),
        "framing header"
    );
    assert!(
        bad(IntegrationInput {
            signing_secret: Some("a\r\nb".into()),
            ..input("w", IntegrationKind::Webhook, "https://x.test")
        }),
        "line break in a secret"
    );
    assert!(
        bad(IntegrationInput { token: Some("t".into()), ..input("w", IntegrationKind::Webhook, "https://x.test") }),
        "a token on a webhook"
    );
    // A trailing-slash-free GitHub default needs no URL.
    assert!(
        s.integration_set(
            &human(),
            "g",
            IntegrationInput {
                project: "a/b".into(),
                token: Some("env:PATH".into()),
                ..input("g", IntegrationKind::Github, "")
            }
        )
        .is_ok()
    );
}

#[tokio::test]
async fn a_second_send_of_the_same_finding_cannot_run_at_once() {
    let mock = Mock::start(|_, _| {
        std::thread::sleep(Duration::from_millis(300));
        (201, r#"{"number":2,"html_url":"https://github.com/a/b/issues/2"}"#.into())
    })
    .await;
    let (s, _) = service();
    s.integration_set(&human(), "gh", github(&mock.url())).unwrap();
    let fid = leaky_finding(&s);
    let me = human();
    let (a, b) = tokio::join!(s.integration_send_finding(&me, fid, send(fid, "gh")), async {
        tokio::time::sleep(Duration::from_millis(80)).await;
        s.integration_send_finding(&me, fid, send(fid, "gh")).await
    });
    assert!(a.is_ok(), "{a:?}");
    assert!(b.is_err(), "{b:?}");
    assert_eq!(mock.got().len(), 1, "one issue");
}
