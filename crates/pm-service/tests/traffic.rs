//! HAR import and export, cURL commands: nothing sent, secrets hidden from agents.

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::{HistoryFilter, Store};
use pm_service::{ExportRequest, ImportRequest, Service};

const HAR: &str = r#"{"log":{"version":"1.2","entries":[
  {"startedDateTime":"2024-05-01T12:00:00.000Z","time":20,
   "request":{"method":"GET","url":"https://shop.test/api/me","httpVersion":"HTTP/1.1",
     "headers":[{"name":"Host","value":"shop.test"},
                {"name":"Cookie","value":"session=s3cr3t-session-value-0123456789"}]},
   "response":{"status":200,"statusText":"OK","headers":[{"name":"Content-Type","value":"application/json"}],
     "content":{"size":14,"text":"{\"user\":\"bo\"}"}}},
  {"startedDateTime":"2024-05-01T12:00:01.000Z","time":5,
   "request":{"method":"POST","url":"https://shop.test/api/cart","headers":[],
     "postData":{"mimeType":"application/json","text":"{\"id\":1}"}},
   "response":{"status":201,"headers":[],"content":{"text":""}}},
  {"request":{"method":"GET","url":"gopher://x/"}}
]}}"#;

fn service() -> Service {
    let roe = "version: 1\nscope:\n  include: [\"https://shop.test/\"]\n";
    Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(roe).unwrap())).unwrap()
}

#[test]
fn imports_and_exports_har() {
    let s = service();
    let human = Actor::parse("human:tester").unwrap();
    let r = s.traffic_import_har(&human, &ImportRequest { har: HAR.into() }).unwrap();
    assert_eq!(r.imported, 2);
    assert_eq!(r.skipped.len(), 1, "{:?}", r.skipped);

    let page =
        s.history_search(&human, &HistoryFilter { source: Some("import".into()), ..Default::default() }).unwrap();
    assert_eq!(page.exchanges.len(), 2);
    let cart = page.exchanges.iter().find(|e| e.path == "/api/cart").unwrap();
    assert_eq!((cart.status, cart.actor_id.as_str()), (Some(201), "human:tester"));

    let har = s.traffic_export_har(&human, &ExportRequest::default()).unwrap();
    let entries = har["log"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let me = entries.iter().find(|e| e["request"]["url"] == "https://shop.test/api/me").unwrap();
    assert!(me.to_string().contains("s3cr3t-session-value"), "humans get the real values");
    assert_eq!(me["response"]["content"]["text"], "{\"user\":\"bo\"}");

    // Agents get placeholders instead of secrets.
    let agent = Actor::parse("agent:test").unwrap();
    let har =
        s.traffic_export_har(&agent, &ExportRequest { ids: Some(vec![me_id(&s)]), ..Default::default() }).unwrap();
    assert!(!har.to_string().contains("s3cr3t-session-value"), "{har}");
    assert!(s.exchange_curl(&agent, me_id(&s)).unwrap().contains("Cookie: session="));
    assert!(!s.exchange_curl(&agent, me_id(&s)).unwrap().contains("s3cr3t"));

    // Export and import are audited; the audit chain still verifies.
    let actions: Vec<String> = s.audit_list(20).unwrap().into_iter().map(|a| a.action).collect();
    assert!(actions.contains(&"import_har".to_string()) && actions.contains(&"export_har".to_string()));
    s.audit_verify().unwrap();
    assert!(s.traffic_import_har(&human, &ImportRequest { har: "{}".into() }).is_err());
}

fn me_id(s: &Service) -> i64 {
    let human = Actor::parse("human:tester").unwrap();
    let page = s.history_search(&human, &HistoryFilter { path: Some("/api/me".into()), ..Default::default() }).unwrap();
    page.exchanges[0].id
}

#[test]
fn curl_round_trip() {
    let s = service();
    let human = Actor::parse("human:tester").unwrap();
    s.traffic_import_har(&human, &ImportRequest { har: HAR.into() }).unwrap();
    let cmd = s.exchange_curl(&human, me_id(&s)).unwrap();
    assert!(cmd.starts_with("curl 'https://shop.test/api/me'"), "{cmd}");
    let parsed = s.curl_parse(&cmd).unwrap();
    assert_eq!(parsed.url, "https://shop.test");
    assert_eq!(parsed.method, "GET");
    assert!(parsed.raw.contains("Cookie: session=s3cr3t-session-value-0123456789\r\n"), "{}", parsed.raw);
    assert!(s.curl_parse("curl").is_err());
}
