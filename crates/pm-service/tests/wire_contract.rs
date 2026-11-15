//! Golden wire tests for the typed API contracts (ADR-0019). Each test pins the exact JSON a type
//! reads or writes, so a serde change (a rename, a default, a skipped field) fails here instead of
//! silently changing the API. The expected strings are the wire format; update one only on purpose.

use pm_service::pm_ai::{BodyView, ExchangeView, MessageView, View};
use pm_service::{
    AuthzCheckRequest, EngageFilter, FindingUpdate, ModelFilter, NewFinding, ProofRequest, ProofResult, ReplayRequest,
    ReplayResult, ScanTaskRequest, WsOut, WsReplayRequest,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

fn json<T: Serialize>(v: &T) -> String {
    serde_json::to_string(v).unwrap()
}

/// Parses `body` and serializes it again: what the service understood the client to have said.
fn reparsed<T: DeserializeOwned + Serialize>(body: &str) -> String {
    json(&serde_json::from_str::<T>(body).unwrap())
}

fn rejects_unknown<T: DeserializeOwned>(body: &str) {
    let err = serde_json::from_str::<T>(body).err().expect("unknown field must be rejected").to_string();
    assert!(err.contains("unknown field `nope`"), "{err}");
}

#[test]
fn replay_request() {
    let sample = ReplayRequest {
        raw: Some("GET / HTTP/1.1\r\nHost: a\r\n\r\n".into()),
        exchange_id: Some(7),
        url: Some("https://a".into()),
        identity: Some("alice".into()),
        fix_content_length: Some(false),
        normalize_newlines: Some(true),
        approval_id: Some("ap1".into()),
        hypothesis_id: Some(3),
        view: Some(View::Headers),
        max_tokens: Some(500),
    };
    assert_eq!(json(&sample), EXPECTED_REPLAY_FULL);
    assert_eq!(json(&ReplayRequest::default()), EXPECTED_REPLAY_EMPTY);
    assert_eq!(reparsed::<ReplayRequest>(r#"{"exchange_id":7,"view":"full"}"#), EXPECTED_REPLAY_PARSED);
    rejects_unknown::<ReplayRequest>(r#"{"nope":1}"#);
}

#[test]
fn proof_request() {
    let sample = ProofRequest {
        oracle: "timing".into(),
        exchange_id: Some(1),
        samples: Some(8),
        raws: vec!["a".into(), "b".into()],
        markers: vec!["root:".into()],
        marker_kind: Some("redirect".into()),
        ..Default::default()
    };
    assert_eq!(json(&sample), EXPECTED_PROOF_SAMPLE);
    assert_eq!(json(&ProofRequest::default()), EXPECTED_PROOF_EMPTY);
    assert_eq!(
        reparsed::<ProofRequest>(r#"{"oracle":"differential_authz","exchange_id":4,"attacker":"bob"}"#),
        EXPECTED_PROOF_PARSED
    );
    rejects_unknown::<ProofRequest>(r#"{"oracle":"timing","nope":1}"#);
}

#[test]
fn authz_check_request() {
    let sample = AuthzCheckRequest { exchange_id: 9, identities: vec!["bob".into()], include_anonymous: Some(false) };
    assert_eq!(json(&sample), EXPECTED_AUTHZ_SAMPLE);
    assert_eq!(reparsed::<AuthzCheckRequest>(r#"{"exchange_id":9}"#), EXPECTED_AUTHZ_PARSED);
    // `exchange_id` is required.
    assert!(serde_json::from_str::<AuthzCheckRequest>("{}").is_err());
    rejects_unknown::<AuthzCheckRequest>(r#"{"exchange_id":9,"nope":1}"#);
}

#[test]
fn scan_task_request() {
    let sample = ScanTaskRequest {
        url: "https://app.example.com/".into(),
        profile: Some("light".into()),
        crawl: Some(true),
        max_pages: Some(10),
        browser: Some(false),
        max_targets: Some(5),
        max_requests: Some(100),
        checks: vec!["xss".into()],
        record_findings: Some(true),
        identity: Some("alice".into()),
        approval_id: Some("ap1".into()),
    };
    assert_eq!(json(&sample), EXPECTED_SCAN_SAMPLE);
    assert_eq!(reparsed::<ScanTaskRequest>(r#"{"url":"https://a/","max_pages":3}"#), EXPECTED_SCAN_PARSED);
    rejects_unknown::<ScanTaskRequest>(r#"{"nope":1}"#);
}

#[test]
fn new_finding() {
    let sample = NewFinding {
        title: "IDOR".into(),
        vuln_class: "idor".into(),
        severity: "high".into(),
        description: "d".into(),
        url: Some("https://a/x".into()),
        evidence: vec![1, 2],
        hypothesis_id: Some(5),
    };
    assert_eq!(json(&sample), EXPECTED_FINDING_SAMPLE);
    assert_eq!(
        reparsed::<NewFinding>(r#"{"title":"t","vuln_class":"xss","severity":"low","description":"d"}"#),
        EXPECTED_FINDING_PARSED
    );
    assert!(serde_json::from_str::<NewFinding>(r#"{"title":"t"}"#).is_err());
    rejects_unknown::<NewFinding>(r#"{"title":"t","vuln_class":"x","severity":"low","description":"d","nope":1}"#);
}

#[test]
fn finding_update() {
    let sample = FindingUpdate {
        id: 3,
        status: Some("confirmed".into()),
        severity: Some("medium".into()),
        description: Some("d".into()),
        add_evidence: vec![4],
    };
    assert_eq!(json(&sample), EXPECTED_FUPDATE_SAMPLE);
    assert_eq!(reparsed::<FindingUpdate>(r#"{"id":3,"status":"fixed"}"#), EXPECTED_FUPDATE_PARSED);
    rejects_unknown::<FindingUpdate>(r#"{"id":3,"nope":1}"#);
}

/// `EngageFilter` and `ModelFilter` only derive `Deserialize` (nothing sends them), so the golden is
/// the parsed value, as `Debug` text.
#[test]
fn engage_filter() {
    let f: EngageFilter = serde_json::from_str(r#"{"host":"a.test","in_scope":true,"max_scan":100}"#).unwrap();
    assert_eq!(format!("{f:?}"), EXPECTED_ENGAGE_PARSED);
    let f: EngageFilter = serde_json::from_str("{}").unwrap();
    assert_eq!(format!("{f:?}"), EXPECTED_ENGAGE_EMPTY);
    rejects_unknown::<EngageFilter>(r#"{"nope":1}"#);
}

#[test]
fn model_filter() {
    let f: ModelFilter =
        serde_json::from_str(r#"{"contains":"orders","include_objects":true,"object_type":"Order"}"#).unwrap();
    assert_eq!(format!("{f:?}"), EXPECTED_MODEL_PARSED);
    let f: ModelFilter = serde_json::from_str("{}").unwrap();
    assert_eq!(format!("{f:?}"), EXPECTED_MODEL_EMPTY);
    rejects_unknown::<ModelFilter>(r#"{"nope":1}"#);
}

#[test]
fn ws_replay_request() {
    let sample = WsReplayRequest {
        exchange_id: 12,
        raw: Some("GET /ws HTTP/1.1\r\n\r\n".into()),
        messages: vec![WsOut { text: Some("hi".into()), hex: None }, WsOut { text: None, hex: Some("00 ff".into()) }],
        wait_ms: Some(500),
        identity: Some("alice".into()),
        approval_id: Some("ap1".into()),
        hypothesis_id: Some(2),
        max_chars: Some(100),
    };
    assert_eq!(json(&sample), EXPECTED_WS_SAMPLE);
    assert_eq!(reparsed::<WsReplayRequest>(r#"{"exchange_id":12,"messages":[{"text":"x"}]}"#), EXPECTED_WS_PARSED);
    rejects_unknown::<WsReplayRequest>(r#"{"nope":1}"#);
    rejects_unknown::<WsOut>(r#"{"nope":1}"#);
}

/// The request bodies and query strings that used to live in `pm-api` (`pm_service::api_types`): what each reads
/// from JSON, what it fills in for a missing field, and whether an unknown field is an error. The strings are
/// the parsed value written back out, so a renamed field, a changed default or a dropped `deny_unknown_fields`
/// fails here.
#[test]
fn api_types_wire_format() {
    use pm_service::api_types::*;

    /// (what the client sent, what the service understood). `reject` lists bodies that must fail.
    fn check<T: DeserializeOwned + Serialize>(cases: &[(&str, &str)], reject: &[&str]) {
        for (sent, understood) in cases {
            assert_eq!(reparsed::<T>(sent), *understood, "{} reading {sent}", std::any::type_name::<T>());
        }
        for sent in reject {
            assert!(serde_json::from_str::<T>(sent).is_err(), "{} must reject {sent}", std::any::type_name::<T>());
        }
    }
    let unknown = r#"{"nope":1}"#;

    // Required fields, unknown fields ignored (no `deny_unknown_fields`).
    check::<CaptureBody>(
        &[
            (r#"{"name":"a","exchange_id":3}"#, r#"{"name":"a","role":null,"exchange_id":3}"#),
            (r#"{"name":"a","exchange_id":3,"extra":1}"#, r#"{"name":"a","role":null,"exchange_id":3}"#),
            (r#"{"name":"a","role":"admin","exchange_id":3}"#, r#"{"name":"a","role":"admin","exchange_id":3}"#),
        ],
        &[r#"{"name":"a"}"#, r#"{"exchange_id":3}"#],
    );
    check::<RecordLoginBody>(
        &[(r#"{"name":"a","from":1}"#, r#"{"name":"a","role":null,"from":1,"to":null}"#)],
        &[r#"{"name":"a"}"#],
    );
    check::<SendBody>(&[(r#"{"text":"hi"}"#, r#"{"chat_id":null,"text":"hi"}"#)], &[r#"{"chat_id":1}"#]);
    check::<ForwardBody>(
        &[
            ("{}", r#"{"raw":null,"fix_content_length":null}"#),
            (r#"{"raw":"x","fix_content_length":false}"#, r#"{"raw":"x","fix_content_length":false}"#),
        ],
        &[],
    );
    check::<AnnotationBody>(&[("{}", r#"{"highlight":null,"comment":null}"#)], &[]);
    check::<CodeQuery>(&[(r#"{"lang":"javascript"}"#, r#"{"lang":"javascript"}"#)], &["{}", r#"{"lang":"ruby"}"#]);
    check::<CompareBody>(&[(r#"{"a":1,"b":2}"#, r#"{"a":1,"b":2}"#)], &[r#"{"a":1}"#]);
    check::<TokensBody>(&[(r#"{"tokens":["a"]}"#, r#"{"tokens":["a"]}"#)], &["{}"]);
    check::<RoeBody>(&[(r#"{"text":"t"}"#, r#"{"text":"t"}"#)], &["{}"]);

    // Everything optional, unknown fields ignored.
    check::<StatusQuery>(&[("{}", r#"{"status":null}"#)], &[]);
    check::<OrganizerQuery>(&[("{}", r#"{"status":null}"#), (unknown, r#"{"status":null}"#)], &[]);
    check::<CollabQuery>(&[("{}", r#"{"limit":null,"token":null}"#)], &[]);
    check::<WsHistoryQuery>(&[("{}", r#"{"host":null,"before_id":null,"limit":null}"#)], &[]);

    // `deny_unknown_fields`, with and without a container `default`.
    check::<SnapshotBody>(&[(r#"{"name":"s"}"#, r#"{"name":"s"}"#)], &[unknown, r#"{"name":"s","nope":1}"#, "{}"]);
    check::<ChangesQuery>(&[(r#"{"snapshot":2}"#, r#"{"snapshot":2}"#)], &[unknown, "{}"]);
    check::<ProbesQuery>(&[("{}", r#"{"limit":null}"#)], &[unknown]);
    check::<ListenBody>(
        &[(r#"{"listen":"127.0.0.1:1"}"#, r#"{"listen":"127.0.0.1:1","public_url":null}"#)],
        &[unknown, "{}"],
    );
    check::<SmtpBody>(&[(r#"{"listen":"127.0.0.1:2"}"#, r#"{"listen":"127.0.0.1:2"}"#)], &[unknown, "{}"]);
    check::<PayloadBody>(&[("{}", r#"{"note":""}"#), (r#"{"note":"n"}"#, r#"{"note":"n"}"#)], &[unknown]);
    check::<OrganizerAdd>(
        &[(r#"{"exchange_id":4}"#, r#"{"exchange_id":4,"note":""}"#)],
        &[unknown, r#"{"exchange_id":4,"nope":1}"#, "{}"],
    );
    check::<UpdateSet>(&[(r#"{"enabled":true}"#, r#"{"enabled":true}"#)], &[unknown, "{}"]);
    check::<UpdateCheck>(&[("{}", r#"{"force":false}"#)], &[unknown]);
    check::<ReconDns>(
        &[
            (r#"{"host":"a"}"#, r#"{"host":"a","resolver":null}"#),
            (r#"{"host":"a","resolver":"1.1.1.1:53"}"#, r#"{"host":"a","resolver":"1.1.1.1:53"}"#),
        ],
        &[r#"{"host":"a","nope":1}"#, "{}", r#"{"host":"a","resolver":"not an address"}"#],
    );
    check::<ReconWayback>(&[(r#"{"host":"a"}"#, r#"{"host":"a","limit":null}"#)], &[r#"{"host":"a","nope":1}"#, "{}"]);
    check::<TriageBody>(&[("{}", r#"{"host":null,"in_scope":null,"limit":null}"#)], &[unknown]);
    check::<HostQuery>(&[("{}", r#"{"host":null}"#)], &[unknown]);
    check::<ScanQuery>(&[("{}", r#"{"scan":null}"#)], &[unknown]);
    check::<ExplainBody>(&[("{}", r#"{"framework":null}"#)], &[unknown]);
    check::<PackQuery>(&[("{}", r#"{"all":false}"#), (r#"{"all":true}"#, r#"{"all":true}"#)], &[unknown]);
    check::<EngageExchange>(
        &[
            (r#"{"exchange_id":5}"#, r#"{"exchange_id":5,"technique":"auto","auto_submit":false}"#),
            (
                r#"{"exchange_id":5,"technique":"text_plain","auto_submit":true}"#,
                r#"{"exchange_id":5,"technique":"text_plain","auto_submit":true}"#,
            ),
        ],
        &[r#"{"exchange_id":5,"nope":1}"#, "{}", r#"{"exchange_id":5,"technique":"Form"}"#],
    );
    check::<PluginSet>(&[(r#"{"enabled":false}"#, r#"{"enabled":false}"#)], &[unknown, "{}"]);
    check::<CheckYaml>(&[(r#"{"yaml":"id: x"}"#, r#"{"yaml":"id: x"}"#)], &[unknown, "{}"]);
    check::<CodeBody>(
        &[(r#"{"url":"https://a","raw":"r","lang":"python"}"#, r#"{"url":"https://a","raw":"r","lang":"python"}"#)],
        &[r#"{"url":"https://a","raw":"r","lang":"python","nope":1}"#, r#"{"url":"https://a","raw":"r"}"#],
    );
    check::<KeyBody>(
        &[(r#"{"name":"N","key":"k"}"#, r#"{"name":"N","key":"k"}"#)],
        &[r#"{"name":"N","key":"k","nope":1}"#, r#"{"name":"N"}"#],
    );
    check::<AiScanMessage>(&[(r#"{"text":"t"}"#, r#"{"text":"t"}"#)], &[unknown, "{}"]);

    // Nested types keep their own rules.
    check::<ListenersBody>(
        &[(
            r#"{"listeners":[{"bind":"127.0.0.1:1"}]}"#,
            r#"{"listeners":[{"bind":"127.0.0.1:1","enabled":true,"redirect_host":"","redirect_port":0,"force_tls":false}]}"#,
        )],
        &["{}", r#"{"listeners":[{"nope":1}]}"#],
    );
    check::<RulesBody>(&[(r#"{"rules":[]}"#, r#"{"rules":[]}"#)], &["{}"]);
}

#[test]
fn proof_result() {
    let done = ProofResult::Completed {
        proof_id: 1,
        oracle: "timing".into(),
        proven: true,
        confidence: "high".into(),
        reasons: vec!["slow".into()],
        exchange_ids: vec![2, 3],
        details: serde_json::json!({"median_ms": 900}),
    };
    assert_eq!(json(&done), EXPECTED_PROOF_COMPLETED);
    let pending = ProofResult::PendingApproval { approval_id: "ap1".into(), summary: "s".into(), reasons: vec![] };
    assert_eq!(json(&pending), EXPECTED_PROOF_PENDING);
    assert_eq!(json(&ProofResult::Denied { reasons: vec!["out of scope".into()] }), EXPECTED_PROOF_DENIED);
}

#[test]
fn replay_result() {
    let view = ExchangeView {
        id: 5,
        url: "https://a/".into(),
        method: "GET".into(),
        status: Some(200),
        duration_ms: Some(12),
        source: "replay".into(),
        actor: "agent:x".into(),
        request: MessageView {
            start_line: "GET / HTTP/1.1".into(),
            headers: vec![("Host".into(), "a".into())],
            body: None,
        },
        response: Some(MessageView {
            start_line: "HTTP/1.1 200 OK".into(),
            headers: vec![],
            body: Some(BodyView {
                kind: "text".into(),
                content_type: Some("text/plain".into()),
                size: 2,
                outline: None,
                text: Some("ok".into()),
                truncated: false,
                notes: vec![],
            }),
        }),
        error: None,
        possible_prompt_injection: vec![],
        redacted: false,
        notice: "untrusted",
    };
    let sent = ReplayResult::Sent { exchange_id: 5, elapsed_ms: 12, notes: vec![], view: Box::new(view) };
    assert_eq!(json(&sent), EXPECTED_REPLAY_SENT);
    assert_eq!(json(&ReplayResult::Failed { exchange_id: 6, error: "refused".into() }), EXPECTED_REPLAY_FAILED);
    let pending =
        ReplayResult::PendingApproval { approval_id: "ap1".into(), summary: "s".into(), reasons: vec!["r".into()] };
    assert_eq!(json(&pending), EXPECTED_REPLAY_PENDING);
    assert_eq!(json(&ReplayResult::Denied { reasons: vec![] }), EXPECTED_REPLAY_DENIED);
}

const EXPECTED_AUTHZ_PARSED: &str = r#"{"exchange_id":9,"identities":[],"include_anonymous":null}"#;
const EXPECTED_AUTHZ_SAMPLE: &str = r#"{"exchange_id":9,"identities":["bob"],"include_anonymous":false}"#;
const EXPECTED_ENGAGE_EMPTY: &str = r#"EngageFilter { host: None, in_scope: None, max_scan: None }"#;
const EXPECTED_ENGAGE_PARSED: &str =
    r#"EngageFilter { host: Some("a.test"), in_scope: Some(true), max_scan: Some(100) }"#;
const EXPECTED_FINDING_PARSED: &str = r#"{"title":"t","vuln_class":"xss","severity":"low","description":"d","url":null,"evidence":[],"hypothesis_id":null}"#;
const EXPECTED_FINDING_SAMPLE: &str = r#"{"title":"IDOR","vuln_class":"idor","severity":"high","description":"d","url":"https://a/x","evidence":[1,2],"hypothesis_id":5}"#;
const EXPECTED_FUPDATE_PARSED: &str =
    r#"{"id":3,"status":"fixed","severity":null,"description":null,"add_evidence":[]}"#;
const EXPECTED_FUPDATE_SAMPLE: &str =
    r#"{"id":3,"status":"confirmed","severity":"medium","description":"d","add_evidence":[4]}"#;
const EXPECTED_MODEL_EMPTY: &str = r#"ModelFilter { contains: None, include_objects: None, object_type: None }"#;
const EXPECTED_MODEL_PARSED: &str =
    r#"ModelFilter { contains: Some("orders"), include_objects: Some(true), object_type: Some("Order") }"#;
const EXPECTED_PROOF_COMPLETED: &str = r#"{"status":"completed","proof_id":1,"oracle":"timing","proven":true,"confidence":"high","reasons":["slow"],"exchange_ids":[2,3],"details":{"median_ms":900}}"#;
const EXPECTED_PROOF_DENIED: &str = r#"{"status":"denied","reasons":["out of scope"]}"#;
const EXPECTED_PROOF_EMPTY: &str = r#"{"oracle":"","exchange_id":null,"attacker":null,"owner":null,"url":null,"baseline_raw":null,"payload_raw":null,"samples":null,"min_effect_ms":null,"raw":null,"wait_seconds":null,"marker_kind":null,"view_raw":null,"identity":null,"finding_id":null,"hypothesis_id":null,"approval_id":null}"#;
const EXPECTED_PROOF_PARSED: &str = r#"{"oracle":"differential_authz","exchange_id":4,"attacker":"bob","owner":null,"url":null,"baseline_raw":null,"payload_raw":null,"samples":null,"min_effect_ms":null,"raw":null,"wait_seconds":null,"marker_kind":null,"view_raw":null,"identity":null,"finding_id":null,"hypothesis_id":null,"approval_id":null}"#;
const EXPECTED_PROOF_PENDING: &str = r#"{"status":"pending_approval","approval_id":"ap1","summary":"s","reasons":[]}"#;
const EXPECTED_PROOF_SAMPLE: &str = r#"{"oracle":"timing","exchange_id":1,"attacker":null,"owner":null,"url":null,"baseline_raw":null,"payload_raw":null,"samples":8,"min_effect_ms":null,"raw":null,"wait_seconds":null,"raws":["a","b"],"markers":["root:"],"marker_kind":"redirect","view_raw":null,"identity":null,"finding_id":null,"hypothesis_id":null,"approval_id":null}"#;
const EXPECTED_REPLAY_DENIED: &str = r#"{"status":"denied","reasons":[]}"#;
const EXPECTED_REPLAY_EMPTY: &str = r#"{"raw":null,"exchange_id":null,"url":null,"identity":null,"fix_content_length":null,"normalize_newlines":null,"approval_id":null,"hypothesis_id":null,"view":null,"max_tokens":null}"#;
const EXPECTED_REPLAY_FAILED: &str = r#"{"status":"failed","exchange_id":6,"error":"refused"}"#;
const EXPECTED_REPLAY_FULL: &str = r#"{"raw":"GET / HTTP/1.1\r\nHost: a\r\n\r\n","exchange_id":7,"url":"https://a","identity":"alice","fix_content_length":false,"normalize_newlines":true,"approval_id":"ap1","hypothesis_id":3,"view":"headers","max_tokens":500}"#;
const EXPECTED_REPLAY_PARSED: &str = r#"{"raw":null,"exchange_id":7,"url":null,"identity":null,"fix_content_length":null,"normalize_newlines":null,"approval_id":null,"hypothesis_id":null,"view":"full","max_tokens":null}"#;
const EXPECTED_REPLAY_PENDING: &str =
    r#"{"status":"pending_approval","approval_id":"ap1","summary":"s","reasons":["r"]}"#;
const EXPECTED_REPLAY_SENT: &str = r#"{"status":"sent","exchange_id":5,"elapsed_ms":12,"view":{"id":5,"url":"https://a/","method":"GET","status":200,"duration_ms":12,"source":"replay","actor":"agent:x","request":{"start_line":"GET / HTTP/1.1","headers":[["Host","a"]]},"response":{"start_line":"HTTP/1.1 200 OK","body":{"kind":"text","content_type":"text/plain","size":2,"text":"ok","truncated":false}},"redacted":false,"notice":"untrusted"}}"#;
const EXPECTED_SCAN_PARSED: &str = r#"{"url":"https://a/","profile":null,"crawl":null,"max_pages":3,"browser":null,"max_targets":null,"max_requests":null,"checks":[],"record_findings":null,"identity":null,"approval_id":null}"#;
const EXPECTED_SCAN_SAMPLE: &str = r#"{"url":"https://app.example.com/","profile":"light","crawl":true,"max_pages":10,"browser":false,"max_targets":5,"max_requests":100,"checks":["xss"],"record_findings":true,"identity":"alice","approval_id":"ap1"}"#;
const EXPECTED_WS_PARSED: &str = r#"{"exchange_id":12,"raw":null,"messages":[{"text":"x","hex":null}],"wait_ms":null,"identity":null,"approval_id":null,"hypothesis_id":null,"max_chars":null}"#;
const EXPECTED_WS_SAMPLE: &str = r#"{"exchange_id":12,"raw":"GET /ws HTTP/1.1\r\n\r\n","messages":[{"text":"hi","hex":null},{"text":null,"hex":"00 ff"}],"wait_ms":500,"identity":"alice","approval_id":"ap1","hypothesis_id":2,"max_chars":100}"#;
