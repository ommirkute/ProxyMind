//! ADR-0019 step 7: a call that the hand-written schemas documented still deserializes into the Rust type each tool
//! now takes, and an argument no schema lists is refused. One representative call per tool family; the arguments are
//! the ones the old schemas described.

use pm_service::api_types::ProtobufDecodeRequest;
use pm_service::mcp_args::*;
use pm_service::pm_store::{HistoryFilter, StreamFilter};
use pm_service::{
    ActiveScanRequest, AuthzMatrixRequest, CrawlRequest, CustomScanRequest, DecodeRequest, DiscoverRequest,
    DomTestRequest, FuzzerRequest, GraphQlImportRequest, GroupRequest, HypothesisUpdate, ImportRequest, NewAttackPath,
    NewHypothesis, OpenApiImportRequest, PluginCheckRequest, RaceRequest, ScanFilter, SearchRequest,
    StreamReplayRequest, TokenAnalyzerRequest, WorkflowRunRequest, WsSearchRequest,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// `valid` deserializes, and so does not the same call with an extra field.
fn accepts<T: DeserializeOwned>(valid: Value) {
    if let Err(e) = serde_json::from_value::<T>(valid.clone()) {
        panic!("{} refused {valid}: {e}", std::any::type_name::<T>());
    }
    let mut bad = valid.clone();
    bad.as_object_mut().unwrap().insert("not_a_field".into(), json!(1));
    let err = serde_json::from_value::<T>(bad).err().unwrap_or_else(|| {
        panic!("{} accepted an unknown field next to {valid}", std::any::type_name::<T>());
    });
    assert!(err.to_string().contains("not_a_field"), "{}: the error should name the field: {err}", err);
}

/// A call without a required argument is refused by the type itself (the others leave that to the service).
fn refuses<T: DeserializeOwned>(invalid: Value) {
    assert!(serde_json::from_value::<T>(invalid).is_err(), "{} accepted it", std::any::type_name::<T>());
}

#[test]
fn history_and_websocket_search() {
    accepts::<HistoryFilter>(json!({"host": "app", "status": 404, "limit": 10, "q": "status:4xx"}));
    // `SearchRequest` flattens `HistoryFilter`, so serde cannot deny unknown fields; the dispatcher does (see the
    // `unknown_arguments_are_refused_by_name` test in `lib.rs`).
    serde_json::from_value::<SearchRequest>(json!({
        "query": "token", "regex": true, "case_sensitive": true, "part": "response_body", "invert": false,
        "in_scope": true, "host": "app", "path": "/api", "method": "POST", "before_id": 100, "max_scan": 500,
        "limit": 20
    }))
    .unwrap();
    accepts::<WsSearchRequest>(json!({
        "query": "x", "regex": false, "case_sensitive": false, "invert": false, "host": "h", "direction": "client",
        "in_scope": true, "before_id": 5, "max_scan": 100, "limit": 10
    }));
    accepts::<SiteMapArgs>(json!({"host": "app"}));
    accepts::<ExchangeGetArgs>(json!({"id": 5, "view": "full", "max_tokens": 3000}));
    accepts::<ExchangeIdArgs>(json!({"id": 5}));
    accepts::<WsMessagesArgs>(json!({"exchange_id": 5, "after_id": 2, "limit": 50, "max_chars": 2000}));
    refuses::<ExchangeGetArgs>(json!({"view": "full"}));
    refuses::<WsMessagesArgs>(json!({"limit": 5}));
}

#[test]
fn raw_stream_tools() {
    accepts::<StreamFilter>(json!({"host": "mail", "port": 25, "client": "10.0.0.7", "since_ms": 1, "until_ms": 2,
        "tls": true, "before_id": 9, "limit": 10}));
    accepts::<StreamGetArgs>(json!({"id": 3, "after": 10, "limit": 50, "max_chars": 2000}));
    refuses::<StreamGetArgs>(json!({"limit": 5}));
    accepts::<StreamReplayRequest>(
        json!({"stream_id": 3, "text_chunks": ["EHLO x\r\n"], "delay_ms": 100, "read_ms": 500,
        "max_response_bytes": 1000, "approval_id": "a1", "max_chars": 500}),
    );
    accepts::<StreamReplayRequest>(json!({"stream_id": 3, "chunks": ["RUhMTw=="]}));
}

#[test]
fn workflow_tools() {
    accepts::<WorkflowRefArgs>(json!({"workflow": "login-and-orders"}));
    refuses::<WorkflowRefArgs>(json!({}));
    accepts::<WorkflowRunRequest>(json!({"workflow": "7", "exchange_id": 12, "approval_id": "a1"}));
    accepts::<WorkflowRunRequest>(json!({"workflow": "login"}));
    refuses::<WorkflowRunRequest>(json!({"workflow": "x", "steps": []}));
}

#[test]
fn sending_tools() {
    accepts::<RaceRequest>(json!({
        "exchange_id": 5, "url": "https://a.example", "raw": "GET / HTTP/1.1\r\n\r\n", "count": 10, "mode": "auto",
        "identity": "alice", "fix_content_length": true, "approval_id": "a1", "hypothesis_id": 3
    }));
    accepts::<GroupRequest>(json!({
        "requests": [{"url": "https://a.example", "exchange_id": 1, "raw": "GET / HTTP/1.1\r\n\r\n", "name": "a"},
                     {"exchange_id": 2}],
        "mode": "parallel", "parallel": "last_byte", "stop_on_error": true, "identity": "alice",
        "fix_content_length": false, "approval_id": "a1", "hypothesis_id": 3
    }));
    accepts::<FuzzerRequest>(json!({
        "exchange_id": 5, "url": "https://a.example", "raw": "GET /§1§ HTTP/1.1\r\n\r\n", "mode": "paired",
        "payload_sets": [{"list": ["a"], "numbers": "1-5", "builtin": "ids", "brute": {"charset": "ab", "min": 1, "max": 2},
            "null_payloads": 2, "case_variants": ["x"], "processing": [{"op": "prefix", "value": "x"},
            {"op": "replace", "find": "a", "with": "b"}, {"op": "base64"}], "url_encode": true}],
        "grep": ["error"], "grep_regex": true, "extract": [{"start": "a", "end": "b"}, {"regex": "x(.)"}],
        "concurrency": 5, "throttle_ms": 100, "identity": "alice", "fix_content_length": true, "hypothesis_id": 1,
        "approval_id": "a1"
    }));
    accepts::<TokenAnalyzerRequest>(json!({
        "exchange_id": 5, "locator": "cookie:sid", "samples": 50, "identity": "alice", "approval_id": "a1"
    }));
    accepts::<DiscoverRequest>(json!({
        "url": "https://a.example/", "words": ["admin"], "builtin": true, "extensions": ["bak"], "max_requests": 100,
        "identity": "alice", "approval_id": "a1"
    }));
    accepts::<CrawlRequest>(json!({
        "url": "https://a.example/", "max_pages": 10, "max_depth": 2, "robots": false, "browser": true,
        "identity": "alice", "approval_id": "a1"
    }));
    refuses::<GroupRequest>(json!({"requests": "x"}));
}

#[test]
fn identity_tools() {
    accepts::<IdentityCaptureArgs>(json!({"name": "alice", "role": "admin", "exchange_id": 5}));
    accepts::<IdentityNameArgs>(json!({"name": "alice"}));
    accepts::<AuthzResultsArgs>(json!({"exchange_id": 5}));
    refuses::<IdentityCaptureArgs>(json!({"name": "alice"}));
    refuses::<IdentityNameArgs>(json!({}));
}

#[test]
fn scanning_tools() {
    accepts::<ScanFilter>(json!({"host": "app", "limit": 100, "min_severity": "low"}));
    accepts::<ActiveScanRequest>(json!({
        "exchange_id": 5, "checks": ["sql_error", "jwt"], "oob_wait_seconds": 10, "max_requests": 200,
        "identity": "alice", "hypothesis_id": 1, "approval_id": "a1"
    }));
    accepts::<TaskIdArgs>(json!({"task_id": "t1"}));
    accepts::<CustomScanRequest>(json!({
        "exchange_id": 5, "checks": ["c1"], "yaml": "id: x", "max_requests": 100, "identity": "alice",
        "approval_id": "a1", "hypothesis_id": 1
    }));
    accepts::<DomTestRequest>(json!({"exchange_id": 5, "storage": true, "pollution": true}));
    accepts::<AuthzMatrixRequest>(json!({"prove": true, "max_operations": 10}));
    accepts::<PluginCheckRequest>(json!({"plugin": "p", "exchange_id": 5, "identity": "alice", "approval_id": "a1"}));
    accepts::<CollaboratorPayloadArgs>(json!({"note": "ssrf in /fetch"}));
    accepts::<CollaboratorInteractionsArgs>(json!({"token": "t", "limit": 5}));
    refuses::<TaskIdArgs>(json!({}));
}

#[test]
fn import_and_conversion_tools() {
    accepts::<OpenApiImportRequest>(json!({
        "spec": "{}", "exchange_id": 5, "base_url": "https://a.example", "send_examples": true, "identity": "alice",
        "approval_id": "a1"
    }));
    accepts::<DecodeRequest>(json!({"input": "aGk=", "ops": ["base64_decode"]}));
    accepts::<ProtobufDecodeRequest>(json!({
        "exchange_id": 5, "part": "request", "body_b64": "CAE=", "body_text": "x", "content_type": "application/grpc",
        "kind": "grpc", "grpc_encoding": "gzip", "annotate": false
    }));
    refuses::<ProtobufDecodeRequest>(json!({"exchange_id": 5, "part": "both"}));
    refuses::<ProtobufDecodeRequest>(json!({"exchange": 5}));
    accepts::<GraphQlImportRequest>(json!({
        "url": "https://a.example/graphql", "schema": "{}", "exchange_id": 5, "fetch": true, "identity": "alice",
        "approval_id": "a1"
    }));
    accepts::<ImportRequest>(json!({"har": "{}"}));
    accepts::<CurlParseArgs>(json!({"command": "curl https://a.example"}));
    accepts::<CompareExchangesArgs>(json!({"a": 1, "b": 2}));
    refuses::<CompareExchangesArgs>(json!({"a": 1}));
}

#[test]
fn engage_recon_and_model_tools() {
    accepts::<SkillGetArgs>(json!({"name": "ssrf_hunt", "focus": "the /api endpoints"}));
    accepts::<AttackPathListArgs>(json!({"scan_id": 3}));
    accepts::<NewAttackPath>(json!({
        "title": "t", "impact": "i", "severity": "high",
        "steps": [{"text": "a", "finding_id": 1, "exchange_id": 2}, {"text": "b"}]
    }));
    accepts::<ModelChangesArgs>(json!({"snapshot_id": 2}));
    accepts::<TrafficTriageArgs>(json!({"host": "app", "in_scope": true, "limit": 10}));
    accepts::<MemorySaveArgs>(json!({"kind": "login", "text": "alice works", "host": "app"}));
    accepts::<MemoryListArgs>(json!({"host": "app"}));
    accepts::<ReconDnsArgs>(json!({"host": "app"}));
    accepts::<ReconWaybackArgs>(json!({"host": "app", "limit": 50}));
    accepts::<ExchangeRefArgs>(json!({"exchange_id": 5}));
    accepts::<CsrfPocArgs>(json!({"exchange_id": 5, "technique": "text_plain", "auto_submit": true}));
    refuses::<MemorySaveArgs>(json!({"kind": "login"}));
    refuses::<CsrfPocArgs>(json!({"exchange_id": 5, "technique": "nope"}));
}

#[test]
fn organizer_hypothesis_and_finding_tools() {
    accepts::<OrganizerAddArgs>(json!({"exchange_id": 5, "note": "look again"}));
    accepts::<OrganizerListArgs>(json!({"status": "done"}));
    accepts::<OrganizerUpdateArgs>(json!({"id": 1, "status": "postponed", "note": "later"}));
    accepts::<NewHypothesis>(json!({"operation": "GET /a", "param": "id", "vuln_class": "idor", "rationale": "r"}));
    accepts::<HypothesisUpdate>(json!({"id": 1, "status": "confirmed", "note": "n"}));
    accepts::<HypothesisListArgs>(json!({"status": "open"}));
    accepts::<CoverageArgs>(json!({"untested_only": false}));
    accepts::<ProofGetArgs>(json!({"proof_id": 3}));
    accepts::<FindingIdArgs>(json!({"id": 3}));
    accepts::<IssueLibraryArgs>(json!({"class": "sqli"}));
    accepts::<FindingListArgs>(json!({"status": "proven"}));
    accepts::<ApprovalStatusArgs>(json!({"approval_id": "a1"}));
    accepts::<NoArgs>(json!({}));
    refuses::<OrganizerUpdateArgs>(json!({"status": "done"}));
    refuses::<ApprovalStatusArgs>(json!({}));
}
