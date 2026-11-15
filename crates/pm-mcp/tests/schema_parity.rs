//! ADR-0019 steps 4 and 7: every MCP tool's `inputSchema` is generated from the Rust type its dispatch arm
//! deserializes the arguments into (`input_schema` in `tools.rs`). This test checks each tool really lists the type's
//! fields and required set (the type serde actually deserializes, `deny_unknown_fields` included), that every
//! property has a description, that the `required` lists the hand-written schemas had are still required, and that no
//! tool schema in the server needs `$ref` resolution.

use std::collections::BTreeSet;

use pm_service::mcp_args::{
    ApprovalStatusArgs, AttackPathListArgs, AuthzResultsArgs, CollaboratorInteractionsArgs, CollaboratorPayloadArgs,
    CompareExchangesArgs, CoverageArgs, CsrfPocArgs, CurlParseArgs, ExchangeGetArgs, ExchangeIdArgs, ExchangeRefArgs,
    FindingIdArgs, FindingListArgs, HypothesisListArgs, IdentityCaptureArgs, IdentityNameArgs, IssueLibraryArgs,
    MemoryListArgs, MemorySaveArgs, ModelChangesArgs, NoArgs, OrganizerAddArgs, OrganizerListArgs, OrganizerUpdateArgs,
    ProofGetArgs, ReconDnsArgs, ReconWaybackArgs, SiteMapArgs, SkillGetArgs, TaskIdArgs, TrafficTriageArgs,
    WsMessagesArgs,
};
use pm_service::pm_store::HistoryFilter;
use pm_service::{
    ActiveScanRequest, AuthzCheckRequest, AuthzMatrixRequest, CrawlRequest, CustomScanRequest, DecodeRequest,
    DiscoverRequest, DomTestRequest, EngageFilter, FindingUpdate, FuzzerRequest, GraphQlImportRequest, GroupRequest,
    HypothesisUpdate, ImportRequest, ModelFilter, NewAttackPath, NewFinding, NewHypothesis, OpenApiImportRequest,
    PluginCheckRequest, ProofRequest, RaceRequest, ReplayRequest, ScanFilter, ScanTaskRequest, SearchRequest,
    TokenAnalyzerRequest, WsReplayRequest, WsSearchRequest,
};
use schemars::JsonSchema;
use serde_json::Value;

fn generated<T: JsonSchema>() -> Value {
    serde_json::to_value(schemars::schema_for!(T)).unwrap()
}

fn property_names(schema: &Value) -> BTreeSet<String> {
    schema.get("properties").and_then(Value::as_object).map(|p| p.keys().cloned().collect()).unwrap_or_default()
}

fn required_names(schema: &Value) -> BTreeSet<String> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default()
}

/// Each tool and the type its dispatch arm in `tools.rs` deserializes its arguments into.
fn tool_types() -> Vec<(&'static str, Value)> {
    vec![
        ("history_search", generated::<HistoryFilter>()),
        ("scan_task_start", generated::<ScanTaskRequest>()),
        ("engage_comments", generated::<EngageFilter>()),
        ("engage_scripts", generated::<EngageFilter>()),
        ("engage_js_endpoints", generated::<EngageFilter>()),
        ("engage_logic", generated::<EngageFilter>()),
        ("engage_analyze", generated::<EngageFilter>()),
        ("ws_send", generated::<WsReplayRequest>()),
        ("replay_send", generated::<ReplayRequest>()),
        ("authz_check", generated::<AuthzCheckRequest>()),
        ("model_get", generated::<ModelFilter>()),
        ("proof_run", generated::<ProofRequest>()),
        ("finding_create", generated::<NewFinding>()),
        ("finding_update", generated::<FindingUpdate>()),
        ("roe_get", generated::<NoArgs>()),
        ("history_grep", generated::<SearchRequest>()),
        ("ws_grep", generated::<WsSearchRequest>()),
        ("site_map", generated::<SiteMapArgs>()),
        ("exchange_get", generated::<ExchangeGetArgs>()),
        ("exchange_raw_request", generated::<ExchangeIdArgs>()),
        ("ws_messages", generated::<WsMessagesArgs>()),
        ("race_send", generated::<RaceRequest>()),
        ("replay_group", generated::<GroupRequest>()),
        ("fuzzer_run", generated::<FuzzerRequest>()),
        ("identity_list", generated::<NoArgs>()),
        ("identity_capture", generated::<IdentityCaptureArgs>()),
        ("identity_check", generated::<IdentityNameArgs>()),
        ("identity_learn_logged_out", generated::<IdentityNameArgs>()),
        ("authz_results", generated::<AuthzResultsArgs>()),
        ("scan_issues", generated::<ScanFilter>()),
        ("scan_active", generated::<ActiveScanRequest>()),
        ("openapi_import", generated::<OpenApiImportRequest>()),
        ("decode", generated::<DecodeRequest>()),
        ("graphql_import", generated::<GraphQlImportRequest>()),
        ("import_har", generated::<ImportRequest>()),
        ("curl_parse", generated::<CurlParseArgs>()),
        ("compare_exchanges", generated::<CompareExchangesArgs>()),
        ("token_analyzer_run", generated::<TokenAnalyzerRequest>()),
        ("discover_content", generated::<DiscoverRequest>()),
        ("scan_task_status", generated::<TaskIdArgs>()),
        ("scan_task_pause", generated::<TaskIdArgs>()),
        ("scan_task_resume", generated::<TaskIdArgs>()),
        ("scan_profiles", generated::<NoArgs>()),
        ("custom_checks", generated::<NoArgs>()),
        ("custom_scan", generated::<CustomScanRequest>()),
        ("dom_test", generated::<DomTestRequest>()),
        ("collaborator_payload", generated::<CollaboratorPayloadArgs>()),
        ("collaborator_interactions", generated::<CollaboratorInteractionsArgs>()),
        ("skills_list", generated::<NoArgs>()),
        ("skill_get", generated::<SkillGetArgs>()),
        ("attack_path_record", generated::<NewAttackPath>()),
        ("attack_path_list", generated::<AttackPathListArgs>()),
        ("authz_matrix", generated::<AuthzMatrixRequest>()),
        ("model_changes", generated::<ModelChangesArgs>()),
        ("traffic_triage", generated::<TrafficTriageArgs>()),
        ("memory_save", generated::<MemorySaveArgs>()),
        ("memory_list", generated::<MemoryListArgs>()),
        ("recon_dns", generated::<ReconDnsArgs>()),
        ("recon_wayback", generated::<ReconWaybackArgs>()),
        ("engage_references", generated::<ExchangeRefArgs>()),
        ("organizer_add", generated::<OrganizerAddArgs>()),
        ("organizer_list", generated::<OrganizerListArgs>()),
        ("organizer_update", generated::<OrganizerUpdateArgs>()),
        ("engage_csrf_poc", generated::<CsrfPocArgs>()),
        ("engage_clickjacking", generated::<ExchangeRefArgs>()),
        ("plugin_list", generated::<NoArgs>()),
        ("plugin_check", generated::<PluginCheckRequest>()),
        ("crawl", generated::<CrawlRequest>()),
        ("authz_candidates", generated::<NoArgs>()),
        ("hypothesis_create", generated::<NewHypothesis>()),
        ("hypothesis_update", generated::<HypothesisUpdate>()),
        ("hypothesis_list", generated::<HypothesisListArgs>()),
        ("coverage", generated::<CoverageArgs>()),
        ("proof_get", generated::<ProofGetArgs>()),
        ("finding_retest", generated::<FindingIdArgs>()),
        ("finding_prove", generated::<FindingIdArgs>()),
        ("issue_library", generated::<IssueLibraryArgs>()),
        ("finding_list", generated::<FindingListArgs>()),
        ("approval_status", generated::<ApprovalStatusArgs>()),
    ]
}

fn contains_ref(v: &Value) -> Option<String> {
    match v {
        Value::Object(o) => o.iter().find_map(|(k, v)| {
            if matches!(k.as_str(), "$ref" | "$defs" | "definitions") { Some(k.clone()) } else { contains_ref(v) }
        }),
        Value::Array(a) => a.iter().find_map(contains_ref),
        _ => None,
    }
}

#[test]
fn generated_input_schemas_list_the_same_fields_as_the_rust_types() {
    let tools = pm_mcp::tool_definitions();
    let mut problems = Vec::new();
    for (name, schema) in tool_types() {
        let tool = tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("no tool named {name}"));
        let input = &tool["inputSchema"];
        assert_eq!(input["type"], "object", "{name}");
        assert_eq!(input["additionalProperties"], false, "{name}: the tool must reject unknown fields");
        assert_eq!(schema["additionalProperties"], false, "{name}: the type must deny unknown fields");
        for key in ["$schema", "title"] {
            assert!(input.get(key).is_none(), "{name}: inputSchema has a top-level `{key}`");
        }
        let (tool_props, type_props) = (property_names(input), property_names(&schema));
        if tool_props != type_props {
            problems.push(format!("{name}: properties differ: tool {tool_props:?}, type {type_props:?}"));
        }
        let (tool_req, type_req) = (required_names(input), required_names(&schema));
        if tool_req != type_req {
            problems.push(format!("{name}: required differs: tool {tool_req:?}, type {type_req:?}"));
        }
        if input.get("required").is_some() != !type_req.is_empty() {
            problems.push(format!("{name}: `required` must be present exactly when it is not empty"));
        }
        // Every property says what it is for.
        for (prop, def) in input["properties"].as_object().into_iter().flatten() {
            if def.get("description").and_then(Value::as_str).is_none_or(|d| d.trim().is_empty()) {
                problems.push(format!("{name}.{prop}: no description (add a doc comment to the field)"));
            }
        }
    }
    assert!(problems.is_empty(), "MCP schemas differ from the Rust types:\n{}", problems.join("\n"));
}

#[test]
fn no_tool_input_schema_needs_ref_resolution() {
    let tools = pm_mcp::tool_definitions();
    assert_eq!(tools.len(), 79);
    for t in &tools {
        if let Some(key) = contains_ref(&t["inputSchema"]) {
            panic!("{}: inputSchema contains `{key}`; subschemas must be inlined", t["name"]);
        }
    }
}

#[test]
fn every_tool_has_a_generated_schema_that_is_checked_against_its_type() {
    let tools = pm_mcp::tool_definitions();
    let typed: BTreeSet<&str> = tool_types().iter().map(|(n, _)| *n).collect();
    let listed: BTreeSet<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(typed, listed, "tool_types() must name every tool, and only tools");
    for t in &tools {
        let name = t["name"].as_str().unwrap();
        let input = &t["inputSchema"];
        assert_eq!(input["type"], "object", "{name}");
        assert_eq!(input["additionalProperties"], false, "{name}: the tool must reject unknown fields");
        assert!(input["properties"].is_object(), "{name}: `properties` must be an object, even when empty");
        for (prop, def) in input["properties"].as_object().unwrap() {
            let text = def.get("description").and_then(Value::as_str);
            assert!(text.is_some_and(|d| !d.trim().is_empty()), "{name}.{prop}: no description");
        }
        assert!(t["description"].as_str().is_some_and(|d| !d.is_empty()), "{name}: no tool description");
    }
}

/// A tool without arguments still has an empty `properties` object (MCP clients expect one).
#[test]
fn tools_without_arguments_have_an_empty_object_schema() {
    let tools = pm_mcp::tool_definitions();
    for name in
        ["roe_get", "identity_list", "scan_profiles", "custom_checks", "skills_list", "plugin_list", "authz_candidates"]
    {
        let t = tools.iter().find(|t| t["name"] == name).unwrap();
        assert_eq!(
            t["inputSchema"],
            serde_json::json!({"type": "object", "properties": {}, "additionalProperties": false}),
            "{name}"
        );
    }
}

/// The `required` lists the hand-written schemas had (before step 7). A generated schema must still demand them.
#[test]
fn arguments_the_hand_written_schemas_required_are_still_required() {
    let expected: &[(&str, &[&str])] = &[
        ("history_grep", &["query"]),
        ("ws_grep", &["query"]),
        ("exchange_get", &["id"]),
        ("exchange_raw_request", &["id"]),
        ("ws_messages", &["exchange_id"]),
        ("replay_group", &["requests"]),
        ("fuzzer_run", &["raw", "payload_sets"]),
        ("identity_capture", &["name", "exchange_id"]),
        ("identity_check", &["name"]),
        ("identity_learn_logged_out", &["name"]),
        ("scan_active", &["exchange_id"]),
        ("decode", &["input"]),
        ("import_har", &["har"]),
        ("curl_parse", &["command"]),
        ("compare_exchanges", &["a", "b"]),
        ("token_analyzer_run", &["exchange_id", "locator"]),
        ("discover_content", &["url"]),
        ("scan_task_status", &["task_id"]),
        ("scan_task_pause", &["task_id"]),
        ("scan_task_resume", &["task_id"]),
        ("custom_scan", &["exchange_id"]),
        ("dom_test", &["exchange_id"]),
        ("skill_get", &["name"]),
        ("attack_path_record", &["title", "impact", "severity", "steps"]),
        ("memory_save", &["kind", "text"]),
        ("memory_list", &["host"]),
        ("recon_dns", &["host"]),
        ("recon_wayback", &["host"]),
        ("engage_references", &["exchange_id"]),
        ("organizer_add", &["exchange_id"]),
        ("organizer_update", &["id"]),
        ("engage_csrf_poc", &["exchange_id"]),
        ("engage_clickjacking", &["exchange_id"]),
        ("plugin_check", &["plugin", "exchange_id"]),
        ("crawl", &["url"]),
        ("hypothesis_create", &["operation", "vuln_class", "rationale"]),
        ("hypothesis_update", &["id"]),
        ("proof_get", &["proof_id"]),
        ("finding_retest", &["id"]),
        ("finding_prove", &["id"]),
        ("approval_status", &["approval_id"]),
    ];
    let tools = pm_mcp::tool_definitions();
    for (name, required) in expected {
        let t = tools.iter().find(|t| t["name"] == *name).unwrap();
        let got = required_names(&t["inputSchema"]);
        let want: BTreeSet<String> = required.iter().map(|r| r.to_string()).collect();
        assert!(want.is_subset(&got), "{name}: required {got:?} lacks {want:?}");
    }
}

/// Enumerations that the service checks against its own constants are written as attributes; these tests keep the
/// two in step.
#[test]
fn enumerated_values_match_the_services_constants() {
    let tools = pm_mcp::tool_definitions();
    let prop = |tool: &str, path: &[&str]| -> Value {
        let t = tools.iter().find(|t| t["name"] == tool).unwrap();
        let mut v = &t["inputSchema"];
        for p in path {
            v = if *p == "[]" { &v["items"] } else { &v["properties"][*p] };
        }
        v.clone()
    };
    let strings = |v: &Value| -> BTreeSet<String> {
        v["enum"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect()
    };
    let checks: BTreeSet<String> = pm_service::pm_scan::active::CHECKS
        .iter()
        .chain(pm_service::pm_scan::oob::CHECKS)
        .map(|c| c.to_string())
        .collect();
    assert_eq!(strings(&prop("scan_active", &["checks", "[]"])), checks);
    let builtins: BTreeSet<String> = pm_service::pm_fuzz::BUILTINS.iter().map(|(name, _)| name.to_string()).collect();
    assert_eq!(strings(&prop("fuzzer_run", &["payload_sets", "[]", "builtin"])), builtins);
    let statuses: BTreeSet<String> = pm_service::ORGANIZER_STATUSES.iter().map(|c| c.to_string()).collect();
    assert_eq!(strings(&prop("organizer_list", &["status"])), statuses);
    assert_eq!(strings(&prop("organizer_update", &["status"])), statuses);
    let kinds: BTreeSet<String> = pm_service::MEMORY_KINDS.iter().map(|c| c.to_string()).collect();
    assert_eq!(strings(&prop("memory_save", &["kind"])), kinds);
}
