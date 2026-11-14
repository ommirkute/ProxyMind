//! ADR-0019 step 3: for each MCP tool whose input is one of the typed request structs, the property
//! names of the hand-written `inputSchema` must match the schema generated from the Rust type (the
//! type serde actually deserializes, `deny_unknown_fields` included). Descriptions, formatting and
//! constraint details are not compared; this is the cheap "same fields" check before the hand-written
//! schemas are replaced (step 4).

use std::collections::BTreeSet;

use pm_service::pm_store::HistoryFilter;
use pm_service::{
    AuthzCheckRequest, EngageFilter, FindingUpdate, ModelFilter, NewFinding, ProofRequest, ReplayRequest,
    ScanTaskRequest, WsReplayRequest,
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

/// Fields the Rust type accepts that the hand-written tool schema does not list, so a model that follows the
/// schema never learns of them. The type is right and the schema is behind; step 4 (generated schemas) removes
/// these entries. The list is exact: a new omission fails the test, and so does fixing one without deleting it.
const UNLISTED_BY_TOOL: &[(&str, &str)] = &[
    ("history_search", "annotated"),
    ("history_search", "hide_ext"),
    ("history_search", "hypothesis_id"),
    ("history_search", "identity"),
    ("history_search", "status_class"),
    ("history_search", "text"),
    ("scan_task_start", "browser"),
    ("scan_task_start", "record_findings"),
];

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
    ]
}

#[test]
fn hand_written_input_schemas_list_the_same_fields_as_the_rust_types() {
    let tools = pm_mcp::tool_definitions();
    let mut problems = Vec::new();
    for (name, schema) in tool_types() {
        let tool = tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("no tool named {name}"));
        let hand = &tool["inputSchema"];
        let (hand_props, gen_props) = (property_names(hand), property_names(&schema));
        for p in hand_props.difference(&gen_props) {
            problems.push(format!("{name}: the tool schema lists `{p}`, which the type does not accept"));
        }
        for p in gen_props.difference(&hand_props) {
            if !UNLISTED_BY_TOOL.contains(&(name, p.as_str())) {
                problems.push(format!("{name}: the type accepts `{p}`, which the tool schema does not list"));
            }
        }
        for (_, p) in UNLISTED_BY_TOOL.iter().filter(|(n, _)| *n == name) {
            if !gen_props.contains(*p) || hand_props.contains(*p) {
                problems.push(format!("{name}: `{p}` is no longer a known omission; remove it from UNLISTED_BY_TOOL"));
            }
        }
        // Both sides reject unknown fields.
        assert_eq!(hand["additionalProperties"], false, "{name}");
        assert_eq!(schema["additionalProperties"], false, "{name}: the type must deny unknown fields");
        let (hand_req, gen_req) = (required_names(hand), required_names(&schema));
        if hand_req != gen_req {
            problems.push(format!("{name}: required differs: tool {hand_req:?}, type {gen_req:?}"));
        }
    }
    assert!(problems.is_empty(), "MCP schemas differ from the Rust types:\n{}", problems.join("\n"));
}
