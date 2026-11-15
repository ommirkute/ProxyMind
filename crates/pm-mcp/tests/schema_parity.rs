//! ADR-0019 step 4: for each MCP tool whose input is one of the typed request structs, the `inputSchema` is
//! generated from that type (`input_schema` in `tools.rs`). This test checks the tool really lists the type's
//! fields and required set (the type serde actually deserializes, `deny_unknown_fields` included), that every
//! property has a description, and that no tool schema in the server needs `$ref` resolution.

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
