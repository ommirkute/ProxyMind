//! The OpenAPI document for the typed part of the API (ADR-0019).
//!
//! The routes listed in [`operations`] are the ones whose request (and, where the handler's result is a
//! named Rust type, response) is a type deriving `schemars::JsonSchema`. Everything else is not described
//! yet. `cargo xtask contracts` writes [`openapi_json`] to `docs/api/openapi.json`, and the test below
//! fails when that file is stale, so a changed Rust type cannot leave the document behind.
//!
//! The paths and methods here repeat `routes.rs`; the handler extractors there are the source of truth
//! for which type each route reads. Step 5 of the ADR derives this table from the router instead.

use std::collections::BTreeMap;

use pm_service::pm_store::HistoryFilter;
use pm_service::{
    AuthzCheckRequest, EngageFilter, FindingUpdate, ModelFilter, NewFinding, ProofRequest, ProofResult, ReplayRequest,
    ReplayResult, ScanTaskRequest, WsReplayRequest,
};
use schemars::generate::SchemaSettings;
use schemars::{Schema, SchemaGenerator};
use serde_json::{Map, Value, json};

/// Builds the schema (or a `$ref` into the generator's definitions) of one type.
type SchemaFn = fn(&mut SchemaGenerator) -> Schema;

/// Where a route reads its request from.
#[derive(Clone, Copy)]
pub enum Input {
    None,
    /// JSON request body of this type.
    Body(SchemaFn),
    /// Query string; each property of this type becomes one parameter.
    Query(SchemaFn),
}

/// One row of the route table.
#[derive(Clone, Copy)]
pub struct Operation {
    /// Lower-case HTTP method.
    pub method: &'static str,
    /// Path including the `/api/v1` prefix; `{name}` marks path parameters.
    pub path: &'static str,
    pub operation_id: &'static str,
    pub summary: &'static str,
    /// Path parameters as (name, JSON type).
    pub path_params: &'static [(&'static str, &'static str)],
    pub input: Input,
    /// The type of a successful response. `None` while the handler's result is still untyped JSON.
    pub output: Option<SchemaFn>,
}

macro_rules! schema_of {
    ($t:ty) => {
        |g: &mut SchemaGenerator| g.subschema_for::<$t>()
    };
}

const NO_PARAMS: &[(&str, &str)] = &[];

/// The routes described so far: (method, path, request type, response type). Responses that are still
/// `Value`, or a service type without a schema yet, are `None`.
pub fn operations() -> Vec<Operation> {
    let engage = |path, operation_id, summary| Operation {
        method: "post",
        path,
        operation_id,
        summary,
        path_params: NO_PARAMS,
        input: Input::Body(schema_of!(EngageFilter)),
        output: None,
    };
    vec![
        Operation {
            method: "get",
            path: "/api/v1/exchanges",
            operation_id: "exchanges_list",
            summary: "Search recorded exchanges, newest first.",
            path_params: NO_PARAMS,
            input: Input::Query(schema_of!(HistoryFilter)),
            output: None, // ExchangePage has no schema yet
        },
        Operation {
            method: "post",
            path: "/api/v1/replay",
            operation_id: "replay_send",
            summary: "Send a request, as recorded or edited, through the policy gate.",
            path_params: NO_PARAMS,
            input: Input::Body(schema_of!(ReplayRequest)),
            output: Some(schema_of!(ReplayResult)),
        },
        Operation {
            method: "post",
            path: "/api/v1/proofs",
            operation_id: "proof_run",
            summary: "Run a proof oracle and store the result.",
            path_params: NO_PARAMS,
            input: Input::Body(schema_of!(ProofRequest)),
            output: Some(schema_of!(ProofResult)),
        },
        Operation {
            method: "post",
            path: "/api/v1/authz/check",
            operation_id: "authz_check",
            summary: "Replay one recorded request as several identities and classify the responses.",
            path_params: NO_PARAMS,
            input: Input::Body(schema_of!(AuthzCheckRequest)),
            output: None, // AuthzReport has no schema yet
        },
        Operation {
            method: "post",
            path: "/api/v1/scan/tasks",
            operation_id: "scan_task_start",
            summary: "Start a crawl-and-audit background task.",
            path_params: NO_PARAMS,
            input: Input::Body(schema_of!(ScanTaskRequest)),
            output: None, // ScanTaskView has no schema yet
        },
        Operation {
            method: "post",
            path: "/api/v1/findings",
            operation_id: "finding_create",
            summary: "Record a finding.",
            path_params: NO_PARAMS,
            input: Input::Body(schema_of!(NewFinding)),
            output: None, // untyped Value
        },
        Operation {
            method: "patch",
            path: "/api/v1/findings/{id}",
            operation_id: "finding_update",
            summary: "Update a finding. The body must still carry `id` (the handler overwrites it with the path id).",
            path_params: &[("id", "integer")],
            input: Input::Body(schema_of!(FindingUpdate)),
            output: None, // untyped Value
        },
        engage("/api/v1/engage/comments", "engage_comments", "Comments found in recorded responses."),
        engage("/api/v1/engage/scripts", "engage_scripts", "Scripts found in recorded responses."),
        engage("/api/v1/engage/js-endpoints", "engage_js_endpoints", "Endpoints referenced from recorded JavaScript."),
        engage("/api/v1/engage/logic", "engage_logic", "Business-logic leads from recorded traffic."),
        engage("/api/v1/engage/analyze", "engage_analyze", "Summary analysis of a target's recorded traffic."),
        Operation {
            method: "post",
            path: "/api/v1/ws/replay",
            operation_id: "ws_replay",
            summary: "Replay a recorded WebSocket session with edited messages.",
            path_params: NO_PARAMS,
            input: Input::Body(schema_of!(WsReplayRequest)),
            output: None, // WsReplayResult has no schema yet
        },
        Operation {
            method: "get",
            path: "/api/v1/model",
            operation_id: "model_get",
            summary: "The application model built from recorded traffic.",
            path_params: NO_PARAMS,
            input: Input::Query(schema_of!(ModelFilter)),
            output: None, // untyped Value
        },
    ]
}

/// Generators for the two directions: what clients send is described as it is deserialized, what the
/// service returns as it is serialized (`skip_serializing_if` fields are optional there).
fn generator(serialize: bool) -> SchemaGenerator {
    let settings = SchemaSettings::draft2020_12().with(|s| {
        s.definitions_path = "/components/schemas".into();
        s.meta_schema = None;
    });
    let settings = if serialize { settings.for_serialize() } else { settings.for_deserialize() };
    settings.into_generator()
}

/// `{"$ref": "#/components/schemas/Name"}` -> `Name`.
fn ref_name(schema: &Value) -> Option<&str> {
    schema.get("$ref")?.as_str()?.strip_prefix("#/components/schemas/")
}

/// Query-string parameters for a request type: one per property.
fn query_parameters(schema: &Value, definitions: &Map<String, Value>) -> Vec<Value> {
    let name = ref_name(schema).expect("query types are named structs");
    let def = &definitions[name];
    let required: Vec<&str> = def
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let props = def["properties"].as_object().expect("query types have properties");
    props
        .iter()
        .map(|(key, prop)| {
            let mut schema = prop.clone();
            let description = schema.as_object_mut().and_then(|o| o.remove("description"));
            let mut p = json!({
                "name": key,
                "in": "query",
                "required": required.contains(&key.as_str()),
                "schema": schema,
            });
            if let Some(d) = description {
                p["description"] = d;
            }
            p
        })
        .collect()
}

/// Rebuilds a value with every object's keys in sorted order, so the output does not depend on the
/// order the generator happened to insert them in (or on serde_json's `preserve_order` feature).
fn sorted(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let ordered: BTreeMap<String, Value> = map.into_iter().map(|(k, v)| (k, sorted(v))).collect();
            Value::Object(ordered.into_iter().collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        other => other,
    }
}

/// The OpenAPI 3.1 document.
pub fn openapi_document() -> Value {
    let mut requests = generator(false);
    let mut responses = generator(true);
    let mut paths: BTreeMap<&str, Map<String, Value>> = BTreeMap::new();

    let ops = operations();
    // Request schemas first, so query parameters can look their type up.
    let request_schemas: Vec<Option<Value>> = ops
        .iter()
        .map(|op| match op.input {
            Input::None => None,
            Input::Body(f) | Input::Query(f) => Some(serde_json::to_value(f(&mut requests)).unwrap()),
        })
        .collect();
    let response_schemas: Vec<Option<Value>> =
        ops.iter().map(|op| op.output.map(|f| serde_json::to_value(f(&mut responses)).unwrap())).collect();

    let mut definitions = requests.take_definitions(true);
    for (name, schema) in responses.take_definitions(true) {
        // A type used in both directions (e.g. `View`) must read the same either way.
        if let Some(existing) = definitions.get(&name) {
            assert_eq!(existing, &schema, "schema `{name}` differs between request and response use");
        }
        definitions.insert(name, schema);
    }

    for ((op, request), response) in ops.iter().zip(request_schemas).zip(response_schemas) {
        let mut parameters: Vec<Value> = op
            .path_params
            .iter()
            .map(|(name, ty)| json!({ "name": name, "in": "path", "required": true, "schema": { "type": ty } }))
            .collect();
        let mut body = None;
        match (op.input, request) {
            (Input::Query(_), Some(schema)) => parameters.extend(query_parameters(&schema, &definitions)),
            (Input::Body(_), Some(schema)) => {
                body = Some(json!({ "required": true, "content": { "application/json": { "schema": schema } } }));
            }
            _ => {}
        }
        let ok = match response {
            Some(schema) => json!({ "description": "OK", "content": { "application/json": { "schema": schema } } }),
            // Still untyped JSON: the document says so by leaving the media type without a schema.
            None => {
                json!({ "description": "OK (response schema not yet typed)", "content": { "application/json": {} } })
            }
        };
        let mut operation = json!({
            "operationId": op.operation_id,
            "summary": op.summary,
            "responses": { "200": ok },
        });
        if !parameters.is_empty() {
            operation["parameters"] = Value::Array(parameters);
        }
        if let Some(body) = body {
            operation["requestBody"] = body;
        }
        paths.entry(op.path).or_default().insert(op.method.to_string(), operation);
    }

    let paths: Map<String, Value> = paths.into_iter().map(|(k, v)| (k.to_string(), Value::Object(v))).collect();
    sorted(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "ProxyMind API",
            "version": "v1",
            "summary": "REST API of the local ProxyMind app (part of it; see docs/adr/0019-typed-api-contracts.md).",
            "description": "Generated from the Rust types by `cargo xtask contracts`; do not edit by hand. Every \
                            request needs the per-install token, and requests that change anything must carry the \
                            header `X-ProxyMind: 1`. Only the routes listed here are described so far.",
            "license": { "name": "AGPL-3.0-only", "identifier": "AGPL-3.0-only" },
        },
        "security": [{ "bearerAuth": [] }],
        "paths": paths,
        "components": {
            "schemas": definitions,
            "securitySchemes": { "bearerAuth": { "type": "http", "scheme": "bearer" } },
        },
    }))
}

/// The document as committed: pretty-printed, sorted keys, one trailing newline.
pub fn openapi_json() -> String {
    let mut s = serde_json::to_string_pretty(&openapi_document()).expect("serializable");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plain `cargo test` catches a stale `docs/api/openapi.json` (same check as `cargo xtask contracts --check`).
    #[test]
    fn committed_openapi_document_is_current() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/api/openapi.json");
        let committed = std::fs::read_to_string(path).unwrap_or_default();
        assert!(committed == openapi_json(), "docs/api/openapi.json is stale: run `cargo xtask contracts`");
    }

    #[test]
    fn document_describes_the_twelve_types() {
        let doc = openapi_document();
        let schemas = doc["components"]["schemas"].as_object().unwrap();
        for name in [
            "ReplayRequest",
            "ProofRequest",
            "AuthzCheckRequest",
            "ScanTaskRequest",
            "HistoryFilter",
            "NewFinding",
            "FindingUpdate",
            "EngageFilter",
            "WsReplayRequest",
            "ModelFilter",
            "ProofResult",
            "ReplayResult",
        ] {
            assert!(schemas.contains_key(name), "missing schema {name}");
        }
        // Not part of the wire format.
        assert!(schemas["HistoryFilter"]["properties"].get("ids").is_none());
    }

    #[test]
    fn every_operation_has_a_unique_id_and_path() {
        let ops = operations();
        let mut ids: Vec<_> = ops.iter().map(|o| o.operation_id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), ops.len());
        let mut keys: Vec<_> = ops.iter().map(|o| (o.method, o.path)).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), ops.len());
    }
}
