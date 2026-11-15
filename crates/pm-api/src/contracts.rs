//! The OpenAPI document for the whole API (ADR-0019).
//!
//! [`operations`] (in `contract_table.rs`) lists one operation for every method of every route that
//! `routes::api()` registers; the test `route_table_matches_router` fails when the two disagree. Where a
//! request or response is a Rust type deriving `schemars::JsonSchema` the document carries its schema; a handler
//! that builds its JSON on the spot is described as untyped JSON with a description of what it writes.
//! `cargo xtask contracts` writes [`openapi_json`] to `docs/api/openapi.json`, and the test below fails when that
//! file is stale, so a changed Rust type cannot leave the document behind.

use std::collections::BTreeMap;

use schemars::generate::SchemaSettings;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde_json::{Map, Value, json};

pub use crate::contract_table::operations;

/// Builds the schema (or a `$ref` into the generator's definitions) of one type.
pub type SchemaFn = fn(&mut SchemaGenerator) -> Schema;

fn schema_fn<T: JsonSchema + ?Sized>(g: &mut SchemaGenerator) -> Schema {
    g.subschema_for::<T>()
}

/// Where a route reads its request from.
#[derive(Clone, Copy)]
pub enum Input {
    None,
    /// JSON request body of this type.
    Body(SchemaFn),
    /// JSON request body that is any JSON value (described in words).
    AnyBody(&'static str),
    /// Request body that is raw bytes of this media type.
    RawBody(&'static str, &'static str),
    /// Query string; each property of this type becomes one parameter.
    Query(SchemaFn),
}

/// What a route answers with.
#[derive(Clone, Copy)]
pub enum Output {
    /// JSON of a Rust type.
    Typed(SchemaFn),
    /// An object the handler builds on the spot; the text says which keys it has.
    Object(&'static str),
    /// A JSON array the handler builds on the spot.
    List(&'static str),
    /// Any JSON value.
    Any(&'static str),
    /// A file download; the media types (comma-separated when it depends on the request) and what it holds.
    Download(&'static str, &'static str),
    /// Server-sent events.
    Events,
}

/// One row of the route table.
#[derive(Clone)]
pub struct Operation {
    /// Lower-case HTTP method.
    pub method: &'static str,
    /// Path including the `/api/v1` prefix; `{name}` marks path parameters.
    pub path: String,
    /// The handler's name in `routes.rs`.
    pub operation_id: &'static str,
    pub summary: &'static str,
    /// The `{id}` path parameter is text, not an integer.
    pub id_is_string: bool,
    pub input: Input,
    pub output: Output,
}

/// Starts a row. `path` is relative to `/api/v1`. Every row must then say what comes back: `.out::<T>()`, `.json(..)`, `.download(..)` or `.sse()`
/// (`every_response_is_described` fails on a row that does not).
pub fn op(method: &'static str, path: &str, operation_id: &'static str, summary: &'static str) -> Operation {
    Operation {
        method,
        path: format!("/api/v1{path}"),
        operation_id,
        summary,
        id_is_string: false,
        input: Input::None,
        output: Output::Any(""),
    }
}

impl Operation {
    pub fn body<T: JsonSchema + ?Sized>(mut self) -> Self {
        self.input = Input::Body(schema_fn::<T>);
        self
    }
    pub fn any_body(mut self, what: &'static str) -> Self {
        self.input = Input::AnyBody(what);
        self
    }
    pub fn raw_body(mut self, media_type: &'static str, what: &'static str) -> Self {
        self.input = Input::RawBody(media_type, what);
        self
    }
    pub fn query<T: JsonSchema + ?Sized>(mut self) -> Self {
        self.input = Input::Query(schema_fn::<T>);
        self
    }
    pub fn out<T: JsonSchema + ?Sized>(mut self) -> Self {
        self.output = Output::Typed(schema_fn::<T>);
        self
    }
    pub fn json(mut self, what: &'static str) -> Self {
        self.output = Output::Object(what);
        self
    }
    pub fn json_list(mut self, what: &'static str) -> Self {
        self.output = Output::List(what);
        self
    }
    pub fn json_any(mut self, what: &'static str) -> Self {
        self.output = Output::Any(what);
        self
    }
    pub fn download(mut self, media_type: &'static str, what: &'static str) -> Self {
        self.output = Output::Download(media_type, what);
        self
    }
    pub fn sse(mut self) -> Self {
        self.output = Output::Events;
        self
    }
    pub fn id_is_string(mut self) -> Self {
        self.id_is_string = true;
        self
    }

    /// Path parameters in order: `id` is an integer unless `id_is_string`, everything else is text.
    pub fn path_params(&self) -> Vec<(&str, &'static str)> {
        let mut out = Vec::new();
        let mut rest = self.path.as_str();
        while let Some(start) = rest.find('{') {
            let end = rest[start..].find('}').expect("balanced braces") + start;
            let name = &rest[start + 1..end];
            out.push((name, if name == "id" && !self.id_is_string { "integer" } else { "string" }));
            rest = &rest[end + 1..];
        }
        out
    }
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

/// The `responses` of one operation.
fn responses_of(op: &Operation, typed: Option<Value>) -> Value {
    let json_ok =
        |schema: Value| json!({ "description": "OK", "content": { "application/json": { "schema": schema } } });
    let ok = match (op.output, typed) {
        (Output::Typed(_), Some(schema)) => json_ok(schema),
        (Output::Object(what), _) => json_ok(json!({ "type": "object", "description": what })),
        (Output::List(what), _) => {
            json_ok(json!({ "type": "array", "items": { "type": "object" }, "description": what }))
        }
        (Output::Any(what), _) => json_ok(json!({ "description": what })),
        (Output::Download(types, what), _) => {
            let content: Map<String, Value> = types
                .split(", ")
                .map(|t| (t.to_string(), json!({ "schema": { "type": "string", "format": "binary" } })))
                .collect();
            json!({ "description": format!("OK: a file download. {what}"), "content": content })
        }
        (Output::Events, _) => json!({
            "description": "OK: a stream of server-sent events (`text/event-stream`).",
            "content": { "text/event-stream": { "schema": { "type": "string" } } },
        }),
        (Output::Typed(_), None) => unreachable!("typed outputs have a schema"),
    };
    json!({
        "200": ok,
        "default": {
            "description": "An error: 400 invalid input, 403 refused by policy, 404 not found, 409 approval needed, \
                            5xx failure.",
            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ApiError" } } },
        },
    })
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
            Input::Body(f) | Input::Query(f) => Some(serde_json::to_value(f(&mut requests)).unwrap()),
            Input::None | Input::AnyBody(_) | Input::RawBody(..) => None,
        })
        .collect();
    let response_schemas: Vec<Option<Value>> = ops
        .iter()
        .map(|op| match op.output {
            Output::Typed(f) => Some(serde_json::to_value(f(&mut responses)).unwrap()),
            _ => None,
        })
        .collect();

    let mut definitions = requests.take_definitions(true);
    for (name, schema) in responses.take_definitions(true) {
        // A type used in both directions reads the same either way except that fields with a serde default are
        // optional in a request. Where the two differ the request reading wins: it is the looser description of
        // a response (a field may be missing) and the only correct one of a request.
        definitions.entry(name).or_insert(schema);
    }
    definitions.insert(
        "ApiError".into(),
        json!({
            "type": "object",
            "description": "Body of every error response.",
            "properties": { "error": { "type": "string", "description": "What went wrong." } },
            "required": ["error"],
        }),
    );

    for ((op, request), response) in ops.iter().zip(request_schemas).zip(response_schemas) {
        let mut parameters: Vec<Value> = op
            .path_params()
            .iter()
            .map(|(name, ty)| json!({ "name": name, "in": "path", "required": true, "schema": { "type": ty } }))
            .collect();
        let mut body = None;
        match (op.input, request) {
            (Input::Query(_), Some(schema)) => parameters.extend(query_parameters(&schema, &definitions)),
            (Input::Body(_), Some(schema)) => {
                body = Some(json!({ "required": true, "content": { "application/json": { "schema": schema } } }));
            }
            (Input::AnyBody(what), _) => {
                body = Some(json!({
                    "required": true,
                    "content": { "application/json": { "schema": { "description": what } } },
                }));
            }
            (Input::RawBody(media_type, what), _) => {
                body = Some(json!({
                    "required": true,
                    "description": what,
                    "content": { media_type: { "schema": { "type": "string", "format": "binary" } } },
                }));
            }
            _ => {}
        }
        let mut operation = json!({
            "operationId": op.operation_id,
            "summary": op.summary,
            "responses": responses_of(op, response),
        });
        if !parameters.is_empty() {
            operation["parameters"] = Value::Array(parameters);
        }
        if let Some(body) = body {
            operation["requestBody"] = body;
        }
        paths.entry(op.path.as_str()).or_default().insert(op.method.to_string(), operation);
    }

    let paths: Map<String, Value> = paths.into_iter().map(|(k, v)| (k.to_string(), Value::Object(v))).collect();
    sorted(json!({
        "openapi": "3.1.0",
        "info": {
            "title": "ProxyMind API",
            "version": "v1",
            "summary": "REST API of the local ProxyMind app (every route; see docs/adr/0019-typed-api-contracts.md).",
            "description": "Generated from the Rust types by `cargo xtask contracts`; do not edit by hand. Every \
                            request needs the per-install token, and requests that change anything must carry the \
                            header `X-ProxyMind: 1`. Responses described only by a sentence come from handlers that \
                            build their JSON on the spot; the sentence lists the keys they write.",
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
        let mut keys: Vec<_> = ops.iter().map(|o| (o.method, o.path.clone())).collect();
        keys.sort();
        keys.dedup();
        assert_eq!(keys.len(), ops.len());
    }

    /// Every row says what comes back: an untyped answer needs words (the keys the handler writes), not silence.
    #[test]
    fn every_response_is_described() {
        for op in operations() {
            let words = match op.output {
                Output::Object(w) | Output::List(w) | Output::Any(w) | Output::Download(_, w) => w,
                Output::Typed(_) | Output::Events => "ok",
            };
            assert!(!words.trim().is_empty(), "{} {} has no response description", op.method, op.path);
            assert!(!op.summary.trim().is_empty(), "{} {} has no summary", op.method, op.path);
        }
    }

    /// The (method, path, handler) triples `routes::api()` registers, read from its source: each `.route("path", ..)`
    /// and the `get`/`post`/`put`/`patch`/`delete` calls inside its second argument.
    fn registered_routes() -> Vec<(String, String, String)> {
        let src = include_str!("routes.rs");
        let start = src.find("pub fn api() -> Router<AppState> {").expect("api() exists");
        let body = &src[start..];
        let body = &body[..body.find("\n}\n").expect("api() ends")];
        let mut out = Vec::new();
        for chunk in body.split(".route(").skip(1) {
            let rest = chunk.trim_start();
            let rest = rest.strip_prefix('"').expect("a route starts with its path");
            let (path, rest) = rest.split_once('"').expect("path ends");
            // The handler expression: up to the `)` that closes `.route(`.
            let mut depth = 1;
            let mut end = rest.len();
            for (i, c) in rest.char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let expr = &rest[..end];
            let bytes = expr.as_bytes();
            for method in ["get", "post", "put", "patch", "delete"] {
                let mut from = 0;
                while let Some(pos) = expr[from..].find(&format!("{method}(")) {
                    let at = from + pos;
                    from = at + method.len();
                    let before = if at == 0 { b' ' } else { bytes[at - 1] };
                    if before.is_ascii_alphanumeric() || before == b'_' {
                        continue; // part of a longer name, e.g. `ui_get(`
                    }
                    let handler: String = expr[at + method.len() + 1..]
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    out.push((method.to_string(), format!("/api/v1{path}"), handler));
                }
            }
        }
        out
    }

    /// A route cannot be added, renamed or removed in `routes.rs` without the contract table (and so the OpenAPI
    /// document) following, and the other way round.
    #[test]
    fn route_table_matches_router() {
        let mut router = registered_routes();
        let mut table: Vec<(String, String, String)> =
            operations().into_iter().map(|o| (o.method.to_string(), o.path, o.operation_id.to_string())).collect();
        assert!(router.len() > 150, "the router parser found only {} operations", router.len());
        router.sort();
        table.sort();
        let missing: Vec<_> = router.iter().filter(|r| !table.contains(r)).collect();
        let extra: Vec<_> = table.iter().filter(|t| !router.contains(t)).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "contract_table.rs and routes::api() disagree (method, path, handler).\n\
             In the router only: {missing:#?}\nIn the table only: {extra:#?}"
        );
    }

    /// Every operation of the router is in the generated document, with a response.
    #[test]
    fn document_covers_every_route() {
        let doc = openapi_document();
        for (method, path, handler) in registered_routes() {
            let op = &doc["paths"][&path][&method];
            assert_eq!(op["operationId"], handler.as_str(), "{method} {path} is missing from openapi.json");
            assert!(op["responses"]["200"].is_object(), "{method} {path} has no 200 response");
        }
    }
}
