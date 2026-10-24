//! GraphQL without I/O: read an introspection result into a list of
//! operations, each with an example document and variables, and build the
//! HTTP request that sends one.
//!
//! The schema is target content: names and descriptions are untrusted.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::{Map, Value, json};

/// The introspection query (types, fields, arguments, input fields, enums).
pub const INTROSPECTION_QUERY: &str = "query IntrospectionQuery { __schema { queryType { name } \
mutationType { name } subscriptionType { name } types { kind name description \
fields(includeDeprecated: true) { name description args { name type { ...TypeRef } defaultValue } \
type { ...TypeRef } } inputFields { name type { ...TypeRef } defaultValue } \
enumValues(includeDeprecated: true) { name } } } } \
fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name \
ofType { kind name ofType { kind name } } } } } }";

/// Most operations listed; more are counted in `truncated`.
pub const MAX_OPERATIONS: usize = 1000;
/// Most fields picked per selection set in an example.
const MAX_SELECTED: usize = 12;
/// How deep example selections and input values go.
const MAX_DEPTH: usize = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError(pub String);

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SchemaError {}

/// A reference to a type, e.g. `[ID!]!`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeRef {
    pub kind: String,
    pub name: Option<String>,
    pub of_type: Option<Box<TypeRef>>,
}

impl TypeRef {
    fn from_value(v: &Value, depth: usize) -> Result<Self, SchemaError> {
        if depth > 10 {
            return Err(SchemaError("type reference nested too deeply".into()));
        }
        let kind = v.get("kind").and_then(Value::as_str).ok_or_else(|| SchemaError("type without kind".into()))?;
        let of_type = match v.get("ofType") {
            Some(o) if !o.is_null() => Some(Box::new(Self::from_value(o, depth + 1)?)),
            _ => None,
        };
        if matches!(kind, "NON_NULL" | "LIST") && of_type.is_none() {
            return Err(SchemaError(format!("{kind} type without ofType")));
        }
        Ok(Self { kind: kind.to_string(), name: v.get("name").and_then(Value::as_str).map(str::to_string), of_type })
    }

    /// As written in GraphQL, e.g. `[ID!]!`.
    pub fn render(&self) -> String {
        match (self.kind.as_str(), &self.of_type) {
            ("NON_NULL", Some(t)) => format!("{}!", t.render()),
            ("LIST", Some(t)) => format!("[{}]", t.render()),
            _ => self.name.clone().unwrap_or_else(|| "?".into()),
        }
    }

    /// The named type inside any lists and non-nulls.
    pub fn named(&self) -> &str {
        match &self.of_type {
            Some(t) if matches!(self.kind.as_str(), "NON_NULL" | "LIST") => t.named(),
            _ => self.name.as_deref().unwrap_or("?"),
        }
    }

    pub fn required(&self) -> bool {
        self.kind == "NON_NULL"
    }
}

#[derive(Debug, Clone)]
struct InputValue {
    name: String,
    ty: TypeRef,
    has_default: bool,
}

#[derive(Debug, Clone)]
struct Field {
    name: String,
    description: String,
    args: Vec<InputValue>,
    ty: TypeRef,
}

#[derive(Debug, Clone)]
struct FullType {
    kind: String,
    fields: Vec<Field>,
    input_fields: Vec<InputValue>,
    enum_values: Vec<String>,
}

/// One argument of an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Arg {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub required: bool,
}

/// A root field: a query, mutation or subscription.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Operation {
    /// query, mutation or subscription
    pub kind: String,
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub args: Vec<Arg>,
    pub returns: String,
    /// An example document selecting a few fields of the result.
    pub document: String,
    /// Example values for the required arguments.
    pub variables: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Schema {
    pub query_type: Option<String>,
    pub mutation_type: Option<String>,
    pub subscription_type: Option<String>,
    pub types: usize,
    pub operations: Vec<Operation>,
    pub truncated: usize,
}

fn str_of<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn arr<'a>(v: &'a Value, k: &str) -> &'a [Value] {
    v.get(k).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default()
}

fn input_values(v: &Value, k: &str) -> Result<Vec<InputValue>, SchemaError> {
    arr(v, k)
        .iter()
        .map(|a| {
            Ok(InputValue {
                name: str_of(a, "name").to_string(),
                ty: TypeRef::from_value(a.get("type").unwrap_or(&Value::Null), 0)?,
                has_default: a.get("defaultValue").is_some_and(|d| !d.is_null()),
            })
        })
        .collect()
}

/// True for a GraphQL name (`[_A-Za-z][_0-9A-Za-z]*`); others can't go into a document.
fn is_name(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f == '_' || f.is_ascii_alphabetic()) && c.all(|x| x == '_' || x.is_ascii_alphanumeric())
}

/// Reads an introspection result: `{"data": {"__schema": …}}`, `{"__schema": …}` or the schema itself.
pub fn parse_introspection(doc: &Value) -> Result<Schema, SchemaError> {
    let schema = doc
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| doc.get("__schema"))
        .or_else(|| doc.get("types").map(|_| doc))
        .ok_or_else(|| {
            let errors = doc
                .get("errors")
                .map(|e| format!(" (server said: {})", e.to_string().chars().take(300).collect::<String>()));
            SchemaError(format!("not an introspection result: no __schema{}", errors.unwrap_or_default()))
        })?;
    let mut types = HashMap::new();
    for t in arr(schema, "types") {
        let name = str_of(t, "name");
        if name.is_empty() {
            continue;
        }
        let fields = arr(t, "fields")
            .iter()
            .map(|f| {
                Ok(Field {
                    name: str_of(f, "name").to_string(),
                    description: str_of(f, "description").to_string(),
                    args: input_values(f, "args")?,
                    ty: TypeRef::from_value(f.get("type").unwrap_or(&Value::Null), 0)?,
                })
            })
            .collect::<Result<Vec<_>, SchemaError>>()?;
        types.insert(
            name.to_string(),
            FullType {
                kind: str_of(t, "kind").to_string(),
                fields,
                input_fields: input_values(t, "inputFields")?,
                enum_values: arr(t, "enumValues").iter().map(|e| str_of(e, "name").to_string()).collect(),
            },
        );
    }
    let root = |k: &str| schema.get(k).and_then(|t| t.get("name")).and_then(Value::as_str).map(str::to_string);
    let (query_type, mutation_type, subscription_type) =
        (root("queryType"), root("mutationType"), root("subscriptionType"));
    if query_type.is_none() {
        return Err(SchemaError("the schema has no query type".into()));
    }
    let mut operations = Vec::new();
    let mut truncated = 0;
    for (kind, root) in [("query", &query_type), ("mutation", &mutation_type), ("subscription", &subscription_type)] {
        let Some(t) = root.as_ref().and_then(|r| types.get(r)) else { continue };
        for f in &t.fields {
            // Names from the schema go into documents: anything that isn't a GraphQL name is skipped.
            if !is_name(&f.name) || f.args.iter().any(|a| !is_name(&a.name) || !is_name(a.ty.named())) {
                continue;
            }
            if operations.len() >= MAX_OPERATIONS {
                truncated += 1;
                continue;
            }
            operations.push(operation(kind, f, &types));
        }
    }
    Ok(Schema { query_type, mutation_type, subscription_type, types: types.len(), operations, truncated })
}

fn operation(kind: &str, f: &Field, types: &HashMap<String, FullType>) -> Operation {
    let op_name: String = f.name.chars().take(1).flat_map(char::to_uppercase).chain(f.name.chars().skip(1)).collect();
    let sig: Vec<String> = f.args.iter().map(|a| format!("${}: {}", a.name, a.ty.render())).collect();
    let call: Vec<String> = f.args.iter().map(|a| format!("{0}: ${0}", a.name)).collect();
    let mut doc = format!("{kind} {op_name}");
    if !sig.is_empty() {
        doc.push_str(&format!("({})", sig.join(", ")));
    }
    doc.push_str(&format!(" {{ {}", f.name));
    if !call.is_empty() {
        doc.push_str(&format!("({})", call.join(", ")));
    }
    let sel = selection(f.ty.named(), types, 0);
    if !sel.is_empty() {
        doc.push(' ');
        doc.push_str(&sel);
    }
    doc.push_str(" }");
    let mut vars = Map::new();
    for a in f.args.iter().filter(|a| a.ty.required() && !a.has_default) {
        vars.insert(a.name.clone(), example(&a.ty, types, 0));
    }
    Operation {
        kind: kind.to_string(),
        name: f.name.clone(),
        description: f.description.clone(),
        args: f
            .args
            .iter()
            .map(|a| Arg { name: a.name.clone(), ty: a.ty.render(), required: a.ty.required() && !a.has_default })
            .collect(),
        returns: f.ty.render(),
        document: doc,
        variables: Value::Object(vars),
    }
}

/// `{ a b c { d } }` for object types; empty for scalars and enums.
fn selection(type_name: &str, types: &HashMap<String, FullType>, depth: usize) -> String {
    let Some(t) = types.get(type_name) else { return String::new() };
    match t.kind.as_str() {
        "OBJECT" | "INTERFACE" => {}
        "UNION" => return "{ __typename }".into(),
        _ => return String::new(),
    }
    let leaf = |f: &&Field| types.get(f.ty.named()).is_none_or(|t| matches!(t.kind.as_str(), "SCALAR" | "ENUM"));
    let callable = |f: &&Field| is_name(&f.name) && f.args.iter().all(|a| !a.ty.required() || a.has_default);
    let mut picked: Vec<String> =
        t.fields.iter().filter(callable).filter(leaf).take(MAX_SELECTED).map(|f| f.name.clone()).collect();
    if depth < MAX_DEPTH {
        for f in t.fields.iter().filter(callable).filter(|f| !leaf(f)) {
            if picked.len() >= MAX_SELECTED {
                break;
            }
            let sub = selection(f.ty.named(), types, depth + 1);
            if !sub.is_empty() {
                picked.push(format!("{} {sub}", f.name));
            }
        }
    }
    if picked.is_empty() {
        picked.push("__typename".into());
    }
    format!("{{ {} }}", picked.join(" "))
}

/// An example value of a type, for variables.
fn example(t: &TypeRef, types: &HashMap<String, FullType>, depth: usize) -> Value {
    match (t.kind.as_str(), &t.of_type) {
        ("NON_NULL", Some(inner)) => example(inner, types, depth),
        ("LIST", Some(inner)) => json!([example(inner, types, depth)]),
        _ => {
            let name = t.name.as_deref().unwrap_or_default();
            match name {
                "Int" => json!(1),
                "Float" => json!(1.5),
                "Boolean" => json!(true),
                "ID" => json!("1"),
                "String" => json!("test"),
                _ => match types.get(name) {
                    Some(ft) if ft.kind == "ENUM" => ft.enum_values.first().map_or(Value::Null, |v| json!(v)),
                    Some(ft) if ft.kind == "INPUT_OBJECT" => {
                        let mut m = Map::new();
                        if depth < MAX_DEPTH + 1 {
                            for f in ft.input_fields.iter().filter(|f| f.ty.required() && !f.has_default) {
                                m.insert(f.name.clone(), example(&f.ty, types, depth + 1));
                            }
                        }
                        Value::Object(m)
                    }
                    // A custom scalar: a string is the most common representation.
                    _ => json!("test"),
                },
            }
        }
    }
}

/// The JSON body that sends a document.
pub fn body(document: &str, variables: &Value, operation_name: Option<&str>) -> String {
    let mut b = json!({ "query": document, "variables": variables });
    if let Some(n) = operation_name {
        b["operationName"] = json!(n);
    }
    b.to_string()
}

/// A POST request (HTTP/1.1, origin-form) that sends a document to `path` on `host`.
pub fn request(host: &str, path: &str, document: &str, variables: &Value) -> String {
    let body = body(document, variables, None);
    format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nAccept: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// Whether a request looks like GraphQL: a JSON body with a `query` document
/// (or a batch of them), or a GET with `?query=` on a path mentioning graphql.
pub fn looks_like_graphql(path: &str, body: &[u8]) -> bool {
    let is_doc = |v: &Value| v.get("query").and_then(Value::as_str).is_some_and(|q| q.contains('{'));
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Array(items)) => !items.is_empty() && items.iter().all(is_doc),
        Ok(v) => is_doc(&v),
        Err(_) => {
            let lower = path.to_ascii_lowercase();
            lower.contains("graphql") && (lower.contains("?query=") || lower.contains("&query="))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(kind: &str, name: Option<&str>, of: Option<Value>) -> Value {
        json!({ "kind": kind, "name": name, "ofType": of })
    }
    fn named(kind: &str, name: &str) -> Value {
        t(kind, Some(name), None)
    }
    fn non_null(v: Value) -> Value {
        t("NON_NULL", None, Some(v))
    }

    fn sample() -> Value {
        json!({ "data": { "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": null,
            "types": [
                {"kind": "OBJECT", "name": "Query", "fields": [
                    {"name": "invoice", "description": "One invoice",
                     "args": [{"name": "id", "type": non_null(named("SCALAR", "ID")), "defaultValue": null}],
                     "type": named("OBJECT", "Invoice")},
                    {"name": "invoices", "args": [{"name": "first", "type": named("SCALAR", "Int"), "defaultValue": "10"}],
                     "type": non_null(t("LIST", None, Some(non_null(named("OBJECT", "Invoice")))))},
                    {"name": "bad name", "args": [], "type": named("SCALAR", "String")},
                    {"name": "search", "args": [{"name": "q", "type": non_null(named("SCALAR", "String"))}],
                     "type": named("UNION", "Result")}
                ]},
                {"kind": "OBJECT", "name": "Mutation", "fields": [
                    {"name": "setStatus", "args": [
                        {"name": "input", "type": non_null(named("INPUT_OBJECT", "StatusInput"))}],
                     "type": named("SCALAR", "Boolean")}
                ]},
                {"kind": "OBJECT", "name": "Invoice", "fields": [
                    {"name": "id", "args": [], "type": non_null(named("SCALAR", "ID"))},
                    {"name": "total", "args": [], "type": named("SCALAR", "Float")},
                    {"name": "status", "args": [], "type": named("ENUM", "Status")},
                    {"name": "owner", "args": [], "type": named("OBJECT", "User")},
                    {"name": "lines", "args": [{"name": "page", "type": non_null(named("SCALAR", "Int"))}],
                     "type": named("SCALAR", "String")}
                ]},
                {"kind": "OBJECT", "name": "User", "fields": [
                    {"name": "email", "args": [], "type": named("SCALAR", "String")},
                    {"name": "friend", "args": [], "type": named("OBJECT", "User")}
                ]},
                {"kind": "ENUM", "name": "Status", "enumValues": [{"name": "PAID"}, {"name": "OPEN"}]},
                {"kind": "UNION", "name": "Result"},
                {"kind": "INPUT_OBJECT", "name": "StatusInput", "inputFields": [
                    {"name": "id", "type": non_null(named("SCALAR", "ID"))},
                    {"name": "status", "type": non_null(named("ENUM", "Status"))},
                    {"name": "note", "type": named("SCALAR", "String")}
                ]},
                {"kind": "SCALAR", "name": "ID"}, {"kind": "SCALAR", "name": "Int"},
                {"kind": "SCALAR", "name": "Float"}, {"kind": "SCALAR", "name": "String"},
                {"kind": "SCALAR", "name": "Boolean"}
            ]
        }}})
    }

    #[test]
    fn reads_operations() {
        let s = parse_introspection(&sample()).unwrap();
        assert_eq!((s.query_type.as_deref(), s.mutation_type.as_deref()), (Some("Query"), Some("Mutation")));
        let names: Vec<&str> = s.operations.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(
            names,
            ["invoice", "invoices", "search", "setStatus"],
            "names that aren't GraphQL names are skipped"
        );

        let inv = &s.operations[0];
        assert_eq!(inv.description, "One invoice");
        assert_eq!(inv.args, [Arg { name: "id".into(), ty: "ID!".into(), required: true }]);
        assert_eq!(
            inv.document,
            "query Invoice($id: ID!) { invoice(id: $id) { id total status owner { email friend { email } } } }"
        );
        assert_eq!(inv.variables, json!({"id": "1"}));

        let list = &s.operations[1];
        assert_eq!(list.returns, "[Invoice!]!");
        assert!(!list.args[0].required, "optional with a default");
        assert_eq!(list.variables, json!({}));
        assert_eq!(s.operations[2].document, "query Search($q: String!) { search(q: $q) { __typename } }");

        let m = &s.operations[3];
        assert_eq!(m.kind, "mutation");
        assert_eq!(m.document, "mutation SetStatus($input: StatusInput!) { setStatus(input: $input) }");
        assert_eq!(m.variables, json!({"input": {"id": "1", "status": "PAID"}}));
    }

    #[test]
    fn rejects_other_documents() {
        assert!(parse_introspection(&json!({"data": {"me": {}}})).is_err());
        let e = parse_introspection(&json!({"errors": [{"message": "introspection is disabled"}]})).unwrap_err();
        assert!(e.0.contains("introspection is disabled"), "{e}");
        assert!(parse_introspection(&json!({"__schema": {"types": []}})).is_err(), "no query type");
        let bad = json!({"__schema": {"queryType": {"name": "Q"}, "types": [
            {"kind": "OBJECT", "name": "Q", "fields": [{"name": "a", "args": [], "type": {"kind": "NON_NULL"}}]}]}});
        assert!(parse_introspection(&bad).is_err());
    }

    #[test]
    fn hostile_names_never_reach_documents() {
        let doc = json!({"__schema": {"queryType": {"name": "Q"}, "types": [
            {"kind": "OBJECT", "name": "Q", "fields": [
                {"name": "a", "args": [{"name": "x", "type": non_null(named("SCALAR", "ID) { evil } #"))}],
                 "type": named("SCALAR", "String")},
                {"name": "b", "args": [], "type": named("OBJECT", "T")}]},
            {"kind": "OBJECT", "name": "T", "fields": [
                {"name": "ok", "args": [], "type": named("SCALAR", "String")},
                {"name": "x } mutation { drop", "args": [], "type": named("SCALAR", "String")}]}]}});
        let s = parse_introspection(&doc).unwrap();
        assert_eq!(s.operations.len(), 1);
        assert_eq!(s.operations[0].document, "query B { b { ok } }");
    }

    #[test]
    fn deep_type_refs_are_refused() {
        let mut v = named("SCALAR", "ID");
        for _ in 0..20 {
            v = t("LIST", None, Some(v));
        }
        assert!(TypeRef::from_value(&v, 0).is_err());
    }

    #[test]
    fn builds_requests_and_detects_graphql() {
        let r = request("shop.test", "/graphql", "query { me { id } }", &json!({}));
        let (head, sent) = r.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("POST /graphql HTTP/1.1\r\nHost: shop.test\r\n"));
        assert!(head.ends_with(&format!("Content-Length: {}", sent.len())));
        assert!(looks_like_graphql("/graphql", sent.as_bytes()));
        assert!(looks_like_graphql("/api", br#"[{"query":"{a}"},{"query":"{b}"}]"#));
        assert!(looks_like_graphql("/graphql?query=%7Bme%7D", b""));
        assert!(!looks_like_graphql("/api/search", br#"{"query":"shoes"}"#));
        assert!(!looks_like_graphql("/search?query=x", b""));
        assert!(
            INTROSPECTION_QUERY.contains("__schema")
                && looks_like_graphql("/", body(INTROSPECTION_QUERY, &json!({}), None).as_bytes())
        );
    }
}
