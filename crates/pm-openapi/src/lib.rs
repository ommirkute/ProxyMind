//! OpenAPI 3.x and Swagger 2.0 import.
//!
//! Turns a spec into the operations it declares and one example request
//! per operation (path and query values, headers, a JSON body built from
//! the schema). The spec comes from the target, so it is untrusted: `$ref`
//! resolution is local-only (`#/...`), depth-limited and cycle-safe, and
//! sizes are capped.

use serde::Serialize;
use serde_json::{Map, Value, json};

/// Most operations imported from one spec.
pub const MAX_OPERATIONS: usize = 2000;
const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecError(pub String);

impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SpecError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Param {
    pub name: String,
    /// path, query, header or cookie
    pub location: String,
    pub required: bool,
    pub example: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Operation {
    pub method: String,
    /// As written in the spec, e.g. `/users/{id}`.
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub summary: String,
    pub params: Vec<Param>,
    /// The operation requires authentication (a security requirement applies).
    pub auth: bool,
    /// An example request (HTTP/1.1, origin-form) for the server's host.
    pub example_request: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Spec {
    pub title: String,
    pub version: String,
    /// Base URL from `servers` / `host` + `basePath`, if absolute.
    pub base_url: Option<String>,
    pub operations: Vec<Operation>,
    /// Operations dropped over MAX_OPERATIONS.
    pub truncated: usize,
}

/// Parses JSON or YAML.
pub fn parse(text: &str) -> Result<Spec, SpecError> {
    let doc: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => serde_saphyr::from_str(text).map_err(|e| SpecError(format!("not JSON or YAML: {e}")))?,
    };
    from_value(&doc, None)
}

/// Builds the import from a parsed document. `spec_url` (where the spec was
/// fetched) resolves relative server URLs.
pub fn from_value(doc: &Value, spec_url: Option<&str>) -> Result<Spec, SpecError> {
    let v3 = doc.get("openapi").and_then(Value::as_str).is_some_and(|v| v.starts_with('3'));
    let v2 = doc.get("swagger").and_then(Value::as_str).is_some_and(|v| v.starts_with('2'));
    if !v3 && !v2 {
        return Err(SpecError("not an OpenAPI 3 or Swagger 2 document (no openapi/swagger version)".into()));
    }
    let info = doc.get("info").cloned().unwrap_or_default();
    let base_url = if v3 {
        doc.pointer("/servers/0/url").and_then(Value::as_str).and_then(|u| absolute(u, spec_url))
    } else {
        let host = doc.get("host").and_then(Value::as_str);
        let base = doc.get("basePath").and_then(Value::as_str).unwrap_or("");
        let scheme = doc.pointer("/schemes/0").and_then(Value::as_str).unwrap_or("https");
        match host {
            Some(h) => Some(format!("{scheme}://{h}{base}")),
            None => spec_url.and_then(|s| absolute(base, Some(s))),
        }
    };
    let host = base_url.as_deref().and_then(|b| url::Url::parse(b).ok()).and_then(|u| {
        u.host_str().map(|h| match u.port() {
            Some(p) => format!("{h}:{p}"),
            None => h.to_string(),
        })
    });
    let prefix = base_url
        .as_deref()
        .and_then(|b| url::Url::parse(b).ok())
        .map(|u| u.path().trim_end_matches('/').to_string())
        .unwrap_or_default();
    let global_security = doc.get("security").and_then(Value::as_array).is_some_and(|a| !a.is_empty());
    let mut operations = Vec::new();
    let mut truncated = 0;
    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        return Err(SpecError("the spec has no paths".into()));
    };
    for (path, item) in paths {
        let item = resolve(doc, item, 0);
        let shared: Vec<Value> = item.get("parameters").and_then(Value::as_array).cloned().unwrap_or_default();
        for method in ["get", "put", "post", "delete", "options", "head", "patch"] {
            let Some(op) = item.get(method) else { continue };
            if operations.len() >= MAX_OPERATIONS {
                truncated += 1;
                continue;
            }
            let op = resolve(doc, op, 0);
            let mut raw_params: Vec<Value> = shared.clone();
            raw_params.extend(op.get("parameters").and_then(Value::as_array).cloned().unwrap_or_default());
            let mut params: Vec<Param> = Vec::new();
            let mut body: Option<Value> = None;
            let mut form = false;
            let mut raw_body: Option<(String, String)> = None;
            for p in raw_params {
                let p = resolve(doc, &p, 0);
                let location = p.get("in").and_then(Value::as_str).unwrap_or("").to_string();
                let name = p.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                if location == "body" {
                    body = p.get("schema").map(|s| example(doc, s, 0));
                    continue;
                }
                if location == "formData" {
                    form = true;
                }
                if name.is_empty() || params.iter().any(|x| x.name == name && x.location == location) {
                    continue;
                }
                let schema = p.get("schema").cloned().unwrap_or_else(|| p.clone());
                let ex = p.get("example").cloned().unwrap_or_else(|| example(doc, &schema, 0));
                params.push(Param {
                    required: location == "path" || p.get("required").and_then(Value::as_bool).unwrap_or(false),
                    name,
                    location,
                    example: scalar(&ex),
                });
            }
            if body.is_none()
                && let Some(content) = resolve(doc, op.get("requestBody").unwrap_or(&Value::Null), 0).get("content")
            {
                if let Some(j) = content.as_object().and_then(|c| c.iter().find(|(k, _)| k.contains("json"))) {
                    body = Some(
                        j.1.get("example")
                            .cloned()
                            .unwrap_or_else(|| example(doc, j.1.get("schema").unwrap_or(&Value::Null), 0)),
                    );
                } else if let Some((ct, x)) = content.as_object().and_then(|c| {
                    c.iter().find(|(k, _)| {
                        k.contains("xml") && k.bytes().all(|b| b.is_ascii_alphanumeric() || b"/+.-".contains(&b))
                    })
                }) {
                    // An XML body: its example as written (there is no schema-based XML example).
                    let text = x.get("example").and_then(Value::as_str).unwrap_or("<?xml version=\"1.0\"?><root/>");
                    raw_body = Some((ct.clone(), text.to_string()));
                } else if let Some(f) = content.get("application/x-www-form-urlencoded") {
                    form = true;
                    if let Some(props) = resolve(doc, f.get("schema").unwrap_or(&Value::Null), 0)
                        .get("properties")
                        .and_then(Value::as_object)
                    {
                        for (k, s) in props {
                            params.push(Param {
                                name: k.clone(),
                                location: "formData".into(),
                                required: false,
                                example: scalar(&example(doc, s, 0)),
                            });
                        }
                    }
                }
            }
            let auth = match op.get("security").and_then(Value::as_array) {
                Some(a) => !a.is_empty() && a.iter().any(|x| x.as_object().is_some_and(|o| !o.is_empty())),
                None => global_security,
            };
            let summary = op
                .get("summary")
                .or_else(|| op.get("operationId"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .chars()
                .take(200)
                .collect();
            let mut example_request = request(method, &prefix, path, &params, body.as_ref(), form, host.as_deref());
            if let Some((ct, text)) = raw_body.filter(|_| body.is_none() && !form)
                && let Some(head) = example_request.strip_suffix("\r\n")
            {
                example_request = format!("{head}Content-Type: {ct}\r\nContent-Length: {}\r\n\r\n{text}", text.len());
            }
            operations.push(Operation {
                method: method.to_ascii_uppercase(),
                path: path.clone(),
                summary,
                params,
                auth,
                example_request,
            });
        }
    }
    Ok(Spec {
        title: info.get("title").and_then(Value::as_str).unwrap_or("").chars().take(200).collect(),
        version: info.get("version").map(scalar).unwrap_or_default(),
        base_url,
        operations,
        truncated,
    })
}

fn absolute(u: &str, spec_url: Option<&str>) -> Option<String> {
    if let Ok(x) = url::Url::parse(u) {
        return matches!(x.scheme(), "http" | "https").then(|| u.trim_end_matches('/').to_string());
    }
    let base = url::Url::parse(spec_url?).ok()?;
    // An empty or "." server means "where the document is": its folder, not
    // the document's own URL (which resolving "" would give).
    let u = if u.trim().is_empty() || u.trim() == "." { "./" } else { u };
    Some(base.join(u).ok()?.to_string().trim_end_matches('/').to_string())
}

/// Follows a local `$ref` (`#/components/schemas/X`), up to a depth.
fn resolve(doc: &Value, v: &Value, depth: usize) -> Value {
    let mut cur = v.clone();
    for _ in depth..MAX_DEPTH {
        let Some(r) = cur.get("$ref").and_then(Value::as_str) else { return cur };
        let Some(ptr) = r.strip_prefix('#') else { return Value::Null };
        match doc.pointer(ptr) {
            Some(t) => cur = t.clone(),
            None => return Value::Null,
        }
    }
    Value::Null
}

/// An example value for a schema.
fn example(doc: &Value, schema: &Value, depth: usize) -> Value {
    if depth > MAX_DEPTH {
        return Value::Null;
    }
    let s = resolve(doc, schema, depth);
    if s.is_null() && schema.get("$ref").is_some() {
        return Value::Null; // remote, missing or cyclic reference
    }
    if let Some(e) = s.get("example").or_else(|| s.get("default")) {
        return e.clone();
    }
    if let Some(e) = s.get("enum").and_then(Value::as_array).and_then(|a| a.first()) {
        return e.clone();
    }
    for key in ["allOf", "oneOf", "anyOf"] {
        if let Some(list) = s.get(key).and_then(Value::as_array) {
            if key == "allOf" {
                let mut merged = Map::new();
                for part in list {
                    if let Value::Object(o) = example(doc, part, depth + 1) {
                        merged.extend(o);
                    }
                }
                return Value::Object(merged);
            }
            return list.first().map(|x| example(doc, x, depth + 1)).unwrap_or(Value::Null);
        }
    }
    let ty = s.get("type").and_then(Value::as_str).unwrap_or(if s.get("properties").is_some() {
        "object"
    } else {
        "string"
    });
    match ty {
        "integer" => json!(1),
        "number" => json!(1.5),
        "boolean" => json!(true),
        "array" => json!([example(doc, s.get("items").unwrap_or(&Value::Null), depth + 1)]),
        "object" => {
            let mut o = Map::new();
            if let Some(props) = s.get("properties").and_then(Value::as_object) {
                for (k, p) in props.iter().take(50) {
                    o.insert(k.clone(), example(doc, p, depth + 1));
                }
            }
            Value::Object(o)
        }
        _ => match s.get("format").and_then(Value::as_str) {
            Some("email") => json!("user@example.com"),
            Some("uuid") => json!("00000000-0000-4000-8000-000000000001"),
            Some("date-time") => json!("2026-01-01T00:00:00Z"),
            Some("date") => json!("2026-01-01"),
            Some("uri" | "url") => json!("https://example.com/"),
            _ => json!("test"),
        },
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "test".into(),
        other => other.to_string(),
    }
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn request(
    method: &str,
    prefix: &str,
    path: &str,
    params: &[Param],
    body: Option<&Value>,
    form: bool,
    host: Option<&str>,
) -> String {
    let mut target = format!("{prefix}{path}");
    for p in params.iter().filter(|p| p.location == "path") {
        target = target.replace(&format!("{{{}}}", p.name), &enc(&p.example));
    }
    let query: Vec<String> = params
        .iter()
        .filter(|p| p.location == "query" && p.required)
        .map(|p| format!("{}={}", enc(&p.name), enc(&p.example)))
        .collect();
    if !query.is_empty() {
        target.push('?');
        target.push_str(&query.join("&"));
    }
    // The spec may come from the target: nothing in it may break a line.
    let target: String = target
        .bytes()
        .map(|b| if b.is_ascii_graphic() { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect();
    let host = host
        .filter(|h| !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._:[]".contains(&b)))
        .unwrap_or("example.invalid");
    let mut req = format!("{} {target} HTTP/1.1\r\nHost: {host}\r\n", method.to_ascii_uppercase());
    let token =
        |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b));
    for p in params.iter().filter(|p| p.location == "header" && p.required && token(&p.name)) {
        req.push_str(&format!("{}: {}\r\n", p.name, p.example.replace(['\r', '\n', '\0'], "")));
    }
    let body_text = if form {
        Some((
            "application/x-www-form-urlencoded",
            params
                .iter()
                .filter(|p| p.location == "formData")
                .map(|p| format!("{}={}", enc(&p.name), enc(&p.example)))
                .collect::<Vec<_>>()
                .join("&"),
        ))
    } else {
        body.map(|b| ("application/json", b.to_string()))
    };
    match body_text {
        Some((ct, b)) => format!("{req}Content-Type: {ct}\r\nContent-Length: {}\r\n\r\n{b}", b.len()),
        None => format!("{req}\r\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V3: &str = r##"
openapi: 3.0.3
info: { title: Shop, version: "1.2" }
servers: [{ url: "https://api.shop.test/v1" }]
security: [{ bearer: [] }]
components:
  schemas:
    Order:
      type: object
      properties:
        id: { type: integer }
        email: { type: string, format: email }
        items: { type: array, items: { $ref: "#/components/schemas/Item" } }
    Item: { type: object, properties: { sku: { type: string, example: "A-1" } } }
    Loop: { $ref: "#/components/schemas/Loop" }
paths:
  /orders/{id}:
    parameters: [{ name: id, in: path, required: true, schema: { type: integer, example: 1001 } }]
    get: { summary: Get an order }
    put:
      requestBody: { content: { application/json: { schema: { $ref: "#/components/schemas/Order" } } } }
  /search:
    get:
      security: []
      parameters:
        - { name: q, in: query, required: true, schema: { type: string } }
        - { name: page, in: query, schema: { type: integer } }
  /loop:
    post:
      requestBody: { content: { application/json: { schema: { $ref: "#/components/schemas/Loop" } } } }
"##;

    #[test]
    fn openapi3_operations_and_examples() {
        let s = parse(V3).unwrap();
        assert_eq!((s.title.as_str(), s.version.as_str()), ("Shop", "1.2"));
        assert_eq!(s.base_url.as_deref(), Some("https://api.shop.test/v1"));
        let ops: Vec<(String, String)> = s.operations.iter().map(|o| (o.method.clone(), o.path.clone())).collect();
        assert_eq!(ops.len(), 4);
        let get = &s.operations[0];
        assert_eq!((get.method.as_str(), get.auth), ("GET", true));
        assert_eq!(get.example_request, "GET /v1/orders/1001 HTTP/1.1\r\nHost: api.shop.test\r\n\r\n");
        let put = s.operations.iter().find(|o| o.method == "PUT").unwrap();
        assert!(put.example_request.contains("Content-Type: application/json"));
        assert!(
            put.example_request.ends_with(r#"{"id":1,"email":"user@example.com","items":[{"sku":"A-1"}]}"#),
            "{}",
            put.example_request
        );
        let search = s.operations.iter().find(|o| o.path == "/search").unwrap();
        assert!(!search.auth, "security: [] opts out");
        assert!(search.example_request.starts_with("GET /v1/search?q=test HTTP/1.1"), "optional params left out");
        // Self-referencing schemas don't loop forever.
        assert!(s.operations.iter().any(|o| o.path == "/loop"));
    }

    #[test]
    fn swagger2() {
        let doc = r##"{"swagger":"2.0","info":{"title":"Old","version":"1"},"host":"old.test:8080","basePath":"/api","schemes":["http"],
            "paths":{"/login":{"post":{"parameters":[{"name":"user","in":"formData","type":"string"},{"name":"pw","in":"formData","type":"string"}]}},
                     "/items":{"post":{"parameters":[{"name":"body","in":"body","schema":{"$ref":"#/definitions/I"}}]}}},
            "definitions":{"I":{"type":"object","properties":{"n":{"type":"integer"}}}}}"##;
        let s = parse(doc).unwrap();
        assert_eq!(s.base_url.as_deref(), Some("http://old.test:8080/api"));
        let login = &s.operations[0];
        assert!(login.example_request.starts_with("POST /api/login HTTP/1.1\r\nHost: old.test:8080\r\n"));
        assert!(login.example_request.ends_with("user=test&pw=test"));
        assert!(s.operations[1].example_request.ends_with(r#"{"n":1}"#));
    }

    #[test]
    fn relative_servers_and_bad_input() {
        let doc: Value = serde_json::from_str(
            r#"{"openapi":"3.1.0","info":{},"servers":[{"url":"/api"}],"paths":{"/x":{"get":{}}}}"#,
        )
        .unwrap();
        let s = from_value(&doc, Some("http://127.0.0.1:8899/openapi.json")).unwrap();
        assert_eq!(s.base_url.as_deref(), Some("http://127.0.0.1:8899/api"));
        assert_eq!(s.operations[0].example_request, "GET /api/x HTTP/1.1\r\nHost: 127.0.0.1:8899\r\n\r\n");
        // VAmPI's servers: [{"url": ""}] means the document's folder.
        let empty: Value =
            serde_json::from_str(r#"{"openapi":"3.0.0","info":{},"servers":[{"url":""}],"paths":{"/x":{"get":{}}}}"#)
                .unwrap();
        let s = from_value(&empty, Some("http://127.0.0.1:5002/openapi.json")).unwrap();
        assert_eq!(s.base_url.as_deref(), Some("http://127.0.0.1:5002"));
        assert!(
            s.operations[0].example_request.starts_with("GET /x HTTP/1.1\r\n"),
            "{}",
            s.operations[0].example_request
        );
        assert!(parse("{\"hello\":1}").is_err());
        assert!(parse("::: not yaml or json").is_err());
        let remote_ref = r##"{"openapi":"3.0.0","info":{},"paths":{"/x":{"post":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"http://evil/x.json"}}}}}}}}"##;
        assert!(
            parse(remote_ref).unwrap().operations[0].example_request.ends_with("\r\n\r\nnull"),
            "remote refs are not fetched"
        );
    }

    #[test]
    fn yaml_alias_bombs_are_refused() {
        let mut doc = String::from("a0: &a0 [x, x, x, x, x, x, x, x, x, x]\n");
        for i in 1..12 {
            let p = i - 1;
            doc.push_str(&format!(
                "a{i}: &a{i} [*a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}, *a{p}]\n"
            ));
        }
        doc.push_str("openapi: 3.0.0\npaths: {}\n");
        let started = std::time::Instant::now();
        assert!(parse(&doc).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn hostile_specs_cannot_break_the_request() {
        let spec = r#"{"openapi":"3.0.0","servers":[{"url":"http://api.test/v1 x\r\nEvil: 1"}],
            "paths":{"/a b\r\nX-Injected: 1\r\n\r\nGET /other":{"get":{"parameters":[
              {"name":"X-Ok","in":"header","required":true,"example":"v\r\nX-Bad: 1"},
              {"name":"Bad: Name","in":"header","required":true}]}}}}"#;
        let s = parse(spec).unwrap();
        let r = &s.operations[0].example_request;
        let end = pm_http::find_head_end(r.as_bytes()).unwrap().unwrap();
        assert_eq!(end, r.len(), "one request only: {r:?}");
        let head = pm_http::parse_request_head(r.as_bytes()).unwrap();
        assert!(head.target.contains("%0D%0AX-Injected:"), "{r:?}");
        assert!(!r.contains("\r\nX-Injected") && !r.contains("\r\nX-Bad") && !r.contains("Bad: Name"), "{r:?}");
    }

    #[test]
    fn xml_bodies_keep_their_example() {
        let doc = r#"{"openapi":"3.0.0","info":{},"paths":{"/import":{"post":{"requestBody":{"content":
            {"application/xml":{"example":"<items><item>Tea</item></items>"}}}}}}}"#;
        let op = &parse(doc).unwrap().operations[0];
        assert!(op.example_request.contains("Content-Type: application/xml\r\nContent-Length: 31\r\n\r\n<items>"));
        assert!(op.example_request.ends_with("</items>"));
    }
}
