//! A small intermediate form for the JSON Schemas in `components/schemas`, shared by the TypeScript and Python emitters.

use serde_json::{Map, Value};

#[derive(Clone, Debug, PartialEq)]
pub enum Lit {
    Str(String),
    Num(String),
    Bool(bool),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Variant {
    pub ty: Ty,
    pub doc: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub name: String,
    pub ty: Ty,
    pub required: bool,
    pub doc: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Object {
    pub fields: Vec<Field>,
    /// `additionalProperties` as a type (`Unknown` for `true`); `None` when extra keys are not allowed.
    pub extra: Option<Box<Ty>>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Ty {
    /// Untyped (`true`, `{}`, or a schema with no usable type): `unknown` / `Any`.
    Unknown,
    Never,
    Null,
    Str,
    Int,
    Num,
    Bool,
    Ref(String),
    Lit(Lit),
    Array(Box<Ty>),
    Tuple(Vec<Ty>),
    /// A map from string keys (`additionalProperties` or `patternProperties` with no named properties).
    Map(Box<Ty>),
    Object(Object),
    Union(Vec<Variant>),
    Inter(Vec<Ty>),
}

/// One entry of `components/schemas`.
pub struct Def {
    pub name: String,
    pub doc: Option<String>,
    pub ty: Ty,
}

/// Every schema under `components/schemas`, sorted by name.
pub fn definitions(document: &Value) -> Vec<Def> {
    let mut defs: Vec<Def> = document["components"]["schemas"]
        .as_object()
        .map(|m| m.iter().map(|(name, s)| Def { name: name.clone(), doc: description(s), ty: convert(s) }).collect())
        .unwrap_or_default();
    defs.sort_by(|a, b| a.name.cmp(&b.name));
    defs
}

fn description(s: &Value) -> Option<String> {
    s.get("description").and_then(Value::as_str).map(|d| d.trim().to_string()).filter(|d| !d.is_empty())
}

fn lit(v: &Value) -> Ty {
    match v {
        Value::String(s) => Ty::Lit(Lit::Str(s.clone())),
        Value::Number(n) => Ty::Lit(Lit::Num(n.to_string())),
        Value::Bool(b) => Ty::Lit(Lit::Bool(*b)),
        Value::Null => Ty::Null,
        _ => Ty::Unknown,
    }
}

/// Builds a union: flattens nested unions, drops duplicates, puts `null` last, collapses a single member.
pub fn union(variants: Vec<Variant>) -> Ty {
    let mut flat: Vec<Variant> = Vec::new();
    for v in variants {
        match v.ty {
            Ty::Union(inner) => flat.extend(inner),
            _ => flat.push(v),
        }
    }
    let mut out: Vec<Variant> = Vec::new();
    for v in flat {
        if !out.iter().any(|o| o.ty == v.ty) {
            out.push(v);
        }
    }
    if let Some(i) = out.iter().position(|v| v.ty == Ty::Null) {
        let null = out.remove(i);
        out.push(null);
    }
    match out.len() {
        0 => Ty::Never,
        1 => out.remove(0).ty,
        _ => Ty::Union(out),
    }
}

pub fn convert(s: &Value) -> Ty {
    let Some(o) = s.as_object() else {
        return if *s == Value::Bool(false) { Ty::Never } else { Ty::Unknown };
    };
    if let Some(r) = o.get("$ref").and_then(Value::as_str) {
        return Ty::Ref(r.rsplit('/').next().unwrap_or(r).to_string());
    }
    if let Some(c) = o.get("const") {
        return lit(c);
    }
    if let Some(e) = o.get("enum").and_then(Value::as_array) {
        return union(e.iter().map(|v| Variant { ty: lit(v), doc: None }).collect());
    }
    for key in ["oneOf", "anyOf"] {
        if let Some(arr) = o.get(key).and_then(Value::as_array) {
            return union(arr.iter().map(|v| Variant { ty: convert(v), doc: description(v) }).collect());
        }
    }
    if let Some(arr) = o.get("allOf").and_then(Value::as_array) {
        let mut parts: Vec<Ty> = arr.iter().map(convert).collect();
        return if parts.len() == 1 { parts.remove(0) } else { Ty::Inter(parts) };
    }
    match o.get("type") {
        Some(Value::String(t)) => typed(t, o),
        Some(Value::Array(ts)) => {
            union(ts.iter().filter_map(Value::as_str).map(|t| Variant { ty: typed(t, o), doc: None }).collect())
        }
        _ if o.contains_key("properties") || o.contains_key("additionalProperties") => typed("object", o),
        _ => Ty::Unknown,
    }
}

fn typed(t: &str, o: &Map<String, Value>) -> Ty {
    match t {
        "string" => Ty::Str,
        "integer" => Ty::Int,
        "number" => Ty::Num,
        "boolean" => Ty::Bool,
        "null" => Ty::Null,
        "array" => {
            if let Some(items) = o.get("prefixItems").and_then(Value::as_array) {
                Ty::Tuple(items.iter().map(convert).collect())
            } else {
                Ty::Array(Box::new(o.get("items").map(convert).unwrap_or(Ty::Unknown)))
            }
        }
        "object" => object(o),
        _ => Ty::Unknown,
    }
}

fn object(o: &Map<String, Value>) -> Ty {
    let required: Vec<&str> = o
        .get("required")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let extra = match o.get("additionalProperties") {
        Some(Value::Bool(false)) | None => None,
        Some(Value::Bool(true)) => Some(Ty::Unknown),
        Some(schema) => Some(convert(schema)),
    };
    let props = o.get("properties").and_then(Value::as_object).filter(|p| !p.is_empty());
    let Some(props) = props else {
        if let Some(e) = extra {
            return Ty::Map(Box::new(e));
        }
        if let Some(p) = o.get("patternProperties").and_then(Value::as_object).and_then(|p| p.values().next()) {
            return Ty::Map(Box::new(convert(p)));
        }
        if o.get("additionalProperties") == Some(&Value::Bool(false)) {
            return Ty::Object(Object { fields: Vec::new(), extra: None });
        }
        return Ty::Map(Box::new(Ty::Unknown));
    };
    let fields = props
        .iter()
        .map(|(name, s)| Field {
            name: name.clone(),
            ty: convert(s),
            required: required.contains(&name.as_str()),
            doc: description(s),
        })
        .collect();
    Ty::Object(Object { fields, extra: extra.map(Box::new) })
}
