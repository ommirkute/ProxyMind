//! The live application model: what the app *is*, built from its traffic.
//!
//! - **Operations**: `GET /api/orders/{id}` instead of thousands of URLs.
//! - **Objects**: `Order 1001`, found in paths and JSON bodies.
//! - **Ownership**: which identity an object belongs to, from list responses
//!   ("these are my orders"), creation responses, or first access.
//!
//! The model lets agents ask questions such as "which operations take an
//! object id that belongs to another user?", which is exactly where
//! access-control bugs live.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;
use serde_json::Value;

/// One recorded exchange, as the model needs it.
#[derive(Debug, Clone)]
pub struct Observation<'a> {
    pub exchange_id: i64,
    pub method: &'a str,
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    /// Path including query.
    pub path: &'a str,
    pub status: Option<u16>,
    /// Identity the request was made as, if known.
    pub identity: Option<&'a str>,
    pub request: &'a [u8],
    pub response: Option<&'a [u8]>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Operation {
    /// e.g. `GET http://shop:8080/api/orders/{id}`
    pub key: String,
    pub method: String,
    pub origin: String,
    pub template: String,
    /// read_item, read_collection, create, update, delete, action
    pub kind: String,
    /// Object type addressed by the `{id}` in the path, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_type: Option<String>,
    pub path_params: Vec<String>,
    pub query_params: Vec<String>,
    pub body_params: Vec<String>,
    pub count: usize,
    pub statuses: BTreeMap<u16, usize>,
    pub identities: BTreeSet<String>,
    /// True if any request carried cookies or an Authorization header.
    pub authenticated: bool,
    /// Exchange ids, most recent last (up to 20).
    pub examples: Vec<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Object {
    pub object_type: String,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// listed (in the owner's collection), created (by the owner), first_seen
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_source: Option<String>,
    /// Identities that successfully read this object directly.
    pub accessed_by: BTreeSet<String>,
    pub seen_in: Vec<i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AppModel {
    pub operations: Vec<Operation>,
    pub objects: Vec<Object>,
}

/// A suggested authorization test: replay `exchange_id` (made by `owner`)
/// as each of `try_as`.
#[derive(Debug, Clone, Serialize)]
pub struct AuthzCandidate {
    pub operation: String,
    pub object: String,
    pub owner: String,
    pub exchange_id: i64,
    pub try_as: Vec<String>,
    pub reason: String,
}

/// Classifies one path segment as an identifier, returning its placeholder.
pub fn classify_segment(seg: &str) -> Option<&'static str> {
    if seg.is_empty() {
        return None;
    }
    if seg.chars().all(|c| c.is_ascii_digit()) {
        return Some("{id}");
    }
    let hexish = |s: &str| s.chars().all(|c| c.is_ascii_hexdigit());
    let parts: Vec<&str> = seg.split('-').collect();
    if parts.len() == 5 && [8, 4, 4, 4, 12].iter().zip(&parts).all(|(n, p)| p.len() == *n && hexish(p)) {
        return Some("{uuid}");
    }
    if seg.len() >= 16 && hexish(seg) {
        return Some("{hex}");
    }
    if seg.contains('@') && seg.contains('.') {
        return Some("{email}");
    }
    let digits = seg.chars().filter(char::is_ascii_digit).count();
    if seg.len() >= 20 && digits >= 3 && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Some("{token}");
    }
    None
}

/// `/api/orders/1001?x=1` → (`/api/orders/{id}`, [("id", "1001", Some("orders"))]).
pub fn template_path(path: &str) -> (String, Vec<(String, String, Option<String>)>) {
    template_path_with(path, |_, _| None)
}

/// Version and prefix segments that name no collection (`/api/v1/books/…`).
fn is_version_like(seg: &str) -> bool {
    let s = seg.to_ascii_lowercase();
    matches!(s.as_str(), "api" | "rest")
        || (s.len() >= 2 && s.starts_with('v') && s[1..].chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// Like [`template_path`], but `hint(prefix, segment)` can name more
/// segments as identifiers: words and names (`/books/v1/my-book`) that the
/// app itself uses as identifiers. `prefix` is the basic template of the
/// path before the segment.
pub fn template_path_with(
    path: &str,
    hint: impl Fn(&str, &str) -> Option<String>,
) -> (String, Vec<(String, String, Option<String>)>) {
    let path = path.split(['?', '#']).next().unwrap_or("/");
    let segs: Vec<&str> = path.split('/').collect();
    let mut out: Vec<String> = Vec::with_capacity(segs.len());
    let mut basic: Vec<String> = Vec::with_capacity(segs.len());
    let mut params = Vec::new();
    for (i, seg) in segs.iter().enumerate() {
        let placeholder = match classify_segment(seg) {
            Some(ph) => Some(ph.to_string()),
            None if !seg.is_empty() && i > 0 => hint(&basic.join("/"), seg).map(|f| format!("{{{f}}}")),
            None => None,
        };
        basic.push(classify_segment(seg).map_or_else(|| (*seg).to_string(), str::to_string));
        match placeholder {
            Some(ph) => {
                // The collection: the nearest earlier literal that isn't a version.
                let prev =
                    out.iter().rev().find(|p| !p.is_empty() && !p.starts_with('{') && !is_version_like(p)).cloned();
                params.push((ph.trim_matches(['{', '}']).to_string(), (*seg).to_string(), prev));
                out.push(ph);
            }
            None => out.push((*seg).to_string()),
        }
    }
    (out.join("/"), params)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = (b[i] == b'%' && i + 2 < b.len())
            .then(|| std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok()))
            .flatten();
        match hex {
            Some(v) => {
                out.push(v);
                i += 3;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// JSON fields that hold an identifier of the object they're in.
fn is_id_field(key: &str) -> bool {
    let l = key.to_ascii_lowercase();
    l == "id"
        || l == "uuid"
        || l.ends_with("_id")
        || (key.ends_with("Id") && key.len() > 2)
        || matches!(
            l.as_str(),
            "slug" | "username" | "user_name" | "login" | "handle" | "name" | "title" | "key" | "code" | "sku"
        )
        || ["_name", "_title", "_slug", "_key", "_code"].iter().any(|s| l.ends_with(s))
        || ["Name", "Title", "Slug"].iter().any(|s| key.ends_with(s) && key.len() > s.len())
}

/// Identifier values in a JSON document: (value, field), a few levels deep.
fn id_values(v: &Value, depth: usize, out: &mut Vec<(String, String)>) {
    if depth > 4 || out.len() > 2000 {
        return;
    }
    match v {
        Value::Object(o) => {
            for (k, x) in o {
                if let Value::String(s) = x
                    && is_id_field(k)
                    && !s.is_empty()
                    && s.len() <= 128
                    && !s.contains('/')
                {
                    out.push((s.clone(), k.clone()));
                }
                id_values(x, depth + 1, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| id_values(x, depth + 1, out)),
        _ => {}
    }
}

/// A placeholder name from a field name (`book_title`, `userId`), else `key`.
fn placeholder_name(field: &str) -> String {
    if !field.is_empty() && field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        field.to_string()
    } else {
        "key".into()
    }
}

/// Which words in paths are identifiers, learned from the app's own JSON: a
/// value that a collection lists, or that is sent to it when creating
/// (`GET /books/v1` lists `"book_title": "my-book"`, so `/books/v1/my-book`
/// addresses a book). Keyed by the collection, so a value listed under one
/// path never turns a literal elsewhere (`/api/admin/…`) into a parameter.
#[derive(Debug, Default)]
pub struct IdHints {
    /// (origin, collection template) → value → field.
    by_collection: HashMap<(String, String), HashMap<String, String>>,
}

impl IdHints {
    pub fn learn(observations: &[Observation<'_>]) -> Self {
        let mut h = Self::default();
        for o in observations {
            let origin = pm_core::url(o.scheme, o.host, o.port, "");
            let (template, _) = template_path(o.path);
            let mut vals = Vec::new();
            if let Some(resp) = o.response.filter(|_| o.status.is_some_and(|s| (200..300).contains(&s)))
                && let Some(j) = body_json(resp)
            {
                id_values(&j, 0, &mut vals);
            }
            if matches!(o.method.to_ascii_uppercase().as_str(), "POST" | "PUT")
                && let Some(j) = body_json(o.request)
            {
                id_values(&j, 0, &mut vals);
            }
            if vals.is_empty() {
                continue;
            }
            let entry = h.by_collection.entry((origin, template.trim_end_matches('/').to_string())).or_default();
            for (v, f) in vals {
                entry.entry(v).or_insert(f);
            }
        }
        h
    }

    /// The field naming `seg` as an identifier under `prefix`, if the app did.
    pub fn lookup(&self, origin: &str, prefix: &str, seg: &str) -> Option<String> {
        let key = (origin.to_string(), prefix.trim_end_matches('/').to_string());
        self.by_collection.get(&key)?.get(&percent_decode(seg)).map(|f| placeholder_name(f))
    }
}

/// The last path segment and the field naming it, when the exchange's own
/// response is that object (`GET /users/v1/name1` → `{"username": "name1"}`).
fn self_hint(o: &Observation<'_>) -> Option<(String, String)> {
    let path = o.path.split(['?', '#']).next().unwrap_or("/");
    let last = path.trim_end_matches('/').rsplit('/').next().filter(|s| !s.is_empty())?;
    if classify_segment(last).is_some() {
        return None;
    }
    let decoded = percent_decode(last);
    let resp = o.response.filter(|_| o.status.is_some_and(|s| (200..300).contains(&s)))?;
    let Value::Object(m) = body_json(resp)? else { return None };
    m.iter()
        .find(|(k, x)| is_id_field(k) && x.as_str() == Some(decoded.as_str()))
        .map(|(k, _)| (last.to_string(), placeholder_name(k)))
}

/// `orders` → `Order`, `categories` → `Category`, `addresses` → `Address`.
pub fn type_name(collection: &str) -> String {
    let s = collection.to_ascii_lowercase();
    let singular = if let Some(stem) = s.strip_suffix("ies") {
        format!("{stem}y")
    } else if s.ends_with("sses") || s.ends_with("xes") || s.ends_with("ches") || s.ends_with("shes") {
        s[..s.len() - 2].to_string()
    } else if let Some(stem) = s.strip_suffix('s').filter(|_| !["ss", "us", "is"].iter().any(|e| s.ends_with(e))) {
        stem.to_string()
    } else {
        s.clone()
    };
    let mut c = singular.chars();
    match c.next() {
        Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
        None => s,
    }
}

fn kind(method: &str, template: &str) -> &'static str {
    let item = template.ends_with('}');
    match method {
        "GET" | "HEAD" if item => "read_item",
        "GET" | "HEAD" => "read_collection",
        "POST" => "create",
        "PUT" | "PATCH" => "update",
        "DELETE" => "delete",
        _ => "action",
    }
}

fn body_json(raw: &[u8]) -> Option<Value> {
    let (head, body) = pm_http::split_message(raw);
    let headers = pm_http::parse_response_head(head)
        .map(|h| h.headers)
        .or_else(|_| pm_http::parse_request_head(head).map(|h| h.headers))
        .ok()?;
    let d = pm_ai::body::decode(&headers, body);
    if d.kind != pm_ai::body::Kind::Json {
        return None;
    }
    serde_json::from_slice(&d.bytes).ok()
}

fn request_param_names(raw: &[u8]) -> Vec<String> {
    let (head, body) = pm_http::split_message(raw);
    if body.is_empty() {
        return Vec::new();
    }
    if let Some(Value::Object(o)) = body_json(raw) {
        return o.keys().cloned().collect();
    }
    let ct = pm_http::parse_request_head(head)
        .ok()
        .and_then(|h| pm_http::header(&h.headers, "content-type").map(|v| String::from_utf8_lossy(v).to_lowercase()));
    if ct.is_some_and(|c| c.contains("x-www-form-urlencoded")) {
        return String::from_utf8_lossy(body)
            .split('&')
            .filter_map(|p| p.split_once('=').map(|(k, _)| k.to_string()))
            .collect();
    }
    Vec::new()
}

fn has_credentials(raw: &[u8]) -> bool {
    let (head, _) = pm_http::split_message(raw);
    pm_http::parse_request_head(head).is_ok_and(|h| {
        h.headers.iter().any(|x| x.name.eq_ignore_ascii_case("cookie") || x.name.eq_ignore_ascii_case("authorization"))
    })
}

/// An object's identifier: `id`, else another identifier field
/// (`*_id` first, then `book_title`, `username`, `slug`…).
fn item_id(item: &Value) -> Option<String> {
    let as_id = |i: &Value| i.as_i64().map(|n| n.to_string()).or_else(|| i.as_str().map(String::from));
    if let Some(id) = item.get("id").and_then(as_id) {
        return Some(id);
    }
    let o = item.as_object()?;
    let rank = |k: &str| {
        let l = k.to_ascii_lowercase();
        usize::from(!(l.ends_with("_id") || (k.ends_with("Id") && k.len() > 2) || l == "uuid"))
    };
    let mut keys: Vec<&String> = o.keys().filter(|k| is_id_field(k) && o[k.as_str()].is_string()).collect();
    keys.sort_by_key(|k| rank(k));
    keys.first().and_then(|k| as_id(&o[k.as_str()]))
}

/// Whether list items name two or more different owners: then the list is
/// everyone's objects, not the caller's.
fn mixed_owners(v: &Value) -> bool {
    const OWNER: &[&str] = &["user", "owner", "author", "created_by", "user_id", "owner_id", "userid", "creator"];
    let items: Vec<&Value> = match v {
        Value::Array(a) => a.iter().collect(),
        Value::Object(o) => o.values().filter_map(Value::as_array).flatten().collect(),
        _ => Vec::new(),
    };
    let mut seen = BTreeSet::new();
    for it in items {
        if let Some(o) = it.as_object() {
            for (k, x) in o {
                if OWNER.contains(&k.to_ascii_lowercase().as_str()) {
                    seen.insert(x.to_string());
                }
            }
        }
    }
    seen.len() >= 2
}

/// Object ids listed in a collection response: `{"orders":[{"id":1}]}` or
/// `[{"id":1}]`, typed by the collection name or the path's last segment.
fn listed_ids(v: &Value, fallback_type: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut take = |arr: &Vec<Value>, ty: &str| {
        for item in arr {
            if let Some(id) = item_id(item) {
                out.push((ty.to_string(), id));
            }
        }
    };
    match v {
        Value::Array(a) => take(a, fallback_type),
        Value::Object(o) => {
            for (k, x) in o {
                if let Value::Array(a) = x {
                    take(a, &type_name(k));
                }
            }
        }
        _ => {}
    }
    out
}

/// Builds the model from observations (any order; sorted by id internally).
pub fn build(observations: &[Observation<'_>]) -> AppModel {
    let mut obs: Vec<&Observation> = observations.iter().collect();
    obs.sort_by_key(|o| o.exchange_id);
    let hints = IdHints::learn(observations);

    let mut ops: BTreeMap<String, Operation> = BTreeMap::new();
    let mut objects: BTreeMap<(String, String), Object> = BTreeMap::new();

    let mut touch = |ty: &str, id: &str, ex: i64| -> (String, String) {
        let key = (ty.to_string(), id.to_string());
        let o = objects.entry(key.clone()).or_insert_with(|| Object {
            object_type: ty.into(),
            id: id.into(),
            owner: None,
            owner_source: None,
            accessed_by: BTreeSet::new(),
            seen_in: Vec::new(),
        });
        if o.seen_in.len() < 20 && !o.seen_in.contains(&ex) {
            o.seen_in.push(ex);
        }
        key
    };
    // Ownership claims, strongest first: listed > created > first_seen.
    let mut claims: Vec<((String, String), String, &'static str, i64)> = Vec::new();

    for o in &obs {
        let method = o.method.to_ascii_uppercase();
        let origin = pm_core::url(o.scheme, o.host, o.port, "");
        let own = self_hint(o);
        let (template, params) = template_path_with(o.path, |prefix, seg| {
            hints
                .lookup(&origin, prefix, seg)
                .or_else(|| own.as_ref().filter(|(s, _)| s == seg).map(|(_, f)| f.clone()))
        });
        let key = format!("{method} {origin}{template}");
        let object_type = params.last().and_then(|(_, _, prev)| prev.as_deref().map(type_name));
        let op = ops.entry(key.clone()).or_insert_with(|| Operation {
            key: key.clone(),
            method: method.clone(),
            origin: origin.clone(),
            template: template.clone(),
            kind: kind(&method, &template).into(),
            object_type: object_type.clone(),
            path_params: params.iter().map(|p| p.0.clone()).collect(),
            query_params: Vec::new(),
            body_params: Vec::new(),
            count: 0,
            statuses: BTreeMap::new(),
            identities: BTreeSet::new(),
            authenticated: false,
            examples: Vec::new(),
        });
        op.count += 1;
        if let Some(s) = o.status {
            *op.statuses.entry(s).or_insert(0) += 1;
        }
        if let Some(i) = o.identity {
            op.identities.insert(i.to_string());
        }
        op.authenticated |= has_credentials(o.request);
        op.examples.push(o.exchange_id);
        if op.examples.len() > 20 {
            op.examples.remove(0);
        }
        if let Some(q) = o.path.split_once('?').map(|x| x.1) {
            for name in q.split('&').filter_map(|p| p.split('=').next()).filter(|n| !n.is_empty()) {
                if !op.query_params.iter().any(|x| x == name) {
                    op.query_params.push(name.to_string());
                }
            }
        }
        for name in request_param_names(o.request) {
            if !op.body_params.contains(&name) {
                op.body_params.push(name);
            }
        }

        let ok = o.status.is_some_and(|s| (200..300).contains(&s));
        // Objects addressed in the path.
        for (_, value, prev) in &params {
            if let Some(prev) = prev {
                let k = touch(&type_name(prev), value, o.exchange_id);
                if ok && let Some(i) = o.identity {
                    claims.push((k, i.to_string(), "first_seen", o.exchange_id));
                }
            }
        }
        let Some(resp) = o.response.filter(|_| ok) else { continue };
        let Some(json) = body_json(resp) else { continue };
        // Objects listed in a collection response belong to the caller, except
        // in admin views, which list everyone's objects.
        let admin_view = ["admin", "manage", "internal"].iter().any(|w| template.to_ascii_lowercase().contains(w));
        // A list of everyone's objects (items name different owners) says nothing about the caller.
        if template.ends_with(|c: char| c != '}') && method == "GET" && !admin_view && !mixed_owners(&json) {
            let last = template.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            for (ty, id) in listed_ids(&json, &type_name(last)) {
                let k = touch(&ty, &id, o.exchange_id);
                if let Some(i) = o.identity {
                    claims.push((k, i.to_string(), "listed", o.exchange_id));
                }
            }
        }
        // A created object belongs to its creator.
        if method == "POST"
            && let Some(id) =
                json.get("id").and_then(|i| i.as_i64().map(|n| n.to_string()).or_else(|| i.as_str().map(String::from)))
        {
            let last = template.trim_end_matches('/').rsplit('/').next().unwrap_or("");
            let k = touch(&type_name(last), &id, o.exchange_id);
            if let Some(i) = o.identity {
                claims.push((k, i.to_string(), "created", o.exchange_id));
            }
        }
    }

    // Accesses and ownership.
    let rank = |s: &str| match s {
        "listed" => 3,
        "created" => 2,
        _ => 1,
    };
    for (k, who, source, _) in &claims {
        let Some(obj) = objects.get_mut(k) else { continue };
        if *source == "first_seen" {
            obj.accessed_by.insert(who.clone());
        }
        let better = match &obj.owner_source {
            None => true,
            Some(cur) => rank(source) > rank(cur),
        };
        if better {
            obj.owner = Some(who.clone());
            obj.owner_source = Some((*source).into());
        }
    }

    AppModel { operations: ops.into_values().collect(), objects: objects.into_values().collect() }
}

impl AppModel {
    /// Read operations on objects whose owner is known, paired with other
    /// identities that should be tried. These are the places where
    /// IDOR/BOLA bugs live.
    pub fn authz_candidates(&self, identities: &[String]) -> Vec<AuthzCandidate> {
        let mut out = Vec::new();
        for op in self.operations.iter().filter(|o| o.kind == "read_item") {
            let Some(ty) = &op.object_type else { continue };
            for obj in self.objects.iter().filter(|o| &o.object_type == ty) {
                let Some(owner) = &obj.owner else { continue };
                // An exchange where the owner read this object through this operation.
                let Some(&ex) =
                    op.examples.iter().rev().find(|e| obj.seen_in.contains(e) && obj.accessed_by.contains(owner))
                else {
                    continue;
                };
                let try_as: Vec<String> = identities.iter().filter(|i| *i != owner).cloned().collect();
                if try_as.is_empty() {
                    continue;
                }
                out.push(AuthzCandidate {
                    operation: op.key.clone(),
                    object: format!("{ty} {}", obj.id),
                    owner: owner.clone(),
                    exchange_id: ex,
                    try_as,
                    reason: format!(
                        "{ty} {} belongs to {owner} ({})",
                        obj.id,
                        obj.owner_source.clone().unwrap_or_default()
                    ),
                });
            }
        }
        // Admin-looking operations used by a privileged identity should be
        // tried by everyone else (function-level authorization).
        for op in
            self.operations.iter().filter(|o| o.template.to_ascii_lowercase().contains("admin") && o.method == "GET")
        {
            for owner in &op.identities {
                if let Some(&ex) = op.examples.last() {
                    let try_as: Vec<String> = identities.iter().filter(|i| *i != owner).cloned().collect();
                    if !try_as.is_empty() {
                        out.push(AuthzCandidate {
                            operation: op.key.clone(),
                            object: "(function)".into(),
                            owner: owner.clone(),
                            exchange_id: ex,
                            try_as,
                            reason: "admin-looking operation: check other roles are refused".into(),
                        });
                    }
                    break;
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_and_types() {
        assert_eq!(template_path("/api/orders/1001?x=1").0, "/api/orders/{id}");
        assert_eq!(template_path("/u/550e8400-e29b-41d4-a716-446655440000/files").0, "/u/{uuid}/files");
        assert_eq!(template_path("/api/v1/users").0, "/api/v1/users");
        assert_eq!(template_path("/static/app.3f9a.js").0, "/static/app.3f9a.js");
        assert_eq!(type_name("orders"), "Order");
        assert_eq!(type_name("categories"), "Category");
        assert_eq!(type_name("addresses"), "Address");
        assert_eq!(type_name("status"), "Status");
    }

    fn ob<'a>(id: i64, method: &'a str, path: &'a str, who: Option<&'a str>, resp: &'a [u8]) -> Observation<'a> {
        Observation {
            exchange_id: id,
            method,
            scheme: "http",
            host: "shop",
            port: 80,
            path,
            status: Some(200),
            identity: who,
            request: b"GET / HTTP/1.1\r\nCookie: s=1\r\n\r\n",
            response: Some(resp),
        }
    }

    #[test]
    fn names_the_app_uses_as_ids_become_parameters() {
        // VAmPI-style: books and users addressed by title and name, a list of
        // everyone's books, a public user profile.
        let j = |body: &'static str| -> Vec<u8> {
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}").into_bytes()
        };
        let books = j(r#"{"Books":[{"book_title":"b-one","user":"alice"},{"book_title":"b-two","user":"bob"}]}"#);
        let book1 = j(r#"{"book_title":"b-one","owner":"alice","secret":"s1"}"#);
        let book2 = j(r#"{"book_title":"b-two","owner":"bob","secret":"s2"}"#);
        let users = j(r#"{"users":[{"username":"alice"},{"username":"bob"}]}"#);
        let alice = j(r#"{"username":"alice","email":"a@x"}"#);
        let me = j(r#"{"username":"alice"}"#);
        let admin = j(r#"{"users":[]}"#);
        let obs = vec![
            ob(1, "GET", "/books/v1", Some("alice"), &books),
            ob(2, "GET", "/books/v1/b-one", Some("alice"), &book1),
            ob(3, "GET", "/books/v1", Some("bob"), &books),
            ob(4, "GET", "/books/v1/b-two", Some("bob"), &book2),
            ob(5, "GET", "/users/v1", None, &users),
            ob(6, "GET", "/users/v1/alice", Some("alice"), &alice),
            ob(7, "GET", "/users/v1/_debug", None, &users),
            ob(8, "GET", "/api/me", Some("alice"), &me),
            ob(9, "GET", "/api/admin/users", Some("alice"), &admin),
        ];
        let m = build(&obs);
        let templates: Vec<&str> = m.operations.iter().map(|o| o.template.as_str()).collect();
        for t in ["/books/v1/{book_title}", "/users/v1/{username}", "/users/v1/_debug", "/api/me", "/api/admin/users"] {
            assert!(templates.contains(&t), "{t} in {templates:?}");
        }
        let op = m.operations.iter().find(|o| o.template == "/books/v1/{book_title}").unwrap();
        assert_eq!(op.object_type.as_deref(), Some("Book"), "the version segment is skipped");
        // The list names two owners, so it doesn't make alice own b-two.
        let b1 = m.objects.iter().find(|o| o.object_type == "Book" && o.id == "b-one").unwrap();
        let b2 = m.objects.iter().find(|o| o.object_type == "Book" && o.id == "b-two").unwrap();
        assert_eq!((b1.owner.as_deref(), b2.owner.as_deref()), (Some("alice"), Some("bob")));
        let cands = m.authz_candidates(&["alice".into(), "bob".into()]);
        assert!(cands.iter().any(|c| c.object == "Book b-one" && c.try_as == ["bob"]), "{cands:?}");
        assert!(cands.iter().any(|c| c.object == "Book b-two" && c.try_as == ["alice"]));
        // Percent-encoded names match too.
        let hints = IdHints::learn(&obs);
        assert_eq!(hints.lookup("http://shop", "/books/v1", "b%2Done").as_deref(), Some("book_title"));
        assert_eq!(hints.lookup("http://shop", "/api", "admin"), None);
    }

    #[test]
    fn builds_operations_objects_and_ownership() {
        let list_a =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"orders\":[{\"id\":1001},{\"id\":1002}]}";
        let list_b = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"orders\":[{\"id\":2001}]}";
        let item = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1001}";
        let obs = vec![
            ob(1, "GET", "/api/orders", Some("alice"), list_a),
            ob(2, "GET", "/api/orders", Some("bob"), list_b),
            ob(3, "GET", "/api/orders/1001", Some("alice"), item),
            ob(4, "GET", "/api/orders/2001", Some("bob"), item),
        ];
        let m = build(&obs);
        assert_eq!(m.operations.len(), 2);
        let item_op = m.operations.iter().find(|o| o.template == "/api/orders/{id}").unwrap();
        assert_eq!((item_op.kind.as_str(), item_op.object_type.as_deref()), ("read_item", Some("Order")));
        let o1001 = m.objects.iter().find(|o| o.id == "1001").unwrap();
        assert_eq!((o1001.owner.as_deref(), o1001.owner_source.as_deref()), (Some("alice"), Some("listed")));
        let cands = m.authz_candidates(&["alice".into(), "bob".into()]);
        let c = cands.iter().find(|c| c.object == "Order 1001").unwrap();
        assert_eq!((c.owner.as_str(), c.exchange_id, c.try_as.clone()), ("alice", 3, vec!["bob".to_string()]));
        assert!(cands.iter().any(|c| c.object == "Order 2001" && c.owner == "bob"));
    }
}
