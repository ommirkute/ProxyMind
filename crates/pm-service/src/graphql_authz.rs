//! Object access over GraphQL: a query that takes an id (`invoice(id: …)`)
//! is asked for an object one test user owns, as its owner, as another
//! test user and anonymously. The other user getting the owner's answer,
//! when an anonymous caller doesn't, is broken object-level authorization
//! (the REST endpoint for the same object may well check ownership).

use pm_policy::{Actor, Tier};
use serde_json::{Value, json};

use crate::auto::ScanLead;
use crate::findings::NewFinding;
use crate::{Authorization, GraphQlImportRequest, GraphQlImportResult, Result, Service};

/// Most queries tried, and objects per query.
const MAX_QUERIES: usize = 6;

/// The single id-like argument of a query (`id`, `invoiceId`, `user_id`), if
/// it has exactly one required argument and that is it.
fn id_arg(op: &pm_graphql::Operation) -> Option<&pm_graphql::Arg> {
    let required: Vec<&pm_graphql::Arg> = op.args.iter().filter(|a| a.required).collect();
    let [arg] = required.as_slice() else { return None };
    let n = arg.name.to_ascii_lowercase();
    (n == "id" || n.ends_with("id") || n.ends_with("_id")).then_some(*arg)
}

/// The id as the argument's type wants it: a number for Int, else a string.
fn id_value(arg: &pm_graphql::Arg, id: &str) -> Option<Value> {
    let ty = arg.ty.trim_end_matches('!');
    match ty {
        "Int" => id.parse::<i64>().ok().map(Value::from),
        "ID" | "String" => Some(Value::from(id)),
        _ => None,
    }
}

/// `data.<field>` of a GraphQL response body, when it is a non-empty object or list.
fn answer(body: &str, field: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(body).ok()?;
    let a = v.get("data")?.get(field)?.clone();
    let empty = a.is_null() || a.as_object().is_some_and(|o| o.is_empty()) || a.as_array().is_some_and(Vec::is_empty);
    (!empty).then_some(a)
}

impl Service {
    /// Finds the GraphQL endpoint in history (a recorded POST that looks like
    /// GraphQL and worked), reads its schema, and tries each id-taking query
    /// on objects the app model knows owners for. Returns the leaks, each
    /// recorded as a suspected IDOR finding.
    pub async fn graphql_object_access(&self, actor: &Actor) -> Result<Vec<ScanLead>> {
        let Some(url) = self.graphql_endpoint()? else { return Ok(Vec::new()) };
        let ids = self.identity_list()?;
        let users: Vec<String> = ids.iter().map(|i| i.name.clone()).collect();
        if users.len() < 2 {
            return Ok(Vec::new());
        }
        let req = GraphQlImportRequest { url: Some(url.clone()), fetch: true, ..Default::default() };
        let ops = match self.graphql_import(actor, req).await {
            Ok(GraphQlImportResult::Imported { operations, .. }) => operations,
            _ => return Ok(Vec::new()),
        };
        let model = self.model()?;
        let endpoint = crate::replay::parse_url_endpoint(&url)?;
        let mut leads = Vec::new();
        let mut gated = false;
        let queries = ops.iter().filter(|o| o.op.kind == "query").filter_map(|o| Some((o, id_arg(&o.op)?)));
        for (op, arg) in queries.take(MAX_QUERIES) {
            let Some(raw_example) = &op.example_request else { continue };
            // The returned type names the object type (`Invoice` for invoice(id)).
            let returns = op.op.returns.trim_matches(|c| c == '[' || c == ']' || c == '!').to_ascii_lowercase();
            let Some(obj) = model.objects.iter().find(|o| {
                o.object_type.eq_ignore_ascii_case(&returns)
                    && o.owner.as_deref().is_some_and(|w| users.iter().any(|u| u == w))
            }) else {
                continue;
            };
            let owner = obj.owner.clone().unwrap_or_default();
            let Some(other) = users.iter().find(|u| **u != owner && !is_admin(&ids, u)) else { continue };
            let Some(value) = id_value(arg, &obj.id) else { continue };
            let mut vars = op.op.variables.clone();
            if !vars.is_object() {
                vars = json!({});
            }
            vars[&arg.name] = value;
            let body = pm_graphql::body(&op.op.document, &vars, None);
            let Some((head, _)) = raw_example.split_once("\r\n\r\n") else { continue };
            let head: Vec<&str> =
                head.lines().filter(|l| !l.to_ascii_lowercase().starts_with("content-length:")).collect();
            let raw = format!("{}\r\nContent-Length: {}\r\n\r\n{body}", head.join("\r\n"), body.len());
            let out = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
            if !gated {
                let extra = json!({ "graphql_object_access": url });
                match self.gate_send_with(
                    actor,
                    "graphql_object_access",
                    &out,
                    None,
                    true,
                    None,
                    Some(Tier::ActiveSafe),
                    extra,
                )? {
                    Authorization::Allowed { .. } => gated = true,
                    _ => return Ok(leads),
                }
            }
            let ask = |who: Option<String>| {
                let out = out.clone();
                async move {
                    let (s, _) = self.send_as(actor, &out, who.as_deref(), true, "authz").await?;
                    let text = s.response.as_deref().map(|r| {
                        let (_, b) = pm_http::split_message(r);
                        String::from_utf8_lossy(&pm_http::decode_chunked(b).unwrap_or_else(|| b.to_vec())).into_owned()
                    });
                    Ok::<_, crate::ServiceError>((s.exchange_id, text.unwrap_or_default()))
                }
            };
            let (_, as_owner) = ask(Some(owner.clone())).await?;
            let Some(owned) = answer(&as_owner, &op.op.name) else { continue };
            let (leak_id, as_other) = ask(Some(other.clone())).await?;
            let (_, as_anon) = ask(Some(pm_identity::ANONYMOUS.to_string())).await?;
            // Public data (anonymous callers get it too) is not a leak.
            if answer(&as_other, &op.op.name).as_ref() != Some(&owned) || answer(&as_anon, &op.op.name).is_some() {
                continue;
            }
            let evidence = format!(
                "{other} asked for {owner}'s {} {} with the {} query and got the same answer as {owner}; an anonymous \
                 caller did not",
                obj.object_type, obj.id, op.op.name
            );
            let finding = self.finding_create(
                actor,
                NewFinding {
                    title: format!("GraphQL {}({}) returns other users' {}", op.op.name, arg.name, obj.object_type),
                    vuln_class: "idor".into(),
                    severity: "high".into(),
                    description: format!(
                        "{evidence}. Check the resolver's ownership rule (the REST endpoint for this object may differ). \
                         Found by the automatic pass; not proven yet."
                    ),
                    url: Some(url.clone()),
                    evidence: vec![leak_id],
                    hypothesis_id: None,
                },
            )?;
            leads.push(ScanLead {
                operation: format!("POST {url} ({})", op.op.name),
                check: "graphql_object_access".into(),
                finding_id: finding["id"].as_i64().unwrap_or_default(),
                evidence,
            });
        }
        Ok(leads)
    }

    /// The URL of a GraphQL endpoint seen in history: a POST that looks like
    /// GraphQL and was answered with a 2xx.
    fn graphql_endpoint(&self) -> Result<Option<String>> {
        let rows = self.store.lock().search_exchanges(&pm_store::HistoryFilter {
            method: Some("POST".into()),
            limit: Some(2000),
            ..Default::default()
        })?;
        for row in rows.iter().filter(|r| r.status.is_some_and(|s| (200..300).contains(&s))) {
            let Ok(ex) = self.exchange_raw(row.id) else { continue };
            let (_, body) = pm_http::split_message(&ex.request);
            let path = row.path.split('?').next().unwrap_or("/");
            if pm_graphql::looks_like_graphql(path, body) {
                return Ok(Some(pm_core::url(&row.scheme, &row.host, row.port, path)));
            }
        }
        Ok(None)
    }
}

fn is_admin(ids: &[crate::IdentityInfo], name: &str) -> bool {
    ids.iter().any(|i| i.name == name && i.role.to_ascii_lowercase().contains("admin"))
}
