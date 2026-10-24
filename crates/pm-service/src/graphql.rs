//! GraphQL: read a schema from an introspection result (pasted, recorded,
//! or fetched through the policy gate) and list its operations with
//! example requests.

use pm_policy::{Actor, Tier};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Authorization, Result, Service, ServiceError};

pub const GRAPHQL_SETTING: &str = "graphql_import";

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GraphQlImportRequest {
    /// The GraphQL endpoint, e.g. https://app.example.com/graphql. Needed to
    /// fetch, and to build example requests.
    pub url: Option<String>,
    /// An introspection result as JSON text…
    pub schema: Option<String>,
    /// …or a recorded exchange whose response is one…
    pub exchange_id: Option<i64>,
    /// …or send the introspection query to `url` (through the policy gate).
    pub fetch: bool,
    pub identity: Option<String>,
    pub approval_id: Option<String>,
}

/// An operation with a ready-to-send example request.
#[derive(Debug, Clone, Serialize)]
pub struct GraphQlOperation {
    #[serde(flatten)]
    pub op: pm_graphql::Operation,
    /// HTTP/1.1 request for `url`, when the endpoint is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub example_request: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GraphQlImportResult {
    Imported {
        url: Option<String>,
        query_type: Option<String>,
        mutation_type: Option<String>,
        types: usize,
        operations: Vec<GraphQlOperation>,
        truncated: usize,
        /// The exchange that fetched the schema, if one was sent.
        #[serde(skip_serializing_if = "Option::is_none")]
        exchange_id: Option<i64>,
    },
    PendingApproval {
        approval_id: String,
        summary: String,
        reasons: Vec<String>,
    },
    Denied {
        reasons: Vec<String>,
    },
}

fn decoded_body(resp: &[u8]) -> Result<String> {
    let (head, body) = pm_http::split_message(resp);
    let head = pm_http::parse_response_head(head).map_err(|e| ServiceError::Invalid(e.to_string()))?;
    Ok(String::from_utf8_lossy(&pm_ai::body::decode(&head.headers, body).bytes).into_owned())
}

impl Service {
    pub async fn graphql_import(&self, actor: &Actor, req: GraphQlImportRequest) -> Result<GraphQlImportResult> {
        let mut url = req.url.clone();
        let mut exchange_id = None;
        let text = match (&req.schema, req.exchange_id, req.fetch) {
            (Some(t), None, false) => t.clone(),
            (None, Some(id), false) => {
                let ex = self
                    .store
                    .lock()
                    .get_exchange(id)?
                    .ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
                let resp =
                    ex.response.ok_or_else(|| ServiceError::Invalid(format!("exchange {id} has no response")))?;
                let s = &ex.summary;
                if url.is_none() {
                    let path = s.path.split('?').next().unwrap_or("/");
                    url = Some(pm_core::url(&s.scheme, &s.host, s.port, path));
                }
                decoded_body(&resp)?
            }
            (None, None, true) => {
                let target = url.as_deref().ok_or_else(|| ServiceError::Invalid("fetch needs url".into()))?;
                let endpoint = crate::replay::parse_url_endpoint(target)?;
                let parsed = url::Url::parse(target).map_err(|e| ServiceError::Invalid(e.to_string()))?;
                let mut path = parsed.path().to_string();
                if let Some(q) = parsed.query() {
                    path = format!("{path}?{q}");
                }
                let host = pm_core::authority(&endpoint.scheme, &endpoint.host, endpoint.port);
                let raw = pm_graphql::request(&host, &path, pm_graphql::INTROSPECTION_QUERY, &json!({}));
                let out = self.outgoing(endpoint, raw.as_bytes(), false)?;
                match self.gate_send_with(
                    actor,
                    "graphql_introspection",
                    &out,
                    req.identity.as_deref(),
                    true,
                    req.approval_id.as_deref(),
                    Some(Tier::ActiveSafe),
                    Value::Null,
                )? {
                    Authorization::Allowed { .. } => {}
                    Authorization::Denied { reasons } => return Ok(GraphQlImportResult::Denied { reasons }),
                    Authorization::PendingApproval { approval_id, summary, reasons } => {
                        return Ok(GraphQlImportResult::PendingApproval {
                            approval_id,
                            summary: format!("send the GraphQL introspection query: {summary}"),
                            reasons,
                        });
                    }
                }
                let (sent, _) = self.send_as(actor, &out, req.identity.as_deref(), true, "graphql").await?;
                exchange_id = Some(sent.exchange_id);
                let resp = sent
                    .response
                    .ok_or_else(|| ServiceError::Invalid(format!("no response: {}", sent.error.unwrap_or_default())))?;
                decoded_body(&resp)?
            }
            _ => return Err(ServiceError::Invalid("give exactly one of schema, exchange_id or fetch".into())),
        };
        if text.len() > 50 * 1024 * 1024 {
            return Err(ServiceError::Invalid("schema larger than 50 MB".into()));
        }
        let doc: Value = serde_json::from_str(&text)
            .map_err(|e| ServiceError::Invalid(format!("the schema is not JSON (an introspection result): {e}")))?;
        let schema = pm_graphql::parse_introspection(&doc).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let target = url.as_deref().and_then(|u| url::Url::parse(u).ok());
        let operations: Vec<GraphQlOperation> = schema
            .operations
            .into_iter()
            .map(|op| {
                let example_request = target.as_ref().map(|u| {
                    let host = pm_core::authority(
                        u.scheme(),
                        u.host_str().unwrap_or_default(),
                        u.port_or_known_default().unwrap_or(80),
                    );
                    let path = match u.query() {
                        Some(q) => format!("{}?{q}", u.path()),
                        None => u.path().to_string(),
                    };
                    pm_graphql::request(&host, &path, &op.document, &op.variables)
                });
                GraphQlOperation { op, example_request }
            })
            .collect();
        let stored = json!({
            "url": url, "query_type": schema.query_type, "mutation_type": schema.mutation_type,
            "types": schema.types, "operations": operations,
        });
        self.store.lock().set_setting(GRAPHQL_SETTING, &stored.to_string())?;
        self.audit(
            &actor.id(),
            "graphql_import",
            json!({ "url": url, "operations": operations.len(), "fetched": exchange_id.is_some() }),
            "ok",
        )?;
        Ok(GraphQlImportResult::Imported {
            url,
            query_type: schema.query_type,
            mutation_type: schema.mutation_type,
            types: schema.types,
            operations,
            truncated: schema.truncated,
            exchange_id,
        })
    }

    /// The last imported GraphQL schema's operations, if any.
    pub fn graphql_get(&self) -> Result<Value> {
        Ok(self
            .store
            .lock()
            .get_setting(GRAPHQL_SETTING)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null))
    }
}
