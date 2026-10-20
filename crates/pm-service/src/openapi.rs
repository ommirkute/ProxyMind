//! Importing an OpenAPI / Swagger description: list the operations with
//! example requests, keep the import in the project, and optionally send
//! the safe (GET) examples so history and the app model learn them.

use pm_policy::{Actor, Target, Tier};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Authorization, Result, Service, ServiceError};

pub const OPENAPI_SETTING: &str = "openapi_import";

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OpenApiImportRequest {
    /// The spec text (JSON or YAML)…
    pub spec: Option<String>,
    /// …or a recorded exchange whose response is the spec (e.g. /openapi.json).
    pub exchange_id: Option<i64>,
    /// scheme://host[:port][/base] when the spec has no absolute server.
    pub base_url: Option<String>,
    /// Send each GET example once (in scope only) so the model learns them.
    pub send_examples: bool,
    pub identity: Option<String>,
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SentExample {
    pub method: String,
    pub path: String,
    pub exchange_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OpenApiImportResult {
    Imported {
        title: String,
        version: String,
        base_url: Option<String>,
        operations: Vec<pm_openapi::Operation>,
        truncated: usize,
        sent: Vec<SentExample>,
        skipped: Vec<String>,
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

impl Service {
    pub async fn openapi_import(&self, actor: &Actor, req: OpenApiImportRequest) -> Result<OpenApiImportResult> {
        let (text, spec_url) = match (&req.spec, req.exchange_id) {
            (Some(t), None) => (t.clone(), None),
            (None, Some(id)) => {
                let ex = self
                    .store
                    .lock()
                    .get_exchange(id)?
                    .ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
                let resp =
                    ex.response.ok_or_else(|| ServiceError::Invalid(format!("exchange {id} has no response")))?;
                let (head, body) = pm_http::split_message(&resp);
                let head = pm_http::parse_response_head(head).map_err(|e| ServiceError::Invalid(e.to_string()))?;
                let decoded = pm_ai::body::decode(&head.headers, body);
                let s = &ex.summary;
                (
                    String::from_utf8_lossy(&decoded.bytes).into_owned(),
                    Some(pm_core::url(&s.scheme, &s.host, s.port, &s.path)),
                )
            }
            _ => return Err(ServiceError::Invalid("give either spec (text) or exchange_id".into())),
        };
        if text.len() > 20 * 1024 * 1024 {
            return Err(ServiceError::Invalid("spec larger than 20 MB".into()));
        }
        let doc: Value = serde_json::from_str(&text)
            .or_else(|_| serde_saphyr::from_str(&text))
            .map_err(|e| ServiceError::Invalid(format!("spec is not JSON or YAML: {e}")))?;
        let base_hint = req.base_url.clone().map(|b| format!("{}/", b.trim_end_matches('/')));
        let spec = pm_openapi::from_value(&doc, spec_url.as_deref().or(base_hint.as_deref()))
            .map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let base_url = req.base_url.clone().or(spec.base_url.clone());
        // The examples' Host header follows the base URL actually used.
        let mut operations = spec.operations.clone();
        if let Some(u) = base_url.as_deref().and_then(|b| url::Url::parse(b).ok()) {
            let host =
                pm_core::authority(u.scheme(), u.host_str().unwrap_or(""), u.port_or_known_default().unwrap_or(80));
            for op in &mut operations {
                if let Some(i) = op.example_request.find("\r\nHost: ") {
                    let end = op.example_request[i + 2..].find("\r\n").map_or(op.example_request.len(), |e| i + 2 + e);
                    op.example_request.replace_range(i + 2..end, &format!("Host: {host}"));
                }
            }
        }

        let mut sent = Vec::new();
        let mut skipped = Vec::new();
        if req.send_examples {
            let base = base_url.as_deref().ok_or_else(|| {
                ServiceError::Invalid("the spec has no absolute server URL; pass base_url to send examples".into())
            })?;
            let endpoint = crate::replay::parse_url_endpoint(base)?;
            let gets: Vec<&pm_openapi::Operation> = operations.iter().filter(|o| o.method == "GET").collect();
            let first =
                gets.first().ok_or_else(|| ServiceError::Invalid("the spec has no GET operations to send".into()))?;
            let probe = self.outgoing(endpoint.clone(), first.example_request.as_bytes(), true)?;
            let extra = json!({ "openapi_examples": gets.iter().map(|o| &o.path).collect::<Vec<_>>() });
            match self.gate_send_with(
                actor,
                "openapi_examples",
                &probe,
                req.identity.as_deref(),
                true,
                req.approval_id.as_deref(),
                Some(Tier::ActiveSafe),
                extra,
            )? {
                Authorization::Allowed { .. } => {}
                Authorization::Denied { reasons } => return Ok(OpenApiImportResult::Denied { reasons }),
                Authorization::PendingApproval { approval_id, summary, reasons } => {
                    return Ok(OpenApiImportResult::PendingApproval {
                        approval_id,
                        summary: format!("send {} GET examples from the spec: {summary}", gets.len()),
                        reasons,
                    });
                }
            }
            for op in gets {
                let out = self.outgoing(endpoint.clone(), op.example_request.as_bytes(), true)?;
                let in_scope =
                    Target::from_parts(&out.endpoint.scheme, &out.endpoint.host, out.endpoint.port, &out.path)
                        .is_ok_and(|t| self.policy.scope_check(&t).is_ok());
                if !in_scope {
                    skipped.push(format!("{} {}: out of scope", op.method, op.path));
                    continue;
                }
                if Tier::for_http_request(&out.raw).0 > Tier::ActiveSafe {
                    skipped.push(format!("{} {}: the example payload is not safe to send", op.method, op.path));
                    continue;
                }
                let (s, _) = self.send_as(actor, &out, req.identity.as_deref(), true, "openapi").await?;
                sent.push(SentExample {
                    method: op.method.clone(),
                    path: op.path.clone(),
                    exchange_id: s.exchange_id,
                    status: s.status,
                });
            }
        }
        let stored = json!({
            "title": spec.title, "version": spec.version, "base_url": base_url, "operations": operations,
        });
        self.store.lock().set_setting(OPENAPI_SETTING, &stored.to_string())?;
        self.audit(
            &actor.id(),
            "openapi_import",
            json!({ "title": spec.title, "operations": operations.len(), "sent": sent.len() }),
            "ok",
        )?;
        Ok(OpenApiImportResult::Imported {
            title: spec.title,
            version: spec.version,
            base_url,
            operations,
            truncated: spec.truncated,
            sent,
            skipped,
        })
    }

    /// The last imported spec's operations, if any.
    pub fn openapi_get(&self) -> Result<Value> {
        Ok(self
            .store
            .lock()
            .get_setting(OPENAPI_SETTING)?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null))
    }
}
