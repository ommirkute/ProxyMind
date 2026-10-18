//! MCP tool definitions and dispatch. Names and shapes follow RFC 0001.

use pm_service::pm_ai::View;
use pm_service::pm_policy::{Actor, ActorKind, Tier};
use pm_service::pm_store::HistoryFilter;
use pm_service::{ReplayRequest, Service};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": { "type": "object", "properties": properties, "required": required, "additionalProperties": false },
    })
}

const VIEW_SCHEMA: &str = r#"{"type":"string","enum":["summary","headers","full"],"description":"summary (default): key headers and a short body preview. headers: all headers. full: everything within max_tokens."}"#;

pub fn tool_definitions() -> Vec<Value> {
    let view: Value = serde_json::from_str(VIEW_SCHEMA).expect("valid schema");
    vec![
        tool(
            "roe_get",
            "Rules of engagement: what is in scope, testing windows, rate limits, and which kinds of actions you may \
             take without human approval. Read this before sending anything.",
            json!({}),
            &[],
        ),
        tool(
            "history_search",
            "Search recorded HTTP traffic, newest first. Returns summaries (no bodies). Combine filters to narrow down.",
            json!({
                "host": {"type":"string","description":"Host contains this text"},
                "path": {"type":"string","description":"Path or query contains this text"},
                "method": {"type":"string"},
                "status": {"type":"integer"},
                "source": {"type":"string","description":"proxy (browser traffic) or replay (sent via ProxyMind)"},
                "actor": {"type":"string","description":"e.g. human:local or agent:claude"},
                "before_id": {"type":"integer","description":"Paging: pass next_before_id from the previous result"},
                "after_id": {"type":"integer","description":"Only exchanges newer than this id"},
                "limit": {"type":"integer","minimum":1,"maximum":500,"description":"Default 50"},
            }),
            &[],
        ),
        tool(
            "exchange_get",
            "One request/response pair as a token-budgeted view. Secrets are replaced with {{secret:...}} placeholders. \
             Target content is wrapped in <untrusted_target_content>.",
            json!({
                "id": {"type":"integer"},
                "view": view,
                "max_tokens": {"type":"integer","minimum":200,"maximum":20000,"description":"Default 1500"},
            }),
            &["id"],
        ),
        tool(
            "exchange_raw_request",
            "The exact raw request text of an exchange (secrets as placeholders), ready to edit and pass to replay_send.",
            json!({ "id": {"type":"integer"} }),
            &["id"],
        ),
        tool(
            "replay_send",
            "Send an HTTP/1.1 request to the target and get the response. Give exchange_id to resend or edit a recorded \
             request (its target is used), or url + raw for a new one. Use {{secret:...}} placeholders exactly as shown \
             to you. GET/HEAD/OPTIONS usually run directly; other methods may return status=pending_approval: ask the \
             user to approve, then call again with identical arguments plus approval_id.",
            json!({
                "exchange_id": {"type":"integer","description":"Recorded exchange to resend or base this on"},
                "url": {"type":"string","description":"scheme://host[:port] when not using exchange_id"},
                "raw": {"type":"string","description":"Full raw request (request line, headers, blank line, body)"},
                "fix_content_length": {"type":"boolean","description":"Set Content-Length to the body length (default true)"},
                "normalize_newlines": {"type":"boolean","description":"Turn \\n into \\r\\n in the head (default true)"},
                "approval_id": {"type":"string","description":"From a previous pending_approval result"},
                "view": view,
                "max_tokens": {"type":"integer","minimum":200,"maximum":20000},
            }),
            &[],
        ),
        tool(
            "approval_status",
            "Check whether a human has approved or denied an action. Status: pending, approved, denied or used.",
            json!({ "approval_id": {"type":"string"} }),
            &["approval_id"],
        ),
    ]
}

fn args<T: DeserializeOwned>(v: Value) -> Result<T, String> {
    serde_json::from_value(v).map_err(|e| format!("invalid arguments: {e}"))
}

fn tier_name(t: Tier) -> String {
    serde_json::to_value(t).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

pub fn roe_summary(service: &Service, actor: &Actor) -> Value {
    let roe = service.policy().roe();
    let tiers: serde_json::Map<String, Value> =
        [Tier::Read, Tier::Passive, Tier::ActiveSafe, Tier::ActiveIntrusive, Tier::Destructive]
            .into_iter()
            .map(|t| (tier_name(t), json!(roe.tier_decision(actor.kind, t).as_str())))
            .collect();
    json!({
        "you_are": actor.id(),
        "engagement": {
            "name": roe.engagement.name,
            "starts": roe.engagement.starts.map(|d| d.to_string()),
            "ends": roe.engagement.ends.map(|d| d.to_string()),
        },
        "in_scope": roe.include.iter().map(|p| &p.text).collect::<Vec<_>>(),
        "excluded": roe.exclude.iter().map(|p| &p.text).collect::<Vec<_>>(),
        "denied_networks": roe.deny_networks.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "max_requests_per_second_per_host": roe.limits.max_rps_per_host,
        "your_permissions": tiers,
        "tiers_explained": {
            "active_safe": "GET/HEAD/OPTIONS requests",
            "active_intrusive": "POST/PUT/PATCH and other state-changing requests",
            "destructive": "DELETE requests",
        },
        "secrets_redacted": service.redacts_for(actor),
        "only_local_models_allowed": !roe.data.allow_cloud_models && actor.kind == ActorKind::Agent,
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GetArgs {
    id: i64,
    view: Option<View>,
    max_tokens: Option<usize>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdArgs {
    id: i64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalArgs {
    approval_id: String,
}

pub async fn call(service: &Service, actor: &Actor, name: &str, a: Value) -> Result<Value, String> {
    match name {
        "roe_get" => Ok(roe_summary(service, actor)),
        "history_search" => {
            let f: HistoryFilter = args(a)?;
            service.history_search(actor, &f).map(to_json).map_err(|e| e.to_string())
        }
        "exchange_get" => {
            let g: GetArgs = args(a)?;
            service
                .exchange_get(actor, g.id, g.view.unwrap_or_default(), g.max_tokens.unwrap_or(1500))
                .map(to_json)
                .map_err(|e| e.to_string())
        }
        "exchange_raw_request" => {
            let g: IdArgs = args(a)?;
            service
                .exchange_raw_request(actor, g.id)
                .map(|raw| json!({ "id": g.id, "raw": raw }))
                .map_err(|e| e.to_string())
        }
        "replay_send" => {
            let r: ReplayRequest = args(a)?;
            service.replay_send(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "approval_status" => {
            let g: ApprovalArgs = args(a)?;
            match service.approval(&g.approval_id).map_err(|e| e.to_string())? {
                Some(row) if row.actor == actor.id() => Ok(json!({
                    "approval_id": row.id, "status": row.status, "summary": row.summary, "decided_by": row.decided_by,
                })),
                _ => Err(format!("no approval {} for {}", g.approval_id, actor.id())),
            }
        }
        _ => Err(format!("unknown tool {name}")),
    }
}

fn to_json<T: serde::Serialize>(v: T) -> Value {
    serde_json::to_value(v).unwrap_or_else(|e| json!({ "error": e.to_string() }))
}
