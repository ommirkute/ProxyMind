//! The MCP endpoint (ADR-0022 step 5): `POST /api/v1/mcp`, one JSON-RPC message (or a batch) in, the response out,
//! `204 No Content` for a notification. It is what `proxymind mcp --server https://host` talks to, so an agent on
//! another machine gets the tools of a local MCP agent through the project server.
//!
//! * **The actor is the request's** (`Me`), never anything in the message: a `pm3_` token's `agent:<name>`, so scope,
//!   tiers (and the token's cap), approvals, redaction and untrusted tagging are exactly the local MCP server's (the
//!   same `pm_mcp::McpServer`, built per request around the same `Service`). A signed-in session or the install token
//!   reaches it too and acts as that person.
//! * **A viewer's token** (ceiling or owner's role) may `initialize`, list tools and read prompts, but `tools/call` is
//!   refused: tools can send traffic and write findings, and the finer per-tool roles come with ADR-0022 step 6.

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use pm_service::access::Role;
use serde_json::{Value, json};

use crate::AppState;
use crate::server_mode::Me;

/// JSON-RPC messages are small; a replay with a large body is the biggest thing an agent sends.
pub(crate) const MCP_BODY_LIMIT: usize = 4 * 1024 * 1024;

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn json_response(status: StatusCode, v: &Value) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], v.to_string()).into_response()
}

pub(crate) async fn mcp_endpoint(State(st): State<AppState>, me: Me, body: Bytes) -> Response {
    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &rpc_error(Value::Null, -32700, &format!("parse error: {e}")),
            );
        }
    };
    // The actor is the request's own. Nothing in `msg` can change it.
    let server = pm_mcp::McpServer::new(st.service.clone(), me.actor.clone());
    let viewer = me.token.is_some() && me.role() == Role::Viewer;
    let one = |m: Value| {
        let server = &server;
        async move {
            let id = m.get("id").cloned();
            if viewer && m.get("method").and_then(Value::as_str) == Some("tools/call") {
                return id.map(|id| rpc_error(id, -32001, "this token acts as a viewer and may not call tools"));
            }
            server.handle(m).await
        }
    };
    match msg {
        Value::Array(batch) => {
            if batch.is_empty() {
                return json_response(StatusCode::BAD_REQUEST, &rpc_error(Value::Null, -32600, "empty batch"));
            }
            let mut replies = Vec::new();
            for m in batch {
                if let Some(r) = one(m).await {
                    replies.push(r);
                }
            }
            if replies.is_empty() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                json_response(StatusCode::OK, &Value::Array(replies))
            }
        }
        m => match one(m).await {
            Some(r) => json_response(StatusCode::OK, &r),
            None => StatusCode::NO_CONTENT.into_response(),
        },
    }
}
