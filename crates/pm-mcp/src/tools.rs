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
                "identity": {"type":"string","description":"Send with this identity's credentials (see identity_list), or 'anonymous'"},
                "raw": {"type":"string","description":"Full raw request (request line, headers, blank line, body)"},
                "fix_content_length": {"type":"boolean","description":"Set Content-Length to the body length (default true)"},
                "normalize_newlines": {"type":"boolean","description":"Turn \\n into \\r\\n in the head (default true)"},
                "approval_id": {"type":"string","description":"From a previous pending_approval result"},
                "hypothesis_id": {"type":"integer","description":"Hypothesis this send tests (links evidence)"},
                "view": view,
                "max_tokens": {"type":"integer","minimum":200,"maximum":20000},
            }),
            &[],
        ),
        tool(
            "identity_list",
            "Test identities (users/roles) whose credentials ProxyMind holds. Shows names, roles, cookie and header \
             names and session status, never secret values.",
            json!({}),
            &[],
        ),
        tool(
            "identity_capture",
            "Create or update an identity from the cookies and auth headers of a recorded request (e.g. a request the \
             user made while logged in as that user). You never see the values.",
            json!({
                "name": {"type":"string","description":"Short name, e.g. alice or admin"},
                "role": {"type":"string","description":"e.g. user, admin, guest"},
                "exchange_id": {"type":"integer"},
            }),
            &["name", "exchange_id"],
        ),
        tool(
            "identity_check",
            "Check an identity's session with its health check, logging in again automatically if it has a login recipe.",
            json!({ "name": {"type":"string"} }),
            &["name"],
        ),
        tool(
            "authz_check",
            "Authorization test: re-send a recorded GET (made by the data's owner) as other identities and as an \
             anonymous user, and compare each response with the owner's while ignoring noise such as timestamps. \
             Verdicts: denied, same_as_owner (possible broken access control), allowed_different, inconclusive.",
            json!({
                "exchange_id": {"type":"integer","description":"A GET/HEAD/OPTIONS exchange made by the owner"},
                "identities": {"type":"array","items":{"type":"string"},"description":"Identity names to try"},
                "include_anonymous": {"type":"boolean","description":"Also try without credentials (default true)"},
            }),
            &["exchange_id"],
        ),
        tool(
            "authz_results",
            "Latest authorization-check results, per exchange and identity.",
            json!({ "exchange_id": {"type":"integer","description":"Only this exchange"} }),
            &[],
        ),
        tool(
            "model_get",
            "The application model built from traffic: operations (method + path template such as \
             /api/orders/{id}, kind, params, identities seen) and object counts. Start here to understand the app.",
            json!({
                "contains": {"type":"string","description":"Only operations whose key contains this text"},
                "include_objects": {"type":"boolean","description":"Also list objects with their owners (default false)"},
                "object_type": {"type":"string","description":"Only objects of this type, e.g. Order"},
            }),
            &[],
        ),
        tool(
            "authz_candidates",
            "Suggested access-control tests from the model: recorded requests for objects owned by one identity, \
             with the other identities to try. Feed them to authz_check, then prove hits with proof_run.",
            json!({}),
            &[],
        ),
        tool(
            "hypothesis_create",
            "Record what you are about to test, so work is shared and coverage is tracked. Pass the returned id as \
             hypothesis_id to replay_send and proof_run to link evidence.",
            json!({
                "operation": {"type":"string","description":"Operation key from model_get"},
                "param": {"type":"string","description":"Parameter tested, if any"},
                "vuln_class": {"type":"string","description":"idor, bfla, authn, sqli, xss, ssrf, mass_assignment, business_logic, or your own"},
                "rationale": {"type":"string"},
            }),
            &["operation", "vuln_class", "rationale"],
        ),
        tool(
            "hypothesis_update",
            "Update a hypothesis: status open/testing/confirmed/refuted and/or add a note. Mark refuted when a test \
             shows the issue is not there, so nobody repeats it.",
            json!({
                "id": {"type":"integer"},
                "status": {"type":"string","enum":["open","testing","confirmed","refuted"]},
                "note": {"type":"string"},
            }),
            &["id"],
        ),
        tool(
            "hypothesis_list",
            "All hypotheses (optionally by status), with linked evidence exchange ids.",
            json!({ "status": {"type":"string","enum":["open","testing","confirmed","refuted"]} }),
            &[],
        ),
        tool(
            "coverage",
            "What has and hasn't been tested: each operation × relevant vulnerability class, untested first.",
            json!({ "untested_only": {"type":"boolean","description":"Only untested/open cells (default true)"} }),
            &[],
        ),
        tool(
            "proof_run",
            "Have ProxyMind verify a suspected vulnerability itself. Oracles: differential_authz (exchange_id of the \
             owner's GET + attacker identity: proves IDOR/BOLA or missing role checks), timing (exchange_id or url, \
             payload_raw with a delay payload, optional baseline_raw: proves time-based injection statistically), oast \
             (url or exchange_id + raw containing {{oast}}: proves SSRF/blind injection via an out-of-band callback). \
             Pass finding_id/hypothesis_id to update them when proven. Payload oracles may need human approval.",
            json!({
                "oracle": {"type":"string","enum":["differential_authz","timing","oast"]},
                "exchange_id": {"type":"integer"},
                "attacker": {"type":"string"},
                "owner": {"type":"string"},
                "url": {"type":"string"},
                "baseline_raw": {"type":"string"},
                "payload_raw": {"type":"string"},
                "samples": {"type":"integer","minimum":5,"maximum":30},
                "min_effect_ms": {"type":"number"},
                "raw": {"type":"string"},
                "wait_seconds": {"type":"integer","minimum":1,"maximum":60},
                "identity": {"type":"string"},
                "finding_id": {"type":"integer"},
                "hypothesis_id": {"type":"integer"},
                "approval_id": {"type":"string"},
            }),
            &["oracle"],
        ),
        tool(
            "proof_get",
            "A stored proof: verdict, reasons, evidence exchange ids and inputs.",
            json!({ "proof_id": {"type":"integer"} }),
            &["proof_id"],
        ),
        tool(
            "finding_create",
            "Record a suspected vulnerability with evidence exchange ids. It becomes 'proven' only via proof_run; \
             humans confirm it.",
            json!({
                "title": {"type":"string"},
                "vuln_class": {"type":"string"},
                "severity": {"type":"string","enum":["critical","high","medium","low","info"]},
                "description": {"type":"string","description":"What is wrong, impact, and how to reproduce"},
                "url": {"type":"string"},
                "evidence": {"type":"array","items":{"type":"integer"}},
                "hypothesis_id": {"type":"integer"},
            }),
            &["title", "vuln_class", "severity", "description"],
        ),
        tool(
            "finding_update",
            "Update a finding's description, severity or evidence. Agents may only set status to suspected.",
            json!({
                "id": {"type":"integer"},
                "status": {"type":"string"},
                "severity": {"type":"string","enum":["critical","high","medium","low","info"]},
                "description": {"type":"string"},
                "add_evidence": {"type":"array","items":{"type":"integer"}},
            }),
            &["id"],
        ),
        tool(
            "finding_list",
            "Findings, optionally by status (suspected, proven, confirmed, false_positive, reported).",
            json!({ "status": {"type":"string"} }),
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
        "identity_list" => service.identity_list().map(to_json).map_err(|e| e.to_string()),
        "identity_capture" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                name: String,
                role: Option<String>,
                exchange_id: i64,
            }
            let g: A = args(a)?;
            service
                .identity_capture(actor, &g.name, g.role.as_deref().unwrap_or("user"), g.exchange_id)
                .map(to_json)
                .map_err(|e| e.to_string())
        }
        "identity_check" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                name: String,
            }
            let g: A = args(a)?;
            service.identity_check(actor, &g.name).await.map(to_json).map_err(|e| e.to_string())
        }
        "authz_check" => {
            let r: pm_service::AuthzCheckRequest = args(a)?;
            service.authz_check(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "authz_results" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                exchange_id: Option<i64>,
            }
            let g: A = args(a)?;
            service.authz_results(g.exchange_id).map(to_json).map_err(|e| e.to_string())
        }
        "model_get" => {
            let f: pm_service::ModelFilter = args(a)?;
            service.model_get(&f).map_err(|e| e.to_string())
        }
        "authz_candidates" => service.authz_candidates().map(to_json).map_err(|e| e.to_string()),
        "hypothesis_create" => {
            let h: pm_service::NewHypothesis = args(a)?;
            service.hypothesis_create(actor, h).map(to_json).map_err(|e| e.to_string())
        }
        "hypothesis_update" => {
            let u: pm_service::HypothesisUpdate = args(a)?;
            service.hypothesis_update(actor, u).map(to_json).map_err(|e| e.to_string())
        }
        "hypothesis_list" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                status: Option<String>,
            }
            let g: A = args(a)?;
            service.hypothesis_list(g.status.as_deref()).map(to_json).map_err(|e| e.to_string())
        }
        "coverage" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                untested_only: Option<bool>,
            }
            let g: A = args(a)?;
            service.coverage(g.untested_only.unwrap_or(true)).map(to_json).map_err(|e| e.to_string())
        }
        "proof_run" => {
            let r: pm_service::ProofRequest = args(a)?;
            service.proof_run(actor, r).await.map(to_json).map_err(|e| e.to_string())
        }
        "proof_get" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                proof_id: i64,
            }
            let g: A = args(a)?;
            service.proof_get(g.proof_id).map_err(|e| e.to_string())
        }
        "finding_create" => {
            let f: pm_service::NewFinding = args(a)?;
            service.finding_create(actor, f).map_err(|e| e.to_string())
        }
        "finding_update" => {
            let u: pm_service::FindingUpdate = args(a)?;
            service.finding_update(actor, u).map_err(|e| e.to_string())
        }
        "finding_list" => {
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct A {
                status: Option<String>,
            }
            let g: A = args(a)?;
            service.finding_list(g.status.as_deref()).map(to_json).map_err(|e| e.to_string())
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
