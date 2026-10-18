//! API routes: thin adapters over `pm-service`.

use std::convert::Infallible;
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use futures_util::Stream;
use pm_service::pm_ai::View;
use pm_service::pm_store::HistoryFilter;
use pm_service::{
    AuthzCheckRequest, FindingUpdate, ModelFilter, NewFinding, ProofRequest, ReplayRequest, ServiceError,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;

pub struct ApiError(ServiceError);

impl From<ServiceError> for ApiError {
    fn from(e: ServiceError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            ServiceError::NotFound(_) => StatusCode::NOT_FOUND,
            ServiceError::Invalid(_) => StatusCode::BAD_REQUEST,
            ServiceError::Approval(_) | ServiceError::ApprovalMismatch(_) => StatusCode::CONFLICT,
            ServiceError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(json!({ "error": self.0.to_string() }))).into_response()
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

fn ok<T: serde::Serialize>(v: T) -> ApiResult {
    Ok(Json(serde_json::to_value(v).unwrap_or(Value::Null)))
}

pub fn api() -> Router<AppState> {
    Router::new()
        .route("/status", get(status))
        .route("/events", get(events))
        .route("/exchanges", get(exchanges))
        .route("/exchanges/{id}", get(exchange))
        .route("/replay", post(replay))
        .route("/approvals", get(approvals))
        .route("/approvals/{id}/{decision}", post(decide))
        .route("/identities", get(identities))
        .route("/identities/capture", post(identity_capture))
        .route("/identities/{name}/check", post(identity_check))
        .route("/authz/check", post(authz_check))
        .route("/authz/results", get(authz_results))
        .route("/authz/candidates", get(authz_candidates))
        .route("/model", get(model))
        .route("/coverage", get(coverage))
        .route("/hypotheses", get(hypotheses))
        .route("/findings", get(findings).post(finding_create))
        .route("/findings/{id}", get(finding).patch(finding_update))
        .route("/proofs", post(proof_run))
        .route("/proofs/{id}", get(proof))
        .route("/proofs/{id}/rerun", post(proof_rerun))
        .route("/audit", get(audit))
        .route("/audit/verify", get(audit_verify))
        .route("/report", get(report))
        .route("/intercept", get(intercept_state))
        .route("/intercept/settings", axum::routing::put(intercept_settings))
        .route("/intercept/forward-all", post(intercept_forward_all))
        .route("/intercept/{id}/forward", post(intercept_forward))
        .route("/intercept/{id}/drop", post(intercept_drop))
        .route("/match-replace", get(rules_get).put(rules_put))
}

#[derive(Deserialize)]
pub struct AuthQuery {
    token: String,
}

/// Exchanges the token from the launch URL for an HttpOnly cookie, so it
/// doesn't stay in the address bar or history.
pub async fn auth(State(st): State<AppState>, Query(q): Query<AuthQuery>) -> Response {
    if !crate::constant_eq(q.token.as_bytes(), st.token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "wrong token").into_response();
    }
    let cookie = format!("pm_token={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000", st.token);
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

async fn status(State(st): State<AppState>) -> ApiResult {
    let roe = st.service.policy().roe();
    ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "project": *st.project,
        "you_are": st.actor.id(),
        "engagement": roe.engagement.name,
        "in_scope": roe.include.iter().map(|p| &p.text).collect::<Vec<_>>(),
        "counters": st.service.counters()?,
    }))
}

/// Server-sent events: `counters` whenever anything the UI shows changes.
async fn events(State(st): State<AppState>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = futures_util::stream::unfold((st, None), |(st, prev)| async move {
        loop {
            let now = st.service.counters().ok();
            if now.is_some() && now != prev {
                let ev = Event::default().event("counters").data(serde_json::to_string(&now).unwrap_or_default());
                return Some((Ok(ev), (st, now)));
            }
            tokio::time::sleep(Duration::from_millis(700)).await;
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn exchanges(State(st): State<AppState>, Query(f): Query<HistoryFilter>) -> ApiResult {
    ok(st.service.history_search(&st.actor, &f)?)
}

async fn exchange(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    let ex = st.service.exchange_raw(id)?;
    let view = st.service.exchange_get(&st.actor, id, View::Full, 6000)?;
    ok(json!({
        "summary": ex.summary,
        "request": String::from_utf8_lossy(&ex.request),
        "response": ex.response.as_deref().map(String::from_utf8_lossy),
        "view": view,
    }))
}

async fn replay(State(st): State<AppState>, Json(r): Json<ReplayRequest>) -> ApiResult {
    ok(st.service.replay_send(&st.actor, r).await?)
}

#[derive(Deserialize)]
struct StatusQuery {
    status: Option<String>,
}

async fn approvals(State(st): State<AppState>, Query(q): Query<StatusQuery>) -> ApiResult {
    let status = q.status.filter(|s| s != "all");
    ok(st.service.approvals(status.as_deref(), 200)?)
}

async fn decide(State(st): State<AppState>, Path((id, decision)): Path<(String, String)>) -> ApiResult {
    let approve = match decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => return Err(ServiceError::Invalid("use /approve or /deny".into()).into()),
    };
    ok(st.service.decide_approval(&id, &st.actor, approve)?)
}

async fn identities(State(st): State<AppState>) -> ApiResult {
    ok(st.service.identity_list()?)
}

#[derive(Deserialize)]
struct CaptureBody {
    name: String,
    #[serde(default)]
    role: Option<String>,
    exchange_id: i64,
}

async fn identity_capture(State(st): State<AppState>, Json(b): Json<CaptureBody>) -> ApiResult {
    ok(st.service.identity_capture(&st.actor, &b.name, b.role.as_deref().unwrap_or("user"), b.exchange_id)?)
}

async fn identity_check(State(st): State<AppState>, Path(name): Path<String>) -> ApiResult {
    ok(st.service.identity_check(&st.actor, &name).await?)
}

async fn authz_check(State(st): State<AppState>, Json(r): Json<AuthzCheckRequest>) -> ApiResult {
    ok(st.service.authz_check(&st.actor, r).await?)
}

#[derive(Deserialize)]
struct ExchangeQuery {
    exchange_id: Option<i64>,
}

async fn authz_results(State(st): State<AppState>, Query(q): Query<ExchangeQuery>) -> ApiResult {
    ok(st.service.authz_results(q.exchange_id)?)
}

async fn authz_candidates(State(st): State<AppState>) -> ApiResult {
    ok(st.service.authz_candidates()?)
}

async fn model(State(st): State<AppState>, Query(f): Query<ModelFilter>) -> ApiResult {
    ok(st.service.model_get(&f)?)
}

#[derive(Deserialize)]
struct CoverageQuery {
    all: Option<bool>,
}

async fn coverage(State(st): State<AppState>, Query(q): Query<CoverageQuery>) -> ApiResult {
    ok(st.service.coverage(!q.all.unwrap_or(false))?)
}

async fn hypotheses(State(st): State<AppState>, Query(q): Query<StatusQuery>) -> ApiResult {
    ok(st.service.hypothesis_list(q.status.as_deref())?)
}

async fn findings(State(st): State<AppState>, Query(q): Query<StatusQuery>) -> ApiResult {
    ok(st.service.finding_list(q.status.as_deref())?)
}

async fn finding(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.finding_get(id)?)
}

async fn finding_create(State(st): State<AppState>, Json(f): Json<NewFinding>) -> ApiResult {
    ok(st.service.finding_create(&st.actor, f)?)
}

async fn finding_update(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(mut u): Json<FindingUpdate>,
) -> ApiResult {
    u.id = id;
    ok(st.service.finding_update(&st.actor, u)?)
}

async fn proof_run(State(st): State<AppState>, Json(r): Json<ProofRequest>) -> ApiResult {
    ok(st.service.proof_run(&st.actor, r).await?)
}

async fn proof(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.proof_get(id)?)
}

async fn proof_rerun(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.proof_rerun(&st.actor, id).await?)
}

#[derive(Deserialize)]
struct LimitQuery {
    limit: Option<usize>,
}

async fn audit(State(st): State<AppState>, Query(q): Query<LimitQuery>) -> ApiResult {
    ok(st.service.audit_list(q.limit.unwrap_or(200).min(5000))?)
}

async fn audit_verify(State(st): State<AppState>) -> ApiResult {
    match st.service.audit_verify() {
        Ok(n) => ok(json!({ "intact": true, "records": n })),
        Err(e) => ok(json!({ "intact": false, "error": e.to_string() })),
    }
}

async fn report(State(st): State<AppState>) -> Result<Response, ApiError> {
    let md = st.service.report_markdown()?;
    Ok(([(header::CONTENT_TYPE, "text/markdown; charset=utf-8")], md).into_response())
}

async fn intercept_state(State(st): State<AppState>) -> ApiResult {
    ok(st.service.intercept_state())
}

async fn intercept_settings(
    State(st): State<AppState>,
    Json(s): Json<pm_service::pm_proxy::InterceptSettings>,
) -> ApiResult {
    ok(st.service.intercept_settings(&st.actor, s)?)
}

#[derive(Deserialize)]
struct ForwardBody {
    #[serde(default)]
    raw: Option<String>,
    #[serde(default)]
    fix_content_length: Option<bool>,
}

async fn intercept_forward(State(st): State<AppState>, Path(id): Path<u64>, Json(b): Json<ForwardBody>) -> ApiResult {
    st.service.intercept_forward(&st.actor, id, b.raw, b.fix_content_length.unwrap_or(true))?;
    ok(json!({ "forwarded": id }))
}

async fn intercept_drop(State(st): State<AppState>, Path(id): Path<u64>) -> ApiResult {
    st.service.intercept_drop(&st.actor, id)?;
    ok(json!({ "dropped": id }))
}

#[derive(Deserialize)]
struct RulesBody {
    rules: Vec<pm_service::pm_proxy::RewriteRule>,
}

async fn rules_get(State(st): State<AppState>) -> ApiResult {
    ok(json!({ "rules": st.service.match_replace_rules()? }))
}

async fn rules_put(State(st): State<AppState>, Json(b): Json<RulesBody>) -> ApiResult {
    ok(json!({ "rules": st.service.set_match_replace_rules(&st.actor, b.rules)? }))
}

async fn intercept_forward_all(State(st): State<AppState>) -> ApiResult {
    ok(json!({ "forwarded": st.service.intercept_forward_all(&st.actor)? }))
}
