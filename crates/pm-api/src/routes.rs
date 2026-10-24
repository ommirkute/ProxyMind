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

pub enum ApiError {
    Service(ServiceError),
    Assistant(pm_assistant::AssistantError),
}

impl From<ServiceError> for ApiError {
    fn from(e: ServiceError) -> Self {
        Self::Service(e)
    }
}

impl From<pm_assistant::AssistantError> for ApiError {
    fn from(e: pm_assistant::AssistantError) -> Self {
        match e {
            pm_assistant::AssistantError::Service(s) => Self::Service(s),
            other => Self::Assistant(other),
        }
    }
}

fn service_status(e: &ServiceError) -> StatusCode {
    match e {
        ServiceError::NotFound(_) => StatusCode::NOT_FOUND,
        ServiceError::Invalid(_) => StatusCode::BAD_REQUEST,
        ServiceError::Approval(_) | ServiceError::ApprovalMismatch(_) => StatusCode::CONFLICT,
        ServiceError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        use pm_assistant::AssistantError as A;
        let (status, msg) = match &self {
            Self::Service(e) => (service_status(e), e.to_string()),
            Self::Assistant(e @ A::Refused(_)) => (StatusCode::FORBIDDEN, e.to_string()),
            Self::Assistant(e @ A::Setup(_)) => (StatusCode::BAD_REQUEST, e.to_string()),
            Self::Assistant(e) => (StatusCode::BAD_GATEWAY, e.to_string()),
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

fn ok<T: serde::Serialize>(v: T) -> ApiResult {
    Ok(Json(serde_json::to_value(v).unwrap_or(Value::Null)))
}

pub fn api() -> Router<AppState> {
    Router::new()
        .route("/status", get(status))
        .route("/roe", get(roe_get).put(roe_put))
        .route("/setup", get(setup))
        .route("/ca.pem", get(ca_pem))
        .route("/browser/open", post(browser_open))
        .route("/roe/check", post(roe_check))
        .route("/events", get(events))
        .route("/exchanges", get(exchanges))
        .route("/exchanges/{id}", get(exchange))
        .route("/search", post(search))
        .route("/sitemap", get(sitemap))
        .route("/exchanges/{id}/ws", get(ws_messages))
        .route("/exchanges/{id}/annotation", axum::routing::put(annotate))
        .route("/ws/history", get(ws_history))
        .route(
            "/ui/{key}",
            get(ui_get).put(ui_put).layer(axum::extract::DefaultBodyLimit::max(pm_service::UI_STATE_MAX + 1024)),
        )
        .route("/exchanges/{id}/curl", get(exchange_curl))
        .route(
            "/import/har",
            post(import_har).layer(axum::extract::DefaultBodyLimit::max(pm_service::MAX_IMPORT_BYTES + 1024)),
        )
        .route("/export/har", post(export_har))
        .route("/tools/curl", post(tools_curl))
        .route("/ws/replay", post(ws_replay))
        .route("/race", post(race))
        .route("/intruder", post(intruder))
        .route("/intruder/attacks", get(attacks_list).post(attack_start))
        .route("/intruder/attacks/{id}", get(attack_status))
        .route("/intruder/attacks/{id}/{action}", post(attack_control))
        .route("/crawl", post(crawl))
        .route("/discover", post(discover))
        .route("/tools/decode", post(tools_decode))
        .route("/tools/compare", post(tools_compare))
        .route("/tools/sequencer", post(tools_sequencer))
        .route("/tools/sequencer/analyze", post(tools_sequencer_analyze))
        .route("/openapi", get(openapi_get))
        .route("/openapi/import", post(openapi_import))
        .route("/graphql", get(graphql_get))
        .route("/graphql/import", post(graphql_import))
        .route("/replay", post(replay))
        .route("/approvals", get(approvals))
        .route("/approvals/{id}/{decision}", post(decide))
        .route("/identities", get(identities))
        .route("/identities/capture", post(identity_capture))
        .route("/identities/{name}/check", post(identity_check))
        .route("/identities/record-login", post(identity_record_login))
        .route("/identities/{name}/learn-logged-out", post(identity_learn_logged_out))
        .route("/history/mark", get(history_mark))
        .route("/authz/check", post(authz_check))
        .route("/authz/results", get(authz_results))
        .route("/authz/candidates", get(authz_candidates))
        .route("/model", get(model))
        .route("/coverage", get(coverage))
        .route("/scan/issues", get(scan_issues))
        .route("/scan/active", post(scan_active))
        .route("/scan/tasks", get(scan_tasks_list).post(scan_task_start))
        .route("/scan/tasks/{id}", get(scan_task_status))
        .route("/scan/tasks/{id}/cancel", post(scan_task_cancel))
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
        .route("/network", get(network_get).put(network_put))
        .route("/proxy/listeners", get(listeners_get).put(listeners_put))
        .route("/history/recording", get(recording_get).put(recording_put))
        .route("/session", get(session_get).put(session_put))
        .route("/session/jar", get(session_jar).delete(session_jar_clear))
        .route("/session/macros/{name}/run", post(session_macro_run))
        .route("/assistant", get(assistant_state))
        .route("/assistant/config", axum::routing::put(assistant_config))
        .route("/assistant/chats/{id}", get(assistant_chat))
        .route("/assistant/send", post(assistant_send))
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

#[derive(serde::Deserialize)]
struct BytesQuery {
    /// Also return the exact bytes, base64-encoded (for hex views).
    #[serde(default)]
    bytes: Option<u8>,
    /// Cut request and response text to this many bytes (`*_truncated`
    /// then gives the full length). Large bodies stay fast in a browser.
    #[serde(default)]
    max: Option<usize>,
}

/// Text of at most `max` bytes (on a character boundary) and, if cut, the full length.
fn capped(raw: &[u8], max: Option<usize>) -> (String, Option<usize>) {
    match max {
        Some(m) if raw.len() > m => {
            let mut s = String::from_utf8_lossy(&raw[..m]).into_owned();
            if s.ends_with('\u{fffd}') {
                s.pop(); // a character cut in half
            }
            (s, Some(raw.len()))
        }
        _ => (String::from_utf8_lossy(raw).into_owned(), None),
    }
}

async fn exchange(State(st): State<AppState>, Path(id): Path<i64>, Query(q): Query<BytesQuery>) -> ApiResult {
    let ex = st.service.exchange_raw(id)?;
    let view = st.service.exchange_get(&st.actor, id, View::Full, 6000)?;
    let max = q.max.map(|m| m.max(1024));
    let (request, request_truncated) = capped(&ex.request, max);
    let response = ex.response.as_deref().map(|r| capped(r, max));
    let mut v = json!({
        "summary": ex.summary,
        "request": request,
        "response": response.as_ref().map(|r| &r.0),
        "view": view,
    });
    if let Some(n) = request_truncated {
        v["request_truncated"] = json!(n);
    }
    if let Some(n) = response.and_then(|r| r.1) {
        v["response_truncated"] = json!(n);
    }
    if q.bytes == Some(1) {
        let cut = |b: &[u8]| pm_core::base64(&b[..max.map_or(b.len(), |m| m.min(b.len()))]);
        v["request_b64"] = json!(cut(&ex.request));
        v["response_b64"] = json!(ex.response.as_deref().map(cut));
    }
    Ok(Json(v))
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

#[derive(Deserialize)]
struct RecordLoginBody {
    name: String,
    #[serde(default)]
    role: Option<String>,
    from: i64,
    #[serde(default)]
    to: Option<i64>,
}

async fn identity_record_login(State(st): State<AppState>, Json(b): Json<RecordLoginBody>) -> ApiResult {
    ok(st.service.identity_record_login(&st.actor, &b.name, b.role.as_deref().unwrap_or("user"), b.from, b.to)?)
}

async fn identity_learn_logged_out(State(st): State<AppState>, Path(name): Path<String>) -> ApiResult {
    ok(st.service.identity_learn_logged_out(&st.actor, &name).await?)
}

async fn history_mark(State(st): State<AppState>) -> ApiResult {
    ok(serde_json::json!({ "id": st.service.history_mark()? }))
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

async fn scan_task_start(State(st): State<AppState>, Json(r): Json<pm_service::ScanTaskRequest>) -> ApiResult {
    ok(st.service.scan_task_start(&st.actor, r)?)
}

async fn scan_tasks_list(State(st): State<AppState>) -> ApiResult {
    ok(st.service.scan_task_list(&st.actor))
}

async fn scan_task_status(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    ok(st.service.scan_task_status(&st.actor, &id)?)
}

async fn scan_task_cancel(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    ok(st.service.scan_task_cancel(&st.actor, &id)?)
}

async fn scan_active(State(st): State<AppState>, Json(r): Json<pm_service::ActiveScanRequest>) -> ApiResult {
    ok(st.service.scan_active(&st.actor, r).await?)
}

async fn scan_issues(State(st): State<AppState>, Query(f): Query<pm_service::ScanFilter>) -> ApiResult {
    // Plugins run as processes; keep them off the async workers.
    let (service, actor) = (st.service.clone(), st.actor.clone());
    let issues = tokio::task::spawn_blocking(move || service.scan_passive(&actor, &f))
        .await
        .map_err(|e| pm_service::ServiceError::Invalid(format!("scan failed: {e}")))??;
    ok(issues)
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

#[derive(serde::Deserialize)]
struct ReportQuery {
    format: Option<String>,
}

async fn report(State(st): State<AppState>, Query(q): Query<ReportQuery>) -> Result<Response, ApiError> {
    let (ct, body) = match q.format.as_deref().unwrap_or("md") {
        "md" | "markdown" => ("text/markdown; charset=utf-8", st.service.report_markdown()?),
        "json" => ("application/json", st.service.report_json()?),
        "sarif" => ("application/sarif+json", st.service.report_sarif()?),
        // Served as a download only, and with its own CSP: it contains target content.
        "html" => ("text/html; charset=utf-8", st.service.report_html()?),
        other => {
            return Err(pm_service::ServiceError::Invalid(format!(
                "unknown format {other}; use md, json, sarif or html"
            ))
            .into());
        }
    };
    Ok(([(header::CONTENT_TYPE, ct), (header::CONTENT_DISPOSITION, "attachment")], body).into_response())
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
struct WsQuery {
    after_id: Option<i64>,
    limit: Option<usize>,
}

async fn search(State(st): State<AppState>, Json(r): Json<pm_service::SearchRequest>) -> ApiResult {
    ok(st.service.history_search_text(&st.actor, &r)?)
}

#[derive(serde::Deserialize)]
struct SiteQuery {
    host: Option<String>,
}

async fn sitemap(State(st): State<AppState>, Query(q): Query<SiteQuery>) -> ApiResult {
    ok(st.service.site_map(&st.actor, q.host.as_deref().filter(|h| !h.is_empty()))?)
}

async fn discover(State(st): State<AppState>, Json(r): Json<pm_service::DiscoverRequest>) -> ApiResult {
    ok(st.service.discover(&st.actor, r).await?)
}

async fn setup(State(st): State<AppState>) -> ApiResult {
    ok(json!({
        "proxy": st.setup.proxy,
        "ca_available": st.setup.ca_pem.is_some(),
        "ca_sha256": st.setup.ca_fingerprint(),
        "browser_available": st.service.browser_available(),
    }))
}

async fn browser_open(State(st): State<AppState>, Json(r): Json<pm_service::BrowserOpenRequest>) -> ApiResult {
    ok(st.service.browser_open(&st.actor, r).await?)
}

/// The CA certificate, as a download (it is public, but stays behind the API token like everything here).
async fn ca_pem(State(st): State<AppState>) -> Result<Response, ApiError> {
    let pem =
        st.setup.ca_pem.clone().ok_or_else(|| {
            pm_service::ServiceError::NotFound("no CA here: this process doesn't run the proxy".into())
        })?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"proxymind-ca.pem\""),
        ],
        pem,
    )
        .into_response())
}

async fn roe_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.roe_get()?)
}

#[derive(serde::Deserialize)]
struct RoeBody {
    text: String,
}

async fn roe_put(State(st): State<AppState>, Json(b): Json<RoeBody>) -> ApiResult {
    ok(st.service.roe_set(&st.actor, &b.text)?)
}

async fn roe_check(State(st): State<AppState>, Json(b): Json<RoeBody>) -> ApiResult {
    ok(st.service.roe_check(&b.text)?)
}

#[derive(serde::Deserialize)]
struct AnnotationBody {
    #[serde(default)]
    highlight: Option<String>,
    #[serde(default)]
    comment: Option<String>,
}

async fn annotate(State(st): State<AppState>, Path(id): Path<i64>, Json(b): Json<AnnotationBody>) -> ApiResult {
    ok(st.service.exchange_annotate(&st.actor, id, b.highlight.as_deref(), b.comment.as_deref())?)
}

#[derive(serde::Deserialize)]
struct WsHistoryQuery {
    host: Option<String>,
    before_id: Option<i64>,
    limit: Option<usize>,
}

async fn ws_history(State(st): State<AppState>, Query(q): Query<WsHistoryQuery>) -> ApiResult {
    let host = q.host.as_deref().filter(|h| !h.is_empty());
    ok(st.service.ws_history(&st.actor, host, q.before_id, q.limit.unwrap_or(500), 2000)?)
}

async fn ui_get(State(st): State<AppState>, Path(key): Path<String>) -> ApiResult {
    ok(st.service.ui_state_get(&key)?)
}

async fn ui_put(State(st): State<AppState>, Path(key): Path<String>, Json(v): Json<Value>) -> ApiResult {
    st.service.ui_state_put(&st.actor, &key, &v)?;
    ok(json!({ "saved": key }))
}

async fn exchange_curl(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(json!({ "command": st.service.exchange_curl(&st.actor, id)? }))
}

async fn import_har(State(st): State<AppState>, Json(r): Json<pm_service::ImportRequest>) -> ApiResult {
    ok(st.service.traffic_import_har(&st.actor, &r)?)
}

/// A HAR download: it holds target content, so it is never rendered here.
async fn export_har(
    State(st): State<AppState>,
    Json(r): Json<pm_service::ExportRequest>,
) -> Result<Response, ApiError> {
    let har = st.service.traffic_export_har(&st.actor, &r)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"proxymind.har\""),
        ],
        har.to_string(),
    )
        .into_response())
}

#[derive(serde::Deserialize)]
struct CurlBody {
    command: String,
}

async fn tools_curl(State(st): State<AppState>, Json(r): Json<CurlBody>) -> ApiResult {
    ok(st.service.curl_parse(&r.command)?)
}

async fn graphql_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.graphql_get()?)
}

async fn graphql_import(State(st): State<AppState>, Json(r): Json<pm_service::GraphQlImportRequest>) -> ApiResult {
    ok(st.service.graphql_import(&st.actor, r).await?)
}

async fn openapi_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.openapi_get()?)
}

async fn openapi_import(State(st): State<AppState>, Json(r): Json<pm_service::OpenApiImportRequest>) -> ApiResult {
    ok(st.service.openapi_import(&st.actor, r).await?)
}

async fn tools_decode(State(st): State<AppState>, Json(r): Json<pm_service::DecodeRequest>) -> ApiResult {
    ok(st.service.decode(&r)?)
}

#[derive(serde::Deserialize)]
struct CompareBody {
    a: i64,
    b: i64,
}

async fn tools_compare(State(st): State<AppState>, Json(r): Json<CompareBody>) -> ApiResult {
    ok(st.service.compare_exchanges(&st.actor, r.a, r.b)?)
}

async fn tools_sequencer(State(st): State<AppState>, Json(r): Json<pm_service::SequencerRequest>) -> ApiResult {
    ok(st.service.sequencer_run(&st.actor, r).await?)
}

#[derive(serde::Deserialize)]
struct TokensBody {
    tokens: Vec<String>,
}

async fn tools_sequencer_analyze(State(st): State<AppState>, Json(r): Json<TokensBody>) -> ApiResult {
    ok(st.service.sequencer_analyze(&r.tokens)?)
}

async fn crawl(State(st): State<AppState>, Json(r): Json<pm_service::CrawlRequest>) -> ApiResult {
    ok(st.service.crawl(&st.actor, r).await?)
}

async fn intruder(State(st): State<AppState>, Json(r): Json<pm_service::IntruderRequest>) -> ApiResult {
    ok(st.service.intruder_run(&st.actor, r).await?)
}

async fn attack_start(State(st): State<AppState>, Json(r): Json<pm_service::IntruderRequest>) -> ApiResult {
    ok(st.service.intruder_start(&st.actor, r)?)
}

async fn attacks_list(State(st): State<AppState>) -> ApiResult {
    ok(st.service.intruder_list(&st.actor))
}

#[derive(serde::Deserialize)]
struct FromQuery {
    from: Option<usize>,
}

async fn attack_status(State(st): State<AppState>, Path(id): Path<String>, Query(q): Query<FromQuery>) -> ApiResult {
    ok(st.service.intruder_status(&st.actor, &id, q.from.unwrap_or(0))?)
}

async fn attack_control(State(st): State<AppState>, Path((id, action)): Path<(String, String)>) -> ApiResult {
    ok(json!({ "status": st.service.intruder_control(&st.actor, &id, &action)? }))
}

async fn race(State(st): State<AppState>, Json(r): Json<pm_service::RaceRequest>) -> ApiResult {
    ok(st.service.race_send(&st.actor, r).await?)
}

async fn ws_replay(State(st): State<AppState>, Json(r): Json<pm_service::WsReplayRequest>) -> ApiResult {
    ok(st.service.ws_replay(&st.actor, r).await?)
}

async fn ws_messages(State(st): State<AppState>, Path(id): Path<i64>, Query(q): Query<WsQuery>) -> ApiResult {
    ok(st.service.ws_messages(&st.actor, id, q.after_id, q.limit.unwrap_or(200), 1 << 20)?)
}

async fn assistant_state(State(st): State<AppState>) -> ApiResult {
    let config = st.service.assistant_config()?;
    let ready = st.assistant.check(&config).map(|_| ()).map_err(|e| e.to_string()).err();
    ok(json!({
        "config": config,
        "local": pm_assistant::is_local_url(&config.base_url),
        "cloud_models_allowed": st.service.cloud_models_allowed(),
        "problem": ready,
        "acts_as": st.assistant.actor().id(),
        "chats": st.service.chat_list(50)?,
    }))
}

async fn assistant_config(State(st): State<AppState>, Json(cfg): Json<pm_service::AssistantConfig>) -> ApiResult {
    ok(st.service.assistant_config_set(&st.actor, cfg)?)
}

async fn assistant_chat(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.chat_get(id)?)
}

#[derive(Deserialize)]
struct SendBody {
    chat_id: Option<i64>,
    text: String,
}

async fn assistant_send(State(st): State<AppState>, Json(b): Json<SendBody>) -> ApiResult {
    if b.text.trim().is_empty() {
        return Err(ServiceError::Invalid("write a message".into()).into());
    }
    ok(st.assistant.send(b.chat_id, &b.text).await?)
}

async fn network_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.network_get()?)
}

async fn network_put(State(st): State<AppState>, Json(cfg): Json<pm_service::pm_replay::NetConfig>) -> ApiResult {
    ok(st.service.network_set(&st.actor, cfg)?)
}

async fn recording_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.recording_get()?)
}

async fn recording_put(State(st): State<AppState>, Json(r): Json<pm_service::RecordingSettings>) -> ApiResult {
    ok(st.service.recording_set(&st.actor, r)?)
}

async fn session_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.session_get(&st.actor)?)
}

async fn session_put(State(st): State<AppState>, Json(cfg): Json<pm_service::SessionConfig>) -> ApiResult {
    ok(st.service.session_set(&st.actor, cfg)?)
}

async fn session_jar(State(st): State<AppState>) -> ApiResult {
    ok(json!({ "cookies": st.service.session_jar(&st.actor)? }))
}

async fn session_jar_clear(State(st): State<AppState>) -> ApiResult {
    st.service.session_jar_clear(&st.actor)?;
    ok(json!({ "cleared": true }))
}

async fn session_macro_run(State(st): State<AppState>, Path(name): Path<String>) -> ApiResult {
    ok(st.service.session_macro_run(&st.actor, &name).await?)
}

#[derive(Deserialize)]
struct ListenersBody {
    listeners: Vec<pm_service::pm_proxy::ListenerConfig>,
}

async fn listeners_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.listeners_get()?)
}

async fn listeners_put(State(st): State<AppState>, Json(b): Json<ListenersBody>) -> ApiResult {
    ok(st.service.listeners_set(&st.actor, b.listeners)?)
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
