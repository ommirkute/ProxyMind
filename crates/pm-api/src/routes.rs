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

/// Request size limit for imported API descriptions.
const SPEC_LIMIT: usize = 32 * 1024 * 1024;

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
        .route("/search/ws", post(search_ws))
        .route("/sitemap", get(sitemap))
        .route("/exchanges/{id}/ws", get(ws_messages))
        .route("/exchanges/{id}/annotation", axum::routing::put(annotate))
        .route("/ws/history", get(ws_history))
        .route(
            "/ui/{key}",
            get(ui_get).put(ui_put).layer(axum::extract::DefaultBodyLimit::max(pm_service::UI_STATE_MAX + 1024)),
        )
        .route("/exchanges/{id}/curl", get(exchange_curl))
        .route("/exchanges/{id}/code", get(exchange_code))
        .route("/tools/code", post(tools_code))
        .route("/match-replace/presets", get(rules_presets))
        .route(
            "/import/har",
            post(import_har).layer(axum::extract::DefaultBodyLimit::max(pm_service::MAX_IMPORT_BYTES + 1024)),
        )
        .route("/export/har", post(export_har))
        .route("/tools/curl", post(tools_curl))
        .route("/ws/replay", post(ws_replay))
        .route("/race", post(race))
        .route("/replay/group", post(replay_group))
        .route("/fuzzer", post(fuzzer))
        .route("/fuzzer/attacks", get(attacks_list).post(attack_start))
        .route("/fuzzer/attacks/{id}", get(attack_status))
        .route("/fuzzer/attacks/{id}/{action}", post(attack_control))
        .route("/crawl", post(crawl))
        .route("/discover", post(discover))
        .route("/tools/decode", post(tools_decode))
        .route("/tools/request-transform", post(tools_request_transform))
        .route("/tools/compare", post(tools_compare))
        .route("/tools/token-analyzer", post(tools_token_analyzer))
        .route("/tools/token-analyzer/analyze", post(tools_token_analyzer_analyze))
        .route("/openapi", get(openapi_get))
        // API descriptions are often larger than the 2 MB default.
        .route("/openapi/import", post(openapi_import).layer(axum::extract::DefaultBodyLimit::max(SPEC_LIMIT)))
        .route("/graphql", get(graphql_get))
        .route("/graphql/import", post(graphql_import).layer(axum::extract::DefaultBodyLimit::max(SPEC_LIMIT)))
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
        .route("/scan/tasks/{id}/pause", post(scan_task_pause))
        .route("/scan/tasks/{id}/resume", post(scan_task_resume))
        .route("/collaborator", get(collaborator_status))
        .route("/collaborator/listener", post(collaborator_listen))
        .route("/collaborator/smtp", post(collaborator_smtp))
        .route("/collaborator/payloads", get(collaborator_payloads).post(collaborator_payload))
        .route("/collaborator/interactions", get(collaborator_interactions))
        .route("/collaborator/probes", get(collaborator_probes))
        .route("/organizer", get(organizer_list).post(organizer_add))
        .route("/organizer/{id}", axum::routing::patch(organizer_update).delete(organizer_delete))
        .route("/engage/comments", post(engage_comments))
        .route("/engage/scripts", post(engage_scripts))
        .route("/engage/js-endpoints", post(engage_js_endpoints))
        .route("/update", get(update_get).put(update_set))
        .route("/skills", get(skills_list))
        .route("/skills/{name}", post(skill_get))
        .route("/update/check", post(update_check))
        .route("/engage/analyze", post(engage_analyze))
        .route("/engage/references", post(engage_references))
        .route("/engage/csrf", post(engage_csrf))
        .route("/engage/clickjacking", post(engage_clickjacking))
        .route("/plugins", get(plugins))
        .route("/plugins/check", post(plugin_check))
        .route("/plugins/{name}", axum::routing::put(plugin_set))
        .route("/plugins/{name}/panels/{panel}", get(plugin_panel))
        .route("/scan/profiles", get(scan_profiles).post(scan_profile_save))
        .route("/scan/custom-checks", get(custom_checks).post(custom_check_save))
        .route("/scan/custom-checks/{id}", axum::routing::delete(custom_check_delete))
        .route("/scan/custom", post(custom_scan))
        .route("/dom/test", post(dom_test))
        .route("/scan/profiles/{name}", axum::routing::delete(scan_profile_delete))
        .route("/scan/schedules", get(scan_schedules).post(scan_schedule_save))
        .route("/scan/schedules/{id}", axum::routing::delete(scan_schedule_delete))
        .route("/scan/schedules/{id}/run", post(scan_schedule_run))
        .route("/hypotheses", get(hypotheses))
        .route("/findings", get(findings).post(finding_create))
        .route("/findings/{id}", get(finding).patch(finding_update))
        .route("/findings/{id}/retest", post(finding_retest))
        .route("/library", get(library))
        .route("/report/templates", get(report_templates).post(report_template_save))
        .route("/report/templates/{name}", axum::routing::delete(report_template_delete))
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
        .route("/assistant/key", axum::routing::put(model_key_set))
        .route("/assistant/key/{name}", axum::routing::delete(model_key_remove))
        .route("/assistant/chats/{id}", get(assistant_chat))
        .route("/assistant/send", post(assistant_send))
        .route("/ai-scan", get(ai_scan_list).post(ai_scan_start))
        .route("/ai-scan/prompt", get(ai_scan_prompt))
        .route("/ai-scan/{id}", get(ai_scan_get))
        .route("/ai-scan/{id}/stop", post(ai_scan_stop))
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

async fn scan_task_pause(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    ok(st.service.scan_task_pause(&st.actor, &id)?)
}

async fn scan_task_resume(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    ok(st.service.scan_task_resume(&st.actor, &id)?)
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct ProbesQuery {
    limit: Option<usize>,
}

async fn collaborator_probes(State(st): State<AppState>, Query(q): Query<ProbesQuery>) -> ApiResult {
    ok(st.service.collaborator_probes(q.limit.unwrap_or(200))?)
}

async fn collaborator_status(State(st): State<AppState>) -> ApiResult {
    ok(st.service.collaborator_status()?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ListenBody {
    listen: String,
    public_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SmtpBody {
    listen: String,
}

async fn collaborator_smtp(State(st): State<AppState>, Json(b): Json<SmtpBody>) -> ApiResult {
    let addr = b
        .listen
        .trim()
        .parse()
        .map_err(|_| pm_service::ServiceError::Invalid(format!("listen on host:port, not {:?}", b.listen)))?;
    ok(st.service.collaborator_smtp(&st.actor, addr).await?)
}

async fn collaborator_listen(State(st): State<AppState>, Json(b): Json<ListenBody>) -> ApiResult {
    let addr = b
        .listen
        .trim()
        .parse()
        .map_err(|_| pm_service::ServiceError::Invalid(format!("listen on host:port, not {:?}", b.listen)))?;
    ok(st.service.collaborator_listen(&st.actor, addr, b.public_url).await?)
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct PayloadBody {
    note: String,
}

async fn collaborator_payload(State(st): State<AppState>, Json(b): Json<PayloadBody>) -> ApiResult {
    ok(st.service.collaborator_payload(&st.actor, &b.note)?)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct OrganizerQuery {
    status: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OrganizerAdd {
    exchange_id: i64,
    #[serde(default)]
    note: String,
}

async fn organizer_list(State(st): State<AppState>, Query(q): Query<OrganizerQuery>) -> ApiResult {
    ok(st.service.organizer_list(&st.actor, q.status.as_deref().filter(|s| !s.is_empty()))?)
}

async fn organizer_add(State(st): State<AppState>, Json(b): Json<OrganizerAdd>) -> ApiResult {
    ok(st.service.organizer_add(&st.actor, b.exchange_id, &b.note)?)
}

async fn organizer_update(
    State(st): State<AppState>,
    Path(id): Path<i64>,
    Json(u): Json<pm_service::OrganizerUpdate>,
) -> ApiResult {
    ok(st.service.organizer_update(&st.actor, id, &u)?)
}

async fn organizer_delete(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    st.service.organizer_delete(&st.actor, id)?;
    ok(json!({ "deleted": id }))
}

#[derive(serde::Deserialize)]
struct CollabQuery {
    limit: Option<usize>,
    token: Option<String>,
}

async fn collaborator_payloads(State(st): State<AppState>, Query(q): Query<CollabQuery>) -> ApiResult {
    ok(st.service.collaborator_payloads(q.limit.unwrap_or(100))?)
}

async fn collaborator_interactions(State(st): State<AppState>, Query(q): Query<CollabQuery>) -> ApiResult {
    ok(st.service.collaborator_interactions(q.token.as_deref().filter(|t| !t.is_empty()), q.limit.unwrap_or(200))?)
}

async fn engage_comments(State(st): State<AppState>, Json(f): Json<pm_service::EngageFilter>) -> ApiResult {
    ok(st.service.engage_comments(&st.actor, &f)?)
}

async fn engage_scripts(State(st): State<AppState>, Json(f): Json<pm_service::EngageFilter>) -> ApiResult {
    ok(st.service.engage_scripts(&st.actor, &f)?)
}

async fn skills_list(State(st): State<AppState>) -> ApiResult {
    ok(st.service.skills_list()?)
}

async fn skill_get(
    State(st): State<AppState>,
    Path(name): Path<String>,
    Json(args): Json<std::collections::BTreeMap<String, String>>,
) -> ApiResult {
    let (skill, text) = st.service.skill_get(&name, &args)?;
    ok(json!({ "skill": skill, "text": text }))
}

async fn update_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.update_get()?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateSet {
    enabled: bool,
}

async fn update_set(State(st): State<AppState>, Json(b): Json<UpdateSet>) -> ApiResult {
    ok(st.service.update_set(&st.actor, b.enabled)?)
}

#[derive(Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct UpdateCheck {
    /// Ask now even if the daily check is off or the last answer is fresh.
    force: bool,
}

async fn update_check(State(st): State<AppState>, Json(b): Json<UpdateCheck>) -> ApiResult {
    ok(st.service.update_check(&st.actor, b.force).await?)
}

async fn engage_js_endpoints(State(st): State<AppState>, Json(f): Json<pm_service::EngageFilter>) -> ApiResult {
    ok(st.service.engage_js_endpoints(&st.actor, &f)?)
}

async fn engage_analyze(State(st): State<AppState>, Json(f): Json<pm_service::EngageFilter>) -> ApiResult {
    ok(st.service.engage_analyze(&st.actor, &f)?)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EngageExchange {
    exchange_id: i64,
    #[serde(default)]
    technique: pm_service::pm_tools::engage::CsrfTechnique,
    #[serde(default)]
    auto_submit: bool,
}

async fn engage_references(State(st): State<AppState>, Json(b): Json<EngageExchange>) -> ApiResult {
    ok(st.service.engage_references(&st.actor, b.exchange_id, &Default::default())?)
}

async fn engage_csrf(State(st): State<AppState>, Json(b): Json<EngageExchange>) -> ApiResult {
    ok(json!({ "html": st.service.engage_csrf_poc(&st.actor, b.exchange_id, b.technique, b.auto_submit)? }))
}

async fn engage_clickjacking(State(st): State<AppState>, Json(b): Json<EngageExchange>) -> ApiResult {
    ok(st.service.engage_clickjacking(b.exchange_id)?)
}

async fn plugins(State(st): State<AppState>) -> ApiResult {
    ok(st.service.plugin_list())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginSet {
    enabled: bool,
}

async fn plugin_set(State(st): State<AppState>, Path(name): Path<String>, Json(b): Json<PluginSet>) -> ApiResult {
    ok(st.service.plugin_set_enabled(&st.actor, &name, b.enabled)?)
}

#[derive(Deserialize)]
struct PanelQuery {
    limit: Option<usize>,
}

async fn plugin_panel(
    State(st): State<AppState>,
    Path((name, panel)): Path<(String, String)>,
    Query(q): Query<PanelQuery>,
) -> ApiResult {
    ok(st.service.plugin_panel(&st.actor, &name, &panel, q.limit)?)
}

async fn plugin_check(State(st): State<AppState>, Json(r): Json<pm_service::PluginCheckRequest>) -> ApiResult {
    ok(st.service.plugin_check(&st.actor, r).await?)
}

async fn scan_profiles(State(st): State<AppState>) -> ApiResult {
    ok(st.service.scan_profiles()?)
}

async fn scan_profile_save(State(st): State<AppState>, Json(p): Json<pm_service::ScanProfile>) -> ApiResult {
    ok(st.service.scan_profile_save(&st.actor, p)?)
}

async fn dom_test(State(st): State<AppState>, Json(r): Json<pm_service::DomTestRequest>) -> ApiResult {
    ok(st.service.dom_test(&st.actor, r).await?)
}

async fn custom_checks(State(st): State<AppState>) -> ApiResult {
    ok(st.service.custom_checks()?)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckYaml {
    yaml: String,
}

async fn custom_check_save(State(st): State<AppState>, Json(b): Json<CheckYaml>) -> ApiResult {
    ok(st.service.custom_check_save(&st.actor, &b.yaml)?)
}

async fn custom_check_delete(State(st): State<AppState>, Path(id): Path<String>) -> ApiResult {
    ok(serde_json::json!({ "deleted": st.service.custom_check_delete(&st.actor, &id)? }))
}

async fn custom_scan(State(st): State<AppState>, Json(r): Json<pm_service::CustomScanRequest>) -> ApiResult {
    ok(st.service.custom_scan(&st.actor, r).await?)
}

async fn scan_profile_delete(State(st): State<AppState>, Path(name): Path<String>) -> ApiResult {
    ok(serde_json::json!({ "deleted": st.service.scan_profile_delete(&st.actor, &name)? }))
}

async fn scan_schedules(State(st): State<AppState>) -> ApiResult {
    ok(st.service.schedule_list()?)
}

async fn scan_schedule_save(State(st): State<AppState>, Json(s): Json<pm_service::ScanSchedule>) -> ApiResult {
    ok(st.service.schedule_save(&st.actor, s)?)
}

async fn scan_schedule_delete(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(serde_json::json!({ "deleted": st.service.schedule_delete(&st.actor, id)? }))
}

async fn scan_schedule_run(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.schedule_run_now(&st.actor, id)?)
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
    template: Option<String>,
    min_severity: Option<String>,
    /// Comma-separated statuses to include.
    statuses: Option<String>,
    evidence: Option<bool>,
}

async fn report(State(st): State<AppState>, Query(q): Query<ReportQuery>) -> Result<Response, ApiError> {
    let opts = pm_service::ReportOptions {
        min_severity: q.min_severity.clone(),
        statuses: q
            .statuses
            .as_deref()
            .map(|s| s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect())
            .unwrap_or_default(),
        evidence: q.evidence,
    };
    let format = q.format.as_deref().unwrap_or("md");
    let r = st.service.report_render(q.template.as_deref(), format, &opts).await?;
    // Always a download: reports hold target content (escaped, with their own
    // CSP). The UI previews HTML in a sandboxed srcdoc frame instead.
    let disposition = format!("attachment; filename=\"proxymind-report.{}\"", r.extension);
    Ok(([(header::CONTENT_TYPE, r.content_type.to_string()), (header::CONTENT_DISPOSITION, disposition)], r.body)
        .into_response())
}

async fn finding_retest(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.finding_retest(&st.actor, id).await?)
}

async fn library() -> ApiResult {
    ok(pm_service::pm_scan::library::LIBRARY)
}

async fn report_templates(State(st): State<AppState>) -> ApiResult {
    ok(st.service.report_templates()?)
}

async fn report_template_save(State(st): State<AppState>, Json(t): Json<pm_service::ReportTemplate>) -> ApiResult {
    ok(st.service.report_template_save(&st.actor, t)?)
}

async fn report_template_delete(State(st): State<AppState>, Path(name): Path<String>) -> ApiResult {
    ok(serde_json::json!({ "deleted": st.service.report_template_delete(&st.actor, &name)? }))
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

async fn search_ws(State(st): State<AppState>, Json(r): Json<pm_service::WsSearchRequest>) -> ApiResult {
    ok(st.service.ws_search_text(&st.actor, &r)?)
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

#[derive(serde::Deserialize)]
struct CodeQuery {
    lang: pm_service::pm_tools::codegen::Lang,
}

async fn exchange_code(State(st): State<AppState>, Path(id): Path<i64>, Query(q): Query<CodeQuery>) -> ApiResult {
    ok(json!({ "code": st.service.exchange_code(&st.actor, id, q.lang)? }))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeBody {
    url: String,
    raw: String,
    lang: pm_service::pm_tools::codegen::Lang,
}

async fn tools_code(State(st): State<AppState>, Json(b): Json<CodeBody>) -> ApiResult {
    ok(json!({ "code": st.service.request_code(&b.url, &b.raw, b.lang)? }))
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

async fn tools_request_transform(State(st): State<AppState>, Json(t): Json<pm_service::RequestTransform>) -> ApiResult {
    ok(st.service.request_transform(&t)?)
}

#[derive(serde::Deserialize)]
struct CompareBody {
    a: i64,
    b: i64,
}

async fn tools_compare(State(st): State<AppState>, Json(r): Json<CompareBody>) -> ApiResult {
    ok(st.service.compare_exchanges(&st.actor, r.a, r.b)?)
}

async fn tools_token_analyzer(
    State(st): State<AppState>,
    Json(r): Json<pm_service::TokenAnalyzerRequest>,
) -> ApiResult {
    ok(st.service.token_analyzer_run(&st.actor, r).await?)
}

#[derive(serde::Deserialize)]
struct TokensBody {
    tokens: Vec<String>,
}

async fn tools_token_analyzer_analyze(State(st): State<AppState>, Json(r): Json<TokensBody>) -> ApiResult {
    ok(st.service.token_analyzer_analyze(&r.tokens)?)
}

async fn crawl(State(st): State<AppState>, Json(r): Json<pm_service::CrawlRequest>) -> ApiResult {
    ok(st.service.crawl(&st.actor, r).await?)
}

async fn fuzzer(State(st): State<AppState>, Json(r): Json<pm_service::FuzzerRequest>) -> ApiResult {
    ok(st.service.fuzzer_run(&st.actor, r).await?)
}

async fn attack_start(State(st): State<AppState>, Json(r): Json<pm_service::FuzzerRequest>) -> ApiResult {
    ok(st.service.fuzzer_start(&st.actor, r)?)
}

async fn attacks_list(State(st): State<AppState>) -> ApiResult {
    ok(st.service.fuzzer_list(&st.actor))
}

#[derive(serde::Deserialize)]
struct FromQuery {
    from: Option<usize>,
}

async fn attack_status(State(st): State<AppState>, Path(id): Path<String>, Query(q): Query<FromQuery>) -> ApiResult {
    ok(st.service.fuzzer_status(&st.actor, &id, q.from.unwrap_or(0))?)
}

async fn attack_control(State(st): State<AppState>, Path((id, action)): Path<(String, String)>) -> ApiResult {
    ok(json!({ "status": st.service.fuzzer_control(&st.actor, &id, &action)? }))
}

async fn replay_group(State(st): State<AppState>, Json(r): Json<pm_service::GroupRequest>) -> ApiResult {
    ok(st.service.replay_group(&st.actor, r).await?)
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBody {
    name: String,
    key: String,
}

async fn model_key_set(State(st): State<AppState>, Json(b): Json<KeyBody>) -> ApiResult {
    ok(st.service.model_key_set(&st.actor, &b.name, &b.key)?)
}

async fn model_key_remove(State(st): State<AppState>, Path(name): Path<String>) -> ApiResult {
    ok(st.service.model_key_remove(&st.actor, &name)?)
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
        "key": st.service.model_key_status(&config.api_key_env),
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

async fn ai_scan_start(State(st): State<AppState>, Json(req): Json<pm_service::AiScanRequest>) -> ApiResult {
    ok(st.assistant.start_ai_scan(&st.actor, req)?)
}

async fn ai_scan_list(State(st): State<AppState>) -> ApiResult {
    ok(st.service.ai_scan_list(50)?)
}

async fn ai_scan_get(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.ai_scan_get(id)?)
}

async fn ai_scan_stop(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.ai_scan_stop(&st.actor, id)?)
}

/// The system prompt a scan would get (with the default target).
async fn ai_scan_prompt(State(st): State<AppState>) -> ApiResult {
    let target = st.service.policy().roe().include.first().map(|p| p.text.clone()).unwrap_or_default();
    ok(json!({ "target": target, "prompt": st.service.ai_scan_prompt(&target, "")? }))
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

async fn rules_presets(State(st): State<AppState>) -> ApiResult {
    ok(st.service.match_replace_presets())
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
