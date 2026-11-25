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
use pm_service::api_types::{
    AiScanMessage, AnnotationBody, CaptureBody, ChangesQuery, CheckYaml, CodeBody, CodeQuery, CollabQuery, CompareBody,
    CoverageQuery, CurlBody, EngageExchange, ExchangeQuery, ExplainBody, ForwardBody, FromQuery, HostQuery, KeyBody,
    LimitQuery, ListenBody, ListenersBody, OrganizerAdd, OrganizerQuery, PackQuery, PanelQuery, PayloadBody, PluginSet,
    ProbesQuery, ReconDns, ReconWayback, RecordLoginBody, ReportQuery, RoeBody, RulesBody, ScanQuery, SendBody,
    SiteQuery, SmtpBody, SnapshotBody, StatusQuery, TokensBody, TriageBody, UpdateCheck, UpdateSet,
    UpstreamResolveRequest, WorkflowRunBody, WorkflowRunsQuery, WorkflowTriggerBody, WsHistoryQuery, WsQuery,
};
use pm_service::pm_ai::View;
use pm_service::pm_store::HistoryFilter;
use pm_service::{
    AuthzCheckRequest, DeliveriesQuery, FindingUpdate, IntegrationEnabledBody, IntegrationInput, ModelFilter,
    NewFinding, ProofRequest, ReplayRequest, SendFindingBody, ServiceError, TrustConfirmRequest,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth_api::{
    AUTH_BODY_LIMIT, auth_invite_accept, auth_invite_create, auth_invite_revoke, auth_invites, auth_login,
    auth_login_enrol, auth_login_enrol_confirm, auth_login_second_factor, auth_logout, auth_me, auth_member_remove,
    auth_member_set, auth_members, auth_password, auth_recovery_codes, auth_session_revoke, auth_sessions,
    auth_sessions_revoke_all, auth_setup, auth_state, auth_totp_begin, auth_totp_confirm, auth_totp_disable,
    auth_user_disable, auth_user_enable, auth_user_reset_second_factor, auth_users,
};
use crate::mcp_api::{MCP_BODY_LIMIT, mcp_endpoint};
use crate::server_mode::Me;
use crate::tokens_api::{token_create, token_revoke, tokens_list};
use pm_service::access::Role;

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
        ServiceError::Forbidden(_) => StatusCode::FORBIDDEN,
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

/// What `me` may read of `v`: a viewer gets the redacted view agents get (secrets replaced by placeholders, evidence
/// marked as target content); everyone else reads it as stored.
fn shown<T: serde::Serialize>(st: &AppState, me: &Me, v: T) -> ApiResult {
    let v = serde_json::to_value(v).unwrap_or(Value::Null);
    Ok(Json(if st.service.is_viewer(&me.actor) { st.service.json_for(&me.actor, v) } else { v }))
}

/// Request size limit for imported API descriptions.
const SPEC_LIMIT: usize = 32 * 1024 * 1024;

pub fn api() -> Router<AppState> {
    Router::new()
        .route("/status", get(status))
        .route("/roe", get(roe_get).put(roe_put))
        .route("/setup", get(setup))
        .route("/setup/mobile", get(setup_mobile))
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
        .route("/streams", get(streams_list))
        .route("/streams/{id}", get(stream_get))
        .route("/streams/{id}/chunks", get(stream_chunks))
        .route("/streams/{id}/replay", post(stream_replay).layer(axum::extract::DefaultBodyLimit::max(24 << 20)))
        .route("/race", post(race))
        .route("/replay/group", post(replay_group))
        .route("/fuzzer", post(fuzzer))
        .route("/fuzzer/attacks", get(attacks_list).post(attack_start))
        .route("/fuzzer/attacks/{id}", get(attack_status))
        .route("/fuzzer/attacks/{id}/{action}", post(attack_control))
        .route("/crawl", post(crawl))
        .route("/discover", post(discover))
        .route("/tools/decode", post(tools_decode))
        .route("/tools/protobuf/decode", post(tools_protobuf_decode))
        .route("/tools/protobuf/encode", post(tools_protobuf_encode))
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
        .route("/authz/matrix", post(authz_matrix))
        .route("/model/snapshots", get(model_snapshots).post(model_snapshot_save))
        .route("/model/changes", get(model_changes))
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
        .route("/engage/logic", post(engage_logic))
        .route("/traffic/triage", post(traffic_triage))
        .route("/memory", get(memory_list))
        .route("/memory/{id}", axum::routing::delete(memory_delete))
        .route("/update", get(update_get).put(update_set))
        .route("/skills", get(skills_list))
        .route("/skills/{name}", post(skill_get))
        .route("/update/check", post(update_check))
        .route("/recon/dns", post(recon_dns))
        .route("/recon/wayback", post(recon_wayback))
        .route("/engage/analyze", post(engage_analyze))
        .route("/engage/references", post(engage_references))
        .route("/engage/csrf", post(engage_csrf))
        .route("/engage/clickjacking", post(engage_clickjacking))
        .route("/plugins", get(plugins))
        .route("/plugins/check", post(plugin_check))
        .route("/plugins/{name}", axum::routing::put(plugin_set))
        .route("/plugins/{name}/accept", post(plugin_accept))
        .route("/plugins/{name}/hooks/{kind}", axum::routing::put(plugin_hook_set))
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
        .route("/findings/{id}/prove", post(finding_prove))
        .route("/findings/prove", post(findings_prove_all))
        .route("/library", get(library))
        .route("/report/templates", get(report_templates).post(report_template_save))
        .route("/report/templates/{name}", axum::routing::delete(report_template_delete))
        .route("/proofs", post(proof_run))
        .route("/proofs/{id}", get(proof))
        .route("/proofs/{id}/rerun", post(proof_rerun))
        .route("/audit", get(audit))
        .route("/audit/verify", get(audit_verify))
        .route("/audit/checkpoint", post(audit_checkpoint))
        .route("/audit/checkpoints", get(audit_checkpoints))
        .route("/report", get(report))
        .route("/evidence/pack", get(evidence_pack))
        .route("/evidence/fingerprint", get(evidence_fingerprint))
        .route("/evidence/verify", post(evidence_verify).layer(axum::extract::DefaultBodyLimit::max(EVIDENCE_LIMIT)))
        .route("/coverage/proof", get(coverage_proof))
        .route("/regress", get(regress_list))
        .route("/regress/export", get(regress_export))
        .route("/intercept", get(intercept_state))
        .route("/intercept/settings", axum::routing::put(intercept_settings))
        .route("/intercept/forward-all", post(intercept_forward_all))
        .route("/intercept/{id}/forward", post(intercept_forward))
        .route("/intercept/{id}/drop", post(intercept_drop))
        .route("/match-replace", get(rules_get).put(rules_put))
        .route("/network", get(network_get).put(network_put))
        .route("/network/upstream/resolve", post(network_resolve))
        .route("/proxy/listeners", get(listeners_get).put(listeners_put))
        .route("/history/recording", get(recording_get).put(recording_put))
        .route("/devices", get(devices_get))
        .route("/devices/{addr}", axum::routing::put(device_put).delete(device_delete))
        .route("/session", get(session_get).put(session_put))
        .route("/session/jar", get(session_jar).delete(session_jar_clear))
        .route("/session/macros/{name}/run", post(session_macro_run))
        .route("/workflows", get(workflows_list).post(workflow_create))
        .route("/workflows/runs", get(workflow_runs))
        .route("/workflows/runs/{id}", get(workflow_run_get))
        .route("/workflows/{id}", get(workflow_get).put(workflow_update).delete(workflow_delete))
        .route("/workflows/{id}/trigger", axum::routing::put(workflow_trigger))
        .route("/workflows/{id}/run", post(workflow_run))
        .route("/integrations", get(integrations_list))
        .route("/integrations/{name}", get(integration_get).put(integration_put).delete(integration_delete))
        .route("/integrations/{name}/enabled", axum::routing::put(integration_enabled))
        .route("/integrations/{name}/test", post(integration_test))
        .route("/integrations/{name}/deliveries", get(integration_deliveries))
        .route("/project/trust", get(project_trust).post(project_trust_confirm))
        .route("/findings/{id}/issue", post(finding_issue))
        .route("/assistant", get(assistant_state))
        .route("/assistant/config", axum::routing::put(assistant_config))
        .route("/assistant/key", axum::routing::put(model_key_set))
        .route("/assistant/key/{name}", axum::routing::delete(model_key_remove))
        .route("/assistant/chats/{id}", get(assistant_chat))
        .route("/assistant/send", post(assistant_send))
        .route("/assistant/models", post(assistant_models))
        .route("/findings/{id}/explain", post(finding_explain))
        .route("/ai-scan", get(ai_scan_list).post(ai_scan_start))
        .route("/ai-scan/prompt", get(ai_scan_prompt))
        .route("/ai-scan/{id}", get(ai_scan_get))
        .route("/ai-scan/{id}/stop", post(ai_scan_stop))
        .route("/ai-scan/{id}/message", post(ai_scan_message))
        .route("/attack-paths", get(attack_paths).post(attack_path_create))
        .route("/attack-paths/{id}", axum::routing::delete(attack_path_delete))
        .route("/attack-graph", get(attack_graph))
        // Tokens (ADR-0022 step 5), both modes: people manage them, a token never does. The MCP endpoint is what
        // `proxymind mcp --server` talks to.
        .route(
            "/tokens",
            get(tokens_list).post(token_create).layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_LIMIT)),
        )
        .route("/tokens/{id}", axum::routing::delete(token_revoke))
        .route("/mcp", post(mcp_endpoint).layer(axum::extract::DefaultBodyLimit::max(MCP_BODY_LIMIT)))
        // Server mode (ADR-0022 step 4): accounts and sessions. Every handler answers 404 in single-user mode.
        .route("/auth/state", get(auth_state))
        .route("/auth/setup", post(auth_setup).layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_LIMIT)))
        .route("/auth/login", post(auth_login).layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_LIMIT)))
        .route(
            "/auth/login/second-factor",
            post(auth_login_second_factor).layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_LIMIT)),
        )
        .route("/auth/login/enrol", post(auth_login_enrol).layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_LIMIT)))
        .route(
            "/auth/login/enrol/confirm",
            post(auth_login_enrol_confirm).layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_LIMIT)),
        )
        .route(
            "/auth/invite/accept",
            post(auth_invite_accept).layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_LIMIT)),
        )
        .route("/auth/me", get(auth_me))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/sessions", get(auth_sessions))
        .route("/auth/sessions/revoke-all", post(auth_sessions_revoke_all))
        .route("/auth/sessions/{reference}", axum::routing::delete(auth_session_revoke))
        .route("/auth/password", post(auth_password).layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_LIMIT)))
        .route("/auth/totp/begin", post(auth_totp_begin))
        .route(
            "/auth/totp/confirm",
            post(auth_totp_confirm).layer(axum::extract::DefaultBodyLimit::max(AUTH_BODY_LIMIT)),
        )
        .route("/auth/totp/disable", post(auth_totp_disable))
        .route("/auth/recovery-codes", post(auth_recovery_codes))
        .route("/auth/members", get(auth_members))
        .route("/auth/members/{user_id}", axum::routing::put(auth_member_set).delete(auth_member_remove))
        .route("/auth/users", get(auth_users))
        .route("/auth/users/{id}/disable", post(auth_user_disable))
        .route("/auth/users/{id}/enable", post(auth_user_enable))
        .route("/auth/users/{id}/reset-second-factor", post(auth_user_reset_second_factor))
        .route("/auth/invites", get(auth_invites).post(auth_invite_create))
        .route("/auth/invites/{id}", axum::routing::delete(auth_invite_revoke))
}

#[derive(Deserialize)]
pub struct AuthQuery {
    token: String,
}

/// Exchanges the token from the launch URL for an HttpOnly cookie, so it
/// doesn't stay in the address bar or history.
pub async fn auth(State(st): State<AppState>, Query(q): Query<AuthQuery>) -> Response {
    // The install token opens a session in single-user mode only.
    if st.server.is_some() {
        return StatusCode::NOT_FOUND.into_response();
    }
    if !crate::constant_eq(q.token.as_bytes(), st.token.as_bytes()) {
        return (StatusCode::UNAUTHORIZED, "wrong token").into_response();
    }
    let cookie = format!("pm_token={}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000", st.token);
    ([(header::SET_COOKIE, cookie)], Redirect::to("/")).into_response()
}

async fn status(State(st): State<AppState>, me: Me) -> ApiResult {
    let roe = st.service.policy().roe();
    ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "project": *st.project,
        "you_are": me.actor.id(),
        "engagement": roe.engagement.name,
        "in_scope": roe.include.iter().map(|p| &p.text).collect::<Vec<_>>(),
        "counters": st.service.counters()?,
        "safe_mode": st.service.safe_mode(),
    }))
}

/// Query of `GET /events`.
#[derive(Deserialize, schemars::JsonSchema)]
pub(crate) struct EventsQuery {
    /// Comma-separated topics, or `all`; `counters` adds the legacy event. Missing: only the legacy `counters` event.
    topics: Option<String>,
}

/// The legacy `counters` event's coalescing window and how often it re-reads the store for changes made by other
/// processes (they publish nothing on this process's bus).
const COUNTERS_EVERY: Duration = Duration::from_millis(250);
const COUNTERS_RELOAD: Duration = Duration::from_secs(5);
/// How often an open stream re-checks that its session or token still holds (server mode).
const WATCH_EVERY: Duration = Duration::from_secs(2);

fn bad_topics(msg: String) -> Response {
    ApiError::Service(ServiceError::Invalid(msg)).into_response()
}

/// Server-sent events (ADR-0018).
///
/// - No `topics`: the legacy stream, one `counters` event (the `Counters` JSON, unchanged) now and whenever a
///   relevant event arrives, at most every 250 ms.
/// - `?topics=exchanges,findings`: typed events as `event: <topic>`, `id: <seq>`, `data: <json>`. `topics=all` means
///   every topic this actor may read, and `counters` may be listed to get the legacy event too. An unknown topic is
///   a 400, a topic the actor may not read a 403.
/// - A subscriber that falls behind gets one `resync` event (`{"missed": n}`) and the stream goes on; so does a
///   reconnect whose `Last-Event-ID` is not the newest seq (nothing is replayed).
///
/// What each event shows is decided by `Service::event_for` for this process's actor.
async fn events(
    State(st): State<AppState>,
    me: Me,
    Query(q): Query<EventsQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Response, ApiError> {
    use pm_service::Topic;
    let mut topics: Vec<Topic> = Vec::new();
    let (mut counters, typed) = (false, q.topics.is_some());
    match q.topics.as_deref() {
        None => counters = true,
        Some(list) => {
            for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                match name {
                    "counters" => counters = true,
                    "all" => topics.extend(Topic::ALL.into_iter().filter(|t| st.service.may_read_topic(&me.actor, *t))),
                    other => match Topic::parse(other) {
                        Some(t) if st.service.may_read_topic(&me.actor, t) => topics.push(t),
                        Some(t) => {
                            let msg = format!("{} may not read topic {}", me.actor.id(), t.as_str());
                            return Ok((StatusCode::FORBIDDEN, Json(json!({ "error": msg }))).into_response());
                        }
                        None => {
                            let known: Vec<_> = Topic::ALL.iter().map(|t| t.as_str()).collect();
                            return Ok(bad_topics(format!(
                                "unknown topic {other:?}; use counters, all or any of {}",
                                known.join(", ")
                            )));
                        }
                    },
                }
            }
            if topics.is_empty() && !counters {
                return Ok(bad_topics("topics is empty".into()));
            }
        }
    }
    // Subscribe before reading the counters, so nothing published in between is missed.
    let sub = st.service.subscribe();
    let tracker = if counters { Some(st.service.counter_tracker()?) } else { None };
    let mut queue = std::collections::VecDeque::new();
    if typed
        && let Some(last) =
            headers.get("last-event-id").and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok())
        && last != sub.latest_seq()
    {
        queue.push_back(resync_event(sub.latest_seq().saturating_sub(last).max(1)));
    }
    // Server mode: the stream is only as long-lived as the sign-in or token that opened it, and as privileged as that
    // account is now (checked again every couple of seconds and at the next event).
    let watch = st.server.is_some().then(|| (me.clone(), tokio::time::Instant::now() + WATCH_EVERY));
    let state = EventStream {
        role: me.role(),
        st,
        watch,
        actor: me.actor.clone(),
        sub,
        topics,
        tracker,
        queue,
        last_sent: None,
        sent: None,
        dirty: true,
        reload_at: tokio::time::Instant::now() + COUNTERS_RELOAD,
    };
    let stream = futures_util::stream::unfold(state, EventStream::next);
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()).into_response())
}

fn resync_event(missed: u64) -> Event {
    Event::default().event("resync").data(json!({ "missed": missed }).to_string())
}

struct EventStream {
    st: AppState,
    /// Server mode: who opened the stream and when its sign-in or token is next checked.
    watch: Option<(Me, tokio::time::Instant)>,
    /// The role last seen for this stream's account (to tell the client when it changes).
    role: Role,
    /// Whose events these are: the actor of the request that opened the stream.
    actor: pm_service::pm_policy::Actor,
    sub: pm_service::Subscription,
    topics: Vec<pm_service::Topic>,
    /// Some when this stream sends `counters`.
    tracker: Option<pm_service::CounterTracker>,
    queue: std::collections::VecDeque<Event>,
    /// When `counters` last went out, for the 250 ms window.
    last_sent: Option<tokio::time::Instant>,
    /// The counters last sent (an unchanged snapshot is not sent again).
    sent: Option<pm_service::Counters>,
    /// Counters may have changed since they were last sent.
    dirty: bool,
    reload_at: tokio::time::Instant,
}

impl EventStream {
    async fn next(mut self) -> Option<(Result<Event, Infallible>, Self)> {
        use pm_service::Delivery;
        use tokio::time::{Instant, sleep_until};
        loop {
            if let Some(ev) = self.queue.pop_front() {
                return Some((Ok(ev), self));
            }
            if !self.still_allowed().await {
                return None;
            }
            let Some(tracker) = self.tracker.as_mut() else {
                // Typed events only.
                let wait = self.watch.as_ref().map_or(COUNTERS_RELOAD, |_| WATCH_EVERY);
                let Ok(d) = tokio::time::timeout(wait, self.sub.recv()).await else { continue };
                match d? {
                    Delivery::Resync { missed } => self.queue.push_back(resync_event(missed)),
                    Delivery::Event(p) => self.typed(&p),
                }
                continue;
            };
            let now = Instant::now();
            if now >= self.reload_at {
                self.reload_at = now + COUNTERS_RELOAD;
                if tracker.reload(&self.st.service).is_ok() {
                    self.dirty = true;
                }
            }
            if self.dirty && self.last_sent.is_none_or(|t| now >= t + COUNTERS_EVERY) {
                self.dirty = false;
                if let Ok(c) = tracker.snapshot(&self.st.service)
                    && self.sent != Some(c)
                {
                    self.sent = Some(c);
                    self.last_sent = Some(now);
                    let data = serde_json::to_string(&c).unwrap_or_default();
                    return Some((Ok(Event::default().event("counters").data(data)), self));
                }
                continue;
            }
            // Wake for the next delivery, the end of the coalescing window, or the next reload.
            let mut wake = match (self.dirty, self.last_sent) {
                (true, Some(t)) => (t + COUNTERS_EVERY).min(self.reload_at),
                _ => self.reload_at,
            };
            if let Some((_, at)) = &self.watch {
                wake = wake.min(*at);
            }
            tokio::select! {
                d = self.sub.recv() => match d? {
                    Delivery::Resync { missed } => {
                        // Counters are state: a fresh snapshot is the resync. Typed clients are told.
                        if let Some(t) = self.tracker.as_mut() {
                            let _ = t.reload(&self.st.service);
                        }
                        self.dirty = true;
                        if !self.topics.is_empty() {
                            self.queue.push_back(resync_event(missed));
                        }
                    }
                    Delivery::Event(p) => {
                        if let Some(t) = self.tracker.as_mut()
                            && t.apply(&p)
                        {
                            self.dirty = true;
                        }
                        self.typed(&p);
                    }
                },
                () = sleep_until(wake) => {}
            }
        }
    }

    /// Server mode: re-checks the sign-in or token behind this stream when it is due, and re-registers the role it
    /// holds now. `false` ends the stream (revoked session, removed member, disabled account, revoked token).
    async fn still_allowed(&mut self) -> bool {
        let Some((me, at)) = self.watch.as_mut() else { return true };
        if tokio::time::Instant::now() < *at {
            return true;
        }
        *at = tokio::time::Instant::now() + WATCH_EVERY;
        let Some(sm) = self.st.server.clone() else { return true };
        match crate::server_mode::still_valid(&sm, me).await {
            Some(role) => {
                let mut p = me.principal();
                p.role = role;
                self.st.service.register_principal(&p);
                if role != self.role {
                    // Tell the client its role changed; it reads who it is again.
                    self.role = role;
                    self.queue
                        .push_back(Event::default().event("role").data(json!({ "role": role.name() }).to_string()));
                }
                true
            }
            None => false,
        }
    }

    /// Queues a typed event if the client asked for its topic and the actor may see it.
    fn typed(&mut self, p: &pm_service::Published) {
        if !self.topics.contains(&p.topic) {
            return;
        }
        if let Some(v) = self.st.service.event_for(&self.actor, p) {
            self.queue.push_back(Event::default().event(p.topic.as_str()).id(p.seq.to_string()).data(v.to_string()));
        }
    }
}

async fn exchanges(State(st): State<AppState>, me: Me, Query(f): Query<HistoryFilter>) -> ApiResult {
    ok(st.service.history_search(&me.actor, &f)?)
}

/// Query of `GET /exchanges/{id}`.
#[derive(serde::Deserialize, schemars::JsonSchema)]
pub(crate) struct BytesQuery {
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

async fn exchange(State(st): State<AppState>, me: Me, Path(id): Path<i64>, Query(q): Query<BytesQuery>) -> ApiResult {
    st.service.require_actor(&me.actor, pm_service::access::Perm::HistoryRead)?;
    let ex = st.service.exchange_raw(id)?;
    let view = st.service.exchange_get(&me.actor, id, View::Full, 6000)?;
    let max = q.max.map(|m| m.max(1024));
    let (request, request_truncated) = capped(&ex.request, max);
    let response = ex.response.as_deref().map(|r| capped(r, max));
    // The bodies as people read them (de-chunked, decompressed, markup kept), for the Pretty and Render views; the
    // `view` is the model's, cut to a token budget and with HTML reduced to its visible text.
    let decoded = |raw: &[u8]| pm_service::pm_ai::body::decoded_text(raw).map(|t| capped(t.as_bytes(), max).0);
    let mut v = json!({
        "summary": ex.summary,
        "request": request,
        "response": response.as_ref().map(|r| &r.0),
        "request_body": decoded(&ex.request),
        "response_body": ex.response.as_deref().and_then(decoded),
        "view": view,
    });
    // gRPC and Protobuf bodies as text (per message, with the status from the trailers); absent for other traffic.
    let proto = |raw: &[u8]| pm_service::pm_ai::body::protobuf_view(raw, true).map(|(_, r)| r.text);
    if let Some(t) = proto(&ex.request) {
        v["request_protobuf"] = json!(t);
    }
    if let Some(t) = ex.response.as_deref().and_then(proto) {
        v["response_protobuf"] = json!(t);
    }
    if let Some(n) = request_truncated {
        v["request_truncated"] = json!(n);
    }
    if let Some(n) = response.and_then(|r| r.1) {
        v["response_truncated"] = json!(n);
    }
    // What rules or the intercept editor changed: the request as the client sent it (`request` is what went to
    // the server) and the response as delivered to the client (`response` is the server's), the list of changes
    // and a diff per changed message.
    v["changes"] = json!(ex.changes);
    v["diffs"] = json!(st.service.change_diffs(&me.actor, &ex));
    for (key, original) in [("request_original", &ex.request_original), ("response_delivered", &ex.response_delivered)]
    {
        if let Some(raw) = original {
            let (text, cut) = capped(raw, max);
            v[key] = json!(text);
            if let Some(n) = cut {
                v[format!("{key}_truncated")] = json!(n);
            }
        }
    }
    // A viewer sees what an agent sees: every string passes the redactor, and the exact bytes are not offered (they
    // would carry the secrets the text hides).
    if st.service.is_viewer(&me.actor) {
        return Ok(Json(st.service.json_for(&me.actor, v)));
    }
    if q.bytes == Some(1) {
        let cut = |b: &[u8]| pm_core::base64(&b[..max.map_or(b.len(), |m| m.min(b.len()))]);
        v["request_b64"] = json!(cut(&ex.request));
        v["response_b64"] = json!(ex.response.as_deref().map(cut));
        if let Some(b) = &ex.request_original {
            v["request_original_b64"] = json!(cut(b));
        }
        if let Some(b) = &ex.response_delivered {
            v["response_delivered_b64"] = json!(cut(b));
        }
    }
    Ok(Json(v))
}

async fn replay(State(st): State<AppState>, me: Me, Json(r): Json<ReplayRequest>) -> ApiResult {
    ok(st.service.replay_send(&me.actor, r).await?)
}

async fn approvals(State(st): State<AppState>, Query(q): Query<StatusQuery>) -> ApiResult {
    let status = q.status.filter(|s| s != "all");
    ok(st.service.approvals(status.as_deref(), 200)?)
}

async fn decide(State(st): State<AppState>, me: Me, Path((id, decision)): Path<(String, String)>) -> ApiResult {
    let approve = match decision.as_str() {
        "approve" => true,
        "deny" => false,
        _ => return Err(ServiceError::Invalid("use /approve or /deny".into()).into()),
    };
    ok(st.service.decide_approval(&id, &me.actor, approve)?)
}

async fn identities(State(st): State<AppState>) -> ApiResult {
    ok(st.service.identity_list()?)
}

async fn identity_capture(State(st): State<AppState>, me: Me, Json(b): Json<CaptureBody>) -> ApiResult {
    ok(st.service.identity_capture(&me.actor, &b.name, b.role.as_deref().unwrap_or("user"), b.exchange_id)?)
}

async fn identity_check(State(st): State<AppState>, me: Me, Path(name): Path<String>) -> ApiResult {
    ok(st.service.identity_check(&me.actor, &name).await?)
}

async fn identity_record_login(State(st): State<AppState>, me: Me, Json(b): Json<RecordLoginBody>) -> ApiResult {
    ok(st.service.identity_record_login(&me.actor, &b.name, b.role.as_deref().unwrap_or("user"), b.from, b.to)?)
}

async fn identity_learn_logged_out(State(st): State<AppState>, me: Me, Path(name): Path<String>) -> ApiResult {
    ok(st.service.identity_learn_logged_out(&me.actor, &name).await?)
}

async fn history_mark(State(st): State<AppState>) -> ApiResult {
    ok(serde_json::json!({ "id": st.service.history_mark()? }))
}

async fn authz_matrix(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::AuthzMatrixRequest>) -> ApiResult {
    ok(st.service.authz_matrix(&me.actor, r).await?)
}

async fn model_snapshots(State(st): State<AppState>) -> ApiResult {
    ok(st.service.model_snapshot_list()?)
}

async fn model_snapshot_save(State(st): State<AppState>, me: Me, Json(b): Json<SnapshotBody>) -> ApiResult {
    ok(st.service.model_snapshot_save(&me.actor, &b.name)?)
}

async fn model_changes(State(st): State<AppState>, me: Me, Query(q): Query<ChangesQuery>) -> ApiResult {
    shown(&st, &me, st.service.model_changes(q.snapshot)?)
}

async fn authz_check(State(st): State<AppState>, me: Me, Json(r): Json<AuthzCheckRequest>) -> ApiResult {
    ok(st.service.authz_check(&me.actor, r).await?)
}

async fn authz_results(State(st): State<AppState>, me: Me, Query(q): Query<ExchangeQuery>) -> ApiResult {
    shown(&st, &me, st.service.authz_results(q.exchange_id)?)
}

async fn authz_candidates(State(st): State<AppState>, me: Me) -> ApiResult {
    shown(&st, &me, st.service.authz_candidates()?)
}

async fn model(State(st): State<AppState>, me: Me, Query(f): Query<ModelFilter>) -> ApiResult {
    shown(&st, &me, st.service.model_get(&f)?)
}

async fn scan_task_start(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::ScanTaskRequest>) -> ApiResult {
    ok(st.service.scan_task_start(&me.actor, r)?)
}

async fn scan_tasks_list(State(st): State<AppState>, me: Me) -> ApiResult {
    ok(st.service.scan_task_list(&me.actor))
}

async fn scan_task_status(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult {
    ok(st.service.scan_task_status(&me.actor, &id)?)
}

async fn scan_task_cancel(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult {
    ok(st.service.scan_task_cancel(&me.actor, &id)?)
}

async fn scan_task_pause(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult {
    ok(st.service.scan_task_pause(&me.actor, &id)?)
}

async fn scan_task_resume(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult {
    ok(st.service.scan_task_resume(&me.actor, &id)?)
}

async fn collaborator_probes(State(st): State<AppState>, Query(q): Query<ProbesQuery>) -> ApiResult {
    ok(st.service.collaborator_probes(q.limit.unwrap_or(200))?)
}

async fn collaborator_status(State(st): State<AppState>) -> ApiResult {
    ok(st.service.collaborator_status()?)
}

async fn collaborator_smtp(State(st): State<AppState>, me: Me, Json(b): Json<SmtpBody>) -> ApiResult {
    let addr = b
        .listen
        .trim()
        .parse()
        .map_err(|_| pm_service::ServiceError::Invalid(format!("listen on host:port, not {:?}", b.listen)))?;
    ok(st.service.collaborator_smtp(&me.actor, addr).await?)
}

async fn collaborator_listen(State(st): State<AppState>, me: Me, Json(b): Json<ListenBody>) -> ApiResult {
    let addr = b
        .listen
        .trim()
        .parse()
        .map_err(|_| pm_service::ServiceError::Invalid(format!("listen on host:port, not {:?}", b.listen)))?;
    ok(st.service.collaborator_listen(&me.actor, addr, b.public_url).await?)
}

async fn collaborator_payload(State(st): State<AppState>, me: Me, Json(b): Json<PayloadBody>) -> ApiResult {
    ok(st.service.collaborator_payload(&me.actor, &b.note)?)
}

async fn organizer_list(State(st): State<AppState>, me: Me, Query(q): Query<OrganizerQuery>) -> ApiResult {
    ok(st.service.organizer_list(&me.actor, q.status.as_deref().filter(|s| !s.is_empty()))?)
}

async fn organizer_add(State(st): State<AppState>, me: Me, Json(b): Json<OrganizerAdd>) -> ApiResult {
    ok(st.service.organizer_add(&me.actor, b.exchange_id, &b.note)?)
}

async fn organizer_update(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<i64>,
    Json(u): Json<pm_service::OrganizerUpdate>,
) -> ApiResult {
    ok(st.service.organizer_update(&me.actor, id, &u)?)
}

async fn organizer_delete(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    st.service.organizer_delete(&me.actor, id)?;
    ok(json!({ "deleted": id }))
}

async fn collaborator_payloads(State(st): State<AppState>, Query(q): Query<CollabQuery>) -> ApiResult {
    ok(st.service.collaborator_payloads(q.limit.unwrap_or(100))?)
}

async fn collaborator_interactions(State(st): State<AppState>, Query(q): Query<CollabQuery>) -> ApiResult {
    ok(st.service.collaborator_interactions(q.token.as_deref().filter(|t| !t.is_empty()), q.limit.unwrap_or(200))?)
}

async fn engage_comments(State(st): State<AppState>, me: Me, Json(f): Json<pm_service::EngageFilter>) -> ApiResult {
    ok(st.service.engage_comments(&me.actor, &f)?)
}

async fn engage_scripts(State(st): State<AppState>, me: Me, Json(f): Json<pm_service::EngageFilter>) -> ApiResult {
    ok(st.service.engage_scripts(&me.actor, &f)?)
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

async fn update_set(State(st): State<AppState>, me: Me, Json(b): Json<UpdateSet>) -> ApiResult {
    ok(st.service.update_set(&me.actor, b.enabled)?)
}

async fn recon_dns(State(st): State<AppState>, me: Me, Json(b): Json<ReconDns>) -> ApiResult {
    ok(st.service.recon_dns(&me.actor, &b.host, b.resolver).await?)
}

async fn recon_wayback(State(st): State<AppState>, me: Me, Json(b): Json<ReconWayback>) -> ApiResult {
    ok(st.service.recon_wayback(&me.actor, &b.host, b.limit.unwrap_or(500), None).await?)
}

async fn update_check(State(st): State<AppState>, me: Me, Json(b): Json<UpdateCheck>) -> ApiResult {
    ok(st.service.update_check(&me.actor, b.force).await?)
}

async fn engage_js_endpoints(State(st): State<AppState>, me: Me, Json(f): Json<pm_service::EngageFilter>) -> ApiResult {
    ok(st.service.engage_js_endpoints(&me.actor, &f)?)
}

async fn traffic_triage(State(st): State<AppState>, me: Me, Json(b): Json<TriageBody>) -> ApiResult {
    let f = pm_service::EngageFilter { host: b.host, in_scope: b.in_scope, ..Default::default() };
    ok(st.service.traffic_triage(&me.actor, &f, b.limit.unwrap_or(100))?)
}

async fn memory_list(State(st): State<AppState>, me: Me, Query(q): Query<HostQuery>) -> ApiResult {
    shown(&st, &me, st.service.memory_list(q.host.as_deref())?)
}

async fn memory_delete(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    st.service.memory_delete(&me.actor, id)?;
    ok(serde_json::json!({ "deleted": id }))
}

async fn engage_logic(State(st): State<AppState>, me: Me, Json(f): Json<pm_service::EngageFilter>) -> ApiResult {
    ok(st.service.engage_logic(&me.actor, &f)?)
}

async fn engage_analyze(State(st): State<AppState>, me: Me, Json(f): Json<pm_service::EngageFilter>) -> ApiResult {
    ok(st.service.engage_analyze(&me.actor, &f)?)
}

async fn engage_references(State(st): State<AppState>, me: Me, Json(b): Json<EngageExchange>) -> ApiResult {
    ok(st.service.engage_references(&me.actor, b.exchange_id, &Default::default())?)
}

async fn engage_csrf(State(st): State<AppState>, me: Me, Json(b): Json<EngageExchange>) -> ApiResult {
    ok(json!({ "html": st.service.engage_csrf_poc(&me.actor, b.exchange_id, b.technique, b.auto_submit)? }))
}

async fn engage_clickjacking(State(st): State<AppState>, Json(b): Json<EngageExchange>) -> ApiResult {
    ok(st.service.engage_clickjacking(b.exchange_id)?)
}

async fn plugins(State(st): State<AppState>) -> ApiResult {
    ok(st.service.plugin_list())
}

async fn plugin_set(
    State(st): State<AppState>,
    me: Me,
    Path(name): Path<String>,
    Json(b): Json<PluginSet>,
) -> ApiResult {
    ok(st.service.plugin_set_enabled(&me.actor, &name, b.enabled)?)
}

async fn plugin_accept(State(st): State<AppState>, me: Me, Path(name): Path<String>) -> ApiResult {
    ok(st.service.plugin_accept_permissions(&me.actor, &name)?)
}

async fn plugin_hook_set(
    State(st): State<AppState>,
    me: Me,
    Path((name, kind)): Path<(String, String)>,
    Json(b): Json<pm_service::api_types::PluginHookSet>,
) -> ApiResult {
    let kind = pm_service::pm_plugin::v2::HookKind::parse(&kind)
        .ok_or_else(|| ServiceError::Invalid("a hook kind is `request` or `response`".into()))?;
    ok(st.service.plugin_hook_set(&me.actor, &name, kind, b.action)?)
}

async fn plugin_panel(
    State(st): State<AppState>,
    me: Me,
    Path((name, panel)): Path<(String, String)>,
    Query(q): Query<PanelQuery>,
) -> ApiResult {
    ok(st.service.plugin_panel(&me.actor, &name, &panel, q.limit)?)
}

async fn plugin_check(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::PluginCheckRequest>) -> ApiResult {
    ok(st.service.plugin_check(&me.actor, r).await?)
}

async fn scan_profiles(State(st): State<AppState>) -> ApiResult {
    ok(st.service.scan_profiles()?)
}

async fn scan_profile_save(State(st): State<AppState>, me: Me, Json(p): Json<pm_service::ScanProfile>) -> ApiResult {
    ok(st.service.scan_profile_save(&me.actor, p)?)
}

async fn dom_test(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::DomTestRequest>) -> ApiResult {
    ok(st.service.dom_test(&me.actor, r).await?)
}

async fn custom_checks(State(st): State<AppState>) -> ApiResult {
    ok(st.service.custom_checks()?)
}

async fn custom_check_save(State(st): State<AppState>, me: Me, Json(b): Json<CheckYaml>) -> ApiResult {
    ok(st.service.custom_check_save(&me.actor, &b.yaml)?)
}

async fn custom_check_delete(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult {
    ok(serde_json::json!({ "deleted": st.service.custom_check_delete(&me.actor, &id)? }))
}

async fn custom_scan(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::CustomScanRequest>) -> ApiResult {
    ok(st.service.custom_scan(&me.actor, r).await?)
}

async fn scan_profile_delete(State(st): State<AppState>, me: Me, Path(name): Path<String>) -> ApiResult {
    ok(serde_json::json!({ "deleted": st.service.scan_profile_delete(&me.actor, &name)? }))
}

async fn scan_schedules(State(st): State<AppState>) -> ApiResult {
    ok(st.service.schedule_list()?)
}

async fn scan_schedule_save(State(st): State<AppState>, me: Me, Json(s): Json<pm_service::ScanSchedule>) -> ApiResult {
    ok(st.service.schedule_save(&me.actor, s)?)
}

async fn scan_schedule_delete(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    ok(serde_json::json!({ "deleted": st.service.schedule_delete(&me.actor, id)? }))
}

async fn scan_schedule_run(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.schedule_run_now(&me.actor, id)?)
}

async fn scan_active(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::ActiveScanRequest>) -> ApiResult {
    ok(st.service.scan_active(&me.actor, r).await?)
}

async fn scan_issues(State(st): State<AppState>, me: Me, Query(f): Query<pm_service::ScanFilter>) -> ApiResult {
    // Plugins run as processes; keep them off the async workers.
    let (service, actor) = (st.service.clone(), me.actor.clone());
    let issues = tokio::task::spawn_blocking(move || service.scan_passive(&actor, &f))
        .await
        .map_err(|e| pm_service::ServiceError::Invalid(format!("scan failed: {e}")))??;
    ok(issues)
}

async fn coverage(State(st): State<AppState>, me: Me, Query(q): Query<CoverageQuery>) -> ApiResult {
    shown(&st, &me, st.service.coverage(!q.all.unwrap_or(false))?)
}

async fn hypotheses(State(st): State<AppState>, me: Me, Query(q): Query<StatusQuery>) -> ApiResult {
    shown(&st, &me, st.service.hypothesis_list(q.status.as_deref())?)
}

async fn findings(State(st): State<AppState>, me: Me, Query(q): Query<StatusQuery>) -> ApiResult {
    shown(&st, &me, st.service.finding_list(q.status.as_deref())?)
}

async fn finding(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    shown(&st, &me, st.service.finding_get(id)?)
}

async fn finding_create(State(st): State<AppState>, me: Me, Json(f): Json<NewFinding>) -> ApiResult {
    ok(st.service.finding_create(&me.actor, f)?)
}

async fn finding_update(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<i64>,
    Json(mut u): Json<FindingUpdate>,
) -> ApiResult {
    u.id = id;
    ok(st.service.finding_update(&me.actor, u)?)
}

async fn proof_run(State(st): State<AppState>, me: Me, Json(r): Json<ProofRequest>) -> ApiResult {
    ok(st.service.proof_run(&me.actor, r).await?)
}

async fn proof(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    shown(&st, &me, st.service.proof_get(id)?)
}

async fn proof_rerun(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.proof_rerun(&me.actor, id).await?)
}

async fn audit(State(st): State<AppState>, Query(q): Query<LimitQuery>) -> ApiResult {
    ok(st.service.audit_list(q.limit.unwrap_or(200).min(5000))?)
}

async fn audit_verify(State(st): State<AppState>) -> ApiResult {
    ok(st.service.audit_verify_report(Vec::new(), None))
}

async fn audit_checkpoint(State(st): State<AppState>, me: Me) -> ApiResult {
    ok(st.service.audit_checkpoint(&me.actor)?)
}

async fn audit_checkpoints(State(st): State<AppState>) -> ApiResult {
    ok(st.service.audit_checkpoints()?)
}

async fn report(State(st): State<AppState>, me: Me, Query(q): Query<ReportQuery>) -> Result<Response, ApiError> {
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
    let r = st.service.report_render_for(&me.actor, q.template.as_deref(), format, &opts).await?;
    // Always a download: reports hold target content (escaped, with their own
    // CSP). The UI previews HTML in a sandboxed srcdoc frame instead.
    let disposition = format!("attachment; filename=\"proxymind-report.{}\"", r.extension);
    Ok(([(header::CONTENT_TYPE, r.content_type.to_string()), (header::CONTENT_DISPOSITION, disposition)], r.body)
        .into_response())
}

/// Largest evidence pack the verify endpoint takes.
const EVIDENCE_LIMIT: usize = 512 * 1024 * 1024;

/// A signed evidence pack (ZIP) to hand to the client.
async fn evidence_pack(State(st): State<AppState>, me: Me, Query(q): Query<PackQuery>) -> Result<Response, ApiError> {
    let (bytes, fingerprint) = st.service.evidence_pack(&me.actor, q.all)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"proxymind-evidence.zip\"".to_string()),
            (header::HeaderName::from_static("x-evidence-fingerprint"), fingerprint),
        ],
        bytes,
    )
        .into_response())
}

async fn evidence_fingerprint(State(st): State<AppState>) -> ApiResult {
    ok(serde_json::json!({ "fingerprint": st.service.evidence_fingerprint()? }))
}

/// Checks an uploaded evidence pack (the body is the ZIP).
async fn evidence_verify(body: axum::body::Bytes) -> ApiResult {
    ok(pm_service::verify_evidence(&body))
}

async fn regress_list(State(st): State<AppState>, me: Me) -> ApiResult {
    shown(&st, &me, st.service.regression_tests()?)
}

/// The regression tests as a ZIP (tests, README, example CI workflow).
async fn regress_export(State(st): State<AppState>, me: Me) -> Result<Response, ApiError> {
    let (bytes, _) = st.service.regression_zip(&me.actor)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/zip".to_string()),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"proxymind-regressions.zip\"".to_string()),
        ],
        bytes,
    )
        .into_response())
}

async fn coverage_proof(State(st): State<AppState>, me: Me) -> ApiResult {
    shown(&st, &me, st.service.coverage_proof()?)
}

async fn finding_prove(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.finding_prove(&me.actor, id).await?)
}

async fn findings_prove_all(State(st): State<AppState>, me: Me) -> ApiResult {
    ok(st.service.auto_prove(&me.actor).await?)
}

async fn finding_retest(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.finding_retest(&me.actor, id).await?)
}

async fn library() -> ApiResult {
    ok(pm_service::pm_scan::library::LIBRARY)
}

async fn report_templates(State(st): State<AppState>) -> ApiResult {
    ok(st.service.report_templates()?)
}

async fn report_template_save(
    State(st): State<AppState>,
    me: Me,
    Json(t): Json<pm_service::ReportTemplate>,
) -> ApiResult {
    ok(st.service.report_template_save(&me.actor, t)?)
}

async fn report_template_delete(State(st): State<AppState>, me: Me, Path(name): Path<String>) -> ApiResult {
    ok(serde_json::json!({ "deleted": st.service.report_template_delete(&me.actor, &name)? }))
}

async fn intercept_state(State(st): State<AppState>) -> ApiResult {
    ok(st.service.intercept_state())
}

async fn intercept_settings(
    State(st): State<AppState>,
    me: Me,
    Json(s): Json<pm_service::pm_proxy::InterceptSettings>,
) -> ApiResult {
    ok(st.service.intercept_settings(&me.actor, s)?)
}

async fn intercept_forward(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<u64>,
    Json(b): Json<ForwardBody>,
) -> ApiResult {
    st.service.intercept_forward(&me.actor, id, b.raw, b.fix_content_length.unwrap_or(true))?;
    ok(json!({ "forwarded": id }))
}

async fn intercept_drop(State(st): State<AppState>, me: Me, Path(id): Path<u64>) -> ApiResult {
    st.service.intercept_drop(&me.actor, id)?;
    ok(json!({ "dropped": id }))
}

async fn search(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::SearchRequest>) -> ApiResult {
    ok(st.service.history_search_text(&me.actor, &r)?)
}

async fn search_ws(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::WsSearchRequest>) -> ApiResult {
    ok(st.service.ws_search_text(&me.actor, &r)?)
}

async fn sitemap(State(st): State<AppState>, me: Me, Query(q): Query<SiteQuery>) -> ApiResult {
    ok(st.service.site_map(&me.actor, q.host.as_deref().filter(|h| !h.is_empty()))?)
}

async fn discover(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::DiscoverRequest>) -> ApiResult {
    ok(st.service.discover(&me.actor, r).await?)
}

async fn setup(State(st): State<AppState>) -> ApiResult {
    ok(json!({
        "proxy": st.setup.proxy,
        "ca_available": st.setup.ca_pem.is_some(),
        "ca_sha256": st.setup.ca_fingerprint(),
        "browser_available": st.service.browser_available(),
    }))
}

/// How a phone reaches ProxyMind's setup page: addresses, a QR code (SVG) and the CA fingerprint.
async fn setup_mobile(State(st): State<AppState>) -> ApiResult {
    ok(st.service.mobile_setup()?)
}

async fn browser_open(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::BrowserOpenRequest>) -> ApiResult {
    ok(st.service.browser_open(&me.actor, r).await?)
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

async fn roe_put(State(st): State<AppState>, me: Me, Json(b): Json<RoeBody>) -> ApiResult {
    ok(st.service.roe_set(&me.actor, &b.text)?)
}

async fn roe_check(State(st): State<AppState>, Json(b): Json<RoeBody>) -> ApiResult {
    ok(st.service.roe_check(&b.text)?)
}

async fn annotate(State(st): State<AppState>, me: Me, Path(id): Path<i64>, Json(b): Json<AnnotationBody>) -> ApiResult {
    ok(st.service.exchange_annotate(&me.actor, id, b.highlight.as_deref(), b.comment.as_deref())?)
}

async fn ws_history(State(st): State<AppState>, me: Me, Query(q): Query<WsHistoryQuery>) -> ApiResult {
    let host = q.host.as_deref().filter(|h| !h.is_empty());
    ok(st.service.ws_history(&me.actor, host, q.before_id, q.limit.unwrap_or(500), 2000)?)
}

async fn ui_get(State(st): State<AppState>, Path(key): Path<String>) -> ApiResult {
    ok(st.service.ui_state_get(&key)?)
}

async fn ui_put(State(st): State<AppState>, me: Me, Path(key): Path<String>, Json(v): Json<Value>) -> ApiResult {
    st.service.ui_state_put(&me.actor, &key, &v)?;
    ok(json!({ "saved": key }))
}

async fn exchange_curl(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    ok(json!({ "command": st.service.exchange_curl(&me.actor, id)? }))
}

async fn exchange_code(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<i64>,
    Query(q): Query<CodeQuery>,
) -> ApiResult {
    ok(json!({ "code": st.service.exchange_code(&me.actor, id, q.lang)? }))
}

async fn tools_code(State(st): State<AppState>, Json(b): Json<CodeBody>) -> ApiResult {
    ok(json!({ "code": st.service.request_code(&b.url, &b.raw, b.lang)? }))
}

async fn import_har(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::ImportRequest>) -> ApiResult {
    ok(st.service.traffic_import_har(&me.actor, &r)?)
}

/// A HAR download: it holds target content, so it is never rendered here.
async fn export_har(
    State(st): State<AppState>,
    me: Me,
    Json(r): Json<pm_service::ExportRequest>,
) -> Result<Response, ApiError> {
    let har = st.service.traffic_export_har(&me.actor, &r)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"proxymind.har\""),
        ],
        har.to_string(),
    )
        .into_response())
}

async fn tools_curl(State(st): State<AppState>, Json(r): Json<CurlBody>) -> ApiResult {
    ok(st.service.curl_parse(&r.command)?)
}

async fn graphql_get(State(st): State<AppState>, me: Me) -> ApiResult {
    shown(&st, &me, st.service.graphql_get()?)
}

async fn graphql_import(
    State(st): State<AppState>,
    me: Me,
    Json(r): Json<pm_service::GraphQlImportRequest>,
) -> ApiResult {
    ok(st.service.graphql_import(&me.actor, r).await?)
}

async fn openapi_get(State(st): State<AppState>, me: Me) -> ApiResult {
    shown(&st, &me, st.service.openapi_get()?)
}

async fn openapi_import(
    State(st): State<AppState>,
    me: Me,
    Json(r): Json<pm_service::OpenApiImportRequest>,
) -> ApiResult {
    ok(st.service.openapi_import(&me.actor, r).await?)
}

async fn tools_decode(State(st): State<AppState>, Json(r): Json<pm_service::DecodeRequest>) -> ApiResult {
    ok(st.service.decode(&r)?)
}

async fn tools_protobuf_decode(
    State(st): State<AppState>,
    me: Me,
    Json(r): Json<pm_service::api_types::ProtobufDecodeRequest>,
) -> ApiResult {
    ok(st.service.protobuf_decode(&me.actor, &r)?)
}

async fn tools_protobuf_encode(
    State(st): State<AppState>,
    Json(r): Json<pm_service::api_types::ProtobufEncodeRequest>,
) -> ApiResult {
    ok(st.service.protobuf_encode(&r)?)
}

async fn tools_request_transform(State(st): State<AppState>, Json(t): Json<pm_service::RequestTransform>) -> ApiResult {
    ok(st.service.request_transform(&t)?)
}

async fn tools_compare(State(st): State<AppState>, me: Me, Json(r): Json<CompareBody>) -> ApiResult {
    ok(st.service.compare_exchanges(&me.actor, r.a, r.b)?)
}

async fn tools_token_analyzer(
    State(st): State<AppState>,
    me: Me,
    Json(r): Json<pm_service::TokenAnalyzerRequest>,
) -> ApiResult {
    ok(st.service.token_analyzer_run(&me.actor, r).await?)
}

async fn tools_token_analyzer_analyze(State(st): State<AppState>, Json(r): Json<TokensBody>) -> ApiResult {
    ok(st.service.token_analyzer_analyze(&r.tokens)?)
}

async fn crawl(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::CrawlRequest>) -> ApiResult {
    ok(st.service.crawl(&me.actor, r).await?)
}

async fn fuzzer(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::FuzzerRequest>) -> ApiResult {
    ok(st.service.fuzzer_run(&me.actor, r).await?)
}

async fn attack_start(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::FuzzerRequest>) -> ApiResult {
    ok(st.service.fuzzer_start(&me.actor, r)?)
}

async fn attacks_list(State(st): State<AppState>, me: Me) -> ApiResult {
    ok(st.service.fuzzer_list(&me.actor))
}

async fn attack_status(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<String>,
    Query(q): Query<FromQuery>,
) -> ApiResult {
    ok(st.service.fuzzer_status(&me.actor, &id, q.from.unwrap_or(0))?)
}

async fn attack_control(State(st): State<AppState>, me: Me, Path((id, action)): Path<(String, String)>) -> ApiResult {
    ok(json!({ "status": st.service.fuzzer_control(&me.actor, &id, &action)? }))
}

async fn replay_group(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::GroupRequest>) -> ApiResult {
    ok(st.service.replay_group(&me.actor, r).await?)
}

async fn race(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::RaceRequest>) -> ApiResult {
    ok(st.service.race_send(&me.actor, r).await?)
}

async fn ws_replay(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::WsReplayRequest>) -> ApiResult {
    ok(st.service.ws_replay(&me.actor, r).await?)
}

async fn streams_list(
    State(st): State<AppState>,
    me: Me,
    Query(q): Query<pm_service::pm_store::StreamFilter>,
) -> ApiResult {
    ok(st.service.streams_list(&me.actor, &q)?)
}

async fn stream_get(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<i64>,
    Query(q): Query<pm_service::api_types::StreamChunksQuery>,
) -> ApiResult {
    ok(st.service.stream_get(&me.actor, id, q.after, q.limit.unwrap_or(100), 4000)?)
}

async fn stream_chunks(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<i64>,
    Query(q): Query<pm_service::api_types::StreamChunksQuery>,
) -> ApiResult {
    ok(st.service.stream_chunks(&me.actor, id, q.after, q.limit.unwrap_or(100), 4000)?)
}

/// The stream id comes from the path; a `stream_id` in the body must agree with it (or be left out).
async fn stream_replay(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<i64>,
    Json(mut r): Json<pm_service::StreamReplayRequest>,
) -> ApiResult {
    if r.stream_id != 0 && r.stream_id != id {
        return Err(pm_service::ServiceError::Invalid(format!(
            "stream_id {} does not match the path ({id})",
            r.stream_id
        ))
        .into());
    }
    r.stream_id = id;
    ok(st.service.stream_replay(&me.actor, r).await?)
}

async fn ws_messages(State(st): State<AppState>, me: Me, Path(id): Path<i64>, Query(q): Query<WsQuery>) -> ApiResult {
    ok(st.service.ws_messages(&me.actor, id, q.after_id, q.limit.unwrap_or(200), 1 << 20)?)
}

async fn model_key_set(State(st): State<AppState>, me: Me, Json(b): Json<KeyBody>) -> ApiResult {
    ok(st.service.model_key_set(&me.actor, &b.name, &b.key)?)
}

async fn model_key_remove(State(st): State<AppState>, me: Me, Path(name): Path<String>) -> ApiResult {
    ok(st.service.model_key_remove(&me.actor, &name)?)
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

async fn assistant_config(
    State(st): State<AppState>,
    me: Me,
    Json(cfg): Json<pm_service::AssistantConfig>,
) -> ApiResult {
    ok(st.service.assistant_config_set(&me.actor, cfg)?)
}

/// Models the server in `cfg` offers (the form's values, before saving).
async fn assistant_models(State(st): State<AppState>, Json(cfg): Json<pm_service::AssistantConfig>) -> ApiResult {
    ok(serde_json::json!({ "models": st.assistant.list_models(&cfg).await? }))
}

async fn finding_explain(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<i64>,
    Json(b): Json<ExplainBody>,
) -> ApiResult {
    let md = st.assistant.explain_finding(&me.actor, id, b.framework.as_deref()).await?;
    ok(serde_json::json!({ "explanation": md }))
}

async fn assistant_chat(State(st): State<AppState>, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.chat_get(id)?)
}

async fn assistant_send(State(st): State<AppState>, Json(b): Json<SendBody>) -> ApiResult {
    if b.text.trim().is_empty() {
        return Err(ServiceError::Invalid("write a message".into()).into());
    }
    ok(st.assistant.send(b.chat_id, &b.text).await?)
}

async fn ai_scan_start(State(st): State<AppState>, me: Me, Json(req): Json<pm_service::AiScanRequest>) -> ApiResult {
    ok(st.assistant.start_ai_scan(&me.actor, req)?)
}

async fn ai_scan_list(State(st): State<AppState>, me: Me) -> ApiResult {
    shown(&st, &me, st.service.ai_scan_list(50)?)
}

async fn ai_scan_get(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    shown(&st, &me, st.service.ai_scan_get(id)?)
}

async fn ai_scan_stop(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.ai_scan_stop(&me.actor, id)?)
}

async fn ai_scan_message(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<i64>,
    Json(b): Json<AiScanMessage>,
) -> ApiResult {
    ok(st.service.ai_scan_message(&me.actor, id, &b.text)?)
}

async fn attack_paths(State(st): State<AppState>, me: Me, Query(q): Query<ScanQuery>) -> ApiResult {
    shown(&st, &me, st.service.attack_path_list(q.scan)?)
}

async fn attack_path_create(State(st): State<AppState>, me: Me, Json(p): Json<pm_service::NewAttackPath>) -> ApiResult {
    ok(st.service.attack_path_create(&me.actor, p)?)
}

async fn attack_path_delete(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    st.service.attack_path_delete(&me.actor, id)?;
    ok(serde_json::json!({ "deleted": id }))
}

async fn attack_graph(State(st): State<AppState>, me: Me, Query(q): Query<ScanQuery>) -> ApiResult {
    shown(&st, &me, st.service.attack_graph(q.scan)?)
}

/// The system prompt a scan would get (with the default target).
async fn ai_scan_prompt(State(st): State<AppState>) -> ApiResult {
    let target = st.service.policy().roe().include.first().map(|p| p.text.clone()).unwrap_or_default();
    ok(json!({ "target": target, "prompt": st.service.ai_scan_prompt(&target, "")? }))
}

async fn network_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.network_get()?)
}

async fn network_resolve(State(st): State<AppState>, Json(b): Json<UpstreamResolveRequest>) -> ApiResult {
    ok(st.service.network_resolve(&b)?)
}

async fn network_put(
    State(st): State<AppState>,
    me: Me,
    Json(cfg): Json<pm_service::pm_replay::NetConfig>,
) -> ApiResult {
    ok(st.service.network_set(&me.actor, cfg)?)
}

async fn recording_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.recording_get()?)
}

async fn recording_put(State(st): State<AppState>, me: Me, Json(r): Json<pm_service::RecordingSettings>) -> ApiResult {
    ok(st.service.recording_set(&me.actor, r)?)
}

async fn devices_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.devices_list()?)
}

async fn device_put(
    State(st): State<AppState>,
    me: Me,
    Path(addr): Path<String>,
    Json(b): Json<pm_service::api_types::DeviceNameBody>,
) -> ApiResult {
    ok(st.service.device_set_name(&me.actor, &addr, &b.name)?)
}

async fn device_delete(State(st): State<AppState>, me: Me, Path(addr): Path<String>) -> ApiResult {
    st.service.device_remove_name(&me.actor, &addr)?;
    ok(json!({ "deleted": addr }))
}

async fn session_get(State(st): State<AppState>, me: Me) -> ApiResult {
    ok(st.service.session_get(&me.actor)?)
}

async fn session_put(State(st): State<AppState>, me: Me, Json(cfg): Json<pm_service::SessionConfig>) -> ApiResult {
    ok(st.service.session_set(&me.actor, cfg)?)
}

async fn session_jar(State(st): State<AppState>, me: Me) -> ApiResult {
    ok(json!({ "cookies": st.service.session_jar(&me.actor)? }))
}

async fn session_jar_clear(State(st): State<AppState>, me: Me) -> ApiResult {
    st.service.session_jar_clear(&me.actor)?;
    ok(json!({ "cleared": true }))
}

async fn workflows_list(State(st): State<AppState>, me: Me) -> ApiResult {
    ok(st.service.workflow_list(&me.actor)?)
}

async fn workflow_create(State(st): State<AppState>, me: Me, Json(w): Json<pm_service::WorkflowInput>) -> ApiResult {
    ok(st.service.workflow_create(&me.actor, w)?)
}

async fn workflow_get(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult {
    ok(st.service.workflow_get(&me.actor, &id)?)
}

async fn workflow_update(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<String>,
    Json(w): Json<pm_service::WorkflowInput>,
) -> ApiResult {
    ok(st.service.workflow_update(&me.actor, &id, w)?)
}

async fn workflow_delete(State(st): State<AppState>, me: Me, Path(id): Path<String>) -> ApiResult {
    st.service.workflow_delete(&me.actor, &id)?;
    ok(json!({ "deleted": id }))
}

async fn workflow_trigger(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<String>,
    Json(b): Json<WorkflowTriggerBody>,
) -> ApiResult {
    ok(st.service.workflow_trigger_set(&me.actor, &id, b.enabled, b.max_per_minute)?)
}

async fn workflow_run(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<String>,
    Json(b): Json<WorkflowRunBody>,
) -> ApiResult {
    let req = pm_service::WorkflowRunRequest { workflow: id, exchange_id: b.exchange_id, approval_id: b.approval_id };
    ok(st.service.workflow_run(&me.actor, req).await?)
}

async fn workflow_runs(State(st): State<AppState>, me: Me, Query(q): Query<WorkflowRunsQuery>) -> ApiResult {
    ok(st.service.workflow_runs(&me.actor, q.workflow.as_deref(), q.limit.unwrap_or(50))?)
}

async fn workflow_run_get(State(st): State<AppState>, me: Me, Path(id): Path<i64>) -> ApiResult {
    ok(st.service.workflow_run_get(&me.actor, id)?)
}

async fn session_macro_run(State(st): State<AppState>, me: Me, Path(name): Path<String>) -> ApiResult {
    ok(st.service.session_macro_run(&me.actor, &name).await?)
}

async fn listeners_get(State(st): State<AppState>) -> ApiResult {
    ok(st.service.listeners_get()?)
}

async fn listeners_put(State(st): State<AppState>, me: Me, Json(b): Json<ListenersBody>) -> ApiResult {
    ok(st.service.listeners_set(&me.actor, b.listeners)?)
}

async fn rules_presets(State(st): State<AppState>) -> ApiResult {
    ok(st.service.match_replace_presets())
}

async fn rules_get(State(st): State<AppState>) -> ApiResult {
    ok(json!({ "rules": st.service.match_replace_rules()? }))
}

async fn rules_put(State(st): State<AppState>, me: Me, Json(b): Json<RulesBody>) -> ApiResult {
    ok(json!({ "rules": st.service.set_match_replace_rules(&me.actor, b.rules)? }))
}

async fn intercept_forward_all(State(st): State<AppState>, me: Me) -> ApiResult {
    ok(json!({ "forwarded": st.service.intercept_forward_all(&me.actor)? }))
}

/// Whether this installation trusts the project, and what is held back if not. Anyone who can call the API may read it.
async fn project_trust(State(st): State<AppState>) -> ApiResult {
    ok(st.service.trust_status()?)
}

/// A person confirms the project's current settings. The API acts as the human who started it.
async fn project_trust_confirm(State(st): State<AppState>, me: Me, Json(b): Json<TrustConfirmRequest>) -> ApiResult {
    ok(st.service.trust_confirm(&me.actor, &b)?)
}

async fn integrations_list(State(st): State<AppState>, me: Me) -> ApiResult {
    ok(st.service.integration_list(&me.actor)?)
}

async fn integration_get(State(st): State<AppState>, me: Me, Path(name): Path<String>) -> ApiResult {
    ok(st.service.integration_get(&me.actor, &name)?)
}

async fn integration_put(
    State(st): State<AppState>,
    me: Me,
    Path(name): Path<String>,
    Json(b): Json<IntegrationInput>,
) -> ApiResult {
    ok(st.service.integration_set(&me.actor, &name, b)?)
}

async fn integration_delete(State(st): State<AppState>, me: Me, Path(name): Path<String>) -> ApiResult {
    st.service.integration_delete(&me.actor, &name)?;
    ok(json!({ "deleted": name }))
}

async fn integration_enabled(
    State(st): State<AppState>,
    me: Me,
    Path(name): Path<String>,
    Json(b): Json<IntegrationEnabledBody>,
) -> ApiResult {
    ok(st.service.integration_enable(&me.actor, &name, b.enabled)?)
}

async fn integration_test(State(st): State<AppState>, me: Me, Path(name): Path<String>) -> ApiResult {
    ok(st.service.integration_test(&me.actor, &name).await?)
}

async fn integration_deliveries(
    State(st): State<AppState>,
    me: Me,
    Path(name): Path<String>,
    Query(q): Query<DeliveriesQuery>,
) -> ApiResult {
    ok(st.service.integration_deliveries(&me.actor, &name, q.limit.unwrap_or(50))?)
}

async fn finding_issue(
    State(st): State<AppState>,
    me: Me,
    Path(id): Path<i64>,
    Json(b): Json<SendFindingBody>,
) -> ApiResult {
    ok(st.service.integration_send_finding(&me.actor, id, b).await?)
}
