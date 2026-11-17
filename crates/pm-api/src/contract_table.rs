//! The route table behind `docs/api/openapi.json` (ADR-0019): one row for every method of every route that
//! `routes::api()` registers. The test `route_table_matches_router` compares this table with the router's source,
//! so a route cannot be added, renamed or removed in one place only.
//!
//! The operation id is the handler's name in `routes.rs`. A request type names the Rust type the handler reads;
//! a response type is the service type the handler returns. Handlers that build their JSON on the spot (`json!`)
//! or return `serde_json::Value` are described as untyped JSON with the keys the handler actually writes.

use pm_service::api_types::*;
use pm_service::pm_store::HistoryFilter;
use pm_service::*;

use crate::contracts::{Operation, op};
use crate::routes::{BytesQuery, EventsQuery};

const ZIP: &str = "application/zip";

/// Every operation of the API, in the order of the router.
#[rustfmt::skip]
pub fn operations() -> Vec<Operation> {
    vec![
        op("get", "/status", "status", "Version, project, who you are, the engagement and its counters.")
            .json("Object with `version`, `project`, `you_are`, `engagement`, `in_scope` (list of patterns) and `counters`."),
        op("get", "/roe", "roe_get", "The rules of engagement as text and as parsed.").out::<RoeView>(),
        op("put", "/roe", "roe_put", "Replace the rules of engagement.").body::<RoeBody>().out::<RoeView>(),
        op("get", "/setup", "setup", "How to point a browser at the proxy: address, CA availability and fingerprint.")
            .json("Object with `proxy`, `ca_available`, `ca_sha256` and `browser_available`."),
        op("get", "/setup/mobile", "setup_mobile", "How a phone or tablet reaches ProxyMind's setup page: URLs on the LAN, a QR code (SVG) of the first, and the CA fingerprint.")
            .out::<MobileSetup>(),
        op("get", "/ca.pem", "ca_pem", "The proxy's CA certificate (PEM) as a download.")
            .download("application/x-pem-file", "The CA certificate."),
        op("post", "/browser/open", "browser_open", "Open the built-in browser through the proxy.")
            .body::<pm_service::BrowserOpenRequest>().out::<BrowserOpened>(),
        op("post", "/roe/check", "roe_check", "Parse rules of engagement text without saving it.")
            .body::<RoeBody>().json("The parse result of the text (what is in and out of scope, and any problems)."),
        op("get", "/events", "events", "Server-sent events: counters, or typed events for the topics asked for.")
            .query::<EventsQuery>().sse(),
        op("get", "/exchanges", "exchanges", "Search recorded exchanges, newest first.").query::<HistoryFilter>().out::<ExchangePage>(),
        op("get", "/exchanges/{id}", "exchange", "One exchange: summary, request and response text, and a model-safe view.")
            .query::<BytesQuery>()
            .json("Object with `summary`, `request`, `response`, `request_body` / `response_body` (the decoded body text: de-chunked, decompressed, markup kept; null when absent or binary), `view`, `request_protobuf` / `response_protobuf` (gRPC and Protobuf bodies as editable text, one `@message` per gRPC message, with `grpc-status` / `grpc-message` when present; absent for other traffic), plus `request_truncated` / `response_truncated` when cut and `request_b64` / `response_b64` with `bytes=1`. When rules or an edit in the intercept queue changed the traffic, `request` is what was sent to the server and `response` is what the server sent, as always; `request_original` is the request as the client sent it and `response_delivered` is the response as delivered to the client (text, cut by `max` like the others, with `*_truncated`; also `request_original_b64` / `response_delivered_b64` with `bytes=1`; each absent when unchanged). `changes` lists what changed them (`phase`, `by` rule, intercept or hook, `name`, optional `note`; empty when nothing did). `diffs` has one line diff per changed message (`phase`, `from_label`, `to_label`, `lines` in the shape of `/tools/compare`): the request from the client's to the one sent, the response from the server's to the delivered one. The `view` carries `request_original` and `response_delivered` too, redacted and marked untrusted for agents."),
        op("post", "/search", "search", "Search recorded traffic for text or a regular expression.")
            .body::<SearchRequest>().out::<SearchResult>(),
        op("post", "/search/ws", "search_ws", "Search recorded WebSocket messages.").body::<WsSearchRequest>().out::<WsSearchResult>(),
        op("get", "/sitemap", "sitemap", "Hosts and paths seen in recorded traffic.").query::<SiteQuery>().out::<Vec<SiteView>>(),
        op("get", "/exchanges/{id}/ws", "ws_messages", "Messages of one recorded WebSocket connection.").query::<WsQuery>().out::<WsPage>(),
        op("put", "/exchanges/{id}/annotation", "annotate", "Set the highlight and comment of an exchange.")
            .body::<AnnotationBody>().out::<pm_service::pm_store::ExchangeSummary>(),
        op("get", "/ws/history", "ws_history", "Recorded WebSocket messages across connections.").query::<WsHistoryQuery>().out::<WsHistoryPage>(),
        op("get", "/ui/{key}", "ui_get", "A value the web UI saved under this key.").json_any("Whatever JSON was saved (null if nothing)."),
        op("put", "/ui/{key}", "ui_put", "Save a value for the web UI under this key.")
            .any_body("Any JSON value, up to the UI state size limit.").json("Object with `saved` (the key)."),
        op("get", "/exchanges/{id}/curl", "exchange_curl", "The exchange as a cURL command.").json("Object with `command`."),
        op("get", "/exchanges/{id}/code", "exchange_code", "The exchange as a code snippet.").query::<CodeQuery>().json("Object with `code`."),
        op("post", "/tools/code", "tools_code", "A request as a code snippet.").body::<CodeBody>().json("Object with `code`."),
        op("get", "/match-replace/presets", "rules_presets", "Ready-made match-and-replace rules.").out::<Vec<pm_service::pm_proxy::presets::Preset>>(),
        op("post", "/import/har", "import_har", "Import a HAR document as recorded traffic.").body::<ImportRequest>().out::<ImportResult>(),
        op("post", "/export/har", "export_har", "Export recorded traffic as a HAR download.")
            .body::<ExportRequest>().download("application/json", "The HAR document."),
        op("post", "/tools/curl", "tools_curl", "Turn a cURL command into a raw request.").body::<CurlBody>().out::<CurlParsed>(),
        op("post", "/ws/replay", "ws_replay", "Replay a recorded WebSocket session with edited messages.")
            .body::<WsReplayRequest>().out::<WsReplayResult>(),
        op("get", "/streams", "streams_list", "Raw TCP and TLS streams the proxy relayed and recorded, newest first.")
            .query::<pm_service::pm_store::StreamFilter>().out::<StreamPage>(),
        op("get", "/streams/{id}", "stream_get", "One recorded stream with its first chunks (base64 plus a text preview each).")
            .query::<StreamChunksQuery>().out::<StreamDetail>(),
        op("get", "/streams/{id}/chunks", "stream_chunks", "A page of one stream's chunks, oldest first.")
            .query::<StreamChunksQuery>().out::<StreamChunkPage>(),
        op("post", "/streams/{id}/replay", "stream_replay", "Replay a stream to the same target (optionally with edited chunks) and record the result as a new stream.")
            .body::<StreamReplayRequest>().out::<StreamReplayResult>(),
        op("post", "/race", "race", "Send the same request several times at once.").body::<RaceRequest>().out::<RaceResult>(),
        op("post", "/replay/group", "replay_group", "Send a group of requests in order or in parallel.").body::<GroupRequest>().out::<GroupResult>(),
        op("post", "/fuzzer", "fuzzer", "Run a fuzzer attack and wait for the result.").body::<FuzzerRequest>().out::<FuzzerResult>(),
        op("get", "/fuzzer/attacks", "attacks_list", "Fuzzer attacks started in the background.").out::<Vec<AttackSummary>>(),
        op("post", "/fuzzer/attacks", "attack_start", "Start a fuzzer attack in the background.").body::<FuzzerRequest>().out::<FuzzerStart>(),
        op("get", "/fuzzer/attacks/{id}", "attack_status", "Status and result rows of a background attack.")
            .id_is_string().query::<FromQuery>().out::<AttackView>(),
        op("post", "/fuzzer/attacks/{id}/{action}", "attack_control", "Pause, resume or stop a background attack (`action`).")
            .id_is_string().json("Object with `status` (the attack's new status)."),
        op("post", "/crawl", "crawl", "Crawl a site and record what it finds.").body::<CrawlRequest>().out::<CrawlResult>(),
        op("post", "/discover", "discover", "Look for files and folders by trying words.").body::<DiscoverRequest>().out::<DiscoverResult>(),
        op("post", "/tools/decode", "tools_decode", "Encode or decode text locally.").body::<DecodeRequest>()
            .json("Object with `steps` (each decoding step) and `ops` (the available operations)."),
        op("post", "/tools/protobuf/decode", "tools_protobuf_decode", "Decode a gRPC or Protobuf body into editable text, without a schema.")
            .body::<ProtobufDecodeRequest>().out::<ProtobufDecoded>(),
        op("post", "/tools/protobuf/encode", "tools_protobuf_encode", "Encode edited Protobuf text back into body bytes (framed for gRPC if asked).")
            .body::<ProtobufEncodeRequest>().out::<ProtobufEncoded>(),
        op("post", "/tools/request-transform", "tools_request_transform", "Change the method or body encoding of a request text.")
            .body::<RequestTransform>().json("Object with `raw` (the rewritten request)."),
        op("post", "/tools/compare", "tools_compare", "Compare two recorded exchanges.").body::<CompareBody>()
            .json("A semantic response diff and a line diff of the two exchanges."),
        op("post", "/tools/token-analyzer", "tools_token_analyzer", "Collect tokens by sending a request repeatedly, then analyze them.")
            .body::<TokenAnalyzerRequest>().out::<TokenAnalyzerResult>(),
        op("post", "/tools/token-analyzer/analyze", "tools_token_analyzer_analyze", "Analyze tokens you already have.")
            .body::<TokensBody>().out::<pm_service::pm_tools::token_analyzer::Analysis>(),
        op("get", "/openapi", "openapi_get", "The API description imported into the model.").json_any("The stored import summary, or null."),
        op("post", "/openapi/import", "openapi_import", "Import an OpenAPI description of the target.")
            .body::<OpenApiImportRequest>().out::<OpenApiImportResult>(),
        op("get", "/graphql", "graphql_get", "The GraphQL schema imported into the model.").json_any("The stored import summary, or null."),
        op("post", "/graphql/import", "graphql_import", "Import a GraphQL schema (pasted, from an exchange, or by introspection).")
            .body::<GraphQlImportRequest>().out::<GraphQlImportResult>(),
        op("post", "/replay", "replay", "Send a request, as recorded or edited, through the policy gate.")
            .body::<ReplayRequest>().out::<ReplayResult>(),
        op("get", "/approvals", "approvals", "Approval requests, newest first (`status=all` or none: every status).")
            .query::<StatusQuery>().out::<Vec<ApprovalRow>>(),
        op("post", "/approvals/{id}/{decision}", "decide", "Approve or deny a request (`decision` is `approve` or `deny`).")
            .id_is_string().out::<ApprovalRow>(),
        op("get", "/identities", "identities", "Saved identities (sessions to test as).").out::<Vec<IdentityInfo>>(),
        op("post", "/identities/capture", "identity_capture", "Save the credentials of a recorded exchange as an identity.")
            .body::<CaptureBody>().out::<IdentityInfo>(),
        op("post", "/identities/{name}/check", "identity_check", "Check whether an identity is still logged in.").out::<IdentityCheck>(),
        op("post", "/identities/record-login", "identity_record_login", "Record a login flow from exchanges so it can be repeated.")
            .body::<RecordLoginBody>().out::<LoginRecording>(),
        op("post", "/identities/{name}/learn-logged-out", "identity_learn_logged_out", "Learn what a logged-out response looks like for an identity.")
            .out::<LoggedOutLearned>(),
        op("get", "/history/mark", "history_mark", "The id of the newest exchange, to mark a point in time.").json("Object with `id`."),
        op("post", "/authz/check", "authz_check", "Replay one recorded request as several identities and classify the responses.")
            .body::<AuthzCheckRequest>().out::<AuthzReport>(),
        op("get", "/authz/results", "authz_results", "Stored access-control results.").query::<ExchangeQuery>().out::<Vec<pm_service::pm_store::AuthzRow>>(),
        op("get", "/authz/candidates", "authz_candidates", "Recorded requests worth an access-control check.").out::<Vec<pm_service::pm_model::AuthzCandidate>>(),
        op("post", "/authz/matrix", "authz_matrix", "Test every operation as every identity.").body::<AuthzMatrixRequest>().out::<AuthzMatrix>(),
        op("get", "/model/snapshots", "model_snapshots", "Saved snapshots of the application model.").out::<Vec<SnapshotInfo>>(),
        op("post", "/model/snapshots", "model_snapshot_save", "Save a snapshot of the application model.").body::<SnapshotBody>().out::<SnapshotInfo>(),
        op("get", "/model/changes", "model_changes", "What changed in the model since a snapshot.").query::<ChangesQuery>().out::<ModelChanges>(),
        op("get", "/model", "model", "The application model built from recorded traffic.").query::<ModelFilter>()
            .json("Object with the model's operations and, with `include_objects`, its objects."),
        op("get", "/coverage", "coverage", "Which operations have been tested.").query::<CoverageQuery>().out::<pm_service::pm_ledger::Coverage>(),
        op("get", "/scan/issues", "scan_issues", "Passive scan: issues found in recorded traffic.").query::<ScanFilter>().out::<Vec<ScanIssue>>(),
        op("post", "/scan/active", "scan_active", "Active scan of one recorded request.").body::<ActiveScanRequest>().out::<ActiveScanResult>(),
        op("get", "/scan/tasks", "scan_tasks_list", "Background scan tasks.").out::<Vec<ScanTaskView>>(),
        op("post", "/scan/tasks", "scan_task_start", "Start a crawl-and-audit background task.").body::<ScanTaskRequest>().out::<ScanTaskView>(),
        op("get", "/scan/tasks/{id}", "scan_task_status", "Status of a background scan task.").id_is_string().out::<ScanTaskView>(),
        op("post", "/scan/tasks/{id}/cancel", "scan_task_cancel", "Cancel a scan task.").id_is_string().out::<ScanTaskView>(),
        op("post", "/scan/tasks/{id}/pause", "scan_task_pause", "Pause a scan task.").id_is_string().out::<ScanTaskView>(),
        op("post", "/scan/tasks/{id}/resume", "scan_task_resume", "Resume a paused scan task.").id_is_string().out::<ScanTaskView>(),
        op("get", "/collaborator", "collaborator_status", "State of the out-of-band listeners.").out::<CollaboratorStatus>(),
        op("post", "/collaborator/listener", "collaborator_listen", "Start the out-of-band HTTP listener.").body::<ListenBody>().out::<CollaboratorStatus>(),
        op("post", "/collaborator/smtp", "collaborator_smtp", "Start the out-of-band SMTP listener.").body::<SmtpBody>().out::<CollaboratorStatus>(),
        op("get", "/collaborator/payloads", "collaborator_payloads", "Payloads created so far.").query::<CollabQuery>().out::<Vec<CollaboratorPayload>>(),
        op("post", "/collaborator/payloads", "collaborator_payload", "Create an out-of-band payload.").body::<PayloadBody>().out::<CollaboratorPayload>(),
        op("get", "/collaborator/interactions", "collaborator_interactions", "Calls the listeners received.")
            .query::<CollabQuery>().out::<Vec<CollaboratorInteraction>>(),
        op("get", "/collaborator/probes", "collaborator_probes", "Probes sent with out-of-band payloads.").query::<ProbesQuery>().out::<Vec<CollaboratorProbe>>(),
        op("get", "/organizer", "organizer_list", "Exchanges kept in the organizer.").query::<OrganizerQuery>().out::<Vec<OrganizerItem>>(),
        op("post", "/organizer", "organizer_add", "Keep an exchange in the organizer.").body::<OrganizerAdd>().out::<OrganizerItem>(),
        op("patch", "/organizer/{id}", "organizer_update", "Change the status or note of an organizer item.").body::<OrganizerUpdate>().out::<OrganizerItem>(),
        op("delete", "/organizer/{id}", "organizer_delete", "Remove an item from the organizer.").json("Object with `deleted` (the id)."),
        op("post", "/engage/comments", "engage_comments", "Comments found in recorded responses.").body::<EngageFilter>().out::<Vec<FoundComment>>(),
        op("post", "/engage/scripts", "engage_scripts", "Scripts found in recorded responses.").body::<EngageFilter>().out::<Vec<FoundScript>>(),
        op("post", "/engage/js-endpoints", "engage_js_endpoints", "Endpoints referenced from recorded JavaScript.").body::<EngageFilter>().out::<Vec<FoundEndpoint>>(),
        op("post", "/engage/logic", "engage_logic", "Business-logic leads from recorded traffic.").body::<EngageFilter>().out::<LogicReport>(),
        op("post", "/traffic/triage", "traffic_triage", "Rank recorded exchanges by how interesting they look.").body::<TriageBody>().out::<Vec<TriageItem>>(),
        op("get", "/memory", "memory_list", "Notes remembered about targets.").query::<HostQuery>().out::<Vec<Memory>>(),
        op("delete", "/memory/{id}", "memory_delete", "Forget a remembered note.").json("Object with `deleted` (the id)."),
        op("get", "/update", "update_get", "Update-check settings and the last answer.").out::<UpdateStatus>(),
        op("put", "/update", "update_set", "Turn the daily update check on or off.").body::<UpdateSet>().out::<UpdateStatus>(),
        op("get", "/skills", "skills_list", "Built-in and custom skills (prompt recipes).").out::<Vec<Skill>>(),
        op("post", "/skills/{name}", "skill_get", "Fill a skill's template with arguments.")
            .body::<std::collections::BTreeMap<String, String>>().json("Object with `skill` and `text` (the filled template)."),
        op("post", "/update/check", "update_check", "Check for a new version now.").body::<UpdateCheck>().out::<UpdateStatus>(),
        op("post", "/recon/dns", "recon_dns", "Look up DNS records of a host.").body::<ReconDns>().out::<DnsReport>(),
        op("post", "/recon/wayback", "recon_wayback", "List captures of a host in the web archive.").body::<ReconWayback>().out::<WaybackReport>(),
        op("post", "/engage/analyze", "engage_analyze", "Summary analysis of a target's recorded traffic.").body::<EngageFilter>().out::<TargetAnalysis>(),
        op("post", "/engage/references", "engage_references", "Exchanges that reference the response of this one.")
            .body::<EngageExchange>().out::<Vec<pm_service::pm_store::ExchangeSummary>>(),
        op("post", "/engage/csrf", "engage_csrf", "A CSRF proof-of-concept page for a recorded request.").body::<EngageExchange>().json("Object with `html`."),
        op("post", "/engage/clickjacking", "engage_clickjacking", "Whether a recorded page can be framed, with a proof-of-concept page.")
            .body::<EngageExchange>().out::<pm_service::pm_tools::engage::Clickjacking>(),
        op("get", "/plugins", "plugins", "Installed plugins and their state.").out::<PluginsView>(),
        op("post", "/plugins/check", "plugin_check", "Run a plugin check on a recorded exchange.").body::<PluginCheckRequest>().out::<PluginCheckResult>(),
        op("put", "/plugins/{name}", "plugin_set", "Turn a plugin on or off.").body::<PluginSet>().out::<PluginsView>(),
        op("post", "/plugins/{name}/accept", "plugin_accept", "A person accepts the permissions a version 2 plugin declares (and the plugin turns on).").out::<PluginsView>(),
        op("put", "/plugins/{name}/hooks/{kind}", "plugin_hook_set", "Turn a plugin's request or response hook on or off, reorder it, pause or resume it.").body::<PluginHookSet>().out::<PluginsView>(),
        op("get", "/plugins/{name}/panels/{panel}", "plugin_panel", "The data of a plugin panel.").query::<PanelQuery>().out::<pm_service::pm_plugin::panel::PanelData>(),
        op("get", "/scan/profiles", "scan_profiles", "Scan profiles, built-in and saved.").out::<Vec<ScanProfile>>(),
        op("post", "/scan/profiles", "scan_profile_save", "Save a scan profile.").body::<ScanProfile>().out::<Vec<ScanProfile>>(),
        op("get", "/scan/custom-checks", "custom_checks", "Saved custom checks.").out::<Vec<SavedCustomCheck>>(),
        op("post", "/scan/custom-checks", "custom_check_save", "Save a custom check written as YAML.").body::<CheckYaml>().out::<SavedCustomCheck>(),
        op("delete", "/scan/custom-checks/{id}", "custom_check_delete", "Delete a custom check.").id_is_string().json("Object with `deleted` (true if it existed)."),
        op("post", "/scan/custom", "custom_scan", "Run custom checks against recorded traffic.").body::<CustomScanRequest>().out::<CustomScanResult>(),
        op("post", "/dom/test", "dom_test", "Render a recorded page in the browser and look for DOM-based problems.").body::<DomTestRequest>().out::<DomTestResult>(),
        op("delete", "/scan/profiles/{name}", "scan_profile_delete", "Delete a saved scan profile.").json("Object with `deleted` (true if it existed)."),
        op("get", "/scan/schedules", "scan_schedules", "Scheduled scans.").out::<Vec<ScanSchedule>>(),
        op("post", "/scan/schedules", "scan_schedule_save", "Save a scheduled scan.").body::<ScanSchedule>().out::<ScanSchedule>(),
        op("delete", "/scan/schedules/{id}", "scan_schedule_delete", "Delete a scheduled scan.").json("Object with `deleted` (true if it existed)."),
        op("post", "/scan/schedules/{id}/run", "scan_schedule_run", "Run a scheduled scan now.").out::<ScanTaskView>(),
        op("get", "/hypotheses", "hypotheses", "Hypotheses to test, newest first.").query::<StatusQuery>().out::<Vec<pm_service::pm_ledger::Hypothesis>>(),
        op("get", "/findings", "findings", "Findings, optionally of one status.").query::<StatusQuery>().json_list("Findings; each is an object (id, title, severity, status, evidence and more)."),
        op("post", "/findings", "finding_create", "Record a finding.").body::<NewFinding>().json("The new finding as an object."),
        op("get", "/findings/{id}", "finding", "One finding.").json("The finding as an object."),
        op("patch", "/findings/{id}", "finding_update", "Update a finding. The body must still carry `id` (the handler overwrites it with the path id).")
            .body::<FindingUpdate>().json("The updated finding as an object."),
        op("post", "/findings/{id}/retest", "finding_retest", "Send the finding's request again and compare.").out::<Retest>(),
        op("post", "/findings/{id}/prove", "finding_prove", "Try to prove a finding with a proof oracle.").out::<FindingProve>(),
        op("post", "/findings/prove", "findings_prove_all", "Try to prove every unproven finding.").out::<ProveSweep>(),
        op("get", "/library", "library", "The built-in issue library (names, descriptions, remediation).").out::<Vec<pm_service::pm_scan::library::IssueType>>(),
        op("get", "/report/templates", "report_templates", "Report templates, built-in and saved.").out::<Vec<ReportTemplate>>(),
        op("post", "/report/templates", "report_template_save", "Save a report template.").body::<ReportTemplate>().out::<Vec<ReportTemplate>>(),
        op("delete", "/report/templates/{name}", "report_template_delete", "Delete a saved report template.").json("Object with `deleted` (true if it existed)."),
        op("post", "/proofs", "proof_run", "Run a proof oracle and store the result.").body::<ProofRequest>().out::<ProofResult>(),
        op("get", "/proofs/{id}", "proof", "A stored proof result.").json("The stored proof as an object."),
        op("post", "/proofs/{id}/rerun", "proof_rerun", "Run a stored proof again.").out::<ProofResult>(),
        op("get", "/audit", "audit", "The audit log, newest first.").query::<LimitQuery>().out::<Vec<pm_service::pm_store::AuditRecord>>(),
        op("get", "/audit/verify", "audit_verify", "Check the audit log's hash chain.")
            .json("Object with `intact` and either `records` (how many were checked) or `error`."),
        op("get", "/report", "report", "Render the report; always a download.").query::<ReportQuery>()
            .download("text/markdown, text/html", "The rendered report; the content type follows `format`."),
        op("get", "/evidence/pack", "evidence_pack", "A signed evidence pack (ZIP); its fingerprint is in the `X-Evidence-Fingerprint` header.")
            .query::<PackQuery>().download(ZIP, "The evidence pack."),
        op("get", "/evidence/fingerprint", "evidence_fingerprint", "The fingerprint of the signing key.").json("Object with `fingerprint`."),
        op("post", "/evidence/verify", "evidence_verify", "Check an evidence pack.")
            .raw_body(ZIP, "The evidence pack (ZIP file bytes).").out::<EvidenceVerification>(),
        op("get", "/coverage/proof", "coverage_proof", "Proof status per operation and identity.").out::<CoverageProof>(),
        op("get", "/regress", "regress_list", "Regression tests made from proven findings.").out::<RegressionExport>(),
        op("get", "/regress/export", "regress_export", "The regression tests as a ZIP (tests, README, example CI workflow).")
            .download(ZIP, "The regression test pack."),
        op("get", "/intercept", "intercept_state", "Intercept settings and the held queue.").out::<InterceptState>(),
        op("put", "/intercept/settings", "intercept_settings", "Change what the proxy holds.").body::<pm_service::pm_proxy::InterceptSettings>().out::<InterceptState>(),
        op("post", "/intercept/forward-all", "intercept_forward_all", "Forward everything held.").json("Object with `forwarded` (how many)."),
        op("post", "/intercept/{id}/forward", "intercept_forward", "Forward one held message, optionally edited.").body::<ForwardBody>().json("Object with `forwarded` (the id)."),
        op("post", "/intercept/{id}/drop", "intercept_drop", "Drop one held message.").json("Object with `dropped` (the id)."),
        op("get", "/match-replace", "rules_get", "Match-and-replace rules.").json("Object with `rules` (list of rules)."),
        op("put", "/match-replace", "rules_put", "Replace all match-and-replace rules.").body::<RulesBody>().json("Object with `rules` (the stored list)."),
        op("get", "/network", "network_get", "Outgoing network settings (ordered upstream rules, client certificates, host overrides). Proxy passwords show as `********`.").out::<pm_service::pm_replay::NetConfig>(),
        op("put", "/network", "network_put", "Change the outgoing network settings.").body::<pm_service::pm_replay::NetConfig>().out::<pm_service::pm_replay::NetConfig>(),
        op("post", "/network/upstream/resolve", "network_resolve", "Which upstream rule decides how a host is reached (saved rules, or a draft passed in `rules`). Sends nothing.")
            .body::<UpstreamResolveRequest>().out::<UpstreamResolution>(),
        op("get", "/proxy/listeners", "listeners_get", "Proxy listeners and their state.").out::<ListenersView>(),
        op("put", "/proxy/listeners", "listeners_put", "Replace the proxy listeners.").body::<ListenersBody>().out::<ListenersView>(),
        op("get", "/history/recording", "recording_get", "What the proxy records.").out::<RecordingSettings>(),
        op("put", "/history/recording", "recording_put", "Change what the proxy records.").body::<RecordingSettings>().out::<RecordingSettings>(),
        op("get", "/devices", "devices_get", "Client addresses (phones, tablets) seen in history, with their names and counts.").out::<DevicesView>(),
        op("put", "/devices/{addr}", "device_put", "Give a client address a name, e.g. Pixel 8.").body::<DeviceNameBody>().out::<DeviceView>(),
        op("delete", "/devices/{addr}", "device_delete", "Remove a device's name.").json("Object with `deleted` (the address)."),
        op("get", "/session", "session_get", "Session handling: cookie jar, macros and rules.").out::<SessionView>(),
        op("put", "/session", "session_put", "Change session handling.").body::<SessionConfig>().out::<SessionView>(),
        op("get", "/session/jar", "session_jar", "Cookies in the jar.").json("Object with `cookies` (list of cookies)."),
        op("delete", "/session/jar", "session_jar_clear", "Empty the cookie jar.").json("Object with `cleared`."),
        op("post", "/session/macros/{name}/run", "session_macro_run", "Run a session macro.").out::<MacroRun>(),
        op("get", "/assistant", "assistant_state", "Assistant settings, key status and recent chats.")
            .json("Object with `config`, `local`, `cloud_models_allowed`, `problem`, `acts_as`, `key` and `chats`."),
        op("put", "/assistant/config", "assistant_config", "Change the assistant's settings.").body::<AssistantConfig>().out::<AssistantConfig>(),
        op("put", "/assistant/key", "model_key_set", "Store a model API key.").body::<KeyBody>().out::<KeyStatus>(),
        op("delete", "/assistant/key/{name}", "model_key_remove", "Remove a stored model API key.").out::<KeyStatus>(),
        op("get", "/assistant/chats/{id}", "assistant_chat", "One assistant chat with its messages.").out::<Chat>(),
        op("post", "/assistant/send", "assistant_send", "Send a message to the assistant and wait for its turn.").body::<SendBody>().out::<pm_assistant::Turn>(),
        op("post", "/assistant/models", "assistant_models", "Models the server in these settings offers.")
            .body::<AssistantConfig>().json("Object with `models` (list of names)."),
        op("post", "/findings/{id}/explain", "finding_explain", "Ask the assistant to explain a finding.").body::<ExplainBody>().json("Object with `explanation` (Markdown)."),
        op("get", "/ai-scan", "ai_scan_list", "AI scans, newest first.").out::<Vec<AiScan>>(),
        op("post", "/ai-scan", "ai_scan_start", "Start an AI scan.").body::<AiScanRequest>().out::<AiScan>(),
        op("get", "/ai-scan/prompt", "ai_scan_prompt", "The system prompt a scan would get, with the default target.").json("Object with `target` and `prompt`."),
        op("get", "/ai-scan/{id}", "ai_scan_get", "One AI scan.").out::<AiScan>(),
        op("post", "/ai-scan/{id}/stop", "ai_scan_stop", "Stop an AI scan.").out::<AiScan>(),
        op("post", "/ai-scan/{id}/message", "ai_scan_message", "Send a message to a running AI scan.").body::<AiScanMessage>().out::<AiScan>(),
        op("get", "/attack-paths", "attack_paths", "Attack paths, optionally of one scan.").query::<ScanQuery>().out::<Vec<AttackPath>>(),
        op("post", "/attack-paths", "attack_path_create", "Record an attack path.").body::<NewAttackPath>().out::<AttackPath>(),
        op("delete", "/attack-paths/{id}", "attack_path_delete", "Delete an attack path.").json("Object with `deleted` (the id)."),
        op("get", "/attack-graph", "attack_graph", "Attack paths merged into a graph.").query::<ScanQuery>().out::<AttackGraph>(),
    ]
}
