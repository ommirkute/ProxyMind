# Access table

<!-- Generated from `crates/pm-service/src/access.rs` by `crates/pm-service/tests/access.rs`. Do not edit by hand: run `UPDATE_ACCESS_DOC=1 cargo test -p pm-service --test access`. -->

Who may do what in `pm-service` (ADR-0022, migration steps 1 and 6). Every public service method that takes an actor asks `Service::require` before it touches anything (a test fails when one does not), the API checks the same table for each route before the handler runs (`pm-api/src/route_perms.rs`) and the MCP server for each tool (`pm-mcp::tool_perm`). The check is deny by default.

- **Roles.** On a project server a principal's role is the member's role on the project (`owner`, `tester`, `viewer`), or for a token the lower of its ceiling and its owner's current role. An actor the server did not register is a `viewer`, never an owner. In single-user mode, a person is the implicit `owner`; an agent, plugin, scanner or CI actor acts as `tester`, the ceiling the ADR gives machine credentials.
- **People only** means that only an actor of kind `human` may, whatever the role: an owner's agent token is still an agent, and a non-person is never above `tester`.
- **Viewers** read what the Owner/Tester/Viewer columns say they read, with secrets replaced by placeholders as agents see them; they cannot send, write or configure anything.
- Roles and `people_only` narrow what the policy gate allows; they never widen it. Traffic still goes through the gate (scope, tiers, windows, approvals). Approvals have finer rules than this table (a tester decides only what their own tokens asked; see `docs/server-mode.md`).
- What an agent or viewer is *shown* (redaction, untrusted-content wrapping, event filtering) is mostly not an access decision; `tests/access.rs` lists those uses of the actor's kind with the reason for each.

| Perm | Owner | Tester | Viewer | People only | Covers | Required by |
| --- | --- | --- | --- | --- | --- | --- |
| `IdentitiesWrite` | yes | yes | no | yes | Define, change and delete identities and login recipes; record logins | `identity_delete`, `identity_record_login`, `identity_set`, `identity_set_login_from`, `pm-api::route_perm` |
| `ScanConfigWrite` | yes | yes | no | yes | Save and delete custom checks and scan profiles | `custom_check_delete`, `custom_check_save`, `pm-api::route_perm`, `scan_profile_delete`, `scan_profile_save` |
| `ReportTemplatesWrite` | yes | yes | no | yes | Save and delete report templates | `pm-api::route_perm`, `report_template_delete`, `report_template_save` |
| `SchedulesWrite` | yes | yes | no | yes | Create, change and delete scan schedules | `pm-api::route_perm`, `schedule_delete`, `schedule_run_now`, `schedule_save` |
| `SessionHandling` | yes | yes | no | yes | See or change session handling, the cookie jar, run a macro | `pm-api::route_perm`, `session_get`, `session_jar`, `session_jar_clear`, `session_macro_run`, `session_set` |
| `InterceptUse` | yes | yes | no | yes | Use the intercept queue, read intercept events | `intercept_drop`, `intercept_forward`, `intercept_forward_all`, `intercept_settings`, `pm-api::route_perm`, `topic_perm` |
| `NetworkWrite` | yes | no | no | yes | Change network settings and what the proxy records | `network_set`, `pm-api::route_perm`, `recording_set` |
| `ListenersWrite` | yes | no | no | yes | Change proxy listeners; start the SMTP and callback listeners | `collaborator_listen`, `collaborator_smtp`, `listeners_set`, `pm-api::route_perm` |
| `RulesWrite` | yes | no | no | yes | Change match-and-replace rules | `pm-api::route_perm`, `set_match_replace_rules` |
| `RoeWrite` | yes | no | no | yes | Change the rules of engagement | `pm-api::a_few_rows_say_what_the_adr_says`, `pm-api::route_perm`, `roe_set` |
| `AssistantConfigWrite` | yes | no | no | yes | Change the assistant settings | `assistant_config_set`, `pm-api::route_perm` |
| `ModelKeysWrite` | yes | no | no | yes | Save and remove model API keys | `model_key_remove`, `model_key_set`, `pm-api::route_perm` |
| `ApprovalsDecide` | yes | yes | no | yes | Approve or deny a pending action | `decide_approval`, `pm-api::route_perm`, `pm-cli::human_actor` |
| `ProjectTrust` | yes | no | no | yes | Confirm a project's settings (leave safe mode) | `pm-api::route_perm`, `trust_confirm` |
| `PluginsManage` | yes | yes | no | yes | Turn plugins on or off, accept their permissions | `plugin_accept_permissions`, `plugin_set_enabled`, `pm-api::route_perm`, `pm-mcp::tool_perm` |
| `HooksManage` | yes | yes | no | yes | Set up plugin hooks | `plugin_hook_set`, `pm-api::route_perm` |
| `WorkflowsWrite` | yes | yes | no | yes | Create, change and delete workflows | `pm-api::route_perm`, `workflow_create`, `workflow_delete`, `workflow_update` |
| `WorkflowTriggers` | yes | yes | no | yes | Switch workflow triggers on or off; run triggers | `pm-api::route_perm`, `trigger_on_exchange`, `workflow_trigger_set` |
| `IntegrationsRead` | yes | no | no | yes | Read integration settings and the delivery log | `integration_deliveries`, `integration_get`, `integration_list`, `pm-api::route_perm` |
| `IntegrationsWrite` | yes | no | no | yes | Create, change, enable, delete and test integrations | `integration_delete`, `integration_enable`, `integration_set`, `integration_test`, `pm-api::route_perm` |
| `IntegrationsSend` | yes | yes | no | yes | Send a finding to an integration | `integration_send_finding`, `pm-api::route_perm` |
| `DevicesWrite` | yes | yes | no | yes | Name or unname client devices | `device_remove_name`, `device_set_name`, `pm-api::route_perm` |
| `ExportEvidence` | yes | yes | no | yes | Export evidence packs and regression tests | `audit_checkpoint`, `evidence_pack`, `pm-api::route_perm`, `regression_zip` |
| `AiScanControl` | yes | yes | no | yes | Start an AI scan, send it messages | `ai_scan_create`, `ai_scan_message`, `ai_scan_stop`, `pm-api::route_perm` |
| `BrowserOpen` | yes | yes | no | yes | Open a browser window | `browser_open`, `pm-api::route_perm` |
| `MemoryDelete` | yes | yes | no | yes | Delete agent memory notes | `memory_delete`, `pm-api::route_perm` |
| `AttackPathsDelete` | yes | yes | no | yes | Delete attack paths | `attack_path_delete`, `pm-api::route_perm` |
| `ModelSnapshotsWrite` | yes | yes | no | yes | Save a model snapshot | `model_snapshot_save`, `pm-api::route_perm` |
| `UiStateWrite` | yes | yes | yes | yes | Save UI state | `pm-api::route_perm`, `ui_state_put` |
| `FindingsExplain` | yes | yes | no | yes | Save a model-written explanation on a finding | `finding_set_explanation`, `pm-api::route_perm`, `pm-assistant::explain_finding` |
| `FindingStatusFinal` | yes | yes | no | yes | Change a judged finding; set statuses only people may set | `finding_update` |
| `RunsReadAll` | yes | yes | yes | yes | See every attack, scan task and workflow run (others see their own) | `attack`, `fuzzer_list`, `scan_task`, `scan_task_list`, `workflow_run_get`, `workflow_runs` |
| `TokensManage` | yes | yes | no | yes | Create, list and revoke one's own tokens (a token cannot manage tokens) | `pm-api::require_person` |
| `TokensManageOthers` | yes | no | no | yes | Create, list and revoke other people's tokens | `pm-api::others_allowed` |
| `HistoryRead` | yes | yes | yes | no | Read recorded traffic (viewers see it redacted, as agents do) | `change_diffs`, `compare_exchanges`, `engage_analyze`, `engage_comments`, `engage_csrf_poc`, `engage_js_endpoints`, `engage_logic`, `engage_references`, `engage_scripts`, `exchange_get`, `exchange_raw_request`, `history_search`, `history_search_text`, `organizer_list`, `pm-api::a_few_rows_say_what_the_adr_says`, `pm-api::exchange`, `pm-api::route_perm`, `pm-mcp::tool_perm`, `protobuf_decode`, `site_map`, `stream_chunks`, `stream_get`, `streams_list`, `token_analyzer_run`, `topic_perm`, `traffic_triage`, `ws_history`, `ws_messages`, `ws_search_text` |
| `FindingsRead` | yes | yes | yes | no | Read findings, passive issues and proofs | `pm-api::route_perm`, `pm-mcp::tool_perm`, `scan_passive`, `topic_perm` |
| `ReportsRead` | yes | yes | yes | no | Read reports and evidence | `pm-api::route_perm`, `report_render_for` |
| `ModelRead` | yes | yes | yes | no | Read the application model, hypotheses and coverage | `pm-api::route_perm`, `pm-mcp::tool_perm`, `workflow_get`, `workflow_list`, `workflow_summaries` |
| `RunsRead` | yes | yes | yes | no | See the state of scan tasks, attacks, workflow runs and AI scans | `fuzzer_list`, `fuzzer_status`, `pm-api::route_perm`, `pm-mcp::tool_perm`, `scan_task_list`, `scan_task_status`, `topic_perm`, `workflow_run_get`, `workflow_runs` |
| `RoeRead` | yes | yes | yes | no | Read the rules of engagement | `pm-api::route_perm`, `pm-mcp::handle`, `pm-mcp::tool_perm` |
| `Info` | yes | yes | yes | no | Public facts: status, setup help, the CA certificate, playbooks | `pm-api::route_perm`, `pm-mcp::tool_perm` |
| `AuditRead` | yes | yes | no | no | Read the audit log and its checkpoints | `pm-api::a_few_rows_say_what_the_adr_says`, `pm-api::route_perm`, `topic_perm` |
| `ApprovalsRead` | yes | yes | no | no | See approvals and the actions they cover | `pm-api::route_perm`, `pm-mcp::tool_perm`, `topic_perm` |
| `IdentitiesRead` | yes | yes | no | no | List identities (never their credentials) | `pm-api::route_perm`, `pm-mcp::tool_perm` |
| `ConfigRead` | yes | yes | no | no | Read network, listener, rule, recording and device settings | `pm-api::route_perm`, `pm-mcp::tool_perm`, `topic_perm` |
| `AssistantUse` | yes | yes | no | yes | Use the built-in assistant: read its chats, send it messages | `pm-api::route_perm` |
| `SendTraffic` | yes | yes | no | no | Send traffic through the gate: replay, fuzz, scan, crawl, workflows, proofs, retests | `authz_check`, `authz_matrix`, `auto_access_control`, `auto_active_sweep`, `auto_discover`, `auto_prove`, `auto_write_checks`, `crawl`, `custom_scan`, `discover`, `dom_test`, `finding_prove`, `finding_retest`, `fuzzer_control`, `fuzzer_run`, `fuzzer_start`, `graphql_import`, `graphql_object_access`, `identity_check`, `identity_learn_logged_out`, `openapi_import`, `pm-api::a_few_rows_say_what_the_adr_says`, `pm-api::route_perm`, `pm-mcp::tool_perm`, `proof_rerun`, `proof_run`, `race_send`, `recon_dns`, `recon_wayback`, `replay_group`, `replay_send`, `scan_active`, `scan_task_cancel`, `scan_task_pause`, `scan_task_resume`, `scan_task_start`, `stream_replay`, `workflow_run`, `ws_replay` |
| `IdentitiesCapture` | yes | yes | no | no | Capture an identity from a recorded request; set a health check from one | `identity_capture`, `identity_set_health_from`, `pm-api::route_perm`, `pm-mcp::tool_perm` |
| `FindingsWrite` | yes | yes | no | no | Create and edit findings | `finding_create`, `pm-api::route_perm`, `pm-mcp::tool_perm` |
| `ModelWrite` | yes | yes | no | no | Create and edit hypotheses | `hypothesis_create`, `hypothesis_update`, `pm-mcp::tool_perm` |
| `NotesWrite` | yes | yes | no | no | Write annotations, organizer items, agent memory and attack paths | `attack_path_create`, `exchange_annotate`, `memory_save`, `organizer_add`, `organizer_delete`, `organizer_update`, `pm-api::route_perm`, `pm-mcp::tool_perm` |
| `TrafficImport` | yes | yes | no | no | Import traffic (HAR, cURL) | `pm-api::route_perm`, `pm-mcp::tool_perm`, `traffic_import_har` |
| `TrafficExport` | yes | yes | no | no | Export traffic (HAR, cURL, code) | `exchange_code`, `exchange_curl`, `pm-api::route_perm`, `traffic_export_har` |
| `CollaboratorUse` | yes | yes | no | no | Use the Collaborator: payloads, interactions, probes | `collaborator_payload`, `pm-api::route_perm`, `pm-mcp::tool_perm`, `topic_perm` |
| `UpdateSettings` | yes | no | no | yes | Change update settings and check for updates | `pm-api::route_perm`, `update_check`, `update_set` |
| `MembersManage` | yes | no | no | yes | List members; change or remove their roles | `pm-api::a_few_rows_say_what_the_adr_says`, `pm-api::members_perm`, `pm-api::route_perm` |
