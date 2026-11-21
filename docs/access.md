# Access table

<!-- Generated from `crates/pm-service/src/access.rs` by `crates/pm-service/tests/access.rs`. Do not edit by hand: run `UPDATE_ACCESS_DOC=1 cargo test -p pm-service --test access`. -->

Who may do what in `pm-service` (ADR-0022, migration step 1). Every action that only some principals may take has an entry here, and the service asks `Service::require` (or `Principal::allows` where the answer shapes a view, not a refusal) before it acts. The check is deny by default.

- **Roles.** In single-user mode, which is all there is today, a person is the implicit `owner`; an agent, plugin, scanner or CI actor acts as `tester`, the ceiling the ADR gives machine credentials. Per-project roles for several people come with ADR-0022 step 6; the columns below already say what each will be allowed.
- **People only** means that only an actor of kind `human` may, whatever the role: an owner's agent is still an agent.
- Roles and `people_only` narrow what the policy gate allows; they never widen it. Traffic still goes through the gate (scope, tiers, windows, approvals).
- What an agent is *shown* (redaction, untrusted-content wrapping, event filtering) is not an access decision; `tests/access.rs` lists those uses of the actor's kind with the reason for each.

| Perm | Owner | Tester | Viewer | People only | Covers | Required by |
| --- | --- | --- | --- | --- | --- | --- |
| `IdentitiesWrite` | yes | yes | no | yes | Define, change and delete identities and login recipes; record logins | `identity_delete`, `identity_record_login`, `identity_set`, `identity_set_login_from` |
| `ScanConfigWrite` | yes | yes | no | yes | Save and delete custom checks and scan profiles | `custom_check_delete`, `custom_check_save`, `scan_profile_delete`, `scan_profile_save` |
| `ReportTemplatesWrite` | yes | yes | no | yes | Save and delete report templates | `report_template_delete`, `report_template_save` |
| `SchedulesWrite` | yes | yes | no | yes | Create, change and delete scan schedules | `schedule_delete`, `schedule_run_now`, `schedule_save` |
| `SessionHandling` | yes | yes | no | yes | See or change session handling, the cookie jar, run a macro | `session_get`, `session_jar`, `session_jar_clear`, `session_macro_run`, `session_set` |
| `InterceptUse` | yes | yes | no | yes | Use the intercept queue, read intercept events | `intercept_drop`, `intercept_forward`, `intercept_forward_all`, `intercept_settings`, `may_read_topic` |
| `NetworkWrite` | yes | no | no | yes | Change network settings and what the proxy records | `network_set`, `recording_set` |
| `ListenersWrite` | yes | no | no | yes | Change proxy listeners; start the SMTP and callback listeners | `collaborator_listen`, `collaborator_smtp`, `listeners_set` |
| `RulesWrite` | yes | no | no | yes | Change match-and-replace rules | `set_match_replace_rules` |
| `RoeWrite` | yes | no | no | yes | Change the rules of engagement | `roe_set` |
| `AssistantConfigWrite` | yes | no | no | yes | Change the assistant settings | `assistant_config_set` |
| `ModelKeysWrite` | yes | no | no | yes | Save and remove model API keys | `model_key_remove`, `model_key_set` |
| `ApprovalsDecide` | yes | yes | no | yes | Approve or deny a pending action | `decide_approval`, `pm-cli::human_actor` |
| `ProjectTrust` | yes | no | no | yes | Confirm a project's settings (leave safe mode) | `trust_confirm` |
| `PluginsManage` | yes | yes | no | yes | Turn plugins on or off, accept their permissions | `plugin_accept_permissions`, `plugin_set_enabled` |
| `HooksManage` | yes | yes | no | yes | Set up plugin hooks | `plugin_hook_set` |
| `WorkflowsWrite` | yes | yes | no | yes | Create, change and delete workflows | `workflow_create`, `workflow_delete`, `workflow_update` |
| `WorkflowTriggers` | yes | yes | no | yes | Switch workflow triggers on or off; run triggers | `trigger_on_exchange`, `workflow_trigger_set` |
| `IntegrationsRead` | yes | no | no | yes | Read integration settings and the delivery log | `integration_deliveries`, `integration_get`, `integration_list` |
| `IntegrationsWrite` | yes | no | no | yes | Create, change, enable, delete and test integrations | `integration_delete`, `integration_enable`, `integration_set`, `integration_test` |
| `IntegrationsSend` | yes | yes | no | yes | Send a finding to an integration | `integration_send_finding` |
| `DevicesWrite` | yes | yes | no | yes | Name or unname client devices | `device_remove_name`, `device_set_name` |
| `ExportEvidence` | yes | yes | no | yes | Export evidence packs and regression tests | `evidence_pack`, `regression_zip` |
| `AiScanControl` | yes | yes | no | yes | Start an AI scan, send it messages | `ai_scan_create`, `ai_scan_message` |
| `BrowserOpen` | yes | yes | no | yes | Open a browser window | `browser_open` |
| `MemoryDelete` | yes | yes | no | yes | Delete agent memory notes | `memory_delete` |
| `AttackPathsDelete` | yes | yes | no | yes | Delete attack paths | `attack_path_delete` |
| `ModelSnapshotsWrite` | yes | yes | no | yes | Save a model snapshot | `model_snapshot_save` |
| `UiStateWrite` | yes | yes | yes | yes | Save UI state | `ui_state_put` |
| `FindingsExplain` | yes | yes | no | yes | Save a model-written explanation on a finding | `finding_set_explanation`, `pm-assistant::explain_finding` |
| `FindingStatusFinal` | yes | yes | no | yes | Change a judged finding; set statuses only people may set | `finding_update` |
| `RunsReadAll` | yes | yes | yes | yes | See every attack, scan task and workflow run (others see their own) | `attack`, `fuzzer_list`, `scan_task`, `scan_task_list`, `workflow_run_get`, `workflow_runs` |
