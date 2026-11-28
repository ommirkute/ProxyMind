//! Which permission each REST route needs (ADR-0022 step 6), for server mode.
//!
//! This is the API's second line. The first is `pm-service`: every public method that takes an actor asks
//! `Service::require` itself, so MCP, the CLI and the assistant are covered without this file. The routes here are
//! checked **before** the handler runs, which also covers the handlers that call a service method without an actor
//! (listing identities, approvals, the audit log, settings), where a viewer would otherwise read what only people with
//! a working role may.
//!
//! Deny by default: a route with no entry is refused to everyone (`route_perm` returns `None`); the test
//! `every_route_has_a_permission` walks the contract table, and the matrix test drives every route as every role.
//! Single-user mode does not use this table: there a person is the implicit owner and agents are held by the service.

use pm_service::access::Perm;

/// What a route needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutePerm {
    /// The handler decides for itself and says why: the sign-in and account endpoints (a session or token reaches
    /// them only as far as `server_mode` lets it) and the MCP endpoint (which asks per tool).
    Open,
    /// This permission, from the principal's role and kind.
    Needs(Perm),
}

use RoutePerm::{Needs, Open};

/// The permission for `method` on the route `template` (as registered, `/status`, `/exchanges/{id}`, without the
/// `/api/v1` prefix). `HEAD` counts as `GET`. `None`: no rule, so the route is refused.
pub fn route_perm(method: &str, template: &str) -> Option<RoutePerm> {
    let method = if method == "HEAD" { "GET" } else { method };
    Some(match (method, template) {
        // Nothing but public facts.
        (
            "GET",
            "/status" | "/setup" | "/setup/mobile" | "/ca.pem" | "/skills" | "/library" | "/events" | "/update",
        )
        | ("GET", "/match-replace/presets" | "/ai-scan/prompt")
        | ("POST", "/skills/{name}" | "/evidence/verify")
        | ("POST", "/tools/decode" | "/tools/code" | "/tools/curl" | "/tools/protobuf/encode")
        | ("POST", "/tools/request-transform" | "/tools/token-analyzer") => Needs(Perm::Info),
        // Account endpoints and the MCP endpoint: their handlers decide.
        (_, t) if t.starts_with("/auth/") && !t.starts_with("/auth/members") => Open,
        ("POST", "/mcp") => Open,
        (_, "/auth/members" | "/auth/members/{user_id}") => Needs(Perm::MembersManage),

        ("GET", "/roe") | ("POST", "/roe/check") => Needs(Perm::RoeRead),
        ("PUT", "/roe") => Needs(Perm::RoeWrite),
        ("POST", "/browser/open") => Needs(Perm::BrowserOpen),

        // Recorded traffic.
        (
            "GET",
            "/exchanges" | "/exchanges/{id}" | "/exchanges/{id}/ws" | "/sitemap" | "/ws/history" | "/history/mark",
        )
        | ("GET", "/streams" | "/streams/{id}" | "/streams/{id}/chunks" | "/organizer")
        | ("POST", "/search" | "/search/ws" | "/tools/compare" | "/tools/token-analyzer/analyze")
        | ("POST", "/tools/protobuf/decode")
        | ("POST", "/engage/comments" | "/engage/scripts" | "/engage/js-endpoints" | "/engage/logic")
        | ("POST", "/engage/analyze" | "/engage/references" | "/engage/csrf" | "/engage/clickjacking")
        | ("POST", "/traffic/triage") => Needs(Perm::HistoryRead),
        ("GET", "/exchanges/{id}/curl" | "/exchanges/{id}/code") | ("POST", "/export/har") => {
            Needs(Perm::TrafficExport)
        }
        ("POST", "/import/har") => Needs(Perm::TrafficImport),
        ("PUT", "/exchanges/{id}/annotation") | ("POST", "/organizer" | "/attack-paths") => Needs(Perm::NotesWrite),
        ("PATCH" | "DELETE", "/organizer/{id}") => Needs(Perm::NotesWrite),
        ("DELETE", "/memory/{id}") => Needs(Perm::MemoryDelete),
        ("DELETE", "/attack-paths/{id}") => Needs(Perm::AttackPathsDelete),
        ("GET" | "PUT", "/ui/{key}") => Needs(Perm::UiStateWrite),

        // Sending.
        ("POST", "/ws/replay" | "/streams/{id}/replay" | "/race" | "/replay/group" | "/fuzzer" | "/replay")
        | ("POST", "/fuzzer/attacks" | "/fuzzer/attacks/{id}/{action}" | "/crawl" | "/discover")
        | ("POST", "/openapi/import" | "/graphql/import" | "/authz/check" | "/authz/matrix" | "/scan/active")
        | ("POST", "/scan/tasks" | "/scan/tasks/{id}/cancel" | "/scan/tasks/{id}/pause" | "/scan/tasks/{id}/resume")
        | ("POST", "/scan/custom" | "/dom/test" | "/recon/dns" | "/recon/wayback" | "/findings/prove" | "/proofs")
        | ("POST", "/identities/{name}/check" | "/identities/{name}/learn-logged-out")
        | ("POST", "/findings/{id}/retest" | "/findings/{id}/prove" | "/proofs/{id}/rerun" | "/workflows/{id}/run") => {
            Needs(Perm::SendTraffic)
        }
        ("POST", "/plugins/check") => Needs(Perm::PluginsManage),

        // State of runs.
        ("GET", "/fuzzer/attacks" | "/fuzzer/attacks/{id}" | "/scan/tasks" | "/scan/tasks/{id}")
        | ("GET", "/workflows/runs" | "/workflows/runs/{id}" | "/ai-scan" | "/ai-scan/{id}") => Needs(Perm::RunsRead),

        // Findings, the model, reports.
        ("GET", "/findings" | "/findings/{id}" | "/scan/issues" | "/proofs/{id}") => Needs(Perm::FindingsRead),
        ("POST", "/findings") | ("PATCH", "/findings/{id}") => Needs(Perm::FindingsWrite),
        ("POST", "/findings/{id}/explain") => Needs(Perm::FindingsExplain),
        ("POST", "/findings/{id}/issue") => Needs(Perm::IntegrationsSend),
        ("GET", "/model" | "/coverage" | "/model/changes" | "/model/snapshots" | "/hypotheses" | "/authz/results")
        | ("GET", "/authz/candidates" | "/openapi" | "/graphql" | "/memory" | "/attack-paths" | "/attack-graph")
        | ("GET", "/workflows" | "/workflows/{id}" | "/coverage/proof") => Needs(Perm::ModelRead),
        ("POST", "/model/snapshots") => Needs(Perm::ModelSnapshotsWrite),
        ("GET", "/report" | "/report/templates" | "/regress" | "/evidence/fingerprint") => Needs(Perm::ReportsRead),
        ("POST", "/report/templates") | ("DELETE", "/report/templates/{name}") => Needs(Perm::ReportTemplatesWrite),
        ("GET", "/evidence/pack" | "/regress/export") | ("POST", "/audit/checkpoint") => Needs(Perm::ExportEvidence),

        // Audit and approvals.
        ("GET", "/audit" | "/audit/verify" | "/audit/checkpoints") => Needs(Perm::AuditRead),
        ("GET", "/approvals") => Needs(Perm::ApprovalsRead),
        ("POST", "/approvals/{id}/{decision}") => Needs(Perm::ApprovalsDecide),

        // Identities.
        ("GET", "/identities") => Needs(Perm::IdentitiesRead),
        ("POST", "/identities/capture") => Needs(Perm::IdentitiesCapture),
        ("POST", "/identities/record-login") => Needs(Perm::IdentitiesWrite),

        // Configuration.
        ("GET", "/scan/profiles" | "/scan/custom-checks" | "/scan/schedules" | "/match-replace" | "/network")
        | ("GET", "/proxy/listeners" | "/history/recording" | "/devices" | "/plugins" | "/project/trust") => {
            Needs(Perm::ConfigRead)
        }
        ("POST", "/scan/profiles") | ("DELETE", "/scan/profiles/{name}") => Needs(Perm::ScanConfigWrite),
        ("POST", "/scan/custom-checks") | ("DELETE", "/scan/custom-checks/{id}") => Needs(Perm::ScanConfigWrite),
        ("POST", "/scan/schedules") | ("DELETE", "/scan/schedules/{id}") | ("POST", "/scan/schedules/{id}/run") => {
            Needs(Perm::SchedulesWrite)
        }
        ("GET" | "PUT", "/session") | ("GET" | "DELETE", "/session/jar") | ("POST", "/session/macros/{name}/run") => {
            Needs(Perm::SessionHandling)
        }
        (
            "GET" | "POST",
            "/intercept" | "/intercept/forward-all" | "/intercept/{id}/forward" | "/intercept/{id}/drop",
        )
        | ("PUT", "/intercept/settings") => Needs(Perm::InterceptUse),
        ("PUT", "/match-replace") => Needs(Perm::RulesWrite),
        ("PUT", "/network" | "/history/recording") | ("POST", "/network/upstream/resolve") => Needs(Perm::NetworkWrite),
        ("PUT", "/proxy/listeners") | ("POST", "/collaborator/listener" | "/collaborator/smtp") => {
            Needs(Perm::ListenersWrite)
        }
        ("PUT" | "DELETE", "/devices/{addr}") => Needs(Perm::DevicesWrite),
        ("PUT", "/update") | ("POST", "/update/check") => Needs(Perm::UpdateSettings),
        ("POST", "/project/trust") => Needs(Perm::ProjectTrust),
        ("PUT", "/plugins/{name}") | ("POST", "/plugins/{name}/accept") | ("GET", "/plugins/{name}/panels/{panel}") => {
            Needs(Perm::PluginsManage)
        }
        ("PUT", "/plugins/{name}/hooks/{kind}") => Needs(Perm::HooksManage),
        ("POST", "/workflows") | ("PUT" | "DELETE", "/workflows/{id}") => Needs(Perm::WorkflowsWrite),
        ("PUT", "/workflows/{id}/trigger") => Needs(Perm::WorkflowTriggers),
        ("GET", "/integrations" | "/integrations/{name}" | "/integrations/{name}/deliveries") => {
            Needs(Perm::IntegrationsRead)
        }
        ("PUT" | "DELETE", "/integrations/{name}") | ("PUT", "/integrations/{name}/enabled") => {
            Needs(Perm::IntegrationsWrite)
        }
        ("POST", "/integrations/{name}/test") => Needs(Perm::IntegrationsWrite),

        // Collaborator, assistant, AI scan, tokens.
        ("GET", "/collaborator" | "/collaborator/payloads" | "/collaborator/interactions" | "/collaborator/probes")
        | ("POST", "/collaborator/payloads") => Needs(Perm::CollaboratorUse),
        ("GET", "/assistant" | "/assistant/chats/{id}") | ("POST", "/assistant/send" | "/assistant/models") => {
            Needs(Perm::AssistantUse)
        }
        ("PUT", "/assistant/config") => Needs(Perm::AssistantConfigWrite),
        ("PUT", "/assistant/key") | ("DELETE", "/assistant/key/{name}") => Needs(Perm::ModelKeysWrite),
        ("POST", "/ai-scan" | "/ai-scan/{id}/stop" | "/ai-scan/{id}/message") => Needs(Perm::AiScanControl),
        // The token endpoints answer for themselves, with their own codes (a token cannot manage tokens; others'
        // tokens need an owner and a fresh sign-in); they ask `TokensManage` of the service.
        ("GET" | "POST", "/tokens") | ("DELETE", "/tokens/{id}") => Open,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deny by default: a route without a rule is refused to everyone, so none may be missing.
    #[test]
    fn every_route_has_a_permission() {
        let missing: Vec<String> = crate::contracts::operations()
            .into_iter()
            .map(|o| (o.method.to_ascii_uppercase(), o.path.trim_start_matches("/api/v1").to_string()))
            .filter(|(m, p)| route_perm(m, p).is_none())
            .map(|(m, p)| format!("{m} {p}"))
            .collect();
        assert!(missing.is_empty(), "routes with no entry in `route_perm`: {missing:?}");
        assert!(route_perm("GET", "/nothing/here").is_none());
        assert_eq!(route_perm("HEAD", "/status"), route_perm("GET", "/status"));
    }

    /// The write routes of the account side name the right permission, and reads of project data never fall to `Info`.
    #[test]
    fn a_few_rows_say_what_the_adr_says() {
        assert_eq!(route_perm("PUT", "/roe"), Some(Needs(Perm::RoeWrite)));
        assert_eq!(route_perm("POST", "/replay"), Some(Needs(Perm::SendTraffic)));
        assert_eq!(route_perm("GET", "/exchanges"), Some(Needs(Perm::HistoryRead)));
        assert_eq!(route_perm("PUT", "/auth/members/{user_id}"), Some(Needs(Perm::MembersManage)));
        assert_eq!(route_perm("GET", "/audit"), Some(Needs(Perm::AuditRead)));
    }
}
