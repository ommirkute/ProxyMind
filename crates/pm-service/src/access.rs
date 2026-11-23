//! Who may do what (ADR-0022, migration step 1). The one place that says which kinds of principal may take which
//! kind of action. Deny by default: an action without a [`Perm`] entry cannot ask [`Service::require`].
//!
//! - [`Perm`] is one entry per kind of action; [`Perm::spec`] is the whole rule set in one `match`, readable in this
//!   file (and rendered to `docs/access.md`, which a test keeps in sync).
//! - [`Principal`] is who asks: an [`Actor`] plus a [`Role`]. In single-user mode (all there is today) every person is
//!   the implicit owner and every other actor (agent, plugin, scanner, CI) has the role `Tester`, which is the ADR's
//!   ceiling for machine credentials. Roles per project member come with ADR-0022 step 6.
//! - `people_only` actions stay people-only whatever the role: an owner's agent is still an agent.
//!
//! Only authorization lives here. Choosing what an agent is *shown* (redaction, untrusted-content wrapping) is not an
//! access decision and stays where the content is built; `tests/access.rs` keeps an explicit allow-list of those.

use pm_policy::audit::AuditContext;
use pm_policy::{Actor, ActorKind};
use serde_json::Value;

use crate::{Result, Service, ServiceError};

/// A project role (ADR-0022). Single-user mode has no memberships: see [`Principal::from_actor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Owner,
    Tester,
    Viewer,
}

impl Role {
    pub const fn name(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Tester => "tester",
            Role::Viewer => "viewer",
        }
    }
}

/// Who is asking: the actor (kind and name, as in the audit log) and the role they act with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub actor: Actor,
    pub role: Role,
    /// The stable account id (`u_...`); None in single-user mode.
    pub user_id: Option<String>,
    /// The token the request came with (its id, never the secret); None unless a token was used.
    pub token_id: Option<String>,
    /// The browser session (first 8 bytes, hex, of the stored hash of its id); None unless a session was used.
    pub session_id: Option<String>,
    /// The client's IP address, when known.
    pub client_addr: Option<String>,
}

impl Principal {
    pub fn new(actor: Actor, role: Role) -> Self {
        Self { actor, role, user_id: None, token_id: None, session_id: None, client_addr: None }
    }

    /// The same principal, seen from this address.
    pub fn with_addr(mut self, addr: impl Into<String>) -> Self {
        self.client_addr = Some(addr.into());
        self
    }

    /// The who-and-where that goes into the audit record (version 2): `token` or `session` when there is one,
    /// else `local`. The project id is added by the audit writer.
    pub fn audit_context(&self) -> AuditContext {
        let kind = if self.token_id.is_some() {
            "token"
        } else if self.session_id.is_some() {
            "session"
        } else {
            "local"
        };
        AuditContext {
            principal_kind: Some(kind.into()),
            user_id: self.user_id.clone(),
            token_id: self.token_id.clone(),
            project_id: None,
            session_id: self.session_id.clone(),
            client_addr: self.client_addr.clone(),
        }
    }

    /// Single-user mode: a person is the implicit owner (every check passes for them); any other actor acts with the
    /// ceiling the ADR gives machine credentials, `tester`, and is further limited by `people_only`.
    pub fn from_actor(actor: &Actor) -> Self {
        let role = if actor.kind == ActorKind::Human { Role::Owner } else { Role::Tester };
        Self::new(actor.clone(), role)
    }

    /// Whether this principal may take actions of kind `perm`.
    pub fn allows(&self, perm: Perm) -> bool {
        let spec = perm.spec();
        spec.roles.contains(&self.role) && (!spec.people_only || self.actor.kind == ActorKind::Human)
    }
}

/// The rule for one [`Perm`].
#[derive(Debug, Clone, Copy)]
pub struct PermSpec {
    /// Roles that may do it.
    pub roles: &'static [Role],
    /// Only a person (`ActorKind::Human`) may, whatever the role.
    pub people_only: bool,
    /// What it covers, for `docs/access.md`.
    pub summary: &'static str,
    /// The message of a refusal when the call site does not give its own.
    pub denial: &'static str,
}

const ANYONE: &[Role] = &[Role::Owner, Role::Tester, Role::Viewer];
const WORKERS: &[Role] = &[Role::Owner, Role::Tester];
const OWNER: &[Role] = &[Role::Owner];

macro_rules! perms {
    ($($(#[$meta:meta])* $name:ident),* $(,)?) => {
        /// One entry per kind of action. See [`Perm::spec`] for who may do each.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Perm {
            $($(#[$meta])* $name),*
        }

        impl Perm {
            /// Every entry, in declaration order.
            pub const ALL: &'static [Perm] = &[$(Perm::$name),*];

            /// The variant's name, as written in code.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Perm::$name => stringify!($name)),*
                }
            }
        }
    };
}

perms! {
    /// Create, replace and delete test identities, their login recipes, and record logins (they hold credentials).
    IdentitiesWrite,
    /// Save and delete custom checks and scan profiles (they decide what scans send).
    ScanConfigWrite,
    /// Save and delete report templates.
    ReportTemplatesWrite,
    /// Create, change and delete scan schedules (they run unattended).
    SchedulesWrite,
    /// See or change session handling: macros, the cookie jar, running a macro (macros hold passwords).
    SessionHandling,
    /// Use the intercept queue and read intercept events.
    InterceptUse,
    /// Change upstream proxy, DNS and TLS settings and what the proxy records.
    NetworkWrite,
    /// Start or change a listener: proxy listeners, the SMTP and callback listeners (they open ports).
    ListenersWrite,
    /// Change match-and-replace rules (they alter every request the browser sends).
    RulesWrite,
    /// Change the rules of engagement.
    RoeWrite,
    /// Change the assistant's provider, model and tool settings.
    AssistantConfigWrite,
    /// Save and remove model API keys.
    ModelKeysWrite,
    /// Approve or deny a pending action.
    ApprovalsDecide,
    /// Confirm that this installation trusts a project's settings (leaves safe mode).
    ProjectTrust,
    /// Turn plugins on or off and accept their permissions (plugins run code).
    PluginsManage,
    /// Set up plugin hooks (hooks change traffic).
    HooksManage,
    /// Create, change and delete workflows.
    WorkflowsWrite,
    /// Switch a workflow's trigger on or off, and run triggers.
    WorkflowTriggers,
    /// Read integration settings and the delivery log.
    IntegrationsRead,
    /// Create, change, enable, delete and test integrations.
    IntegrationsWrite,
    /// Send a finding to an integration.
    IntegrationsSend,
    /// Name or unname client devices.
    DevicesWrite,
    /// Export evidence packs and regression tests.
    ExportEvidence,
    /// Start an AI scan and send it messages (it starts an agent).
    AiScanControl,
    /// Open a browser window routed through the proxy.
    BrowserOpen,
    /// Delete notes in the agent memory.
    MemoryDelete,
    /// Delete attack paths.
    AttackPathsDelete,
    /// Save a model snapshot.
    ModelSnapshotsWrite,
    /// Save UI state (the person's workspace).
    UiStateWrite,
    /// Save a model-written explanation on a finding.
    FindingsExplain,
    /// Change a finding a person has already judged, and set statuses only people may set.
    FindingStatusFinal,
    /// See every fuzzer attack, scan task and workflow run, not only the actor's own.
    RunsReadAll,
    /// Create, list and revoke one's own `pm3_` tokens (ADR-0022 step 5). A token can never do this itself.
    TokensManage,
    /// Create, list and revoke other people's tokens.
    TokensManageOthers,
}

impl Perm {
    /// The rule: who may, and what a refusal says. The whole rule set is this `match`.
    pub const fn spec(self) -> PermSpec {
        const fn rule(
            roles: &'static [Role],
            people_only: bool,
            summary: &'static str,
            denial: &'static str,
        ) -> PermSpec {
            PermSpec { roles, people_only, summary, denial }
        }
        match self {
            Perm::IdentitiesWrite => rule(
                WORKERS,
                true,
                "Define, change and delete identities and login recipes; record logins",
                "only humans can define identities with credentials",
            ),
            Perm::ScanConfigWrite => rule(
                WORKERS,
                true,
                "Save and delete custom checks and scan profiles",
                "only humans can change scan profiles",
            ),
            Perm::ReportTemplatesWrite => {
                rule(WORKERS, true, "Save and delete report templates", "only humans can change report templates")
            }
            Perm::SchedulesWrite => rule(
                WORKERS,
                true,
                "Create, change and delete scan schedules",
                "only humans can change scan schedules (they run unattended)",
            ),
            Perm::SessionHandling => rule(
                WORKERS,
                true,
                "See or change session handling, the cookie jar, run a macro",
                "only humans can see or change session handling (macros hold passwords)",
            ),
            Perm::InterceptUse => rule(
                WORKERS,
                true,
                "Use the intercept queue, read intercept events",
                "only humans can use the intercept queue",
            ),
            Perm::NetworkWrite => rule(
                OWNER,
                true,
                "Change network settings and what the proxy records",
                "only humans can change network settings",
            ),
            Perm::ListenersWrite => rule(
                OWNER,
                true,
                "Change proxy listeners; start the SMTP and callback listeners",
                "only humans can change proxy listeners",
            ),
            Perm::RulesWrite => {
                rule(OWNER, true, "Change match-and-replace rules", "only humans can change match-and-replace rules")
            }
            Perm::RoeWrite => {
                rule(OWNER, true, "Change the rules of engagement", "only humans can change the rules of engagement")
            }
            Perm::AssistantConfigWrite => {
                rule(OWNER, true, "Change the assistant settings", "only humans can change the assistant settings")
            }
            Perm::ModelKeysWrite => {
                rule(OWNER, true, "Save and remove model API keys", "only people can set model API keys")
            }
            Perm::ApprovalsDecide => {
                rule(WORKERS, true, "Approve or deny a pending action", "only humans can approve actions")
            }
            Perm::ProjectTrust => rule(
                OWNER,
                true,
                "Confirm a project's settings (leave safe mode)",
                "only people can trust a project: review it and confirm yourself",
            ),
            Perm::PluginsManage => rule(
                WORKERS,
                true,
                "Turn plugins on or off, accept their permissions",
                "only people can do this: plugins run code and hooks change traffic, so an agent can't turn them on, accept their permissions or set them up",
            ),
            Perm::HooksManage => rule(
                WORKERS,
                true,
                "Set up plugin hooks",
                "only people can do this: plugins run code and hooks change traffic, so an agent can't turn them on, accept their permissions or set them up",
            ),
            Perm::WorkflowsWrite => rule(
                WORKERS,
                true,
                "Create, change and delete workflows",
                "only people can create, change or delete workflows and switch their triggers",
            ),
            Perm::WorkflowTriggers => rule(
                WORKERS,
                true,
                "Switch workflow triggers on or off; run triggers",
                "only people can create, change or delete workflows and switch their triggers",
            ),
            Perm::IntegrationsRead => rule(
                OWNER,
                true,
                "Read integration settings and the delivery log",
                "only people can read integration settings",
            ),
            Perm::IntegrationsWrite => rule(
                OWNER,
                true,
                "Create, change, enable, delete and test integrations",
                "only people can change integrations",
            ),
            Perm::IntegrationsSend => {
                rule(WORKERS, true, "Send a finding to an integration", "only people can send findings to integrations")
            }
            Perm::DevicesWrite => rule(WORKERS, true, "Name or unname client devices", "only humans can name devices"),
            Perm::ExportEvidence => {
                rule(WORKERS, true, "Export evidence packs and regression tests", "only people export evidence")
            }
            Perm::AiScanControl => {
                rule(WORKERS, true, "Start an AI scan, send it messages", "only people can start an AI scan")
            }
            Perm::BrowserOpen => {
                rule(WORKERS, true, "Open a browser window", "only a person can open a browser window")
            }
            Perm::MemoryDelete => rule(WORKERS, true, "Delete agent memory notes", "only people delete memory"),
            Perm::AttackPathsDelete => rule(WORKERS, true, "Delete attack paths", "only people delete attack paths"),
            Perm::ModelSnapshotsWrite => {
                rule(WORKERS, true, "Save a model snapshot", "only people save model snapshots")
            }
            Perm::UiStateWrite => rule(ANYONE, true, "Save UI state", "only people have UI state"),
            Perm::FindingsExplain => rule(
                WORKERS,
                true,
                "Save a model-written explanation on a finding",
                "only people save a finding explanation",
            ),
            Perm::FindingStatusFinal => rule(
                WORKERS,
                true,
                "Change a judged finding; set statuses only people may set",
                "only a person can change this finding",
            ),
            Perm::RunsReadAll => rule(
                ANYONE,
                true,
                "See every attack, scan task and workflow run (others see their own)",
                "only people see every run",
            ),
            Perm::TokensManage => rule(
                WORKERS,
                true,
                "Create, list and revoke one's own tokens (a token cannot manage tokens)",
                "only a person signed in as themselves can manage tokens: a token cannot create, list or revoke tokens",
            ),
            Perm::TokensManageOthers => rule(
                OWNER,
                true,
                "Create, list and revoke other people's tokens",
                "only an owner of the project can manage other people's tokens",
            ),
        }
    }
}

/// How a refusal is reported, when the call site needs more than the default.
#[derive(Debug, Default)]
pub struct Denial {
    /// Replaces [`PermSpec::denial`] (call sites keep the wording their clients already see).
    pub message: Option<String>,
    /// Audit the refusal under this action name with this detail (decision `deny`).
    pub audit: Option<(&'static str, Value)>,
}

impl Denial {
    pub fn message(message: impl Into<String>) -> Self {
        Self { message: Some(message.into()), audit: None }
    }

    pub fn audited(action: &'static str, detail: Value) -> Self {
        Self { message: None, audit: Some((action, detail)) }
    }

    /// Also audit the refusal.
    pub fn and_audit(mut self, action: &'static str, detail: Value) -> Self {
        self.audit = Some((action, detail));
        self
    }
}

impl Service {
    /// Deny by default: `Ok` only when `principal` may take actions of kind `perm`. A refusal is
    /// `ServiceError::Invalid` with the perm's message (as the scattered checks returned before ADR-0022).
    pub fn require(&self, principal: &Principal, perm: Perm) -> Result<()> {
        self.require_with(principal, perm, Denial::default())
    }

    /// [`Service::require`] for the single-user principal of `actor` ([`Principal::from_actor`]).
    pub fn require_actor(&self, actor: &Actor, perm: Perm) -> Result<()> {
        self.require(&Principal::from_actor(actor), perm)
    }

    /// [`Service::require_actor`] with a call-specific message and/or an audit entry for the refusal.
    pub fn require_actor_with(&self, actor: &Actor, perm: Perm, denial: Denial) -> Result<()> {
        self.require_with(&Principal::from_actor(actor), perm, denial)
    }

    pub fn require_with(&self, principal: &Principal, perm: Perm, denial: Denial) -> Result<()> {
        if principal.allows(perm) {
            return Ok(());
        }
        if let Some((action, detail)) = denial.audit {
            let _ = self.audit(&principal.actor.id(), action, detail, "deny");
        }
        Err(ServiceError::Invalid(denial.message.unwrap_or_else(|| perm.spec().denial.to_string())))
    }
}
