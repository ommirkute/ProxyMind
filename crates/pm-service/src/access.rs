//! Who may do what (ADR-0022, migration step 1). The one place that says which kinds of principal may take which
//! kind of action. Deny by default: an action without a [`Perm`] entry cannot ask [`Service::require`].
//!
//! - [`Perm`] is one entry per kind of action; [`Perm::spec`] is the whole rule set in one `match`, readable in this
//!   file (and rendered to `docs/access.md`, which a test keeps in sync).
//! - [`Principal`] is who asks: an [`Actor`] plus a [`Role`] and, on a project server, the account, token, session
//!   and address behind the request. In single-user mode every person is the implicit owner and every other actor
//!   (agent, plugin, scanner, CI) has the role `Tester`, which is the ADR's ceiling for machine credentials.
//! - **Who is this actor?** Service methods take an `&Actor`, so the server's adapters register what they know about
//!   an actor for the life of the process ([`Service::register_principal`], called by the API's guard on every
//!   authenticated request, after the session or token was checked against `server.db`). [`Service::principal_of`]
//!   answers from that registry once [`Service::set_access_control`] is on (server mode): an actor nobody registered
//!   is a `viewer`, never an owner (deny by default), and a non-person is never above `tester`. With access control
//!   off (single-user mode) it is [`Principal::from_actor`], so nothing changes there.
//! - `people_only` actions stay people-only whatever the role: an owner's agent is still an agent.
//!
//! Only authorization lives here. Choosing what an agent is *shown* (redaction, untrusted-content wrapping) is not an
//! access decision and stays where the content is built; `tests/access.rs` keeps an explicit allow-list of those.

use std::collections::HashMap;

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
    /// Owner 3, tester 2, viewer 1: for "the lower of two roles".
    pub const fn rank(self) -> u8 {
        match self {
            Role::Owner => 3,
            Role::Tester => 2,
            Role::Viewer => 1,
        }
    }

    /// The lower of two roles.
    pub const fn min(self, other: Role) -> Role {
        if self.rank() <= other.rank() { self } else { other }
    }

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
    /// The role of the account behind this principal on the project: a person's own, a token's owner's. `role` is
    /// lower for a token (its ceiling) and for every non-person (capped at tester); this is what says whose work an
    /// action was, for the approval rules. `None` in single-user mode.
    pub account_role: Option<Role>,
}

impl Principal {
    pub fn new(actor: Actor, role: Role) -> Self {
        Self { actor, role, user_id: None, token_id: None, session_id: None, client_addr: None, account_role: None }
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
    /// Read recorded traffic: history, exchanges, search, the site map, WebSocket messages, streams, notes on them.
    HistoryRead,
    /// Read findings and passive scan issues, the issue library, proofs.
    FindingsRead,
    /// Read reports and the evidence the reports cite.
    ReportsRead,
    /// Read the application model, hypotheses, coverage, attack paths and what changed.
    ModelRead,
    /// See the state of scan tasks, fuzzer attacks, workflows and AI scans (`RunsReadAll` decides whose).
    RunsRead,
    /// Read the rules of engagement and what the principal may do under them.
    RoeRead,
    /// Public facts about the server and project that carry no project data (status, setup help, the CA certificate,
    /// playbooks, the issue library).
    Info,
    /// Read the audit log and its checkpoints.
    AuditRead,
    /// See pending and decided approvals (they hold the exact parameters of the action asked).
    ApprovalsRead,
    /// List identities (names, roles and health; never their credentials).
    IdentitiesRead,
    /// Read settings: network, listeners, match-and-replace, recording, devices, session handling summaries.
    ConfigRead,
    /// Use the built-in assistant: read its chats, send it messages.
    AssistantUse,
    /// Send traffic to targets through the gate: replay, group, race, fuzz, scan, crawl, discover, workflows run,
    /// stream and WebSocket replay, proofs, authorization checks, retests, AI-free sweeps.
    SendTraffic,
    /// Create an identity from the credentials in a recorded request, or set its health check from one: agents may,
    /// because they never see the values.
    IdentitiesCapture,
    /// Create and edit findings.
    FindingsWrite,
    /// Create and edit hypotheses.
    ModelWrite,
    /// Write notes: annotations, the organizer, agent memory, attack paths.
    NotesWrite,
    /// Import traffic (HAR, cURL) into the project.
    TrafficImport,
    /// Export traffic (HAR, cURL, code) from the project.
    TrafficExport,
    /// Use the Collaborator (OAST): make payloads, read interactions and probes.
    CollaboratorUse,
    /// Change how this installation checks for updates and run the check.
    UpdateSettings,
    /// Manage the project's members and their roles.
    MembersManage,
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
            Perm::HistoryRead => rule(
                ANYONE,
                false,
                "Read recorded traffic (viewers see it redacted, as agents do)",
                "your role may not read recorded traffic",
            ),
            Perm::FindingsRead => {
                rule(ANYONE, false, "Read findings, passive issues and proofs", "your role may not read findings")
            }
            Perm::ReportsRead => rule(ANYONE, false, "Read reports and evidence", "your role may not read reports"),
            Perm::ModelRead => rule(
                ANYONE,
                false,
                "Read the application model, hypotheses and coverage",
                "your role may not read the model",
            ),
            Perm::RunsRead => rule(
                ANYONE,
                false,
                "See the state of scan tasks, attacks, workflow runs and AI scans",
                "your role may not see runs",
            ),
            Perm::RoeRead => {
                rule(ANYONE, false, "Read the rules of engagement", "your role may not read the rules of engagement")
            }
            Perm::Info => {
                rule(ANYONE, false, "Public facts: status, setup help, the CA certificate, playbooks", "refused")
            }
            Perm::AuditRead => {
                rule(WORKERS, false, "Read the audit log and its checkpoints", "your role may not read the audit log")
            }
            Perm::ApprovalsRead => {
                rule(WORKERS, false, "See approvals and the actions they cover", "your role may not see approvals")
            }
            Perm::IdentitiesRead => {
                rule(WORKERS, false, "List identities (never their credentials)", "your role may not list identities")
            }
            Perm::ConfigRead => rule(
                WORKERS,
                false,
                "Read network, listener, rule, recording and device settings",
                "your role may not read settings",
            ),
            Perm::AssistantUse => rule(
                WORKERS,
                true,
                "Use the built-in assistant: read its chats, send it messages",
                "only people with a working role can use the assistant",
            ),
            Perm::SendTraffic => rule(
                WORKERS,
                false,
                "Send traffic through the gate: replay, fuzz, scan, crawl, workflows, proofs, retests",
                "your role may not send traffic to targets",
            ),
            Perm::IdentitiesCapture => rule(
                WORKERS,
                false,
                "Capture an identity from a recorded request; set a health check from one",
                "your role may not capture identities",
            ),
            Perm::FindingsWrite => {
                rule(WORKERS, false, "Create and edit findings", "your role may not create or change findings")
            }
            Perm::ModelWrite => {
                rule(WORKERS, false, "Create and edit hypotheses", "your role may not create or change hypotheses")
            }
            Perm::NotesWrite => rule(
                WORKERS,
                false,
                "Write annotations, organizer items, agent memory and attack paths",
                "your role may not write notes",
            ),
            Perm::TrafficImport => {
                rule(WORKERS, false, "Import traffic (HAR, cURL)", "your role may not import traffic")
            }
            Perm::TrafficExport => {
                rule(WORKERS, false, "Export traffic (HAR, cURL, code)", "your role may not export traffic")
            }
            Perm::CollaboratorUse => rule(
                WORKERS,
                false,
                "Use the Collaborator: payloads, interactions, probes",
                "your role may not use the Collaborator",
            ),
            Perm::UpdateSettings => rule(
                OWNER,
                true,
                "Change update settings and check for updates",
                "only an owner can change update settings",
            ),
            Perm::MembersManage => rule(
                OWNER,
                true,
                "List members; change or remove their roles",
                "only an owner of the project can manage its members",
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

/// What the server's adapters know about the actors that act in this process (see the module docs).
#[derive(Default)]
pub(crate) struct AccessState {
    /// Server mode: roles come from the registry and an unknown actor is a viewer.
    enabled: bool,
    /// Actor id to what is known of it. Refreshed on every authenticated request.
    principals: HashMap<String, Principal>,
}

tokio::task_local! {
    /// The principal of the request being served (set by the API around a handler), so every audit record of the
    /// request names the session or token and the address of exactly that request. Work spawned from a request
    /// (scan tasks, fuzzer attacks) runs outside the scope and falls back to the registry.
    static REQUEST: Principal;
}

impl Service {
    /// Turns server-mode access control on or off. On: [`Service::principal_of`] answers from the registry (an actor
    /// nobody registered is a viewer); off (single-user mode, the default): [`Principal::from_actor`].
    pub fn set_access_control(&self, on: bool) {
        self.access.write().enabled = on;
    }

    /// Whether server-mode access control is on.
    pub fn access_control(&self) -> bool {
        self.access.read().enabled
    }

    /// Records what is known of an actor for the life of the process: the role it acts with now, and the account,
    /// token, session and address behind it. A non-person's role is capped at `tester`. Call it on every
    /// authenticated request, after the session or token was checked: that is what makes a demotion take effect on
    /// the next request.
    pub fn register_principal(&self, principal: &Principal) {
        self.access.write().principals.insert(principal.actor.id(), principal.clone());
    }

    /// Registers `child` (a worker the service starts on behalf of `parent`, such as an AI scan's) with the parent's
    /// role, capped at tester, and the parent's account and token.
    pub fn inherit_principal(&self, parent: &Actor, child: &Actor) {
        if !self.access_control() {
            return;
        }
        let mut p = self.principal_of(parent);
        p.actor = child.clone();
        self.register_principal(&p);
    }

    /// Background work that acts as a person who vouched for the project (scheduled scans, workflow triggers):
    /// registered as a `tester` with no account, unless the actor is already known (a registration never gets
    /// *more* from here than it has).
    pub fn register_background(&self, actor: &Actor) {
        let mut a = self.access.write();
        if a.enabled && !a.principals.contains_key(&actor.id()) {
            a.principals.insert(actor.id(), Principal::new(actor.clone(), Role::Tester));
        }
    }

    /// A member's role changed or was removed (`None`): every registered actor of that account, and of tokens owned by
    /// it, takes the new role at once, without waiting for its next request. Removal makes them viewers; the API
    /// refuses their next request anyway.
    pub fn principals_of_user_changed(&self, user_id: &str, role: Option<Role>) {
        let mut a = self.access.write();
        for p in a.principals.values_mut().filter(|p| p.user_id.as_deref() == Some(user_id)) {
            p.role = role.map_or(Role::Viewer, |r| p.role.min(r));
            p.account_role = Some(role.unwrap_or(Role::Viewer));
        }
    }

    /// Who `actor` is for authorization. Single-user mode: [`Principal::from_actor`]. Server mode: what was
    /// registered; an actor nobody registered is a viewer (deny by default), and a non-person is never above tester.
    pub fn principal_of(&self, actor: &Actor) -> Principal {
        let a = self.access.read();
        // Single-user mode knows only the `pm3_` tokens that were used (their role ceiling must bite there too);
        // every other actor is the implicit owner or the machine ceiling.
        if !a.enabled && !a.principals.contains_key(&actor.id()) {
            return Principal::from_actor(actor);
        }
        match a.principals.get(&actor.id()) {
            Some(p) => {
                let mut p = p.clone();
                if p.actor.kind != ActorKind::Human {
                    p.role = p.role.min(Role::Tester);
                }
                p
            }
            None => Principal::new(actor.clone(), Role::Viewer),
        }
    }

    /// Whether `actor` acts as a viewer (a person or token that reads, with secrets hidden).
    pub fn is_viewer(&self, actor: &Actor) -> bool {
        self.principal_of(actor).role == Role::Viewer
    }

    /// Runs `fut` with `principal` as the request's principal (audit records written meanwhile carry it).
    pub async fn in_request<F: std::future::Future>(&self, principal: Principal, fut: F) -> F::Output {
        REQUEST.scope(principal, fut).await
    }

    /// The audit context for `actor`: the request in scope when it is theirs, else what was registered, else none.
    pub(crate) fn audit_context_of(&self, actor: &str) -> Option<AuditContext> {
        if let Ok(Some(c)) = REQUEST.try_with(|p| (p.actor.id() == actor).then(|| p.audit_context())) {
            return Some(c);
        }
        let a = self.access.read();
        if !a.enabled {
            return None;
        }
        a.principals.get(actor).map(Principal::audit_context)
    }

    /// Deny by default: `Ok` only when `principal` may take actions of kind `perm`. A refusal is
    /// `ServiceError::Invalid` with the perm's message in single-user mode (as the scattered checks returned before
    /// ADR-0022) and `ServiceError::Forbidden` in server mode (a 403).
    pub fn require(&self, principal: &Principal, perm: Perm) -> Result<()> {
        self.require_with(principal, perm, Denial::default())
    }

    /// [`Service::require`] for `actor`, resolved by [`Service::principal_of`].
    pub fn require_actor(&self, actor: &Actor, perm: Perm) -> Result<()> {
        self.require(&self.principal_of(actor), perm)
    }

    /// [`Service::require_actor`] with a call-specific message and/or an audit entry for the refusal.
    pub fn require_actor_with(&self, actor: &Actor, perm: Perm, denial: Denial) -> Result<()> {
        self.require_with(&self.principal_of(actor), perm, denial)
    }

    pub fn require_with(&self, principal: &Principal, perm: Perm, denial: Denial) -> Result<()> {
        if principal.allows(perm) {
            return Ok(());
        }
        if let Some((action, detail)) = denial.audit {
            let _ = self.audit_principal(principal, action, detail, "deny");
        }
        let msg = denial.message.unwrap_or_else(|| perm.spec().denial.to_string());
        // Server mode, and a single-user token whose role is a registered viewer ceiling, refuse with a 403; the
        // rest of single-user mode keeps the `Invalid` refusal it always had.
        let registered = self.access.read().principals.contains_key(&principal.actor.id());
        Err(if self.access_control() || registered { ServiceError::Forbidden(msg) } else { ServiceError::Invalid(msg) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pm_policy::{ActionRequest, Policy, Roe, Target, Tier};
    use pm_store::Store;
    use serde_json::json;

    fn service(roe_extra: &str) -> Service {
        // A person's own active-intrusive requests need approval too, so that they can be decided.
        let yaml = format!(
            "version: 1\nscope:\n  include: [\"https://app.example.com/\"]\ntiers:\n  human:\n    active_intrusive: approve\n{roe_extra}"
        );
        let svc = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&yaml).unwrap())).unwrap();
        svc.set_access_control(true);
        svc
    }

    fn actor(id: &str) -> Actor {
        Actor::parse(id).unwrap()
    }

    /// Registers `id` as the request of account `user` (and `token`) with `role`.
    fn register(svc: &Service, id: &str, role: Role, user: &str, token: Option<&str>) {
        let mut p = Principal::new(actor(id), role);
        p.account_role = Some(role);
        p.user_id = Some(user.into());
        p.token_id = token.map(Into::into);
        p.session_id = token.is_none().then(|| "s0123456".into());
        p.client_addr = Some("203.0.113.7".into());
        svc.register_principal(&p);
    }

    fn denied(r: Result<()>) -> bool {
        matches!(r, Err(ServiceError::Forbidden(_)))
    }

    #[test]
    fn single_user_mode_is_unchanged() {
        let svc = service("");
        svc.set_access_control(false);
        assert_eq!(svc.principal_of(&actor("human:anyone")).role, Role::Owner);
        assert_eq!(svc.principal_of(&actor("agent:a")).role, Role::Tester);
        svc.require_actor(&actor("human:anyone"), Perm::RoeWrite).unwrap();
        // A refusal is the `Invalid` error it always was, not `Forbidden`.
        let err = svc.require_actor(&actor("agent:a"), Perm::RoeWrite).unwrap_err();
        assert!(matches!(err, ServiceError::Invalid(_)), "{err:?}");
    }

    #[test]
    fn an_actor_nobody_registered_is_a_viewer_never_an_owner() {
        let svc = service("");
        for id in ["human:alice", "agent:claude", "ci:pipeline", "plugin:p"] {
            let p = svc.principal_of(&actor(id));
            assert_eq!(p.role, Role::Viewer, "{id}");
            assert!(!p.allows(Perm::SendTraffic) && !p.allows(Perm::RoeWrite), "{id}");
            assert!(p.allows(Perm::HistoryRead), "{id}");
        }
        assert!(denied(svc.require_actor(&actor("human:alice"), Perm::SendTraffic)));
    }

    #[test]
    fn registered_roles_decide_what_is_allowed() {
        let svc = service("");
        register(&svc, "human:olga", Role::Owner, "u_o", None);
        register(&svc, "human:tess", Role::Tester, "u_t", None);
        register(&svc, "human:vic", Role::Viewer, "u_v", None);
        let may = |who: &str, perm| svc.require_actor(&actor(who), perm).is_ok();
        for perm in
            [Perm::SendTraffic, Perm::FindingsWrite, Perm::NotesWrite, Perm::ApprovalsDecide, Perm::IdentitiesWrite]
        {
            assert!(may("human:olga", perm) && may("human:tess", perm), "{perm:?}");
            assert!(!may("human:vic", perm), "{perm:?}");
        }
        for perm in
            [Perm::RoeWrite, Perm::MembersManage, Perm::NetworkWrite, Perm::IntegrationsWrite, Perm::ModelKeysWrite]
        {
            assert!(may("human:olga", perm), "{perm:?}");
            assert!(!may("human:tess", perm) && !may("human:vic", perm), "{perm:?}");
        }
        for perm in
            [Perm::HistoryRead, Perm::FindingsRead, Perm::ReportsRead, Perm::ModelRead, Perm::RoeRead, Perm::Info]
        {
            assert!(may("human:vic", perm), "{perm:?}");
        }
        assert!(denied(svc.require_actor(&actor("human:vic"), Perm::RoeWrite)));
    }

    #[test]
    fn a_non_person_is_never_above_tester_and_people_only_holds_for_an_owners_token() {
        let svc = service("");
        register(&svc, "agent:owners", Role::Owner, "u_o", Some("t_1"));
        let p = svc.principal_of(&actor("agent:owners"));
        assert_eq!(p.role, Role::Tester);
        assert!(p.allows(Perm::SendTraffic));
        for perm in [Perm::ApprovalsDecide, Perm::RoeWrite, Perm::MembersManage, Perm::TokensManage] {
            assert!(!p.allows(perm), "{perm:?}");
        }
    }

    #[test]
    fn a_demotion_or_removal_takes_effect_at_once() {
        let svc = service("");
        register(&svc, "human:tess", Role::Tester, "u_t", None);
        register(&svc, "agent:tess-bot", Role::Tester, "u_t", Some("t_9"));
        register(&svc, "human:other", Role::Tester, "u_x", None);
        assert!(svc.require_actor(&actor("human:tess"), Perm::SendTraffic).is_ok());
        svc.principals_of_user_changed("u_t", Some(Role::Viewer));
        assert!(denied(svc.require_actor(&actor("human:tess"), Perm::SendTraffic)));
        assert!(denied(svc.require_actor(&actor("agent:tess-bot"), Perm::SendTraffic)), "their token too");
        assert!(svc.require_actor(&actor("human:other"), Perm::SendTraffic).is_ok(), "nobody else");
        // A promotion does not raise a registered role by itself; the next request registers the new one.
        svc.principals_of_user_changed("u_t", Some(Role::Owner));
        assert_eq!(svc.principal_of(&actor("human:tess")).role, Role::Viewer);
        svc.principals_of_user_changed("u_x", None);
        assert_eq!(svc.principal_of(&actor("human:other")).role, Role::Viewer);
    }

    #[test]
    fn background_work_never_gets_more_than_tester_nor_overwrites_a_registration() {
        let svc = service("");
        svc.register_background(&actor("human:vouched"));
        assert_eq!(svc.principal_of(&actor("human:vouched")).role, Role::Tester);
        register(&svc, "human:vic", Role::Viewer, "u_v", None);
        svc.register_background(&actor("human:vic"));
        assert_eq!(svc.principal_of(&actor("human:vic")).role, Role::Viewer);
    }

    fn pending(svc: &Service, who: &str) -> String {
        let req = ActionRequest {
            actor: actor(who),
            action: "replay_send".into(),
            tier: Tier::ActiveIntrusive,
            target: Some(Target::from_url("https://app.example.com/x").unwrap()),
            summary: "send".into(),
        };
        match svc.authorize(req, &json!({ "raw": "POST /x" })).unwrap() {
            crate::Authorization::PendingApproval { approval_id, .. } => approval_id,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_approval_records_who_asked() {
        let svc = service("");
        register(&svc, "agent:bot", Role::Tester, "u_t", Some("t_77"));
        let id = pending(&svc, "agent:bot");
        let row = svc.approval(&id).unwrap().unwrap();
        assert_eq!(
            (row.requested_user.as_deref(), row.requested_token.as_deref(), row.requested_role.as_deref()),
            (Some("u_t"), Some("t_77"), Some("tester"))
        );
    }

    #[test]
    fn who_may_decide_which_approval() {
        let svc = service("");
        register(&svc, "human:olga", Role::Owner, "u_o", None);
        register(&svc, "human:tess", Role::Tester, "u_t", None);
        register(&svc, "human:tom", Role::Tester, "u_m", None);
        register(&svc, "human:vic", Role::Viewer, "u_v", None);
        register(&svc, "agent:tess-bot", Role::Tester, "u_t", Some("t_1"));
        register(&svc, "agent:tom-bot", Role::Tester, "u_m", Some("t_2"));
        register(&svc, "agent:olga-bot", Role::Owner, "u_o", Some("t_3"));
        let decide = |who: &str, id: &str| svc.decide_approval(id, &actor(who), true);

        let tess_asked = pending(&svc, "agent:tess-bot");
        assert!(
            matches!(decide("human:vic", &tess_asked), Err(ServiceError::Forbidden(_))),
            "a viewer decides nothing"
        );
        assert!(matches!(decide("human:tom", &tess_asked), Err(ServiceError::Forbidden(_))), "not another tester's");
        decide("human:tess", &tess_asked).unwrap();

        let tom_asked = pending(&svc, "agent:tom-bot");
        assert!(matches!(decide("human:tess", &tom_asked), Err(ServiceError::Forbidden(_))));
        decide("human:olga", &tom_asked).unwrap();

        // A tester cannot decide what an owner's token asked; an owner can.
        let olga_asked = pending(&svc, "agent:olga-bot");
        assert!(matches!(decide("human:tess", &olga_asked), Err(ServiceError::Forbidden(_))));
        decide("human:olga", &olga_asked).unwrap();

        // A person's own request: they may decide it themselves (a tester too).
        let own = pending(&svc, "human:tess");
        decide("human:tess", &own).unwrap();
        // Refusals are audited as such.
        assert!(svc.audit_list(200).unwrap().iter().any(|r| r.action == "approval_decide" && r.decision == "rejected"));
    }

    #[test]
    fn the_roe_can_let_testers_decide_for_the_team() {
        let svc = service("approvals:\n  testers_decide_team: true\n");
        register(&svc, "human:tess", Role::Tester, "u_t", None);
        register(&svc, "human:tom", Role::Tester, "u_m", None);
        register(&svc, "human:olga", Role::Owner, "u_o", None);
        register(&svc, "agent:tom-bot", Role::Tester, "u_m", Some("t_2"));
        register(&svc, "agent:olga-bot", Role::Owner, "u_o", Some("t_3"));
        let tom_asked = pending(&svc, "agent:tom-bot");
        svc.decide_approval(&tom_asked, &actor("human:tess"), true).unwrap();
        // Still not an owner's.
        let olga_asked = pending(&svc, "agent:olga-bot");
        assert!(svc.decide_approval(&olga_asked, &actor("human:tess"), true).is_err());
    }

    #[test]
    fn four_eyes_need_another_owner() {
        let svc = service("approvals:\n  require_other_person: true\n");
        register(&svc, "human:olga", Role::Owner, "u_o", None);
        register(&svc, "human:omar", Role::Owner, "u_p", None);
        register(&svc, "agent:olga-bot", Role::Owner, "u_o", Some("t_3"));
        let asked = pending(&svc, "agent:olga-bot");
        let err = svc.decide_approval(&asked, &actor("human:olga"), true).unwrap_err();
        assert!(matches!(err, ServiceError::Forbidden(_)), "{err:?}");
        assert!(err.to_string().contains("different owner"), "{err}");
        svc.decide_approval(&asked, &actor("human:omar"), true).unwrap();
        // A person's own tiered request too.
        let own = pending(&svc, "human:olga");
        assert!(svc.decide_approval(&own, &actor("human:olga"), true).is_err());
        svc.decide_approval(&own, &actor("human:omar"), false).unwrap();
    }

    #[tokio::test]
    async fn audit_records_carry_the_account_and_the_request() {
        let svc = service("");
        register(&svc, "human:tess", Role::Tester, "u_t", None);
        let _ = pending(&svc, "human:tess"); // outside any request: the registry's context
        let log = svc.audit_list(10).unwrap();
        assert_eq!(log[0].user_id.as_deref(), Some("u_t"));
        assert_eq!(log[0].principal_kind.as_deref(), Some("session"));
        assert_eq!(log[0].client_addr.as_deref(), Some("203.0.113.7"));

        // Inside a request: that request's own session and address, not the registry's.
        let mut p = Principal::new(actor("human:tess"), Role::Tester);
        p.user_id = Some("u_t".into());
        p.session_id = Some("feedface".into());
        p.client_addr = Some("198.51.100.9".into());
        svc.in_request(p, async {
            let _ = pending(&svc, "human:tess");
        })
        .await;
        let log = svc.audit_list(10).unwrap();
        assert_eq!(
            (log[0].session_id.as_deref(), log[0].client_addr.as_deref()),
            (Some("feedface"), Some("198.51.100.9"))
        );
        // A request in scope says nothing about another actor's records.
        let mut other = Principal::new(actor("human:tom"), Role::Tester);
        other.session_id = Some("0badc0de".into());
        svc.in_request(other, async {
            let _ = pending(&svc, "human:tess");
        })
        .await;
        assert_eq!(svc.audit_list(1).unwrap()[0].session_id.as_deref(), Some("s0123456"));
        svc.audit_verify().unwrap();
    }

    #[test]
    fn redactors_are_per_user_and_a_viewer_is_always_redacted() {
        let svc = service("data:\n  redact_before_llm: false\n");
        register(&svc, "human:vic", Role::Viewer, "u_v", None);
        register(&svc, "human:vera", Role::Viewer, "u_w", None);
        register(&svc, "human:olga", Role::Owner, "u_o", None);
        register(&svc, "agent:vic-bot", Role::Tester, "u_v", Some("t_1"));
        // Even with the ROE's redaction off, a viewer sees placeholders; an owner sees the real value.
        assert!(svc.redacts_for(&actor("human:vic")));
        assert!(!svc.redacts_for(&actor("human:olga")));
        let (a, b) = (svc.redactor_of(&actor("human:vic")), svc.redactor_of(&actor("human:vera")));
        let shown_a = a.redact("Cookie: session=aaaaaaaa1111");
        let shown_b = b.redact("Cookie: session=bbbbbbbb2222");
        assert_eq!(shown_a, shown_b.replace("bbbbbbbb2222", "aaaaaaaa1111"), "both are the first secret of their user");
        assert!(shown_a.contains("{{secret:cookie_session_1}}"), "{shown_a}");
        // The same placeholder means a different value for each, so one user cannot send another's secret.
        assert_eq!(a.unredact(b"{{secret:cookie_session_1}}"), b"aaaaaaaa1111");
        assert_eq!(b.unredact(b"{{secret:cookie_session_1}}"), b"bbbbbbbb2222");
        // A token shares its owner's redactor.
        assert!(std::ptr::eq(svc.redactor_of(&actor("agent:vic-bot")), a));
        assert!(!std::ptr::eq(a, b));
    }
}
