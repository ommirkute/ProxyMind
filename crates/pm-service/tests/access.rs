//! ADR-0022 step 1: the access table is the one place that decides who may do what.
//!
//! - the rule table behaves as documented (people-only perms refuse every non-person; roles narrow, never widen);
//! - no authorization check on the actor's kind is left in `pm-service` outside `access.rs` (the allow-list below holds
//!   the uses that are not authorization, each with its reason, and must stay exact);
//! - every `Perm` is used somewhere (no dead entries);
//! - `docs/access.md` is the table rendered from `access.rs` plus the methods that require each entry.
//!
//! To refresh the document after changing the table: `UPDATE_ACCESS_DOC=1 cargo test -p pm-service --test access`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use pm_service::access::{Denial, Perm, Principal, Role};
use pm_service::pm_policy::{Actor, ActorKind, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{Service, ServiceError};

const KINDS: [ActorKind; 5] =
    [ActorKind::Human, ActorKind::Agent, ActorKind::Plugin, ActorKind::Scanner, ActorKind::Ci];
const ROLES: [Role; 3] = [Role::Owner, Role::Tester, Role::Viewer];

fn actor(kind: ActorKind) -> Actor {
    Actor { kind, name: "t".into() }
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

fn service_sources() -> Vec<(String, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(files.len() > 50, "found no sources under {}", src.display());
    let mut out: Vec<(String, String)> = files
        .into_iter()
        .map(|f| {
            (f.strip_prefix(&src).unwrap().to_string_lossy().replace('\\', "/"), std::fs::read_to_string(&f).unwrap())
        })
        .collect();
    out.sort();
    out
}

fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.trim_start().starts_with("//"))
}

// ---- the table -----------------------------------------------------------------------------------------------

#[test]
fn people_only_perms_refuse_every_non_person_whatever_the_role() {
    let mut people_only = 0;
    for &perm in Perm::ALL {
        let spec = perm.spec();
        if !spec.people_only {
            continue;
        }
        people_only += 1;
        for kind in KINDS.into_iter().filter(|k| *k != ActorKind::Human) {
            for role in ROLES {
                let p = Principal::new(actor(kind), role);
                assert!(!p.allows(perm), "{} must refuse {kind:?} acting as {role:?}", perm.name());
            }
        }
        // An owner who is a person may, unless the perm is not open to owners at all.
        assert!(spec.roles.contains(&Role::Owner), "{} must allow the owner", perm.name());
        assert!(Principal::new(actor(ActorKind::Human), Role::Owner).allows(perm), "{}", perm.name());
        assert!(Principal::from_actor(&actor(ActorKind::Human)).allows(perm), "{}", perm.name());
    }
    assert!(people_only >= 20, "expected most of the table to be people-only, found {people_only}");
}

#[test]
fn single_user_mode_maps_actors_to_roles() {
    for kind in KINDS {
        let p = Principal::from_actor(&actor(kind));
        let expected = if kind == ActorKind::Human { Role::Owner } else { Role::Tester };
        assert_eq!(p.role, expected, "{kind:?}");
        assert_eq!(p.actor, actor(kind));
    }
    // The implicit owner passes every check: the existing suite is the proof that nothing changed for people.
    let owner = Principal::from_actor(&actor(ActorKind::Human));
    for &perm in Perm::ALL {
        assert!(owner.allows(perm), "{}", perm.name());
    }
}

#[test]
fn roles_narrow_and_never_widen() {
    let names = |role: Role| -> Vec<&'static str> {
        Perm::ALL
            .iter()
            .filter(|p| Principal::new(actor(ActorKind::Human), role).allows(**p))
            .map(|p| p.name())
            .collect()
    };
    let owner = names(Role::Owner);
    let tester = names(Role::Tester);
    let viewer = names(Role::Viewer);
    assert_eq!(owner.len(), Perm::ALL.len());
    assert!(tester.iter().all(|n| owner.contains(n)));
    assert!(viewer.iter().all(|n| tester.contains(n)));
    // ADR-0022 "Roles": a viewer reads (traffic with secrets hidden, findings, reports, the model, the ROE) and keeps
    // their own workspace; a tester does everything a person does while testing but not what configures the project;
    // the owner alone changes the ROE, the network side, integrations, model keys, trust, updates and members.
    assert_eq!(
        viewer,
        [
            "UiStateWrite",
            "RunsReadAll",
            "HistoryRead",
            "FindingsRead",
            "ReportsRead",
            "ModelRead",
            "RunsRead",
            "RoeRead",
            "Info"
        ]
    );
    let owner_only: Vec<&str> = owner.iter().copied().filter(|n| !tester.contains(n)).collect();
    assert_eq!(
        owner_only,
        [
            "NetworkWrite",
            "ListenersWrite",
            "RulesWrite",
            "RoeWrite",
            "AssistantConfigWrite",
            "ModelKeysWrite",
            "ProjectTrust",
            "IntegrationsRead",
            "IntegrationsWrite",
            "TokensManageOthers",
            "UpdateSettings",
            "MembersManage",
        ]
    );
}

fn service(name: &str) -> Service {
    let dir = std::env::temp_dir().join(format!("pm-access-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("p.pmproj");
    Service::new(
        Store::open(&path).unwrap(),
        Policy::new(Roe::parse("version: 1\nscope:\n  include: [\"http://shop.test/\"]\n").unwrap()),
    )
    .unwrap()
}

#[test]
fn require_is_deny_by_default_and_audits_when_asked() {
    let svc = service("require");
    let human = actor(ActorKind::Human);
    let agent = Actor { kind: ActorKind::Agent, name: "claude".into() };
    svc.require_actor(&human, Perm::RoeWrite).unwrap();

    // Default refusal: the perm's message, no audit entry (as the scattered checks behaved).
    let err = svc.require_actor(&agent, Perm::RoeWrite).unwrap_err();
    assert!(matches!(&err, ServiceError::Invalid(m) if m == Perm::RoeWrite.spec().denial), "{err}");
    assert!(svc.audit_list(10).unwrap().is_empty());

    // A call-specific message and an audit entry.
    let denial = Denial::message("nope").and_audit("some_action", serde_json::json!({ "x": 1 }));
    let err = svc.require_actor_with(&agent, Perm::RoeWrite, denial).unwrap_err();
    assert_eq!(err.to_string(), "nope");
    let log = svc.audit_list(10).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(
        (log[0].actor.as_str(), log[0].action.as_str(), log[0].decision.as_str()),
        ("agent:claude", "some_action", "deny")
    );
    svc.audit_verify().unwrap();

    // A viewer who is a person is still refused what is not theirs.
    let viewer = Principal::new(human, Role::Viewer);
    assert!(svc.require(&viewer, Perm::RoeWrite).is_err());
    assert!(svc.require(&viewer, Perm::UiStateWrite).is_ok());
}

// ---- the source scan -----------------------------------------------------------------------------------------

/// Uses of the actor's kind that are not authorization, per file (the number of matching lines). Anything else in
/// `pm-service` that looks at `ActorKind::` or `actor.kind` must be a `Perm` in `access.rs`. A new entry needs a reason
/// a reviewer accepts; the count must stay exact so a new check cannot hide behind an old entry.
const NOT_AUTHORIZATION: &[(&str, usize, &str)] = &[
    ("auto.rs", 1, "the ROE decides the tier by actor kind (`tier_decision`); the gate, not a role"),
    ("ci.rs", 2, "the ROE tier of the CI actor kind (`tier_decision(ActorKind::Ci, ..)`)"),
    (
        "events.rs",
        1,
        "what a non-person is shown of an event (scope and run ownership, ADR-0018); the topic and the role are \
         `topic_perm` in this file's `Perm` table, and a viewer is redacted by role (`redacts_for`), not by kind",
    ),
    ("integration_events.rs", 1, "builds the service's own internal actor to read a task for a notification"),
    (
        "lib.rs",
        2,
        "redaction and untrusted-content wrapping for agents (`redacts_for`, `json_for`): presentation; a viewer, \
         though a person, is redacted too, by role (`redacts_for` asks `principal_of`)",
    ),
    ("protobuf.rs", 1, "redaction and untrusted wrapping of decoded text for agents: presentation"),
    ("roe.rs", 5, "the ROE's name-to-kind table for the tier lines (`human`, `agent`, ...): parsing, not a check"),
    ("scan.rs", 2, "untrusted-content wrapping of scan evidence for agents: presentation"),
    (
        "scan_task.rs",
        2,
        "untrusted wrapping of task evidence for agents; and who owns a resumed task (a person takes over a person's \
         task, an agent's keeps its limits): state, not a permission",
    ),
    ("streams.rs", 1, "redaction and untrusted wrapping of stream chunks for agents: presentation"),
    ("tools.rs", 1, "untrusted-content notice on a comparison shown to agents: presentation"),
    (
        "trust.rs",
        3,
        "safe mode refuses non-person actors at the gate (project state, not a role); a trust record follows a person's \
         edit; a stored schedule or trigger owner must name a person",
    ),
    (
        "workflow_service.rs",
        1,
        "`is_person`: agents see workflows and runs with secrets hidden, and start them only on in-scope exchanges: \
         presentation and scope, not a permission",
    ),
    ("ws.rs", 2, "redaction and untrusted wrapping of WebSocket messages for agents: presentation"),
];

#[test]
fn no_actor_kind_checks_outside_the_access_module() {
    let mut found: BTreeMap<String, usize> = BTreeMap::new();
    for (file, text) in service_sources() {
        if file == "access.rs" {
            continue;
        }
        let n = code_lines(&text)
            .filter(|l| l.contains("ActorKind::") || l.contains("actor.kind") || l.contains("approver.kind"))
            .count();
        if n > 0 {
            found.insert(file, n);
        }
    }
    let allowed: BTreeMap<String, usize> = NOT_AUTHORIZATION.iter().map(|(f, n, _)| (f.to_string(), *n)).collect();
    assert!(NOT_AUTHORIZATION.iter().all(|(_, _, why)| !why.is_empty()));
    assert_eq!(
        found, allowed,
        "authorization on the actor's kind belongs in `pm-service/src/access.rs` (add a `Perm` and call \
         `self.require_actor(actor, Perm::X)?`); if the new use is not authorization, add it to NOT_AUTHORIZATION \
         with a reason"
    );
}

/// `Perm::Name` uses outside `access.rs` in the workspace's crates, with the function each is in.
fn perm_uses() -> BTreeMap<String, BTreeSet<String>> {
    let crates = workspace().join("crates");
    let mut uses: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for krate in std::fs::read_dir(crates).unwrap() {
        let krate = krate.unwrap().path();
        let name = krate.file_name().unwrap().to_string_lossy().to_string();
        let src = krate.join("src");
        if !src.is_dir() {
            continue;
        }
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        for f in files {
            if name == "pm-service" && f.file_name().is_some_and(|n| n == "access.rs") {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            let mut current = String::new();
            for line in code_lines(&text) {
                if let Some(i) = line.find("fn ") {
                    let rest = &line[i + 3..];
                    let id: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if !id.is_empty() && (i == 0 || line[..i].ends_with(' ')) {
                        current = id;
                    }
                }
                let mut rest = line;
                while let Some(i) = rest.find("Perm::") {
                    let after = &rest[i + 6..];
                    let id: String = after.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if Perm::ALL.iter().any(|p| p.name() == id) {
                        let label = if name == "pm-service" { current.clone() } else { format!("{name}::{current}") };
                        uses.entry(id).or_default().insert(label);
                    }
                    rest = after;
                }
            }
        }
    }
    uses
}

#[test]
fn every_perm_is_used() {
    let uses = perm_uses();
    let unused: Vec<&str> = Perm::ALL.iter().map(|p| p.name()).filter(|n| !uses.contains_key(*n)).collect();
    assert!(unused.is_empty(), "no code requires these perms (remove them or use them): {unused:?}");
}

// ---- every public method asks first ---------------------------------------------------------------------------

/// Public `Service` methods that take an `&Actor` or `&Principal` and do not begin with `self.require...`, each with the
/// reason that is accepted. Everything else must ask before it touches the store, the gate or the network. A new entry
/// needs a reason a reviewer accepts.
const NO_REQUIRE: &[(&str, &str, &str)] = &[
    ("access.rs", "register_principal", "the registry itself: records what the guard learned about an actor"),
    ("access.rs", "inherit_principal", "the registry itself: a worker the service starts takes its parent's role"),
    (
        "access.rs",
        "register_background",
        "the registry itself: background work gets tester at most, never more than registered",
    ),
    ("access.rs", "principal_of", "the registry itself: answers who an actor is"),
    ("access.rs", "is_viewer", "the registry itself: a presentation switch, grants nothing"),
    ("access.rs", "require_with", "this is the check"),
    (
        "ai_scan.rs",
        "ai_scan_tool",
        "only the scan's own agent reaches it (`scan_of`), and it writes that scan's own log, phase and report",
    ),
    (
        "approvals.rs",
        "run_approved",
        "the approval row binds actor, action and parameters; the role was checked when it was decided",
    ),
    (
        "assistant.rs",
        "audit_model_call",
        "writes the audit record of a model call that already happened; reads no project data",
    ),
    ("audit_log.rs", "audit_principal", "writes an audit record for a principal whose action was already authorized"),
    ("events.rs", "may_read_topic", "is the per-topic permission (`topic_perm`) the event stream asks"),
    (
        "events.rs",
        "event_for",
        "is the per-event filter: topic permission, scope for non-people, redaction, run ownership",
    ),
    ("lib.rs", "redacts_for", "presentation: whether content shown to this actor has secrets replaced"),
    ("lib.rs", "json_for", "presentation: redacts and tags a result for this actor"),
    ("trust.rs", "note_person_edit", "bookkeeping after an edit whose own method already asked for its permission"),
    ("workflow_service.rs", "workflow_run_for", "presentation: hides variable values from non-people"),
];

/// The text up to the first thing that reads or changes project data, sends, or audits.
fn before_first_touch(body: &str) -> &str {
    const TOUCH: &[&str] = &[
        "self.store",
        "self.authorize",
        ".await",
        "self.gate",
        "self.sender",
        "self.audit",
        "self.policy",
        "self.redact",
        "self.bus",
        "self.plugins",
    ];
    let cut = TOUCH.iter().filter_map(|t| body.find(t)).min().unwrap_or(body.len());
    &body[..cut]
}

/// `(file, method, asks_first)` for every public method of an `impl Service` block that takes an actor or principal.
fn actor_methods() -> Vec<(String, String, bool)> {
    let mut out = Vec::new();
    for (file, text) in service_sources() {
        let lines: Vec<&str> = text.lines().collect();
        let mut in_service = false;
        let mut i = 0;
        while i < lines.len() {
            let l = lines[i];
            if l.starts_with("impl Service {") || l.starts_with("impl Service<") {
                in_service = true;
            } else if !l.is_empty() && !l.starts_with(' ') && !l.starts_with('}') && !l.starts_with("//") {
                in_service = false;
            }
            let name = l
                .strip_prefix("    pub async fn ")
                .or_else(|| l.strip_prefix("    pub fn "))
                .map(|r| r.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect::<String>());
            if let (true, Some(name)) = (in_service, name) {
                let mut sig = l.to_string();
                let mut j = i;
                while !lines[j].trim_end().ends_with('{') && !lines[j].trim_end().ends_with(';') {
                    j += 1;
                    sig.push(' ');
                    sig.push_str(lines[j].trim());
                }
                let takes_actor = ["&Actor", "&Principal", "&pm_policy::Actor", "&crate::access::Principal"]
                    .iter()
                    .any(|t| sig.contains(t));
                if takes_actor {
                    let mut body = String::new();
                    let mut k = j + 1;
                    while k < lines.len() && !lines[k].starts_with("    }") {
                        if !lines[k].trim_start().starts_with("//") {
                            body.push_str(lines[k]);
                            body.push('\n');
                        }
                        k += 1;
                    }
                    let head = before_first_touch(&body);
                    let asks = head.contains("self.require") || head.contains(".require_actor");
                    out.push((file.clone(), name, asks));
                }
                i = j;
            }
            i += 1;
        }
    }
    out
}

#[test]
fn every_public_service_method_that_takes_an_actor_asks_first() {
    let methods = actor_methods();
    assert!(methods.len() > 120, "the scan found only {} methods: has the source layout changed?", methods.len());
    assert!(NO_REQUIRE.iter().all(|(_, _, why)| !why.is_empty()));
    let unasked: BTreeSet<(String, String)> =
        methods.iter().filter(|(_, _, asks)| !asks).map(|(f, n, _)| (f.clone(), n.clone())).collect();
    let allowed: BTreeSet<(String, String)> =
        NO_REQUIRE.iter().map(|(f, n, _)| (f.to_string(), n.to_string())).collect();
    let missing: Vec<_> = unasked.difference(&allowed).collect();
    assert!(
        missing.is_empty(),
        "these public `Service` methods take an actor but do not call `self.require...` before touching the store, \
         the gate or the network (add `self.require_actor(actor, Perm::X)?;` as the first statement, or add them to \
         NO_REQUIRE with a reason): {missing:?}"
    );
    let stale: Vec<_> = allowed.difference(&unasked).collect();
    assert!(stale.is_empty(), "NO_REQUIRE lists methods that do ask (or no longer exist): {stale:?}");
    let asking = methods.iter().filter(|(_, _, a)| *a).count();
    assert!(asking >= 130, "only {asking} methods ask");
}

// ---- docs/access.md ------------------------------------------------------------------------------------------

fn render() -> String {
    let uses = perm_uses();
    let mut s = String::new();
    s.push_str(
        "# Access table\n\n\
         <!-- Generated from `crates/pm-service/src/access.rs` by `crates/pm-service/tests/access.rs`. Do not edit by \
         hand: run `UPDATE_ACCESS_DOC=1 cargo test -p pm-service --test access`. -->\n\n\
         Who may do what in `pm-service` (ADR-0022, migration steps 1 and 6). Every public service method that takes an \
         actor asks `Service::require` before it touches anything (a test fails when one does not), the API checks the \
         same table for each route before the handler runs (`pm-api/src/route_perms.rs`) and the MCP server for each \
         tool (`pm-mcp::tool_perm`). The check is deny by default.\n\n\
         - **Roles.** On a project server a principal's role is the member's role on the project (`owner`, `tester`, \
         `viewer`), or for a token the lower of its ceiling and its owner's current role. An actor the server did not \
         register is a `viewer`, never an owner. In single-user mode, a person is the implicit `owner`; an agent, \
         plugin, scanner or CI actor acts as `tester`, the ceiling the ADR gives machine credentials.\n\
         - **People only** means that only an actor of kind `human` may, whatever the role: an owner's agent token is \
         still an agent, and a non-person is never above `tester`.\n\
         - **Viewers** read what the Owner/Tester/Viewer columns say they read, with secrets replaced by placeholders \
         as agents see them; they cannot send, write or configure anything.\n\
         - Roles and `people_only` narrow what the policy gate allows; they never widen it. Traffic still goes \
         through the gate (scope, tiers, windows, approvals). Approvals have finer rules than this table (a tester \
         decides only what their own tokens asked; see `docs/server-mode.md`).\n\
         - What an agent or viewer is *shown* (redaction, untrusted-content wrapping, event filtering) is mostly not an \
         access decision; `tests/access.rs` lists those uses of the actor's kind with the reason for each.\n\n\
         | Perm | Owner | Tester | Viewer | People only | Covers | Required by |\n\
         | --- | --- | --- | --- | --- | --- | --- |\n",
    );
    for &perm in Perm::ALL {
        let spec = perm.spec();
        let mark = |r: Role| if spec.roles.contains(&r) { "yes" } else { "no" };
        let methods = uses
            .get(perm.name())
            .map(|m| m.iter().map(|x| format!("`{x}`")).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        s.push_str(&format!(
            "| `{}` | {} | {} | {} | {} | {} | {} |\n",
            perm.name(),
            mark(Role::Owner),
            mark(Role::Tester),
            mark(Role::Viewer),
            if spec.people_only { "yes" } else { "no" },
            spec.summary,
            methods
        ));
    }
    s
}

#[test]
fn access_doc_is_in_sync_with_the_table() {
    let path = workspace().join("docs/access.md");
    let want = render();
    if std::env::var_os("UPDATE_ACCESS_DOC").is_some() {
        std::fs::write(&path, &want).unwrap();
    }
    let have = std::fs::read_to_string(&path).unwrap_or_default();
    assert_eq!(
        have, want,
        "docs/access.md is out of date: run `UPDATE_ACCESS_DOC=1 cargo test -p pm-service --test access`"
    );
}
