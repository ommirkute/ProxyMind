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
    // ADR-0022 "Roles": a viewer reads and comments only (here: their own workspace and the run lists); a tester does
    // everything a person does while testing but not what configures the project; the owner alone changes the ROE,
    // the network side, integrations, model keys and trust.
    assert_eq!(viewer, ["UiStateWrite", "RunsReadAll"]);
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
        "what an agent is shown of an event (scope and redaction, ADR-0018); membership filtering comes with ADR-0022 step 6",
    ),
    ("integration_events.rs", 1, "builds the service's own internal actor to read a task for a notification"),
    ("lib.rs", 2, "redaction and untrusted-content wrapping for agents (`redacts_for`, `view_for`): presentation"),
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

// ---- docs/access.md ------------------------------------------------------------------------------------------

fn render() -> String {
    let uses = perm_uses();
    let mut s = String::new();
    s.push_str(
        "# Access table\n\n\
         <!-- Generated from `crates/pm-service/src/access.rs` by `crates/pm-service/tests/access.rs`. Do not edit by \
         hand: run `UPDATE_ACCESS_DOC=1 cargo test -p pm-service --test access`. -->\n\n\
         Who may do what in `pm-service` (ADR-0022, migration step 1). Every action that only some principals may take \
         has an entry here, and the service asks `Service::require` (or `Principal::allows` where the answer shapes a \
         view, not a refusal) before it acts. The check is deny by default.\n\n\
         - **Roles.** In single-user mode, which is all there is today, a person is the implicit `owner`; an agent, \
         plugin, scanner or CI actor acts as `tester`, the ceiling the ADR gives machine credentials. Per-project \
         roles for several people come with ADR-0022 step 6; the columns below already say what each will be allowed.\n\
         - **People only** means that only an actor of kind `human` may, whatever the role: an owner's agent is still \
         an agent.\n\
         - Roles and `people_only` narrow what the policy gate allows; they never widen it. Traffic still goes \
         through the gate (scope, tiers, windows, approvals).\n\
         - What an agent is *shown* (redaction, untrusted-content wrapping, event filtering) is not an access decision; \
         `tests/access.rs` lists those uses of the actor's kind with the reason for each.\n\n\
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
