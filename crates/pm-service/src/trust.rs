//! Safe open of a project file (threat model F-2, ADR-0022 step 0).
//!
//! A project file is active content: it carries listeners, upstream proxy rules, rewrite rules, scan schedules,
//! workflow triggers, session macros, an assistant URL and the rules of engagement that define "in scope". A file
//! that came from somewhere else must not start acting on that say-so. So a project is only **trusted** when this
//! installation says so, and an untrusted project opens in **safe mode**.
//!
//! - **Where trust lives:** `<home>/project-trust.json`, a map from the project id (setting `project_id`, made when
//!   the project is first opened) to a record `{digest, by, at_ms, basis}`. Never in the project file: a project
//!   cannot vouch for itself. This is the design integrations use (`integration-trust.json`, 3.5).
//! - **What trust is:** a SHA-256 digest of the security-relevant settings (see [`material`]). If the file changes
//!   (another program edits it, a different file is swapped in under the same id) the digest no longer matches and
//!   the project is in safe mode again until a person confirms. People's own edits through the service update the
//!   record in the same step, so working in a trusted project never drops it into safe mode.
//! - **How a project becomes trusted:** (1) this process created the file (`Store::created_here`; recorded when the
//!   home is attached, so the `proxymind` that made it and every later process agree); (2) a person confirms the
//!   current digest (`POST /project/trust`, `proxymind project trust`), after reading what would be switched on;
//!   (3) a person edits it through this installation while it is trusted. In-memory projects are always trusted:
//!   nothing foreign can be in them. A project that existed before this change is **not** trusted until confirmed
//!   once (one click or `proxymind project trust --yes`): there is no honest way to tell it from a download.
//! - **Without a home** (library use, tests) the records live in process memory, so a project the process created
//!   and reopens stays trusted; a file that arrives some other way (a copy, a snapshot) does not.
//!
//! What safe mode holds back is listed by [`Service::trust_status`]; the doc of that type says what is not held.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use pm_core::now_ms;
use pm_policy::{Actor, ActorKind};
use pm_store::Store;
use ring::digest;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::access::{Denial, Perm};
use crate::{Result, Service, ServiceError};

/// The trust records, in the user's home folder.
pub const TRUST_FILE: &str = "project-trust.json";
/// Project setting holding the random id the trust records are filed under.
pub const PROJECT_ID_SETTING: &str = "project_id";
/// How long a verdict is reused by the hot paths (the gate, the triggers). Status calls always recompute.
const CACHE: Duration = Duration::from_millis(1000);

const SAFE_MODE_REASON: &str = "this project is in safe mode: it was not created by this installation (or its settings \
     changed since a person trusted it). Review and trust it first: `proxymind project trust`, or the banner in the \
     web UI";

/// What this installation recorded about a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRecord {
    /// SHA-256 of the settings that were trusted.
    pub digest: String,
    /// Who vouched for them: `human:name`. Scheduled scans and triggers run as this person.
    pub by: String,
    pub at_ms: i64,
    /// `created` (this install made the project), `confirmed` (a person reviewed it) or `edited` (a person changed it).
    pub basis: String,
}

/// Records of processes that have no home folder (tests, library use), shared so a reopened project stays trusted.
static MEMORY: Mutex<BTreeMap<String, TrustRecord>> = Mutex::new(BTreeMap::new());

/// The verdict for one project at one moment.
#[derive(Debug, Clone)]
pub struct Eval {
    pub trusted: bool,
    pub project_id: String,
    pub digest: String,
    pub record: Option<TrustRecord>,
}

struct Inner {
    /// An in-memory project cannot hold anything foreign: always trusted.
    in_memory: bool,
    home: OnceLock<PathBuf>,
    cache: Mutex<Option<(Instant, bool)>>,
}

/// Decides whether the project in a store is trusted in this installation. Cheap to clone; the service, the
/// background watchers and the schedulers share one.
#[derive(Clone)]
pub struct TrustGate {
    inner: Arc<Inner>,
}

/// `human:<user>` for the person running this process (what `proxymind ui` acts as by default).
pub fn default_person() -> String {
    let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default();
    let user: String = user.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c)).collect();
    format!("human:{}", if user.is_empty() { "local" } else { &user })
}

fn random_id() -> String {
    let mut b = [0u8; 12];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system randomness");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Gives a project an id if it has none (a write: call it where the store is owned, never on a read connection).
pub fn ensure_project_id(store: &mut Store) -> Result<String> {
    if let Some(id) = store.get_setting(PROJECT_ID_SETTING)?.filter(|s| !s.is_empty()) {
        return Ok(id);
    }
    Ok(store.init_setting(PROJECT_ID_SETTING, &random_id())?)
}

/// What the digest covers, in a fixed order. Run state (last run, next run, counters) and the identity strings
/// (`created_by`, `enabled_by`, `saved_by`) are left out: the first change all the time, the second are never trusted.
#[derive(Serialize)]
struct Material {
    roe: Option<String>,
    network: Option<String>,
    listeners: Option<String>,
    rewrite_rules: Option<String>,
    session: Option<String>,
    assistant: Option<String>,
    schedules: Vec<serde_json::Value>,
    triggers: Vec<serde_json::Value>,
}

fn material(store: &Store) -> Result<Material> {
    let schedules = store
        .list_schedules()?
        .into_iter()
        .map(|row| match crate::scan_schedule::from_row(row.clone()) {
            Some(s) => {
                json!({ "id": s.id, "name": s.name, "every": s.every, "request": s.request, "enabled": s.enabled })
            }
            None => json!({ "id": row.id, "raw": row.data, "enabled": row.enabled }),
        })
        .collect();
    let triggers = match crate::workflow_service::load_workflows(store) {
        Ok(list) => list
            .into_iter()
            .filter(|w| w.trigger.enabled)
            .map(
                |w| json!({ "id": w.id, "name": w.name, "steps": w.steps, "max_per_minute": w.trigger.max_per_minute }),
            )
            .collect(),
        // Unreadable workflows cannot run; their text still counts, so a later fix is a change.
        Err(_) => vec![json!({ "raw": store.get_setting(crate::WORKFLOWS_SETTING)? })],
    };
    Ok(Material {
        roe: store.get_setting(crate::ROE_SETTING)?,
        network: store.get_setting(crate::NETWORK_SETTING)?,
        listeners: store.get_setting(crate::LISTENERS_SETTING)?,
        rewrite_rules: store.get_setting(crate::RULES_SETTING)?,
        session: store.get_setting(crate::SESSION_SETTING)?,
        assistant: store.get_setting(crate::assistant::ASSISTANT_SETTING)?,
        schedules,
        triggers,
    })
}

/// The digest of the settings a person is asked to trust.
pub fn digest_of(store: &Store) -> Result<String> {
    let bytes = serde_json::to_vec(&material(store)?).map_err(|e| ServiceError::Invalid(e.to_string()))?;
    Ok(digest::digest(&digest::SHA256, &bytes).as_ref().iter().map(|b| format!("{b:02x}")).collect())
}

fn write_private(path: &std::path::Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| ServiceError::Invalid(format!("saving trust: {e}")))?;
    }
    let tmp = path.with_extension("json.tmp");
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp).map_err(|e| ServiceError::Invalid(format!("saving trust: {e}")))?;
        std::io::Write::write_all(&mut f, text.as_bytes())
            .map_err(|e| ServiceError::Invalid(format!("saving trust: {e}")))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| ServiceError::Invalid(format!("saving trust: {e}")))
}

impl TrustGate {
    pub fn new(in_memory: bool) -> Self {
        Self { inner: Arc::new(Inner { in_memory, home: OnceLock::new(), cache: Mutex::new(None) }) }
    }

    /// The home folder, once attached.
    pub fn home(&self) -> Option<PathBuf> {
        self.inner.home.get().cloned()
    }

    fn file(&self) -> Option<PathBuf> {
        self.inner.home.get().map(|h| h.join(TRUST_FILE))
    }

    fn records(&self) -> BTreeMap<String, TrustRecord> {
        match self.file() {
            Some(p) => std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default(),
            None => MEMORY.lock().map(|m| m.clone()).unwrap_or_default(),
        }
    }

    fn put(&self, pid: &str, rec: TrustRecord) -> Result<()> {
        match self.file() {
            Some(p) => {
                let mut m = self.records();
                m.insert(pid.to_string(), rec);
                write_private(
                    &p,
                    &serde_json::to_string_pretty(&m).map_err(|e| ServiceError::Invalid(e.to_string()))?,
                )?;
            }
            None => {
                if let Ok(mut m) = MEMORY.lock() {
                    m.insert(pid.to_string(), rec);
                }
            }
        }
        self.invalidate();
        Ok(())
    }

    /// Forgets the cached verdict (after a record or a setting changed in this process).
    pub fn invalidate(&self) {
        if let Ok(mut c) = self.inner.cache.lock() {
            *c = None;
        }
    }

    /// Whether the project has a record in this installation (with the current home, or in memory).
    fn has_record(&self, store: &Store) -> bool {
        store.get_setting(PROJECT_ID_SETTING).ok().flatten().is_some_and(|pid| self.records().contains_key(&pid))
    }

    /// Records a project this process created as trusted, once, if this installation has no record of it yet.
    pub fn note_creation(&self, store: &Store) {
        if self.inner.in_memory || !store.created_here() || self.has_record(store) {
            return;
        }
        let (Some(pid), Ok(d)) = (store.get_setting(PROJECT_ID_SETTING).ok().flatten(), digest_of(store)) else {
            return;
        };
        let rec = TrustRecord { digest: d, by: default_person(), at_ms: now_ms(), basis: "created".into() };
        if let Err(e) = self.put(&pid, rec) {
            tracing::warn!("could not record the new project as trusted: {e}");
        }
    }

    /// Attaches the user's home folder (the trust records live there from now on).
    pub fn attach_home(&self, home: PathBuf, store: &Store) {
        let _ = self.inner.home.set(home);
        self.note_creation(store);
        self.invalidate();
    }

    /// The verdict, recomputed.
    pub fn evaluate(&self, store: &Store) -> Eval {
        let project_id = store.get_setting(PROJECT_ID_SETTING).ok().flatten().unwrap_or_default();
        let digest = digest_of(store).unwrap_or_default();
        if self.inner.in_memory {
            return Eval { trusted: true, project_id, digest, record: None };
        }
        let record = self.records().remove(&project_id).filter(|_| !project_id.is_empty());
        let trusted = !digest.is_empty() && record.as_ref().is_some_and(|r| r.digest == digest);
        Eval { trusted, project_id, digest, record }
    }

    /// Whether the project is trusted, from a verdict at most a second old.
    pub fn is_trusted(&self, store: &Store) -> bool {
        if self.inner.in_memory {
            return true;
        }
        if let Ok(c) = self.inner.cache.lock()
            && let Some((at, v)) = *c
            && at.elapsed() < CACHE
        {
            return v;
        }
        let v = self.evaluate(store).trusted;
        if let Ok(mut c) = self.inner.cache.lock() {
            *c = Some((Instant::now(), v));
        }
        v
    }

    /// Makes the project's current settings trusted, as vouched for by `by`.
    pub fn record_current(&self, store: &Store, by: &str, basis: &str) -> Result<Eval> {
        let mut ev = self.evaluate(store);
        if self.inner.in_memory {
            return Ok(ev);
        }
        if ev.project_id.is_empty() {
            return Err(ServiceError::Invalid("this project has no id yet; open it with ProxyMind first".into()));
        }
        let rec = TrustRecord { digest: ev.digest.clone(), by: by.to_string(), at_ms: now_ms(), basis: basis.into() };
        self.put(&ev.project_id, rec.clone())?;
        ev.trusted = true;
        ev.record = Some(rec);
        Ok(ev)
    }

    /// Who scheduled scans and triggers run as: the person who last vouched for the project.
    pub fn runner(&self, store: &Store) -> Option<String> {
        self.evaluate(store).record.map(|r| r.by)
    }
}

/// A trust gate for a process that opens the project without a `Service` (the proxy without rules of engagement):
/// gives the project an id, attaches `home`, and records a project this process created.
pub fn trust_gate_for(store: &mut Store, home: Option<PathBuf>) -> Result<TrustGate> {
    ensure_project_id(store)?;
    let gate = TrustGate::new(store.path().is_none());
    match home {
        Some(h) => gate.attach_home(h, store),
        None => gate.note_creation(store),
    }
    Ok(gate)
}

/// Whether `home` records the project in `store` as trusted with its current settings (a read; nothing is recorded).
pub fn project_trusted_in(store: &Store, home: &std::path::Path) -> bool {
    let gate = TrustGate::new(false);
    let _ = gate.inner.home.set(home.to_path_buf());
    gate.evaluate(store).trusted
}

// ---- what a person is asked to review ------------------------------------------------------------------------

/// One thing the project file would switch on.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct HeldBack {
    /// `listener`, `upstream`, `network`, `rewrite_rule`, `schedule`, `workflow_trigger`, `session`, `assistant`, `roe`
    pub kind: String,
    pub what: String,
    /// What safe mode does about it.
    pub why: String,
}

/// One line of the review page.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct ReviewItem {
    pub what: String,
    pub detail: String,
    /// A name the file says is responsible (a schedule's `created_by`, a trigger's `enabled_by`). Shown as
    /// written in the file, never used as an identity.
    pub claimed_by: Option<String>,
}

/// Everything the file would do, grouped, for the person who is deciding.
#[derive(Debug, Clone, Default, Serialize, schemars::JsonSchema)]
pub struct TrustReview {
    pub roe_text: Option<String>,
    pub roe_summary: serde_json::Value,
    pub listeners: Vec<ReviewItem>,
    pub upstream_rules: Vec<ReviewItem>,
    pub network_other: Vec<ReviewItem>,
    pub rewrite_rules: Vec<ReviewItem>,
    pub schedules: Vec<ReviewItem>,
    pub triggers: Vec<ReviewItem>,
    pub session: Vec<ReviewItem>,
    pub assistant: Vec<ReviewItem>,
}

/// Whether the project in this installation is trusted, and if not, what is held back.
///
/// **Held back in safe mode** (until a person confirms): extra proxy listeners (the primary one, from the command
/// line, still runs); scan schedules (they do not fire); workflow triggers (they do not run); the project's network
/// settings as a whole (upstream proxy rules, client certificates, hostname overrides, TLS pass-through: traffic
/// goes direct and unmodified, never through an address the file names); match-and-replace rules; session rules
/// and macros; OAST settings; the assistant (no model call, so no key and no traffic leave for a URL the file
/// names); and every action by an agent, plugin or the AI scan that would send traffic (the scope the gate checks
/// is the file's own).
///
/// **Not held back:** reading the project; a person's own actions (Replay, scans started by hand, editing
/// settings, which stay in safe mode); the proxy's main listener; integrations (they have their own trust,
/// `integration-trust.json`); plugins (installed per user, never from a project); `proxymind ci`, which ignores
/// all of these settings anyway.
#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct TrustView {
    /// `trusted` or `safe_mode`.
    pub status: String,
    pub safe_mode: bool,
    pub project_id: String,
    /// The digest of the settings as they are now. Send it back when confirming, so a person confirms what they read.
    pub digest: String,
    /// Who vouched for the project and when, if anyone did.
    pub trusted_by: Option<String>,
    pub trusted_at_ms: Option<i64>,
    /// `created`, `confirmed` or `edited`.
    pub basis: Option<String>,
    /// A record exists but the settings no longer match it: the file changed since.
    pub changed_since_trust: bool,
    pub held_back: Vec<HeldBack>,
    pub review: TrustReview,
}

/// `POST /project/trust`.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TrustConfirmRequest {
    /// The digest from `GET /project/trust` that the person reviewed. If the project has changed since, the
    /// confirmation is refused. Omit to confirm whatever is there now (scripts).
    pub digest: Option<String>,
}

fn clip(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if s.chars().count() > n { format!("{t}…") } else { t }
}

fn item(what: impl Into<String>, detail: impl Into<String>, claimed_by: Option<String>) -> ReviewItem {
    ReviewItem { what: what.into(), detail: detail.into(), claimed_by: claimed_by.filter(|s| !s.is_empty()) }
}

impl Service {
    /// Wires the trust gate's home to the user's home folder (done by `attach_plugin_home`).
    pub(crate) fn trust_attach_home(&self, home: PathBuf) {
        self.store.read(|db| self.trust.attach_home(home, db));
        self.trust_changed();
    }

    /// Points trust at the user's home folder without loading anything else from it (the CLI's one-shot commands).
    pub fn attach_trust_home(&self, home: PathBuf) {
        self.trust_attach_home(home);
    }

    /// A person changed settings directly in the project file through this installation (the CLI's `roe use`):
    /// `was_trusted` is [`project_trusted_in`] from before the change.
    pub fn note_person_edit(&self, actor: &Actor, was_trusted: bool) {
        self.trust_after(actor, was_trusted);
    }

    /// The gate, for the background watchers that open the project on their own connection.
    pub fn trust_gate(&self) -> TrustGate {
        self.trust.clone()
    }

    /// Something that affects trust changed in this process: forget cached verdicts and re-apply what safe mode
    /// holds back (or releases).
    pub(crate) fn trust_changed(&self) {
        self.trust.invalidate();
        self.workflow_invalidate();
        if let Err(e) = self.resync_held_settings() {
            tracing::warn!("settings not re-applied after a trust change: {e}");
        }
    }

    /// True while the project is not trusted here. A `proxymind ci` run ignores the file's settings itself, so it
    /// is never "in safe mode".
    pub fn safe_mode(&self) -> bool {
        if self.run_guard.lock().isolated {
            return false;
        }
        !self.store.read(|db| self.trust.is_trusted(db))
    }

    /// Why an action that would send traffic or call a model is refused right now, if it is. Looks at the project
    /// afresh (not the one-second cache the hot paths use): a model call is rare and sends data away.
    pub fn safe_mode_reason(&self) -> Option<String> {
        if self.run_guard.lock().isolated || self.trust_before() {
            return None;
        }
        self.trust.invalidate();
        Some(SAFE_MODE_REASON.to_string())
    }

    /// The gate's check for actors that are not people (see [`TrustView`]); cached for a second, like the other hot paths.
    pub(crate) fn safe_mode_refusal(&self, actor: &Actor) -> Option<String> {
        (actor.kind != ActorKind::Human && self.safe_mode()).then(|| SAFE_MODE_REASON.to_string())
    }

    /// Whether the project is trusted right now, from the store (not cached). For the edit hooks.
    pub(crate) fn trust_before(&self) -> bool {
        self.store.read(|db| self.trust.evaluate(db).trusted)
    }

    /// After a person changed a setting: if the project was trusted before the change, it stays trusted (the person
    /// made the change in this installation) and the record follows the new settings. Otherwise nothing changes: an
    /// untrusted project stays in safe mode however it is edited.
    pub(crate) fn trust_after(&self, actor: &Actor, was_trusted: bool) {
        if was_trusted && actor.kind == ActorKind::Human {
            let r = self.store.read(|db| self.trust.record_current(db, &actor.id(), "edited"));
            if let Err(e) = r {
                tracing::warn!("trust record not updated after an edit: {e}");
            }
        }
        self.trust_changed();
    }

    /// The person scheduled scans and triggers run as. In an in-memory project the stored name is used (nothing
    /// foreign can be in it); otherwise it is the person who vouched for the project, and the name stored in the
    /// file is ignored.
    pub(crate) fn run_as(&self, stored: &str) -> Result<Actor> {
        let name = match self.store.read(|db| (self.trust.inner.in_memory, self.trust.runner(db))) {
            (true, _) => stored.to_string(),
            (false, Some(by)) => by,
            (false, None) => {
                return Err(ServiceError::Invalid("the project is not trusted in this installation".into()));
            }
        };
        let actor = Actor::parse(&name).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid(format!("{name} is not a person; scheduled work needs one")));
        }
        // On a project server this work has no request behind it: it acts with the tester role (never owner),
        // unless the same person is signed in, whose registered role stays.
        self.register_background(&actor);
        Ok(actor)
    }

    fn held_back_now(&self) -> Result<(Vec<HeldBack>, TrustReview)> {
        let roe = self.policy.roe();
        let roe_text = self.store.read(|db| db.get_setting(crate::ROE_SETTING))?;
        let mut held = Vec::new();
        let mut review =
            TrustReview { roe_text: roe_text.clone(), roe_summary: crate::roe::summarize(&roe), ..Default::default() };
        held.push(HeldBack {
            kind: "roe".into(),
            what: format!(
                "Rules of engagement{}: in scope {}",
                match roe.engagement.name.as_deref().filter(|n| !n.is_empty()) {
                    Some(n) => format!(" \"{n}\""),
                    None => String::new(),
                },
                if roe.include.is_empty() {
                    "nothing".to_string()
                } else {
                    roe.include.iter().map(|p| p.text.clone()).collect::<Vec<_>>().join(", ")
                }
            ),
            why:
                "the scope the gate enforces was written by the file's author; agents, plugins and the AI scan cannot \
                  send until a person confirms it"
                    .into(),
        });

        for l in self.store.read(crate::load_listeners)?.iter().filter(|l| l.enabled) {
            let ip = l.bind.rsplit_once(':').map(|(h, _)| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>());
            let exposed = !matches!(ip, Some(Ok(ip)) if ip.is_loopback());
            let kind = match l.kind {
                pm_proxy::ListenerKind::Socks5 => "SOCKS5",
                _ => "HTTP",
            };
            let what = format!("{kind} listener on {}{}", l.bind, if l.transparent { " (transparent)" } else { "" });
            let mut detail = vec![if exposed {
                "reachable from other machines: anyone who can connect can use the proxy".to_string()
            } else {
                "loopback only".to_string()
            }];
            if !l.username.is_empty() {
                detail.push("asks for a login".into());
            }
            if !l.redirect_host.is_empty() {
                detail.push(format!("sends every request to {}:{}", l.redirect_host, l.redirect_port));
            }
            review.listeners.push(item(what.clone(), detail.join("; "), None));
            held.push(HeldBack { kind: "listener".into(), what, why: "not started".into() });
        }

        let net = self.store.read(crate::load_network)?;
        for r in &net.upstream_rules {
            let who = if r.matches.is_empty() { "all other hosts".to_string() } else { r.matches.join(", ") };
            let what = format!("{who} via {}", r.via);
            let detail = if r.username.is_empty() { "no login".to_string() } else { "with a saved login".to_string() };
            review.upstream_rules.push(item(what.clone(), detail, None));
            held.push(HeldBack {
                kind: "upstream".into(),
                what: format!("Upstream rule: {what}"),
                why: "not applied: traffic goes direct".into(),
            });
        }
        for h in &net.hosts {
            review.network_other.push(item(format!("{} resolves to {}", h.host, h.address), "hostname override", None));
        }
        for p in &net.tls_passthrough {
            review.network_other.push(item(format!("TLS pass-through for {p}"), "not decrypted, not recorded", None));
        }
        if !net.client_certs.is_empty() {
            review.network_other.push(item(
                format!("{} client certificate(s)", net.client_certs.len()),
                "files named by the project",
                None,
            ));
        }
        if !net.hosts.is_empty() || !net.tls_passthrough.is_empty() || !net.client_certs.is_empty() {
            held.push(HeldBack {
                kind: "network".into(),
                what: "Hostname overrides, TLS pass-through or client certificates".into(),
                why: "not applied".into(),
            });
        }

        for r in self.store.read(crate::load_rules)?.iter().filter(|r| r.enabled) {
            let what = format!("{:?}: {} → {}", r.part, clip(&r.pattern, 80), clip(&r.replace, 80));
            review.rewrite_rules.push(item(
                what.clone(),
                format!(
                    "{}{}",
                    if r.regex { "regex; " } else { "" },
                    if r.in_scope_only { "in-scope targets only" } else { "all targets" }
                ),
                None,
            ));
            held.push(HeldBack {
                kind: "rewrite_rule".into(),
                what: format!("Match-and-replace rule {what}"),
                why: "not applied".into(),
            });
        }

        for row in self.store.read(|db| db.list_schedules())? {
            let claimed = Some(row.created_by.clone());
            match crate::scan_schedule::from_row(row.clone()) {
                Some(s) if s.enabled => {
                    let what = format!("Scan schedule \"{}\" of {}", s.name, s.request.url);
                    review.schedules.push(item(what.clone(), format!("{:?}", s.every), claimed));
                    held.push(HeldBack { kind: "schedule".into(), what, why: "does not fire".into() });
                }
                Some(s) => {
                    review.schedules.push(item(format!("Scan schedule \"{}\" (paused)", s.name), "off", claimed))
                }
                None => review.schedules.push(item(format!("Unreadable schedule {}", row.id), "will not run", claimed)),
            }
        }

        if let Ok(list) = self.store.read(crate::workflow_service::load_workflows) {
            for w in list.into_iter().filter(|w| w.trigger.enabled) {
                let what = format!("Workflow \"{}\" runs on new proxied traffic", w.name);
                review.triggers.push(item(
                    what.clone(),
                    format!("{} step(s), at most {} run(s) a minute", w.steps.len(), w.trigger.max_per_minute),
                    Some(w.trigger.enabled_by.clone()),
                ));
                held.push(HeldBack { kind: "workflow_trigger".into(), what, why: "does not run".into() });
            }
        }

        if let Ok(cfg) = self.store.read(crate::session::load_config)
            && (!cfg.rules.is_empty() || !cfg.macros.is_empty())
        {
            let what = format!("{} session rule(s) and {} macro(s)", cfg.rules.len(), cfg.macros.len());
            review.session.push(item(
                what.clone(),
                "they add cookies and headers to requests and send login requests on their own",
                Some(cfg.saved_by.clone()),
            ));
            held.push(HeldBack { kind: "session".into(), what, why: "not applied".into() });
        }

        if let Some(text) = self.store.read(|db| db.get_setting(crate::assistant::ASSISTANT_SETTING))?
            && let Ok(cfg) = serde_json::from_str::<crate::AssistantConfig>(&text)
        {
            let what = format!("Assistant model at {}", cfg.base_url);
            let key =
                if cfg.api_key_env.is_empty() { "no key".to_string() } else { format!("key {}", cfg.api_key_env) };
            review.assistant.push(item(what.clone(), format!("model {}; {key}", cfg.model), None));
            held.push(HeldBack {
                kind: "assistant".into(),
                what,
                why: "no model call (so no key and no data leave for that URL)".into(),
            });
        }
        Ok((held, review))
    }

    /// Whether the project is trusted here and what is held back. Any actor may read it.
    pub fn trust_status(&self) -> Result<TrustView> {
        let ev = self.store.read(|db| self.trust.evaluate(db));
        // The verdict just computed is the freshest: use it for the hot paths too.
        self.trust.invalidate();
        let isolated = self.run_guard.lock().isolated;
        let safe = !ev.trusted && !isolated;
        let (held_back, review) = self.held_back_now()?;
        Ok(TrustView {
            status: if safe { "safe_mode" } else { "trusted" }.into(),
            safe_mode: safe,
            project_id: ev.project_id,
            digest: ev.digest.clone(),
            trusted_by: ev.record.as_ref().map(|r| r.by.clone()),
            trusted_at_ms: ev.record.as_ref().map(|r| r.at_ms),
            basis: ev.record.as_ref().map(|r| r.basis.clone()),
            changed_since_trust: ev.record.as_ref().is_some_and(|r| r.digest != ev.digest),
            held_back: if safe { held_back } else { vec![] },
            review,
        })
    }

    /// A person confirms the project's current settings: they are trusted from now on in this installation, the
    /// listeners start, schedules and triggers run (as this person), rules and network settings apply. People only;
    /// audited, a refusal too.
    pub fn trust_confirm(&self, actor: &Actor, req: &TrustConfirmRequest) -> Result<TrustView> {
        self.require_actor_with(
            actor,
            Perm::ProjectTrust,
            Denial::audited("project_trust", json!({ "reason": "only people confirm a project" })),
        )?;
        let before = self.trust_status()?;
        if let Some(d) = &req.digest
            && *d != before.digest
        {
            let _ = self.audit(
                &actor.id(),
                "project_trust",
                json!({ "reason": "the project changed while reviewing" }),
                "deny",
            );
            return Err(ServiceError::Invalid(
                "the project changed since you reviewed it; review it again before confirming".into(),
            ));
        }
        // Names stored in the file are not identities: from now on they are this person (the runs use the trust
        // record anyway; this makes the file say the same).
        self.reattribute(actor)?;
        let ev = self.store.read(|db| self.trust.record_current(db, &actor.id(), "confirmed"))?;
        self.audit(
            &actor.id(),
            "project_trust",
            json!({ "digest": ev.digest, "project_id": ev.project_id, "released": before.held_back.iter().map(|h| &h.what).collect::<Vec<_>>() }),
            "allow",
        )?;
        self.trust_changed();
        self.trust_status()
    }

    /// Rewrites the schedules' and triggers' stored names to `actor` (neither is part of the digest).
    fn reattribute(&self, actor: &Actor) -> Result<()> {
        let id = actor.id();
        for row in self.store.read(|db| db.list_schedules())? {
            if let Some(mut s) = crate::scan_schedule::from_row(row.clone()) {
                s.created_by = id.clone();
                let data = serde_json::to_string(&s).map_err(|e| ServiceError::Invalid(e.to_string()))?;
                let new = pm_store::ScheduleRow {
                    id: row.id,
                    created_by: id.clone(),
                    data,
                    enabled: row.enabled,
                    next_run_ms: row.next_run_ms,
                };
                self.store.write(|db| -> Result<()> {
                    db.save_schedule(&new)?;
                    Ok(db.set_schedule_owner(new.id, &id)?)
                })?;
            }
        }
        self.store.write(|db| -> Result<()> {
            let Ok(mut list) = crate::workflow_service::load_workflows(db) else { return Ok(()) };
            let mut changed = false;
            for w in list.iter_mut().filter(|w| !w.trigger.enabled_by.is_empty() && w.trigger.enabled_by != id) {
                w.trigger.enabled_by.clone_from(&id);
                changed = true;
            }
            if changed {
                crate::workflow_service::save_workflows(db, &list)?;
            }
            Ok(())
        })
    }

    /// Brings the settings this process applies live (network, rewrite rules, listeners) in line with the trust
    /// verdict: the saved ones when trusted, none when not.
    pub(crate) fn resync_held_settings(&self) -> Result<()> {
        let gate = self.trust.clone();
        self.store.read(|db| -> Result<()> {
            crate::sync_network_gated(db, self.sender.network(), &gate)?;
            if let Some(r) = self.rewriter.get() {
                crate::rules::sync_rules_gated(db, r, &gate)?;
            }
            if let Some(l) = self.listeners.get() {
                crate::network::sync_listeners_gated(db, l, &gate)?;
            }
            Ok(())
        })
    }
}
