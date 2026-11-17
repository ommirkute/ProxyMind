//! Traffic hooks (ADR-0020): long-lived sandboxed workers that see messages in flight and may replace them.
//!
//! A [`HookEngine`] holds the hooks a person turned on, in order. For each (plugin, hook kind) it starts one worker
//! process lazily, on the first message that matches, in the same sandbox as other plugin processes, and talks to
//! it in JSON lines (see [`crate::frames`]). The proxy asks the engine for each message; with no hook on, that is
//! one atomic load.
//!
//! Failure never stalls or corrupts traffic: a call has a deadline, at most [`MAX_INFLIGHT`] calls are in flight per
//! worker (more bypass instead of waiting), messages over [`MAX_MESSAGE`] bypass, and a timeout, crash, malformed
//! answer or a replacement that isn't an HTTP message forwards the original and is noted. After
//! [`PAUSE_AFTER`] failures within [`PAUSE_WINDOW`] the hook is paused until a person resumes it. A hook may ask for
//! `on_error: drop`, which blocks the message instead. A replacement is forwarded exactly as returned.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tokio::sync::oneshot;

pub use crate::frames::MAX_MESSAGE;
use crate::frames::{Answer, ExchangeInfo, MAX_LINE, decode_answer, encode_call};
use crate::v2::{HookKind, HookMatch, HookSpec, OnError, hook_id};
use crate::{Installed, sandbox, sign};

/// Calls in flight per worker; more bypass the hook.
pub const MAX_INFLIGHT: usize = 4;
/// Failures within [`PAUSE_WINDOW`] that pause a hook.
pub const PAUSE_AFTER: usize = 5;
pub const PAUSE_WINDOW: Duration = Duration::from_secs(60);
/// Extra time the first call to a freshly started worker gets, for the interpreter to start.
const STARTUP_GRACE: Duration = Duration::from_millis(500);
const KEEP_FAILURES: usize = 10;

/// Whether a target is in scope (supplied by the service layer).
pub type ScopeFn = Arc<dyn Fn(&str, &str, u16, &str) -> bool + Send + Sync>;
/// Told when a hook's state changes on its own (`plugin`, `what`).
pub type ChangeFn = Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Where a message goes (or came from): the request's target.
#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub method: &'a str,
    pub path: &'a str,
}

/// What happened with one hook, to record on the exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// `<plugin>/<kind>`.
    pub name: String,
    pub note: Option<String>,
    /// The hook changed the message. When false the message went on unchanged (bypassed, or failed).
    pub applied: bool,
}

/// A hook stopped the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub name: String,
    pub why: String,
    /// The hook asked for it (`drop`), rather than failed with `on_error: drop`.
    pub dropped: bool,
}

/// The outcome of running a message through the hooks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Run {
    /// The message to forward instead of the original, when a hook changed it.
    pub bytes: Option<Vec<u8>>,
    pub notes: Vec<Note>,
    pub block: Option<Block>,
}

/// A recent failure of a hook.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct Failure {
    pub at_ms: i64,
    pub reason: String,
}

/// How a configured hook is doing.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, schemars::JsonSchema)]
pub struct HookStatus {
    pub plugin: String,
    pub kind: HookKind,
    pub paused: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused_reason: Option<String>,
    /// Messages sent to the hook since it was configured.
    pub calls: u64,
    /// Messages it changed.
    pub changed: u64,
    /// Latest failures, newest last.
    pub failures: Vec<Failure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CallError {
    Busy,
    Timeout(u64),
    Exited,
    Malformed(String),
}

impl CallError {
    fn text(&self) -> String {
        match self {
            CallError::Busy => "busy".into(),
            CallError::Timeout(ms) => format!("no answer within {ms} ms"),
            CallError::Exited => "the hook process exited".into(),
            CallError::Malformed(w) => w.clone(),
        }
    }
}

type Reply = Result<Answer, CallError>;

#[derive(Default)]
struct Pending {
    waiting: HashMap<u64, oneshot::Sender<Reply>>,
    /// Calls that timed out and may still be answered; their answers are ignored.
    abandoned: HashSet<u64>,
}

struct Shared {
    alive: AtomicBool,
    pending: StdMutex<Pending>,
}

impl Shared {
    fn deliver(&self, id: u64, r: Reply) {
        let Ok(mut p) = self.pending.lock() else { return };
        match p.waiting.remove(&id) {
            Some(tx) => {
                let _ = tx.send(r);
            }
            None => {
                p.abandoned.remove(&id); // a stale answer after a timeout
            }
        }
    }

    fn fail_all(&self, e: &CallError) {
        let Ok(mut p) = self.pending.lock() else { return };
        for (_, tx) in p.waiting.drain() {
            let _ = tx.send(Err(e.clone()));
        }
    }
}

/// One worker process.
struct Worker {
    child: Arc<Mutex<Child>>,
    tx: SyncSender<Vec<u8>>,
    shared: Arc<Shared>,
    inflight: AtomicUsize,
    fresh: AtomicBool,
}

struct Dec<'a>(&'a AtomicUsize);
impl Drop for Dec<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}

impl Worker {
    fn spawn(p: &Installed, hook: &HookSpec, kind: HookKind) -> Result<Arc<Worker>, String> {
        if let Some(f) = sign::changed(&p.dir, &p.files) {
            return Err(format!("{f} changed since install: install the plugin again"));
        }
        let mut cmd = sandbox::worker_command(&p.dir, &hook.command)?;
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("could not start {}: {e}", hook.command[0]))?;
        let (mut stdin, stdout) = match (child.stdin.take(), child.stdout.take()) {
            (Some(i), Some(o)) => (i, o),
            _ => {
                let _ = child.kill();
                return Err("the hook process has no pipes".into());
            }
        };
        let shared = Arc::new(Shared { alive: AtomicBool::new(true), pending: StdMutex::new(Pending::default()) });
        let child = Arc::new(Mutex::new(child));
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(MAX_INFLIGHT * 2);
        std::thread::Builder::new()
            .name("hook-writer".into())
            .spawn(move || {
                for frame in rx {
                    if stdin.write_all(&frame).and_then(|()| stdin.flush()).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        let (sh, ch) = (shared.clone(), child.clone());
        std::thread::Builder::new()
            .name("hook-reader".into())
            .spawn(move || {
                let mut r = BufReader::new(stdout);
                loop {
                    let mut line = Vec::new();
                    match (&mut r).take(MAX_LINE as u64 + 1).read_until(b'\n', &mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    if line.len() > MAX_LINE {
                        sh.fail_all(&CallError::Malformed("the answer line is too long".into()));
                        break;
                    }
                    while line.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                        line.pop();
                    }
                    if line.is_empty() {
                        continue;
                    }
                    match decode_answer(&line, kind) {
                        Ok((id, a)) => sh.deliver(id, Ok(a)),
                        Err(m) => match m.id {
                            Some(id) => sh.deliver(id, Err(CallError::Malformed(m.why))),
                            None => {
                                // Not attributable to a call: the stream can't be trusted any more.
                                sh.fail_all(&CallError::Malformed(m.why));
                                break;
                            }
                        },
                    }
                }
                sh.alive.store(false, Relaxed);
                sh.fail_all(&CallError::Exited);
                let mut c = ch.lock();
                let _ = c.kill();
                let _ = c.wait();
            })
            .map_err(|e| e.to_string())?;
        Ok(Arc::new(Worker { child, tx, shared, inflight: AtomicUsize::new(0), fresh: AtomicBool::new(true) }))
    }

    fn alive(&self) -> bool {
        self.shared.alive.load(Relaxed)
    }

    fn kill(&self) {
        let _ = self.child.lock().kill();
    }

    async fn call(&self, id: u64, frame: Vec<u8>, timeout: Duration) -> Reply {
        if !self.alive() {
            return Err(CallError::Exited);
        }
        if self.inflight.fetch_add(1, Relaxed) >= MAX_INFLIGHT {
            self.inflight.fetch_sub(1, Relaxed);
            return Err(CallError::Busy);
        }
        let _dec = Dec(&self.inflight);
        let (tx, rx) = oneshot::channel();
        if let Ok(mut p) = self.shared.pending.lock() {
            p.waiting.insert(id, tx);
        }
        if let Err(e) = self.tx.try_send(frame) {
            if let Ok(mut p) = self.shared.pending.lock() {
                p.waiting.remove(&id);
            }
            return Err(match e {
                TrySendError::Full(_) => CallError::Busy,
                TrySendError::Disconnected(_) => CallError::Exited,
            });
        }
        let wait = timeout + if self.fresh.swap(false, Relaxed) { STARTUP_GRACE } else { Duration::ZERO };
        match tokio::time::timeout(wait, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(CallError::Exited),
            Err(_) => {
                let stuck = match self.shared.pending.lock() {
                    Ok(mut p) => {
                        if p.waiting.remove(&id).is_some() {
                            p.abandoned.insert(id);
                        }
                        p.abandoned.len() >= MAX_INFLIGHT
                    }
                    Err(_) => true,
                };
                if stuck {
                    self.kill(); // wedged: a fresh worker starts on the next message
                }
                Err(CallError::Timeout(timeout.as_millis() as u64))
            }
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        self.kill();
    }
}

#[derive(Default)]
struct HState {
    failures: VecDeque<Instant>,
    recent: VecDeque<Failure>,
    paused: Option<String>,
    calls: u64,
    changed: u64,
}

/// One configured hook: its spec, state and (lazily started) worker.
struct Runtime {
    plugin: Installed,
    kind: HookKind,
    hook: HookSpec,
    state: Mutex<HState>,
    worker: Mutex<Option<Arc<Worker>>>,
    next_id: AtomicU64,
    notify: Arc<RwLock<Option<ChangeFn>>>,
}

impl Runtime {
    fn name(&self) -> String {
        hook_id(&self.plugin.manifest.name, self.kind)
    }

    fn paused(&self) -> bool {
        self.state.lock().paused.is_some()
    }

    fn worker(&self) -> Result<Arc<Worker>, String> {
        let mut slot = self.worker.lock();
        if let Some(w) = slot.as_ref().filter(|w| w.alive()) {
            return Ok(w.clone());
        }
        *slot = None; // drops (kills) a dead one
        let w = Worker::spawn(&self.plugin, &self.hook, self.kind)?;
        *slot = Some(w.clone());
        Ok(w)
    }

    fn tell(&self, what: &str) {
        if let Some(f) = self.notify.read().as_ref() {
            f(&self.plugin.manifest.name, what);
        }
    }

    /// Counts a failure; pauses the hook after too many.
    fn fail(&self, why: &str) {
        let paused_now = {
            let mut s = self.state.lock();
            let now = Instant::now();
            s.failures.push_back(now);
            while s.failures.front().is_some_and(|t| now.duration_since(*t) > PAUSE_WINDOW) {
                s.failures.pop_front();
            }
            s.recent.push_back(Failure { at_ms: pm_core::now_ms(), reason: why.to_string() });
            while s.recent.len() > KEEP_FAILURES {
                s.recent.pop_front();
            }
            if s.failures.len() >= PAUSE_AFTER && s.paused.is_none() {
                s.paused = Some(format!("{PAUSE_AFTER} failures within a minute (last: {why})"));
                true
            } else {
                false
            }
        };
        tracing_warn(&self.name(), why);
        if paused_now {
            *self.worker.lock() = None;
            self.tell("hook_paused");
        }
    }

    fn status(&self) -> HookStatus {
        let s = self.state.lock();
        HookStatus {
            plugin: self.plugin.manifest.name.clone(),
            kind: self.kind,
            paused: s.paused.is_some(),
            paused_reason: s.paused.clone(),
            calls: s.calls,
            changed: s.changed,
            failures: s.recent.iter().cloned().collect(),
        }
    }
}

fn tracing_warn(name: &str, why: &str) {
    tracing::warn!(hook = name, "{why}");
}

enum Outcome {
    Pass,
    Replace(Vec<u8>, Option<String>),
    Drop,
    /// Bypassed, not a failure.
    Skipped(String),
    Failed(String),
}

impl Runtime {
    async fn call(&self, ex: &ExchangeInfo, raw: &[u8]) -> Outcome {
        let worker = match self.worker() {
            Ok(w) => w,
            Err(e) => return Outcome::Failed(e),
        };
        let id = self.next_id.fetch_add(1, Relaxed);
        let frame = encode_call(id, self.kind, ex, raw);
        self.state.lock().calls += 1;
        let timeout = Duration::from_millis(self.hook.timeout_ms());
        match worker.call(id, frame, timeout).await {
            Err(CallError::Busy) => {
                self.state.lock().calls -= 1;
                Outcome::Skipped("bypassed: the hook is busy".into())
            }
            Err(e) => Outcome::Failed(e.text()),
            Ok(Answer::Pass) => Outcome::Pass,
            Ok(Answer::Drop) => Outcome::Drop,
            Ok(Answer::Replace { raw, note }) => {
                if parses(self.kind, &raw) {
                    Outcome::Replace(raw, note)
                } else {
                    Outcome::Failed(match self.kind {
                        HookKind::Request => "the replacement is not an HTTP request".into(),
                        HookKind::Response => "the replacement is not an HTTP response".into(),
                    })
                }
            }
        }
    }
}

/// Whether bytes are a message `pm-http` can parse.
fn parses(kind: HookKind, raw: &[u8]) -> bool {
    let Ok(Some(end)) = pm_http::find_head_end(raw) else { return false };
    match kind {
        HookKind::Request => pm_http::parse_request_head(&raw[..end]).is_ok(),
        HookKind::Response => pm_http::parse_response_head(&raw[..end]).is_ok(),
    }
}

/// `*` matches any run of characters; case-insensitive.
fn glob(pattern: &str, text: &str) -> bool {
    let (p, t): (Vec<char>, Vec<char>) =
        (pattern.to_ascii_lowercase().chars().collect(), text.to_ascii_lowercase().chars().collect());
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// The media type of a message's `Content-Type` header (lowercase, without parameters).
pub fn content_type(raw: &[u8]) -> Option<String> {
    let end = pm_http::find_head_end(raw).ok().flatten().unwrap_or(raw.len().min(64 * 1024));
    for line in raw[..end].split(|b| *b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|b| *b == b':') else { continue };
        if line[..colon].eq_ignore_ascii_case(b"content-type") {
            let v = String::from_utf8_lossy(&line[colon + 1..]).into_owned();
            return Some(v.split(';').next().unwrap_or("").trim().to_ascii_lowercase());
        }
    }
    None
}

fn status_of(raw: &[u8]) -> Option<u16> {
    std::str::from_utf8(raw.split(|b| *b == b' ').nth(1)?).ok()?.parse().ok()
}

impl HookMatch {
    /// Whether a message to `t` with this head (for its content type) matches.
    pub fn matches(&self, t: &Target<'_>, head: &[u8]) -> bool {
        (self.hosts.is_empty() || self.hosts.iter().any(|h| glob(h, t.host)))
            && (self.paths.is_empty() || self.paths.iter().any(|p| t.path.starts_with(p.as_str())))
            && (self.methods.is_empty() || self.methods.iter().any(|m| m.eq_ignore_ascii_case(t.method)))
            && (self.content_types.is_empty() || {
                let ct = content_type(head);
                ct.is_some_and(|ct| {
                    self.content_types.iter().any(|want| {
                        let want = want.to_ascii_lowercase();
                        match want.strip_suffix("/*") {
                            Some(major) => ct.split('/').next() == Some(major),
                            None => ct == want,
                        }
                    })
                })
            })
    }
}

/// The hooks a person turned on, and the way to run messages through them.
#[derive(Default)]
pub struct HookEngine {
    list: RwLock<Arc<Vec<Arc<Runtime>>>>,
    any_request: AtomicBool,
    any_response: AtomicBool,
    scope: RwLock<Option<ScopeFn>>,
    notify: Arc<RwLock<Option<ChangeFn>>>,
}

impl HookEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hooks only ever see in-scope traffic; without a scope function nothing is in scope.
    pub fn set_scope(&self, f: ScopeFn) {
        *self.scope.write() = Some(f);
    }

    /// Called when a hook pauses itself.
    pub fn set_observer(&self, f: ChangeFn) {
        *self.notify.write() = Some(f);
    }

    /// Replaces the hooks, in order. A hook that is unchanged keeps its worker and state (a paused hook stays
    /// paused); anything else starts fresh, and workers that are no longer wanted are stopped.
    pub fn configure(&self, hooks: Vec<(Installed, HookKind)>) {
        let old = self.list.read().clone();
        let mut next = Vec::new();
        for (plugin, kind) in hooks {
            let Some(hook) = plugin.manifest.hook(kind).cloned() else { continue };
            let same = old.iter().find(|r| r.kind == kind && r.plugin == plugin && r.hook == hook);
            next.push(match same {
                Some(r) => r.clone(),
                None => Arc::new(Runtime {
                    plugin,
                    kind,
                    hook,
                    state: Mutex::new(HState::default()),
                    worker: Mutex::new(None),
                    next_id: AtomicU64::new(1),
                    notify: self.notify.clone(),
                }),
            });
        }
        self.any_request.store(next.iter().any(|r| r.kind == HookKind::Request), Relaxed);
        self.any_response.store(next.iter().any(|r| r.kind == HookKind::Response), Relaxed);
        *self.list.write() = Arc::new(next);
    }

    /// Whether any hook of this kind is on (the proxy's cheap check).
    pub fn wants(&self, kind: HookKind) -> bool {
        match kind {
            HookKind::Request => self.any_request.load(Relaxed),
            HookKind::Response => self.any_response.load(Relaxed),
        }
    }

    fn applicable(&self, kind: HookKind, t: &Target<'_>, head: &[u8], include_paused: bool) -> Vec<Arc<Runtime>> {
        if !self.wants(kind) {
            return Vec::new();
        }
        let in_scope = self.scope.read().as_ref().is_some_and(|f| f(t.scheme, t.host, t.port, t.path));
        if !in_scope {
            return Vec::new();
        }
        let list = self.list.read().clone();
        list.iter()
            .filter(|r| r.kind == kind && (include_paused || !r.paused()) && r.hook.matcher.matches(t, head))
            .cloned()
            .collect()
    }

    /// Whether a message to `t` (with this head) would go to a hook.
    pub fn may_apply(&self, kind: HookKind, t: &Target<'_>, head: &[u8]) -> bool {
        !self.applicable(kind, t, head, false).is_empty()
    }

    /// Notes for the hooks that would have seen this message, saying why they didn't (streamed, too big, upgraded).
    pub fn skipped(&self, kind: HookKind, t: &Target<'_>, head: &[u8], why: &str) -> Vec<Note> {
        self.applicable(kind, t, head, false)
            .iter()
            .map(|r| Note { name: r.name(), note: Some(format!("bypassed: {why}")), applied: false })
            .collect()
    }

    /// Runs one message through the matching hooks in order. Never fails: problems are notes (or a block, for a
    /// hook with `on_error: drop`).
    pub async fn run(&self, kind: HookKind, t: &Target<'_>, raw: &[u8]) -> Run {
        let hooks = self.applicable(kind, t, raw, false);
        let mut out = Run::default();
        if hooks.is_empty() {
            return out;
        }
        let info = ExchangeInfo {
            method: t.method.to_string(),
            scheme: t.scheme.to_string(),
            host: t.host.to_string(),
            port: t.port,
            path: t.path.to_string(),
            status: if kind == HookKind::Response { status_of(raw) } else { None },
        };
        for h in hooks {
            let current = out.bytes.as_deref().unwrap_or(raw);
            if current.len() > MAX_MESSAGE {
                out.notes.push(Note {
                    name: h.name(),
                    note: Some("bypassed: message over 8 MB".into()),
                    applied: false,
                });
                continue;
            }
            match h.call(&info, current).await {
                Outcome::Pass => {}
                Outcome::Replace(new, note) => {
                    if new != current {
                        h.state.lock().changed += 1;
                        out.bytes = Some(new);
                        // The prefixes mark notes that changed nothing; a hook's own words can't use them.
                        let note = note.map(|n| {
                            if n.starts_with("bypassed:") || n.starts_with("failed:") {
                                format!("hook says: {n}")
                            } else {
                                n
                            }
                        });
                        out.notes.push(Note { name: h.name(), note, applied: true });
                    }
                }
                Outcome::Drop => {
                    out.block =
                        Some(Block { name: h.name(), why: "the hook dropped the request".into(), dropped: true });
                    break;
                }
                Outcome::Skipped(why) => out.notes.push(Note { name: h.name(), note: Some(why), applied: false }),
                Outcome::Failed(why) => {
                    h.fail(&why);
                    let closed = h.hook.on_error == OnError::Drop;
                    let tail = if closed { "blocked" } else { "original forwarded" };
                    out.notes.push(Note {
                        name: h.name(),
                        note: Some(format!("failed: {why}; {tail}")),
                        applied: false,
                    });
                    if closed {
                        out.block = Some(Block { name: h.name(), why, dropped: false });
                        break;
                    }
                }
            }
        }
        out
    }

    /// How the configured hooks are doing.
    pub fn statuses(&self) -> Vec<HookStatus> {
        self.list.read().iter().map(|r| r.status()).collect()
    }

    pub fn status(&self, plugin: &str, kind: HookKind) -> Option<HookStatus> {
        self.statuses().into_iter().find(|s| s.plugin == plugin && s.kind == kind)
    }

    /// Pauses a configured hook (a person's act). False if it isn't configured.
    pub fn pause(&self, plugin: &str, kind: HookKind) -> bool {
        self.with(plugin, kind, |r| {
            r.state.lock().paused = Some("paused by a person".into());
            *r.worker.lock() = None;
        })
    }

    /// Resumes a paused hook and forgets its recent failures. False if it isn't configured.
    pub fn resume(&self, plugin: &str, kind: HookKind) -> bool {
        self.with(plugin, kind, |r| {
            let mut s = r.state.lock();
            s.paused = None;
            s.failures.clear();
        })
    }

    fn with(&self, plugin: &str, kind: HookKind, f: impl FnOnce(&Runtime)) -> bool {
        let list = self.list.read().clone();
        match list.iter().find(|r| r.kind == kind && r.plugin.manifest.name == plugin) {
            Some(r) => {
                f(r);
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("*.example.com", "api.example.com") && glob("*.EXAMPLE.com", "a.b.example.com"));
        assert!(!glob("*.example.com", "example.com") && !glob("*.example.com", "example.com.evil.io"));
        assert!(glob("api.*", "api.x.io") && glob("*", "") && glob("a*c*e", "abcde") && !glob("a*c*e", "abcdf"));
        assert!(glob("exact.io", "exact.io") && !glob("exact.io", "exact.io2"));
    }

    #[test]
    fn matchers() {
        let m = HookMatch {
            hosts: vec!["*.example.com".into()],
            paths: vec!["/api/".into()],
            methods: vec!["post".into()],
            content_types: vec!["application/json".into(), "text/*".into()],
        };
        let t = Target { scheme: "https", host: "a.example.com", port: 443, method: "POST", path: "/api/x?y=1" };
        let head = b"POST /api/x HTTP/1.1\r\nContent-Type: Application/JSON; charset=utf-8\r\n\r\n";
        assert!(m.matches(&t, head));
        assert!(m.matches(&t, b"POST / HTTP/1.1\r\ncontent-type: text/plain\r\n\r\n"), "wildcard subtype");
        assert!(!m.matches(&t, b"POST / HTTP/1.1\r\n\r\n"), "no content type");
        assert!(!m.matches(&t, b"POST / HTTP/1.1\r\nContent-Type: image/png\r\n\r\n"));
        assert!(!m.matches(&Target { method: "GET", ..t }, head));
        assert!(!m.matches(&Target { path: "/other", ..t }, head));
        assert!(!m.matches(&Target { host: "example.org", ..t }, head));
        assert!(HookMatch::default().matches(&t, b""), "empty lists match everything");
    }

    #[test]
    fn replacements_must_parse() {
        assert!(parses(HookKind::Request, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"));
        assert!(!parses(HookKind::Request, b"nonsense"));
        assert!(parses(HookKind::Response, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
        assert!(!parses(HookKind::Response, b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!parses(HookKind::Response, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"), "no end of head");
        assert_eq!(status_of(b"HTTP/1.1 404 Not Found\r\n\r\n"), Some(404));
    }
}
