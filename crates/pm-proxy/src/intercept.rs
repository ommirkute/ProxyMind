//! The intercept queue: hold requests (and optionally responses) until a
//! human forwards, edits or drops them.
//!
//! The proxy calls [`InterceptQueue::hold`] for every message. If
//! interception is off or the message doesn't match, it returns at once
//! with `Forward(None)` and the bytes go through unchanged. Otherwise the
//! proxy task waits until [`InterceptQueue::decide`] is called (from the
//! UI, through the service layer).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::sync::oneshot;

/// Extensions skipped by default: static assets are rarely worth stopping for.
pub const DEFAULT_SKIP_EXTENSIONS: &[&str] =
    &["js", "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf", "map", "webp"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InterceptSettings {
    pub enabled: bool,
    pub requests: bool,
    pub responses: bool,
    /// Hold WebSocket messages (both directions) on connections opened while
    /// this is on. Those connections are opened without compression so
    /// messages can be edited.
    pub websocket: bool,
    /// Only hold traffic the rules of engagement put in scope.
    pub in_scope_only: bool,
    /// Only hold when the host contains this text.
    pub host_contains: String,
    /// Only hold when the path contains this text.
    pub path_contains: String,
    /// Don't hold paths ending in these extensions.
    pub skip_extensions: Vec<String>,
}

impl Default for InterceptSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            requests: true,
            responses: false,
            websocket: false,
            in_scope_only: true,
            host_contains: String::new(),
            path_contains: String::new(),
            skip_extensions: DEFAULT_SKIP_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Request,
    Response,
    /// A WebSocket message from the browser.
    WsToServer,
    /// A WebSocket message from the server.
    WsToClient,
}

impl Kind {
    pub fn is_websocket(self) -> bool {
        matches!(self, Kind::WsToServer | Kind::WsToClient)
    }
}

/// A message waiting for a decision.
#[derive(Debug, Clone, Serialize)]
pub struct Held {
    pub id: u64,
    pub kind: Kind,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    /// The message as text (lossy for non-UTF-8 bytes).
    pub raw: String,
    /// False when the message isn't valid UTF-8: it can be forwarded or
    /// dropped, but not edited as text.
    pub editable: bool,
    pub held_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Send on: unchanged (`None`) or with these bytes.
    Forward(Option<Vec<u8>>),
    Drop,
}

/// Returns whether a target is in scope (supplied by the service layer).
pub type ScopeFn = Arc<dyn Fn(&str, &str, u16, &str) -> bool + Send + Sync>;

/// What happened to the queue, for whoever watches it (the service layer's event bus).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueChange {
    /// A message was held under this id.
    Held(u64),
    /// A held message was released (forwarded, dropped, or let through when interception was turned off).
    Resolved(u64),
}

/// Must not block or call back into the queue (arrivals are reported while its lock is held).
pub type QueueObserver = Arc<dyn Fn(QueueChange) + Send + Sync>;

struct Waiting {
    held: Held,
    tx: oneshot::Sender<Decision>,
}

#[derive(Default)]
pub struct InterceptQueue {
    settings: RwLock<InterceptSettings>,
    scope: RwLock<Option<ScopeFn>>,
    waiting: Mutex<BTreeMap<u64, Waiting>>,
    next: AtomicU64,
    observer: RwLock<Option<QueueObserver>>,
}

impl InterceptQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn settings(&self) -> InterceptSettings {
        self.settings.read().clone()
    }

    /// Changes settings. Turning interception off releases everything held.
    pub fn set_settings(&self, s: InterceptSettings) {
        let off = !s.enabled;
        *self.settings.write() = s;
        if off {
            self.forward_all();
        }
    }

    pub fn set_scope(&self, f: ScopeFn) {
        *self.scope.write() = Some(f);
    }

    /// Reports arrivals and releases to `f` (one observer; a later call replaces it).
    pub fn set_observer(&self, f: QueueObserver) {
        *self.observer.write() = Some(f);
    }

    fn notify(&self, c: QueueChange) {
        let f = self.observer.read().clone();
        if let Some(f) = f {
            f(c);
        }
    }

    pub fn held(&self) -> Vec<Held> {
        self.waiting.lock().values().map(|w| w.held.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.waiting.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, id: u64) -> Option<Held> {
        self.waiting.lock().get(&id).map(|w| w.held.clone())
    }

    /// Delivers a decision. Returns false if nothing with this id is held
    /// (already decided, or the client went away).
    pub fn decide(&self, id: u64, d: Decision) -> bool {
        let removed = self.waiting.lock().remove(&id);
        match removed {
            Some(w) => {
                let sent = w.tx.send(d).is_ok();
                self.notify(QueueChange::Resolved(id));
                sent
            }
            None => false,
        }
    }

    pub fn forward_all(&self) -> usize {
        let all = std::mem::take(&mut *self.waiting.lock());
        let n = all.len();
        for (id, w) in all {
            let _ = w.tx.send(Decision::Forward(None));
            self.notify(QueueChange::Resolved(id));
        }
        n
    }

    fn matches(&self, kind: Kind, scheme: &str, host: &str, port: u16, path: &str) -> bool {
        let s = self.settings.read();
        let wanted = match kind {
            Kind::Request => s.requests,
            Kind::Response => s.responses,
            Kind::WsToServer | Kind::WsToClient => s.websocket,
        };
        if !s.enabled || !wanted {
            return false;
        }
        if !s.host_contains.is_empty() && !host.to_lowercase().contains(&s.host_contains.to_lowercase()) {
            return false;
        }
        let bare = path.split(['?', '#']).next().unwrap_or("");
        if !s.path_contains.is_empty() && !path.to_lowercase().contains(&s.path_contains.to_lowercase()) {
            return false;
        }
        if let Some(ext) = bare.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())
            && !ext.contains('/')
            && s.skip_extensions.iter().any(|x| x.eq_ignore_ascii_case(&ext))
        {
            return false;
        }
        if s.in_scope_only {
            // Without a scope function nothing counts as in scope.
            return self.scope.read().as_ref().is_some_and(|f| f(scheme, host, port, path));
        }
        true
    }

    /// Whether WebSocket messages on a connection to this target would be
    /// held right now (checked when the connection opens).
    pub fn wants_websocket(&self, scheme: &str, host: &str, port: u16, path: &str) -> bool {
        self.matches(Kind::WsToServer, scheme, host, port, path)
    }

    /// Whether a message of this kind would be held (responses are then
    /// read whole before the browser gets them).
    pub fn wants(&self, kind: Kind, scheme: &str, host: &str, port: u16, path: &str) -> bool {
        self.matches(kind, scheme, host, port, path)
    }

    /// Holds a message if the settings say so, and waits for a decision.
    #[allow(clippy::too_many_arguments)]
    pub async fn hold(
        &self,
        kind: Kind,
        scheme: &str,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
        raw: &[u8],
    ) -> Decision {
        if !self.matches(kind, scheme, host, port, path) {
            return Decision::Forward(None);
        }
        let (tx, rx) = oneshot::channel();
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let text = std::str::from_utf8(raw);
        let held = Held {
            id,
            kind,
            scheme: scheme.into(),
            host: host.into(),
            port,
            method: method.into(),
            path: path.into(),
            raw: text.map(str::to_string).unwrap_or_else(|_| String::from_utf8_lossy(raw).into_owned()),
            editable: text.is_ok(),
            held_ms: pm_core::now_ms(),
        };
        {
            // Notified under the lock, so a fast decision cannot be reported before the arrival.
            let mut waiting = self.waiting.lock();
            waiting.insert(id, Waiting { held, tx });
            self.notify(QueueChange::Held(id));
        }
        // If the queue is dropped or the decision sender vanishes, let the
        // message through rather than hanging the browser.
        rx.await.unwrap_or(Decision::Forward(None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on() -> InterceptSettings {
        InterceptSettings { enabled: true, in_scope_only: false, ..Default::default() }
    }

    #[tokio::test]
    async fn off_or_unmatched_passes_straight_through() {
        let q = InterceptQueue::new();
        assert_eq!(q.hold(Kind::Request, "http", "a", 80, "GET", "/", b"x").await, Decision::Forward(None));
        q.set_settings(on());
        assert_eq!(q.hold(Kind::Request, "http", "a", 80, "GET", "/app.js", b"x").await, Decision::Forward(None));
        assert_eq!(q.hold(Kind::Response, "http", "a", 80, "GET", "/", b"x").await, Decision::Forward(None));
        q.set_settings(InterceptSettings { in_scope_only: true, ..on() });
        assert_eq!(
            q.hold(Kind::Request, "http", "a", 80, "GET", "/", b"x").await,
            Decision::Forward(None),
            "no scope fn"
        );
    }

    #[tokio::test]
    async fn holds_until_decided_and_releases_when_turned_off() {
        let q = Arc::new(InterceptQueue::new());
        q.set_settings(on());
        let q2 = q.clone();
        let t = tokio::spawn(async move { q2.hold(Kind::Request, "http", "a", 80, "GET", "/x", b"GET /x").await });
        while q.is_empty() {
            tokio::task::yield_now().await;
        }
        let h = q.held().pop().unwrap();
        assert_eq!((h.path.as_str(), h.editable), ("/x", true));
        assert!(q.decide(h.id, Decision::Forward(Some(b"GET /y".to_vec()))));
        assert_eq!(t.await.unwrap(), Decision::Forward(Some(b"GET /y".to_vec())));
        assert!(!q.decide(h.id, Decision::Drop), "already decided");

        let q3 = q.clone();
        let t = tokio::spawn(async move { q3.hold(Kind::Request, "http", "a", 80, "GET", "/z", &[0xff, 0xfe]).await });
        while q.is_empty() {
            tokio::task::yield_now().await;
        }
        assert!(!q.held()[0].editable, "binary messages can't be edited as text");
        q.set_settings(InterceptSettings::default());
        assert_eq!(t.await.unwrap(), Decision::Forward(None));
    }

    #[tokio::test]
    async fn scope_function_decides_when_in_scope_only() {
        let q = InterceptQueue::new();
        q.set_settings(InterceptSettings { enabled: true, ..Default::default() });
        q.set_scope(Arc::new(|_, host, _, _| host == "in.scope"));
        assert!(q.matches(Kind::Request, "https", "in.scope", 443, "/"));
        assert!(!q.matches(Kind::Request, "https", "other", 443, "/"));
    }

    #[test]
    fn websocket_messages_have_their_own_switch() {
        let q = InterceptQueue::new();
        q.set_settings(on());
        assert!(!q.wants_websocket("https", "a", 443, "/ws"));
        q.set_settings(InterceptSettings { websocket: true, requests: false, ..on() });
        assert!(q.wants_websocket("https", "a", 443, "/ws"));
        assert!(q.matches(Kind::WsToClient, "https", "a", 443, "/ws"));
        assert!(!q.matches(Kind::Request, "https", "a", 443, "/ws"));
    }
}
