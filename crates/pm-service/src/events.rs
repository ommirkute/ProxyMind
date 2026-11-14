//! The typed event bus (ADR-0018).
//!
//! `Service` publishes a small [`Event`] after each write has committed. Events carry ids and short summaries
//! only, never bodies, headers, evidence text or secrets: a consumer fetches the row through the normal,
//! actor-checked service call. Each event gets a strictly increasing per-process `seq`, assigned and sent in one
//! critical section so that `seq` order is delivery order. Publishing never blocks (a `tokio` broadcast send),
//! and "no subscribers" is not an error. Nothing is replayed: a subscriber that falls behind gets a
//! [`Delivery::Resync`] and refetches what it shows.
//!
//! [`Service::event_for`] is the one place that decides what an actor may see of an event (scope, topic and
//! redaction); the API's SSE stream, and later MCP notifications and webhooks, all go through it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use pm_policy::{Actor, ActorKind, Target};
use pm_store::{CommittedExchange, CommittedWs};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::broadcast;

use crate::{Counters, Result, Service};

/// Events a slow subscriber may fall behind by before it gets a resync.
pub const EVENT_BUFFER: usize = 1024;

/// Progress (scan, fuzzer, AI scan) is published at most this often per run; the newest update that was held back
/// goes out when the window ends, and the final one always goes out at once.
const PROGRESS_EVERY: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Topic {
    Exchanges,
    Findings,
    Scans,
    Proofs,
    Intercept,
    Approvals,
    Audit,
    Collaborator,
    Websockets,
    Fuzzer,
    AiScan,
}

impl Topic {
    pub const ALL: [Topic; 11] = [
        Topic::Exchanges,
        Topic::Findings,
        Topic::Scans,
        Topic::Proofs,
        Topic::Intercept,
        Topic::Approvals,
        Topic::Audit,
        Topic::Collaborator,
        Topic::Websockets,
        Topic::Fuzzer,
        Topic::AiScan,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Topic::Exchanges => "exchanges",
            Topic::Findings => "findings",
            Topic::Scans => "scans",
            Topic::Proofs => "proofs",
            Topic::Intercept => "intercept",
            Topic::Approvals => "approvals",
            Topic::Audit => "audit",
            Topic::Collaborator => "collaborator",
            Topic::Websockets => "websockets",
            Topic::Fuzzer => "fuzzer",
            Topic::AiScan => "ai_scan",
        }
    }

    pub fn parse(s: &str) -> Option<Topic> {
        Topic::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// What happened. May only grow by adding variants and fields (ADR-0018). A variant with free text must say
/// what `event_for` redacts: today only `host` is target-derived text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    /// An exchange was stored (proxy, replay, import, ...). `host` is target-derived.
    ExchangeRecorded {
        id: i64,
        host: String,
        method: String,
        status: Option<u16>,
    },
    /// A finding was created, merged into, or updated.
    FindingChanged {
        id: i64,
        status: String,
    },
    /// A crawl-and-audit task or other scan moved on.
    ScanProgress {
        task: String,
        done: usize,
        total: usize,
    },
    /// A proof run finished. `verdict` is `proven` or `not_proven`; `finding_id` is the finding it named, if any.
    ProofCompleted {
        proof_id: i64,
        finding_id: Option<i64>,
        verdict: String,
    },
    InterceptQueued {
        id: u64,
    },
    InterceptResolved {
        id: u64,
    },
    ApprovalRequested {
        id: String,
    },
    /// `decision` is `approved` or `denied`.
    ApprovalDecided {
        id: String,
        decision: String,
    },
    AuditAppended {
        seq: u64,
    },
    /// A Collaborator (out-of-band) callback was stored; `id` is the `oast_interactions` row.
    CollaboratorHit {
        id: i64,
    },
    /// WebSocket messages were stored for this exchange (at most one event per exchange per write; fetch the
    /// messages with `ws_messages`). Carries no target-derived text.
    WsMessageRecorded {
        exchange_id: i64,
    },
    /// A scan task moved to another state: `crawling`, `auditing`, `paused`, `done`, `cancelled` or `failed`. Sent for
    /// every transition (never rate-limited). Carries no target-derived text.
    ScanStateChanged {
        task: String,
        state: String,
    },
    /// A fuzzer attack made progress or changed state (`running`, `paused`, `cancelled`, `done`, `failed`). State
    /// changes always go out; plain progress is rate-limited. Carries no request or response text.
    FuzzerProgress {
        attack: String,
        done: usize,
        total: usize,
        state: String,
    },
    /// An AI scan's status, phase, log, steps or cost changed. `state` is `running`, `stopping`, `stopped`, `done` or
    /// `failed`; `phase` one of the fixed phase words. No log text, report or model output: the page refetches the
    /// scan through the normal API.
    AiScanChanged {
        scan_id: i64,
        state: String,
        phase: String,
    },
}

impl Event {
    pub fn topic(&self) -> Topic {
        match self {
            Event::ExchangeRecorded { .. } => Topic::Exchanges,
            Event::FindingChanged { .. } => Topic::Findings,
            Event::ScanProgress { .. } => Topic::Scans,
            Event::ProofCompleted { .. } => Topic::Proofs,
            Event::InterceptQueued { .. } | Event::InterceptResolved { .. } => Topic::Intercept,
            Event::ApprovalRequested { .. } | Event::ApprovalDecided { .. } => Topic::Approvals,
            Event::AuditAppended { .. } => Topic::Audit,
            Event::CollaboratorHit { .. } => Topic::Collaborator,
            Event::WsMessageRecorded { .. } => Topic::Websockets,
            Event::ScanStateChanged { .. } => Topic::Scans,
            Event::FuzzerProgress { .. } => Topic::Fuzzer,
            Event::AiScanChanged { .. } => Topic::AiScan,
        }
    }
}

/// An event as published: with its `seq` and topic. The scope target (what an agent's scope check needs) and the
/// owner (who started the run, for scans and attacks) are kept out of the serialized form.
#[derive(Debug, Clone)]
pub struct Published {
    pub seq: u64,
    pub topic: Topic,
    pub event: Event,
    scope: Option<Target>,
    owner: Option<String>,
}

/// How a progress-like event is paced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rate {
    /// At most one per 250 ms per key; the newest one held back is sent when the window ends.
    Limited,
    /// A state change: sent at once, and it supersedes anything held back.
    Always,
    /// The final update of a run: sent at once and the key is forgotten.
    Last,
}

struct Slot {
    at: Instant,
    held: Option<(Event, Option<String>)>,
}

#[derive(Clone)]
pub(crate) struct Bus {
    tx: broadcast::Sender<Published>,
    seq: std::sync::Arc<parking_lot::Mutex<u64>>,
    progress: std::sync::Arc<parking_lot::Mutex<HashMap<String, Slot>>>,
}

impl Bus {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            tx: broadcast::channel(capacity).0,
            seq: std::sync::Arc::new(parking_lot::Mutex::new(0)),
            progress: std::sync::Arc::new(parking_lot::Mutex::new(HashMap::new())),
        }
    }

    /// Never blocks. `scope` is the request target an agent's scope rules are checked against, if the event
    /// belongs to one.
    pub(crate) fn publish(&self, event: Event, scope: Option<Target>) {
        self.publish_full(event, scope, None);
    }

    fn publish_full(&self, event: Event, scope: Option<Target>, owner: Option<String>) {
        let mut seq = self.seq.lock();
        *seq += 1;
        // Err only means nobody is subscribed.
        let _ = self.tx.send(Published { seq: *seq, topic: event.topic(), event, scope, owner });
    }

    pub(crate) fn has_subscribers(&self) -> bool {
        self.tx.receiver_count() > 0
    }

    pub(crate) fn publish_exchanges(&self, rows: &[CommittedExchange]) {
        for r in rows {
            let scope = Target::from_parts(&r.scheme, &r.host, r.port, &r.path).ok();
            let event =
                Event::ExchangeRecorded { id: r.id, host: r.host.clone(), method: r.method.clone(), status: r.status };
            self.publish(event, scope);
        }
    }

    pub(crate) fn publish_ws(&self, rows: &[CommittedWs]) {
        for r in rows {
            let scope = Target::from_parts(&r.scheme, &r.host, r.port, &r.path).ok();
            self.publish(Event::WsMessageRecorded { exchange_id: r.exchange_id }, scope);
        }
    }

    /// Subscribes, and says the newest `seq` published so far, atomically: everything after it will be delivered.
    pub(crate) fn subscribe(&self) -> Subscription {
        let seq = self.seq.lock();
        Subscription { rx: self.tx.subscribe(), latest: *seq }
    }

    /// Publishes a progress-like event for the run `key`, paced by `rate`. `owner` is who started the run (an agent
    /// only gets events of its own runs). Never blocks. With `Limited`, an update inside the 250 ms window is held,
    /// and the newest held one is sent when the window ends (from a tokio task, so without a runtime it is dropped:
    /// the next update or the final one carries the state).
    pub(crate) fn publish_rated(&self, key: &str, event: Event, owner: Option<&str>, rate: Rate) {
        let owner = owner.map(str::to_string);
        // The map lock is held while publishing, so the pacing state and `seq` order cannot disagree.
        let mut map = self.progress.lock();
        let now = Instant::now();
        match rate {
            Rate::Last => {
                map.remove(key);
            }
            Rate::Always => {
                map.insert(key.to_string(), Slot { at: now, held: None });
            }
            Rate::Limited => {
                if let Some(slot) = map.get_mut(key)
                    && now.duration_since(slot.at) < PROGRESS_EVERY
                {
                    if let Ok(rt) = tokio::runtime::Handle::try_current() {
                        let first = slot.held.is_none();
                        slot.held = Some((event, owner));
                        if first {
                            let (bus, key) = (self.clone(), key.to_string());
                            let wait = PROGRESS_EVERY - now.duration_since(slot.at);
                            rt.spawn(async move {
                                tokio::time::sleep(wait).await;
                                bus.flush(&key);
                            });
                        }
                    }
                    return;
                }
                if map.len() >= 1024 {
                    // Runs that never ended (a crashed task) must not pile up.
                    map.retain(|_, s| now.duration_since(s.at) < Duration::from_secs(60));
                }
                map.insert(key.to_string(), Slot { at: now, held: None });
            }
        }
        self.publish_full(event, None, owner);
    }

    /// Sends the update held back for `key`, if it is still held (a final or state-change update clears it).
    fn flush(&self, key: &str) {
        let mut map = self.progress.lock();
        if let Some(slot) = map.get_mut(key)
            && let Some((event, owner)) = slot.held.take()
        {
            slot.at = Instant::now();
            self.publish_full(event, None, owner);
        }
    }
}

/// A subscriber's view of the bus.
pub struct Subscription {
    rx: broadcast::Receiver<Published>,
    latest: u64,
}

/// What a subscriber gets next.
#[derive(Debug, Clone)]
pub enum Delivery {
    Event(Published),
    /// The subscriber fell behind and `missed` events were dropped for it. Refetch what you show; live events
    /// follow.
    Resync {
        missed: u64,
    },
}

impl Subscription {
    /// The newest `seq` published before this subscription began (0 if none). A client that reconnects with a
    /// `Last-Event-ID` different from this has missed events (nothing is replayed) and should resync.
    pub fn latest_seq(&self) -> u64 {
        self.latest
    }

    /// The next delivery; `None` once the service is gone.
    pub async fn recv(&mut self) -> Option<Delivery> {
        match self.rx.recv().await {
            Ok(p) => Some(Delivery::Event(p)),
            Err(broadcast::error::RecvError::Lagged(missed)) => Some(Delivery::Resync { missed }),
            Err(broadcast::error::RecvError::Closed) => None,
        }
    }
}

impl Service {
    /// Subscribes to every event published from now on. See the module docs for what is and is not promised.
    pub fn subscribe(&self) -> Subscription {
        self.bus.subscribe()
    }

    pub(crate) fn publish(&self, event: Event) {
        self.bus.publish(event, None);
    }

    /// Publishes an event that belongs to a request target, so agents' scope rules apply to it.
    pub(crate) fn publish_scoped(&self, event: Event, url: &str) {
        // A URL that does not parse gets no scope target, which hides the event from agents (fail closed).
        self.bus.publish(event, Target::from_url(url).ok());
    }

    pub(crate) fn finding_changed(&self, id: i64, status: &str, url: &str) {
        self.publish_scoped(Event::FindingChanged { id, status: status.into() }, url);
    }

    /// Publishes a progress-like event for run `key`, owned by `owner` (None: everyone may read it). See
    /// [`Bus::publish_rated`].
    pub(crate) fn publish_rated(&self, key: &str, event: Event, owner: Option<&str>, rate: Rate) {
        self.bus.publish_rated(key, event, owner, rate);
    }

    /// Whether `actor` may read events of this topic. The intercept queue is for humans only, like its REST routes.
    ///
    /// Scan, fuzzer and AI-scan events carry no host, so scope does not apply; they follow the resource's own API.
    /// `scans` and `fuzzer` events go to humans and to the agent that started the run (`event_for` checks the owner),
    /// like `scan_task_*` and `fuzzer_*` ("people see every task, agents only their own"). `ai_scan` is readable by
    /// every actor, like `GET /ai-scan`, which has no actor check; its events carry ids and state words only.
    pub fn may_read_topic(&self, actor: &Actor, topic: Topic) -> bool {
        topic != Topic::Intercept || actor.kind == ActorKind::Human
    }

    /// What `actor` may see of a published event, as JSON (`seq`, `topic`, `type` and the event's fields), or
    /// `None` when the event must not reach them. The single place for these rules (ADR-0018):
    /// - a topic the actor may not read is dropped;
    /// - for an agent, an event about a request target (`ExchangeRecorded`, `FindingChanged`, `WsMessageRecorded`) is dropped when the
    ///   target is out of scope, or when its scope could not be determined;
    /// - for an agent, strings pass through the redactor when the ROE asks for it (`json_for`), so a host
    ///   containing a secret is replaced by a placeholder. Humans see events as published;
    /// - for an agent or plugin, an event of a run someone else started (scan tasks, fuzzer attacks) is dropped.
    pub fn event_for(&self, actor: &Actor, p: &Published) -> Option<Value> {
        if !self.may_read_topic(actor, p.topic) {
            return None;
        }
        if actor.kind != ActorKind::Human {
            if p.owner.as_deref().is_some_and(|o| o != actor.id()) {
                return None;
            }
            let targeted = matches!(
                p.event,
                Event::ExchangeRecorded { .. } | Event::FindingChanged { .. } | Event::WsMessageRecorded { .. }
            );
            match &p.scope {
                Some(t) if self.policy.scope_check(t).is_err() => return None,
                None if targeted => return None,
                _ => {}
            }
        }
        let mut v = serde_json::to_value(&p.event).ok()?;
        v["seq"] = json!(p.seq);
        v["topic"] = json!(p.topic.as_str());
        Some(self.json_for(actor, v))
    }
}

/// Running counters kept from events, so a stream does not re-read the store for each change (ADR-0018 step 2).
///
/// Exchanges, the newest exchange id and the audit length come straight from events. Findings and pending
/// approvals cannot (an event does not say whether a finding is new or an approval was pending), so a relevant
/// event only marks them stale and the next [`CounterTracker::snapshot`] recounts them with `COUNT` queries; the
/// held-message count comes from memory.
pub struct CounterTracker {
    counters: Counters,
    stale: bool,
}

impl CounterTracker {
    /// Folds one event in. Returns whether it can change [`Counters`] (so a client needs a fresh snapshot).
    pub fn apply(&mut self, p: &Published) -> bool {
        match &p.event {
            Event::ExchangeRecorded { id, .. } => {
                // Rows already counted by the initial read (events published while it ran) are skipped.
                if *id > self.counters.last_exchange_id {
                    self.counters.exchanges += 1;
                    self.counters.last_exchange_id = *id;
                }
                true
            }
            Event::AuditAppended { seq } => {
                self.counters.audit_records = self.counters.audit_records.max(*seq as usize);
                true
            }
            Event::FindingChanged { .. } | Event::ApprovalRequested { .. } | Event::ApprovalDecided { .. } => {
                self.stale = true;
                true
            }
            Event::InterceptQueued { .. } | Event::InterceptResolved { .. } => true,
            _ => false,
        }
    }

    /// The current counters.
    pub fn snapshot(&mut self, svc: &Service) -> Result<Counters> {
        if self.stale {
            let (findings, pending) = svc.store.read(|s| -> anyhow::Result<_> {
                Ok((s.count_rows("findings", None)?, s.count_approvals(Some("pending"))?))
            })?;
            self.counters.findings = findings as usize;
            self.counters.pending_approvals = pending as usize;
            self.stale = false;
        }
        self.counters.intercepted = svc.intercept_held_count();
        Ok(self.counters)
    }

    /// Re-reads everything from the store (for changes made by other processes, which publish nothing here).
    pub fn reload(&mut self, svc: &Service) -> Result<Counters> {
        self.counters = svc.counters()?;
        self.stale = false;
        Ok(self.counters)
    }
}

impl Service {
    /// A tracker initialised once from the store. Subscribe before creating it, so no event is missed.
    pub fn counter_tracker(&self) -> Result<CounterTracker> {
        Ok(CounterTracker { counters: self.counters()?, stale: false })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: i64) -> Event {
        Event::ExchangeRecorded { id, host: "h".into(), method: "GET".into(), status: Some(200) }
    }

    #[test]
    fn seq_increases_strictly_and_topics_follow_events() {
        let bus = Bus::new(16);
        let mut sub = bus.subscribe();
        assert_eq!(sub.latest_seq(), 0);
        bus.publish(ev(1), None);
        bus.publish(Event::AuditAppended { seq: 7 }, None);
        bus.publish(Event::InterceptQueued { id: 3 }, None);
        let got: Vec<_> = (0..3)
            .map(|_| match futures_util::FutureExt::now_or_never(sub.recv()).flatten() {
                Some(Delivery::Event(p)) => (p.seq, p.topic),
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(got, [(1, Topic::Exchanges), (2, Topic::Audit), (3, Topic::Intercept)]);
        assert_eq!(bus.subscribe().latest_seq(), 3);
    }

    #[test]
    fn a_lagging_subscriber_gets_exactly_one_resync_then_live_events() {
        let bus = Bus::new(4);
        let mut sub = bus.subscribe();
        for i in 1..=10 {
            bus.publish(ev(i), None);
        }
        let now = |s: &mut Subscription| futures_util::FutureExt::now_or_never(s.recv()).flatten();
        assert!(matches!(now(&mut sub), Some(Delivery::Resync { missed: 6 })));
        // The four newest are still buffered and come next, in order; no second resync.
        let seqs: Vec<u64> = (0..4)
            .map(|_| match now(&mut sub) {
                Some(Delivery::Event(p)) => p.seq,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(seqs, [7, 8, 9, 10]);
        assert!(now(&mut sub).is_none(), "drained");
        bus.publish(ev(11), None);
        assert!(matches!(now(&mut sub), Some(Delivery::Event(p)) if p.seq == 11));
    }

    fn progress(done: usize) -> Event {
        Event::ScanProgress { task: "t".into(), done, total: 10 }
    }

    fn dones(sub: &mut Subscription) -> Vec<usize> {
        let mut out = Vec::new();
        while let Some(Some(Delivery::Event(p))) = futures_util::FutureExt::now_or_never(sub.recv()) {
            if let Event::ScanProgress { done, .. } = p.event {
                out.push(done);
            }
        }
        out
    }

    #[test]
    fn progress_is_rate_limited_per_key_and_the_last_always_goes_out() {
        let bus = Bus::new(16);
        let mut sub = bus.subscribe();
        bus.publish_rated("a", progress(1), None, Rate::Limited);
        bus.publish_rated("a", progress(2), None, Rate::Limited);
        bus.publish_rated("b", progress(3), None, Rate::Limited);
        assert_eq!(dones(&mut sub), [1, 3], "one per window per key; another key has its own clock");
        bus.publish_rated("a", progress(4), None, Rate::Last);
        assert_eq!(dones(&mut sub), [4], "the final update is never dropped");
        bus.publish_rated("a", progress(5), None, Rate::Limited);
        assert_eq!(dones(&mut sub), [5], "and the key starts over");
    }

    #[tokio::test]
    async fn the_newest_held_update_goes_out_when_the_window_ends() {
        let bus = Bus::new(16);
        let mut sub = bus.subscribe();
        for i in 1..=5 {
            bus.publish_rated("a", progress(i), None, Rate::Limited);
        }
        let got = |p: Published| match p.event {
            Event::ScanProgress { done, .. } => done,
            e => panic!("{e:?}"),
        };
        let first = tokio::time::timeout(Duration::from_secs(5), sub.recv()).await.unwrap();
        assert!(matches!(first, Some(Delivery::Event(p)) if got(p.clone()) == 1));
        let second = tokio::time::timeout(Duration::from_secs(5), sub.recv()).await.unwrap();
        assert!(matches!(second, Some(Delivery::Event(p)) if got(p.clone()) == 5), "the newest, not every held one");
        assert!(dones(&mut sub).is_empty());
    }

    #[test]
    fn a_state_change_supersedes_held_progress() {
        let bus = Bus::new(16);
        let mut sub = bus.subscribe();
        bus.publish_rated("a", progress(1), None, Rate::Limited);
        bus.publish_rated("a", progress(2), None, Rate::Limited);
        bus.publish_rated("a", progress(3), None, Rate::Always);
        assert_eq!(dones(&mut sub), [1, 3]);
    }

    #[test]
    fn topics_round_trip() {
        for t in Topic::ALL {
            assert_eq!(Topic::parse(t.as_str()), Some(t));
        }
        assert_eq!(Topic::parse("counters"), None);
    }
}
