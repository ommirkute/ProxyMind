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

/// Scan progress is published at most this often per task (the final update always is).
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
}

impl Topic {
    pub const ALL: [Topic; 9] = [
        Topic::Exchanges,
        Topic::Findings,
        Topic::Scans,
        Topic::Proofs,
        Topic::Intercept,
        Topic::Approvals,
        Topic::Audit,
        Topic::Collaborator,
        Topic::Websockets,
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
        }
    }
}

/// An event as published: with its `seq` and topic. The scope target (what an agent's scope check needs) is kept
/// out of the serialized form.
#[derive(Debug, Clone)]
pub struct Published {
    pub seq: u64,
    pub topic: Topic,
    pub event: Event,
    scope: Option<Target>,
}

pub(crate) struct Bus {
    tx: broadcast::Sender<Published>,
    seq: parking_lot::Mutex<u64>,
    progress: parking_lot::Mutex<HashMap<String, Instant>>,
}

impl Bus {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            tx: broadcast::channel(capacity).0,
            seq: parking_lot::Mutex::new(0),
            progress: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Never blocks. `scope` is the request target an agent's scope rules are checked against, if the event
    /// belongs to one.
    pub(crate) fn publish(&self, event: Event, scope: Option<Target>) {
        let mut seq = self.seq.lock();
        *seq += 1;
        // Err only means nobody is subscribed.
        let _ = self.tx.send(Published { seq: *seq, topic: event.topic(), event, scope });
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

    /// Whether a progress update for `task` should go out now (at most one per 250 ms, always when `last`).
    fn progress_due(&self, task: &str, last: bool) -> bool {
        let mut map = self.progress.lock();
        if last {
            map.remove(task);
            return true;
        }
        let now = Instant::now();
        match map.get(task) {
            Some(t) if now.duration_since(*t) < PROGRESS_EVERY => false,
            _ => {
                map.insert(task.to_string(), now);
                true
            }
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

    /// Publishes scan progress, rate-limited per task; `last` marks the final update, which always goes out.
    pub(crate) fn publish_scan_progress(&self, task: &str, done: usize, total: usize, last: bool) {
        if self.bus.progress_due(task, last) {
            self.publish(Event::ScanProgress { task: task.into(), done, total });
        }
    }

    /// Whether `actor` may read events of this topic. The intercept queue is for humans only, like its REST routes.
    pub fn may_read_topic(&self, actor: &Actor, topic: Topic) -> bool {
        topic != Topic::Intercept || actor.kind == ActorKind::Human
    }

    /// What `actor` may see of a published event, as JSON (`seq`, `topic`, `type` and the event's fields), or
    /// `None` when the event must not reach them. The single place for these rules (ADR-0018):
    /// - a topic the actor may not read is dropped;
    /// - for an agent, an event about a request target (`ExchangeRecorded`, `FindingChanged`, `WsMessageRecorded`) is dropped when the
    ///   target is out of scope, or when its scope could not be determined;
    /// - for an agent, strings pass through the redactor when the ROE asks for it (`json_for`), so a host
    ///   containing a secret is replaced by a placeholder. Humans see events as published.
    pub fn event_for(&self, actor: &Actor, p: &Published) -> Option<Value> {
        if !self.may_read_topic(actor, p.topic) {
            return None;
        }
        if actor.kind != ActorKind::Human {
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

    #[test]
    fn progress_is_rate_limited_per_task_and_the_last_always_goes_out() {
        let bus = Bus::new(4);
        assert!(bus.progress_due("a", false));
        assert!(!bus.progress_due("a", false));
        assert!(bus.progress_due("b", false), "another task has its own clock");
        assert!(bus.progress_due("a", true), "the final update is never dropped");
        assert!(bus.progress_due("a", false), "and the task starts over");
    }

    #[test]
    fn topics_round_trip() {
        for t in Topic::ALL {
            assert_eq!(Topic::parse(t.as_str()), Some(t));
        }
        assert_eq!(Topic::parse("counters"), None);
    }
}
