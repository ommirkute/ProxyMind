//! Fuzzer through the policy gate: one approval covers the whole attack
//! (the template, every payload set and the mode), then each request is
//! sent with the usual rate limits, identity handling and recording.
//!
//! Attacks run in the background (`fuzzer_start`): the UI polls their
//! progress and can pause, resume or cancel them. `fuzzer_run` runs one
//! to the end and returns everything (for agents and the CLI).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use futures_util::StreamExt;
use pm_fuzz::{Extract, Grep, Mode, Observed, PayloadSet, Template};
use pm_policy::{Actor, ActorKind, Tier};
use pm_replay::Endpoint;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::replay::{Outgoing, parse_url_endpoint};
use crate::{Authorization, Result, Service, ServiceError};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct FuzzerRequest {
    /// Recorded exchange whose target to use (scheme, host, port).
    pub exchange_id: Option<i64>,
    /// Target as scheme://host[:port], when not using exchange_id.
    pub url: Option<String>,
    /// The request with positions marked §like this§.
    pub raw: String,
    pub mode: Mode,
    /// One set for one_at_a_time and same everywhere; one per position otherwise.
    pub payload_sets: Vec<PayloadSet>,
    /// Report responses containing any of these (case-insensitive).
    pub grep: Vec<String>,
    /// Treat grep terms as regular expressions.
    pub grep_regex: bool,
    /// Values to pull out of each response into their own columns.
    pub extract: Vec<Extract>,
    /// Requests in flight at once (1-20, default 1). The rules of
    /// engagement's rate limits still apply.
    pub concurrency: Option<usize>,
    /// Pause before each request, in milliseconds (0-60000).
    pub throttle_ms: Option<u64>,
    pub identity: Option<String>,
    pub fix_content_length: Option<bool>,
    pub hypothesis_id: Option<i64>,
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzerRow {
    /// Position in the attack (0-based; the baseline has none).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    pub exchange_id: i64,
    /// Payload per position; null keeps the original value.
    pub payloads: Vec<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub body_length: usize,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub matches: Vec<String>,
    /// One entry per extract rule (null when not found).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extracted: Vec<Option<String>>,
    pub reflected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FuzzerResult {
    Done {
        /// The request with the original values.
        baseline: FuzzerRow,
        results: Vec<FuzzerRow>,
        /// Results that stand out, with why; `index` points into results.
        anomalies: Vec<pm_fuzz::Anomaly>,
    },
    PendingApproval {
        approval_id: String,
        summary: String,
        reasons: Vec<String>,
    },
    Denied {
        reasons: Vec<String>,
    },
}

/// What starting a background attack did.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum FuzzerStart {
    Started { attack_id: String, total: usize },
    PendingApproval { approval_id: String, summary: String, reasons: Vec<String> },
    Denied { reasons: Vec<String> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackStatus {
    Running,
    Paused,
    Cancelled,
    Done,
    Failed,
}

/// An attack's progress and results so far.
#[derive(Debug, Clone, Serialize)]
pub struct AttackView {
    pub attack_id: String,
    pub summary: String,
    pub actor: String,
    pub created_ms: i64,
    pub status: AttackStatus,
    pub total: usize,
    pub done: usize,
    /// Column names for `extracted` values.
    pub extract_columns: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<FuzzerRow>,
    /// Results in completion order, from `from` on.
    pub rows: Vec<FuzzerRow>,
    /// Over all results so far; `index` is a row's `index`.
    pub anomalies: Vec<pm_fuzz::Anomaly>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackSummary {
    pub attack_id: String,
    pub summary: String,
    pub actor: String,
    pub created_ms: i64,
    pub status: AttackStatus,
    pub total: usize,
    pub done: usize,
}

struct AttackState {
    status: AttackStatus,
    baseline: Option<FuzzerRow>,
    rows: Vec<FuzzerRow>,
    error: Option<String>,
}

pub(crate) struct Attack {
    id: String,
    summary: String,
    actor: String,
    created_ms: i64,
    total: usize,
    extract_columns: Vec<String>,
    state: parking_lot::Mutex<AttackState>,
    paused: AtomicBool,
    cancelled: AtomicBool,
}

/// Attacks kept in memory (their requests are in history either way).
const KEEP_ATTACKS: usize = 20;

/// Everything an approved attack needs to run.
struct Prepared {
    baseline: Outgoing,
    planned: Vec<(pm_fuzz::Planned, Outgoing)>,
    positions: usize,
    identity: Option<String>,
    fix_cl: bool,
    grep: Grep,
    extract: Vec<(Extract, Option<regex::Regex>)>,
    concurrency: usize,
    throttle_ms: u64,
}

fn invalid(e: impl ToString) -> ServiceError {
    ServiceError::Invalid(e.to_string())
}

impl Service {
    /// Builds the attack and asks the gate. Fuzzing is at least
    /// active-intrusive, and the attack takes the highest tier any of its
    /// requests calls for.
    fn fuzzer_prepare(
        &self,
        actor: &Actor,
        req: &FuzzerRequest,
    ) -> Result<std::result::Result<Prepared, FuzzerResult>> {
        let template = Template::parse(&req.raw).map_err(invalid)?;
        let sets: Vec<Vec<String>> =
            req.payload_sets.iter().map(PayloadSet::expand).collect::<std::result::Result<_, _>>().map_err(invalid)?;
        let planned = pm_fuzz::plan(&template, req.mode, &sets).map_err(invalid)?;
        let grep = Grep::new(&req.grep, req.grep_regex).map_err(invalid)?;
        let extract =
            req.extract.iter().map(|e| Ok((e.clone(), e.compile().map_err(invalid)?))).collect::<Result<Vec<_>>>()?;
        let endpoint: Endpoint = match (req.exchange_id, &req.url) {
            (Some(id), _) => {
                let ex = self
                    .store
                    .lock()
                    .get_exchange(id)?
                    .ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
                Endpoint::new(&ex.summary.scheme, &ex.summary.host, ex.summary.port)
            }
            (None, Some(u)) => parse_url_endpoint(u)?,
            _ => return Err(invalid("give exchange_id or url for the target")),
        };
        if let Some(name) = &req.identity {
            self.load_identity(name)?;
        }
        let mut baseline = self.outgoing(endpoint.clone(), template.baseline().as_bytes(), true)?;
        baseline.hypothesis_id = req.hypothesis_id;
        let mut outs = Vec::with_capacity(planned.len());
        let mut tier = Tier::ActiveIntrusive;
        for p in planned {
            let mut out = self.outgoing(endpoint.clone(), p.raw.as_bytes(), true)?;
            out.hypothesis_id = req.hypothesis_id;
            tier = tier.max(Tier::for_http_request(&out.raw).0);
            outs.push((p, out));
        }
        let fix_cl = req.fix_content_length.unwrap_or(true);
        // The approval binds the whole attack, not just the baseline.
        let extra = json!({
            "fuzzer": { "template": req.raw, "mode": req.mode, "payload_sets": req.payload_sets,
                          "grep": req.grep, "requests": outs.len() }
        });
        match self.gate_send_with(
            actor,
            "fuzzer_run",
            &baseline,
            req.identity.as_deref(),
            fix_cl,
            req.approval_id.as_deref(),
            Some(tier),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(Err(FuzzerResult::Denied { reasons })),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(Err(FuzzerResult::PendingApproval {
                    approval_id,
                    summary: format!("fuzzer ({}, {} requests): {summary}", req.mode.label(), outs.len()),
                    reasons,
                }));
            }
        }
        Ok(Ok(Prepared {
            baseline,
            planned: outs,
            positions: template.positions(),
            identity: req.identity.clone(),
            fix_cl,
            grep,
            extract,
            concurrency: req.concurrency.unwrap_or(1).clamp(1, 20),
            throttle_ms: req.throttle_ms.unwrap_or(0).min(60_000),
        }))
    }

    fn new_attack(&self, actor: &Actor, req: &FuzzerRequest, total: usize) -> Arc<Attack> {
        let first = req.raw.lines().next().unwrap_or_default().replace(pm_fuzz::MARKER, "");
        let a = Arc::new(Attack {
            id: pm_oast::new_token()[..12].to_string(),
            summary: format!(
                "{} · {} · {total} requests",
                first.chars().take(120).collect::<String>(),
                req.mode.label()
            ),
            actor: actor.id(),
            created_ms: pm_core::now_ms(),
            total,
            extract_columns: req
                .extract
                .iter()
                .map(|e| match (&e.regex, &e.start) {
                    (Some(r), _) if !r.is_empty() => format!("/{r}/"),
                    (_, Some(s)) => format!("after {s}"),
                    _ => "extract".into(),
                })
                .collect(),
            state: parking_lot::Mutex::new(AttackState {
                status: AttackStatus::Running,
                baseline: None,
                rows: Vec::new(),
                error: None,
            }),
            paused: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
        });
        let mut list = self.attacks.lock();
        list.push(a.clone());
        // Forget the oldest finished attacks beyond the limit.
        while list.len() > KEEP_ATTACKS {
            match list.iter().position(|x| x.state.lock().status != AttackStatus::Running) {
                Some(i) => {
                    list.remove(i);
                }
                None => break,
            }
        }
        a
    }

    async fn fuzzer_execute(&self, actor: &Actor, p: Prepared, a: &Attack) {
        let send = |out: Outgoing| {
            let identity = p.identity.clone();
            async move { self.send_as(actor, &out, identity.as_deref(), p.fix_cl, "fuzzer").await.map(|(s, _)| s) }
        };
        match send(p.baseline.clone()).await {
            Ok(b) => a.state.lock().baseline = Some(row(b, None, vec![None; p.positions], &p.grep, &p.extract)),
            Err(e) => {
                let mut st = a.state.lock();
                st.status = AttackStatus::Failed;
                st.error = Some(e.to_string());
                return;
            }
        }
        let jobs = p.planned.into_iter().enumerate().map(|(i, (plan, out))| {
            let send = &send;
            async move {
                // Wait while paused; stop when cancelled.
                while a.paused.load(Ordering::Relaxed) && !a.cancelled.load(Ordering::Relaxed) {
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                }
                if a.cancelled.load(Ordering::Relaxed) {
                    return None;
                }
                if p.throttle_ms > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(p.throttle_ms)).await;
                }
                Some((i, plan.payloads, send(out).await))
            }
        });
        let mut stream = futures_util::stream::iter(jobs).buffer_unordered(p.concurrency);
        while let Some(r) = stream.next().await {
            let Some((i, payloads, sent)) = r else { continue };
            let mut st = a.state.lock();
            match sent {
                Ok(s) => st.rows.push(row(s, Some(i), payloads, &p.grep, &p.extract)),
                Err(e) => {
                    // The gate or the target refused mid-attack (rate limit window,
                    // scope change): stop and say why.
                    st.status = AttackStatus::Failed;
                    st.error = Some(e.to_string());
                    a.cancelled.store(true, Ordering::Relaxed);
                }
            }
        }
        let mut st = a.state.lock();
        if matches!(st.status, AttackStatus::Running | AttackStatus::Paused) {
            st.status = if a.cancelled.load(Ordering::Relaxed) { AttackStatus::Cancelled } else { AttackStatus::Done };
        }
    }

    /// Runs an attack to the end and returns every result.
    pub async fn fuzzer_run(&self, actor: &Actor, req: FuzzerRequest) -> Result<FuzzerResult> {
        let p = match self.fuzzer_prepare(actor, &req)? {
            Ok(p) => p,
            Err(outcome) => return Ok(outcome),
        };
        let a = self.new_attack(actor, &req, p.planned.len());
        self.fuzzer_execute(actor, p, &a).await;
        let st = a.state.lock();
        if let Some(e) = &st.error {
            return Err(ServiceError::Invalid(format!("the attack stopped: {e}")));
        }
        let mut results = st.rows.clone();
        results.sort_by_key(|r| r.index);
        let baseline = st.baseline.clone().ok_or_else(|| invalid("no baseline"))?;
        let anomalies = anomalies_of(Some(&baseline), &results);
        Ok(FuzzerResult::Done { baseline, results, anomalies })
    }

    /// Starts an attack in the background; poll it with `fuzzer_status`.
    pub fn fuzzer_start(self: &Arc<Self>, actor: &Actor, req: FuzzerRequest) -> Result<FuzzerStart> {
        let p = match self.fuzzer_prepare(actor, &req)? {
            Ok(p) => p,
            Err(FuzzerResult::PendingApproval { approval_id, summary, reasons }) => {
                return Ok(FuzzerStart::PendingApproval { approval_id, summary, reasons });
            }
            Err(FuzzerResult::Denied { reasons }) => return Ok(FuzzerStart::Denied { reasons }),
            Err(FuzzerResult::Done { .. }) => unreachable!("prepare never runs the attack"),
        };
        let total = p.planned.len();
        let a = self.new_attack(actor, &req, total);
        let (svc, actor2, a2) = (self.clone(), actor.clone(), a.clone());
        tokio::spawn(async move { svc.fuzzer_execute(&actor2, p, &a2).await });
        Ok(FuzzerStart::Started { attack_id: a.id.clone(), total })
    }

    fn attack(&self, actor: &Actor, id: &str) -> Result<Arc<Attack>> {
        let a = self
            .attacks
            .lock()
            .iter()
            .find(|a| a.id == id)
            .cloned()
            .ok_or_else(|| ServiceError::NotFound(format!("attack {id}")))?;
        // People see every attack; agents and plugins only their own.
        if actor.kind != ActorKind::Human && a.actor != actor.id() {
            return Err(ServiceError::NotFound(format!("attack {id}")));
        }
        Ok(a)
    }

    /// An attack's progress, with results from `from` on (completion order).
    pub fn fuzzer_status(&self, actor: &Actor, id: &str, from: usize) -> Result<AttackView> {
        let a = self.attack(actor, id)?;
        let st = a.state.lock();
        Ok(AttackView {
            attack_id: a.id.clone(),
            summary: a.summary.clone(),
            actor: a.actor.clone(),
            created_ms: a.created_ms,
            status: st.status,
            total: a.total,
            done: st.rows.len(),
            extract_columns: a.extract_columns.clone(),
            baseline: st.baseline.clone(),
            rows: st.rows.iter().skip(from).cloned().collect(),
            anomalies: anomalies_of(st.baseline.as_ref(), &st.rows),
            error: st.error.clone(),
        })
    }

    /// pause, resume or cancel.
    pub fn fuzzer_control(&self, actor: &Actor, id: &str, action: &str) -> Result<AttackStatus> {
        let a = self.attack(actor, id)?;
        let mut st = a.state.lock();
        if !matches!(st.status, AttackStatus::Running | AttackStatus::Paused) {
            return Ok(st.status);
        }
        match action {
            "pause" => {
                a.paused.store(true, Ordering::Relaxed);
                st.status = AttackStatus::Paused;
            }
            "resume" => {
                a.paused.store(false, Ordering::Relaxed);
                st.status = AttackStatus::Running;
            }
            "cancel" => {
                a.cancelled.store(true, Ordering::Relaxed);
                a.paused.store(false, Ordering::Relaxed);
                st.status = AttackStatus::Cancelled;
            }
            other => return Err(invalid(format!("unknown action {other}; use pause, resume or cancel"))),
        }
        Ok(st.status)
    }

    /// Recent attacks, newest first.
    pub fn fuzzer_list(&self, actor: &Actor) -> Vec<AttackSummary> {
        self.attacks
            .lock()
            .iter()
            .rev()
            .filter(|a| actor.kind == ActorKind::Human || a.actor == actor.id())
            .map(|a| {
                let st = a.state.lock();
                AttackSummary {
                    attack_id: a.id.clone(),
                    summary: a.summary.clone(),
                    actor: a.actor.clone(),
                    created_ms: a.created_ms,
                    status: st.status,
                    total: a.total,
                    done: st.rows.len(),
                }
            })
            .collect()
    }
}

/// Anomalies over rows in any order; `index` in the result is each row's attack index.
fn anomalies_of(baseline: Option<&FuzzerRow>, rows: &[FuzzerRow]) -> Vec<pm_fuzz::Anomaly> {
    let observe = |r: &FuzzerRow| Observed {
        status: r.status,
        body_length: r.body_length,
        elapsed_ms: r.elapsed_ms,
        matches: r.matches.clone(),
        reflected: r.reflected,
    };
    let observed: Vec<Observed> = rows.iter().map(observe).collect();
    let base = baseline.map(observe);
    pm_fuzz::anomalies(base.as_ref(), &observed)
        .into_iter()
        .map(|mut an| {
            an.index = rows[an.index].index.unwrap_or(an.index);
            an
        })
        .collect()
}

fn row(
    sent: crate::replay::Sent,
    index: Option<usize>,
    payloads: Vec<Option<String>>,
    grep: &Grep,
    extract: &[(Extract, Option<regex::Regex>)],
) -> FuzzerRow {
    let (body, text) = match &sent.response {
        Some(r) => {
            let (head, body) = pm_http::split_message(r);
            let decoded = match pm_http::parse_response_head(head) {
                Ok(h) => pm_ai::body::decode(&h.headers, body).bytes,
                Err(_) => body.to_vec(),
            };
            // Head and decoded body: extract rules may look at headers too.
            let mut t = String::from_utf8_lossy(head).into_owned();
            t.push_str(&String::from_utf8_lossy(&decoded));
            (body.len(), t)
        }
        None => (0, String::new()),
    };
    let lower = text.to_lowercase();
    let matches = grep.matches(&text, &lower);
    let extracted = extract.iter().map(|(e, re)| e.find(re.as_ref(), &text)).collect();
    // Reflection matters for payloads with markup or quotes (or long unique
    // strings); an id echoed back in JSON is not interesting.
    let reflected = payloads.iter().flatten().any(|p| {
        let plain = pm_policy::payload::normalise(p);
        let telling = plain.len() >= 8 || plain.chars().any(|c| !c.is_alphanumeric() && c != ' ');
        telling && plain.len() >= 3 && (lower.contains(&p.to_lowercase()) || lower.contains(&plain))
    });
    FuzzerRow {
        index,
        exchange_id: sent.exchange_id,
        payloads,
        status: sent.status,
        body_length: body,
        elapsed_ms: sent.elapsed_ms,
        matches,
        extracted,
        reflected,
        error: sent.error,
    }
}
