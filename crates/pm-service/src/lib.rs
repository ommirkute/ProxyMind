//! The service layer: the one place where actions happen (ADR-0005).
//!
//! REST, MCP, the CLI and the UI all call this crate. Every action is
//! checked by the policy gate and written to the audit log, whether it is
//! allowed, sent for approval or denied.

mod approvals;
mod assistant;
mod authz;
mod findings;
mod history;
mod identity;
mod intercept;
mod model;
mod network;
mod proof;
mod replay;
mod rules;
mod ws;

pub use assistant::{AssistantConfig, Chat, ChatSummary, ProviderKind};
pub use authz::{AuthzCheckRequest, AuthzReport};
pub use findings::{FindingUpdate, NewFinding};
pub use history::ExchangePage;
pub use identity::{IdentityCheck, IdentityInfo};
pub use intercept::InterceptState;
pub use model::{HypothesisUpdate, ModelFilter, NewHypothesis};
pub use network::{NETWORK_SETTING, load_network, sync_network};
pub use pm_store::ApprovalRow;
pub use proof::{ProofRequest, ProofResult};
pub use replay::{ReplayRequest, ReplayResult};
pub use rules::{RULES_SETTING, load_rules, sync_rules};
pub use ws::{WsMessageView, WsPage};

use parking_lot::Mutex;
use pm_ai::Redactor;
use pm_core::now_ms;
use pm_policy::{ActionRequest, Actor, Decision, Policy, RateLimiter, Verdict, audit};
use pm_replay::Sender;
use pm_store::Store;
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

pub use {
    pm_ai, pm_diff, pm_identity, pm_ledger, pm_model, pm_oast, pm_policy, pm_proof, pm_proxy, pm_replay, pm_store,
};

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("{0}")]
    Approval(String),
    #[error("approval {0} is not approved, was already used, or does not cover these parameters")]
    ApprovalMismatch(String),
    #[error("{0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("{0:#}")]
    Store(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, ServiceError>;

/// Outcome of asking to run an action.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Authorization {
    /// Go ahead.
    Allowed { reasons: Vec<String> },
    /// Waiting for a human. Retry with `run_approved` once approved.
    PendingApproval { approval_id: String, summary: String, reasons: Vec<String> },
    /// Refused.
    Denied { reasons: Vec<String> },
}

pub struct Service {
    policy: Policy,
    store: Mutex<Store>,
    sender: Sender,
    limiter: RateLimiter,
    redactor: Redactor,
    intercept: std::sync::OnceLock<std::sync::Arc<pm_proxy::InterceptQueue>>,
    rewriter: std::sync::OnceLock<std::sync::Arc<pm_proxy::Rewriter>>,
}

impl Service {
    pub fn new(store: Store, policy: Policy) -> Result<Self> {
        Self::with_sender(store, policy, Sender::new(false)?)
    }

    pub fn with_sender(store: Store, policy: Policy, sender: Sender) -> Result<Self> {
        let limits = policy.roe().limits;
        // Saved network settings apply from the start; a bad entry (say, a
        // moved certificate file) is reported but doesn't stop the project opening.
        if let Err(e) = network::sync_network(&store, sender.network()) {
            tracing::warn!("network settings not applied: {e}");
        }
        Ok(Self {
            limiter: RateLimiter::new(limits.max_rps_per_host, limits.max_concurrency),
            policy,
            store: Mutex::new(store),
            sender,
            redactor: Redactor::new(),
            intercept: std::sync::OnceLock::new(),
            rewriter: std::sync::OnceLock::new(),
        })
    }

    /// Whether content shown to this actor should have secrets replaced.
    /// Agents follow the ROE setting; humans see real values.
    pub fn redacts_for(&self, actor: &Actor) -> bool {
        actor.kind != pm_policy::ActorKind::Human && self.policy.roe().data.redact_before_llm
    }

    fn redactor_for(&self, actor: &Actor) -> Option<&Redactor> {
        self.redacts_for(actor).then_some(&self.redactor)
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Evaluates without recording anything. For "what would happen if"
    /// questions from the UI or CLI.
    pub fn dry_run(&self, req: &ActionRequest) -> Verdict {
        self.policy.evaluate(req, jiff::Timestamp::now())
    }

    fn audit(&self, actor: &str, action: &str, detail: Value, decision: &str) -> Result<()> {
        let mut store = self.store.lock();
        let prev = store.last_audit()?;
        let rec = audit::next_record(prev.as_ref(), now_ms(), actor, action, &detail, decision);
        store.append_audit(&rec)?;
        Ok(())
    }

    fn detail(req: &ActionRequest, params: &Value, verdict: &Verdict) -> Value {
        // Keep audit records small: large parameters (e.g. request bodies)
        // are cut, and the full hash is kept so they can still be matched.
        let text = params.to_string();
        let params = if text.len() > 4096 {
            let cut = text.char_indices().take_while(|(i, _)| *i < 4096).map(|(_, c)| c).collect::<String>();
            json!({ "preview": cut, "blake3": blake3_hex(&text) })
        } else {
            params.clone()
        };
        json!({
            "tier": req.tier,
            "target": req.target.as_ref().map(|t| format!("{}://{}:{}{}", t.scheme, t.host, t.port, t.path)),
            "summary": req.summary,
            "params": params,
            "reasons": verdict.reasons,
        })
    }

    /// Asks to run an action with these exact parameters. Always audited.
    pub fn authorize(&self, req: ActionRequest, params: &Value) -> Result<Authorization> {
        let verdict = self.policy.evaluate(&req, jiff::Timestamp::now());
        let detail = Self::detail(&req, params, &verdict);
        let actor = req.actor.id();
        let action = req.action.clone();
        let auth = match verdict.decision {
            Decision::Allow => Authorization::Allowed { reasons: verdict.reasons },
            Decision::Deny => Authorization::Denied { reasons: verdict.reasons },
            Decision::Approve => {
                let id = self.submit_approval(&req, params)?;
                Authorization::PendingApproval {
                    approval_id: id,
                    summary: req.summary.clone(),
                    reasons: verdict.reasons,
                }
            }
        };
        let decision = match &auth {
            Authorization::Allowed { .. } => "allow".to_string(),
            Authorization::Denied { .. } => "deny".to_string(),
            Authorization::PendingApproval { approval_id, .. } => format!("pending:{approval_id}"),
        };
        self.audit(&actor, &action, detail, &decision)?;
        Ok(auth)
    }
}

/// Counters the UI watches for live updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct Counters {
    pub exchanges: i64,
    pub last_exchange_id: i64,
    pub pending_approvals: usize,
    pub findings: usize,
    pub audit_records: usize,
    pub intercepted: usize,
}

impl Service {
    pub fn counters(&self) -> Result<Counters> {
        let store = self.store.lock();
        let last = store.search_exchanges(&pm_store::HistoryFilter { limit: Some(1), ..Default::default() })?;
        Ok(Counters {
            exchanges: store.count_exchanges()?,
            last_exchange_id: last.first().map_or(0, |e| e.id),
            pending_approvals: store.list_approvals(Some("pending"), 1000)?.len(),
            findings: store.rows("findings", None, 10_000)?.len(),
            audit_records: store.last_audit()?.map_or(0, |r| r.seq as usize),
            intercepted: self.intercept_held_count(),
        })
    }

    /// Audit records, newest first.
    pub fn audit_list(&self, limit: usize) -> Result<Vec<pm_store::AuditRecord>> {
        let mut r = self.store.lock().audit_records()?;
        r.reverse();
        r.truncate(limit);
        Ok(r)
    }

    pub fn audit_verify(&self) -> Result<usize> {
        verify_audit(&self.store.lock())
    }

    /// The raw bytes of an exchange as text, for humans (no redaction).
    pub fn exchange_raw(&self, id: i64) -> Result<pm_store::Exchange> {
        self.store.lock().get_exchange(id)?.ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))
    }
}

fn blake3_hex(s: &str) -> String {
    pm_policy::audit::content_hash(s.as_bytes())
}

/// Checks the audit chain of a project. Returns the number of records.
pub fn verify_audit(store: &Store) -> Result<usize> {
    let records = store.audit_records()?;
    audit::verify(&records).map_err(|e| ServiceError::Store(anyhow::anyhow!(e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pm_policy::{Roe, Target, Tier};

    const ROE: &str = r#"
version: 1
scope:
  include: ["https://app.example.com/"]
"#;

    fn service() -> Service {
        Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap()
    }

    fn req(actor: &str, tier: Tier, url: &str) -> ActionRequest {
        ActionRequest {
            actor: Actor::parse(actor).unwrap(),
            action: "replay_send".into(),
            tier,
            target: Some(Target::from_url(url).unwrap()),
            summary: format!("send to {url}"),
        }
    }

    #[test]
    fn approval_flow_is_enforced_and_audited() {
        let s = service();
        let params = json!({"raw": "POST /x HTTP/1.1"});
        let auth = s.authorize(req("agent:a", Tier::ActiveIntrusive, "https://app.example.com/x"), &params).unwrap();
        let Authorization::PendingApproval { approval_id, .. } = auth else { panic!("expected pending: {auth:?}") };

        // Not approved yet.
        assert!(s.run_approved(&approval_id, &params).is_err());
        // Agents can't approve.
        assert!(s.decide_approval(&approval_id, &Actor::parse("agent:a").unwrap(), true).is_err());
        s.decide_approval(&approval_id, &Actor::parse("human:alice").unwrap(), true).unwrap();
        // Changed parameters are not covered by the approval.
        assert!(s.run_approved(&approval_id, &json!({"raw": "DELETE /x HTTP/1.1"})).is_err());
        assert!(matches!(s.run_approved(&approval_id, &params).unwrap(), Authorization::Allowed { .. }));
        // Single use.
        assert!(s.run_approved(&approval_id, &params).is_err());

        let store = s.store.lock();
        // authorize, run(not approved), decide(rejected), decide(approved), run(mismatch), run(ok), run(used)
        assert_eq!(verify_audit(&store).unwrap(), 7);
    }

    #[test]
    fn denials_are_audited_too() {
        let s = service();
        let auth = s.authorize(req("agent:a", Tier::ActiveSafe, "https://evil.com/"), &json!({})).unwrap();
        assert!(matches!(auth, Authorization::Denied { .. }));
        let auth = s.authorize(req("agent:a", Tier::Destructive, "https://app.example.com/x"), &json!({})).unwrap();
        assert!(matches!(auth, Authorization::Denied { .. }));
        let records = s.store.lock().audit_records().unwrap();
        assert_eq!(records.iter().map(|r| r.decision.as_str()).collect::<Vec<_>>(), ["deny", "deny"]);
    }

    #[test]
    fn direct_file_tampering_is_detected() {
        let path = std::env::temp_dir().join(format!("pm-service-tamper-{}.pmproj", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let s = Service::new(Store::open(&path).unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap();
            for url in ["https://app.example.com/a", "https://evil.com/", "https://app.example.com/b"] {
                s.authorize(req("agent:a", Tier::ActiveSafe, url), &json!({})).unwrap();
            }
            assert_eq!(verify_audit(&s.store.lock()).unwrap(), 3);
        }
        // Someone edits the file outside ProxyMind: removes the guard
        // triggers and flips the denial to an allow.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("DROP TRIGGER audit_log_no_update; UPDATE audit_log SET decision = 'allow' WHERE seq = 2;")
            .unwrap();
        drop(conn);
        let err = verify_audit(&Store::open(&path).unwrap()).unwrap_err().to_string();
        assert!(err.contains("record 2"), "{err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn approvals_are_shared_between_processes() {
        let path = std::env::temp_dir().join(format!("pm-service-shared-{}.pmproj", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let open = || Service::new(Store::open(&path).unwrap(), Policy::new(Roe::parse(ROE).unwrap())).unwrap();
        let (mcp, cli) = (open(), open());
        let params = json!({"raw": "POST /x"});
        let auth = mcp.authorize(req("agent:a", Tier::ActiveIntrusive, "https://app.example.com/x"), &params).unwrap();
        let Authorization::PendingApproval { approval_id, .. } = auth else { panic!("{auth:?}") };

        assert_eq!(cli.approvals(Some("pending"), 10).unwrap()[0].id, approval_id);
        cli.decide_approval(&approval_id, &Actor::parse("human:omkar").unwrap(), true).unwrap();
        assert!(cli.decide_approval(&approval_id, &Actor::parse("human:other").unwrap(), false).is_err());
        assert!(matches!(mcp.run_approved(&approval_id, &params).unwrap(), Authorization::Allowed { .. }));
        assert_eq!(cli.approval(&approval_id).unwrap().unwrap().status, "used");
        drop((mcp, cli));
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
        }
    }
}
