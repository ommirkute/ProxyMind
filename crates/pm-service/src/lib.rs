//! The service layer: the one place where actions happen (ADR-0005).
//!
//! REST, MCP, the CLI and the UI all call this crate. Every action is
//! checked by the policy gate and written to the audit log, whether it is
//! allowed, sent for approval or denied.

use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use pm_policy::{ActionRequest, Actor, Approval, ApprovalError, ApprovalQueue, Decision, Policy, Verdict, audit};
use pm_store::Store;
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

pub use pm_policy;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    Approval(#[from] ApprovalError),
    #[error("approval {0} is not approved, was already used, or does not cover these parameters")]
    ApprovalMismatch(String),
    #[error("storage: {0:#}")]
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
    approvals: ApprovalQueue,
    store: Mutex<Store>,
}

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

impl Service {
    pub fn new(store: Store, policy: Policy) -> Self {
        Self { policy, approvals: ApprovalQueue::new(), store: Mutex::new(store) }
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
                let summary = req.summary.clone();
                let a = self.approvals.submit(req, params);
                Authorization::PendingApproval { approval_id: a.id, summary, reasons: verdict.reasons }
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

    /// A human approves or denies a pending action. Audited.
    pub fn decide_approval(&self, id: &str, approver: &Actor, approve: bool) -> Result<Approval> {
        let result = self.approvals.decide(id, approver, approve);
        let decision = match &result {
            Ok(_) if approve => "approved",
            Ok(_) => "denied",
            Err(_) => "rejected",
        };
        let err = result.as_ref().err().map(ToString::to_string);
        self.audit(&approver.id(), "approval_decide", json!({ "approval_id": id, "error": err }), decision)?;
        Ok(result?)
    }

    pub fn approval(&self, id: &str) -> Option<Approval> {
        self.approvals.get(id)
    }

    pub fn pending_approvals(&self) -> Vec<Approval> {
        self.approvals.pending()
    }

    /// Runs a previously approved action. Scope and time windows are checked
    /// again, because they may have changed since the request was made.
    /// The parameters must match the approved ones exactly.
    pub fn run_approved(&self, approval_id: &str, params: &Value) -> Result<Authorization> {
        let Some(a) = self.approvals.consume(approval_id, params) else {
            let actor = self.approvals.get(approval_id).map(|a| a.request.actor.id()).unwrap_or_default();
            let detail = json!({ "approval_id": approval_id });
            self.audit(&actor, "run_approved", detail, "rejected:not-approved-used-or-params-changed")?;
            return Err(ServiceError::ApprovalMismatch(approval_id.into()));
        };
        let mut verdict = self.policy.evaluate(&a.request, jiff::Timestamp::now());
        // The tier rule was satisfied by the human approval; only hard
        // limits (scope, time) can still deny it.
        if verdict.decision == Decision::Approve {
            verdict.decision = Decision::Allow;
        }
        let detail = json!({ "approval_id": approval_id, "reasons": verdict.reasons });
        let auth = match verdict.decision {
            Decision::Deny => Authorization::Denied { reasons: verdict.reasons },
            _ => Authorization::Allowed { reasons: vec![format!("approved by {}", a.decided_by.unwrap_or_default())] },
        };
        let decision = if matches!(auth, Authorization::Denied { .. }) { "deny" } else { "allow" };
        self.audit(&a.request.actor.id(), &a.request.action, detail, decision)?;
        Ok(auth)
    }
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
        Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(ROE).unwrap()))
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
            let s = Service::new(Store::open(&path).unwrap(), Policy::new(Roe::parse(ROE).unwrap()));
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
}
