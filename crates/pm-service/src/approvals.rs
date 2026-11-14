//! Human approvals, stored in the project so every process shares them.

use pm_core::now_ms;
use pm_policy::{ActionRequest, Actor, ActorKind, Decision, Target, Tier};
use pm_store::ApprovalRow;
use serde_json::{Value, json};

use crate::{Authorization, Result, Service, ServiceError};

/// An unguessable id (OS randomness, mixed with time and a counter in case
/// randomness is unavailable).
fn new_id() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut r = [0u8; 16];
    let _ = SystemRandom::new().fill(&mut r);
    let mut seed = format!("{}:{}:{n}:", now_ms(), std::process::id()).into_bytes();
    seed.extend_from_slice(&r);
    format!("apr_{}", &pm_policy::audit::content_hash(&seed)[..24])
}

fn tier_name(t: Tier) -> String {
    serde_json::to_value(t).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

impl Service {
    pub(crate) fn submit_approval(&self, req: &ActionRequest, params: &Value) -> Result<String> {
        let row = ApprovalRow {
            id: new_id(),
            created_ms: now_ms(),
            actor: req.actor.id(),
            action: req.action.clone(),
            tier: tier_name(req.tier),
            target: req.target.as_ref().map(|t| pm_core::url(&t.scheme, &t.host, t.port, &t.path)),
            summary: req.summary.clone(),
            params: params.to_string(),
            params_hash: pm_policy::params_hash(params),
            status: "pending".into(),
            decided_by: None,
            decided_ms: None,
        };
        self.store.write(|db| db.insert_approval(&row))?;
        Ok(row.id)
    }

    pub fn approval(&self, id: &str) -> Result<Option<ApprovalRow>> {
        Ok(self.store.read(|db| db.get_approval(id))?)
    }

    pub fn approvals(&self, status: Option<&str>, limit: usize) -> Result<Vec<ApprovalRow>> {
        Ok(self.store.read(|db| db.list_approvals(status, limit))?)
    }

    /// A human approves or denies a pending action. Audited, including refusals.
    pub fn decide_approval(&self, id: &str, approver: &Actor, approve: bool) -> Result<ApprovalRow> {
        let outcome = if approver.kind != ActorKind::Human {
            Err("only humans can approve actions".to_string())
        } else {
            let to = if approve { "approved" } else { "denied" };
            match self.store.write(|db| db.transition_approval(id, "pending", to, Some(&approver.id()), None, now_ms()))
            {
                Ok(true) => Ok(()),
                Ok(false) => Err(format!("approval {id} does not exist or was already decided")),
                Err(e) => Err(format!("{e:#}")),
            }
        };
        let decision = match (&outcome, approve) {
            (Ok(()), true) => "approved",
            (Ok(()), false) => "denied",
            (Err(_), _) => "rejected",
        };
        let error = outcome.as_ref().err().cloned();
        self.audit(&approver.id(), "approval_decide", json!({ "approval_id": id, "error": error }), decision)?;
        outcome.map_err(ServiceError::Approval)?;
        self.approval(id)?.ok_or_else(|| ServiceError::NotFound(id.into()))
    }

    /// Runs a previously approved action. The approval is used up, and scope
    /// and time windows are checked again because they may have changed.
    /// Only the actor who asked can use it, for the same action, and the
    /// parameters must match the approved ones exactly.
    pub fn run_approved(
        &self,
        actor: &Actor,
        action: &str,
        approval_id: &str,
        params: &Value,
    ) -> Result<Authorization> {
        if let Some(row) = self.approval(approval_id)?
            && (row.actor != actor.id() || row.action != action)
        {
            let detail = json!({ "approval_id": approval_id, "action": action, "approved_for": row.actor });
            self.audit(&actor.id(), "run_approved", detail, "rejected:other-actor-or-action")?;
            return Err(ServiceError::Approval(format!(
                "approval {approval_id} was given to {} for {}, not to {} for {action}",
                row.actor,
                row.action,
                actor.id()
            )));
        }
        let hash = pm_policy::params_hash(params);
        let consumed = self
            .store
            .write(|db| db.transition_approval(approval_id, "approved", "used", None, Some(&hash), now_ms()))?;
        let row = self.approval(approval_id)?;
        let Some(row) = row.filter(|_| consumed) else {
            let actor = self.approval(approval_id)?.map(|a| a.actor).unwrap_or_default();
            let detail = json!({ "approval_id": approval_id });
            self.audit(&actor, "run_approved", detail, "rejected:not-approved-used-or-params-changed")?;
            return Err(ServiceError::Approval(format!(
                "approval {approval_id} is not approved, was already used, or does not cover these parameters"
            )));
        };
        let req = ActionRequest {
            actor: Actor::parse(&row.actor).map_err(|e| ServiceError::Invalid(e.to_string()))?,
            action: row.action.clone(),
            tier: Tier::parse(&row.tier).unwrap_or(Tier::Destructive),
            target: row
                .target
                .as_deref()
                .map(Target::from_url)
                .transpose()
                .map_err(|e| ServiceError::Invalid(e.to_string()))?,
            summary: row.summary.clone(),
        };
        let verdict = self.policy.evaluate(&req, jiff::Timestamp::now());
        // The human approval satisfies the tier rule; only hard limits
        // (scope, dates, time windows, a tier set to deny) can still refuse.
        let auth = match verdict.decision {
            Decision::Deny => Authorization::Denied { reasons: verdict.reasons },
            _ => Authorization::Allowed {
                reasons: vec![format!("approved by {}", row.decided_by.clone().unwrap_or_default())],
            },
        };
        let decision = if matches!(auth, Authorization::Denied { .. }) { "deny" } else { "allow" };
        self.audit(&row.actor, &row.action, json!({ "approval_id": approval_id }), decision)?;
        Ok(auth)
    }
}
