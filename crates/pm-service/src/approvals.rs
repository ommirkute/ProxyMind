//! Human approvals, stored in the project so every process shares them.

use pm_core::now_ms;
use pm_policy::{ActionRequest, Actor, Decision, Target, Tier};
use pm_store::ApprovalRow;
use serde_json::{Value, json};

use crate::access::{Perm, Principal, Role};
use crate::{Authorization, Event, Result, Service, ServiceError};

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
        // Who asked, for the decision rules of a project server (ADR-0022 step 6).
        let who = self.principal_of(&req.actor);
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
            requested_user: who.user_id.clone(),
            requested_token: who.token_id.clone(),
            // The account's role, not the token's ceiling: "a tester's token" is one a tester owns.
            requested_role: self.access_control().then(|| who.account_role.unwrap_or(who.role).name().to_string()),
        };
        self.store.write(|db| db.insert_approval(&row))?;
        self.publish(Event::ApprovalRequested { id: row.id.clone() });
        Ok(row.id)
    }

    pub fn approval(&self, id: &str) -> Result<Option<ApprovalRow>> {
        Ok(self.store.read(|db| db.get_approval(id))?)
    }

    pub fn approvals(&self, status: Option<&str>, limit: usize) -> Result<Vec<ApprovalRow>> {
        Ok(self.store.read(|db| db.list_approvals(status, limit))?)
    }

    /// A human approves or denies a pending action. Audited, including refusals.
    ///
    /// On a project server (ADR-0022 step 6) who may decide what is: an owner any; a tester only what their own tokens
    /// (or they themselves) asked, and what other testers' tokens asked when the ROE says `approvals.testers_decide_team`;
    /// a viewer nothing; and with `approvals.require_other_person` nobody decides what they, or their own tokens, asked.
    /// Single-user mode has one person, who decides everything.
    pub fn decide_approval(&self, id: &str, approver: &Actor, approve: bool) -> Result<ApprovalRow> {
        let who = self.principal_of(approver);
        // Err(true, ..): refused by role (a 403 on a server); Err(false, ..): the approval's own state.
        let outcome: std::result::Result<(), (bool, String)> = match self.require(&who, Perm::ApprovalsDecide) {
            Err(e) => Err((
                true,
                if who.role == Role::Viewer { "viewers cannot approve actions".into() } else { e.to_string() },
            )),
            Ok(()) => self.may_decide(&who, id).map_err(|m| (true, m)).and_then(|()| {
                let to = if approve { "approved" } else { "denied" };
                match self
                    .store
                    .write(|db| db.transition_approval(id, "pending", to, Some(&approver.id()), None, now_ms()))
                {
                    Ok(true) => {
                        self.publish(Event::ApprovalDecided { id: id.to_string(), decision: to.to_string() });
                        Ok(())
                    }
                    Ok(false) => Err((false, format!("approval {id} does not exist or was already decided"))),
                    Err(e) => Err((false, format!("{e:#}"))),
                }
            }),
        };
        let decision = match (&outcome, approve) {
            (Ok(()), true) => "approved",
            (Ok(()), false) => "denied",
            (Err(_), _) => "rejected",
        };
        let error = outcome.as_ref().err().map(|(_, m)| m.clone());
        self.audit_principal(&who, "approval_decide", json!({ "approval_id": id, "error": error }), decision)?;
        outcome.map_err(|(by_role, m)| {
            if by_role && self.access_control() { ServiceError::Forbidden(m) } else { ServiceError::Approval(m) }
        })?;
        self.approval(id)?.ok_or_else(|| ServiceError::NotFound(id.into()))
    }

    /// The decision rules above, for one pending approval. `Ok` also when it does not exist (the transition says so).
    fn may_decide(&self, who: &Principal, id: &str) -> std::result::Result<(), String> {
        if !self.access_control() {
            return Ok(());
        }
        let Some(row) = self.approval(id).map_err(|e| e.to_string())? else { return Ok(()) };
        let rules = self.policy.roe().approvals;
        // Asked by this person: as themselves, or with one of their tokens.
        let own = row.actor == who.actor.id() || (who.user_id.is_some() && row.requested_user == who.user_id);
        if rules.require_other_person && own {
            return Err(format!(
                "{} may not decide approval {id}: the rules of engagement ask for a different owner than the one who asked (approvals.require_other_person)",
                who.actor.id()
            ));
        }
        match who.role {
            Role::Owner => Ok(()),
            Role::Tester if own => Ok(()),
            Role::Tester if rules.testers_decide_team && row.requested_role.as_deref() == Some("tester") => Ok(()),
            Role::Tester => Err(format!(
                "{} may not decide approval {id}: a tester decides only what their own tokens asked{}",
                who.actor.id(),
                if rules.testers_decide_team { " or another tester's tokens" } else { "" }
            )),
            Role::Viewer => Err(format!("{} may not decide approval {id}: viewers cannot approve", who.actor.id())),
        }
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
        if let Some(reason) = self.safe_mode_refusal(&req.actor) {
            self.audit(&row.actor, &row.action, json!({ "approval_id": approval_id, "reasons": [reason] }), "deny")?;
            return Ok(Authorization::Denied { reasons: vec![reason] });
        }
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
