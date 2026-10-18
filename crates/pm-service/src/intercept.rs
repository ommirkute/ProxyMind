//! The intercept queue, as seen by humans through the API/UI.

use std::sync::Arc;

use pm_policy::{Actor, ActorKind, Policy, Target};
use pm_proxy::intercept::{Decision, Held, Kind};
use pm_proxy::{InterceptQueue, InterceptSettings};
use serde::Serialize;
use serde_json::json;

use crate::{Result, Service, ServiceError};

#[derive(Debug, Clone, Serialize)]
pub struct InterceptState {
    pub attached: bool,
    pub settings: InterceptSettings,
    pub held: Vec<Held>,
}

impl Service {
    /// Connects the proxy's intercept queue. The queue's "in scope only"
    /// option uses this project's rules of engagement.
    pub fn attach_intercept(&self, q: Arc<InterceptQueue>) {
        let policy = Arc::new(Policy::new(self.policy.roe().clone()));
        q.set_scope(Arc::new(move |scheme, host, port, path| {
            Target::from_parts(scheme, host, port, path).is_ok_and(|t| policy.scope_check(&t).is_ok())
        }));
        let _ = self.intercept.set(q);
    }

    fn queue(&self) -> Result<&Arc<InterceptQueue>> {
        self.intercept.get().ok_or_else(|| {
            ServiceError::Invalid("interception needs the proxy running in this process (proxymind ui)".into())
        })
    }

    fn human_only(actor: &Actor) -> Result<()> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only humans can use the intercept queue".into()));
        }
        Ok(())
    }

    pub fn intercept_state(&self) -> InterceptState {
        match self.intercept.get() {
            Some(q) => InterceptState { attached: true, settings: q.settings(), held: q.held() },
            None => InterceptState { attached: false, settings: InterceptSettings::default(), held: vec![] },
        }
    }

    pub fn intercept_held_count(&self) -> usize {
        self.intercept.get().map_or(0, |q| q.len())
    }

    pub fn intercept_settings(&self, actor: &Actor, s: InterceptSettings) -> Result<InterceptState> {
        Self::human_only(actor)?;
        self.queue()?.set_settings(s.clone());
        self.audit(&actor.id(), "intercept_settings", json!(s), "allow")?;
        Ok(self.intercept_state())
    }

    /// Forwards a held message, optionally edited. Edits and their hashes
    /// are audited; plain forwards are not (they would flood the log).
    pub fn intercept_forward(
        &self,
        actor: &Actor,
        id: u64,
        raw: Option<String>,
        fix_content_length: bool,
    ) -> Result<()> {
        Self::human_only(actor)?;
        let q = self.queue()?;
        let held = q.get(id).ok_or_else(|| ServiceError::NotFound(format!("intercepted message {id}")))?;
        let decision = match raw {
            Some(text) if text != held.raw => {
                if !held.editable {
                    return Err(ServiceError::Invalid("this message is binary and can't be edited as text".into()));
                }
                // WebSocket payloads are sent exactly as typed; HTTP heads
                // get CRLF line endings.
                let mut bytes = if held.kind.is_websocket() {
                    text.as_bytes().to_vec()
                } else {
                    crate::replay::crlf_head(text.as_bytes())
                };
                if fix_content_length && held.kind == Kind::Request {
                    bytes = pm_http::fix_content_length(&bytes);
                }
                let preview: String = text.chars().take(2000).collect();
                self.audit(
                    &actor.id(),
                    "intercept_edit",
                    json!({
                        "kind": held.kind, "url": pm_core::url(&held.scheme, &held.host, held.port, &held.path),
                        "original_blake3": pm_policy::audit::content_hash(held.raw.as_bytes()),
                        "edited_blake3": pm_policy::audit::content_hash(&bytes), "edited_preview": preview,
                    }),
                    "allow",
                )?;
                Decision::Forward(Some(bytes))
            }
            _ => Decision::Forward(None),
        };
        if !q.decide(id, decision) {
            return Err(ServiceError::NotFound(format!("intercepted message {id} (already handled)")));
        }
        Ok(())
    }

    pub fn intercept_drop(&self, actor: &Actor, id: u64) -> Result<()> {
        Self::human_only(actor)?;
        let q = self.queue()?;
        let held = q.get(id).ok_or_else(|| ServiceError::NotFound(format!("intercepted message {id}")))?;
        q.decide(id, Decision::Drop);
        self.audit(
            &actor.id(),
            "intercept_drop",
            json!({ "kind": held.kind, "url": pm_core::url(&held.scheme, &held.host, held.port, &held.path) }),
            "allow",
        )?;
        Ok(())
    }

    pub fn intercept_forward_all(&self, actor: &Actor) -> Result<usize> {
        Self::human_only(actor)?;
        Ok(self.queue()?.forward_all())
    }
}
