//! Collaborator: out-of-band payloads to paste anywhere by hand, and the
//! interactions they cause (HTTP requests and DNS lookups reaching the OAST
//! listener). Scanner and proof payloads use the same listener; these are
//! for manual testing.
//!
//! Payloads are recorded in the project with who made them, so the
//! interactions list can say which payload fired. Interactions come from
//! the network and are untrusted content.

use std::net::SocketAddr;
use std::sync::Arc;

use pm_core::now_ms;
use pm_policy::{Actor, ActorKind};
use serde::Serialize;
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError};

const MAX_PAYLOADS: u64 = 10_000;

#[derive(Debug, Clone, Serialize)]
pub struct CollaboratorStatus {
    /// Where payloads call back (`oast_public_url`), if set.
    pub public_url: Option<String>,
    /// The DNS zone delegated to the OAST listener, if set.
    pub dns_domain: Option<String>,
    /// The address this process listens on, if it runs the listener.
    pub listening: Option<String>,
    pub payloads: u64,
    pub interactions: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CollaboratorPayload {
    pub token: String,
    pub note: String,
    pub created_ms: i64,
    pub actor: String,
    /// `<public url>/<token>` when a public URL is set.
    pub http_url: Option<String>,
    /// `<token>.<dns domain>` when a DNS zone is set.
    pub dns_name: Option<String>,
    /// Interactions seen for this payload so far.
    pub interactions: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CollaboratorInteraction {
    pub id: i64,
    pub token: String,
    /// "http" or "dns".
    pub protocol: String,
    pub remote: String,
    pub method: String,
    pub path: String,
    pub ts_ms: i64,
    /// The request head (HTTP) or a description of the lookup (DNS).
    pub raw: String,
    /// The payload's note, when the token is one of ours.
    pub note: Option<String>,
}

fn s(row: &serde_json::Map<String, Value>, k: &str) -> String {
    row.get(k).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn i(row: &serde_json::Map<String, Value>, k: &str) -> i64 {
    row.get(k).and_then(Value::as_i64).unwrap_or_default()
}

impl Service {
    fn oast_settings(&self) -> Result<(Option<String>, Option<String>)> {
        let st = self.store.lock();
        Ok((st.get_setting(crate::proof::OAST_SETTING)?, st.get_setting(crate::proof::OAST_DNS_SETTING)?))
    }

    pub fn collaborator_status(&self) -> Result<CollaboratorStatus> {
        let (public_url, dns_domain) = self.oast_settings()?;
        let st = self.store.lock();
        Ok(CollaboratorStatus {
            public_url,
            dns_domain,
            listening: self.oast_listening.get().map(ToString::to_string),
            payloads: st.count_rows("oast_payloads", None)?,
            interactions: st.count_rows("oast_interactions", None)?,
        })
    }

    /// Starts the HTTP callback listener in this process (once). Targets
    /// must be able to reach `public_url` (default `http://<listen>`).
    /// People only: it opens a port.
    pub async fn collaborator_listen(
        self: &Arc<Self>,
        actor: &Actor,
        listen: SocketAddr,
        public_url: Option<String>,
    ) -> Result<CollaboratorStatus> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only people can start the callback listener (it opens a port)".into()));
        }
        if self.oast_listening.get().is_some() {
            return Err(ServiceError::Invalid("the callback listener already runs in this process".into()));
        }
        let l = tokio::net::TcpListener::bind(listen)
            .await
            .map_err(|e| ServiceError::Invalid(format!("can't listen on {listen}: {e}")))?;
        let bound = l.local_addr().map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let public = public_url.filter(|u| !u.trim().is_empty()).unwrap_or_else(|| format!("http://{bound}"));
        self.set_oast_public_url(public.trim())?;
        let _ = self.oast_listening.set(bound);
        let me = self.clone();
        tokio::spawn(pm_oast::serve(l, move |i| {
            if let Err(e) = me.record_oast(&i) {
                tracing::warn!("could not record a callback: {e}");
            }
        }));
        self.audit(
            &actor.id(),
            "collaborator_listen",
            json!({ "listen": bound.to_string(), "public_url": public }),
            "allow",
        )?;
        self.collaborator_status()
    }

    /// Hands out a new payload. It sends nothing.
    pub fn collaborator_payload(&self, actor: &Actor, note: &str) -> Result<CollaboratorPayload> {
        let (public_url, dns_domain) = self.oast_settings()?;
        if public_url.is_none() && dns_domain.is_none() {
            return Err(ServiceError::Invalid(
                "no callback listener is set up: start one on the Collaborator page, or run `proxymind oast-server`"
                    .into(),
            ));
        }
        if self.store.lock().count_rows("oast_payloads", None)? >= MAX_PAYLOADS {
            return Err(ServiceError::Invalid(format!("at most {MAX_PAYLOADS} payloads per project")));
        }
        let token = pm_oast::new_token();
        let note: String = note.chars().filter(|c| !c.is_control()).take(200).collect();
        let mut row = serde_json::Map::new();
        row.insert("token".into(), json!(token));
        row.insert("note".into(), json!(note));
        row.insert("actor".into(), json!(actor.id()));
        row.insert("created_ms".into(), json!(now_ms()));
        self.store.lock().insert_row("oast_payloads", &row)?;
        self.audit(&actor.id(), "collaborator_payload", json!({ "token": token, "note": note }), "allow")?;
        Ok(CollaboratorPayload {
            http_url: public_url.map(|u| format!("{}/{token}", u.trim_end_matches('/'))),
            dns_name: dns_domain.map(|d| format!("{token}.{d}")),
            token,
            note,
            created_ms: now_ms(),
            actor: actor.id(),
            interactions: 0,
        })
    }

    /// Recent payloads, newest first, with how many interactions each had.
    pub fn collaborator_payloads(&self, limit: usize) -> Result<Vec<CollaboratorPayload>> {
        let (public_url, dns_domain) = self.oast_settings()?;
        let st = self.store.lock();
        let rows = st.rows("oast_payloads", None, limit.clamp(1, 1000))?;
        rows.iter()
            .map(|r| {
                let token = s(r, "token");
                Ok(CollaboratorPayload {
                    http_url: public_url.as_ref().map(|u| format!("{}/{token}", u.trim_end_matches('/'))),
                    dns_name: dns_domain.as_ref().map(|d| format!("{token}.{d}")),
                    interactions: st.count_rows("oast_interactions", Some(("token", &json!(token))))?,
                    note: s(r, "note"),
                    actor: s(r, "actor"),
                    created_ms: i(r, "created_ms"),
                    token,
                })
            })
            .collect()
    }

    /// Interactions, newest first: for one token, or all of them.
    pub fn collaborator_interactions(&self, token: Option<&str>, limit: usize) -> Result<Vec<CollaboratorInteraction>> {
        let st = self.store.lock();
        let filter = token.map(|t| json!(t.trim().to_ascii_lowercase()));
        let rows = st.rows("oast_interactions", filter.as_ref().map(|t| ("token", t)), limit.clamp(1, 1000))?;
        let mut notes = std::collections::HashMap::new();
        Ok(rows
            .iter()
            .map(|r| {
                let token = s(r, "token");
                let note = notes
                    .entry(token.clone())
                    .or_insert_with(|| {
                        st.rows("oast_payloads", Some(("token", &json!(token))), 1)
                            .ok()
                            .and_then(|v| v.first().map(|p| s(p, "note")))
                    })
                    .clone();
                CollaboratorInteraction {
                    id: i(r, "id"),
                    protocol: s(r, "protocol"),
                    remote: s(r, "remote"),
                    method: s(r, "method"),
                    path: s(r, "path"),
                    ts_ms: i(r, "ts_ms"),
                    raw: s(r, "raw"),
                    note,
                    token,
                }
            })
            .collect())
    }
}
