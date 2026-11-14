//! Replay groups: several different requests sent together, either one
//! after another (a multi-step flow) or in parallel so they reach the
//! server at the same moment (a race across endpoints). All go to one
//! server; one gate decision, and one approval, covers the whole group.

use std::time::Instant;

use pm_policy::{Actor, Target, Tier};
use pm_replay::race::RaceMode;
use pm_store::NewExchange;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::race::RaceModeChoice;
use crate::replay::ReplayRequest;
use crate::{Authorization, Result, Service, ServiceError, now_ms};

/// Most requests in a group.
pub const MAX_GROUP: usize = 20;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupMode {
    /// One after another, each waiting for the previous response.
    #[default]
    Sequence,
    /// All at once to one server (HTTP/2 single packet, else last-byte sync).
    Parallel,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GroupItem {
    /// Target as scheme://host[:port] (or use exchange_id).
    pub url: Option<String>,
    pub exchange_id: Option<i64>,
    /// The request (default: the recorded one). May contain placeholders.
    pub raw: Option<String>,
    /// A label for the result (e.g. the Replay tab name).
    pub name: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GroupRequest {
    pub requests: Vec<GroupItem>,
    pub mode: GroupMode,
    /// For parallel groups: how to send at once (default auto).
    pub parallel: RaceModeChoice,
    /// Sequence only: stop at the first request that fails to get a response.
    pub stop_on_error: bool,
    pub identity: Option<String>,
    pub fix_content_length: Option<bool>,
    pub approval_id: Option<String>,
    pub hypothesis_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupItemResult {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// None when the request wasn't sent (an earlier one failed).
    pub exchange_id: Option<i64>,
    pub status: Option<u16>,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum GroupResult {
    Done {
        mode: GroupMode,
        /// For parallel groups, how they were sent.
        #[serde(skip_serializing_if = "Option::is_none")]
        parallel: Option<RaceMode>,
        results: Vec<GroupItemResult>,
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

impl Service {
    /// Sends a group of requests through the policy gate.
    pub async fn replay_group(&self, actor: &Actor, req: GroupRequest) -> Result<GroupResult> {
        let n = req.requests.len();
        if !(2..=MAX_GROUP).contains(&n) {
            return Err(ServiceError::Invalid(format!("a group holds 2 to {MAX_GROUP} requests")));
        }
        let mut outs = Vec::with_capacity(n);
        for (i, item) in req.requests.iter().enumerate() {
            let one = ReplayRequest {
                raw: item.raw.clone(),
                exchange_id: item.exchange_id,
                url: item.url.clone(),
                hypothesis_id: req.hypothesis_id,
                ..Default::default()
            };
            let out = self
                .outgoing_from_request(&one)
                .map_err(|e| ServiceError::Invalid(format!("request {}: {e}", i + 1)))?;
            outs.push(out);
        }
        // One gate decision covers the group, and the rules of engagement
        // decide per target, so a group stays on one server.
        if outs.iter().any(|o| o.endpoint != outs[0].endpoint) {
            return Err(ServiceError::Invalid(
                "a group sends to one server: every request needs the same target".into(),
            ));
        }
        // Every request must be in scope on its own; the gate checks the first.
        for (i, o) in outs.iter().enumerate() {
            let t = Target::from_parts(&o.endpoint.scheme, &o.endpoint.host, o.endpoint.port, &o.path)
                .map_err(|e| ServiceError::Invalid(e.to_string()))?;
            if let Err(why) = self.policy.scope_check(&t) {
                return Ok(GroupResult::Denied { reasons: vec![format!("request {}: {why}", i + 1)] });
            }
        }
        if let Some(name) = &req.identity {
            self.load_identity(name)?;
        }
        let fix_cl = req.fix_content_length.unwrap_or(true);
        let mut tier = outs.iter().map(|o| Tier::for_http_request(&o.raw).0).max().unwrap_or(Tier::Passive);
        if req.mode == GroupMode::Parallel {
            tier = tier.max(Tier::ActiveIntrusive);
        }
        // The approval binds every request in the group, in order.
        let extra = json!({
            "group": {
                "mode": req.mode,
                "parallel": req.parallel,
                "stop_on_error": req.stop_on_error,
                "requests": outs.iter().map(|o| json!({
                    "endpoint": format!("{}://{}:{}", o.endpoint.scheme, o.endpoint.host, o.endpoint.port),
                    "request": String::from_utf8_lossy(&o.raw),
                })).collect::<Vec<_>>(),
            }
        });
        let label = match req.mode {
            GroupMode::Sequence => "sequence",
            GroupMode::Parallel => "parallel",
        };
        match self.gate_send_with(
            actor,
            "replay_group",
            &outs[0],
            req.identity.as_deref(),
            fix_cl,
            req.approval_id.as_deref(),
            Some(tier),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(GroupResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(GroupResult::PendingApproval {
                    approval_id,
                    summary: format!("group of {n} ({label}), first: {summary}"),
                    reasons,
                });
            }
        }
        let names: Vec<Option<String>> = req.requests.iter().map(|r| r.name.clone()).collect();
        match req.mode {
            GroupMode::Sequence => {
                let mut results = Vec::with_capacity(n);
                let mut stopped = false;
                for (i, out) in outs.iter().enumerate() {
                    if stopped {
                        results.push(GroupItemResult {
                            index: i,
                            name: names[i].clone(),
                            exchange_id: None,
                            status: None,
                            elapsed_ms: 0,
                            error: Some("not sent: an earlier request failed".into()),
                        });
                        continue;
                    }
                    let (sent, _) = self.send_as(actor, out, req.identity.as_deref(), fix_cl, "replay").await?;
                    stopped = req.stop_on_error && sent.error.is_some();
                    results.push(GroupItemResult {
                        index: i,
                        name: names[i].clone(),
                        exchange_id: Some(sent.exchange_id),
                        status: sent.status,
                        elapsed_ms: sent.elapsed_ms,
                        error: sent.error,
                    });
                }
                Ok(GroupResult::Done { mode: req.mode, parallel: None, results })
            }
            GroupMode::Parallel => {
                self.group_parallel(actor, &outs, &names, req.identity.as_deref(), fix_cl, req.parallel).await
            }
        }
    }

    async fn group_parallel(
        &self,
        actor: &Actor,
        outs: &[crate::replay::Outgoing],
        names: &[Option<String>],
        identity: Option<&str>,
        fix_cl: bool,
        mode: RaceModeChoice,
    ) -> Result<GroupResult> {
        let ep = &outs[0].endpoint;
        let _permit = self.acquire_slot(&ep.host).await?;
        let ident = identity.map(|n| self.load_identity(n)).transpose()?;
        let mut wires = Vec::with_capacity(outs.len());
        for o in outs {
            let mut w = self.redactor.unredact(&o.raw);
            if let Some(id) = &ident {
                w = pm_identity::apply(&w, &id.auth);
            }
            if fix_cl {
                w = pm_http::fix_content_length(&w);
            }
            wires.push((w, o.method.clone()));
        }
        let prefer_h2 = match mode {
            RaceModeChoice::Auto => ep.scheme == "https",
            RaceModeChoice::SinglePacket => true,
            RaceModeChoice::LastByte => false,
        };
        let check = |ips: &[std::net::IpAddr]| self.policy.check_resolved(ips);
        let started = Instant::now();
        let outcome = self
            .sender
            .send_race(ep, &wires, prefer_h2, Some(&check))
            .await
            .map_err(|e| ServiceError::Invalid(format!("the group failed: {e:#}")))?;
        let mut results = Vec::with_capacity(outs.len());
        for (i, r) in outcome.results.into_iter().enumerate() {
            let o = &outs[i];
            let mut record = NewExchange {
                ts_ms: now_ms(),
                duration_ms: Some(started.elapsed().as_millis() as i64),
                source: "replay".into(),
                actor_id: actor.id(),
                scheme: o.endpoint.scheme.clone(),
                host: o.endpoint.host.clone(),
                port: o.endpoint.port,
                method: o.method.clone(),
                path: o.path.clone(),
                status: None,
                request: wires[i].0.clone(),
                response: None,
                error: None,
                identity: identity.map(str::to_string),
                hypothesis_id: o.hypothesis_id,
            };
            let mut elapsed_ms = 0;
            match r {
                Ok(resp) => {
                    elapsed_ms = resp.elapsed.as_millis() as u64;
                    if let Some(sent) = resp.sent {
                        record.request = sent;
                    }
                    record.status = Some(resp.head.status);
                    record.duration_ms = Some(elapsed_ms as i64);
                    record.response = Some(resp.raw);
                }
                Err(e) => record.error = Some(format!("{e:#}")),
            }
            let id = self.store.write(|db| db.insert_exchange(&record))?;
            results.push(GroupItemResult {
                index: i,
                name: names[i].clone(),
                exchange_id: Some(id),
                status: record.status,
                elapsed_ms,
                error: record.error,
            });
        }
        Ok(GroupResult::Done { mode: GroupMode::Parallel, parallel: Some(outcome.mode), results })
    }
}
