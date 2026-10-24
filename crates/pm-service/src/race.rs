//! Race-condition testing through the policy gate: one request sent many
//! times so the copies reach the server together.

use std::collections::BTreeMap;
use std::time::Instant;

use pm_policy::{Actor, Tier};
use pm_replay::race::{MAX_RACE, RaceMode};
use pm_store::NewExchange;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::replay::ReplayRequest;
use crate::{Authorization, Result, Service, ServiceError, now_ms};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RaceModeChoice {
    /// HTTP/2 single-packet for HTTPS servers that speak it, else last-byte.
    #[default]
    Auto,
    /// Force HTTP/2 (h2c for plain HTTP).
    SinglePacket,
    LastByte,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RaceRequest {
    /// Recorded exchange to race (its target is used).
    pub exchange_id: Option<i64>,
    /// Target as scheme://host[:port], when not using exchange_id.
    pub url: Option<String>,
    /// The request (default: the recorded one). May contain placeholders.
    pub raw: Option<String>,
    /// How many copies to send at once (2 to 50, default 10).
    pub count: Option<usize>,
    pub mode: RaceModeChoice,
    pub identity: Option<String>,
    pub fix_content_length: Option<bool>,
    pub approval_id: Option<String>,
    pub hypothesis_id: Option<i64>,
}

/// Responses that look alike (same status and body length).
#[derive(Debug, Clone, Serialize)]
pub struct RaceGroup {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub body_length: usize,
    pub count: usize,
    pub exchange_ids: Vec<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RaceResult {
    Done {
        mode: RaceMode,
        count: usize,
        /// Responses grouped by status and body length, biggest group first.
        groups: Vec<RaceGroup>,
        /// How many got a 2xx: more than one for an action meant to work
        /// once (redeem, transfer, vote) suggests a race condition.
        successes: usize,
        /// Fastest and slowest time from release to response.
        fastest_ms: u64,
        slowest_ms: u64,
        exchange_ids: Vec<i64>,
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
    /// Sends `count` copies of a request so they arrive together, if the
    /// policy allows it. Racing is at least active-intrusive.
    pub async fn race_send(&self, actor: &Actor, req: RaceRequest) -> Result<RaceResult> {
        let count = req.count.unwrap_or(10);
        if !(2..=MAX_RACE).contains(&count) {
            return Err(ServiceError::Invalid(format!("count must be 2 to {MAX_RACE}")));
        }
        let base = ReplayRequest {
            raw: req.raw.clone(),
            exchange_id: req.exchange_id,
            url: req.url.clone(),
            hypothesis_id: req.hypothesis_id,
            ..Default::default()
        };
        let out = self.outgoing_from_request(&base)?;
        let fix_cl = req.fix_content_length.unwrap_or(true);
        if let Some(name) = &req.identity {
            self.load_identity(name)?;
        }
        let tier = Tier::for_http_method(&out.method).max(Tier::ActiveIntrusive);
        let extra = json!({ "race_count": count, "race_mode": req.mode });
        let identity = req.identity.as_deref();
        match self.gate_send_with(
            actor,
            "race_send",
            &out,
            identity,
            fix_cl,
            req.approval_id.as_deref(),
            Some(tier),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(RaceResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(RaceResult::PendingApproval {
                    approval_id,
                    summary: format!("race ×{count}: {summary}"),
                    reasons,
                });
            }
        }

        self.race_execute(actor, &out, req.identity.as_deref(), fix_cl, count, req.mode).await
    }

    /// Sends `count` copies at once and records them (the caller has asked the gate).
    pub(crate) async fn race_execute(
        &self,
        actor: &Actor,
        out: &crate::replay::Outgoing,
        identity: Option<&str>,
        fix_cl: bool,
        count: usize,
        mode: RaceModeChoice,
    ) -> Result<RaceResult> {
        // One slot for the whole race: the point is to send at once.
        let _permit = self.acquire_slot(&out.endpoint.host).await?;
        let mut wire = self.redactor.unredact(&out.raw);
        if let Some(name) = identity {
            wire = pm_identity::apply(&wire, &self.load_identity(name)?.auth);
        }
        if fix_cl {
            wire = pm_http::fix_content_length(&wire);
        }
        let prefer_h2 = match mode {
            RaceModeChoice::Auto => out.endpoint.scheme == "https",
            RaceModeChoice::SinglePacket => true,
            RaceModeChoice::LastByte => false,
        };
        let requests = vec![(wire.clone(), out.method.clone()); count];
        let check = |ips: &[std::net::IpAddr]| self.policy.check_resolved(ips);
        let started = Instant::now();
        let outcome = self
            .sender
            .send_race(&out.endpoint, &requests, prefer_h2, Some(&check))
            .await
            .map_err(|e| ServiceError::Invalid(format!("race failed: {e:#}")))?;

        let mut exchange_ids = Vec::with_capacity(count);
        let mut groups: BTreeMap<(Option<u16>, usize, Option<String>), Vec<i64>> = BTreeMap::new();
        let (mut fastest, mut slowest, mut successes) = (u64::MAX, 0u64, 0usize);
        for r in outcome.results {
            let mut record = NewExchange {
                ts_ms: now_ms(),
                duration_ms: Some(started.elapsed().as_millis() as i64),
                source: "race".into(),
                actor_id: actor.id(),
                scheme: out.endpoint.scheme.clone(),
                host: out.endpoint.host.clone(),
                port: out.endpoint.port,
                method: out.method.clone(),
                path: out.path.clone(),
                status: None,
                request: wire.clone(),
                response: None,
                error: None,
                identity: identity.map(str::to_string),
                hypothesis_id: out.hypothesis_id,
            };
            let key = match r {
                Ok(resp) => {
                    let ms = resp.elapsed.as_millis() as u64;
                    fastest = fastest.min(ms);
                    slowest = slowest.max(ms);
                    if (200..300).contains(&resp.head.status) {
                        successes += 1;
                    }
                    if let Some(sent) = resp.sent {
                        record.request = sent;
                    }
                    let body_len = pm_http::split_message(&resp.raw).1.len();
                    record.status = Some(resp.head.status);
                    record.duration_ms = Some(ms as i64);
                    record.response = Some(resp.raw);
                    (Some(resp.head.status), body_len, None)
                }
                Err(e) => {
                    record.error = Some(format!("{e:#}"));
                    (None, 0, record.error.clone())
                }
            };
            let id = self.store.lock().insert_exchange(&record)?;
            exchange_ids.push(id);
            groups.entry(key).or_default().push(id);
        }
        let mut groups: Vec<RaceGroup> = groups
            .into_iter()
            .map(|((status, body_length, error), ids)| RaceGroup {
                status,
                body_length,
                count: ids.len(),
                exchange_ids: ids,
                error,
            })
            .collect();
        groups.sort_by(|a, b| b.count.cmp(&a.count).then(a.status.cmp(&b.status)));
        Ok(RaceResult::Done {
            mode: outcome.mode,
            count,
            groups,
            successes,
            fastest_ms: if fastest == u64::MAX { 0 } else { fastest },
            slowest_ms: slowest,
            exchange_ids,
        })
    }
}
