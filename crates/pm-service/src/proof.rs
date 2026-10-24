//! Proof runs: send the requests an oracle needs, decide, and store the
//! result with its inputs so it can be re-run later (e.g. during a retest).

use std::time::Duration;

use pm_policy::{ActionRequest, Actor, Target, Tier};
use pm_replay::Endpoint;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::replay::{Outgoing, parse_url_endpoint};
use crate::{Authorization, Result, Service, ServiceError, now_ms};

pub const OAST_SETTING: &str = "oast_public_url";
/// Project setting: the domain delegated to the OAST DNS responder.
pub const OAST_DNS_SETTING: &str = "oast_dns_domain";

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProofRequest {
    /// differential_authz, timing, oast or reflection
    pub oracle: String,
    /// Recorded exchange to work from (the owner's request for
    /// differential_authz; the baseline for timing; the target for oast).
    pub exchange_id: Option<i64>,
    /// differential_authz: identity that should NOT have access.
    pub attacker: Option<String>,
    /// differential_authz: identity that owns the data (defaults to the one
    /// the exchange was made as).
    pub owner: Option<String>,
    /// timing/oast: scheme://host[:port] when there is no exchange_id.
    pub url: Option<String>,
    /// timing: normal request (defaults to the exchange's request).
    pub baseline_raw: Option<String>,
    /// timing: the same request with the delay payload.
    pub payload_raw: Option<String>,
    /// timing: samples of each (default 8, 5–30).
    pub samples: Option<usize>,
    /// timing: required median slowdown in ms (default 500).
    pub min_effect_ms: Option<f64>,
    /// oast: request containing {{oast}} where the callback URL goes, or
    /// {{oast_dns}} where a host name to resolve goes (needs a DNS listener).
    /// reflection: request containing {{xss}} (payload as is), {{xss_url}}
    /// (percent-encoded) or {{token}} (inside a payload of your own).
    pub raw: Option<String>,
    /// oast: how long to wait for a callback (default 10 s, max 60).
    pub wait_seconds: Option<u64>,
    /// timing/oast/reflection: send with this identity's credentials.
    pub identity: Option<String>,
    /// Mark this finding as proven if the proof succeeds.
    pub finding_id: Option<i64>,
    /// Mark this hypothesis as confirmed if the proof succeeds.
    pub hypothesis_id: Option<i64>,
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProofResult {
    Completed {
        proof_id: i64,
        oracle: String,
        proven: bool,
        confidence: String,
        reasons: Vec<String>,
        exchange_ids: Vec<i64>,
        details: Value,
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

fn invalid<T>(msg: impl Into<String>) -> Result<T> {
    Err(ServiceError::Invalid(msg.into()))
}

impl Service {
    fn exchange_outgoing(&self, id: i64) -> Result<(Outgoing, Option<String>)> {
        let ex = self.store.lock().get_exchange(id)?.ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
        let s = &ex.summary;
        let raw = self.redactor.redact(&String::from_utf8_lossy(&ex.request));
        let out = self.outgoing(Endpoint::new(&s.scheme, &s.host, s.port), raw.as_bytes(), false)?;
        let who = s.identity.clone().or_else(|| {
            let ids: Vec<pm_identity::Identity> = self
                .store
                .lock()
                .list_identities()
                .ok()?
                .iter()
                .filter_map(|r| serde_json::from_str(&r.data).ok())
                .collect();
            let auth = pm_identity::auth_from_request(&ex.request);
            ids.into_iter()
                .find(|i| {
                    i.auth
                        .cookies
                        .iter()
                        .any(|(n, v)| v.len() >= 8 && auth.cookies.iter().any(|(n2, v2)| n == n2 && v == v2))
                })
                .map(|i| i.name)
        });
        Ok((out, who))
    }

    /// Gate for a whole proof run with an explicit tier (e.g. payload sends
    /// are intrusive even when they are GETs).
    fn gate_proof(
        &self,
        actor: &Actor,
        action: &str,
        tier: Tier,
        out: &Outgoing,
        params: &Value,
        approval: Option<&str>,
    ) -> Result<Authorization> {
        let target = Target::from_parts(&out.endpoint.scheme, &out.endpoint.host, out.endpoint.port, &out.path)
            .map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let (by_request, payload_reasons) = Tier::for_http_request(&out.raw);
        let tier = tier.max(by_request);
        let note = if payload_reasons.is_empty() {
            String::new()
        } else {
            format!(" [payload: {}]", payload_reasons.join("; "))
        };
        match approval {
            Some(id) => self.run_approved(id, params),
            None => self.authorize(
                ActionRequest {
                    actor: actor.clone(),
                    action: action.into(),
                    tier,
                    target: Some(target),
                    summary: format!("{action}: {} {}{note}", out.method, out.url()),
                },
                params,
            ),
        }
    }

    pub async fn proof_run(&self, actor: &Actor, req: ProofRequest) -> Result<ProofResult> {
        let run = match req.oracle.as_str() {
            "differential_authz" => self.prove_differential(actor, &req).await?,
            "timing" => self.prove_timing(actor, &req).await?,
            "oast" => self.prove_oast(actor, &req).await?,
            "reflection" => self.prove_reflection(actor, &req).await?,
            other => {
                return invalid(format!(
                    "unknown oracle {other:?}; use differential_authz, timing, oast or reflection"
                ));
            }
        };
        let (verdict, exchange_ids, details) = match run {
            Ok(x) => x,
            Err(early) => return Ok(early),
        };
        let mut inputs = serde_json::to_value(&req).unwrap_or_default();
        if let Some(o) = inputs.as_object_mut() {
            o.remove("approval_id");
            o.retain(|_, v| !v.is_null());
        }
        let mut row = serde_json::Map::new();
        for (k, v) in [
            ("oracle", json!(req.oracle)),
            ("inputs", json!(inputs.to_string())),
            ("proven", json!(verdict.proven)),
            ("confidence", json!(verdict.confidence)),
            ("reasons", json!(serde_json::to_string(&verdict.reasons).unwrap_or_default())),
            ("details", json!(details.to_string())),
            ("exchange_ids", json!(serde_json::to_string(&exchange_ids).unwrap_or_default())),
            ("finding_id", json!(req.finding_id)),
            ("actor", json!(actor.id())),
            ("created_ms", json!(now_ms())),
        ] {
            row.insert(k.into(), v);
        }
        let proof_id = self.store.lock().insert_row("proofs", &row)?;
        if verdict.proven {
            if let Some(f) = req.finding_id {
                let mut ch = serde_json::Map::new();
                ch.insert("status".into(), json!("proven"));
                ch.insert("proof_id".into(), json!(proof_id));
                ch.insert("updated_ms".into(), json!(now_ms()));
                self.store.lock().update_row("findings", f, &ch)?;
            }
            if let Some(h) = req.hypothesis_id {
                let mut ch = serde_json::Map::new();
                ch.insert("status".into(), json!("confirmed"));
                ch.insert("updated_ms".into(), json!(now_ms()));
                self.store.lock().update_row("hypotheses", h, &ch)?;
            }
        }
        self.audit(
            &actor.id(),
            "proof_run",
            json!({ "proof_id": proof_id, "oracle": req.oracle, "proven": verdict.proven }),
            if verdict.proven { "proven" } else { "not_proven" },
        )?;
        Ok(ProofResult::Completed {
            proof_id,
            oracle: req.oracle,
            proven: verdict.proven,
            confidence: verdict.confidence.into(),
            reasons: verdict.reasons,
            exchange_ids,
            details,
        })
    }

    /// Re-runs a stored proof with the same inputs (new requests, new result).
    pub async fn proof_rerun(&self, actor: &Actor, proof_id: i64) -> Result<ProofResult> {
        let row = self
            .store
            .lock()
            .row("proofs", proof_id)?
            .ok_or_else(|| ServiceError::NotFound(format!("proof {proof_id}")))?;
        let inputs: ProofRequest = serde_json::from_str(row.get("inputs").and_then(Value::as_str).unwrap_or("{}"))
            .map_err(|e| ServiceError::Invalid(format!("stored inputs unreadable: {e}")))?;
        self.proof_run(actor, inputs).await
    }

    pub fn proof_get(&self, proof_id: i64) -> Result<Value> {
        let row = self
            .store
            .lock()
            .row("proofs", proof_id)?
            .ok_or_else(|| ServiceError::NotFound(format!("proof {proof_id}")))?;
        Ok(decode_proof(&row))
    }

    pub fn proofs_for_finding(&self, finding_id: i64) -> Result<Vec<Value>> {
        Ok(self
            .store
            .lock()
            .rows("proofs", Some(("finding_id", &json!(finding_id))), 100)?
            .iter()
            .map(decode_proof)
            .collect())
    }

    #[allow(clippy::type_complexity)]
    async fn prove_differential(
        &self,
        actor: &Actor,
        req: &ProofRequest,
    ) -> Result<std::result::Result<(pm_proof::Verdict, Vec<i64>, Value), ProofResult>> {
        let id = req.exchange_id.ok_or_else(|| ServiceError::Invalid("differential_authz needs exchange_id".into()))?;
        let attacker =
            req.attacker.clone().ok_or_else(|| ServiceError::Invalid("differential_authz needs attacker".into()))?;
        let (mut out, recorded_as) = self.exchange_outgoing(id)?;
        out.hypothesis_id = req.hypothesis_id;
        if Tier::for_http_method(&out.method) != Tier::ActiveSafe {
            return invalid("differential_authz only re-sends GET/HEAD/OPTIONS requests");
        }
        let owner = req.owner.clone().or(recorded_as).ok_or_else(|| {
            ServiceError::Invalid("can't tell who owns this data; pass owner (an identity name)".into())
        })?;
        let (owner_ident, attacker_ident) = (self.load_identity(&owner)?, self.load_identity(&attacker)?);
        let mut sends = Vec::new();
        for who in [Some(owner.as_str()), Some(owner.as_str()), Some(attacker.as_str()), Some(pm_identity::ANONYMOUS)] {
            match self.gate_send(actor, "proof_run", &out, who, false, None)? {
                Authorization::Allowed { .. } => {}
                Authorization::Denied { reasons } => return Ok(Err(ProofResult::Denied { reasons })),
                Authorization::PendingApproval { approval_id, summary, reasons } => {
                    return Ok(Err(ProofResult::PendingApproval { approval_id, summary, reasons }));
                }
            }
            sends.push(self.send_as(actor, &out, who, false, "proof").await?.0);
        }
        let resp = |i: usize| sends[i].response.clone().unwrap_or_default();
        let noise = pm_diff::learn_noise(&resp(0), &resp(1));
        let d = pm_diff::diff(&resp(0), &resp(2), &noise);
        // Values that identify the owner: their name, and owner-response
        // strings containing it or looking like emails.
        let owner_body = String::from_utf8_lossy(pm_http::split_message(&resp(0)).1).into_owned();
        let attacker_body = String::from_utf8_lossy(pm_http::split_message(&resp(2)).1).into_owned();
        let mut markers: Vec<String> = Vec::new();
        if let Ok(v) = serde_json::from_str::<Value>(&owner_body) {
            collect_markers(&v, &owner.to_lowercase(), &mut markers);
        }
        if owner.len() >= 3 && owner_body.to_lowercase().contains(&owner.to_lowercase()) {
            markers.push(owner.clone());
        }
        markers.sort();
        markers.dedup();
        let found: Vec<String> = markers.into_iter().filter(|m| attacker_body.contains(m.as_str())).collect();
        let verdict = pm_proof::differential_authz(&pm_proof::DifferentialInputs {
            owner: owner.clone(),
            attacker: attacker.clone(),
            attacker_role: attacker_ident.role.clone(),
            owner_role: owner_ident.role.clone(),
            owner_statuses: [sends[0].status, sends[1].status],
            attacker_status: sends[2].status,
            anonymous_status: sends[3].status,
            similarity: d.similarity,
            markers_found: found.clone(),
        });
        let ids = sends.iter().map(|s| s.exchange_id).collect();
        let details = json!({
            "owner": owner, "attacker": attacker,
            "statuses": { "owner": [sends[0].status, sends[1].status], "attacker": sends[2].status, "anonymous": sends[3].status },
            "similarity": d.similarity, "diff": d.summary, "noise": noise, "markers_found": found,
            "exchanges": { "owner": [sends[0].exchange_id, sends[1].exchange_id], "attacker": sends[2].exchange_id, "anonymous": sends[3].exchange_id },
        });
        Ok(Ok((verdict, ids, details)))
    }

    #[allow(clippy::type_complexity)]
    async fn prove_timing(
        &self,
        actor: &Actor,
        req: &ProofRequest,
    ) -> Result<std::result::Result<(pm_proof::Verdict, Vec<i64>, Value), ProofResult>> {
        let payload =
            req.payload_raw.clone().ok_or_else(|| ServiceError::Invalid("timing needs payload_raw".into()))?;
        let (endpoint, baseline_raw) = match (req.exchange_id, &req.url) {
            (Some(id), _) => {
                let (o, _) = self.exchange_outgoing(id)?;
                (
                    o.endpoint.clone(),
                    req.baseline_raw.clone().unwrap_or_else(|| String::from_utf8_lossy(&o.raw).into_owned()),
                )
            }
            (None, Some(u)) => (
                parse_url_endpoint(u)?,
                req.baseline_raw
                    .clone()
                    .ok_or_else(|| ServiceError::Invalid("timing with url needs baseline_raw".into()))?,
            ),
            _ => return invalid("timing needs exchange_id or url"),
        };
        let mut base = self.outgoing(endpoint.clone(), baseline_raw.as_bytes(), true)?;
        let mut pay = self.outgoing(endpoint, payload.as_bytes(), true)?;
        base.hypothesis_id = req.hypothesis_id;
        pay.hypothesis_id = req.hypothesis_id;
        let samples = req.samples.unwrap_or(8).clamp(5, 30);
        let min_effect = req.min_effect_ms.unwrap_or(500.0).max(50.0);
        let params = json!({
            "endpoint": format!("{}://{}:{}", pay.endpoint.scheme, pay.endpoint.host, pay.endpoint.port),
            "baseline": String::from_utf8_lossy(&base.raw), "payload": String::from_utf8_lossy(&pay.raw),
            "samples": samples, "identity": req.identity,
        });
        match self.gate_proof(
            actor,
            "proof_timing",
            Tier::ActiveIntrusive,
            &pay,
            &params,
            req.approval_id.as_deref(),
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(Err(ProofResult::Denied { reasons })),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(Err(ProofResult::PendingApproval { approval_id, summary, reasons }));
            }
        }
        let (mut b_ms, mut p_ms, mut ids) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..samples {
            for (out, bucket) in [(&base, &mut b_ms), (&pay, &mut p_ms)] {
                let (sent, _) = self.send_as(actor, out, req.identity.as_deref(), true, "proof").await?;
                ids.push(sent.exchange_id);
                if sent.error.is_none() {
                    bucket.push(sent.elapsed_ms as f64);
                }
            }
        }
        let (verdict, p, mb, mp) = pm_proof::timing(&b_ms, &p_ms, min_effect);
        let details = json!({ "baseline_ms": b_ms, "payload_ms": p_ms, "p_value": p, "median_baseline_ms": mb,
                              "median_payload_ms": mp, "min_effect_ms": min_effect });
        Ok(Ok((verdict, ids, details)))
    }

    #[allow(clippy::type_complexity)]
    async fn prove_oast(
        &self,
        actor: &Actor,
        req: &ProofRequest,
    ) -> Result<std::result::Result<(pm_proof::Verdict, Vec<i64>, Value), ProofResult>> {
        let raw = req
            .raw
            .clone()
            .ok_or_else(|| ServiceError::Invalid("oast needs raw containing {{oast}} or {{oast_dns}}".into()))?;
        let (wants_http, wants_dns) = (raw.contains("{{oast}}"), raw.contains("{{oast_dns}}"));
        if !wants_http && !wants_dns {
            return invalid(
                "put {{oast}} in raw where the callback URL should go, or {{oast_dns}} where a host name goes",
            );
        }
        let public = self.store.lock().get_setting(OAST_SETTING)?;
        let dns_domain = self.store.lock().get_setting(OAST_DNS_SETTING)?;
        if wants_http && public.is_none() {
            return invalid("no OAST listener configured: run `proxymind oast-server` or start mcp with --oast-listen");
        }
        if wants_dns && dns_domain.is_none() {
            return invalid(
                "no OAST DNS domain configured: run `proxymind oast-server --dns <addr> --domain <domain>`",
            );
        }
        let endpoint = match (req.exchange_id, &req.url) {
            (Some(id), _) => self.exchange_outgoing(id)?.0.endpoint,
            (None, Some(u)) => parse_url_endpoint(u)?,
            _ => return invalid("oast needs exchange_id or url"),
        };
        let wait = req.wait_seconds.unwrap_or(10).clamp(1, 60);
        let template = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
        let params = json!({
            "endpoint": format!("{}://{}:{}", endpoint.scheme, endpoint.host, endpoint.port),
            "raw": raw, "identity": req.identity, "wait_seconds": wait,
        });
        match self.gate_proof(
            actor,
            "proof_oast",
            Tier::ActiveIntrusive,
            &template,
            &params,
            req.approval_id.as_deref(),
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(Err(ProofResult::Denied { reasons })),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(Err(ProofResult::PendingApproval { approval_id, summary, reasons }));
            }
        }
        let token = pm_oast::new_token();
        let callback = public.map(|p| format!("{}/{token}", p.trim_end_matches('/')));
        let dns_name = dns_domain.map(|d| format!("{token}.{}", d.trim_end_matches('.')));
        let mut filled = raw.clone();
        if let Some(c) = &callback {
            filled = filled.replace("{{oast}}", c);
        }
        if let Some(n) = &dns_name {
            filled = filled.replace("{{oast_dns}}", n);
        }
        let mut out = self.outgoing(endpoint, filled.as_bytes(), true)?;
        out.hypothesis_id = req.hypothesis_id;
        let (sent, _) = self.send_as(actor, &out, req.identity.as_deref(), true, "proof").await?;
        let deadline = std::time::Instant::now() + Duration::from_secs(wait);
        let hits = loop {
            let hits = self.store.lock().rows("oast_interactions", Some(("token", &json!(token))), 20)?;
            if !hits.is_empty() || std::time::Instant::now() >= deadline {
                break hits;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        let first = hits.last().map(|h| {
            format!(
                "{} {} {} from {}",
                h.get("protocol").and_then(Value::as_str).unwrap_or("").to_uppercase(),
                h.get("method").and_then(Value::as_str).unwrap_or(""),
                h.get("path").and_then(Value::as_str).unwrap_or(""),
                h.get("remote").and_then(Value::as_str).unwrap_or("")
            )
        });
        let verdict = pm_proof::oast(&token, hits.len(), first.as_deref());
        let details = json!({ "token": token, "callback_url": callback, "dns_name": dns_name, "interactions": hits });
        Ok(Ok((verdict, vec![sent.exchange_id], details)))
    }

    /// The browser used for reflection proofs: `$PROXYMIND_CHROMIUM`, then
    /// the usual install locations. Deliberately not a project setting: a
    /// project file handed over by someone else must not pick what runs.
    pub fn chromium_path(&self) -> Result<Option<std::path::PathBuf>> {
        Ok(pm_browser::find_chromium())
    }

    /// Reflected XSS: send the request with a payload carrying a fresh token,
    /// then render the *recorded* response in headless Chromium with every
    /// other request blocked. Proven only if script ran and returned the token.
    #[allow(clippy::type_complexity)]
    async fn prove_reflection(
        &self,
        actor: &Actor,
        req: &ProofRequest,
    ) -> Result<std::result::Result<(pm_proof::Verdict, Vec<i64>, Value), ProofResult>> {
        let raw = req.raw.clone().ok_or_else(|| {
            ServiceError::Invalid("reflection needs raw containing {{xss}}, {{xss_url}} or {{token}}".into())
        })?;
        if !pm_proof::XSS_PLACEHOLDERS.iter().any(|p| raw.contains(p)) {
            return invalid("put {{xss}}, {{xss_url}} (percent-encoded) or {{token}} in raw where the payload goes");
        }
        let endpoint = match (req.exchange_id, &req.url) {
            (Some(id), _) => self.exchange_outgoing(id)?.0.endpoint,
            (None, Some(u)) => parse_url_endpoint(u)?,
            _ => return invalid("reflection needs exchange_id or url"),
        };
        // Find the browser before asking for approval or sending anything.
        let chromium = self.chromium_path()?.ok_or_else(|| {
            ServiceError::Invalid(format!(
                "no Chromium or Chrome found for the reflection oracle: install one, or set {} to its path",
                pm_browser::ENV_CHROMIUM
            ))
        })?;
        let template = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
        let params = json!({
            "endpoint": format!("{}://{}:{}", endpoint.scheme, endpoint.host, endpoint.port),
            "raw": raw, "identity": req.identity,
        });
        match self.gate_proof(
            actor,
            "proof_reflection",
            Tier::ActiveIntrusive,
            &template,
            &params,
            req.approval_id.as_deref(),
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(Err(ProofResult::Denied { reasons })),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(Err(ProofResult::PendingApproval { approval_id, summary, reasons }));
            }
        }
        let token = xss_token()?;
        let mut out = self.outgoing(endpoint, pm_proof::fill_xss_template(&raw, &token).as_bytes(), true)?;
        out.hypothesis_id = req.hypothesis_id;
        let (sent, _) = self.send_as(actor, &out, req.identity.as_deref(), true, "proof").await?;
        // Render exactly what was recorded.
        let recorded = self.store.lock().get_exchange(sent.exchange_id)?.and_then(|e| e.response);
        let payload = pm_proof::xss_payload(&token);
        let mut inputs = pm_proof::ReflectionInputs { token: token.clone(), status: sent.status, ..Default::default() };
        let mut activity = Value::Null;
        let mut render_error = None;
        let mut blocked_total = 0;
        if let Some(doc) = recorded.as_deref().and_then(|r| recorded_document(&out.url(), r)) {
            let body = String::from_utf8_lossy(&doc.body);
            inputs.token_in_body = body.contains(&token);
            // The payload as sent: the default one, or the user's own around {{token}}.
            inputs.payload_in_body = body.contains(&payload)
                || custom_payload(&raw, &token).is_some_and(|p| !p.is_empty() && body.contains(&p));
            inputs.content_type =
                doc.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("content-type")).map(|(_, v)| v.clone());
            let opts = pm_browser::RenderOptions {
                binding: pm_proof::XSS_BINDING.into(),
                stop_on: Some(token.clone()),
                ..Default::default()
            };
            match pm_browser::render(&chromium, &doc, &opts).await {
                Ok(r) => {
                    inputs.rendered = r.served;
                    inputs.binding_calls = r.binding_calls.clone();
                    inputs.dialogs = r.dialogs.iter().map(|d| d.message.clone()).collect();
                    inputs.blocked_requests = r.blocked_total;
                    blocked_total = r.blocked_total;
                    let dialogs: Vec<Value> =
                        r.dialogs.iter().map(|d| json!({ "type": d.kind, "message": d.message })).collect();
                    let page = json!({ "binding_calls": r.binding_calls, "dialogs": dialogs,
                                       "blocked_requests": r.blocked.iter().take(10).collect::<Vec<_>>() });
                    activity = json!(pm_ai::wrap_untrusted(&page.to_string()));
                }
                Err(e) => render_error = Some(e.to_string()),
            }
        }
        let mut verdict = pm_proof::reflection(&inputs);
        if let Some(e) = &render_error {
            verdict.reasons.push(format!("browser error: {e}"));
        }
        let details = json!({
            "token": token, "payload": payload, "url": out.url(), "status": sent.status,
            "content_type": inputs.content_type, "token_in_body": inputs.token_in_body,
            "payload_in_body": inputs.payload_in_body, "rendered": inputs.rendered,
            "blocked_total": blocked_total, "page_activity": activity, "render_error": render_error,
        });
        Ok(Ok((verdict, vec![sent.exchange_id], details)))
    }

    /// Where payloads should send callbacks (the OAST listener's public URL).
    pub fn set_oast_public_url(&self, url: &str) -> Result<()> {
        url::Url::parse(url).map_err(|e| ServiceError::Invalid(format!("bad OAST url: {e}")))?;
        self.store.lock().set_setting(OAST_SETTING, url)?;
        Ok(())
    }

    /// The domain delegated to the OAST DNS responder (payloads use
    /// `<token>.<domain>` via {{oast_dns}}).
    pub fn set_oast_dns_domain(&self, domain: &str) -> Result<()> {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        let ok = !d.is_empty()
            && d.len() <= 200
            && d.split('.')
                .all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
        if !ok {
            return invalid(format!("{domain:?} is not a valid domain name"));
        }
        self.store.lock().set_setting(OAST_DNS_SETTING, &d)?;
        Ok(())
    }

    /// Stores an OAST interaction (called by the OAST listener).
    pub fn record_oast(&self, i: &pm_oast::Interaction) -> Result<()> {
        record_oast_in(&mut self.store.lock(), i)
    }
}

/// A fresh, unguessable token (so a page can't fake a proof).
fn xss_token() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 10];
    SystemRandom::new().fill(&mut b).map_err(|_| ServiceError::Invalid("no system randomness".into()))?;
    Ok(format!("pm{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()))
}

/// For a template using {{token}} in a payload of the user's own, the
/// unencoded text around the token on that line (e.g. `<svg onload=alert('…')>`).
fn custom_payload(raw: &str, token: &str) -> Option<String> {
    let line = raw.lines().find(|l| l.contains("{{token}}"))?;
    let start = line[..line.find("{{token}}")?].rfind(['=', '&', '?', ' ']).map_or(0, |i| i + 1);
    let rest = &line[start..];
    let end = rest.find(['&', ' ']).unwrap_or(rest.len());
    Some(percent_decode(&rest[..end].replace("{{token}}", token)))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = |c: u8| (c as char).to_digit(16);
        match (b[i], b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(h), Some(l)) => {
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b'+', ..) => {
                out.push(b' ');
                i += 1;
            }
            (c, ..) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The recorded response as a browser document: HTTP/2 text converted,
/// body de-chunked and decompressed.
pub(crate) fn recorded_document(url: &str, raw: &[u8]) -> Option<pm_browser::Document> {
    let converted;
    let raw = if pm_http::h2text::is_http2_response(raw) {
        converted = pm_http::h2text::to_http1_response(raw)?;
        &converted[..]
    } else {
        raw
    };
    let (head, body) = pm_http::split_message(raw);
    let head = pm_http::parse_response_head(head).ok()?;
    let decoded = pm_ai::body::decode(&head.headers, body);
    let mut headers: Vec<(String, String)> =
        head.headers.iter().map(|h| (h.name.clone(), String::from_utf8_lossy(&h.value).into_owned())).collect();
    if decoded.notes.iter().any(|n| n.contains("decoded")) {
        // The body handed over is plain; the browser must not decode it again.
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-encoding"));
    }
    Some(pm_browser::Document {
        url: url.to_string(),
        status: head.status,
        headers,
        body: decoded.bytes,
        resources: vec![],
    })
}

pub fn record_oast_in(store: &mut pm_store::Store, i: &pm_oast::Interaction) -> Result<()> {
    let mut row = serde_json::Map::new();
    for (k, v) in [
        ("token", json!(i.token)),
        ("protocol", json!(i.protocol)),
        ("remote", json!(i.remote)),
        ("method", json!(i.method)),
        ("path", json!(i.path)),
        ("raw", json!(i.raw)),
        ("ts_ms", json!(i.ts_ms)),
    ] {
        row.insert(k.into(), v);
    }
    store.insert_row("oast_interactions", &row)?;
    Ok(())
}

fn collect_markers(v: &Value, owner: &str, out: &mut Vec<String>) {
    match v {
        Value::String(s)
            if s.len() >= 3 && (s.to_lowercase().contains(owner) || (s.contains('@') && s.contains('.'))) =>
        {
            out.push(s.clone());
        }
        Value::Object(o) => o.values().for_each(|x| collect_markers(x, owner, out)),
        Value::Array(a) => a.iter().for_each(|x| collect_markers(x, owner, out)),
        _ => {}
    }
}

pub(crate) fn decode_proof(row: &serde_json::Map<String, Value>) -> Value {
    let parse = |k: &str| {
        row.get(k).and_then(Value::as_str).and_then(|s| serde_json::from_str::<Value>(s).ok()).unwrap_or(Value::Null)
    };
    json!({
        "proof_id": row.get("id"),
        "oracle": row.get("oracle"),
        "proven": row.get("proven").and_then(Value::as_i64) == Some(1),
        "confidence": row.get("confidence"),
        "reasons": parse("reasons"),
        "exchange_ids": parse("exchange_ids"),
        "details": parse("details"),
        "inputs": parse("inputs"),
        "finding_id": row.get("finding_id"),
        "actor": row.get("actor"),
        "created_ms": row.get("created_ms"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_payloads_are_found_and_decoded() {
        let raw = "GET /s?a=1&q=%3Csvg%20onload%3Dalert('{{token}}')%3E&b=2 HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(custom_payload(raw, "T").as_deref(), Some("<svg onload=alert('T')>"));
        assert_eq!(custom_payload("q={{xss}}", "T"), None);
        assert_eq!(percent_decode("a+b%2"), "a b%2");
    }

    #[test]
    fn recorded_documents_are_decoded() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let d = recorded_document("http://x/", raw).unwrap();
        assert_eq!((d.status, d.body.as_slice()), (200, &b"hello"[..]));
        let h2 = b"HTTP/2 200\r\ncontent-type: text/html\r\n\r\n<p>x</p>";
        assert_eq!(recorded_document("http://x/", h2).unwrap().body, b"<p>x</p>");
    }
}
