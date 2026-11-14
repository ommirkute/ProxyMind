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
    /// differential_authz, timing, oast, reflection, sql_error,
    /// boolean_injection, path_traversal, expression or marker
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
    /// sql_error: [baseline, quote, second quote, harmless change] raw
    /// requests. boolean_injection: [baseline, true-condition,
    /// false-condition]. path_traversal: [baseline, control, file-1, file-2, …] where
    /// each file-N request reads a known file; `markers[N]` is what proves it.
    /// expression: [baseline, control, payload-1, payload-2, …] where each
    /// payload sends an arithmetic expression and `markers[N]` is its result;
    /// the control sends the same numbers without template delimiters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raws: Vec<String>,
    /// path_traversal: a marker expected in each file request's response (same
    /// order as the file requests in `raws`, i.e. offset by the two leading
    /// baseline/control requests), e.g. "root:". Values from the target are
    /// untrusted; these are strings ProxyMind chose, so safe to match on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub markers: Vec<String>,
    /// marker: what to prove — "redirect" (open redirect), "crlf" (CRLF header
    /// injection), "host" (Host-header injection: the marker comes back in an
    /// absolute URL) or "cors" (an `Origin` carrying the marker is trusted with
    /// credentials). The request goes in `raw` with `{{marker}}` where a fresh
    /// random value should be placed.
    pub marker_kind: Option<String>,
    /// reflection: a request for the page that shows what `raw` stored
    /// (stored XSS). `raw` is sent first, then this, and this page is the one
    /// rendered.
    pub view_raw: Option<String>,
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
        let ex = self
            .store
            .read(|db| db.get_exchange(id))?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
        let s = &ex.summary;
        let raw = self.redactor.redact(&String::from_utf8_lossy(&ex.request));
        let out = self.outgoing(Endpoint::new(&s.scheme, &s.host, s.port), raw.as_bytes(), false)?;
        let who = s.identity.clone().or_else(|| {
            let ids: Vec<pm_identity::Identity> = self
                .store
                .read(|db| db.list_identities())
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
            Some(id) => self.run_approved(actor, action, id, params),
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
            "sql_error" => self.prove_sql_error(actor, &req).await?,
            "boolean_injection" => self.prove_boolean(actor, &req).await?,
            "path_traversal" => self.prove_traversal(actor, &req).await?,
            "expression" => self.prove_expression(actor, &req).await?,
            "marker" => self.prove_marker(actor, &req).await?,
            other => {
                return invalid(format!(
                    "unknown oracle {other:?}; use differential_authz, timing, oast, reflection, sql_error, \
                     boolean_injection, path_traversal, expression or marker"
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
        let proof_id = self.store.write(|db| db.insert_row("proofs", &row))?;
        if verdict.proven {
            if let Some(f) = req.finding_id {
                let mut ch = serde_json::Map::new();
                ch.insert("status".into(), json!("proven"));
                ch.insert("proof_id".into(), json!(proof_id));
                ch.insert("updated_ms".into(), json!(now_ms()));
                self.store.write(|db| db.update_row("findings", f, &ch))?;
            }
            if let Some(h) = req.hypothesis_id {
                let mut ch = serde_json::Map::new();
                ch.insert("status".into(), json!("confirmed"));
                ch.insert("updated_ms".into(), json!(now_ms()));
                self.store.write(|db| db.update_row("hypotheses", h, &ch))?;
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
            .read(|db| db.row("proofs", proof_id))?
            .ok_or_else(|| ServiceError::NotFound(format!("proof {proof_id}")))?;
        let inputs: ProofRequest = serde_json::from_str(row.get("inputs").and_then(Value::as_str).unwrap_or("{}"))
            .map_err(|e| ServiceError::Invalid(format!("stored inputs unreadable: {e}")))?;
        self.proof_run(actor, inputs).await
    }

    /// Ties a proven proof to a finding (made after the proof): the finding
    /// becomes proven, as if the proof had named it.
    pub(crate) fn link_proof(&self, proof_id: i64, finding_id: i64) -> Result<()> {
        let mut p = serde_json::Map::new();
        p.insert("finding_id".into(), json!(finding_id));
        self.store.write(|db| db.update_row("proofs", proof_id, &p))?;
        let mut f = serde_json::Map::new();
        f.insert("status".into(), json!("proven"));
        f.insert("proof_id".into(), json!(proof_id));
        f.insert("updated_ms".into(), json!(now_ms()));
        self.store.write(|db| db.update_row("findings", finding_id, &f))?;
        Ok(())
    }

    pub fn proof_get(&self, proof_id: i64) -> Result<Value> {
        let row = self
            .store
            .read(|db| db.row("proofs", proof_id))?
            .ok_or_else(|| ServiceError::NotFound(format!("proof {proof_id}")))?;
        Ok(decode_proof(&row))
    }

    pub fn proofs_for_finding(&self, finding_id: i64) -> Result<Vec<Value>> {
        Ok(self
            .store
            .read(|db| db.rows("proofs", Some(("finding_id", &json!(finding_id))), 100))?
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
            // A GraphQL query sent by POST only reads; anything else could change state.
            let (_, raw_body) = pm_http::split_message(&out.raw);
            let body = pm_http::decode_chunked(raw_body).unwrap_or_else(|| raw_body.to_vec());
            if !out.method.eq_ignore_ascii_case("POST") {
                return invalid("differential_authz only re-sends GET/HEAD/OPTIONS requests");
            }
            if let Err(why) = graphql_read_only(&body) {
                return invalid(format!(
                    "differential_authz only re-sends GET/HEAD/OPTIONS requests or GraphQL queries sent by POST ({why})"
                ));
            }
        }
        let graphql = !out.method.eq_ignore_ascii_case("GET") && !out.method.eq_ignore_ascii_case("HEAD");
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
        // GraphQL answers a refused query with 200 and an `errors` array, so judge it by the body.
        let status = |i: usize| match sends[i].status {
            Some(s) if graphql && graphql_refused(&resp(i)) && (200..300).contains(&s) => Some(401),
            other => other,
        };
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
            owner_statuses: [status(0), status(1)],
            attacker_status: status(2),
            anonymous_status: status(3),
            similarity: d.similarity,
            markers_found: found.clone(),
        });
        let ids = sends.iter().map(|s| s.exchange_id).collect();
        let details = json!({
            "owner": owner, "attacker": attacker,
            "statuses": { "owner": [status(0), status(1)], "attacker": status(2), "anonymous": status(3) },
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
        let public = self.store.read(|db| db.get_setting(OAST_SETTING))?;
        let dns_domain = self.store.read(|db| db.get_setting(OAST_DNS_SETTING))?;
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
            let hits = self.store.read(|db| db.rows("oast_interactions", Some(("token", &json!(token))), 20))?;
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
        let view = req.view_raw.as_deref().map(|v| self.outgoing(endpoint.clone(), v.as_bytes(), true)).transpose()?;
        let params = json!({
            "endpoint": format!("{}://{}:{}", endpoint.scheme, endpoint.host, endpoint.port),
            "raw": raw, "view_raw": req.view_raw, "identity": req.identity,
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
        let mut out = self.outgoing(endpoint.clone(), pm_proof::fill_xss_template(&raw, &token).as_bytes(), true)?;
        out.hypothesis_id = req.hypothesis_id;
        let (sent, _) = self.send_as(actor, &out, req.identity.as_deref(), true, "proof").await?;
        let mut exchange_ids = vec![sent.exchange_id];
        // Stored XSS: the payload shows on another page; that page is the one rendered.
        let (shown, page_url) = match &view {
            Some(v) => {
                let (seen, _) = self.send_as(actor, v, req.identity.as_deref(), true, "proof").await?;
                exchange_ids.push(seen.exchange_id);
                (seen, v.url())
            }
            None => (sent, out.url()),
        };
        // Render exactly what was recorded.
        let recorded = self.store.read(|db| db.get_exchange(shown.exchange_id))?.and_then(|e| e.response);
        let payload = pm_proof::xss_payload(&token);
        let mut inputs =
            pm_proof::ReflectionInputs { token: token.clone(), status: shown.status, ..Default::default() };
        let mut activity = Value::Null;
        let mut render_error = None;
        let mut blocked_total = 0;
        if let Some(mut doc) = recorded.as_deref().and_then(|r| recorded_document(&page_url, r)) {
            // The page's own scripts run too (DOM XSS goes through them).
            doc.resources = self.page_scripts(actor, &doc, &endpoint, req.identity.as_deref()).await;
            let body = String::from_utf8_lossy(&doc.body).into_owned();
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
        if verdict.proven && view.is_some() {
            verdict.reasons.push(format!("the first request stored the payload; it ran on {page_url}"));
        }
        if let Some(e) = &render_error {
            verdict.reasons.push(format!("browser error: {e}"));
        }
        let details = json!({
            "token": token, "payload": payload, "url": out.url(), "shown_on": page_url, "status": shown.status,
            "content_type": inputs.content_type, "token_in_body": inputs.token_in_body,
            "payload_in_body": inputs.payload_in_body, "rendered": inputs.rendered,
            "blocked_total": blocked_total, "page_activity": activity, "render_error": render_error,
        });
        Ok(Ok((verdict, exchange_ids, details)))
    }

    /// The page's same-origin scripts, so a render runs them: the recorded
    /// copy when there is one, else fetched once with a plain GET (the send
    /// still checks scope).
    async fn page_scripts(
        &self,
        actor: &Actor,
        doc: &pm_browser::Document,
        endpoint: &Endpoint,
        identity: Option<&str>,
    ) -> Vec<pm_browser::Resource> {
        let html = String::from_utf8_lossy(&doc.body).into_owned();
        let mut out = Vec::new();
        for src in pm_scan::active::script_srcs(&html, &doc.url) {
            let raw = match self.recorded_for_url(&src) {
                Some(r) => r,
                None => {
                    let Ok(u) = url::Url::parse(&src) else { continue };
                    let path = format!("{}{}", u.path(), u.query().map(|q| format!("?{q}")).unwrap_or_default());
                    let host = pm_core::authority(&endpoint.scheme, &endpoint.host, endpoint.port);
                    let get = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\n\r\n");
                    let Ok(o) = self.outgoing(endpoint.clone(), get.as_bytes(), true) else { continue };
                    match self.send_as(actor, &o, identity, true, "proof").await {
                        Ok((sent, _)) => match sent.response {
                            Some(r) => r,
                            None => continue,
                        },
                        Err(_) => continue,
                    }
                }
            };
            if let Some(d) = recorded_document(&src, &raw) {
                out.push(pm_browser::Resource { url: src, status: d.status, headers: d.headers, body: d.body });
            }
        }
        out
    }

    /// Error-based SQL injection: send the baseline, two quote payloads and a
    /// benign change; a database error that appears only with the quote proves
    /// the input reaches a SQL statement.
    #[allow(clippy::type_complexity)]
    async fn prove_sql_error(
        &self,
        actor: &Actor,
        req: &ProofRequest,
    ) -> Result<std::result::Result<(pm_proof::Verdict, Vec<i64>, Value), ProofResult>> {
        if req.raws.len() != 4 {
            return invalid("sql_error needs raws = [baseline, quote, second-quote, benign]");
        }
        let endpoint = self.proof_endpoint(req)?;
        let outs: Vec<_> =
            req.raws.iter().map(|r| self.outgoing(endpoint.clone(), r.as_bytes(), true)).collect::<Result<_>>()?;
        let params = json!({ "raws": req.raws, "identity": req.identity });
        match self.gate_proof(
            actor,
            "proof_sql_error",
            Tier::ActiveIntrusive,
            &outs[1],
            &params,
            req.approval_id.as_deref(),
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(Err(ProofResult::Denied { reasons })),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(Err(ProofResult::PendingApproval { approval_id, summary, reasons }));
            }
        }
        let mut sends = Vec::new();
        for out in &outs {
            sends.push(self.send_as(actor, out, req.identity.as_deref(), true, "proof").await?.0);
        }
        let responses: Vec<Vec<u8>> = sends.iter().map(|s| s.response.clone().unwrap_or_default()).collect();
        let (verdict, mut details) = judge_sql_error(&responses);
        let ids: Vec<i64> = sends.iter().map(|s| s.exchange_id).collect();
        details["exchanges"] = json!(ids);
        Ok(Ok((verdict, ids, details)))
    }

    /// Boolean-condition injection: send the baseline, a tautology and a
    /// contradiction, twice. Proven when the tautology returns the normal page
    /// and the contradiction a clearly different one, consistently.
    #[allow(clippy::type_complexity)]
    async fn prove_boolean(
        &self,
        actor: &Actor,
        req: &ProofRequest,
    ) -> Result<std::result::Result<(pm_proof::Verdict, Vec<i64>, Value), ProofResult>> {
        if req.raws.len() != 3 {
            return invalid("boolean_injection needs raws = [baseline, true-condition, false-condition]");
        }
        let endpoint = self.proof_endpoint(req)?;
        let base = self.outgoing(endpoint.clone(), req.raws[0].as_bytes(), true)?;
        let tcond = self.outgoing(endpoint.clone(), req.raws[1].as_bytes(), true)?;
        let fcond = self.outgoing(endpoint, req.raws[2].as_bytes(), true)?;
        let params = json!({ "raws": req.raws, "identity": req.identity });
        match self.gate_proof(
            actor,
            "proof_boolean",
            Tier::ActiveIntrusive,
            &tcond,
            &params,
            req.approval_id.as_deref(),
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(Err(ProofResult::Denied { reasons })),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(Err(ProofResult::PendingApproval { approval_id, summary, reasons }));
            }
        }
        let mut ids = Vec::new();
        let mut rounds = Vec::new();
        for _ in 0..2 {
            let mut round: [Vec<u8>; 3] = Default::default();
            for (slot, out) in round.iter_mut().zip([&base, &tcond, &fcond]) {
                let (sent, _) = self.send_as(actor, out, req.identity.as_deref(), true, "proof").await?;
                ids.push(sent.exchange_id);
                *slot = sent.response.unwrap_or_default();
            }
            rounds.push(round);
        }
        let (verdict, mut details) = judge_boolean(&rounds, &req.raws);
        details["exchanges"] = json!(ids);
        Ok(Ok((verdict, ids, details)))
    }

    /// Path traversal: read known files and confirm a bogus name reads nothing.
    #[allow(clippy::type_complexity)]
    async fn prove_traversal(
        &self,
        actor: &Actor,
        req: &ProofRequest,
    ) -> Result<std::result::Result<(pm_proof::Verdict, Vec<i64>, Value), ProofResult>> {
        if req.raws.len() < 3 || req.markers.len() != req.raws.len() - 2 {
            return invalid(
                "path_traversal needs raws = [baseline, control, file-1, …] and one marker per file request",
            );
        }
        let endpoint = self.proof_endpoint(req)?;
        let outs: Vec<_> =
            req.raws.iter().map(|r| self.outgoing(endpoint.clone(), r.as_bytes(), true)).collect::<Result<_>>()?;
        let params = json!({ "raws": req.raws, "markers": req.markers, "identity": req.identity });
        // The first file request carries the traversal payload: gate on it.
        match self.gate_proof(
            actor,
            "proof_traversal",
            Tier::ActiveIntrusive,
            &outs[2],
            &params,
            req.approval_id.as_deref(),
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(Err(ProofResult::Denied { reasons })),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(Err(ProofResult::PendingApproval { approval_id, summary, reasons }));
            }
        }
        let mut sends = Vec::new();
        for out in &outs {
            sends.push(self.send_as(actor, out, req.identity.as_deref(), true, "proof").await?.0);
        }
        let responses: Vec<Vec<u8>> = sends.iter().map(|s| s.response.clone().unwrap_or_default()).collect();
        let (verdict, mut details) = judge_traversal(&req.raws, &req.markers, &responses);
        let ids: Vec<i64> = sends.iter().map(|s| s.exchange_id).collect();
        details["exchanges"] = json!(ids);
        Ok(Ok((verdict, ids, details)))
    }

    /// Expression oracle (template injection): arithmetic on random numbers is
    /// evaluated only if the input reaches a template or code evaluator.
    #[allow(clippy::type_complexity)]
    async fn prove_expression(
        &self,
        actor: &Actor,
        req: &ProofRequest,
    ) -> Result<std::result::Result<(pm_proof::Verdict, Vec<i64>, Value), ProofResult>> {
        if req.raws.len() < 3 || req.markers.len() != req.raws.len() - 2 || req.markers.iter().any(|m| m.len() < 5) {
            return invalid(
                "expression needs raws = [baseline, control, payload-1, …] and one expected result (5+ digits) per \
                 payload request",
            );
        }
        let endpoint = self.proof_endpoint(req)?;
        let outs: Vec<_> =
            req.raws.iter().map(|r| self.outgoing(endpoint.clone(), r.as_bytes(), true)).collect::<Result<_>>()?;
        let params = json!({ "raws": req.raws, "markers": req.markers, "identity": req.identity });
        match self.gate_proof(
            actor,
            "proof_expression",
            Tier::ActiveIntrusive,
            &outs[2],
            &params,
            req.approval_id.as_deref(),
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(Err(ProofResult::Denied { reasons })),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(Err(ProofResult::PendingApproval { approval_id, summary, reasons }));
            }
        }
        let mut sends = Vec::new();
        for out in &outs {
            sends.push(self.send_as(actor, out, req.identity.as_deref(), true, "proof").await?.0);
        }
        let responses: Vec<Vec<u8>> = sends.iter().map(|s| s.response.clone().unwrap_or_default()).collect();
        let (verdict, mut details) = judge_expression(&req.markers, &responses);
        let ids: Vec<i64> = sends.iter().map(|s| s.exchange_id).collect();
        details["exchanges"] = json!(ids);
        Ok(Ok((verdict, ids, details)))
    }

    /// Marker oracle: inject a fresh random marker and check it reaches the one
    /// dangerous place — the redirect target's host, an injected response
    /// header, or a reflected absolute URL.
    #[allow(clippy::type_complexity)]
    async fn prove_marker(
        &self,
        actor: &Actor,
        req: &ProofRequest,
    ) -> Result<std::result::Result<(pm_proof::Verdict, Vec<i64>, Value), ProofResult>> {
        let raw =
            req.raw.clone().ok_or_else(|| ServiceError::Invalid("marker needs raw containing {{marker}}".into()))?;
        if !raw.contains("{{marker}}") {
            return invalid("put {{marker}} in raw where a fresh random value should go");
        }
        let kind = req.marker_kind.clone().unwrap_or_default();
        if !MARKER_KINDS.contains(&kind.as_str()) {
            return invalid("marker_kind must be \"redirect\", \"crlf\", \"host\" or \"cors\"");
        }
        let endpoint = self.proof_endpoint(req)?;
        let template = self.outgoing(endpoint.clone(), raw.as_bytes(), true)?;
        let params = json!({ "raw": raw, "marker_kind": kind, "identity": req.identity });
        match self.gate_proof(
            actor,
            "proof_marker",
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
        let marker = marker_token()?;
        let filled = raw.replace("{{marker}}", &marker);
        let out = self.outgoing(endpoint, filled.as_bytes(), true)?;
        let (sent, _) = self.send_as(actor, &out, req.identity.as_deref(), true, "proof").await?;
        let resp = sent.response.clone().unwrap_or_default();
        let (verdict, mut details) = judge_marker(&kind, &marker, &resp, &out.endpoint.host);
        details["exchange"] = json!(sent.exchange_id);
        Ok(Ok((verdict, vec![sent.exchange_id], details)))
    }

    /// Endpoint for an oracle that works from a template, from exchange_id or url.
    fn proof_endpoint(&self, req: &ProofRequest) -> Result<Endpoint> {
        match (req.exchange_id, &req.url) {
            (Some(id), _) => Ok(self.exchange_outgoing(id)?.0.endpoint),
            (None, Some(u)) => parse_url_endpoint(u),
            _ => invalid("needs exchange_id or url"),
        }
    }

    /// Where payloads should send callbacks (the OAST listener's public URL).
    pub fn set_oast_public_url(&self, url: &str) -> Result<()> {
        url::Url::parse(url).map_err(|e| ServiceError::Invalid(format!("bad OAST url: {e}")))?;
        self.store.write(|db| db.set_setting(OAST_SETTING, url))?;
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
        self.store.write(|db| db.set_setting(OAST_DNS_SETTING, &d))?;
        Ok(())
    }

    /// Stores an OAST interaction (called by the OAST listener).
    /// Records a callback. When it is the first for a scanner probe whose
    /// scan stopped waiting already, it becomes a suspected finding now:
    /// blind bugs (queued jobs, log processors, nightly imports) often call
    /// back minutes or hours later.
    pub fn record_oast(&self, i: &pm_oast::Interaction) -> Result<()> {
        let late = self.store.write(|store| -> Result<_> {
            if !record_oast_in(store, i)? {
                return Ok(None);
            }
            let first = store.count_rows("oast_interactions", Some(("token", &json!(i.token))))? == 1;
            let probe = store.rows("oast_probes", Some(("token", &json!(i.token))), 1)?.into_iter().next();
            Ok(probe.filter(|p| {
                first
                    && p.get("finding_id").is_none_or(Value::is_null)
                    // At or after the deadline: the scan has stopped waiting by then.
                    && p.get("deadline_ms").and_then(Value::as_i64).is_some_and(|d| i.ts_ms >= d)
            }))
        })?;
        let Some(p) = late else { return Ok(()) };
        let s = |k: &str| p.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let after = (i.ts_ms - p.get("deadline_ms").and_then(Value::as_i64).unwrap_or(i.ts_ms)) / 1000;
        let actor = pm_policy::Actor::parse(&s("actor"))
            .or_else(|_| pm_policy::Actor::parse("human:oast"))
            .map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let exchange = p.get("exchange_id").and_then(Value::as_i64);
        let finding = self.finding_create(
            &actor,
            crate::NewFinding {
                title: format!("{} in {} ({}): late callback", s("title"), s("url"), s("point")),
                vuln_class: s("vuln_class"),
                severity: s("severity"),
                description: format!(
                    "The scanner sent {:?} in {}. The callback came {after} s after the scan stopped waiting: {} {} \
                     {} from {}. Found from a late out-of-band callback; not proven yet (retest with proof_run \
                     oast).",
                    s("payload"),
                    s("point"),
                    i.protocol.to_uppercase(),
                    i.method,
                    i.path,
                    i.remote
                ),
                url: Some(s("url")),
                evidence: exchange.into_iter().collect(),
                hypothesis_id: None,
            },
        )?;
        let id = finding["id"].as_i64();
        if let (Some(row), Some(fid)) = (p.get("id").and_then(Value::as_i64), id) {
            let mut changes = serde_json::Map::new();
            changes.insert("finding_id".into(), json!(fid));
            self.store.write(|db| db.update_row("oast_probes", row, &changes))?;
        }
        self.audit(&actor.id(), "oast_late_callback", json!({ "token": i.token, "finding_id": id }), "ok")?;
        Ok(())
    }

    /// Stores the out-of-band probes a scan sent (for late callbacks), at
    /// most 200 000 in a project.
    pub(crate) fn remember_oob_probes(
        &self,
        actor: &pm_policy::Actor,
        url: &str,
        deadline_ms: i64,
        sent: &[(&pm_scan::oob::OobProbe, i64)],
    ) -> Result<()> {
        self.store.write(|store| -> Result<()> {
            if store.count_rows("oast_probes", None)? >= 200_000 {
                return Ok(());
            }
            for (p, exchange_id) in sent {
                let issue = pm_scan::oob::issue(p, "");
                let mut row = serde_json::Map::new();
                for (k, v) in [
                    ("token", json!(p.token)),
                    ("check_name", json!(p.probe.check)),
                    ("vuln_class", json!(pm_scan::oob::class(p.probe.check))),
                    ("title", json!(issue.title)),
                    ("severity", json!(issue.severity)),
                    ("url", json!(url)),
                    ("point", json!(issue.point)),
                    ("payload", json!(p.probe.payload)),
                    ("exchange_id", json!(exchange_id)),
                    ("actor", json!(actor.id())),
                    ("deadline_ms", json!(deadline_ms)),
                    ("created_ms", json!(pm_core::now_ms())),
                ] {
                    row.insert(k.into(), v);
                }
                store.insert_row("oast_probes", &row)?;
            }
            Ok(())
        })
    }
}

/// A fresh, unguessable token (so a page can't fake a proof).
fn xss_token() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 10];
    SystemRandom::new().fill(&mut b).map_err(|_| ServiceError::Invalid("no system randomness".into()))?;
    Ok(format!("pm{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()))
}

/// A fresh, unguessable marker safe to use inside a host label (letters and
/// digits only) so a reflected copy can only have come from our injection.
pub(crate) fn marker_token() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 8];
    SystemRandom::new().fill(&mut b).map_err(|_| ServiceError::Invalid("no system randomness".into()))?;
    Ok(format!("pm{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()))
}

/// Where a marker has to land for the marker oracle to count it a hit.
#[derive(Debug, Clone, Copy)]
enum MarkerHit {
    /// The redirect target's host contains the marker (open redirect).
    RedirectHost,
    /// A response header name or value contains the marker (CRLF injection).
    ResponseHeader,
    /// The marker is reflected in a Location or absolute URL (Host injection).
    Reflected,
    /// `Access-Control-Allow-Origin` names the marker's origin and credentials
    /// are allowed (any site can read the user's data).
    TrustedOrigin,
}

/// Decides whether `marker` reached the dangerous place in a recorded
/// response, and returns short printable evidence. `self_host` is the target's
/// own host, so a redirect back to it is not counted.
fn marker_lands(resp: &[u8], marker: &str, kind: MarkerHit, self_host: &str) -> (bool, String) {
    let (head, _) = pm_http::split_message(resp);
    let Ok(parsed) = pm_http::parse_response_head(head) else {
        return (false, "could not parse the response".into());
    };
    let header = |name: &str| {
        parsed
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(&h.value).into_owned())
    };
    match kind {
        MarkerHit::RedirectHost => {
            let Some(loc) = header("location") else { return (false, "no Location header".into()) };
            let host = url::Url::parse(&loc)
                .ok()
                .and_then(|u| u.host_str().map(str::to_string))
                .or_else(|| loc.trim_start_matches(['/', '\\']).split(['/', '?', '#']).next().map(str::to_string))
                .unwrap_or_default();
            let hit = host.contains(marker) && !host.eq_ignore_ascii_case(self_host);
            (hit, format!("Location: {}", loc.chars().take(120).collect::<String>()))
        }
        MarkerHit::ResponseHeader => {
            let found = parsed.headers.iter().find(|h| {
                h.name.to_ascii_lowercase().contains(marker)
                    || String::from_utf8_lossy(&h.value).to_ascii_lowercase().contains(marker)
            });
            match found {
                Some(h) => (true, format!("response header {}: {}", h.name, String::from_utf8_lossy(&h.value))),
                None => (false, "no response header carried the marker".into()),
            }
        }
        MarkerHit::Reflected => {
            if let Some(loc) = header("location").filter(|l| l.contains(marker)) {
                return (true, format!("Location: {}", loc.chars().take(120).collect::<String>()));
            }
            // Only an absolute URL counts: a page that echoes request headers
            // back (a debug page, an API mirror) shows the bare value too.
            let body = body_text(resp);
            let hit = body.contains(&format!("//{marker}"));
            let detail = if hit {
                format!("marker reflected in an absolute URL (//{marker}…)")
            } else if body.contains(marker) {
                "the marker is echoed, but not as a link or redirect host".into()
            } else {
                "not reflected".into()
            };
            (hit, detail)
        }
        MarkerHit::TrustedOrigin => {
            let Some(acao) = header("access-control-allow-origin") else {
                return (false, "no Access-Control-Allow-Origin header".into());
            };
            let creds =
                header("access-control-allow-credentials").is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
            let named = acao.contains(marker);
            let detail = format!(
                "Access-Control-Allow-Origin: {}, Access-Control-Allow-Credentials: {}",
                acao.chars().take(120).collect::<String>(),
                if creds { "true" } else { "absent" }
            );
            (named && creds, detail)
        }
    }
}

// The verdicts below work on raw responses, so a proof run and a regression
// test (`regress.rs`) that re-sends a proof's requests judge them alike.

/// The body of a raw response as text: de-chunked and decompressed.
pub(crate) fn body_text(resp: &[u8]) -> String {
    let (head, body) = pm_http::split_message(resp);
    match pm_http::parse_response_head(head) {
        Ok(h) => String::from_utf8_lossy(&pm_ai::body::decode(&h.headers, body).bytes).into_owned(),
        Err(_) => String::from_utf8_lossy(body).into_owned(),
    }
}

/// The status code of a raw response.
pub(crate) fn status_of(resp: &[u8]) -> Option<u16> {
    pm_http::parse_response_head(pm_http::split_message(resp).0).ok().map(|h| h.status)
}

/// Error-based SQL injection, from the responses to
/// `[baseline, quote, second quote, benign change]`.
pub(crate) fn judge_sql_error(responses: &[Vec<u8>]) -> (pm_proof::Verdict, Value) {
    let db_error =
        |i: usize| responses.get(i).is_some_and(|r| pm_scan::error_signature(&body_text(r)).is_some_and(|e| e.1));
    let inputs = pm_proof::SqlErrorInputs {
        control_clean: !db_error(0),
        quote_error: db_error(1),
        second_quote_error: db_error(2),
        benign_clean: !db_error(3),
    };
    let details = json!({
        "control_clean": inputs.control_clean, "quote_error": inputs.quote_error,
        "second_quote_error": inputs.second_quote_error, "benign_clean": inputs.benign_clean,
    });
    (pm_proof::sql_error(&inputs), details)
}

/// Boolean-condition injection, from two rounds of responses to
/// `[baseline, true condition, false condition]` (`requests`, the same three
/// requests, when known). A page that echoes its input differs between the
/// two conditions by the echo alone, so an echoed condition is masked in
/// both answers before they are compared.
pub(crate) fn judge_boolean(rounds: &[[Vec<u8>; 3]], requests: &[String]) -> (pm_proof::Verdict, Value) {
    let mut echoed = None;
    let masked: Vec<[Vec<u8>; 3]>;
    let rounds = match (requests.get(1), requests.get(2)) {
        (Some(t), Some(f)) => {
            masked = rounds
                .iter()
                .map(|r| match mask_echo(t, f, &r[1], &r[2]) {
                    Some((mt, mf, window)) => {
                        echoed = Some(window);
                        [r[0].clone(), mt, mf]
                    }
                    None => r.clone(),
                })
                .collect();
            &masked[..]
        }
        _ => rounds,
    };
    let split = |r: &[Vec<u8>; 3]| {
        let noise = pm_diff::learn_noise(&r[0], &r[1]);
        let sim = |a: &[u8], b: &[u8]| pm_diff::diff(a, b, &noise).similarity;
        (sim(&r[0], &r[1]), sim(&r[0], &r[2]), sim(&r[1], &r[2]))
    };
    let empty: [Vec<u8>; 3] = Default::default();
    let (first, second) = (rounds.first().unwrap_or(&empty), rounds.get(1).unwrap_or(&empty));
    let (ts1, fs1, tf1) = split(first);
    let (ts2, _, tf2) = split(second);
    let inputs = pm_proof::BooleanInputs {
        true_similarity: ts1,
        false_similarity: fs1,
        true_false_similarity: tf1,
        status_true: status_of(&first[1]),
        status_false: status_of(&first[2]),
        repeated_consistent: rounds.len() >= 2 && ts1 >= 0.9 && ts2 >= 0.9 && tf1 <= 0.85 && tf2 <= 0.85,
    };
    let details = json!({
        "true_similarity": ts1, "false_similarity": fs1, "true_false_similarity": tf1,
        "round2": { "true_similarity": ts2, "true_false_similarity": tf2 },
        "statuses": { "true": inputs.status_true, "false": inputs.status_false },
        "echoed_condition": echoed,
    });
    (pm_proof::boolean_injection(&inputs), details)
}

/// Where the true and false requests differ, the longest stretch around the
/// difference (decoded, as is or HTML-escaped) that each answer echoes back:
/// both answers with it replaced by the same placeholder, and the stretch.
fn mask_echo(t_req: &str, f_req: &str, t_resp: &[u8], f_resp: &[u8]) -> Option<(Vec<u8>, Vec<u8>, String)> {
    let (t, f): (Vec<char>, Vec<char>) =
        (percent_decode(t_req).chars().collect(), percent_decode(f_req).chars().collect());
    let prefix = t.iter().zip(&f).take_while(|(a, b)| a == b).count();
    let suffix = t.iter().rev().zip(f.iter().rev()).take_while(|(a, b)| a == b).count();
    let (t_end, f_end) = (t.len().saturating_sub(suffix).max(prefix), f.len().saturating_sub(suffix).max(prefix));
    if t_end == prefix && f_end == prefix {
        return None;
    }
    let (t_text, f_text) = (String::from_utf8_lossy(t_resp).into_owned(), String::from_utf8_lossy(f_resp).into_owned());
    let found = |text: &str, s: &str| html_forms(s).into_iter().find(|v| text.contains(v.as_str()));
    // Longest window first; at least 4 characters so a lone digit isn't "echoed".
    let mut best: Option<(usize, String, String, String)> = None;
    for left in 0..=16usize.min(prefix) {
        for right in 0..=16usize.min(suffix) {
            let tw: String = t[prefix - left..t_end + right].iter().collect();
            let fw: String = f[prefix - left..f_end + right].iter().collect();
            if tw.chars().count() < 4 || best.as_ref().is_some_and(|b| b.0 >= left + right) {
                continue;
            }
            if let (Some(tv), Some(fv)) = (found(&t_text, &tw), found(&f_text, &fw)) {
                best = Some((left + right, tw, tv, fv));
            }
        }
    }
    let (_, window, tv, fv) = best?;
    let placeholder = "\u{1}pm-echo\u{1}";
    Some((t_text.replace(&tv, placeholder).into_bytes(), f_text.replace(&fv, placeholder).into_bytes(), window))
}

/// `s` as is and HTML-escaped the usual ways.
fn html_forms(s: &str) -> Vec<String> {
    let base = s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
    let mut out = vec![s.to_string()];
    for q in ["&#39;", "&#x27;", "&apos;"] {
        let v = base.replace('\'', q);
        if !out.contains(&v) {
            out.push(v);
        }
    }
    out
}

/// Path traversal, from the responses to `[baseline, bogus name, file 1, …]`
/// (`raws` are the requests, `markers[n]` what proves file n was read).
pub(crate) fn judge_traversal(
    raws: &[String],
    markers: &[String],
    responses: &[Vec<u8>],
) -> (pm_proof::Verdict, Value) {
    let empty = Vec::new();
    let resp = |i: usize| responses.get(i).unwrap_or(&empty);
    let (baseline_body, control_body) = (body_text(resp(0)), body_text(resp(1)));
    let noise = pm_diff::learn_noise(resp(0), resp(0));
    let mut markers_found = Vec::new();
    let mut differs = false;
    for (i, m) in markers.iter().enumerate() {
        if body_text(resp(i + 2)).contains(m.as_str()) && !baseline_body.contains(m.as_str()) {
            let line = raws.get(i + 2).and_then(|r| r.lines().next()).unwrap_or_default();
            markers_found.push(format!("{line:?}: {m}"));
            differs |= pm_diff::diff(resp(0), resp(i + 2), &noise).similarity < 0.9;
        }
    }
    // The bogus name must not read any of the files back.
    let control_clean = !markers.iter().any(|m| control_body.contains(m.as_str()));
    let details = json!({ "markers_found": markers_found, "control_clean": control_clean });
    let inputs = pm_proof::TraversalInputs { markers_found, control_clean, differs_from_baseline: differs };
    (pm_proof::path_traversal(&inputs), details)
}

/// Template injection, from the responses to `[baseline, control, payload
/// 1, …]`; `products[n]` is what payload n evaluates to.
pub(crate) fn judge_expression(products: &[String], responses: &[Vec<u8>]) -> (pm_proof::Verdict, Value) {
    let empty = Vec::new();
    let body = |i: usize| body_text(responses.get(i).unwrap_or(&empty));
    let (baseline, control) = (body(0), body(1));
    let products_found: Vec<bool> =
        products.iter().enumerate().map(|(i, p)| body(i + 2).contains(p.as_str())).collect();
    let inputs = pm_proof::ExpressionInputs {
        syntax: "the injected expression".into(),
        products_found: products_found.clone(),
        baseline_clean: !products.iter().any(|p| baseline.contains(p.as_str())),
        control_clean: !products.iter().any(|p| control.contains(p.as_str())),
    };
    let details = json!({
        "products": products, "products_found": products_found,
        "baseline_clean": inputs.baseline_clean, "control_clean": inputs.control_clean,
    });
    (pm_proof::expression(&inputs), details)
}

/// The kinds the marker oracle knows.
pub(crate) const MARKER_KINDS: &[&str] = &["redirect", "crlf", "host", "cors"];

/// The marker oracle, from the response to the request that carried `marker`.
/// `kind` is one of [`MARKER_KINDS`] (anything else is never a hit).
pub(crate) fn judge_marker(kind: &str, marker: &str, resp: &[u8], self_host: &str) -> (pm_proof::Verdict, Value) {
    let (label, place) = match kind {
        "redirect" => ("open redirect", Some(MarkerHit::RedirectHost)),
        "crlf" => ("CRLF header injection", Some(MarkerHit::ResponseHeader)),
        "host" => ("Host-header injection", Some(MarkerHit::Reflected)),
        "cors" => ("CORS trusts any origin", Some(MarkerHit::TrustedOrigin)),
        _ => ("marker", None),
    };
    let (hit, detail) = match place {
        Some(p) => marker_lands(resp, marker, p, self_host),
        None => (false, format!("unknown marker kind {kind:?}")),
    };
    let verdict = pm_proof::marker(&pm_proof::MarkerInputs {
        label: label.into(),
        marker: marker.into(),
        hit,
        control_hit: false,
        detail: detail.clone(),
    });
    (verdict, json!({ "marker": marker, "marker_kind": kind, "hit": hit, "detail": detail }))
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

/// At most this many callbacks are kept per token, and in all: anyone who
/// can reach the OAST listener can send made-up ones.
const OAST_PER_TOKEN: u64 = 20;
const OAST_TOTAL: u64 = 100_000;

/// Stores a callback; `false` when it was dropped (over a cap).
pub fn record_oast_in(store: &mut pm_store::Store, i: &pm_oast::Interaction) -> Result<bool> {
    if store.count_rows("oast_interactions", Some(("token", &json!(i.token))))? >= OAST_PER_TOKEN
        || store.count_rows("oast_interactions", None)? >= OAST_TOTAL
    {
        return Ok(false);
    }
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
    Ok(true)
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

/// A 2xx GraphQL response whose every result has errors and no data: the
/// server refused the query even though HTTP says 200.
fn graphql_refused(response: &[u8]) -> bool {
    let body = pm_http::split_message(response).1;
    let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
    let Ok(v) = serde_json::from_slice::<Value>(&body) else { return false };
    let results: Vec<&Value> = match &v {
        Value::Array(a) => a.iter().collect(),
        other => vec![other],
    };
    !results.is_empty()
        && results.iter().all(|r| {
            r.get("errors").and_then(Value::as_array).is_some_and(|e| !e.is_empty())
                && r.get("data").is_none_or(Value::is_null)
        })
}

/// Whether a request body is a GraphQL request (or a batch of them) that can
/// only read: JSON with a string `query` field whose document has no
/// `mutation` or `subscription` operation. Conservative: anything it can't
/// parse is refused, with the reason.
fn graphql_read_only(body: &[u8]) -> std::result::Result<(), String> {
    let v: Value = serde_json::from_slice(body).map_err(|_| "the body is not JSON".to_string())?;
    let items: Vec<&Value> = match &v {
        Value::Array(a) if !a.is_empty() => a.iter().collect(),
        Value::Array(_) => return Err("empty GraphQL batch".into()),
        other => vec![other],
    };
    for item in items {
        let doc = item
            .get("query")
            .and_then(Value::as_str)
            .ok_or_else(|| "the JSON body has no string \"query\" field, so it isn't a GraphQL query".to_string())?;
        graphql_document_read_only(doc)?;
    }
    Ok(())
}

/// Scans a GraphQL document, skipping comments and string values (including
/// block strings), and refuses a `mutation` or `subscription` keyword outside
/// any braces, parentheses or brackets (an operation definition).
fn graphql_document_read_only(doc: &str) -> std::result::Result<(), String> {
    let c: Vec<char> = doc.chars().collect();
    let (mut i, mut depth) = (0usize, 0i64);
    while i < c.len() {
        match c[i] {
            '#' => {
                while i < c.len() && c[i] != '\n' && c[i] != '\r' {
                    i += 1;
                }
            }
            '"' => {
                if c[i..].starts_with(&['"', '"', '"']) {
                    i += 3;
                    loop {
                        if i >= c.len() {
                            return Err("unterminated GraphQL block string".into());
                        }
                        if c[i..].starts_with(&['\\', '"', '"', '"']) {
                            i += 4;
                        } else if c[i..].starts_with(&['"', '"', '"']) {
                            i += 3;
                            break;
                        } else {
                            i += 1;
                        }
                    }
                } else {
                    i += 1;
                    loop {
                        match c.get(i) {
                            None | Some('\n') => return Err("unterminated GraphQL string".into()),
                            Some('\\') => i += 2,
                            Some('"') => {
                                i += 1;
                                break;
                            }
                            Some(_) => i += 1,
                        }
                    }
                }
            }
            '{' | '(' | '[' => {
                depth += 1;
                i += 1;
            }
            '}' | ')' | ']' => {
                depth -= 1;
                if depth < 0 {
                    return Err("unbalanced GraphQL document".into());
                }
                i += 1;
            }
            ch if ch.is_ascii_alphabetic() || ch == '_' => {
                let start = i;
                while i < c.len() && (c[i].is_ascii_alphanumeric() || c[i] == '_') {
                    i += 1;
                }
                let word: String = c[start..i].iter().collect();
                if depth == 0 && matches!(word.as_str(), "mutation" | "subscription") {
                    return Err(format!("the document has a {word} operation"));
                }
            }
            _ => i += 1,
        }
    }
    if depth != 0 {
        return Err("unbalanced GraphQL document".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gql(doc: &str) -> Vec<u8> {
        json!({ "query": doc }).to_string().into_bytes()
    }

    #[test]
    fn graphql_queries_are_read_only_and_mutations_are_not() {
        for ok in [
            "{ invoice(id: 5001) { total } }",
            "query Q { a }",
            "# hi\nquery { a }",
            "{ search(q: \"mutation\") { id } }",
        ] {
            assert_eq!(graphql_read_only(&gql(ok)), Ok(()), "{ok}");
        }
        for bad in [
            "mutation { delete(id:1) }",
            "# comment\nmutation M { x }",
            "{ a }\nmutation M { x }",
            "subscription S { x }",
            "query Q { a } mutation { b }",
            "{ a",
        ] {
            assert!(graphql_read_only(&gql(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn graphql_batches_need_every_element_to_be_a_query() {
        let ok = br#"[{"query":"{ a }"},{"query":"query B { b }"}]"#;
        assert_eq!(graphql_read_only(ok), Ok(()));
        let bad = br#"[{"query":"{ a }"},{"query":"mutation { b }"}]"#;
        assert!(graphql_read_only(bad).is_err());
        assert!(graphql_read_only(b"[]").is_err());
        assert!(graphql_read_only(br#"[{"query":"{ a }"},{"id":"abc"}]"#).is_err());
    }

    #[test]
    fn graphql_errors_without_data_count_as_refused() {
        let resp = |b: &str| format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{b}", b.len()).into_bytes();
        assert!(graphql_refused(&resp(r#"{"errors":[{"message":"not logged in"}],"data":null}"#)));
        assert!(!graphql_refused(&resp(r#"{"data":{"me":{"id":"1"}}}"#)));
        assert!(!graphql_refused(&resp(r#"{"errors":[{"message":"x"}],"data":{"a":1}}"#)));
        assert!(!graphql_refused(&resp("not json")));
    }

    #[test]
    fn non_graphql_post_bodies_are_refused() {
        assert!(graphql_read_only(b"a=1&b=2").is_err());
        assert!(graphql_read_only(br#"{"name":"x"}"#).is_err());
        assert!(graphql_read_only(br#"{"query":5}"#).is_err());
    }

    fn page(body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len()).into_bytes()
    }

    #[test]
    fn an_echoed_condition_is_not_a_boolean_split() {
        let req = |v: &str| format!("GET /s?q=guest{v} HTTP/1.1\r\nHost: x\r\n\r\n");
        let raws = vec![req(""), req("%27%20AND%20%271%27%3D%271"), req("%27%20AND%20%271%27%3D%272")];
        // An echo page, HTML-escaping the quote: only the echo differs.
        let echo = |v: &str| page(&format!("<p>You searched for {}</p>", v.replace('\'', "&#39;")));
        let round = [echo("guest"), echo("guest' AND '1'='1"), echo("guest' AND '1'='2")];
        let (v, d) = judge_boolean(&[round.clone(), round], &raws);
        assert!(!v.proven, "{:?}", v.reasons);
        assert!(d["echoed_condition"].is_string(), "{d}");
        // A real split echoes the term too, but the rows differ as well.
        let rows = "<ul><li>Green tea, loose leaf, 100 g</li><li>Black tea, Assam, 250 g</li></ul>";
        let real = |v: &str, hit: bool| {
            let shown = v.replace('\'', "&#39;");
            page(&format!("<p>You searched for {shown}</p>{}", if hit { rows } else { "<p>No results.</p>" }))
        };
        let round = [real("guest", true), real("guest' AND '1'='1", true), real("guest' AND '1'='2", false)];
        let (v, _) = judge_boolean(&[round.clone(), round], &raws);
        assert!(v.proven, "{:?}", v.reasons);
    }

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

    #[test]
    fn oast_callbacks_are_capped_per_token() {
        let mut store = pm_store::Store::open_in_memory().unwrap();
        let hit = |token: &str| pm_oast::Interaction {
            token: token.into(),
            protocol: "http".into(),
            remote: "203.0.113.9:1".into(),
            method: "GET".into(),
            path: format!("/{token}"),
            ts_ms: 1,
            raw: String::new(),
        };
        let (a, b) = (pm_oast::new_token(), pm_oast::new_token());
        for _ in 0..(OAST_PER_TOKEN + 5) {
            record_oast_in(&mut store, &hit(&a)).unwrap();
        }
        record_oast_in(&mut store, &hit(&b)).unwrap();
        let count = |t: &str| store.count_rows("oast_interactions", Some(("token", &json!(t)))).unwrap();
        assert_eq!((count(&a), count(&b)), (OAST_PER_TOKEN, 1));
    }
}
