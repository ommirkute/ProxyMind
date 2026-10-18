//! The application model and the ledger, built from the project's traffic.

use std::collections::BTreeMap;

use pm_identity::Identity;
use pm_ledger::{Coverage, Hypothesis, OperationInfo};
use pm_model::{AppModel, AuthzCandidate, Observation};
use pm_policy::Actor;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError, now_ms};

/// How many recent exchanges the model is built from.
const MODEL_WINDOW: usize = 20_000;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ModelFilter {
    /// Only operations whose key contains this text.
    pub contains: Option<String>,
    /// Include objects (default false; there can be many).
    pub include_objects: Option<bool>,
    /// Only objects of this type, e.g. Order.
    pub object_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewHypothesis {
    /// Operation key from model_get, e.g. "GET http://shop/api/orders/{id}".
    pub operation: String,
    #[serde(default)]
    pub param: String,
    /// idor, bfla, authn, sqli, xss, ssrf, mass_assignment, business_logic, or your own.
    pub vuln_class: String,
    pub rationale: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisUpdate {
    pub id: i64,
    /// open, testing, confirmed, refuted
    pub status: Option<String>,
    pub note: Option<String>,
}

fn decode_hypothesis(row: &serde_json::Map<String, Value>) -> Hypothesis {
    let s = |k: &str| row.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let i = |k: &str| row.get(k).and_then(Value::as_i64).unwrap_or_default();
    Hypothesis {
        id: i("id"),
        operation: s("operation"),
        param: s("param"),
        vuln_class: s("vuln_class"),
        rationale: s("rationale"),
        status: s("status"),
        actor: s("actor"),
        notes: serde_json::from_str(&s("notes")).unwrap_or_default(),
        evidence: Vec::new(),
        created_ms: i("created_ms"),
        updated_ms: i("updated_ms"),
    }
}

impl Service {
    /// Builds the application model. Exchanges recorded through the proxy
    /// are attributed to an identity when their credentials match one.
    pub fn model(&self) -> Result<AppModel> {
        let (exchanges, identities) = {
            let store = self.store.lock();
            let ids: Vec<Identity> = store
                .list_identities()?
                .iter()
                .filter_map(|r| serde_json::from_str::<Identity>(&r.data).ok())
                .collect();
            (store.recent_exchanges(MODEL_WINDOW)?, ids)
        };
        let resolved: Vec<Option<String>> = exchanges
            .iter()
            .map(|e| e.summary.identity.clone().or_else(|| resolve_identity(&e.request, &identities)))
            .collect();
        let obs: Vec<Observation> = exchanges
            .iter()
            .zip(&resolved)
            .filter(|(e, _)| e.summary.source != "authz" && e.summary.source != "proof")
            .map(|(e, who)| Observation {
                exchange_id: e.summary.id,
                method: &e.summary.method,
                scheme: &e.summary.scheme,
                host: &e.summary.host,
                port: e.summary.port,
                path: &e.summary.path,
                status: e.summary.status,
                identity: who.as_deref(),
                request: &e.request,
                response: e.response.as_deref(),
            })
            .collect();
        Ok(pm_model::build(&obs))
    }

    /// The model, filtered and trimmed for a reader.
    pub fn model_get(&self, f: &ModelFilter) -> Result<Value> {
        let m = self.model()?;
        let ops: Vec<&pm_model::Operation> = m
            .operations
            .iter()
            .filter(|o| f.contains.as_ref().is_none_or(|c| o.key.to_lowercase().contains(&c.to_lowercase())))
            .collect();
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for o in &m.objects {
            *counts.entry(o.object_type.as_str()).or_insert(0) += 1;
        }
        let mut out = json!({ "operations": ops, "object_counts": counts });
        if f.include_objects.unwrap_or(false) || f.object_type.is_some() {
            let objs: Vec<&pm_model::Object> = m
                .objects
                .iter()
                .filter(|o| f.object_type.as_ref().is_none_or(|t| t.eq_ignore_ascii_case(&o.object_type)))
                .take(500)
                .collect();
            out["objects"] = json!(objs);
        }
        Ok(out)
    }

    /// Suggested authorization tests from the model's ownership data.
    pub fn authz_candidates(&self) -> Result<Vec<AuthzCandidate>> {
        let names: Vec<String> = self.identity_list()?.into_iter().map(|i| i.name).collect();
        Ok(self.model()?.authz_candidates(&names))
    }

    pub fn hypothesis_create(&self, actor: &Actor, h: NewHypothesis) -> Result<Hypothesis> {
        if h.operation.trim().is_empty() || h.vuln_class.trim().is_empty() {
            return Err(ServiceError::Invalid("operation and vuln_class are required".into()));
        }
        let now = now_ms();
        let mut row = serde_json::Map::new();
        for (k, v) in [
            ("operation", json!(h.operation)),
            ("param", json!(h.param)),
            ("vuln_class", json!(h.vuln_class.to_ascii_lowercase())),
            ("rationale", json!(h.rationale)),
            ("status", json!("open")),
            ("actor", json!(actor.id())),
            ("notes", json!("[]")),
            ("created_ms", json!(now)),
            ("updated_ms", json!(now)),
        ] {
            row.insert(k.into(), v);
        }
        let id = self.store.lock().insert_row("hypotheses", &row)?;
        self.audit(&actor.id(), "hypothesis_create", json!({ "id": id, "hypothesis": h }), "allow")?;
        self.hypothesis_get(id)
    }

    pub fn hypothesis_get(&self, id: i64) -> Result<Hypothesis> {
        let row = self
            .store
            .lock()
            .row("hypotheses", id)?
            .ok_or_else(|| ServiceError::NotFound(format!("hypothesis {id}")))?;
        let mut h = decode_hypothesis(&row);
        let f = pm_store::HistoryFilter { hypothesis_id: Some(id), limit: Some(100), ..Default::default() };
        h.evidence = self.store.lock().search_exchanges(&f)?.into_iter().map(|e| e.id).collect();
        Ok(h)
    }

    pub fn hypothesis_update(&self, actor: &Actor, u: HypothesisUpdate) -> Result<Hypothesis> {
        let mut h = self.hypothesis_get(u.id)?;
        let mut changes = serde_json::Map::new();
        if let Some(st) = &u.status {
            pm_ledger::Status::parse(st).ok_or_else(|| {
                ServiceError::Invalid(format!("status must be open, testing, confirmed or refuted, not {st}"))
            })?;
            changes.insert("status".into(), json!(st));
        }
        if let Some(note) = &u.note {
            h.notes.push(format!("{}: {note}", actor.id()));
            changes.insert("notes".into(), json!(serde_json::to_string(&h.notes).unwrap_or_default()));
        }
        changes.insert("updated_ms".into(), json!(now_ms()));
        self.store.lock().update_row("hypotheses", u.id, &changes)?;
        self.audit(&actor.id(), "hypothesis_update", json!(u), "allow")?;
        self.hypothesis_get(u.id)
    }

    pub fn hypothesis_list(&self, status: Option<&str>) -> Result<Vec<Hypothesis>> {
        let filter = status.map(|s| json!(s));
        let rows = self.store.lock().rows("hypotheses", filter.as_ref().map(|v| ("status", v)), 1000)?;
        Ok(rows.iter().map(decode_hypothesis).collect())
    }

    /// Checklist coverage across the model's operations.
    pub fn coverage(&self, untested_only: bool) -> Result<Coverage> {
        let m = self.model()?;
        let hyps = self.hypothesis_list(None)?;
        let ops: Vec<OperationInfo> = m
            .operations
            .iter()
            .map(|o| OperationInfo {
                key: &o.key,
                method: &o.method,
                template: &o.template,
                kind: &o.kind,
                authenticated: o.authenticated,
                query_params: &o.query_params,
                body_params: &o.body_params,
            })
            .collect();
        let mut c = pm_ledger::coverage(&ops, &hyps);
        if untested_only {
            c.cells.retain(|x| x.status == "untested" || x.status == "open");
        }
        Ok(c)
    }
}

/// Which identity a recorded request was made as, by matching its
/// credentials (session-like cookie values or auth headers).
fn resolve_identity(request: &[u8], identities: &[Identity]) -> Option<String> {
    let auth = pm_identity::auth_from_request(request);
    if auth.is_empty() {
        return None;
    }
    identities
        .iter()
        .find(|i| {
            i.auth.cookies.iter().any(|(n, v)| v.len() >= 8 && auth.cookies.iter().any(|(n2, v2)| n == n2 && v == v2))
                || i.auth
                    .headers
                    .iter()
                    .any(|(h, v)| auth.headers.iter().any(|(h2, v2)| h.eq_ignore_ascii_case(h2) && v == v2))
        })
        .map(|i| i.name.clone())
}
