//! Traffic in and out: HAR import and export, cURL commands.
//!
//! Importing records exchanges without sending anything, so it needs no
//! gate decision; it is audited and every row is tagged `source: import`.
//! Exports for agents have secrets replaced, like every other agent view.

use pm_policy::Actor;
use pm_store::{HistoryFilter, NewExchange};
use pm_tools::{curl, har};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError};

/// Largest HAR file accepted.
pub const MAX_IMPORT_BYTES: usize = 200 * 1024 * 1024;
/// Most exchanges in one export.
pub const MAX_EXPORT: usize = 20_000;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImportRequest {
    /// The HAR document as text.
    pub har: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    pub imported: usize,
    /// Ids of the new exchanges (first 1000).
    pub exchange_ids: Vec<i64>,
    pub skipped: Vec<String>,
}

/// A request read from a cURL command, ready for Replay.
#[derive(Debug, Clone, Serialize)]
pub struct CurlParsed {
    /// Where to send it (scheme://host[:port]).
    pub url: String,
    pub method: String,
    pub raw: String,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ExportRequest {
    /// Exactly these exchanges…
    pub ids: Option<Vec<i64>>,
    /// …or everything matching a history filter (`limit` caps the count).
    #[serde(flatten)]
    pub filter: HistoryFilter,
}

impl Service {
    /// Adds the exchanges of a HAR file to history. Sends nothing.
    pub fn traffic_import_har(&self, actor: &Actor, req: &ImportRequest) -> Result<ImportResult> {
        if req.har.len() > MAX_IMPORT_BYTES {
            return Err(ServiceError::Invalid(format!("HAR larger than {} MB", MAX_IMPORT_BYTES / 1024 / 1024)));
        }
        let (entries, mut skipped) = har::parse_har(&req.har, pm_core::now_ms()).map_err(ServiceError::Invalid)?;
        let actor_id = actor.id();
        let mut ids = Vec::new();
        let mut imported = 0;
        {
            let mut store = self.store.lock();
            for e in entries {
                let error = e.response.is_none().then(|| "no response in the HAR file".to_string());
                let row = NewExchange {
                    ts_ms: e.ts_ms,
                    duration_ms: e.duration_ms,
                    source: "import".into(),
                    actor_id: actor_id.clone(),
                    scheme: e.scheme,
                    host: e.host,
                    port: e.port,
                    method: e.method,
                    path: e.path,
                    status: e.status,
                    request: e.request,
                    response: e.response,
                    error,
                    identity: None,
                    hypothesis_id: None,
                };
                match store.insert_exchange(&row) {
                    Ok(id) => {
                        imported += 1;
                        if ids.len() < 1000 {
                            ids.push(id);
                        }
                    }
                    Err(e) => skipped.push(format!("{} {}: {e:#}", row.method, row.path)),
                }
            }
        }
        self.audit(&actor_id, "import_har", json!({ "imported": imported, "skipped": skipped.len() }), "ok")?;
        Ok(ImportResult { imported, exchange_ids: ids, skipped })
    }

    /// Exchanges as a HAR 1.2 document (newest first unless `ids` are given).
    pub fn traffic_export_har(&self, actor: &Actor, req: &ExportRequest) -> Result<Value> {
        let ids: Vec<i64> = match &req.ids {
            Some(ids) => ids.iter().take(MAX_EXPORT).copied().collect(),
            None => {
                // The same search as history (queries and scope included).
                let want = req.filter.limit.unwrap_or(MAX_EXPORT).clamp(1, MAX_EXPORT);
                let mut filter = req.filter.clone();
                let mut ids = Vec::new();
                while ids.len() < want {
                    filter.limit = Some((want - ids.len()).min(500));
                    let page = self.history_search(actor, &filter)?;
                    ids.extend(page.exchanges.iter().map(|r| r.id));
                    match page.next_before_id {
                        Some(b) => filter.before_id = Some(b),
                        None => break,
                    }
                }
                ids
            }
        };
        let mut rows = Vec::with_capacity(ids.len());
        {
            let store = self.store.lock();
            for id in ids {
                rows.push(store.get_exchange(id)?.ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?);
            }
        }
        let redactor = self.redactor_for(actor);
        let redact = |b: &[u8]| -> Vec<u8> {
            match redactor {
                Some(r) => r.redact(&String::from_utf8_lossy(b)).into_bytes(),
                None => b.to_vec(),
            }
        };
        let items: Vec<har::ExportItem> = rows
            .iter()
            .map(|ex| {
                let s = &ex.summary;
                let url = pm_core::url(&s.scheme, &s.host, s.port, &s.path);
                har::ExportItem {
                    ts_ms: s.ts_ms,
                    duration_ms: s.duration_ms,
                    url: redactor.map_or(url.clone(), |r| r.redact(&url)),
                    request: redact(&ex.request),
                    response: ex.response.as_deref().map(redact),
                }
            })
            .collect();
        self.audit(&actor.id(), "export_har", json!({ "exchanges": items.len() }), "ok")?;
        Ok(har::to_har(&items, env!("CARGO_PKG_VERSION")))
    }

    /// A curl command that sends the same request as a recorded exchange.
    pub fn exchange_curl(&self, actor: &Actor, id: i64) -> Result<String> {
        let ex = self.store.lock().get_exchange(id)?.ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
        let s = &ex.summary;
        let url = pm_core::url(&s.scheme, &s.host, s.port, &s.path);
        let raw = match self.redactor_for(actor) {
            Some(r) => r.redact(&String::from_utf8_lossy(&ex.request)).into_bytes(),
            None => ex.request,
        };
        curl::to_curl(&url, &raw).map_err(ServiceError::Invalid)
    }

    /// Reads a curl command into a request for Replay. Sends nothing.
    pub fn curl_parse(&self, command: &str) -> Result<CurlParsed> {
        if command.len() > 10 * 1024 * 1024 {
            return Err(ServiceError::Invalid("command larger than 10 MB".into()));
        }
        let c = curl::parse_curl(command).map_err(ServiceError::Invalid)?;
        Ok(CurlParsed {
            url: format!("{}://{}", c.url.scheme, c.url.authority()),
            method: c.method,
            raw: String::from_utf8_lossy(&c.raw).into_owned(),
            warnings: c.warnings,
        })
    }
}
