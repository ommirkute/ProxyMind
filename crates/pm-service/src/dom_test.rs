//! DOM testing (`pm_scan::dom`) on a recorded page: rendered offline with
//! its recorded scripts, every network request blocked. Nothing is sent to
//! the target, so this is a read (not gated); it needs a local Chromium.

use pm_policy::Actor;
use pm_scan::dom::{self, Flow, Markers};
use pm_store::HistoryFilter;
use serde::{Deserialize, Serialize};

use crate::{Result, Service, ServiceError};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DomTestRequest {
    /// A recorded HTML page.
    pub exchange_id: i64,
    /// Also seed localStorage / sessionStorage reads (missing keys).
    pub storage: bool,
    /// Also try prototype pollution through the URL (one render per technique).
    pub pollution: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomTestResult {
    pub url: String,
    /// Sources that reached sinks, exploitable ones first.
    pub flows: Vec<Flow>,
    /// Techniques that set `Object.prototype` from the URL.
    pub pollution: Vec<String>,
    /// Same-origin scripts the page loads, and whether a recorded copy was used.
    pub scripts: Vec<(String, bool)>,
    pub notes: Vec<String>,
}

impl Service {
    /// The latest recorded 2xx response for exactly `url` (scheme, host, port, path and query).
    fn recorded_for_url(&self, url: &str) -> Option<Vec<u8>> {
        let u = url::Url::parse(url).ok()?;
        let path = format!("{}{}", u.path(), u.query().map(|q| format!("?{q}")).unwrap_or_default());
        let rows = self
            .store
            .lock()
            .search_exchanges(&HistoryFilter {
                host: Some(u.host_str()?.to_string()),
                path: Some(path.clone()),
                limit: Some(50),
                ..Default::default()
            })
            .ok()?;
        let port = u.port_or_known_default()?;
        let row = rows.iter().find(|r| {
            r.path == path
                && r.port == port
                && r.scheme == u.scheme()
                && r.status.is_some_and(|s| (200..300).contains(&s))
        })?;
        self.store.lock().get_exchange(row.id).ok().flatten()?.response
    }

    /// Seeds the page's sources with markers and reports which reach dangerous sinks.
    pub async fn dom_test(&self, actor: &Actor, req: DomTestRequest) -> Result<DomTestResult> {
        let ex = self
            .store
            .lock()
            .get_exchange(req.exchange_id)?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {}", req.exchange_id)))?;
        let s = &ex.summary;
        let page_url = pm_core::url(&s.scheme, &s.host, s.port, &s.path);
        let raw = ex.response.as_deref().ok_or_else(|| ServiceError::Invalid("the exchange has no response".into()))?;
        let doc = crate::proof::recorded_document(&page_url, raw)
            .ok_or_else(|| ServiceError::Invalid("the response can't be read".into()))?;
        let html = String::from_utf8_lossy(&doc.body).into_owned();
        if !html.to_ascii_lowercase().contains("<script") {
            return Err(ServiceError::Invalid("the page has no scripts to test".into()));
        }
        let chromium = pm_browser::find_chromium().ok_or_else(|| {
            ServiceError::Invalid(format!("no Chromium found: install one or set {}", pm_browser::ENV_CHROMIUM))
        })?;
        let mut notes = Vec::new();
        let mut scripts = Vec::new();
        let mut resources = Vec::new();
        for src in pm_scan::active::script_srcs(&html, &page_url) {
            match self.recorded_for_url(&src).and_then(|r| crate::proof::recorded_document(&src, &r)) {
                Some(d) => {
                    resources.push(pm_browser::Resource {
                        url: src.clone(),
                        status: d.status,
                        headers: d.headers,
                        body: d.body,
                    });
                    scripts.push((src, true));
                }
                None => scripts.push((src, false)),
            }
        }
        if scripts.iter().any(|(_, used)| !used) {
            notes.push(
                "some scripts aren't in history: browse the page through the proxy first, then test again".into(),
            );
        }
        let markers = Markers::new(&format!("pmd{}", &pm_oast::new_token()[..8]));
        let url = markers.url(&page_url);
        let mut d = doc.clone();
        d.url = url.clone();
        d.resources = resources.clone();
        let opts = pm_browser::RenderOptions {
            init_script: Some(dom::hooks(&markers, "pmProof", req.storage)),
            settle: std::time::Duration::from_millis(1200),
            ..Default::default()
        };
        let rep = pm_browser::render(&chromium, &d, &opts)
            .await
            .map_err(|e| ServiceError::Invalid(format!("the browser failed: {e}")))?;
        if !rep.loaded {
            notes.push(format!(
                "the page didn't finish loading{}",
                rep.navigation_error.map(|e| format!(" ({e})")).unwrap_or_default()
            ));
        }
        let mut flows = dom::flows(&rep.binding_calls, &markers);
        let mut pollution = Vec::new();
        if req.pollution {
            for (label, technique) in dom::POLLUTION {
                let mut d = doc.clone();
                d.url = dom::pollution_url(&page_url, technique);
                d.resources = resources.clone();
                let opts = pm_browser::RenderOptions {
                    init_script: Some(dom::pollution_check("pmProof")),
                    stop_on: Some("polluted".into()),
                    ..Default::default()
                };
                match pm_browser::render(&chromium, &d, &opts).await {
                    Ok(r) if r.binding_calls.iter().any(|c| c == "polluted") => pollution.push((*label).to_string()),
                    Ok(_) => {}
                    Err(e) => notes.push(format!("pollution test ({label}): browser error: {e}")),
                }
            }
        }
        // What came from the page is untrusted, for agents redacted too.
        if let Some(r) = self.redactor_for(actor) {
            for f in &mut flows {
                f.value = pm_ai::wrap_untrusted(&r.redact(&f.value));
                f.stack = r.redact(&f.stack);
            }
        }
        Ok(DomTestResult { url, flows, pollution, scripts, notes })
    }
}
