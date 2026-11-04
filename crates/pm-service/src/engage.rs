//! Engagement tools over recorded traffic (nothing is sent): comments and
//! scripts in responses, what links to a page, the parameters a target
//! uses, and CSRF / clickjacking proof-of-concept pages.

use std::collections::{BTreeMap, HashMap};

use pm_policy::Actor;
use pm_store::{ExchangeSummary, HistoryFilter};
use pm_tools::engage::{self, Clickjacking, CsrfTechnique, ParamSummary};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{Result, Service, ServiceError};

/// Which recorded exchanges the tools look at.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EngageFilter {
    /// Host contains this text.
    pub host: Option<String>,
    /// Only in-scope exchanges (default: true when the ROE has a scope).
    pub in_scope: Option<bool>,
    /// Most exchanges looked at, newest first (default 3000, max 20000).
    pub max_scan: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FoundComment {
    pub kind: &'static str,
    pub text: String,
    pub url: String,
    pub exchange_id: i64,
    pub line: usize,
    /// Responses with the same comment.
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FoundScript {
    pub kind: &'static str,
    /// An external script's URL, resolved against the page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    pub snippet: String,
    pub length: usize,
    /// The first page it was seen on.
    pub url: String,
    pub exchange_id: i64,
    /// Pages it appears on.
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetAnalysis {
    pub host_filter: Option<String>,
    pub requests: usize,
    /// Distinct URLs (path with query) and how many are static files.
    pub urls: usize,
    pub static_urls: usize,
    /// URLs that take input (with a query or a body), up to 300.
    pub dynamic_urls: Vec<String>,
    pub methods: BTreeMap<String, usize>,
    pub statuses: BTreeMap<u16, usize>,
    pub content_types: BTreeMap<String, usize>,
    pub params: Vec<ParamSummary>,
}

struct Seen {
    summary: ExchangeSummary,
    request: Vec<u8>,
    /// Response head and decoded body.
    response: Option<(pm_http::ResponseHead, String, Vec<u8>)>,
}

fn url_of(s: &ExchangeSummary) -> String {
    pm_core::url(&s.scheme, &s.host, s.port, &s.path)
}

impl Service {
    /// Recorded exchanges, newest first, with decoded responses.
    fn recorded(&self, actor: &Actor, f: &EngageFilter) -> Result<Vec<Seen>> {
        let in_scope = f.in_scope.unwrap_or_else(|| !self.policy.roe().include.is_empty());
        let max = f.max_scan.unwrap_or(3000).clamp(1, 20_000);
        let mut filter = HistoryFilter {
            host: f.host.clone().filter(|h| !h.is_empty()),
            in_scope: in_scope.then_some(true),
            limit: Some(500),
            ..Default::default()
        };
        let mut ids = Vec::new();
        while ids.len() < max {
            let page = self.history_search(actor, &filter)?;
            ids.extend(page.exchanges.iter().map(|e| e.id));
            match page.next_before_id {
                Some(b) => filter.before_id = Some(b),
                None => break,
            }
        }
        ids.truncate(max);
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let Some(ex) = self.store.lock().get_exchange(id)? else { continue };
            let response = ex.response.as_deref().and_then(|raw| {
                let converted;
                let raw = if pm_http::h2text::is_http2_response(raw) {
                    converted = pm_http::h2text::to_http1_response(raw)?;
                    &converted[..]
                } else {
                    raw
                };
                let (head, body) = pm_http::split_message(raw);
                let head = pm_http::parse_response_head(head).ok()?;
                let d = pm_ai::body::decode(&head.headers, body);
                Some((head, d.content_type.unwrap_or_default(), d.bytes))
            });
            out.push(Seen { summary: ex.summary, request: ex.request, response });
        }
        Ok(out)
    }

    /// Comments left in HTML, JavaScript and CSS responses, de-duplicated.
    pub fn engage_comments(&self, actor: &Actor, f: &EngageFilter) -> Result<Vec<FoundComment>> {
        let mut found: Vec<FoundComment> = Vec::new();
        let mut at: HashMap<(&'static str, String), usize> = HashMap::new();
        for s in self.recorded(actor, f)? {
            let Some((_, ct, body)) = &s.response else { continue };
            let text = String::from_utf8_lossy(body);
            for c in engage::find_comments(ct, &text) {
                match at.get(&(c.kind, c.text.clone())) {
                    Some(&i) => found[i].count += 1,
                    None if found.len() < 5000 => {
                        at.insert((c.kind, c.text.clone()), found.len());
                        found.push(FoundComment {
                            kind: c.kind,
                            text: c.text,
                            url: url_of(&s.summary),
                            exchange_id: s.summary.id,
                            line: c.line,
                            count: 1,
                        });
                    }
                    None => {}
                }
            }
        }
        Ok(found)
    }

    /// Scripts in recorded HTML pages: external (by URL), inline and handlers.
    pub fn engage_scripts(&self, actor: &Actor, f: &EngageFilter) -> Result<Vec<FoundScript>> {
        let mut found: Vec<FoundScript> = Vec::new();
        let mut at: HashMap<String, usize> = HashMap::new();
        for s in self.recorded(actor, f)? {
            let Some((_, ct, body)) = &s.response else { continue };
            let text = String::from_utf8_lossy(body);
            if engage::kind_of(ct, &text) != Some("html") {
                continue;
            }
            let page = url_of(&s.summary);
            let base = url::Url::parse(&page).ok();
            for sc in engage::find_scripts(&text) {
                let src = sc
                    .src
                    .as_ref()
                    .map(|u| base.as_ref().and_then(|b| b.join(u).ok()).map_or_else(|| u.clone(), |x| x.to_string()));
                let key = format!("{}|{}", sc.kind, src.as_deref().unwrap_or(&sc.snippet));
                match at.get(&key) {
                    Some(&i) => found[i].count += 1,
                    None if found.len() < 5000 => {
                        at.insert(key, found.len());
                        found.push(FoundScript {
                            kind: sc.kind,
                            src,
                            snippet: sc.snippet,
                            length: sc.length,
                            url: page.clone(),
                            exchange_id: s.summary.id,
                            count: 1,
                        });
                    }
                    None => {}
                }
            }
        }
        found.sort_by_key(|s| match s.kind {
            "external" => 0,
            "inline" => 1,
            _ => 2,
        });
        Ok(found)
    }

    /// Recorded responses that link to or mention the page of `exchange_id`.
    pub fn engage_references(&self, actor: &Actor, exchange_id: i64, f: &EngageFilter) -> Result<Vec<ExchangeSummary>> {
        let ex = self
            .store
            .lock()
            .get_exchange(exchange_id)?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {exchange_id}")))?;
        let path = ex.summary.path.split(['?', '#']).next().unwrap_or("").to_string();
        if path.len() < 2 {
            return Err(ServiceError::Invalid("pick a page with a path (\"/\" is everywhere)".into()));
        }
        let mut out = Vec::new();
        for s in self.recorded(actor, f)? {
            if s.summary.id == exchange_id {
                continue;
            }
            let Some((_, _, body)) = &s.response else { continue };
            if memchr::memmem::find(body, path.as_bytes()).is_some() && out.len() < 500 {
                out.push(s.summary);
            }
        }
        Ok(out)
    }

    /// What a target is made of: URLs, methods, statuses, content types and
    /// every parameter seen (where, how often, example values).
    pub fn engage_analyze(&self, actor: &Actor, f: &EngageFilter) -> Result<TargetAnalysis> {
        let seen = self.recorded(actor, f)?;
        let mut urls = std::collections::BTreeSet::new();
        let mut dynamic = std::collections::BTreeSet::new();
        let (mut methods, mut statuses, mut types) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        let mut params = engage::ParamCollector::default();
        for s in &seen {
            let u = url_of(&s.summary);
            *methods.entry(s.summary.method.clone()).or_insert(0) += 1;
            if let Some(st) = s.summary.status {
                *statuses.entry(st).or_insert(0) += 1;
            }
            if let Some((_, ct, _)) = &s.response {
                let t = ct.split(';').next().unwrap_or("").trim().to_string();
                if !t.is_empty() {
                    *types.entry(t).or_insert(0) += 1;
                }
            }
            let has_input = s.summary.path.contains('?') || s.summary.req_len > 0 && s.summary.method != "GET";
            if has_input && !engage::is_static(&s.summary.path) && dynamic.len() < 300 {
                dynamic.insert(format!("{} {}", s.summary.method, u));
            }
            params.add(&s.summary.path, &s.request);
            urls.insert(u);
        }
        let static_urls = urls.iter().filter(|u| engage::is_static(u)).count();
        Ok(TargetAnalysis {
            host_filter: f.host.clone(),
            requests: seen.len(),
            urls: urls.len(),
            static_urls,
            dynamic_urls: dynamic.into_iter().collect(),
            methods,
            statuses,
            content_types: types,
            params: params.finish(),
        })
    }

    /// An HTML page that submits the recorded request from another site.
    pub fn engage_csrf_poc(
        &self,
        actor: &Actor,
        exchange_id: i64,
        technique: CsrfTechnique,
        auto_submit: bool,
    ) -> Result<String> {
        let ex = self
            .store
            .lock()
            .get_exchange(exchange_id)?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {exchange_id}")))?;
        let s = &ex.summary;
        if pm_http::h2text::is_http2_request(&ex.request) {
            return Err(ServiceError::Invalid(
                "CSRF proofs are built from HTTP/1.1 requests; resend it as HTTP/1.1".into(),
            ));
        }
        let origin = pm_core::url(&s.scheme, &s.host, s.port, "");
        let html = engage::csrf_poc(origin.trim_end_matches('/'), &ex.request, technique, auto_submit)
            .map_err(ServiceError::Invalid)?;
        self.audit(&actor.id(), "engage_csrf_poc", json!({ "exchange_id": exchange_id }), "allow")?;
        Ok(html)
    }

    /// Whether the recorded page can be framed, and a clickjacking test page.
    pub fn engage_clickjacking(&self, exchange_id: i64) -> Result<Clickjacking> {
        let ex = self
            .store
            .lock()
            .get_exchange(exchange_id)?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {exchange_id}")))?;
        let resp =
            ex.response.ok_or_else(|| ServiceError::Invalid(format!("exchange {exchange_id} has no response")))?;
        let converted;
        let raw = if pm_http::h2text::is_http2_response(&resp) {
            converted = pm_http::h2text::to_http1_response(&resp).unwrap_or_default();
            &converted[..]
        } else {
            &resp[..]
        };
        let head = pm_http::parse_response_head(pm_http::split_message(raw).0)
            .map_err(|e| ServiceError::Invalid(format!("the response can't be read: {e}")))?;
        Ok(engage::clickjacking(&url_of(&ex.summary), &head.headers))
    }
}
