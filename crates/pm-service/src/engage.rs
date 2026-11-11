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

/// A recorded request worth testing (see `traffic_triage`).
#[derive(Debug, Clone, Serialize)]
pub struct TriageItem {
    pub exchange_id: i64,
    pub method: String,
    pub url: String,
    /// Sum of the hints' weights.
    pub score: u32,
    pub hints: Vec<pm_tools::triage::Hint>,
    /// Other recorded requests with the same method and path shape.
    pub similar: usize,
}

/// Business-logic candidates (see `engage_logic`).
#[derive(Debug, Clone, Serialize)]
pub struct LogicReport {
    pub candidates: Vec<pm_tools::logic::LogicCandidate>,
    /// Recorded URLs that look like steps of a multi-step flow.
    pub flow_paths: Vec<String>,
}

/// An endpoint a recorded script mentions.
#[derive(Debug, Clone, Serialize)]
pub struct FoundEndpoint {
    /// Absolute URL (resolved against the page or script it came from).
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    /// Another script, worth reading in turn.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub script: bool,
    /// Already in the app model (seen in traffic).
    pub known: bool,
    /// On another origin than the script that mentions it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub external: bool,
    /// The first response that mentions it, and how many do.
    pub exchange_id: i64,
    pub count: usize,
}

/// Whether a concrete or templated path matches a model template
/// (`{…}` segments match anything).
fn template_matches(template: &str, path: &str) -> bool {
    let (t, p): (Vec<&str>, Vec<&str>) = (template.split('/').collect(), path.split('/').collect());
    t.len() == p.len() && t.iter().zip(&p).all(|(a, b)| a == b || a.starts_with('{') || b.starts_with('{'))
}

/// The scripts of an HTML page (their text), for the endpoint reader.
fn inline_scripts(html: &str) -> String {
    let lower = html.to_ascii_lowercase();
    let mut out = String::new();
    let mut at = 0;
    while let Some(open) = lower[at..].find("<script").map(|i| i + at) {
        let Some(body) = lower[open..].find('>').map(|i| open + i + 1) else { break };
        let Some(close) = lower[body..].find("</script").map(|i| body + i) else { break };
        out.push_str(&html[body..close]);
        out.push('\n');
        at = close;
    }
    out
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

    /// Endpoints that recorded scripts (JavaScript responses and the inline
    /// scripts of pages) mention, newest-first sources, new ones first.
    /// Nothing is sent.
    pub fn engage_js_endpoints(&self, actor: &Actor, f: &EngageFilter) -> Result<Vec<FoundEndpoint>> {
        let model = self.model()?;
        let mut found: Vec<FoundEndpoint> = Vec::new();
        let mut at: HashMap<(String, Option<&'static str>), usize> = HashMap::new();
        for s in self.recorded(actor, f)? {
            let Some((_, ct, body)) = &s.response else { continue };
            let text = String::from_utf8_lossy(body);
            let script = match engage::kind_of(ct, &text) {
                Some("js") => text.into_owned(),
                Some("html") => inline_scripts(&text),
                _ => continue,
            };
            let page = url_of(&s.summary);
            let Ok(base) = url::Url::parse(&page) else { continue };
            for e in pm_crawl::js::js_endpoints(&script) {
                let Ok(u) = base.join(&e.path) else { continue };
                if !matches!(u.scheme(), "http" | "https") {
                    continue;
                }
                let external = u.origin() != base.origin();
                // `{param}` survives as %7Bparam%7D in a parsed URL: keep it readable.
                let url = u.to_string().replace("%7B", "{").replace("%7D", "}");
                let path = u.path().replace("%7B", "{").replace("%7D", "}");
                let origin = u.origin().ascii_serialization();
                let known = model.operations.iter().any(|o| {
                    o.origin.eq_ignore_ascii_case(&origin)
                        && e.method.is_none_or(|m| m == o.method)
                        && template_matches(&o.template, &path)
                });
                match at.get(&(url.clone(), e.method)) {
                    Some(&i) => {
                        found[i].count += 1;
                        for p in e.params {
                            if !found[i].params.contains(&p) {
                                found[i].params.push(p);
                            }
                        }
                    }
                    None if found.len() < 5000 => {
                        at.insert((url.clone(), e.method), found.len());
                        found.push(FoundEndpoint {
                            url,
                            method: e.method,
                            params: e.params,
                            script: e.script,
                            known,
                            external,
                            exchange_id: s.summary.id,
                            count: 1,
                        });
                    }
                    None => {}
                }
            }
        }
        found.sort_by(|a, b| (a.known, a.external, &a.url).cmp(&(b.known, b.external, &b.url)));
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

    /// Recorded requests worth testing, most promising first: object ids,
    /// URL/file/command-like parameters, reflected input, JWTs, uploads,
    /// GraphQL, unauthenticated APIs, admin paths and error details, each
    /// with what to try. One entry per method and path shape (ids folded),
    /// at most `limit`. Sends nothing.
    pub fn traffic_triage(&self, actor: &Actor, f: &EngageFilter, limit: usize) -> Result<Vec<TriageItem>> {
        let seen = self.recorded(actor, f)?;
        let mut by_shape: BTreeMap<String, TriageItem> = BTreeMap::new();
        for s in &seen {
            let (status, ct, body) = match &s.response {
                Some((head, ct, body)) => (Some(head.status), ct.as_str(), body.as_slice()),
                None => (None, "", &[][..]),
            };
            let hints = pm_tools::triage::hints(&pm_tools::triage::Exchange {
                method: &s.summary.method,
                path: &s.summary.path,
                request: &s.request,
                status,
                content_type: ct,
                body,
            });
            let score: u32 = hints.iter().map(|h| u32::from(h.weight)).sum();
            let path = s.summary.path.split(['?', '#']).next().unwrap_or("");
            let folded: Vec<String> = path
                .split('/')
                .map(|seg| {
                    let id = (!seg.is_empty() && seg.len() <= 12 && seg.bytes().all(|b| b.is_ascii_digit()))
                        || (seg.len() == 36 && seg.matches('-').count() == 4);
                    if id { "{id}".to_string() } else { seg.to_string() }
                })
                .collect();
            let shape = format!("{} {}{}", s.summary.method, s.summary.host, folded.join("/"));
            let e = by_shape.entry(shape).or_insert_with(|| TriageItem {
                exchange_id: s.summary.id,
                method: s.summary.method.clone(),
                url: url_of(&s.summary),
                score: 0,
                hints: vec![],
                similar: 0,
            });
            if score > e.score {
                let similar = e.similar;
                *e = TriageItem {
                    exchange_id: s.summary.id,
                    method: s.summary.method.clone(),
                    url: url_of(&s.summary),
                    score,
                    hints,
                    similar,
                };
            }
            e.similar += 1;
        }
        let mut out: Vec<TriageItem> = by_shape
            .into_values()
            .filter(|t| t.score > 0)
            .map(|mut t| {
                t.similar -= 1;
                t
            })
            .collect();
        out.sort_by(|a, b| b.score.cmp(&a.score).then(a.exchange_id.cmp(&b.exchange_id)));
        out.truncate(limit.clamp(1, 500));
        Ok(out)
    }

    /// Business-logic test candidates from recorded traffic: parameters that
    /// look like money, quantities, discounts, limits, identities, roles or
    /// workflow state, with abuse cases to try, plus paths that look like
    /// steps of a flow (cart, checkout, transfer…). Sends nothing.
    pub fn engage_logic(&self, actor: &Actor, f: &EngageFilter) -> Result<LogicReport> {
        let a = self.engage_analyze(actor, f)?;
        let paths: Vec<&str> = a.dynamic_urls.iter().filter_map(|u| u.split_once(' ').map(|(_, rest)| rest)).collect();
        let flows = pm_tools::logic::flow_paths(
            paths
                .iter()
                .map(|u| u.find("://").and_then(|i| u[i + 3..].find('/').map(|j| &u[i + 3 + j..])).unwrap_or(u)),
        );
        Ok(LogicReport { candidates: pm_tools::logic::candidates(&a.params), flow_paths: flows })
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
