//! Searching the contents of history, and history as a site map. Both only
//! read the project; nothing is sent.

use pm_ai::wrap_untrusted;
use pm_policy::{Actor, Target};
use pm_store::{ExchangeSummary, HistoryFilter};
use pm_tools::search::{Matcher, Snippet, snippet};
use pm_tools::sitemap;
use serde::{Deserialize, Serialize};

use crate::{Result, Service, ServiceError};

/// Most exchanges one search looks at.
pub const MAX_SCAN: usize = 50_000;
/// Most exchanges in a site map.
pub const MAX_SITE_ROWS: usize = 200_000;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct SearchRequest {
    /// Text (or a regex with `regex: true`) to find.
    pub query: String,
    pub regex: bool,
    pub case_sensitive: bool,
    /// request, response or both (default).
    pub part: Option<String>,
    /// How many exchanges to look at, newest first (default 5000).
    pub max_scan: Option<usize>,
    /// Which exchanges to look in; `limit` is the most hits returned (default 50).
    #[serde(flatten)]
    pub filter: HistoryFilter,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub exchange: ExchangeSummary,
    /// request or response
    pub part: &'static str,
    /// Matches in this part (counted up to 100).
    pub matches: usize,
    /// Up to 3 excerpts. For agents the text is wrapped as untrusted and offsets are 0.
    pub snippets: Vec<Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    pub scanned: usize,
    /// Pass as `before_id` to keep searching older exchanges.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before_id: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiteView {
    #[serde(flatten)]
    pub site: sitemap::Site,
    pub in_scope: bool,
}

/// Head as recorded plus the body decoded (chunked, gzip…), for searching.
pub(crate) fn searchable(raw: &[u8]) -> Vec<u8> {
    let (head, body) = pm_http::split_message(raw);
    let headers = pm_http::parse_request_head(head)
        .map(|h| h.headers)
        .or_else(|_| pm_http::parse_response_head(head).map(|h| h.headers))
        .unwrap_or_default();
    let mut out = head.to_vec();
    out.extend_from_slice(&pm_ai::body::decode(&headers, body).bytes);
    out
}

impl Service {
    /// Finds text in recorded requests and responses (a read; not audited).
    pub fn history_search_text(&self, actor: &Actor, req: &SearchRequest) -> Result<SearchResult> {
        let matcher = Matcher::new(&req.query, req.regex, req.case_sensitive).map_err(ServiceError::Invalid)?;
        let (want_req, want_resp) = match req.part.as_deref().unwrap_or("both") {
            "both" => (true, true),
            "request" => (true, false),
            "response" => (false, true),
            other => return Err(ServiceError::Invalid(format!("part must be request, response or both, not {other}"))),
        };
        let max_hits = req.filter.limit.unwrap_or(50).clamp(1, 500);
        let max_scan = req.max_scan.unwrap_or(5000).clamp(1, MAX_SCAN);
        let redactor = self.redactor_for(actor);
        let mut filter = req.filter.clone();
        let mut hits = Vec::new();
        let mut scanned = 0;
        let mut last_id = None;
        let mut exhausted = false;
        'pages: while scanned < max_scan && hits.len() < max_hits {
            filter.limit = Some((max_scan - scanned).min(500));
            let page = self.store.lock().search_exchanges(&filter)?;
            if page.len() < filter.limit.unwrap_or(0) {
                exhausted = true;
            }
            let Some(last) = page.last().map(|r| r.id) else { break };
            filter.before_id = Some(last);
            for mut summary in page {
                let Some(ex) = self.store.lock().get_exchange(summary.id)? else { continue };
                scanned += 1;
                last_id = Some(summary.id);
                if let Some(r) = redactor {
                    summary.path = r.redact(&summary.path);
                }
                let parts = [("request", want_req.then_some(&ex.request[..])), ("response", ex.response.as_deref())];
                for (name, raw) in parts {
                    let Some(raw) = raw.filter(|_| name == "request" || want_resp) else { continue };
                    let mut hay = searchable(raw);
                    // Agents search what they would see: secrets are already replaced.
                    if let Some(r) = redactor {
                        hay = r.redact(&String::from_utf8_lossy(&hay)).into_bytes();
                    }
                    let found = matcher.find(&hay, 100);
                    if found.is_empty() {
                        continue;
                    }
                    let snippets = found
                        .iter()
                        .take(3)
                        .map(|&m| {
                            let s = snippet(&hay, m, 60);
                            if redactor.is_some() {
                                Snippet { text: wrap_untrusted(&s.text), start: 0, end: 0 }
                            } else {
                                s
                            }
                        })
                        .collect();
                    hits.push(SearchHit { exchange: summary.clone(), part: name, matches: found.len(), snippets });
                    if hits.len() >= max_hits {
                        break 'pages;
                    }
                }
                if scanned >= max_scan {
                    break 'pages;
                }
            }
            if exhausted {
                break;
            }
        }
        let next_before_id = if exhausted && scanned < max_scan && hits.len() < max_hits { None } else { last_id };
        Ok(SearchResult { hits, scanned, next_before_id })
    }

    /// History as a tree per origin (a read; not audited).
    pub fn site_map(&self, actor: &Actor, host: Option<&str>) -> Result<Vec<SiteView>> {
        let mut rows = self.store.lock().site_rows(host, MAX_SITE_ROWS)?;
        if let Some(r) = self.redactor_for(actor) {
            for row in &mut rows {
                row.path = r.redact(&row.path);
            }
        }
        let origins: Vec<String> = rows.iter().map(|r| pm_core::url(&r.scheme, &r.host, r.port, "")).collect();
        let sites = sitemap::build(rows.iter().zip(&origins).map(|(r, origin)| sitemap::Entry {
            origin,
            method: &r.method,
            path: &r.path,
            status: r.status,
            id: r.id,
        }));
        Ok(sites
            .into_iter()
            .map(|site| {
                let row = rows.iter().zip(&origins).find(|(_, o)| **o == site.origin).map(|(r, _)| r);
                let in_scope = row.is_some_and(|r| {
                    Target::from_parts(&r.scheme, &r.host, r.port, "/")
                        .is_ok_and(|t| self.policy.scope_check(&t).is_ok())
                });
                SiteView { site, in_scope }
            })
            .collect())
    }
}
