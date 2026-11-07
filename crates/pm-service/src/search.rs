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
    /// both (default), request, response, headers, bodies, request_headers,
    /// request_body, response_headers or response_body.
    pub part: Option<String>,
    /// How many exchanges to look at, newest first (default 5000).
    pub max_scan: Option<usize>,
    /// List exchanges where the searched parts do NOT match (no snippets).
    pub invert: bool,
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

/// Which part of a message a search looks in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    All,
    Headers,
    Body,
}

fn parse_part(part: Option<&str>) -> Result<(Option<Part>, Option<Part>)> {
    Ok(match part.unwrap_or("both") {
        "both" => (Some(Part::All), Some(Part::All)),
        "request" => (Some(Part::All), None),
        "response" => (None, Some(Part::All)),
        "headers" => (Some(Part::Headers), Some(Part::Headers)),
        "bodies" => (Some(Part::Body), Some(Part::Body)),
        "request_headers" => (Some(Part::Headers), None),
        "request_body" => (Some(Part::Body), None),
        "response_headers" => (None, Some(Part::Headers)),
        "response_body" => (None, Some(Part::Body)),
        other => {
            return Err(ServiceError::Invalid(format!(
                "part must be both, request, response, headers, bodies, request_headers, request_body, \
                 response_headers or response_body, not {other}"
            )));
        }
    })
}

/// The searched bytes of one message part.
fn haystack(raw: &[u8], part: Part) -> Vec<u8> {
    let all = searchable(raw);
    let head_len = pm_http::split_message(raw).0.len();
    match part {
        Part::All => all,
        Part::Headers => all[..head_len.min(all.len())].to_vec(),
        Part::Body => all.get(head_len..).unwrap_or_default().to_vec(),
    }
}

/// A search through WebSocket messages.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WsSearchRequest {
    pub query: String,
    pub regex: bool,
    pub case_sensitive: bool,
    /// Messages that don't match.
    pub invert: bool,
    /// Host contains this text.
    pub host: Option<String>,
    /// client (to the server), server, or both (default).
    pub direction: Option<String>,
    /// Only connections whose targets are in scope.
    pub in_scope: Option<bool>,
    pub before_id: Option<i64>,
    /// Messages to look at, newest first (default 5000, max 50 000).
    pub max_scan: Option<usize>,
    /// Most hits (default 50, max 500).
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WsSearchHit {
    pub id: i64,
    pub exchange_id: i64,
    pub ts_ms: i64,
    pub from_client: bool,
    pub host: String,
    pub path: String,
    pub len: u64,
    pub matches: usize,
    pub snippets: Vec<Snippet>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WsSearchResult {
    pub hits: Vec<WsSearchHit>,
    pub scanned: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before_id: Option<i64>,
}

impl Service {
    /// Finds text in recorded requests and responses (a read; not audited).
    /// The filters (including `in_scope` and an HQL `q`) pick the exchanges;
    /// `part` picks what is searched; `invert` lists exchanges without a match.
    pub fn history_search_text(&self, actor: &Actor, req: &SearchRequest) -> Result<SearchResult> {
        let matcher = Matcher::new(&req.query, req.regex, req.case_sensitive).map_err(ServiceError::Invalid)?;
        let (want_req, want_resp) = parse_part(req.part.as_deref())?;
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
            // history_search applies the scope and query filters and redacts paths for agents.
            let page = self.history_search(actor, &filter)?;
            match page.next_before_id {
                Some(b) => filter.before_id = Some(b),
                None => exhausted = true,
            }
            if page.exchanges.is_empty() {
                last_id = page.next_before_id.or(last_id);
            }
            for summary in page.exchanges {
                let Some(ex) = self.store.lock().get_exchange(summary.id)? else { continue };
                scanned += 1;
                last_id = Some(summary.id);
                let parts =
                    [("request", want_req, Some(&ex.request[..])), ("response", want_resp, ex.response.as_deref())];
                let mut any = false;
                let mut found_parts = Vec::new();
                for (name, want, raw) in parts {
                    let (Some(part), Some(raw)) = (want, raw) else { continue };
                    let mut hay = haystack(raw, part);
                    // Agents search what they would see: secrets are already replaced.
                    if let Some(r) = redactor {
                        hay = r.redact(&String::from_utf8_lossy(&hay)).into_bytes();
                    }
                    let found = matcher.find(&hay, 100);
                    if found.is_empty() {
                        continue;
                    }
                    any = true;
                    found_parts.push((name, hay, found));
                }
                if req.invert {
                    if !any {
                        hits.push(SearchHit { exchange: summary.clone(), part: "none", matches: 0, snippets: vec![] });
                    }
                } else {
                    for (name, hay, found) in found_parts {
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
                    }
                }
                if hits.len() >= max_hits || scanned >= max_scan {
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

    /// Finds text in recorded WebSocket messages (a read; not audited).
    /// Compressed or binary payloads are searched as bytes.
    pub fn ws_search_text(&self, actor: &Actor, req: &WsSearchRequest) -> Result<WsSearchResult> {
        let matcher = Matcher::new(&req.query, req.regex, req.case_sensitive).map_err(ServiceError::Invalid)?;
        let dir = match req.direction.as_deref().unwrap_or("both") {
            "both" => None,
            "client" => Some(true),
            "server" => Some(false),
            other => {
                return Err(ServiceError::Invalid(format!("direction must be client, server or both, not {other}")));
            }
        };
        let max_hits = req.limit.unwrap_or(50).clamp(1, 500);
        let max_scan = req.max_scan.unwrap_or(5000).clamp(1, MAX_SCAN);
        let in_scope = req.in_scope.unwrap_or(false);
        let host = req.host.as_deref().filter(|h| !h.is_empty());
        let redactor = self.redactor_for(actor);
        let mut before = req.before_id;
        let (mut hits, mut scanned, mut last_id, mut exhausted) = (Vec::new(), 0usize, None, false);
        let mut scope_cache: std::collections::HashMap<i64, bool> = std::collections::HashMap::new();
        'pages: while scanned < max_scan && hits.len() < max_hits {
            let page = self.store.lock().ws_history(host, before, 1000)?;
            if page.len() < 1000 {
                exhausted = true;
            }
            let Some(last) = page.last().map(|r| r.message.id) else { break };
            before = Some(last);
            for row in page {
                scanned += 1;
                last_id = Some(row.message.id);
                let m = &row.message;
                let dir_ok = dir.is_none_or(|c| c == m.from_client);
                let scope_ok = !in_scope
                    || *scope_cache.entry(m.exchange_id).or_insert_with(|| {
                        self.store.lock().get_exchange(m.exchange_id).ok().flatten().is_some_and(|e| {
                            let s = &e.summary;
                            pm_policy::Target::from_parts(&s.scheme, &s.host, s.port, &s.path)
                                .is_ok_and(|t| self.policy.scope_check(&t).is_ok())
                        })
                    });
                if dir_ok && scope_ok {
                    let hay = match redactor {
                        Some(r) => r.redact(&String::from_utf8_lossy(&m.payload)).into_bytes(),
                        None => m.payload.clone(),
                    };
                    let found = matcher.find(&hay, 100);
                    if found.is_empty() == req.invert {
                        let snippets = found
                            .iter()
                            .take(3)
                            .map(|&r| {
                                let s = snippet(&hay, r, 60);
                                if redactor.is_some() {
                                    Snippet { text: wrap_untrusted(&s.text), start: 0, end: 0 }
                                } else {
                                    s
                                }
                            })
                            .collect();
                        let path = match redactor {
                            Some(r) => r.redact(&row.path),
                            None => row.path.clone(),
                        };
                        hits.push(WsSearchHit {
                            id: m.id,
                            exchange_id: m.exchange_id,
                            ts_ms: m.ts_ms,
                            from_client: m.from_client,
                            host: row.host.clone(),
                            path,
                            len: m.len,
                            matches: found.len(),
                            snippets,
                        });
                    }
                }
                if hits.len() >= max_hits || scanned >= max_scan {
                    break 'pages;
                }
            }
            if exhausted {
                break;
            }
        }
        let next_before_id = if exhausted && scanned < max_scan && hits.len() < max_hits { None } else { last_id };
        Ok(WsSearchResult { hits, scanned, next_before_id })
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
