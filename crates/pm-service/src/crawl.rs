//! Crawling through the policy gate: GET only, in scope only, never links
//! that change state (log out, delete), within page and depth limits. Every
//! fetched page is recorded, so it feeds History and the app model.

use pm_policy::{Actor, Target, Tier};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use crate::{Authorization, Result, Service, ServiceError};

pub const MAX_CRAWL_PAGES: usize = 500;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CrawlRequest {
    /// Where to start, e.g. https://app.example.com/
    pub url: String,
    /// Most pages to fetch (default 50, max 500).
    pub max_pages: Option<usize>,
    /// Most link hops from the start (default 3, max 10).
    pub max_depth: Option<usize>,
    /// Also read /robots.txt and sitemaps for paths (default true).
    pub robots: Option<bool>,
    /// Crawl as this identity.
    pub identity: Option<String>,
    pub approval_id: Option<String>,
    /// Load pages in a headless browser that runs their JavaScript (single-page
    /// apps, routes, API calls made by scripts). Default false.
    pub browser: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrawledPage {
    pub url: String,
    pub depth: usize,
    pub exchange_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub links_found: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Skipped {
    pub url: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CrawlResult {
    Done {
        pages: Vec<CrawledPage>,
        /// Forms seen (never submitted): where they post and their fields.
        forms: Vec<pm_crawl::Form>,
        /// Links not followed and why (first 200).
        skipped: Vec<Skipped>,
        skipped_total: usize,
        /// Links still queued when the page limit was reached.
        not_visited: usize,
        /// Requests the app's scripts made that weren't sent because they
        /// would change state (browser crawls), e.g. `POST https://app/api/cart`.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        not_sent: Vec<String>,
        /// Pages were loaded in a browser.
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        browser: bool,
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

fn get_request(u: &Url) -> String {
    let host = match u.port() {
        Some(p) => format!("{}:{p}", u.host_str().unwrap_or("")),
        None => u.host_str().unwrap_or("").to_string(),
    };
    let target = match u.query() {
        Some(q) => format!("{}?{q}", u.path()),
        None => u.path().to_string(),
    };
    format!(
        "GET {target} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ProxyMind-crawler\r\nAccept: text/html,*/*;q=0.8\r\n\r\n"
    )
}

impl Service {
    /// Crawls from `url` if the policy allows it (active-safe: GETs only).
    pub async fn crawl(&self, actor: &Actor, req: CrawlRequest) -> Result<CrawlResult> {
        let start = Url::parse(&req.url).map_err(|e| ServiceError::Invalid(format!("bad url: {e}")))?;
        if !matches!(start.scheme(), "http" | "https") {
            return Err(ServiceError::Invalid("crawl needs an http(s) URL".into()));
        }
        let max_pages = req.max_pages.unwrap_or(50).clamp(1, MAX_CRAWL_PAGES);
        let max_depth = req.max_depth.unwrap_or(3).min(10);
        let robots = req.robots.unwrap_or(true);
        if let Some(name) = &req.identity {
            self.load_identity(name)?;
        }
        let out =
            self.outgoing(crate::replay::parse_url_endpoint(start.as_str())?, get_request(&start).as_bytes(), false)?;
        let extra = json!({ "crawl": { "max_pages": max_pages, "max_depth": max_depth, "robots": robots } });
        match self.gate_send_with(
            actor,
            "crawl",
            &out,
            req.identity.as_deref(),
            false,
            req.approval_id.as_deref(),
            Some(Tier::ActiveSafe),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(CrawlResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(CrawlResult::PendingApproval {
                    approval_id,
                    summary: format!("crawl (≤{max_pages} pages, depth {max_depth}): {summary}"),
                    reasons,
                });
            }
        }

        if req.browser.unwrap_or(false) {
            return self.crawl_in_browser(actor, &req, start, max_pages, max_depth).await;
        }
        let mut frontier = pm_crawl::Frontier::new(start.clone(), max_depth);
        if robots {
            let mut origin = start.clone();
            origin.set_path("/robots.txt");
            origin.set_query(None);
            frontier.push(origin, 1);
        }
        let (mut pages, mut forms, mut skipped) = (Vec::new(), Vec::new(), Vec::new());
        let mut skipped_total = 0;
        let mut skip = |url: &Url, reason: String, skipped: &mut Vec<Skipped>| {
            skipped_total += 1;
            if skipped.len() < 200 {
                skipped.push(Skipped { url: url.to_string(), reason });
            }
        };
        while pages.len() < max_pages {
            let Some((url, depth)) = frontier.pop() else { break };
            // Each URL is checked on its own: scope, state-changing links,
            // and what the request would do.
            let target = match Target::from_url(url.as_str()) {
                Ok(t) => t,
                Err(e) => {
                    skip(&url, e.to_string(), &mut skipped);
                    continue;
                }
            };
            if let Err(why) = self.policy.scope_check(&target) {
                skip(&url, format!("out of scope: {why}"), &mut skipped);
                continue;
            }
            if depth > 0
                && let Some(why) = pm_crawl::risky(&url)
            {
                skip(&url, format!("not followed: the link probably {why}"), &mut skipped);
                continue;
            }
            let raw = get_request(&url);
            let (tier, reasons) = Tier::for_http_request(raw.as_bytes());
            if tier > Tier::ActiveSafe {
                skip(&url, format!("not followed: {}", reasons.join("; ")), &mut skipped);
                continue;
            }
            let out = self.outgoing(crate::replay::parse_url_endpoint(url.as_str())?, raw.as_bytes(), false)?;
            let (sent, _) = self.send_as(actor, &out, req.identity.as_deref(), false, "crawl").await?;
            let mut page = CrawledPage {
                url: url.to_string(),
                depth,
                exchange_id: sent.exchange_id,
                status: sent.status,
                content_type: None,
                links_found: 0,
            };
            if let Some(resp) = &sent.response {
                let (head, body) = pm_http::split_message(resp);
                if let Ok(h) = pm_http::parse_response_head(head) {
                    let decoded = pm_ai::body::decode(&h.headers, body);
                    let text = String::from_utf8_lossy(&decoded.bytes);
                    page.content_type = decoded.content_type.clone();
                    let mut found: Vec<Url> = Vec::new();
                    // Redirects point somewhere worth a look.
                    if (300..400).contains(&h.status)
                        && let Some(loc) = pm_http::header(&h.headers, "location")
                        && let Ok(u) = url.join(&String::from_utf8_lossy(loc))
                    {
                        found.push(u);
                    }
                    if url.path() == "/robots.txt" && h.status == 200 {
                        let (paths, maps) = pm_crawl::robots(&url, &text);
                        found.extend(paths);
                        found.extend(maps);
                    } else if url.path().ends_with(".xml") && text.contains("<loc>") {
                        found.extend(pm_crawl::sitemap(&text));
                    } else if decoded.kind == pm_ai::body::Kind::Html {
                        let e = pm_crawl::extract(&url, &text);
                        for f in e.forms {
                            if !forms.iter().any(|x: &pm_crawl::Form| x.action == f.action && x.method == f.method) {
                                forms.push(f);
                            }
                        }
                        found.extend(e.links);
                    }
                    page.links_found = found.len();
                    for u in found {
                        frontier.push(u, depth + 1);
                    }
                }
            }
            pages.push(page);
        }
        let not_visited = frontier.pending();
        Ok(CrawlResult::Done {
            pages,
            forms,
            skipped,
            skipped_total,
            not_visited,
            not_sent: Vec::new(),
            browser: false,
        })
    }
}

/// Request headers a browser sets that the sender handles itself.
fn skip_browser_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "content-length" | "connection" | "proxy-connection" | "keep-alive" | "transfer-encoding"
    )
}

/// Resources not worth sending while crawling: they never lead anywhere.
fn static_resource(kind: &str) -> bool {
    matches!(kind, "Image" | "Media" | "Font" | "Stylesheet" | "Manifest" | "TextTrack" | "Ping" | "CSPViolationReport")
}

/// What one browser-crawled page made happen, gathered across requests.
#[derive(Default)]
struct BrowserLog {
    /// URL → exchange id of each request sent.
    sent: Vec<(String, i64, Option<u16>, Option<String>)>,
    not_sent: Vec<String>,
    skipped: Vec<Skipped>,
    skipped_total: usize,
}

impl Service {
    /// The browser half of [`Service::crawl`]: pages load in headless
    /// Chromium; every request they make comes back here and is checked,
    /// sent and recorded like any crawler request (GET only, in scope, no
    /// state-changing links), and its response goes back to the page.
    async fn crawl_in_browser(
        &self,
        actor: &Actor,
        req: &CrawlRequest,
        start: Url,
        max_pages: usize,
        max_depth: usize,
    ) -> Result<CrawlResult> {
        let chromium = pm_browser::find_chromium().ok_or_else(|| {
            ServiceError::Invalid(format!(
                "no Chromium or Chrome found for a browser crawl: install one, or set {}",
                pm_browser::ENV_CHROMIUM
            ))
        })?;
        let mut session = pm_browser::crawl::CrawlSession::start(&chromium)
            .await
            .map_err(|e| ServiceError::Invalid(format!("the browser did not start: {e}")))?;
        let log = parking_lot::Mutex::new(BrowserLog::default());
        let identity = req.identity.clone();
        let handler = |ireq: pm_browser::crawl::Intercepted| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Option<pm_browser::crawl::Served>> + Send + '_>,
        > {
            let (log, identity) = (&log, identity.clone());
            Box::pin(async move { self.crawl_fetch(actor, identity.as_deref(), ireq, log).await })
        };
        let mut frontier = pm_crawl::Frontier::new(start.clone(), max_depth);
        let (mut pages, mut forms) = (Vec::new(), Vec::new());
        let opts = pm_browser::crawl::VisitOptions::default();
        let mut result = Ok(());
        while pages.len() < max_pages {
            let Some((url, depth)) = frontier.pop() else { break };
            if let Err(why) = Target::from_url(url.as_str())
                .map_err(|e| e.to_string())
                .and_then(|t| self.policy.scope_check(&t).map_err(|e| format!("out of scope: {e}")))
            {
                let mut l = log.lock();
                l.skipped_total += 1;
                if l.skipped.len() < 200 {
                    l.skipped.push(Skipped { url: url.to_string(), reason: why });
                }
                continue;
            }
            if depth > 0
                && let Some(why) = pm_crawl::risky(&url)
            {
                let mut l = log.lock();
                l.skipped_total += 1;
                l.skipped
                    .push(Skipped { url: url.to_string(), reason: format!("not followed: the link probably {why}") });
                continue;
            }
            let before = log.lock().sent.len();
            let visit = match session.visit(url.as_str(), &handler, &opts).await {
                Ok(v) => v,
                Err(e) => {
                    result = Err(ServiceError::Invalid(format!("the browser failed on {url}: {e}")));
                    break;
                }
            };
            // The page's own exchange: the first document request sent for it.
            let (exchange_id, status, content_type) = {
                let l = log.lock();
                let mine = &l.sent[before..];
                mine.iter()
                    .find(|(u, ..)| u.split('#').next() == url.as_str().split('#').next())
                    .or_else(|| mine.first())
                    .map(|(_, id, st, ct)| (*id, *st, ct.clone()))
                    .unwrap_or((0, None, None))
            };
            for f in visit.forms {
                let form =
                    pm_crawl::Form { page: url.to_string(), method: f.method, action: f.action, inputs: f.fields };
                if !forms.iter().any(|x: &pm_crawl::Form| x.action == form.action && x.method == form.method) {
                    forms.push(form);
                }
            }
            let mut found = 0;
            for l in visit.links.iter().chain(std::iter::once(&visit.final_url)) {
                if let Ok(u) = Url::parse(l)
                    && matches!(u.scheme(), "http" | "https")
                {
                    found += usize::from(frontier.push(u, depth + 1));
                }
            }
            pages.push(CrawledPage {
                url: url.to_string(),
                depth,
                exchange_id,
                status,
                content_type,
                links_found: found,
            });
        }
        session.close().await;
        result?;
        let not_visited = frontier.pending();
        let l = log.into_inner();
        Ok(CrawlResult::Done {
            pages,
            forms,
            skipped: l.skipped,
            skipped_total: l.skipped_total,
            not_visited,
            not_sent: l.not_sent,
            browser: true,
        })
    }

    /// Answers one request from a browser-crawled page.
    async fn crawl_fetch(
        &self,
        actor: &Actor,
        identity: Option<&str>,
        ireq: pm_browser::crawl::Intercepted,
        log: &parking_lot::Mutex<BrowserLog>,
    ) -> Option<pm_browser::crawl::Served> {
        let skip = |reason: String| {
            let mut l = log.lock();
            l.skipped_total += 1;
            if l.skipped.len() < 200 {
                l.skipped.push(Skipped { url: ireq.url.clone(), reason });
            }
        };
        let url = Url::parse(&ireq.url).ok().filter(|u| matches!(u.scheme(), "http" | "https"))?;
        if static_resource(&ireq.resource_type) {
            return None;
        }
        let target = Target::from_url(url.as_str()).ok()?;
        if let Err(why) = self.policy.scope_check(&target) {
            skip(format!("out of scope: {why}"));
            return None;
        }
        let method = ireq.method.to_ascii_uppercase();
        if !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
            let mut l = log.lock();
            let entry = format!("{method} {}", url.as_str().split('#').next().unwrap_or(""));
            if !l.not_sent.contains(&entry) && l.not_sent.len() < 200 {
                l.not_sent.push(entry);
            }
            return None;
        }
        if let Some(why) = pm_crawl::risky(&url) {
            skip(format!("not followed: the link probably {why}"));
            return None;
        }
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or("")),
            None => url.host_str().unwrap_or("").to_string(),
        };
        let path = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_string(),
        };
        let mut raw = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
        for (k, v) in &ireq.headers {
            if !skip_browser_header(k) {
                raw.push_str(&format!("{k}: {v}\r\n"));
            }
        }
        raw.push_str("\r\n");
        let (tier, reasons) = Tier::for_http_request(raw.as_bytes());
        if tier > Tier::ActiveSafe {
            skip(format!("not followed: {}", reasons.join("; ")));
            return None;
        }
        let out = self.outgoing(crate::replay::parse_url_endpoint(url.as_str()).ok()?, raw.as_bytes(), false).ok()?;
        let sent = match self.send_as(actor, &out, identity, false, "crawl").await {
            Ok((sent, _)) => sent,
            Err(e) => {
                skip(format!("not sent: {e}"));
                return None;
            }
        };
        let resp = sent.response.as_deref()?;
        let (head, body) = pm_http::split_message(resp);
        let h = pm_http::parse_response_head(head).ok()?;
        let decoded = pm_ai::body::decode(&h.headers, body);
        log.lock().sent.push((url.to_string(), sent.exchange_id, sent.status, decoded.content_type.clone()));
        let mut headers: Vec<(String, String)> =
            h.headers.iter().map(|x| (x.name.clone(), String::from_utf8_lossy(&x.value).into_owned())).collect();
        if decoded.notes.iter().any(|n| n.contains("decoded")) {
            headers.retain(|(n, _)| !n.eq_ignore_ascii_case("content-encoding"));
        }
        Some(pm_browser::crawl::Served { status: h.status, headers, body: decoded.bytes })
    }
}
