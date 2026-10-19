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
        Ok(CrawlResult::Done { pages, forms, skipped, skipped_total, not_visited })
    }
}
