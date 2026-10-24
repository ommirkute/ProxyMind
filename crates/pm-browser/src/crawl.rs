//! A crawling session: one headless Chromium that loads pages of a
//! JavaScript app while the caller answers every request it makes.
//!
//! The browser has no network of its own (the same dead proxy and resolver
//! as [`crate::render`]); each request it tries is paused and handed to the
//! caller's handler, which decides whether to send it (through the policy
//! gate, recorded) and what to answer. What the page shows is read back:
//! links, forms, routes pushed with the History API, and pages reached by
//! clicking harmless-looking buttons.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::Instant;

use crate::{Browser, Cdp, Error, Result, clip, skip_header};

/// A request the page tried to make.
#[derive(Debug, Clone)]
pub struct Intercepted {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
    /// Document, Script, XHR, Fetch, Image, Stylesheet, Font, …
    pub resource_type: String,
}

/// The answer handed back to the page.
#[derive(Debug, Clone)]
pub struct Served {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Plain (de-chunked, decompressed) body.
    pub body: Vec<u8>,
}

/// Answers a request, or `None` to make it fail in the page.
pub type Handler<'a> =
    dyn Fn(Intercepted) -> Pin<Box<dyn Future<Output = Option<Served>> + Send + 'a>> + Send + Sync + 'a;

#[derive(Debug, Clone)]
pub struct VisitOptions {
    /// Quiet time with no request in flight before the page counts as loaded.
    pub idle: Duration,
    /// Longest time for one page, clicks included.
    pub timeout: Duration,
    /// Most elements to click on the page (0: none).
    pub clicks: usize,
}

impl Default for VisitOptions {
    fn default() -> Self {
        Self { idle: Duration::from_millis(600), timeout: Duration::from_secs(25), clicks: 8 }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FoundForm {
    pub action: String,
    pub method: String,
    pub fields: Vec<String>,
}

/// What a page visit found.
#[derive(Debug, Clone, Default)]
pub struct Visit {
    /// Where the page ended up (after redirects).
    pub final_url: String,
    /// Absolute URLs of links and app routes (pushState, hash routes, pages reached by clicks).
    pub links: Vec<String>,
    pub forms: Vec<FoundForm>,
    /// Requests the page made: (method, URL, answered).
    pub requests: Vec<(String, String, bool)>,
    pub clicked: usize,
}

/// Runs before the app's own scripts: notes every route the app pushes.
const ROUTE_HOOK: &str = r#"(() => {
  window.__pmRoutes = [];
  const note = (u) => { try { if (u != null) window.__pmRoutes.push(new URL(String(u), location.href).href); } catch (e) {} };
  for (const k of ['pushState', 'replaceState']) {
    const f = history[k];
    history[k] = function (s, t, u) { note(u); return f.apply(this, arguments); };
  }
  addEventListener('hashchange', () => note(location.href));
  window.open = (u) => { note(u); return null; };
})();"#;

/// Reads links, forms and routes from the page.
const COLLECT: &str = r#"JSON.stringify((() => {
  const abs = (u) => { try { return new URL(u, location.href).href; } catch (e) { return null; } };
  const links = [];
  for (const a of document.querySelectorAll('a[href], area[href], [routerlink], [ng-href], [data-href]')) {
    const h = a.getAttribute('href') ?? a.getAttribute('routerlink') ?? a.getAttribute('ng-href') ?? a.getAttribute('data-href');
    if (h && !/^(javascript|mailto|tel):/i.test(h)) { const u = abs(h); if (u) links.push(u); }
  }
  for (const f of document.querySelectorAll('iframe[src], frame[src]')) { const u = abs(f.getAttribute('src')); if (u) links.push(u); }
  const forms = [...document.forms].map((f) => ({
    action: abs(f.getAttribute('action') || location.href) || location.href,
    method: (f.getAttribute('method') || 'GET').toUpperCase(),
    fields: [...f.elements].map((e) => e.name).filter(Boolean),
  }));
  return { href: location.href, links: links.concat(window.__pmRoutes || []), forms };
})())"#;

/// Marks up to N harmless-looking clickable elements and returns how many.
fn mark_clickables(n: usize) -> String {
    format!(
        r##"(() => {{
  const bad = /(delete|remove|destroy|erase|log ?out|sign ?out|unsubscribe|pay|buy|purchase|checkout|order now|transfer|send|submit|confirm|reset|cancel|close account|deactivate|ban|block|revoke|approve|reject|wipe|drop|disable)/i;
  const seen = new Set();
  const els = [...document.querySelectorAll('button, [role=button], [role=link], [role=tab], [role=menuitem], [onclick], [ng-click], a:not([href]), a[href="#"], summary')]
    .filter((e) => {{
      if (seen.has(e)) return false; seen.add(e);
      const t = (e.innerText || e.getAttribute('aria-label') || e.title || '').trim();
      if (bad.test(t) || bad.test(e.id || '') || bad.test(e.className || '')) return false;
      if (e.closest('form')) return false; // never submit forms
      const r = e.getBoundingClientRect();
      return r.width > 0 && r.height > 0 && !e.disabled;
    }})
    .slice(0, {n});
  els.forEach((e, i) => e.setAttribute('data-pm-click', String(i)));
  return els.length;
}})()"##
    )
}

/// A page's address without plain anchors; `#/route` fragments are kept,
/// since single-page apps route with them.
fn page_key(href: &str) -> &str {
    match href.split_once('#') {
        Some((base, f)) if !(f.starts_with('/') || f.starts_with("!/")) => base,
        _ => href,
    }
}

/// A headless browser kept open across page visits (cookies and storage persist).
pub struct CrawlSession {
    browser: Option<Browser>,
    cdp: Cdp,
    session: String,
    target_id: String,
}

impl CrawlSession {
    pub async fn start(chromium: &std::path::Path) -> Result<Self> {
        let browser = Browser::launch(chromium).await?;
        let mut attempt = 0;
        let mut cdp = loop {
            match Cdp::connect(browser.port, &browser.ws_path).await {
                Ok(c) => break c,
                Err(e) if attempt < 2 => {
                    tracing::warn!("DevTools connection failed ({e}); retrying");
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => {
                    browser.shutdown().await;
                    return Err(e);
                }
            }
        };
        let target = cdp.call("Target.createTarget", json!({ "url": "about:blank" }), None).await?;
        let target_id = target["targetId"].as_str().ok_or_else(|| Error::Protocol("no targetId".into()))?.to_string();
        let attached =
            cdp.call("Target.attachToTarget", json!({ "targetId": target_id, "flatten": true }), None).await?;
        let session = attached["sessionId"].as_str().ok_or_else(|| Error::Protocol("no sessionId".into()))?.to_string();
        let s = Some(session.as_str());
        cdp.call("Fetch.enable", json!({ "patterns": [{ "urlPattern": "*" }] }), s).await?;
        cdp.call("Page.enable", json!({}), s).await?;
        cdp.call("Runtime.enable", json!({}), s).await?;
        cdp.call("Page.addScriptToEvaluateOnNewDocument", json!({ "source": ROUTE_HOOK }), s).await?;
        Ok(Self { browser: Some(browser), cdp, session, target_id })
    }

    pub async fn close(mut self) {
        if let Some(b) = self.browser.take() {
            b.shutdown().await;
        }
    }

    /// Loads `url`, answering its requests with `handler`, then reads what it shows.
    pub async fn visit(&mut self, url: &str, handler: &Handler<'_>, opts: &VisitOptions) -> Result<Visit> {
        let deadline = Instant::now() + opts.timeout;
        let mut visit = Visit::default();
        let nav = self.cdp.send("Page.navigate", json!({ "url": url }), Some(&self.session)).await?;
        self.pump(handler, deadline, opts.idle, Some(nav), &mut visit).await?;
        let first = self.collect().await?;
        visit.final_url = first.0.clone();
        visit.links.extend(first.1);
        visit.forms.extend(first.2);

        if opts.clicks > 0 && Instant::now() < deadline {
            let n = self.eval(&mark_clickables(opts.clicks)).await?.as_u64().unwrap_or(0) as usize;
            for i in 0..n {
                if Instant::now() >= deadline {
                    break;
                }
                let clicked = self
                    .eval(&format!(
                        "(() => {{ const e = document.querySelector('[data-pm-click=\"{i}\"]'); if (!e) return false; e.click(); return true; }})()"
                    ))
                    .await?;
                if clicked != Value::Bool(true) {
                    continue;
                }
                visit.clicked += 1;
                self.pump(handler, deadline, opts.idle, None, &mut visit).await?;
                let (href, links, forms) = self.collect().await?;
                visit.links.push(href.clone());
                visit.links.extend(links);
                for f in forms {
                    if !visit.forms.contains(&f) {
                        visit.forms.push(f);
                    }
                }
                // A click that left the page: go back for the next one.
                if page_key(&href) != page_key(&visit.final_url) {
                    let nav =
                        self.cdp.send("Page.navigate", json!({ "url": visit.final_url }), Some(&self.session)).await?;
                    self.pump(handler, deadline, opts.idle, Some(nav), &mut visit).await?;
                    self.eval(&mark_clickables(opts.clicks)).await?;
                }
            }
        }
        visit.links.sort();
        visit.links.dedup();
        Ok(visit)
    }

    async fn eval(&mut self, expr: &str) -> Result<Value> {
        let r = self
            .cdp
            .call(
                "Runtime.evaluate",
                json!({ "expression": expr, "returnByValue": true, "awaitPromise": false }),
                Some(&self.session),
            )
            .await?;
        if let Some(ex) = r.get("exceptionDetails") {
            let text = ex["exception"]["description"].as_str().or(ex["text"].as_str()).unwrap_or("exception");
            return Err(Error::Protocol(format!("script in the page failed: {}", clip(text))));
        }
        Ok(r["result"]["value"].clone())
    }

    async fn collect(&mut self) -> Result<(String, Vec<String>, Vec<FoundForm>)> {
        let v = self.eval(COLLECT).await?;
        let parsed: Value = v.as_str().and_then(|s| serde_json::from_str(s).ok()).unwrap_or(Value::Null);
        let href = parsed["href"].as_str().unwrap_or("").to_string();
        let links = parsed["links"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let forms = serde_json::from_value(parsed["forms"].clone()).unwrap_or_default();
        Ok((href, links, forms))
    }

    /// Answers paused requests until the page has been quiet for `idle`
    /// (after the navigation `nav`, if any, has finished) or the deadline.
    async fn pump(
        &mut self,
        handler: &Handler<'_>,
        deadline: Instant,
        idle: Duration,
        nav: Option<u64>,
        visit: &mut Visit,
    ) -> Result<()> {
        let mut navigated = nav.is_none();
        let mut quiet_until = Instant::now() + idle;
        loop {
            let wait = if navigated { quiet_until.min(deadline) } else { deadline };
            let Some(msg) = self.cdp.next(wait).await? else {
                return Ok(()); // quiet long enough, or out of time
            };
            if nav.is_some() && msg.get("id").and_then(Value::as_u64) == nav {
                navigated = true;
                quiet_until = Instant::now() + idle;
                continue;
            }
            if msg.get("sessionId").and_then(Value::as_str) != Some(self.session.as_str()) {
                continue;
            }
            let p = &msg["params"];
            match msg["method"].as_str().unwrap_or("") {
                "Fetch.requestPaused" => {
                    let request_id = p["requestId"].as_str().unwrap_or_default().to_string();
                    let req = &p["request"];
                    let headers = req["headers"]
                        .as_object()
                        .map(|o| o.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
                        .unwrap_or_default();
                    let body = req["postData"].as_str().map(|s| s.as_bytes().to_vec());
                    let ireq = Intercepted {
                        url: req["url"].as_str().unwrap_or("").to_string(),
                        method: req["method"].as_str().unwrap_or("GET").to_string(),
                        headers,
                        body,
                        resource_type: p["resourceType"].as_str().unwrap_or("Other").to_string(),
                    };
                    let (method, url) = (ireq.method.clone(), clip(&ireq.url));
                    let answer = handler(ireq).await;
                    visit.requests.push((method, url, answer.is_some()));
                    let s = Some(self.session.as_str());
                    match answer {
                        Some(r) => {
                            let headers: Vec<Value> = r
                                .headers
                                .iter()
                                .filter(|(n, _)| !skip_header(n))
                                .map(|(n, v)| json!({ "name": n, "value": v }))
                                .collect();
                            self.cdp
                                .send(
                                    "Fetch.fulfillRequest",
                                    json!({ "requestId": request_id, "responseCode": r.status,
                                            "responseHeaders": headers, "body": pm_core::base64(&r.body) }),
                                    s,
                                )
                                .await?;
                        }
                        None => {
                            self.cdp
                                .send(
                                    "Fetch.failRequest",
                                    json!({ "requestId": request_id, "errorReason": "BlockedByClient" }),
                                    s,
                                )
                                .await?;
                        }
                    }
                    quiet_until = Instant::now() + idle;
                }
                "Page.javascriptDialogOpening" => {
                    self.cdp
                        .send("Page.handleJavaScriptDialog", json!({ "accept": false }), Some(&self.session))
                        .await?;
                }
                "Page.frameNavigated"
                    if p["frame"]["parentId"].is_null()
                        && p["frame"]["id"].as_str() == Some(self.target_id.as_str()) =>
                {
                    quiet_until = Instant::now() + idle;
                }
                _ => {}
            }
        }
    }
}

impl Drop for CrawlSession {
    fn drop(&mut self) {
        // Close was not awaited (an error on the way): kill_on_drop ends the process.
        let _ = self.browser.take();
    }
}

#[cfg(test)]
mod tests {
    use super::page_key;

    #[test]
    fn route_fragments_are_part_of_the_page() {
        assert_eq!(page_key("http://x/a#top"), "http://x/a");
        assert_eq!(page_key("http://x/#/contact"), "http://x/#/contact");
        assert_eq!(page_key("http://x/#!/about"), "http://x/#!/about");
        assert_eq!(page_key("http://x/a"), "http://x/a");
    }
}
