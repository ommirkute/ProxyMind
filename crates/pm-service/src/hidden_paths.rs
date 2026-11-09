//! More of the attack surface for the automatic pass: folders robots.txt
//! hides, other API versions of known paths, described XML uploads, and
//! endpoints the app's JavaScript mentions.
//! Each sends a few requests through the policy gate.

use pm_policy::{Actor, Tier};
use serde_json::json;

use crate::{Authorization, DiscoverRequest, DiscoverResult, Found, Result, Service};

/// Most known paths tried under other versions, and versions per path.
const MAX_VERSION_PATHS: usize = 8;
/// Most scripts fetched, and new endpoints from scripts tried, per origin.
const MAX_SCRIPTS: usize = 15;
const MAX_JS_ENDPOINTS: usize = 80;

/// What reading the app's JavaScript added.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct JsSweep {
    /// Scripts the pages reference, fetched to read.
    pub scripts: usize,
    /// Endpoints the scripts mention that traffic hadn't shown.
    pub new: usize,
    /// Those that exist (`GET /rest/admin/application-version → 200`).
    pub found: Vec<String>,
}

impl Service {
    /// Runs content discovery in each folder the site's robots.txt hides
    /// (`Disallow: /internal/`). Returns what it found.
    pub(crate) async fn robots_discover(&self, actor: &Actor, origin: &str, found: &[Found]) -> Result<Vec<Found>> {
        let Some(robots) = found.iter().find(|f| f.status == 200 && f.url.ends_with("/robots.txt")) else {
            return Ok(Vec::new());
        };
        let Ok(ex) = self.exchange_raw(robots.exchange_id) else { return Ok(Vec::new()) };
        let Some(resp) = ex.response.as_deref() else { return Ok(Vec::new()) };
        let (_, body) = pm_http::split_message(resp);
        let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
        let mut out = Vec::new();
        for dir in pm_crawl::discover::robots_dirs(&String::from_utf8_lossy(&body)).into_iter().take(4) {
            let req = DiscoverRequest { url: format!("{origin}{dir}"), max_requests: Some(120), ..Default::default() };
            if let Ok(DiscoverResult::Done { found, .. }) = self.discover(actor, req).await {
                out.extend(found);
            }
        }
        Ok(out)
    }

    /// Tries known paths under other API versions (`/api/login` as
    /// `/api/v2/login` when the app uses `/api/v3/…`): GETs without
    /// parameters and logins, re-sent from a recorded example with only
    /// the path changed. A version answers when its status differs from a
    /// version that can't exist (v97). Returns `METHOD path → status` hits.
    pub(crate) async fn version_siblings(&self, actor: &Actor, origin: &str) -> Result<Vec<String>> {
        let model = self.model()?;
        let ops: Vec<_> = model.operations.iter().filter(|o| o.origin.eq_ignore_ascii_case(origin)).collect();
        // Logins first (old versions often lack newer protections), then GETs.
        let mut templates: Vec<String> = ops.iter().map(|o| o.template.clone()).collect();
        templates.sort_by_key(|t| !crate::auto::is_login(t));
        templates.dedup();
        let pairs = pm_crawl::discover::version_siblings(&templates);
        let mut hits = Vec::new();
        let mut by_known: Vec<(&str, Vec<&str>)> = Vec::new();
        for (known, sibling) in &pairs {
            match by_known.iter_mut().find(|(k, _)| *k == known.as_str()) {
                Some((_, v)) => v.push(sibling.as_str()),
                None => by_known.push((known.as_str(), vec![sibling.as_str()])),
            }
        }
        for (known, siblings) in by_known.into_iter().take(MAX_VERSION_PATHS) {
            let Some(op) = ops.iter().find(|o| {
                o.template == known && (o.method == "GET" || (o.method == "POST" && crate::auto::is_login(known)))
            }) else {
                continue;
            };
            let Some(&example) = op.examples.last() else { continue };
            let Ok(ex) = self.exchange_raw(example) else { continue };
            let endpoint = crate::replay::parse_url_endpoint(origin)?;
            let with_path = |path: &str| pm_http::replace_request_target(&ex.request, path);
            // One gate decision per known path (its siblings are the same request elsewhere).
            let Some(first) = with_path(siblings[0]) else { continue };
            let out = self.outgoing(endpoint.clone(), &first, true)?;
            let tier = if op.method == "GET" { Tier::ActiveSafe } else { Tier::ActiveIntrusive };
            let extra = json!({ "version_siblings": { "known": known, "siblings": siblings } });
            match self.gate_send_with(actor, "version_siblings", &out, None, true, None, Some(tier), extra)? {
                Authorization::Allowed { .. } => {}
                _ => continue,
            }
            let send = |raw: Vec<u8>| {
                let endpoint = endpoint.clone();
                async move {
                    let out = self.outgoing(endpoint, &raw, true)?;
                    Ok::<_, crate::ServiceError>(self.send_as(actor, &out, None, true, "discover").await?.0)
                }
            };
            let control_path = siblings[0].replacen(&version_of(siblings[0]), "v97", 1);
            let Some(control) = with_path(&control_path) else { continue };
            let control = send(control).await?.status;
            for s in siblings {
                let Some(raw) = with_path(s) else { continue };
                let got = send(raw.clone()).await?;
                let Some(status) = got.status else { continue };
                if matches!(status, 404 | 405 | 410 | 501) || Some(status) == control {
                    continue;
                }
                // Discovery's 4xx answers stay out of the app model unless marked as hits.
                if status >= 400 {
                    let out = self.outgoing(endpoint.clone(), &raw, true)?;
                    self.send_as(actor, &out, None, true, "discover_hit").await?;
                }
                hits.push(format!("{} {s} → {status}", op.method));
            }
        }
        Ok(hits)
    }

    /// Sends the description's XML upload examples (POST or PUT with an XML
    /// body and no login needed) once each, so the sweep's XML checks (XXE)
    /// have a request to work on. At most two.
    pub(crate) async fn send_xml_examples(
        &self,
        actor: &Actor,
        base: &str,
        operations: &[pm_openapi::Operation],
    ) -> Result<Vec<String>> {
        let endpoint = crate::replay::parse_url_endpoint(base)?;
        let mut sent = Vec::new();
        let xml = |o: &&pm_openapi::Operation| {
            let head = o.example_request.split("\r\n\r\n").next().unwrap_or_default().to_ascii_lowercase();
            head.lines().any(|l| l.starts_with("content-type:") && l.contains("xml"))
        };
        let candidates = operations
            .iter()
            .filter(|o| !o.auth && matches!(o.method.as_str(), "POST" | "PUT"))
            .filter(|o| !crate::auto::changes_state(&o.path))
            .filter(xml);
        for op in candidates.take(2) {
            let out = self.outgoing(endpoint.clone(), op.example_request.as_bytes(), true)?;
            let extra = json!({ "openapi_xml_example": op.path });
            if let Authorization::Allowed { .. } = self.gate_send_with(
                actor,
                "openapi_xml_example",
                &out,
                None,
                true,
                None,
                Some(Tier::ActiveIntrusive),
                extra,
            )? {
                let (s, _) = self.send_as(actor, &out, None, true, "openapi").await?;
                sent.push(format!(
                    "{} {} → {}",
                    op.method,
                    op.path,
                    s.status.map_or("no answer".into(), |c| c.to_string())
                ));
            }
        }
        Ok(sent)
    }
}

impl Service {
    /// Reads the app's JavaScript for endpoints traffic hasn't shown: fetches
    /// the scripts its pages reference (same origin), lists the endpoints
    /// they mention, and checks the new GET ones without placeholders with
    /// content discovery (so a catch-all page doesn't count). Those that take
    /// query parameters are then sent once with them, so the scanner has a
    /// request to work on.
    pub(crate) async fn js_discover(&self, actor: &Actor, origin: &str) -> Result<JsSweep> {
        let mut sweep = JsSweep::default();
        let host = url::Url::parse(origin).ok().and_then(|u| u.host_str().map(str::to_string));
        let filter = crate::EngageFilter { host, ..Default::default() };
        let same = |u: &str| u.starts_with(origin) && u[origin.len()..].starts_with('/');
        // 1. Scripts: referenced by pages, or named by other scripts.
        let mut scripts: Vec<String> = Vec::new();
        let referenced = self.engage_scripts(actor, &filter)?.into_iter().filter_map(|s| s.src);
        let named = self.engage_js_endpoints(actor, &filter)?.into_iter().filter(|e| e.script).map(|e| e.url);
        for u in referenced.chain(named) {
            let path = u.split(['?', '#']).next().unwrap_or_default().to_string();
            if same(&path) && !scripts.contains(&path) {
                scripts.push(path);
            }
        }
        let words = |urls: &[String]| -> Vec<String> {
            urls.iter().map(|u| u[origin.len()..].trim_start_matches('/').to_string()).collect()
        };
        scripts.truncate(MAX_SCRIPTS);
        if !scripts.is_empty() {
            let req = DiscoverRequest {
                url: format!("{origin}/"),
                words: words(&scripts),
                max_requests: Some(scripts.len()),
                ..Default::default()
            };
            if let Ok(DiscoverResult::Done { found, .. }) = self.discover(actor, req).await {
                sweep.scripts = found.iter().filter(|f| f.status == 200).count();
            }
        }
        // 2. New endpoints they mention.
        let new: Vec<crate::FoundEndpoint> = self
            .engage_js_endpoints(actor, &filter)?
            .into_iter()
            .filter(|e| !e.known && !e.external && !e.script && e.method.is_none_or(|m| m == "GET"))
            .filter(|e| same(&e.url) && !e.url.contains('{'))
            .take(MAX_JS_ENDPOINTS)
            .collect();
        sweep.new = new.len();
        if new.is_empty() {
            return Ok(sweep);
        }
        let paths: Vec<String> = new.iter().map(|e| e.url.split('?').next().unwrap_or_default().to_string()).collect();
        let req = DiscoverRequest {
            url: format!("{origin}/"),
            words: words(&paths),
            max_requests: Some(paths.len()),
            ..Default::default()
        };
        let Ok(DiscoverResult::Done { found, .. }) = self.discover(actor, req).await else { return Ok(sweep) };
        // 3. Found ones with parameters, sent once with them.
        let endpoint = crate::replay::parse_url_endpoint(origin)?;
        let mut gated = false;
        for f in &found {
            sweep.found.push(format!("GET {} → {}", &f.url[origin.len()..], f.status));
            let Some(e) = new.iter().find(|e| e.url.split('?').next() == Some(f.url.as_str())) else { continue };
            if e.params.is_empty() || f.status >= 400 {
                continue;
            }
            let query: Vec<String> = e.params.iter().map(|p| format!("{p}=1")).collect();
            let target = format!("{}?{}", &f.url[origin.len()..], query.join("&"));
            let host = url::Url::parse(origin).ok().and_then(|u| u.host_str().map(str::to_string)).unwrap_or_default();
            let raw = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\n\r\n");
            let out = self.outgoing(endpoint.clone(), raw.as_bytes(), false)?;
            if !gated {
                let extra = json!({ "js_endpoints": origin });
                match self.gate_send_with(
                    actor,
                    "js_endpoints",
                    &out,
                    None,
                    false,
                    None,
                    Some(Tier::ActiveSafe),
                    extra,
                )? {
                    Authorization::Allowed { .. } => gated = true,
                    _ => break,
                }
            }
            self.send_as(actor, &out, None, false, "discover").await?;
        }
        Ok(sweep)
    }
}

/// The version segment of a path (`v2` in `/api/v2/login`).
fn version_of(path: &str) -> String {
    path.split('/')
        .find(|s| s.len() >= 2 && s.starts_with('v') && s[1..].chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("v1")
        .to_string()
}
