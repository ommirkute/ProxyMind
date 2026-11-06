//! More of the attack surface for the automatic pass: folders robots.txt
//! hides, other API versions of known paths, and described XML uploads.
//! Each sends a few requests through the policy gate.

use pm_policy::{Actor, Tier};
use serde_json::json;

use crate::{Authorization, DiscoverRequest, DiscoverResult, Found, Result, Service};

/// Most known paths tried under other versions, and versions per path.
const MAX_VERSION_PATHS: usize = 8;

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

/// The version segment of a path (`v2` in `/api/v2/login`).
fn version_of(path: &str) -> String {
    path.split('/')
        .find(|s| s.len() >= 2 && s.starts_with('v') && s[1..].chars().all(|c| c.is_ascii_digit()))
        .unwrap_or("v1")
        .to_string()
}
