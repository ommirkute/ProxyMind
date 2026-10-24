//! Content discovery through the policy gate: GET each candidate path once,
//! in scope only, and report what exists, telling real pages from the
//! server's "not found" page (soft 404s).

use pm_crawl::discover::{self, NotFound};
use pm_policy::{Actor, Target, Tier};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

use crate::{Authorization, Result, Service, ServiceError};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiscoverRequest {
    /// The folder to look in, e.g. https://app.example.com/ or …/api/
    pub url: String,
    /// Words to try (paths relative to url). Empty: the built-in list.
    pub words: Vec<String>,
    /// Also try the built-in list when giving words.
    pub builtin: bool,
    /// Extensions to add to words without one, e.g. ["bak", "old", "php"].
    pub extensions: Vec<String>,
    /// Most requests (default 500, max 5000).
    pub max_requests: Option<usize>,
    pub identity: Option<String>,
    pub approval_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Found {
    pub url: String,
    pub status: u16,
    pub length: usize,
    pub exchange_id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// Why it deserves a look (backup, source control, admin…), if it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DiscoverResult {
    Done {
        base: String,
        tried: usize,
        found: Vec<Found>,
        /// The server answers missing pages with something other than 404.
        soft_404: bool,
        /// Candidates not sent and why (first 100).
        skipped: Vec<String>,
        /// Requests that failed (first 20).
        errors: Vec<String>,
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
    let host = pm_core::authority(u.scheme(), u.host_str().unwrap_or(""), u.port_or_known_default().unwrap_or(80));
    format!("GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ProxyMind-discover\r\nAccept: */*\r\n\r\n", u.path())
}

fn token() -> Result<String> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = [0u8; 6];
    SystemRandom::new().fill(&mut b).map_err(|_| ServiceError::Invalid("no system randomness".into()))?;
    Ok(format!("pm{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()))
}

/// Status, Location and decoded body of a recorded response.
fn parts(resp: &[u8]) -> Option<(u16, Option<String>, Vec<u8>)> {
    let (head, body) = pm_http::split_message(resp);
    let h = pm_http::parse_response_head(head).ok()?;
    let loc = pm_http::header(&h.headers, "location").map(|v| String::from_utf8_lossy(v).into_owned());
    Some((h.status, loc, pm_ai::body::decode(&h.headers, body).bytes))
}

/// Which "not found" fingerprint applies: folders, files with an extension, or plain words.
fn shape(u: &Url) -> usize {
    let last = u.path().rsplit('/').next().unwrap_or_default();
    if u.path().ends_with('/') {
        0
    } else if last.contains('.') {
        1
    } else {
        2
    }
}

impl Service {
    pub async fn discover(&self, actor: &Actor, req: DiscoverRequest) -> Result<DiscoverResult> {
        let base = Url::parse(&req.url).map_err(|e| ServiceError::Invalid(format!("bad url: {e}")))?;
        if !matches!(base.scheme(), "http" | "https") {
            return Err(ServiceError::Invalid("discovery needs an http(s) URL".into()));
        }
        let mut words = req.words.clone();
        if words.is_empty() || req.builtin {
            words.extend(discover::BUILTIN_WORDS.iter().map(|s| s.to_string()));
        }
        let max = req.max_requests.unwrap_or(500).clamp(1, discover::MAX_CANDIDATES);
        let mut cands = discover::candidates(&base, &words, &req.extensions);
        cands.truncate(max);
        if cands.is_empty() {
            return Err(ServiceError::Invalid("no usable words".into()));
        }
        if let Some(name) = &req.identity {
            self.load_identity(name)?;
        }
        let first =
            self.outgoing(crate::replay::parse_url_endpoint(base.as_str())?, get_request(&base).as_bytes(), false)?;
        let extra = json!({ "discover": { "base": base.as_str(), "candidates": cands.len() } });
        match self.gate_send_with(
            actor,
            "discover",
            &first,
            req.identity.as_deref(),
            false,
            req.approval_id.as_deref(),
            Some(Tier::ActiveSafe),
            extra,
        )? {
            Authorization::Allowed { .. } => {}
            Authorization::Denied { reasons } => return Ok(DiscoverResult::Denied { reasons }),
            Authorization::PendingApproval { approval_id, summary, reasons } => {
                return Ok(DiscoverResult::PendingApproval {
                    approval_id,
                    summary: format!("look for {} hidden paths (GET only): {summary}", cands.len()),
                    reasons,
                });
            }
        }

        let identity = req.identity.as_deref();
        let send = |u: Url| async move {
            let out =
                self.outgoing(crate::replay::parse_url_endpoint(u.as_str())?, get_request(&u).as_bytes(), false)?;
            let (sent, _) = self.send_as(actor, &out, identity, false, "discover").await?;
            Ok::<_, ServiceError>(sent)
        };

        // What missing pages look like here, for each shape of path.
        let mut dir = base.clone();
        dir.set_query(None);
        if !dir.path().ends_with('/') {
            let p = format!("{}/", dir.path());
            dir.set_path(&p);
        }
        let mut fingerprints: Vec<Option<NotFound>> = vec![None, None, None];
        let mut soft_404 = false;
        for (i, suffix) in ["/", ".html", ""].iter().enumerate() {
            let t = token()?;
            let probe = dir.join(&format!("{t}{suffix}")).map_err(|e| ServiceError::Invalid(e.to_string()))?;
            if let Some((status, loc, body)) = send(probe).await?.response.as_deref().and_then(parts) {
                soft_404 |= !matches!(status, 404 | 410);
                fingerprints[i] = Some(NotFound::new(status, loc.as_deref(), &body, &t));
            }
        }

        let (mut found, mut skipped, mut errors) = (Vec::new(), Vec::new(), Vec::new());
        let mut tried = 0;
        for u in cands {
            let in_scope = Target::from_url(u.as_str()).is_ok_and(|t| self.policy.scope_check(&t).is_ok());
            let why = if !in_scope {
                Some("out of scope".to_string())
            } else if let Some(r) = pm_crawl::risky(&u) {
                Some(format!("the path probably {r}"))
            } else if Tier::for_http_request(get_request(&u).as_bytes()).0 > Tier::ActiveSafe {
                Some("not a safe request".into())
            } else {
                None
            };
            if let Some(why) = why {
                if skipped.len() < 100 {
                    skipped.push(format!("{}: {why}", u.path()));
                }
                continue;
            }
            tried += 1;
            let sent = send(u.clone()).await?;
            let Some((status, location, body)) = sent.response.as_deref().and_then(parts) else {
                if errors.len() < 20 {
                    errors.push(format!("{}: {}", u.path(), sent.error.unwrap_or_else(|| "no response".into())));
                }
                continue;
            };
            let word = u.path().trim_end_matches('/').rsplit('/').next().unwrap_or_default();
            let missing = matches!(status, 404 | 410)
                || fingerprints[shape(&u)]
                    .as_ref()
                    .is_some_and(|nf| nf.matches(status, location.as_deref(), &body, word));
            if missing {
                continue;
            }
            found.push(Found {
                url: u.to_string(),
                status,
                length: body.len(),
                exchange_id: sent.exchange_id,
                location,
                note: discover::interesting(u.path()),
            });
        }
        self.audit(
            &actor.id(),
            "discover_done",
            json!({ "base": base.as_str(), "tried": tried, "found": found.len() }),
            "ok",
        )?;
        Ok(DiscoverResult::Done { base: dir.to_string(), tried, found, soft_404, skipped, errors })
    }
}
