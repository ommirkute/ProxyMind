//! Sending to integrations (roadmap 3.5): provider requests, the outbound path, redaction of what leaves.
//!
//! Outbound requests here are not target traffic: they are not recorded in history and not checked against the
//! rules of engagement. They go through ProxyMind's own sender with the network settings (upstream rules, hostname
//! overrides), TLS verification always on, timeouts, and a destination check: a name that resolves to a private,
//! loopback or link-local address is refused unless the person allowed private destinations for that integration
//! (link-local, the cloud metadata range, is refused either way), plain `http` is only allowed to a private address
//! that was allowed, redirects are not followed, and a secret is only used for the server it was saved for. Every
//! send is audited (action, integration, host, status; never a body, a header or a secret) and leaves a row in the
//! delivery log.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pm_core::now_ms;
use pm_policy::Actor;
use pm_store::{DeliveryRow, NewDelivery};
use serde_json::{Value, json};
use url::Url;

use crate::access::{Denial, Perm};
use crate::integration_payload::{self as payload, Brief, IssueBrief, ProofBrief, Step};
use crate::integrations::{
    Bucket, Integration, IntegrationKind, IssueLink, SendFindingBody, base_of, clean_secret, origin_of, parse_url,
};
use crate::{Result, Service, ServiceError};

/// Most requests shown in a reproduction, and how much of each.
const MAX_STEPS: usize = 4;
const HEAD_CHARS: usize = 2000;
const BODY_CHARS: usize = 800;
/// Most of an error response that is kept in the log (after scrubbing).
const ERROR_SNIPPET: usize = 200;
/// Response bodies are read for the issue key only: nothing larger is looked at.
const MAX_RESPONSE: usize = 256 * 1024;

fn invalid<T>(msg: impl Into<String>) -> Result<T> {
    Err(ServiceError::Invalid(msg.into()))
}

// ---- destination check ---------------------------------------------------------------------------------------

/// Loopback, private, shared (CGNAT), unique-local and documentation ranges, and IPv4 inside IPv6 forms.
pub(crate) fn is_private(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v) => private_v4(v),
        IpAddr::V6(v) => {
            let s = v.segments();
            if v.is_loopback() || v.is_unspecified() || s[0] & 0xfe00 == 0xfc00 || s[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // NAT64 (64:ff9b::/96) and 6to4 (2002::/16) carry an IPv4 address that decides where packets go.
            if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
                return private_v4(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8));
            }
            if s[0] == 0x2002 {
                return private_v4(Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8));
            }
            false
        }
    }
}

fn private_v4(v: Ipv4Addr) -> bool {
    let o = v.octets();
    v.is_loopback()
        || v.is_private()
        || v.is_link_local()
        || v.is_unspecified()
        || v.is_broadcast()
        || v.is_documentation()
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || o[0] == 0
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || o[0] >= 240
}

/// Never allowed, whatever the integration says: link-local (cloud metadata at 169.254.169.254), unspecified,
/// multicast and broadcast.
pub(crate) fn always_denied(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v) => v.is_link_local() || v.is_unspecified() || v.is_multicast() || v.is_broadcast(),
        IpAddr::V6(v) => {
            v.is_unspecified() || v.is_multicast() || v.segments()[0] & 0xffc0 == 0xfe80 || is_embedded_link_local(v)
        }
    }
}

fn is_embedded_link_local(v: Ipv6Addr) -> bool {
    let s = v.segments();
    let embedded = if s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0, 0, 0, 0] {
        Some(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8))
    } else if s[0] == 0x2002 {
        Some(Ipv4Addr::new((s[1] >> 8) as u8, s[1] as u8, (s[2] >> 8) as u8, s[2] as u8))
    } else {
        None
    };
    embedded.is_some_and(|e| e.is_link_local() || e.is_unspecified())
}

/// The check run on the addresses a host name resolved to, right before connecting.
pub(crate) fn guard_addresses(
    ips: &[IpAddr],
    plain_http: bool,
    allow_private: bool,
) -> std::result::Result<(), String> {
    for &ip in ips {
        if always_denied(ip) {
            return Err(format!("{ip} is never allowed for integrations (link-local, unspecified or multicast)"));
        }
        if is_private(ip) && !allow_private {
            return Err(format!(
                "the host resolves to {ip}, a private or loopback address; allow private destinations for this \
                 integration if that is intended"
            ));
        }
        if plain_http && !is_private(ip) {
            return Err("plain http is only allowed to a private address (use https)".into());
        }
    }
    Ok(())
}

// ---- requests ------------------------------------------------------------------------------------------------

/// One outbound request, before it is turned into bytes.
pub(crate) struct Prepared {
    pub url: Url,
    pub method: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub json: bool,
}

impl Prepared {
    fn new(method: &'static str, url: Url) -> Self {
        Self { url, method, headers: vec![], body: vec![], json: false }
    }

    fn header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.to_string(), v.into()));
        self
    }

    fn json_body(mut self, v: &Value) -> Self {
        self.body = serde_json::to_vec(v).unwrap_or_default();
        self.json = true;
        self
    }

    fn raw(&self) -> Result<Vec<u8>> {
        let host = self.url.host_str().unwrap_or_default();
        let port = self.url.port_or_known_default().unwrap_or(443);
        let mut path = self.url.path().to_string();
        if let Some(q) = self.url.query() {
            path.push('?');
            path.push_str(q);
        }
        let mut out = format!(
            "{} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ProxyMind/{}\r\nConnection: close\r\n",
            self.method,
            pm_core::authority(self.url.scheme(), host.trim_matches(['[', ']']), port),
            env!("CARGO_PKG_VERSION")
        );
        if !self.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("accept")) {
            out.push_str("Accept: application/json, text/plain, */*\r\n");
        }
        if self.json {
            out.push_str("Content-Type: application/json\r\n");
        }
        if !self.body.is_empty() || self.method != "GET" {
            out.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        for (k, v) in &self.headers {
            if !clean_secret(v) || k.chars().any(|c| c.is_control() || c == ':' || c.is_whitespace()) {
                return invalid(format!("the value of header {k} is empty or has a line break"));
            }
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }
}

/// A path under a base URL that may itself have a path (`https://host/jira`).
fn join(base: &Url, tail: &str) -> Result<Url> {
    let mut u = base.clone();
    u.set_query(None);
    u.set_fragment(None);
    let p = format!("{}/{}", base.path().trim_end_matches('/'), tail.trim_start_matches('/'));
    // `set_path` would re-encode a %2F we put there on purpose (GitLab project paths); build the string instead.
    Url::parse(&format!("{}{}", &u[..url::Position::BeforePath], p))
        .map_err(|e| ServiceError::Invalid(format!("not a valid address: {e}")))
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn jira_auth(i: &Integration, token: &str) -> String {
    if i.email.is_empty() {
        format!("Bearer {token}")
    } else {
        format!("Basic {}", pm_core::base64(format!("{}:{token}", i.email).as_bytes()))
    }
}

/// How an integration's request for each action looks. `token` is the API token.
pub(crate) fn tracker_request(i: &Integration, token: &str, action: Action<'_>) -> Result<Prepared> {
    let base = base_of(i)?;
    let version = env!("CARGO_PKG_VERSION");
    let labels = &i.labels;
    Ok(match (i.kind, action) {
        (IntegrationKind::Jira, Action::Test) => {
            Prepared::new("GET", join(&base, &format!("/rest/api/2/project/{}", enc(&i.project)))?)
                .header("Authorization", jira_auth(i, token))
        }
        (IntegrationKind::Jira, Action::Create(b)) => {
            let mut fields = json!({
                "project": { "key": i.project },
                "summary": payload::title(b),
                "issuetype": { "name": i.issue_type },
                "description": payload::jira_body(b, version),
            });
            if !labels.is_empty() {
                fields["labels"] = json!(labels.iter().map(|l| payload::jira_label(l)).collect::<Vec<_>>());
            }
            Prepared::new("POST", join(&base, "/rest/api/2/issue")?)
                .header("Authorization", jira_auth(i, token))
                .json_body(&json!({ "fields": fields }))
        }
        (IntegrationKind::Jira, Action::Update(b, key)) => {
            Prepared::new("PUT", join(&base, &format!("/rest/api/2/issue/{}", enc(key)))?)
                .header("Authorization", jira_auth(i, token))
                .json_body(&json!({ "fields": {
                    "summary": payload::title(b),
                    "description": payload::jira_body(b, version),
                }}))
        }
        (IntegrationKind::Github, a) => {
            let (owner, repo) = i.project.split_once('/').unwrap_or_default();
            let repo_path = format!("/repos/{}/{}", enc(owner), enc(repo));
            let p = match a {
                Action::Test => Prepared::new("GET", join(&base, &repo_path)?),
                Action::Create(b) => {
                    let mut body = json!({ "title": payload::title(b), "body": payload::markdown_body(b, version) });
                    if !labels.is_empty() {
                        body["labels"] = json!(labels);
                    }
                    Prepared::new("POST", join(&base, &format!("{repo_path}/issues"))?).json_body(&body)
                }
                Action::Update(b, n) => Prepared::new("PATCH", join(&base, &format!("{repo_path}/issues/{}", enc(n)))?)
                    .json_body(&json!({ "title": payload::title(b), "body": payload::markdown_body(b, version) })),
            };
            p.header("Authorization", format!("Bearer {token}"))
                .header("Accept", "application/vnd.github+json")
                .header("X-GitHub-Api-Version", "2022-11-28")
        }
        (IntegrationKind::Gitlab, a) => {
            let project = format!("/api/v4/projects/{}", enc(&i.project));
            let p = match a {
                Action::Test => Prepared::new("GET", join(&base, &project)?),
                Action::Create(b) => {
                    let mut body =
                        json!({ "title": payload::title(b), "description": payload::markdown_body(b, version) });
                    if !labels.is_empty() {
                        body["labels"] = json!(labels.join(","));
                    }
                    Prepared::new("POST", join(&base, &format!("{project}/issues"))?).json_body(&body)
                }
                Action::Update(b, iid) => Prepared::new("PUT", join(&base, &format!("{project}/issues/{}", enc(iid)))?)
                    .json_body(
                        &json!({ "title": payload::title(b), "description": payload::markdown_body(b, version) }),
                    ),
            };
            p.header("PRIVATE-TOKEN", token)
        }
        _ => return invalid(format!("{} does not create issues", i.name)),
    })
}

/// What to ask a tracker.
pub(crate) enum Action<'a> {
    /// Read the project (checks the address, the project and the token).
    Test,
    Create(&'a Brief),
    /// Update the issue with this provider id.
    Update(&'a Brief, &'a str),
}

/// The link a tracker's answer to a create describes.
fn parse_created(i: &Integration, body: &[u8]) -> Result<(String, String, String)> {
    let v: Value = serde_json::from_slice(body)
        .map_err(|_| ServiceError::Invalid("the server's answer was not the JSON of an issue".into()))?;
    let base = base_of(i)?;
    let safe = |u: Option<&str>| u.filter(|u| u.starts_with("https://") || u.starts_with("http://")).map(String::from);
    match i.kind {
        IntegrationKind::Jira => {
            let key = v["key"]
                .as_str()
                .filter(|k| k.len() < 64 && !k.contains(['/', '?', '#', ' ']))
                .ok_or_else(|| ServiceError::Invalid("Jira's answer had no issue key".into()))?;
            let url = join(&base, &format!("/browse/{}", enc(key)))?.to_string();
            Ok((key.to_string(), url, key.to_string()))
        }
        IntegrationKind::Github | IntegrationKind::Gitlab => {
            let (field, url_field) =
                if i.kind == IntegrationKind::Github { ("number", "html_url") } else { ("iid", "web_url") };
            let n =
                v[field].as_i64().ok_or_else(|| ServiceError::Invalid(format!("the answer had no issue {field}")))?;
            let fallback = if i.kind == IntegrationKind::Github {
                format!("https://github.com/{}/issues/{n}", i.project)
            } else {
                format!("{}/{}/-/issues/{n}", origin_of(&base), i.project)
            };
            Ok((format!("#{n}"), safe(v[url_field].as_str()).unwrap_or(fallback), n.to_string()))
        }
        _ => invalid("not a tracker"),
    }
}

// ---- delivering ----------------------------------------------------------------------------------------------

/// Who sent what, for the delivery log.
#[derive(Clone, Copy)]
struct Delivered<'a> {
    actor: &'a str,
    kind: &'a str,
    event: &'a str,
    finding_id: Option<i64>,
}

pub(crate) struct Sent {
    pub status: u16,
    pub body: Vec<u8>,
    pub attempts: u32,
    pub host: String,
}

pub(crate) struct SendFail {
    pub message: String,
    pub status: Option<u16>,
    pub attempts: u32,
    pub host: String,
}

fn scrub_with(text: &str, secrets: &[String]) -> String {
    let mut t = text.to_string();
    for s in secrets.iter().filter(|s| s.len() >= 4) {
        t = t.replace(s.as_str(), "[secret]");
        // A webhook URL's path is the secret part: hide it, and each long segment of it, on its own too.
        if let Some(p) = s.split_once("://").and_then(|(_, r)| r.split_once('/')).map(|(_, p)| p) {
            for part in std::iter::once(p).chain(p.split('/')).filter(|x| x.len() >= 8) {
                t = t.replace(part, "[secret]");
            }
        }
    }
    t
}

impl Service {
    fn integration_sender(&self) -> Result<Arc<pm_replay::Sender>> {
        let mut rt = self.integrations.lock();
        if let Some(s) = &rt.sender {
            return Ok(s.clone());
        }
        // Verification is always on: there is no insecure option for integrations.
        let s = Arc::new(
            pm_replay::Sender::new(true)?
                .with_network(self.network().clone())
                .with_timeouts(Duration::from_secs(10), Duration::from_secs(20)),
        );
        rt.sender = Some(s.clone());
        Ok(s)
    }

    /// Redacts text the way reports shown to agents are, then removes the integration's own secrets.
    pub(crate) fn scrub(&self, text: &str, secrets: &[String]) -> String {
        scrub_with(&self.redactor_scope("integrations").redact(text), secrets)
    }

    /// Sends `p`, retrying transport errors, 408, 429 and 5xx with a doubling wait when `retry` (at most the tuned
    /// number of attempts). Redirects are not followed. `secrets` are scrubbed out of anything returned.
    pub(crate) async fn deliver(
        &self,
        integ: &Integration,
        p: &Prepared,
        retry: bool,
        secrets: &[String],
    ) -> std::result::Result<Sent, SendFail> {
        let host = p.url.host_str().unwrap_or_default().to_string();
        let fail = |message: String, status: Option<u16>, attempts: u32| SendFail {
            message: scrub_with(&message, secrets).chars().take(300).collect(),
            status,
            attempts,
            host: host.clone(),
        };
        let raw = p.raw().map_err(|e| fail(e.to_string(), None, 0))?;
        let sender = self.integration_sender().map_err(|e| fail(e.to_string(), None, 0))?;
        let ep_host = match p.url.host() {
            Some(url::Host::Domain(d)) => d.to_string(),
            Some(url::Host::Ipv4(a)) => a.to_string(),
            Some(url::Host::Ipv6(a)) => a.to_string(),
            None => return Err(fail("the address has no host".into(), None, 0)),
        };
        let ep = pm_replay::Endpoint::new(p.url.scheme(), &ep_host, p.url.port_or_known_default().unwrap_or(443));
        let (plain, allow) = (p.url.scheme() == "http", integ.allow_private);
        let check = move |ips: &[IpAddr]| guard_addresses(ips, plain, allow);
        let tuning = self.integration_tuning();
        let max = if retry { tuning.max_attempts.max(1) } else { 1 };
        let mut attempt = 0;
        loop {
            attempt += 1;
            let result = sender.send(&ep, &raw, p.method, Some(&check)).await;
            let (retryable, failure) = match result {
                Ok(r) => {
                    let status = r.head.status;
                    let (_, body) = pm_http::split_message(&r.raw);
                    let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
                    let body = body[..body.len().min(MAX_RESPONSE)].to_vec();
                    if (200..300).contains(&status) {
                        return Ok(Sent { status, body, attempts: attempt, host: host.clone() });
                    }
                    let text = String::from_utf8_lossy(&body[..body.len().min(2048)]).into_owned();
                    let snippet: String = scrub_with(&self.redactor_scope("integrations").redact(&text), secrets)
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ")
                        .chars()
                        .take(ERROR_SNIPPET)
                        .collect();
                    let note = match status {
                        300..=399 => "the server redirected (redirects are not followed)".to_string(),
                        401 | 403 => "the server refused the credentials".to_string(),
                        404 => "not found (check the address and the project)".to_string(),
                        _ => format!("the server answered {status}"),
                    };
                    let msg = if snippet.is_empty() {
                        format!("HTTP {status}: {note}")
                    } else {
                        format!("HTTP {status}: {note} ({snippet})")
                    };
                    (matches!(status, 408 | 429 | 500..=599), fail(msg, Some(status), attempt))
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    let permanent =
                        ["refused before connecting", "certificate", "invalid peer", "UnknownIssuer", "not a valid"]
                            .iter()
                            .any(|m| msg.contains(m));
                    (!permanent, fail(msg, None, attempt))
                }
            };
            if !retryable || attempt >= max {
                return Err(failure);
            }
            let wait = tuning.backoff_base_ms.saturating_mul(1 << (attempt - 1).min(16)).min(tuning.backoff_cap_ms);
            tokio::time::sleep(Duration::from_millis(wait)).await;
        }
    }

    /// Writes one row of the delivery log and one audit record (names and status, nothing else).
    pub(crate) fn integration_record(&self, d: NewDelivery) -> DeliveryRow {
        let id = match self.store.write(|db| db.insert_delivery(&d)) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!("integration delivery not logged: {e:#}");
                0
            }
        };
        let detail = json!({
            "integration": d.integration, "kind": d.kind, "event": d.event, "finding_id": d.finding_id,
            "host": d.host, "http_status": d.http_status, "attempts": d.attempts,
        });
        if let Err(e) =
            self.audit(&d.actor, "integration_send", detail, if d.status == "ok" { "allow" } else { &d.status })
        {
            tracing::warn!("integration send not audited: {e}");
        }
        DeliveryRow {
            id,
            integration: d.integration,
            ts_ms: d.ts_ms,
            kind: d.kind,
            event: d.event,
            finding_id: d.finding_id,
            status: d.status,
            http_status: d.http_status,
            attempts: d.attempts,
            host: d.host,
            detail: d.detail,
            actor: d.actor,
        }
    }

    fn delivery(
        &self,
        integ: &Integration,
        what: Delivered<'_>,
        result: &std::result::Result<Sent, SendFail>,
        ok_detail: String,
    ) -> DeliveryRow {
        let Delivered { actor, kind, event, finding_id } = what;
        let (status, http_status, attempts, host, detail) = match result {
            Ok(s) => ("ok", Some(s.status), s.attempts, s.host.clone(), ok_detail),
            Err(f) => ("failed", f.status, f.attempts, f.host.clone(), f.message.clone()),
        };
        self.integration_record(NewDelivery {
            integration: integ.name.clone(),
            ts_ms: now_ms(),
            kind: kind.into(),
            event: event.into(),
            finding_id,
            status: status.into(),
            http_status,
            attempts,
            host,
            detail,
            actor: actor.into(),
        })
    }

    fn require_active(&self, integ: &Integration) -> Result<()> {
        if !integ.enabled {
            return invalid(format!("{} is turned off", integ.name));
        }
        if !self.integration_trusted(integ) {
            return invalid(format!(
                "{} has not been enabled in this installation (it may have come with the project file): review its \
                 address and enable it first",
                integ.name
            ));
        }
        Ok(())
    }

    fn token_of(&self, integ: &Integration) -> Result<String> {
        self.integration_secret(integ, "token")?.ok_or_else(|| {
            ServiceError::Invalid(format!("{} has no token (set it, or check its environment variable)", integ.name))
        })
    }

    /// Whether and how much to take from an integration's notification budget.
    pub(crate) fn take_token(&self, name: &str, per_minute: u32) -> bool {
        let cap = f64::from(per_minute.max(1));
        let mut rt = self.integrations.lock();
        let now = Instant::now();
        let b = rt.buckets.entry(name.to_string()).or_insert(Bucket { tokens: cap, at: now });
        b.tokens = (b.tokens + now.duration_since(b.at).as_secs_f64() * cap / 60.0).min(cap);
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    // ---- what a finding becomes ----

    /// The finding as an integration sends it: every string redacted (cookies, tokens, passwords, JWTs, and the
    /// integration's own secrets), requests cut to a few lines, no response bodies.
    pub(crate) fn finding_brief(&self, id: i64, secrets: &[String], with_steps: bool) -> Result<Brief> {
        let f = self.finding_get(id)?;
        let s = |v: &Value| self.scrub(v.as_str().unwrap_or(""), secrets);
        let class = f["vuln_class"].as_str().unwrap_or("");
        let issue = pm_scan::library::lookup(class);
        let proven = f["proofs"].as_array().and_then(|a| a.iter().find(|p| p["proven"] == true)).cloned();
        let mut ids: Vec<i64> = serde_json::from_value(f["evidence"].clone()).unwrap_or_default();
        if let Some(p) = &proven {
            for e in serde_json::from_value::<Vec<i64>>(p["exchange_ids"].clone()).unwrap_or_default() {
                if !ids.contains(&e) {
                    ids.push(e);
                }
            }
        }
        ids.truncate(8);
        let mut steps = vec![];
        if with_steps {
            for ex_id in ids.iter().take(MAX_STEPS) {
                let Some(ex) = self.store.read(|db| db.get_exchange(*ex_id))? else { continue };
                steps.push(Step {
                    exchange_id: *ex_id,
                    identity: ex.summary.identity.as_deref().map(|i| self.scrub(i, secrets)),
                    request: self.scrub(&request_text(&ex.request), secrets),
                });
            }
        }
        Ok(Brief {
            id,
            title: s(&f["title"]),
            severity: f["severity"].as_str().unwrap_or("info").to_string(),
            status: f["status"].as_str().unwrap_or("").to_string(),
            vuln_class: s(&f["vuln_class"]),
            url: s(&f["url"]),
            description: s(&f["description"]),
            issue: issue.map(|i| IssueBrief {
                id: i.id.to_string(),
                name: i.name.to_string(),
                cwe: i.cwe.iter().map(|c| format!("CWE-{c}")).collect(),
                owasp: i.owasp.to_string(),
                owasp_api: i.owasp_api.map(String::from),
            }),
            proof: proven.as_ref().map(|p| ProofBrief {
                oracle: s(&p["oracle"]),
                confidence: s(&p["confidence"]),
                reasons: p["reasons"].as_array().into_iter().flatten().map(s).collect(),
            }),
            steps,
            exchange_ids: ids,
            remediation: issue.map(|i| i.remediation.chars().take(1500).collect()).unwrap_or_default(),
        })
    }

    /// The issues already created for a finding.
    pub(crate) fn issue_links_of(&self, finding: &Value) -> Vec<IssueLink> {
        serde_json::from_value(finding["issue_links"].clone()).unwrap_or_default()
    }

    // ---- actions ----

    /// Creates (or, with `update`, refreshes) the issue for a finding in a Jira, GitHub or GitLab integration. People
    /// only. The finding's text, proof summary and reproduction go through the redactor; the issue's key and URL are
    /// kept on the finding. A finding that already has an issue there is refused unless `update` is set, and two
    /// sends of the same finding to one integration cannot run at once.
    pub async fn integration_send_finding(
        &self,
        actor: &Actor,
        finding_id: i64,
        body: SendFindingBody,
    ) -> Result<IssueLink> {
        self.require_actor_with(
            actor,
            Perm::IntegrationsSend,
            Denial::audited(
                "integration_send_finding",
                json!({ "integration": &body.integration, "finding_id": finding_id }),
            ),
        )?;
        let integ = self.integration_find(&body.integration)?;
        if !integ.kind.is_tracker() {
            return invalid(format!("{} is a {}: it takes notifications, not issues", integ.name, integ.kind.as_str()));
        }
        self.require_active(&integ)?;
        let finding = self.finding_get(finding_id)?;
        let links = self.issue_links_of(&finding);
        let existing = links.iter().find(|l| l.integration == integ.name).cloned();
        if let Some(l) = &existing
            && !body.update
        {
            return invalid(format!(
                "finding {finding_id} already has issue {} in {} ({}): send with update to refresh it",
                l.key, integ.name, l.url
            ));
        }
        let key = format!("{}/{finding_id}", integ.name);
        if !self.integrations.lock().in_flight.insert(key.clone()) {
            return invalid("this finding is already being sent to this integration");
        }
        let result = self.send_issue(actor, &integ, finding_id, existing, links).await;
        self.integrations.lock().in_flight.remove(&key);
        result
    }

    async fn send_issue(
        &self,
        actor: &Actor,
        integ: &Integration,
        finding_id: i64,
        existing: Option<IssueLink>,
        mut links: Vec<IssueLink>,
    ) -> Result<IssueLink> {
        let token = self.token_of(integ)?;
        let mut secrets = self.integration_secret_values(integ);
        secrets.push(token.clone());
        let brief = self.finding_brief(finding_id, &secrets, true)?;
        let p = match &existing {
            Some(l) => tracker_request(integ, &token, Action::Update(&brief, &l.id))?,
            None => tracker_request(integ, &token, Action::Create(&brief))?,
        };
        // An issue is created once: a POST that timed out may still have worked, so it is not retried.
        let result = self.deliver(integ, &p, false, &secrets).await;
        let event = if existing.is_some() { "update_issue" } else { "create_issue" };
        let parsed = match (&result, &existing) {
            (Ok(_), Some(l)) => Ok((l.key.clone(), l.url.clone(), l.id.clone())),
            (Ok(s), None) => parse_created(integ, &s.body),
            (Err(f), _) => Err(ServiceError::Invalid(f.message.clone())),
        };
        let detail = parsed.as_ref().map(|(k, _, _)| k.clone()).unwrap_or_default();
        let row = self.delivery(
            integ,
            Delivered { actor: &actor.id(), kind: "issue", event, finding_id: Some(finding_id) },
            &result,
            detail,
        );
        let (key, url, id) = match parsed {
            Ok(v) => v,
            Err(e) if result.is_ok() => {
                // The server said yes but its answer could not be read: say so (the issue may exist).
                return invalid(format!(
                    "{} accepted the request but {e}; check the tracker before sending again",
                    integ.name
                ));
            }
            Err(e) => return Err(e),
        };
        let now = now_ms();
        let link = IssueLink {
            integration: integ.name.clone(),
            kind: integ.kind,
            key,
            url,
            id,
            created_ms: existing.as_ref().map_or(now, |l| l.created_ms),
            updated_ms: now,
            by: actor.id(),
        };
        links.retain(|l| l.integration != integ.name);
        links.push(link.clone());
        let mut ch = serde_json::Map::new();
        ch.insert("issue_links".into(), json!(serde_json::to_string(&links).unwrap_or_default()));
        ch.insert("updated_ms".into(), json!(now));
        self.store.write(|db| db.update_row("findings", finding_id, &ch))?;
        let f = self.finding_get(finding_id)?;
        self.finding_changed(finding_id, f["status"].as_str().unwrap_or(""), f["url"].as_str().unwrap_or(""));
        let _ = row;
        Ok(link)
    }

    /// Checks an integration end to end: a read of the tracker's project, a test message to Slack, a `test` event to a
    /// webhook. Recorded in the delivery log. People only; the integration must be on and enabled in this
    /// installation.
    pub async fn integration_test(&self, actor: &Actor, name: &str) -> Result<DeliveryRow> {
        self.require_actor_with(
            actor,
            Perm::IntegrationsWrite,
            Denial::message("only people can test integrations").and_audit("integration_test", json!({ "name": name })),
        )?;
        let integ = self.integration_find(name)?;
        self.require_active(&integ)?;
        let mut secrets = self.integration_secret_values(&integ);
        let (p, event) = if integ.kind.is_tracker() {
            let token = self.token_of(&integ)?;
            secrets.push(token.clone());
            (tracker_request(&integ, &token, Action::Test)?, "test")
        } else {
            let msg = self.test_notice(actor);
            (self.notification_request(&integ, "test", &msg.0, &msg.1, &mut secrets)?, "test")
        };
        let result = self.deliver(&integ, &p, false, &secrets).await;
        Ok(self.delivery(
            &integ,
            Delivered { actor: &actor.id(), kind: "test", event, finding_id: None },
            &result,
            format!("HTTP {}", result.as_ref().map_or(0, |s| s.status)),
        ))
    }

    fn test_notice(&self, actor: &Actor) -> (String, payload::WebhookData) {
        let text = format!("ProxyMind test message from {}. If you can read this, the integration works.", actor.id());
        (text.clone(), payload::WebhookData { message: Some(text), ..Default::default() })
    }

    /// The request a Slack or webhook integration sends for `event`: `headline` is the Slack text, `data` the
    /// webhook payload's `data`. Adds the secrets it used to `secrets` so they can be scrubbed from errors.
    pub(crate) fn notification_request(
        &self,
        integ: &Integration,
        event: &str,
        headline: &str,
        data: &payload::WebhookData,
        secrets: &mut Vec<String>,
    ) -> Result<Prepared> {
        match integ.kind {
            IntegrationKind::Slack => {
                let url = self
                    .integration_secret(integ, "webhook_url")?
                    .ok_or_else(|| ServiceError::Invalid(format!("{} has no webhook URL", integ.name)))?;
                secrets.push(url.clone());
                let u = parse_url(&url)?;
                let lines: Vec<String> = slack_lines(data);
                Ok(Prepared::new("POST", u)
                    .json_body(&payload::slack_message(&payload::slack_escape(headline), &lines)))
            }
            IntegrationKind::Webhook => {
                let u = parse_url(&integ.base_url)?;
                let id = random_id();
                let body = payload::WebhookPayload {
                    v: payload::WEBHOOK_VERSION,
                    id: id.clone(),
                    ts: jiff::Timestamp::now().to_string(),
                    event: event.to_string(),
                    engagement: self.policy.roe().engagement.name.clone(),
                    data: data.clone(),
                };
                let bytes = serde_json::to_vec(&body).map_err(|e| ServiceError::Invalid(e.to_string()))?;
                let mut p = Prepared::new("POST", u);
                p.json = true;
                p = p
                    .header("X-ProxyMind-Event", event)
                    .header("X-ProxyMind-Delivery", id)
                    .header("X-ProxyMind-Timestamp", body.ts.clone());
                if let Some(secret) = self.integration_secret(integ, "signing_secret")? {
                    p = p.header("X-ProxyMind-Signature", payload::signature(secret.as_bytes(), &bytes));
                    secrets.push(secret);
                }
                for n in &integ.header_names {
                    if let Some(v) = self.integration_secret(integ, &format!("header:{n}"))? {
                        secrets.push(v.clone());
                        p = p.header(n, v);
                    }
                }
                p.body = bytes;
                Ok(p)
            }
            _ => invalid(format!("{} takes no notifications", integ.name)),
        }
    }

    /// Sends one notification to one integration right now, as the event loop does: within its rate limit, with
    /// bounded retries, logged either way. It does not check that the integration is enabled in this installation
    /// (the event loop only picks integrations that are).
    #[doc(hidden)]
    pub async fn integration_notify_for_test(
        &self,
        integ: &Integration,
        event: &str,
        headline: &str,
        data: &payload::WebhookData,
    ) {
        self.notify_one(integ, event, None, headline, data).await;
    }

    /// Sends one notification to one integration: within its rate limit, with bounded retries, logged either way.
    pub(crate) async fn notify_one(
        &self,
        integ: &Integration,
        event: &str,
        finding_id: Option<i64>,
        headline: &str,
        data: &payload::WebhookData,
    ) {
        let actor = "scanner:integrations";
        let host = base_of_host(integ);
        if !self.take_token(&integ.name, integ.rate_per_minute) {
            self.integration_record(NewDelivery {
                integration: integ.name.clone(),
                ts_ms: now_ms(),
                kind: "event".into(),
                event: event.into(),
                finding_id,
                status: "skipped".into(),
                http_status: None,
                attempts: 0,
                host,
                detail: format!("rate limited ({} per minute)", integ.rate_per_minute),
                actor: actor.into(),
            });
            return;
        }
        let mut secrets = self.integration_secret_values(integ);
        let prepared = self.notification_request(integ, event, headline, data, &mut secrets);
        let result = match prepared {
            Ok(p) => self.deliver(integ, &p, true, &secrets).await,
            Err(e) => Err(SendFail { message: e.to_string(), status: None, attempts: 0, host }),
        };
        let ok = format!("HTTP {}", result.as_ref().map_or(0, |s| s.status));
        self.delivery(integ, Delivered { actor, kind: "event", event, finding_id }, &result, ok);
    }
}

fn base_of_host(i: &Integration) -> String {
    Url::parse(&i.base_url).ok().and_then(|u| u.host_str().map(String::from)).unwrap_or_default()
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The raw text of a request for an issue: the head, and a short body when it is text. Line endings become `\n`.
fn request_text(raw: &[u8]) -> String {
    let (head, body) = pm_http::split_message(raw);
    let head = String::from_utf8_lossy(head).replace("\r\n", "\n");
    let head: String = head.trim_end().chars().take(HEAD_CHARS).collect();
    let body = match std::str::from_utf8(body) {
        Ok("") => String::new(),
        Ok(t) => {
            let cut: String = t.chars().take(BODY_CHARS).collect();
            if cut.len() < t.len() { format!("{cut}\n… (cut)") } else { cut }
        }
        Err(_) => format!("[binary body, {} bytes]", body.len()),
    };
    if body.is_empty() { head } else { format!("{head}\n\n{body}") }
}

/// Lines under a Slack message's headline (escaped).
fn slack_lines(d: &payload::WebhookData) -> Vec<String> {
    let esc = payload::slack_escape;
    let mut out = vec![];
    if let Some(f) = &d.finding {
        out.push(format!("*Status:* {}  *Class:* {}", esc(&f.status), esc(&f.vuln_class)));
        out.push(format!("*URL:* {}", esc(&f.url)));
        if let Some(p) = &f.proof {
            out.push(format!("*Proof:* {} ({})", esc(&p.oracle), esc(&p.confidence)));
        }
        if let Some(prev) = &d.previous_status {
            out.push(format!("*Was:* {}", esc(prev)));
        }
        for l in &f.issue_links {
            out.push(format!("*Issue:* {} {}", esc(&l.integration), esc(&l.key)));
        }
    }
    if let Some(s) = &d.scan {
        out.push(format!(
            "*Start URL:* {}\n*Issues:* {}  *Requests:* {}  *Targets:* {}/{}",
            esc(&s.url),
            s.issues,
            s.requests,
            s.targets_done,
            s.targets_total
        ));
        if let Some(e) = &s.error {
            out.push(format!("*Error:* {}", esc(e)));
        }
    }
    if let Some(s) = &d.summary {
        let sev: Vec<String> =
            s.by_severity.iter().filter(|c| c.count > 0).map(|c| format!("{} {}", c.count, esc(&c.name))).collect();
        out.push(format!("*Findings:* {} ({} proven)  {}", s.findings, s.proven, sev.join(", ")));
        for t in &s.top {
            out.push(format!("• #{} [{}] {} ({})", t.id, esc(&t.severity), esc(&t.title), esc(&t.status)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn private_ranges_are_recognised_in_every_form() {
        for p in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::1",
        ] {
            assert!(is_private(ip(p)), "{p} is private");
        }
        for p in ["93.184.216.34", "8.8.8.8", "172.32.0.1", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808"] {
            assert!(!is_private(ip(p)), "{p} is public");
        }
    }

    #[test]
    fn link_local_is_never_allowed_and_http_needs_a_private_address() {
        let meta = [ip("169.254.169.254")];
        assert!(guard_addresses(&meta, false, true).is_err(), "metadata refused even when private is allowed");
        assert!(guard_addresses(&[ip("::ffff:169.254.169.254")], false, true).is_err());
        assert!(guard_addresses(&[ip("fe80::1")], false, true).is_err());
        let lo = [ip("127.0.0.1")];
        assert!(guard_addresses(&lo, false, false).is_err());
        assert!(guard_addresses(&lo, false, true).is_ok());
        assert!(guard_addresses(&lo, true, true).is_ok(), "plain http to an allowed private address");
        assert!(guard_addresses(&[ip("93.184.216.34")], true, true).is_err(), "plain http to the internet");
        assert!(guard_addresses(&[ip("93.184.216.34")], false, false).is_ok());
        // One bad address among good ones refuses the lot (a name with several records).
        assert!(guard_addresses(&[ip("93.184.216.34"), ip("10.0.0.1")], false, false).is_err());
    }

    #[test]
    fn request_text_cuts_bodies_and_marks_binary() {
        let t = request_text(b"POST /x HTTP/1.1\r\nHost: a\r\n\r\n{\"a\":1}");
        assert_eq!(t, "POST /x HTTP/1.1\nHost: a\n\n{\"a\":1}");
        let t = request_text(b"POST /x HTTP/1.1\r\nHost: a\r\n\r\n\xff\xfe\x00");
        assert!(t.ends_with("[binary body, 3 bytes]"));
        let long = format!("POST /x HTTP/1.1\r\n\r\n{}", "a".repeat(2000));
        assert!(request_text(long.as_bytes()).ends_with("(cut)"));
    }

    #[test]
    fn join_keeps_context_paths_and_encoded_slashes() {
        let base = Url::parse("https://host.test/jira/").unwrap();
        assert_eq!(join(&base, "/rest/api/2/issue").unwrap().as_str(), "https://host.test/jira/rest/api/2/issue");
        let base = Url::parse("https://gitlab.test").unwrap();
        let u = join(&base, &format!("/api/v4/projects/{}/issues", enc("group/sub proj"))).unwrap();
        assert_eq!(u.as_str(), "https://gitlab.test/api/v4/projects/group%2Fsub%20proj/issues");
    }

    #[test]
    fn scrub_hides_secrets_and_webhook_paths() {
        let url = "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX".to_string();
        let s = scrub_with(&format!("bad: {url} and XXXXXXXXXXXX"), &[url.clone(), "tok-123456".into()]);
        assert!(!s.contains("XXXXXXXXXXXX") && !s.contains("services/T000"), "{s}");
        assert_eq!(scrub_with("tok-123456 x", &["tok-123456".into()]), "[secret] x");
    }
}
