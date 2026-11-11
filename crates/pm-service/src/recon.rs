//! Passive recon that sends nothing to the target: DNS records (asked of
//! the resolver) and the URLs the Internet Archive has seen for the site.
//! Only for hosts in scope (and, for DNS, their parent domains, where SPF
//! and DMARC records live); every lookup is audited.

use std::net::SocketAddr;
use std::time::Duration;

use pm_policy::Actor;
use pm_tools::dns::{self, Record};
use pm_tools::wayback::{self, Capture};
use serde::Serialize;
use serde_json::json;

use crate::{Result, Service, ServiceError};

/// Most captures asked of the archive.
const MAX_CAPTURES: usize = 5000;
const ARCHIVE: &str = "https://web.archive.org";

#[derive(Debug, Clone, Serialize)]
pub struct DnsReport {
    pub host: String,
    pub resolver: String,
    pub records: Vec<Record>,
    /// What stands out (no SPF or DMARC, a permissive policy, a CNAME to a
    /// service often left dangling…).
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WaybackCapture {
    #[serde(flatten)]
    pub capture: Capture,
    /// Traffic has shown this path already.
    pub known: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WaybackReport {
    pub host: String,
    /// Captures on this host (before `limit` cut the list).
    pub total: usize,
    pub interesting: usize,
    pub captures: Vec<WaybackCapture>,
}

/// CNAME targets of services where a deleted resource leaves the name claimable.
const DANGLING: &[&str] = &[
    ".s3.amazonaws.com",
    ".cloudfront.net",
    ".herokuapp.com",
    ".github.io",
    ".azurewebsites.net",
    ".cloudapp.net",
    ".trafficmanager.net",
    ".blob.core.windows.net",
    ".pantheonsite.io",
    ".netlify.app",
    ".vercel.app",
    ".fastly.net",
    ".zendesk.com",
    ".ghost.io",
];

/// The first nameserver in /etc/resolv.conf, if any.
fn system_resolver() -> Option<SocketAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    text.lines().find_map(|l| {
        let ip = l.trim().strip_prefix("nameserver")?.trim().split('%').next()?.parse::<std::net::IpAddr>().ok()?;
        Some(SocketAddr::new(ip, 53))
    })
}

async fn ask(resolver: SocketAddr, name: &str, qtype: u16) -> Option<dns::Answer> {
    let bind: SocketAddr = if resolver.is_ipv6() { "[::]:0".parse().ok()? } else { "0.0.0.0:0".parse().ok()? };
    let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
    for _ in 0..2 {
        let id: u16 = rand_id();
        let q = dns::query(id, name, qtype)?;
        sock.send_to(&q, resolver).await.ok()?;
        let mut buf = vec![0u8; 4096];
        if let Ok(Ok((n, from))) = tokio::time::timeout(Duration::from_secs(3), sock.recv_from(&mut buf)).await
            && from == resolver
            && let Some(a) = dns::parse(&buf[..n])
            && a.id == id
        {
            return Some(a);
        }
    }
    None
}

fn rand_id() -> u16 {
    let t = pm_oast::new_token();
    u16::from_str_radix(&t[..4], 16).unwrap_or(4242)
}

impl Service {
    /// Hosts the scope covers: exact hosts, and suffixes for `*.` patterns.
    fn scope_hosts(&self) -> Vec<(String, bool)> {
        self.policy
            .roe()
            .include
            .iter()
            .filter_map(|p| {
                let text = p.text.replace("://*.", "://wildcard-placeholder.");
                let host = url::Url::parse(&text).ok()?.host_str()?.to_ascii_lowercase();
                match host.strip_prefix("wildcard-placeholder.") {
                    Some(rest) => Some((rest.to_string(), true)),
                    None => Some((host, false)),
                }
            })
            .collect()
    }

    /// Whether DNS may be asked about `host`: a host in scope or a parent
    /// domain of one (at least two labels).
    fn dns_allowed(&self, host: &str) -> bool {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        if !h.contains('.') {
            return false;
        }
        self.scope_hosts()
            .iter()
            .any(|(s, wild)| *s == h || s.ends_with(&format!(".{h}")) || (*wild && h.ends_with(&format!(".{s}"))))
    }

    /// DNS records for a host in scope (or a parent domain): A, AAAA, CNAME,
    /// MX, TXT, NS, SOA, CAA, plus `_dmarc` TXT. Asks `resolver` (default:
    /// the system's, else 1.1.1.1); sends nothing to the target.
    pub async fn recon_dns(&self, actor: &Actor, host: &str, resolver: Option<SocketAddr>) -> Result<DnsReport> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if !self.dns_allowed(&host) {
            return Err(ServiceError::Invalid(format!(
                "{host} isn't in scope (or a parent domain of a host in scope)"
            )));
        }
        let resolver = resolver.or_else(system_resolver).unwrap_or_else(|| "1.1.1.1:53".parse().expect("valid"));
        let mut records = Vec::new();
        let mut notes = Vec::new();
        let mut answered = false;
        for (_, t) in dns::TYPES {
            if let Some(a) = ask(resolver, &host, *t).await {
                answered = true;
                if a.truncated {
                    notes.push(format!(
                        "the {} answer was truncated (too large for UDP)",
                        dns::TYPES.iter().find(|x| x.1 == *t).map_or("", |x| x.0)
                    ));
                }
                for r in a.records {
                    if !records.contains(&r) {
                        records.push(r);
                    }
                }
            }
        }
        let dmarc_name = format!("_dmarc.{host}");
        let dmarc: Vec<Record> = ask(resolver, &dmarc_name, 16)
            .await
            .map(|a| a.records)
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.kind == "TXT")
            .collect();
        if !answered {
            notes.push(format!("no answer from the resolver {resolver}"));
        } else {
            let txt =
                |pred: &dyn Fn(&str) -> bool| records.iter().filter(|r| r.kind == "TXT" && pred(&r.value)).count();
            match txt(&|v| v.starts_with("v=spf1")) {
                0 if records.iter().any(|r| r.kind == "MX") => notes.push("MX records but no SPF record".into()),
                _ => {}
            }
            if records.iter().any(|r| {
                r.kind == "TXT"
                    && r.value.starts_with("v=spf1")
                    && (r.value.trim_end().ends_with("+all") || r.value.trim_end().ends_with("?all"))
            }) {
                notes.push("the SPF record ends with +all or ?all: anyone may send mail as this domain".into());
            }
            match dmarc.iter().find(|r| r.value.starts_with("v=DMARC1")) {
                None if records.iter().any(|r| r.kind == "MX") => notes.push("no DMARC record (_dmarc)".into()),
                Some(d) if d.value.replace(' ', "").contains("p=none") => {
                    notes.push("DMARC policy is p=none (reports only, nothing rejected)".into());
                }
                _ => {}
            }
            if !records.iter().any(|r| r.kind == "CAA") {
                notes.push("no CAA record: any certificate authority may issue for this name".into());
            }
            for r in records.iter().filter(|r| r.kind == "CNAME") {
                let target = r.value.to_ascii_lowercase();
                if DANGLING.iter().any(|d| target.ends_with(d)) {
                    notes.push(format!(
                        "CNAME to {target}: check the resource still exists there (a deleted one can be claimed)"
                    ));
                }
            }
        }
        records.extend(dmarc);
        self.audit(
            &actor.id(),
            "recon_dns",
            json!({ "host": host, "resolver": resolver.to_string(), "records": records.len() }),
            "ok",
        )?;
        Ok(DnsReport { host, resolver: resolver.to_string(), records, notes })
    }

    /// URLs the Internet Archive has captured for a host in scope, interesting
    /// ones first (backups, configs, APIs, parameters), each marked if
    /// traffic has shown it. Asks the archive (through the upstream proxy
    /// settings), never the target. `archive` overrides the archive's
    /// address (tests).
    pub async fn recon_wayback(
        &self,
        actor: &Actor,
        host: &str,
        limit: usize,
        archive: Option<&str>,
    ) -> Result<WaybackReport> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if !self.scope_hosts().iter().any(|(s, wild)| *s == host || (*wild && host.ends_with(&format!(".{s}")))) {
            return Err(ServiceError::Invalid(format!("{host} isn't in scope")));
        }
        let base = archive.unwrap_or(ARCHIVE);
        let url = url::Url::parse(base).map_err(|e| ServiceError::Invalid(e.to_string()))?;
        let scheme = url.scheme().to_string();
        let ah = url.host_str().unwrap_or_default().to_string();
        let port = url.port_or_known_default().unwrap_or(443);
        let target = format!(
            "/cdx/search/cdx?url={host}/*&output=json&fl=original,statuscode,mimetype,timestamp&collapse=urlkey&limit={MAX_CAPTURES}"
        );
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: {ah}\r\nUser-Agent: ProxyMind/{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );
        let sender = pm_replay::Sender::new(true)
            .map_err(|e| ServiceError::Invalid(format!("{e:#}")))?
            .with_network(self.network().clone())
            .with_timeouts(Duration::from_secs(15), Duration::from_secs(90));
        let ep = pm_replay::Endpoint::new(&scheme, &ah, port);
        let r = sender
            .send(&ep, request.as_bytes(), "GET", None)
            .await
            .map_err(|e| ServiceError::Invalid(format!("couldn't reach the Internet Archive: {e:#}")))?;
        if r.head.status != 200 {
            return Err(ServiceError::Invalid(format!("the Internet Archive answered {}", r.head.status)));
        }
        let (_, body) = pm_http::split_message(&r.raw);
        let body = pm_http::decode_chunked(body).unwrap_or_else(|| body.to_vec());
        let model = self.model()?;
        let mut caps: Vec<WaybackCapture> = wayback::parse_cdx(&String::from_utf8_lossy(&body))
            .into_iter()
            .filter(|c| {
                url::Url::parse(&c.url).ok().and_then(|u| u.host_str().map(str::to_ascii_lowercase)).as_deref()
                    == Some(host.as_str())
            })
            .map(|c| {
                let path = url::Url::parse(&c.url).map(|u| u.path().to_string()).unwrap_or_default();
                let known = model.operations.iter().any(|o| o.template == path);
                WaybackCapture { capture: c, known }
            })
            .collect();
        let total = caps.len();
        caps.sort_by_key(|c| (c.capture.note.is_none(), c.known));
        let interesting = caps.iter().filter(|c| c.capture.note.is_some()).count();
        caps.truncate(limit.clamp(1, MAX_CAPTURES));
        self.audit(&actor.id(), "recon_wayback", json!({ "host": host, "captures": total }), "ok")?;
        Ok(WaybackReport { host, total, interesting, captures: caps })
    }
}
