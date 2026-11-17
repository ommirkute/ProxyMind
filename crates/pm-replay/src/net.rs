//! Network settings for outgoing connections: an ordered list of upstream rules (direct, an HTTP proxy or a SOCKS5
//! proxy, chosen per host), client certificates for mutual TLS, hostname overrides, and hosts whose TLS the proxy
//! passes through without interception.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use parking_lot::RwLock;
use pm_tls::TlsConnector;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct NetConfig {
    /// Where outgoing connections go, by target host. The first rule whose `match` fits the host wins; a host
    /// that fits no rule is reached directly. Used by the proxy, Replay, the scanner, the fuzzer and agents.
    pub upstream_rules: Vec<UpstreamRule>,
    /// The older single-upstream form. Still accepted on input: it becomes `upstream_rules` (one rule that
    /// goes through the proxy, after one that sends the `bypass` hosts directly) and is never returned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<UpstreamProxy>,
    /// Client certificates, by host. The first matching entry is used.
    pub client_certs: Vec<ClientCert>,
    /// Fixed addresses for host names (like a hosts file). The first
    /// matching entry wins. TLS still uses the name (SNI, certificate).
    pub hosts: Vec<HostOverride>,
    /// The proxy tunnels connections to these hosts without decrypting them
    /// (`example.com`, `*.example.com`): for certificate pinning or noise.
    /// Nothing inside such a tunnel is recorded.
    pub tls_passthrough: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostOverride {
    /// `api.example.com` or `*.example.com`.
    pub host: String,
    /// The address to connect to instead of what DNS says.
    pub address: IpAddr,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    #[default]
    Http,
    Socks5,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamProxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// Optional login (Basic for HTTP proxies, username/password for SOCKS5).
    pub username: String,
    pub password: String,
    /// Let the proxy resolve target names: "socks5h" for SOCKS5; for HTTP
    /// proxies, CONNECT tunnels name the host instead of the checked address
    /// (for proxies that only allow named hosts). Off by default so the proxy
    /// connects to the address ProxyMind resolved and checked against the
    /// denied networks. Plain HTTP through an HTTP proxy always goes by name.
    pub remote_dns: bool,
    /// Hosts reached directly: `example.com`, `*.example.com` or `*`.
    pub bypass: Vec<String>,
}

/// How many upstream rules a project can have.
pub const MAX_UPSTREAM_RULES: usize = 64;
/// How many match patterns one upstream rule can have.
pub const MAX_RULE_PATTERNS: usize = 100;

/// One entry of the ordered upstream list: which targets it covers and how to reach them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamRule {
    /// Which targets this rule covers: host names (`example.com` is exact, `*.example.com` also covers
    /// `example.com`, `*` and `?` work anywhere else, `*` is everything) and CIDR ranges such as `10.0.0.0/8`
    /// or `fd00::/8`. A range covers targets given as an IP address, not names that resolve into it. Empty:
    /// covers everything, which only makes sense for the last rule.
    #[serde(rename = "match")]
    pub matches: Vec<String>,
    /// `direct`, `http://host:port` (CONNECT for HTTPS) or `socks5://host:port`.
    pub via: String,
    /// Optional login for the proxy (Basic for HTTP, username/password for SOCKS5). Kept in the project like
    /// other secrets, hidden when settings are shown (`********`) and never logged.
    pub username: String,
    pub password: String,
    /// Let the proxy resolve target names ("socks5h" for SOCKS5; for HTTP proxies, CONNECT names the host).
    /// Off by default so the proxy is asked for the address ProxyMind resolved and checked against the denied
    /// networks (protection against DNS rebinding). Plain HTTP through an HTTP proxy always goes by name.
    pub remote_dns: bool,
}

/// What `via` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Via {
    Direct,
    Proxy { kind: ProxyKind, host: String, port: u16 },
}

/// Reads a `via` value: `direct`, `http://host:port` or `socks5://host:port`.
pub fn parse_via(via: &str) -> Result<Via> {
    let v = via.trim();
    if v.eq_ignore_ascii_case("direct") {
        return Ok(Via::Direct);
    }
    let (kind, rest) = if let Some(r) = v.strip_prefix("http://") {
        (ProxyKind::Http, r)
    } else if let Some(r) = v.strip_prefix("socks5://") {
        (ProxyKind::Socks5, r)
    } else {
        bail!("`via` must be direct, http://host:port or socks5://host:port (got {v:?})");
    };
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    ensure!(
        !rest.contains(['@', '/', '?', '#']),
        "`via` takes no login or path: put the login in the username and password fields"
    );
    let (host, port) = pm_http::split_host_port(rest, 0).ok_or_else(|| anyhow!("bad host in `via` {v:?}"))?;
    ensure!(!host.is_empty() && port != 0, "`via` {v:?} needs a host and a port");
    Ok(Via::Proxy { kind, host, port })
}

fn via_text(kind: ProxyKind, host: &str, port: u16) -> String {
    let scheme = if kind == ProxyKind::Socks5 { "socks5" } else { "http" };
    if host.contains(':') { format!("{scheme}://[{host}]:{port}") } else { format!("{scheme}://{host}:{port}") }
}

/// Whether one match pattern covers a host (a name or an IP address, with or without brackets).
pub fn pattern_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim();
    let host = host.trim().trim_matches(['[', ']']);
    if let Some((net, bits)) = parse_cidr(pattern) {
        return host.parse::<IpAddr>().is_ok_and(|ip| cidr_contains(net, bits, ip.to_canonical()));
    }
    if pattern.starts_with("*.") || !pattern.contains(['*', '?']) {
        return host_matches(pattern, host);
    }
    glob(pattern.to_ascii_lowercase().as_bytes(), host.trim_end_matches('.').to_ascii_lowercase().as_bytes())
}

/// `*` (any run) and `?` (one byte) wildcards.
fn glob(p: &[u8], t: &[u8]) -> bool {
    let (mut pi, mut ti, mut star, mut mark) = (0, 0, None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) && p[pi] != b'*' {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

fn parse_cidr(p: &str) -> Option<(IpAddr, u8)> {
    let (ip, bits) = p.split_once('/')?;
    let ip: IpAddr = ip.trim().trim_matches(['[', ']']).parse().ok()?;
    let bits: u8 = bits.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((ip.to_canonical(), bits))
}

fn cidr_contains(net: IpAddr, bits: u8, ip: IpAddr) -> bool {
    let (a, b): (u128, u128) = match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => (u128::from(u32::from(n)) << 96, u128::from(u32::from(i)) << 96),
        (IpAddr::V6(n), IpAddr::V6(i)) => (u128::from(n), u128::from(i)),
        _ => return false,
    };
    if bits == 0 {
        return true;
    }
    let mask = u128::MAX << (128 - u32::from(bits));
    a & mask == b & mask
}

/// A rule pattern: a name pattern (letters, digits, `-`, `.`, `_`, `:`, `*`, `?`) or a CIDR range.
fn valid_rule_pattern(p: &str) -> bool {
    let p = p.trim();
    if p.contains('/') {
        return parse_cidr(p).is_some();
    }
    !p.is_empty()
        && p.len() <= 253
        && p.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':' | '*' | '?'))
}

impl UpstreamRule {
    /// The proxy this rule uses, in the form the sender works with; `None` for `direct`.
    fn proxy(&self) -> Option<UpstreamProxy> {
        match parse_via(&self.via).ok()? {
            Via::Direct => None,
            Via::Proxy { kind, host, port } => Some(UpstreamProxy {
                kind,
                host,
                port,
                username: self.username.clone(),
                password: self.password.clone(),
                remote_dns: self.remote_dns,
                bypass: vec![],
            }),
        }
    }

    /// The first pattern that covers the host (`None` when none does; an empty `match` covers everything).
    pub fn covering_pattern(&self, host: &str) -> Option<Option<&str>> {
        if self.matches.is_empty() {
            return Some(None);
        }
        self.matches.iter().find(|p| pattern_matches(p, host)).map(|p| Some(p.as_str()))
    }

    /// Checks one rule (not its place in the list).
    pub fn validate(&self) -> Result<()> {
        ensure!(self.matches.len() <= MAX_RULE_PATTERNS, "at most {MAX_RULE_PATTERNS} match patterns per rule");
        for p in &self.matches {
            ensure!(valid_rule_pattern(p), "bad match pattern {p:?}: use a host name, a * pattern or a CIDR range");
        }
        let via = parse_via(&self.via)?;
        ensure!(self.username.len() <= 255 && self.password.len() <= 255, "proxy username and password: 255 bytes max");
        if via == Via::Direct {
            ensure!(
                self.username.is_empty() && self.password.is_empty() && !self.remote_dns,
                "a direct rule has no login and no remote DNS"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ClientCert {
    /// `api.example.com`, `*.example.com` or `*`.
    pub host: String,
    /// PEM certificate chain, leaf first.
    pub cert_file: PathBuf,
    /// PEM private key.
    pub key_file: PathBuf,
}

/// `example.com` matches only itself; `*.example.com` matches subdomains
/// and `example.com`; `*` matches everything. Case-insensitive.
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let (p, h) = (pattern.trim().to_ascii_lowercase(), host.trim_end_matches('.').to_ascii_lowercase());
    match p.strip_prefix("*.") {
        _ if p == "*" => true,
        Some(base) => h == base || h.ends_with(&format!(".{base}")),
        None => p == h,
    }
}

/// A host name or `*.` pattern: letters, digits, `-`, `.` and `_` (or `*`).
fn valid_pattern(p: &str) -> bool {
    let rest = p.strip_prefix("*.").unwrap_or(p);
    p == "*"
        || (!rest.is_empty()
            && rest.len() <= 253
            && rest.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':')))
}

impl UpstreamProxy {
    fn basic_auth(&self) -> Option<String> {
        (!self.username.is_empty())
            .then(|| format!("Basic {}", pm_core::base64(format!("{}:{}", self.username, self.password).as_bytes())))
    }
}

impl NetConfig {
    /// Folds the older single `upstream` into `upstream_rules`. Fails when both are given.
    pub fn normalized(mut self) -> Result<Self> {
        let Some(u) = self.upstream.take() else { return Ok(self) };
        ensure!(self.upstream_rules.is_empty(), "give either `upstream` (older form) or `upstream_rules`, not both");
        ensure!(!u.host.trim().is_empty() && u.port != 0, "the upstream proxy needs a host and port");
        let bypass: Vec<String> = u.bypass.iter().filter(|b| !b.trim().is_empty()).cloned().collect();
        if !bypass.is_empty() {
            self.upstream_rules.push(UpstreamRule { matches: bypass, via: "direct".into(), ..Default::default() });
        }
        self.upstream_rules.push(UpstreamRule {
            matches: vec![],
            via: via_text(u.kind, u.host.trim(), u.port),
            username: u.username,
            password: u.password,
            remote_dns: u.remote_dns,
        });
        Ok(self)
    }

    /// Checks the settings and loads the certificates.
    pub fn validate(&self) -> Result<()> {
        if let Some(u) = &self.upstream {
            ensure!(!u.host.trim().is_empty() && u.port != 0, "the upstream proxy needs a host and port");
            ensure!(u.username.len() <= 255 && u.password.len() <= 255, "proxy username and password: 255 bytes max");
        }
        ensure!(self.upstream_rules.len() <= MAX_UPSTREAM_RULES, "at most {MAX_UPSTREAM_RULES} upstream rules");
        for (i, r) in self.upstream_rules.iter().enumerate() {
            r.validate().with_context(|| format!("upstream rule {}", i + 1))?;
            ensure!(
                !r.matches.is_empty() || i + 1 == self.upstream_rules.len(),
                "upstream rule {}: a rule with no match covers every host, so it must be the last",
                i + 1
            );
        }
        for c in &self.client_certs {
            ensure!(!c.host.trim().is_empty(), "each client certificate needs a host pattern");
            load_cert(c, false)?;
        }
        ensure!(self.hosts.len() <= 500, "at most 500 hostname overrides");
        for h in &self.hosts {
            ensure!(valid_pattern(&h.host), "bad host name in a hostname override: {:?}", h.host);
        }
        ensure!(self.tls_passthrough.len() <= 500, "at most 500 TLS pass-through hosts");
        for p in &self.tls_passthrough {
            ensure!(valid_pattern(p), "bad host pattern for TLS pass-through: {p:?}");
        }
        Ok(())
    }

    /// The settings with proxy passwords hidden, for logs and display.
    pub fn masked(&self) -> Self {
        let mut c = self.clone();
        if let Some(u) = c.upstream.as_mut()
            && !u.password.is_empty()
        {
            u.password = "********".into();
        }
        for r in &mut c.upstream_rules {
            if !r.password.is_empty() {
                r.password = "********".into();
            }
        }
        c
    }

    /// The rule that decides how to reach `host`: its index and the pattern that matched (`None` pattern: an
    /// empty `match`). `None` when no rule covers the host, which means direct.
    pub fn resolve(&self, host: &str) -> Option<(usize, Option<String>)> {
        self.upstream_rules
            .iter()
            .enumerate()
            .find_map(|(i, r)| r.covering_pattern(host).map(|p| (i, p.map(str::to_string))))
    }
}

fn load_cert(c: &ClientCert, verify: bool) -> Result<TlsConnector> {
    let cert = std::fs::read(&c.cert_file).with_context(|| format!("reading {}", c.cert_file.display()))?;
    let key = std::fs::read(&c.key_file).with_context(|| format!("reading {}", c.key_file.display()))?;
    let cfg = pm_tls::upstream_client_config_with_cert(verify, &cert, &key)
        .with_context(|| format!("client certificate for {}", c.host))?;
    Ok(TlsConnector::from(cfg))
}

struct Loaded {
    config: NetConfig,
    /// The proxy of each upstream rule (`None`: direct), in order.
    proxies: Vec<Option<UpstreamProxy>>,
    /// (host pattern, connector without and with upstream verification).
    certs: Vec<(String, TlsConnector, TlsConnector)>,
}

/// Live network settings shared by every `Sender` in a process.
#[derive(Clone)]
pub struct Network(Arc<RwLock<Arc<Loaded>>>);

impl Default for Network {
    fn default() -> Self {
        Self(Arc::new(RwLock::new(Arc::new(Loaded { config: NetConfig::default(), proxies: vec![], certs: vec![] }))))
    }
}

impl Network {
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies new settings; on error the old ones stay in place.
    pub fn set(&self, config: NetConfig) -> Result<()> {
        let config = config.normalized()?;
        config.validate()?;
        let certs = config
            .client_certs
            .iter()
            .map(|c| Ok((c.host.clone(), load_cert(c, false)?, load_cert(c, true)?)))
            .collect::<Result<Vec<_>>>()?;
        let proxies = config.upstream_rules.iter().map(UpstreamRule::proxy).collect();
        *self.0.write() = Arc::new(Loaded { config, proxies, certs });
        Ok(())
    }

    pub fn config(&self) -> NetConfig {
        self.0.read().config.clone()
    }

    /// The proxy `host` is reached through (`None`: directly), from the first upstream rule that covers it.
    pub(crate) fn upstream_for(&self, host: &str) -> Option<UpstreamProxy> {
        let l = self.0.read();
        let (i, _) = l.config.resolve(host)?;
        l.proxies.get(i).cloned().flatten()
    }

    /// Which upstream rule covers `host` (see [`NetConfig::resolve`]).
    pub fn resolve(&self, host: &str) -> Option<(usize, Option<String>)> {
        self.0.read().config.resolve(host)
    }

    /// The fixed address for a host name, if an override matches.
    pub fn address_for(&self, host: &str) -> Option<IpAddr> {
        self.0.read().config.hosts.iter().find(|h| host_matches(&h.host, host)).map(|h| h.address)
    }

    /// Whether the proxy should tunnel TLS to this host without intercepting it.
    pub fn passthrough(&self, host: &str) -> bool {
        self.0.read().config.tls_passthrough.iter().any(|p| host_matches(p, host))
    }

    pub(crate) fn tls_for(&self, host: &str, verify: bool) -> Option<TlsConnector> {
        let l = self.0.read();
        l.certs.iter().find(|(p, ..)| host_matches(p, host)).map(|(_, a, b)| if verify { b.clone() } else { a.clone() })
    }
}

/// Opens a tunnel through an HTTP proxy with CONNECT.
pub(crate) async fn http_connect<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    proxy: &UpstreamProxy,
    host: &str,
    port: u16,
) -> Result<()> {
    let authority = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(auth) = proxy.basic_auth() {
        req.push_str(&format!("Proxy-Authorization: {auth}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        ensure!(head.len() < 16 * 1024, "the upstream proxy sent an oversized CONNECT response");
        if s.read(&mut b).await? == 0 {
            bail!("the upstream proxy closed the connection during CONNECT");
        }
        head.push(b[0]);
    }
    let resp = pm_http::parse_response_head(&head).context("bad CONNECT response from the upstream proxy")?;
    if !(200..300).contains(&resp.status) {
        bail!("the upstream proxy refused CONNECT to {authority}: {} {}", resp.status, resp.reason);
    }
    Ok(())
}

/// Where a SOCKS5 proxy should connect.
pub(crate) enum SocksTarget<'a> {
    Ip(IpAddr),
    Name(&'a str),
}

/// SOCKS5 handshake (RFC 1928, username/password per RFC 1929).
pub(crate) async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    proxy: &UpstreamProxy,
    target: SocksTarget<'_>,
    port: u16,
) -> Result<()> {
    let with_auth = !proxy.username.is_empty();
    s.write_all(if with_auth { &[5, 2, 0, 2] } else { &[5, 1, 0] }).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await.context("SOCKS5 greeting")?;
    ensure!(r[0] == 5, "the upstream proxy is not a SOCKS5 server");
    match r[1] {
        0 => {}
        2 if with_auth => {
            let mut a = vec![1, proxy.username.len() as u8];
            a.extend_from_slice(proxy.username.as_bytes());
            a.push(proxy.password.len() as u8);
            a.extend_from_slice(proxy.password.as_bytes());
            s.write_all(&a).await?;
            s.read_exact(&mut r).await.context("SOCKS5 login")?;
            ensure!(r[1] == 0, "the SOCKS5 proxy rejected the username or password");
        }
        0xFF => bail!("the SOCKS5 proxy accepts none of our login methods"),
        m => bail!("the SOCKS5 proxy chose an unsupported login method ({m})"),
    }
    let mut req = vec![5, 1, 0];
    match target {
        SocksTarget::Ip(IpAddr::V4(ip)) => {
            req.push(1);
            req.extend_from_slice(&ip.octets());
        }
        SocksTarget::Ip(IpAddr::V6(ip)) => {
            req.push(4);
            req.extend_from_slice(&ip.octets());
        }
        SocksTarget::Name(name) => {
            ensure!(name.len() <= 255, "host name too long for SOCKS5");
            req.push(3);
            req.push(name.len() as u8);
            req.extend_from_slice(name.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await.context("SOCKS5 connect reply")?;
    if h[1] != 0 {
        let why = match h[1] {
            1 => "general failure",
            2 => "not allowed by the proxy's rules",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "TTL expired",
            _ => "error",
        };
        return Err(anyhow!("the SOCKS5 proxy could not connect: {why}"));
    }
    // Skip the bound address.
    let skip = match h[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            usize::from(l[0])
        }
        _ => bail!("bad SOCKS5 reply"),
    } + 2;
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await?;
    Ok(())
}

/// A plain-HTTP request rewritten for an HTTP proxy: absolute-form target
/// and, if set, a Proxy-Authorization header. The origin server receives
/// what the proxy makes of it.
///
/// The proxy goes wherever the target names, so the target always names
/// the endpoint that was checked: an absolute-form target for another host
/// gets the endpoint's origin, and requests whose target can't be pinned
/// (authority-form, `*`, unparseable) are refused.
pub(crate) fn for_http_proxy(request: &[u8], host: &str, port: u16, proxy: &UpstreamProxy) -> Result<Vec<u8>> {
    let end = match pm_http::find_head_end(request) {
        Ok(Some(end)) => end,
        _ => bail!("cannot send an incomplete request head through an HTTP upstream proxy"),
    };
    let head = pm_http::parse_request_head(&request[..end])
        .map_err(|e| anyhow::anyhow!("cannot send through an HTTP upstream proxy: {e}"))?;
    let path = if head.target.starts_with('/') {
        head.target.as_str()
    } else if let Some((_, _, path)) = pm_http::split_absolute_target(&head.target) {
        path
    } else {
        bail!("only origin-form and absolute-form targets can go through an HTTP upstream proxy");
    };
    let h = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    let origin = if port == 80 { format!("http://{h}") } else { format!("http://{h}:{port}") };
    let mut out = pm_http::replace_request_target(request, &format!("{origin}{path}"))
        .ok_or_else(|| anyhow::anyhow!("cannot rewrite the request target for the upstream proxy"))?;
    if let Some(auth) = proxy.basic_auth()
        && let Some(eol) = out.windows(2).position(|w| w == b"\r\n")
    {
        let line = format!("\r\nProxy-Authorization: {auth}");
        out.splice(eol..eol, line.into_bytes());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_patterns() {
        assert!(host_matches("*", "anything.test"));
        assert!(host_matches("*.corp.test", "a.b.corp.test") && host_matches("*.corp.test", "CORP.test."));
        assert!(!host_matches("*.corp.test", "evilcorp.test"));
        assert!(host_matches("api.test", "API.test") && !host_matches("api.test", "x.api.test"));
    }

    #[test]
    fn plain_http_requests_get_absolute_form_and_proxy_auth() {
        let p = UpstreamProxy { username: "u".into(), password: "p".into(), ..Default::default() };
        let out = for_http_proxy(b"GET /a?b=1 HTTP/1.1\r\nHost: x\r\n\r\n", "shop.test", 8080, &p).unwrap();
        assert_eq!(
            out,
            b"GET http://shop.test:8080/a?b=1 HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\nHost: x\r\n\r\n"
        );
        let anon = UpstreamProxy::default();
        assert_eq!(
            for_http_proxy(b"GET / HTTP/1.1\r\n\r\n", "shop.test", 80, &anon).unwrap(),
            b"GET http://shop.test/ HTTP/1.1\r\n\r\n"
        );
    }

    #[test]
    fn upstream_proxy_targets_are_pinned_to_the_checked_endpoint() {
        let anon = UpstreamProxy::default();
        assert_eq!(
            for_http_proxy(b"GET http://elsewhere.test/x?y HTTP/1.1\r\n\r\n", "shop.test", 80, &anon).unwrap(),
            b"GET http://shop.test/x?y HTTP/1.1\r\n\r\n"
        );
        assert_eq!(
            for_http_proxy(b"GET http://elsewhere.test HTTP/1.1\r\n\r\n", "shop.test", 81, &anon).unwrap(),
            b"GET http://shop.test:81/ HTTP/1.1\r\n\r\n"
        );
        assert!(for_http_proxy(b"CONNECT elsewhere.test:443 HTTP/1.1\r\n\r\n", "shop.test", 80, &anon).is_err());
        assert!(for_http_proxy(b"OPTIONS * HTTP/1.1\r\n\r\n", "shop.test", 80, &anon).is_err());
        assert!(for_http_proxy(b"GET / HTTP/1.1\r\nHost: x", "shop.test", 80, &anon).is_err());
    }

    #[test]
    fn masking_and_validation() {
        let c = NetConfig {
            upstream: Some(UpstreamProxy {
                host: "p".into(),
                port: 3128,
                password: "hunter2".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(c.masked().upstream.unwrap().password, "********");
        assert!(c.validate().is_ok());
        let missing = NetConfig {
            client_certs: vec![ClientCert {
                host: "*".into(),
                cert_file: "/nope.pem".into(),
                key_file: "/nope.key".into(),
            }],
            ..Default::default()
        };
        assert!(missing.validate().is_err());
        let hosts = NetConfig {
            hosts: vec![HostOverride { host: "*.corp.test".into(), address: "10.0.0.5".parse().unwrap() }],
            tls_passthrough: vec!["pinned.test".into()],
            ..Default::default()
        };
        assert!(hosts.validate().is_ok());
        let net = Network::new();
        net.set(hosts).unwrap();
        assert_eq!(net.address_for("api.corp.test"), Some("10.0.0.5".parse().unwrap()));
        assert_eq!(net.address_for("other.test"), None);
        assert!(net.passthrough("PINNED.test") && !net.passthrough("x.pinned.test"));
        let bad = NetConfig { tls_passthrough: vec!["a b".into()], ..Default::default() };
        assert!(bad.validate().is_err());
    }
}
