//! Network settings for outgoing connections: an upstream proxy (HTTP or
//! SOCKS5), client certificates for mutual TLS, hostname overrides, and
//! hosts whose TLS the proxy passes through without interception.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail, ensure};
use parking_lot::RwLock;
use pm_tls::TlsConnector;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetConfig {
    /// Send traffic through this proxy (None: connect directly).
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostOverride {
    /// `api.example.com` or `*.example.com`.
    pub host: String,
    /// The address to connect to instead of what DNS says.
    pub address: IpAddr,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    #[default]
    Http,
    Socks5,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamProxy {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    /// Optional login (Basic for HTTP proxies, username/password for SOCKS5).
    pub username: String,
    pub password: String,
    /// SOCKS5 only: let the proxy resolve target names ("socks5h"). Off by
    /// default so ProxyMind resolves and checks the address it connects to.
    pub remote_dns: bool,
    /// Hosts reached directly: `example.com`, `*.example.com` or `*`.
    pub bypass: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    pub fn applies_to(&self, host: &str) -> bool {
        !self.bypass.iter().any(|b| host_matches(b, host))
    }

    fn basic_auth(&self) -> Option<String> {
        (!self.username.is_empty())
            .then(|| format!("Basic {}", pm_core::base64(format!("{}:{}", self.username, self.password).as_bytes())))
    }
}

impl NetConfig {
    /// Checks the settings and loads the certificates.
    pub fn validate(&self) -> Result<()> {
        if let Some(u) = &self.upstream {
            ensure!(!u.host.trim().is_empty() && u.port != 0, "the upstream proxy needs a host and port");
            ensure!(u.username.len() <= 255 && u.password.len() <= 255, "proxy username and password: 255 bytes max");
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

    /// The settings with the proxy password hidden, for logs and display.
    pub fn masked(&self) -> Self {
        let mut c = self.clone();
        if let Some(u) = c.upstream.as_mut()
            && !u.password.is_empty()
        {
            u.password = "********".into();
        }
        c
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
    /// (host pattern, connector without and with upstream verification).
    certs: Vec<(String, TlsConnector, TlsConnector)>,
}

/// Live network settings shared by every `Sender` in a process.
#[derive(Clone)]
pub struct Network(Arc<RwLock<Arc<Loaded>>>);

impl Default for Network {
    fn default() -> Self {
        Self(Arc::new(RwLock::new(Arc::new(Loaded { config: NetConfig::default(), certs: vec![] }))))
    }
}

impl Network {
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies new settings; on error the old ones stay in place.
    pub fn set(&self, config: NetConfig) -> Result<()> {
        config.validate()?;
        let certs = config
            .client_certs
            .iter()
            .map(|c| Ok((c.host.clone(), load_cert(c, false)?, load_cert(c, true)?)))
            .collect::<Result<Vec<_>>>()?;
        *self.0.write() = Arc::new(Loaded { config, certs });
        Ok(())
    }

    pub fn config(&self) -> NetConfig {
        self.0.read().config.clone()
    }

    pub(crate) fn upstream_for(&self, host: &str) -> Option<UpstreamProxy> {
        self.0.read().config.upstream.as_ref().filter(|u| u.applies_to(host)).cloned()
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
