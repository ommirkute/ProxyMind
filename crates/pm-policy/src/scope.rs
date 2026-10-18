//! Scope matching.
//!
//! Safety rule: when in doubt, a target is treated as *out* of scope.
//! Targets are normalized the way a lenient server might read them
//! (percent-decoding, dot segments, backslashes, `;` path parameters,
//! duplicate slashes) so that tricks like `/%61dmin`, `/api/../admin` or
//! `//admin` cannot slip past an exclusion. Exclusions also match
//! case-insensitively, because many servers treat paths that way.

use std::net::IpAddr;

use url::{Host, Url};

use crate::PolicyError;

/// A request target, normalized for scope checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub scheme: String,
    /// Lowercase host name or IP address text (IPv6 without brackets).
    pub host: String,
    pub ip: Option<IpAddr>,
    pub port: u16,
    /// Normalized path (see module docs). Query is not part of scope.
    pub path: String,
}

impl Target {
    /// Parses a full URL such as `https://app.example.com/api/x?y=1`.
    pub fn from_url(url: &str) -> Result<Self, PolicyError> {
        let u = Url::parse(url).map_err(|e| PolicyError::Target(format!("{url}: {e}")))?;
        Self::from_parsed(&u, None)
    }

    /// Builds a target from the parts the proxy sees on the wire. `path` is
    /// the raw request target in origin form.
    pub fn from_parts(scheme: &str, host: &str, port: u16, path: &str) -> Result<Self, PolicyError> {
        let host_part = if host.contains(':') && !host.starts_with('[') { format!("[{host}]") } else { host.into() };
        // Parse only scheme + host through the URL parser (it normalizes
        // odd IPv4 forms like 0x7f.1 and IDNA names); keep the raw path.
        let base = format!("{scheme}://{host_part}:{port}/");
        let u = Url::parse(&base).map_err(|e| PolicyError::Target(format!("{base}: {e}")))?;
        Self::from_parsed(&u, Some(path))
    }

    fn from_parsed(u: &Url, raw_path: Option<&str>) -> Result<Self, PolicyError> {
        let scheme = u.scheme().to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(PolicyError::Target(format!("unsupported scheme {scheme}")));
        }
        if !u.username().is_empty() || u.password().is_some() {
            // `https://in-scope.com@evil.com/` style confusion: refuse outright.
            return Err(PolicyError::Target("URLs with user info are not allowed".into()));
        }
        let (host, ip) = match u.host() {
            Some(Host::Domain(d)) => (d.trim_end_matches('.').to_ascii_lowercase(), None),
            Some(Host::Ipv4(a)) => (a.to_string(), Some(IpAddr::V4(a))),
            Some(Host::Ipv6(a)) => (a.to_string(), Some(IpAddr::V6(a))),
            None => return Err(PolicyError::Target("URL has no host".into())),
        };
        if host.is_empty() {
            return Err(PolicyError::Target("URL has an empty host".into()));
        }
        let port = u.port_or_known_default().ok_or_else(|| PolicyError::Target("URL has no port".into()))?;
        let path = normalize_path(raw_path.unwrap_or_else(|| u.path()));
        Ok(Self { scheme, host, ip, port, path })
    }
}

/// Normalizes a path the way a permissive server might interpret it.
pub fn normalize_path(raw: &str) -> String {
    // Drop query and fragment.
    let raw = raw.split(['?', '#']).next().unwrap_or("");
    // Decode repeatedly (catches double encoding), bounded.
    let mut decoded = raw.to_string();
    for _ in 0..3 {
        let next = percent_decode(&decoded);
        if next == decoded {
            break;
        }
        decoded = next;
    }
    let decoded = decoded.replace('\\', "/");
    let mut out: Vec<&str> = Vec::new();
    for seg in decoded.split('/') {
        // Strip path parameters (`/admin;jsessionid=1`), as Tomcat and others do.
        let seg = seg.split(';').next().unwrap_or("");
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let trailing = decoded.ends_with('/') && !out.is_empty();
    let mut path = format!("/{}", out.join("/"));
    if trailing {
        path.push('/');
    }
    path
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2]))
        {
            out.push(h * 16 + l);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// One scope entry, e.g. `https://*.example.com/api/`.
///
/// - Scheme must match exactly.
/// - Host: `*` matches exactly one label (`*.example.com` matches
///   `a.example.com`, not `example.com` or `a.b.example.com`). A leading
///   `**.` matches one or more labels.
/// - Port: if omitted, only the scheme's default port; `:*` means any port.
/// - Path: prefix match on the normalized path. `*` matches within one
///   segment. A pattern ending in `/` matches everything below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlPattern {
    pub text: String,
    scheme: String,
    host_labels: Vec<String>,
    any_subdomains: bool,
    port: Option<u16>,
    path: String,
}

impl UrlPattern {
    pub fn parse(text: &str) -> Result<Self, PolicyError> {
        let bad = |why: &str| PolicyError::Roe(format!("bad scope pattern {text:?}: {why}"));
        let (scheme, rest) = text.split_once("://").ok_or_else(|| bad("missing scheme"))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(bad("scheme must be http or https"));
        }
        let slash = rest.find('/').unwrap_or(rest.len());
        let (authority, path) = rest.split_at(slash);
        if authority.contains('@') {
            return Err(bad("user info is not allowed"));
        }
        let (host, port) = split_pattern_authority(authority).ok_or_else(|| bad("bad host or port"))?;
        let default_port = if scheme == "https" { 443 } else { 80 };
        let port = match port {
            None => Some(default_port),
            Some("*") => None,
            Some(p) => Some(p.parse().map_err(|_| bad("bad port"))?),
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let (any_subdomains, host) = match host.strip_prefix("**.") {
            Some(h) => (true, h.to_string()),
            None => (false, host),
        };
        if host.is_empty() || host.contains("**") {
            return Err(bad("bad host"));
        }
        let host_labels = if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
            vec![host.trim_matches(['[', ']']).to_string()]
        } else {
            host.split('.').map(str::to_string).collect()
        };
        let path = if path.is_empty() { "/".to_string() } else { pattern_path(path) };
        Ok(Self { text: text.to_string(), scheme, host_labels, any_subdomains, port, path })
    }

    /// Exact match: used for `include`.
    pub fn matches(&self, t: &Target) -> bool {
        self.matches_inner(t, false)
    }

    /// Lenient match (case-insensitive path): used for `exclude`.
    pub fn matches_lenient(&self, t: &Target) -> bool {
        self.matches_inner(t, true)
    }

    fn matches_inner(&self, t: &Target, ignore_case: bool) -> bool {
        if self.scheme != t.scheme {
            return false;
        }
        if let Some(p) = self.port
            && p != t.port
        {
            return false;
        }
        if !self.host_matches(&t.host) {
            return false;
        }
        if ignore_case {
            path_matches(&self.path.to_lowercase(), &t.path.to_lowercase())
        } else {
            path_matches(&self.path, &t.path)
        }
    }

    fn host_matches(&self, host: &str) -> bool {
        if self.host_labels.len() == 1 && host.parse::<IpAddr>().is_ok() {
            return self.host_labels[0] == host;
        }
        let labels: Vec<&str> = host.split('.').collect();
        let n = self.host_labels.len();
        if self.any_subdomains {
            if labels.len() <= n {
                return false;
            }
            let tail = &labels[labels.len() - n..];
            return tail.iter().zip(&self.host_labels).all(|(l, p)| glob(p, l));
        }
        labels.len() == n && labels.iter().zip(&self.host_labels).all(|(l, p)| glob(p, l))
    }
}

/// Normalizes a pattern path like a target path, but keeps `*`.
fn pattern_path(p: &str) -> String {
    normalize_path(p)
}

fn split_pattern_authority(a: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = a.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        return match after.strip_prefix(':') {
            Some(p) => Some((h, Some(p))),
            None if after.is_empty() => Some((h, None)),
            None => None,
        };
    }
    match a.rsplit_once(':') {
        Some((h, p)) => Some((h, Some(p))),
        None => Some((a, None)),
    }
}

/// Prefix match by segments. A pattern without a trailing slash still
/// matches its own subtree (`/api` matches `/api` and `/api/x`, not `/apix`).
fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "/" {
        return true;
    }
    let pat: Vec<&str> = pattern.trim_end_matches('/').split('/').collect();
    let segs: Vec<&str> = path.split('/').collect();
    if segs.len() < pat.len() {
        // `/api/` pattern vs `/api` path: same resource, matches.
        return segs.len() + 1 == pat.len() && pat.last() == Some(&"") && pat[..segs.len()] == segs[..];
    }
    pat.iter().zip(&segs).all(|(p, s)| glob(p, s))
}

/// `*` matches any run of characters within one label or segment.
fn glob(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || !text[first.len()..].ends_with(last) || text.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for mid in &parts[1..parts.len() - 1] {
        match rest.find(mid) {
            Some(i) => rest = &rest[i + mid.len()..],
            None => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(url: &str) -> Target {
        Target::from_url(url).unwrap()
    }

    #[test]
    fn normalizes_tricky_paths() {
        assert_eq!(normalize_path("/api/../admin"), "/admin");
        assert_eq!(normalize_path("/%61dmin"), "/admin");
        assert_eq!(normalize_path("/%2561dmin"), "/admin");
        assert_eq!(normalize_path("//admin//x/"), "/admin/x/");
        assert_eq!(normalize_path("/admin;jsessionid=1/x"), "/admin/x");
        assert_eq!(normalize_path("\\admin\\x"), "/admin/x");
        assert_eq!(normalize_path("/a/./b/%2e%2e/c?q=/../x"), "/a/c");
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("/../../"), "/");
    }

    #[test]
    fn host_wildcards() {
        let p = UrlPattern::parse("https://*.example.com/").unwrap();
        assert!(p.matches(&t("https://a.example.com/x")));
        assert!(!p.matches(&t("https://example.com/x")));
        assert!(!p.matches(&t("https://a.b.example.com/x")));
        assert!(!p.matches(&t("https://a.example.com.evil.com/x")));
        let p = UrlPattern::parse("https://**.example.com/").unwrap();
        assert!(p.matches(&t("https://a.b.example.com/x")));
        assert!(!p.matches(&t("https://example.com/x")));
        assert!(!p.matches(&t("https://badexample.com/x")));
    }

    #[test]
    fn ports_and_schemes() {
        let p = UrlPattern::parse("https://app.example.com/").unwrap();
        assert!(p.matches(&t("https://app.example.com:443/")));
        assert!(!p.matches(&t("https://app.example.com:8443/")));
        assert!(!p.matches(&t("http://app.example.com/")));
        let p = UrlPattern::parse("https://app.example.com:*/").unwrap();
        assert!(p.matches(&t("https://app.example.com:8443/")));
    }

    #[test]
    fn path_prefixes_by_segment() {
        let p = UrlPattern::parse("https://a.com/api").unwrap();
        assert!(p.matches(&t("https://a.com/api")));
        assert!(p.matches(&t("https://a.com/api/x")));
        assert!(!p.matches(&t("https://a.com/apix")));
        let p = UrlPattern::parse("https://a.com/api/").unwrap();
        assert!(p.matches(&t("https://a.com/api")));
        assert!(p.matches(&t("https://a.com/api/v1/x")));
        let p = UrlPattern::parse("https://a.com/v*/billing").unwrap();
        assert!(p.matches(&t("https://a.com/v1/billing/x")));
        assert!(!p.matches(&t("https://a.com/v1/other")));
    }

    #[test]
    fn rejects_userinfo_and_bad_schemes() {
        assert!(Target::from_url("https://app.example.com@evil.com/").is_err());
        assert!(Target::from_url("ftp://a.com/").is_err());
        assert!(UrlPattern::parse("https://user@a.com/").is_err());
        assert!(UrlPattern::parse("a.com/").is_err());
    }

    #[test]
    fn odd_ip_forms_are_normalized() {
        assert_eq!(t("http://0x7f.1/").host, "127.0.0.1");
        assert_eq!(t("http://2130706433/").host, "127.0.0.1");
        assert_eq!(Target::from_parts("http", "0177.0.0.1", 80, "/").unwrap().host, "127.0.0.1");
        assert_eq!(t("https://APP.Example.COM./").host, "app.example.com");
    }

    #[test]
    fn from_parts_keeps_raw_path_semantics() {
        let x = Target::from_parts("https", "a.com", 443, "/api/%2e%2e/admin?x=1").unwrap();
        assert_eq!(x.path, "/admin");
    }
}
