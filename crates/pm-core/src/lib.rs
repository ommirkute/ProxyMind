//! Small shared helpers used across ProxyMind crates.

use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Default port for a URL scheme.
pub fn default_port(scheme: &str) -> u16 {
    if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 }
}

/// `host:port`, bracketing IPv6 literals and omitting default ports.
pub fn authority(scheme: &str, host: &str, port: u16) -> String {
    let host = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    if port == default_port(scheme) { host } else { format!("{host}:{port}") }
}

/// Full URL for a target and origin-form path.
pub fn url(scheme: &str, host: &str, port: u16, path: &str) -> String {
    format!("{scheme}://{}{path}", authority(scheme, host, port))
}

#[cfg(test)]
mod tests {
    #[test]
    fn builds_urls() {
        assert_eq!(super::url("https", "a.com", 443, "/x"), "https://a.com/x");
        assert_eq!(super::url("http", "::1", 8080, "/"), "http://[::1]:8080/");
    }
}
