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

/// Standard base64 with padding (RFC 4648).
pub fn base64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            out.push(if i <= chunk.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

#[cfg(test)]
mod base64_tests {
    #[test]
    fn rfc4648_vectors() {
        let cases =
            [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("foobar", "Zm9vYmFy")];
        for (i, o) in cases {
            assert_eq!(super::base64(i.as_bytes()), o);
        }
    }
}
