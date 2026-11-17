//! Transparent mode: traffic the operating system redirected to a listener (Linux `iptables`/`nftables` `REDIRECT`
//! or `TPROXY`), from clients that have no proxy settings. The proxy asks the OS where the client was really going
//! (the original destination) and, for HTTP and TLS, still names the target by the Host header or the TLS server
//! name, so recording, rules and certificates work as with a proxy client.
//!
//! The deciding logic here is pure and tested with a fake [`OriginalDst`]; the real lookup uses `SO_ORIGINAL_DST`
//! through the `nix` crate (no `unsafe` in this workspace) and only exists on Linux. macOS (`pf`) and Windows are
//! not supported.

use std::net::SocketAddr;

use tokio::net::TcpStream;

use crate::SelfAddr;

/// Finds where a redirected connection was going.
pub trait OriginalDst: Send + Sync {
    /// The address the client connected to before the redirect; `None` when the connection was not redirected
    /// (the client connected to the listener itself).
    fn original_dst(&self, tcp: &TcpStream) -> Option<SocketAddr>;
}

/// The operating system's answer: `SO_ORIGINAL_DST` (`REDIRECT`) or the accepted socket's own address (`TPROXY`,
/// which keeps the destination). Linux only; elsewhere it never finds one.
pub struct SystemOriginalDst {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    listener: SocketAddr,
}

impl SystemOriginalDst {
    /// For a listener bound to `listener`.
    pub fn new(listener: SocketAddr) -> Self {
        Self { listener }
    }
}

#[cfg(target_os = "linux")]
impl OriginalDst for SystemOriginalDst {
    fn original_dst(&self, tcp: &TcpStream) -> Option<SocketAddr> {
        use std::net::{Ipv4Addr, Ipv6Addr};

        use nix::sys::socket::{getsockopt, sockopt};

        if let Ok(a) = getsockopt(tcp, sockopt::OriginalDst) {
            let ip = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            return Some(SocketAddr::new(ip.into(), u16::from_be(a.sin_port)));
        }
        if let Ok(a) = getsockopt(tcp, sockopt::Ip6tOriginalDst) {
            let ip = Ipv6Addr::from(a.sin6_addr.s6_addr);
            return Some(SocketAddr::new(ip.into(), u16::from_be(a.sin6_port)));
        }
        // TPROXY delivers the connection with its destination intact: the local address is not the listener's.
        let local = tcp.local_addr().ok()?;
        let same_port = local.port() == self.listener.port();
        let same_ip =
            self.listener.ip().is_unspecified() || local.ip().to_canonical() == self.listener.ip().to_canonical();
        (!(same_port && same_ip)).then_some(local)
    }
}

#[cfg(not(target_os = "linux"))]
impl OriginalDst for SystemOriginalDst {
    fn original_dst(&self, _tcp: &TcpStream) -> Option<SocketAddr> {
        None
    }
}

/// Lets the listening socket accept `TPROXY` connections (`IP_TRANSPARENT`; needs `CAP_NET_ADMIN`). Failure is
/// reported, not fatal: `REDIRECT` does not need it.
#[cfg(target_os = "linux")]
pub(crate) fn allow_tproxy(listener: &std::net::TcpListener) -> std::io::Result<()> {
    if listener.local_addr().is_ok_and(|a| a.is_ipv6()) {
        return Ok(());
    }
    nix::sys::socket::setsockopt(listener, nix::sys::socket::sockopt::IpTransparent, &true)
        .map_err(std::io::Error::from)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn allow_tproxy(_listener: &std::net::TcpListener) -> std::io::Result<()> {
    Ok(())
}

/// Whether this build can do transparent mode.
pub const SUPPORTED: bool = cfg!(target_os = "linux");

/// The original destination if it is a real one: a connection "redirected" to the listener's own address would
/// loop, so it counts as not redirected (and the loop guard still applies to what follows).
pub(crate) fn effective_orig(orig: Option<SocketAddr>, me: Option<SelfAddr>) -> Option<SocketAddr> {
    let o = orig?;
    if o.port() == 0 || o.ip().is_unspecified() {
        return None;
    }
    if let Some(me) = me
        && o.port() == me.port
        && o.ip().to_canonical() == me.ip.to_canonical()
    {
        return None;
    }
    Some(o)
}

/// What the first bytes of a stream look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sniff {
    /// A TLS record (handshake).
    Tls,
    /// An HTTP/1.x request line.
    Http,
    /// Anything else: not something the proxy can read.
    Other,
}

/// Classifies the first bytes of a client stream; `None` when more bytes are needed to tell.
pub(crate) fn classify(prefix: &[u8]) -> Option<Sniff> {
    let first = *prefix.first()?;
    if first == 0x16 {
        return Some(match prefix.get(1) {
            Some(0x03) | None => Sniff::Tls,
            Some(_) => Sniff::Other,
        });
    }
    // A request line: METHOD SP target. The method is capital letters; the target starts like an origin-form,
    // absolute-form or asterisk-form target (a protocol that happens to start with a word and a space, such as an
    // SMTP "EHLO host", is not HTTP). CONNECT takes an authority.
    let mut i = 0;
    while let Some(&b) = prefix.get(i) {
        if b.is_ascii_uppercase() && i < 20 {
            i += 1;
            continue;
        }
        break;
    }
    if i == 0 {
        return Some(Sniff::Other);
    }
    let &after = prefix.get(i)?;
    if after != b' ' {
        return Some(Sniff::Other);
    }
    if &prefix[..i] == b"CONNECT" {
        return Some(Sniff::Http);
    }
    let rest = &prefix[i + 1..];
    match rest.first() {
        None => None,
        Some(b'/') | Some(b'*') => Some(Sniff::Http),
        Some(_) => {
            let lower: Vec<u8> = rest.iter().take(8).map(u8::to_ascii_lowercase).collect();
            if lower.starts_with(b"http://") || lower.starts_with(b"https://") {
                Some(Sniff::Http)
            } else if b"http://".starts_with(&lower) || b"https://".starts_with(&lower) {
                None
            } else {
                Some(Sniff::Other)
            }
        }
    }
}

/// What to do with a stream once its first bytes are known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    /// Read it as a proxy client would speak (CONNECT, absolute-form or origin-form requests, TLS by server name),
    /// using the original destination for where to connect.
    Proxy,
    /// TLS inside a tunnel to a named host: intercept it for that host.
    InterceptTls,
    /// Plain HTTP inside a tunnel to a named host.
    InterceptHttp,
    /// Not HTTP or TLS: relay the bytes unchanged.
    Raw,
}

/// The decision for a stream. `addressed`: the stream's target is an IP address (a redirected connection, or a
/// SOCKS5 request that gave one), so HTTP and TLS are read as a proxy client would speak and named by their Host
/// header or server name; a stream to a name takes that name as the target.
pub(crate) fn flow_for(addressed: bool, sniff: Sniff) -> Flow {
    match (sniff, addressed) {
        (Sniff::Other, _) => Flow::Raw,
        (_, true) => Flow::Proxy,
        (Sniff::Tls, false) => Flow::InterceptTls,
        (Sniff::Http, false) => Flow::InterceptHttp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me(ip: &str, port: u16) -> Option<SelfAddr> {
        Some(SelfAddr { ip: ip.parse().unwrap(), port })
    }

    #[test]
    fn classification() {
        assert_eq!(classify(b""), None);
        assert_eq!(classify(&[0x16, 0x03, 0x01]), Some(Sniff::Tls));
        assert_eq!(classify(&[0x16]), Some(Sniff::Tls));
        assert_eq!(classify(&[0x16, 0x99]), Some(Sniff::Other));
        for ok in [
            "GET / HTTP/1.1",
            "POST /x",
            "OPTIONS * HTTP/1.1",
            "GET http://a/ HTTP/1.1",
            "GET HTTPS://a/",
            "CONNECT a:443 HTTP/1.1",
            "PROPFIND /d",
            "PRI * HTTP/2.0",
        ] {
            assert_eq!(classify(ok.as_bytes()), Some(Sniff::Http), "{ok}");
        }
        for incomplete in ["G", "GET", "GET ", "GET h", "GET http:/", "GET HTTPS:/"] {
            assert_eq!(classify(incomplete.as_bytes()), None, "{incomplete}");
        }
        for other in [
            "SSH-2.0-OpenSSH_9.6\r\n",
            "EHLO mail.test",
            "GET x",
            "get / HTTP/1.1",
            "\x00\x01",
            "220 hi\r\n",
            "PING\r\n",
            " GET /",
        ] {
            assert_eq!(classify(other.as_bytes()), Some(Sniff::Other), "{other:?}");
        }
    }

    #[test]
    fn original_destination_must_be_real() {
        let a: SocketAddr = "203.0.113.7:443".parse().unwrap();
        assert_eq!(effective_orig(Some(a), me("127.0.0.1", 8080)), Some(a));
        assert_eq!(effective_orig(None, me("127.0.0.1", 8080)), None);
        // Redirected to ProxyMind itself: that would loop.
        assert_eq!(effective_orig(Some("127.0.0.1:8080".parse().unwrap()), me("127.0.0.1", 8080)), None);
        assert_eq!(effective_orig(Some("[::ffff:127.0.0.1]:8080".parse().unwrap()), me("127.0.0.1", 8080)), None);
        assert!(effective_orig(Some("127.0.0.1:9090".parse().unwrap()), me("127.0.0.1", 8080)).is_some());
        assert_eq!(effective_orig(Some("0.0.0.0:80".parse().unwrap()), None), None);
        assert_eq!(effective_orig(Some("10.0.0.1:0".parse().unwrap()), None), None);
    }

    #[test]
    fn flows() {
        // A redirected connection (addressed by IP): HTTP and TLS are read like a proxy client's.
        assert_eq!(flow_for(true, Sniff::Tls), Flow::Proxy);
        assert_eq!(flow_for(true, Sniff::Http), Flow::Proxy);
        assert_eq!(flow_for(true, Sniff::Other), Flow::Raw);
        // A SOCKS5 request that named a host.
        assert_eq!(flow_for(false, Sniff::Tls), Flow::InterceptTls);
        assert_eq!(flow_for(false, Sniff::Http), Flow::InterceptHttp);
        assert_eq!(flow_for(false, Sniff::Other), Flow::Raw);
    }
}
