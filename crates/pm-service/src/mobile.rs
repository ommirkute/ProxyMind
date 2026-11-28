//! Mobile onboarding: the address a phone opens to install the CA, and a QR code for it.
//!
//! The page itself is served by the proxy (`pm_proxy::setup_page`) on its listener, because that is the port a
//! phone can reach; the API port accepts only localhost with a token. This module works out which addresses a
//! phone could use and draws the QR code as SVG.

use std::net::{IpAddr, SocketAddr};

use crate::api_types::MobileSetup;
use crate::{Result, Service};

impl Service {
    /// What the Proxy setup page shows for phones and tablets (a `read` action: nothing secret, not audited).
    pub fn mobile_setup(&self) -> Result<MobileSetup> {
        self.mobile_setup_with(&lan_addresses())
    }

    pub(crate) fn mobile_setup_with(&self, lan: &[IpAddr]) -> Result<MobileSetup> {
        let setup_host_url = format!("http://{}/", pm_proxy::setup_page::SETUP_HOST);
        let Some(info) = self.proxy_info.get() else {
            return Ok(MobileSetup { setup_host_url, ..Default::default() });
        };
        let mut binds: Vec<SocketAddr> = info.addr.parse().ok().into_iter().collect();
        for st in self.listeners_get()?.status {
            if st.running
                && st.kind == pm_proxy::ListenerKind::Http
                && let Ok(a) = st.bind.parse()
                && !binds.contains(&a)
            {
                binds.push(a);
            }
        }
        let reachable = plan(&binds, lan);
        let urls: Vec<String> = reachable.iter().map(|a| format!("http://{a}/")).collect();
        let qr_svg = urls.first().and_then(|u| qr_svg(u));
        Ok(MobileSetup {
            proxy_running: true,
            listener_reachable: binds.iter().any(|b| !b.ip().is_loopback()),
            qr_url: qr_svg.as_ref().and_then(|_| urls.first().cloned()),
            qr_svg,
            urls,
            proxy_addresses: reachable.iter().map(ToString::to_string).collect(),
            setup_host_url,
            listeners: binds.iter().map(ToString::to_string).collect(),
            ca_fingerprint: pm_tls::pem_fingerprint(&info.ca_pem).ok(),
        })
    }
}

/// The `ip:port` pairs a phone on the LAN could use: each listener on a specific non-loopback address as it is,
/// each listener on every interface (`0.0.0.0` or `::`) once per LAN address. Loopback listeners are left out.
/// IPv6 interface addresses are not listed: phones are set up over IPv4.
fn plan(binds: &[SocketAddr], lan: &[IpAddr]) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut push = |a: SocketAddr| {
        if !out.contains(&a) {
            out.push(a);
        }
    };
    for b in binds {
        if b.ip().is_loopback() {
            continue;
        }
        if b.ip().is_unspecified() {
            for ip in lan.iter().filter(|ip| ip.is_ipv4()) {
                push(SocketAddr::new(*ip, b.port()));
            }
        } else {
            push(*b);
        }
    }
    out
}

/// This machine's addresses on the local network, the likeliest first. Built from the standard library only: the
/// address the system would use to reach the Internet (a UDP "connect" sends nothing), plus, on Linux, every
/// local IPv4 address from the kernel's routing table.
///
/// `PROXYMIND_LAN_ADDR` (comma-separated IP addresses) replaces the search: use it where the machine cannot see its
/// own LAN address, e.g. inside a container.
pub(crate) fn lan_addresses() -> Vec<IpAddr> {
    let forced = lan_override(std::env::var("PROXYMIND_LAN_ADDR").ok().as_deref());
    if !forced.is_empty() {
        return forced;
    }
    let mut found: Vec<IpAddr> = Vec::new();
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0")
        && s.connect("192.0.2.1:9").is_ok()
        && let Ok(a) = s.local_addr()
    {
        found.push(a.ip());
    }
    #[cfg(target_os = "linux")]
    if let Ok(t) = std::fs::read_to_string("/proc/net/fib_trie") {
        found.extend(parse_fib_trie(&t));
    }
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in found {
        if usable(&ip) && !out.contains(&ip) {
            out.push(ip);
        }
    }
    // Stable: the primary address stays first within its kind; private ranges come before the rest.
    out.sort_by_key(|ip| match ip {
        IpAddr::V4(v4) if v4.is_private() => 0,
        _ => 1,
    });
    out
}

/// The addresses named by `PROXYMIND_LAN_ADDR`; entries that are not IP addresses are ignored.
fn lan_override(value: Option<&str>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in value.unwrap_or_default().split(',').filter_map(|s| s.trim().parse::<IpAddr>().ok()) {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

fn usable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_unspecified() || v4.is_link_local() || v4.is_multicast()),
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || v6.is_multicast()),
    }
}

/// Local IPv4 addresses (`/32 host LOCAL` entries) from the text of `/proc/net/fib_trie`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_fib_trie(text: &str) -> Vec<IpAddr> {
    let mut out = Vec::new();
    let mut last: Option<IpAddr> = None;
    for line in text.lines() {
        let l = line.trim();
        if let Some(ip) = l.strip_prefix("|--") {
            last = ip.trim().parse().ok();
        } else if l.starts_with("/32 host LOCAL")
            && let Some(ip) = last.take()
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
}

/// A QR code for `text` as a self-contained SVG: black modules on white with a four-module quiet zone, no scripts,
/// no external references. None if the text does not fit in a QR code.
pub fn qr_svg(text: &str) -> Option<String> {
    use qrcode::{Color, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
    let n = code.width();
    let colors = code.to_colors();
    let size = n + 8;
    let mut path = String::new();
    for y in 0..n {
        let mut x = 0;
        while x < n {
            if colors[y * n + x] == Color::Dark {
                let start = x;
                while x < n && colors[y * n + x] == Color::Dark {
                    x += 1;
                }
                path.push_str(&format!("M{},{}h{}v1h-{}z", start + 4, y + 4, x - start, x - start));
            } else {
                x += 1;
            }
        }
    }
    Some(format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {size} {size}\" width=\"{px}\" height=\"{px}\" \
         shape-rendering=\"crispEdges\"><rect width=\"{size}\" height=\"{size}\" fill=\"#fff\"/>\
         <path d=\"{path}\" fill=\"#000\"/></svg>",
        px = size * 6
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn only_listeners_a_phone_can_reach_make_urls() {
        let lan = [ip("192.168.1.5"), ip("10.0.0.8"), ip("fd00::5")];
        assert!(plan(&[sa("127.0.0.1:8080")], &lan).is_empty(), "loopback is unreachable");
        assert!(plan(&[sa("[::1]:8080")], &lan).is_empty());
        assert_eq!(plan(&[sa("0.0.0.0:8080")], &lan), [sa("192.168.1.5:8080"), sa("10.0.0.8:8080")]);
        assert_eq!(plan(&[sa("[::]:8080")], &lan), [sa("192.168.1.5:8080"), sa("10.0.0.8:8080")]);
        assert_eq!(plan(&[sa("10.0.0.8:9000")], &lan), [sa("10.0.0.8:9000")], "a specific address as it is");
        assert_eq!(
            plan(&[sa("127.0.0.1:8080"), sa("0.0.0.0:8081"), sa("10.0.0.8:8081")], &lan),
            [sa("192.168.1.5:8081"), sa("10.0.0.8:8081")],
            "no duplicates"
        );
        assert!(plan(&[sa("0.0.0.0:8080")], &[]).is_empty(), "no LAN address found");
    }

    #[test]
    fn reads_local_addresses_from_the_kernel_table() {
        let t = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 0.0.0.0\n        /0 universe UNICAST\n     +-- 127.0.0.0/8 2 0 2\n        |-- 127.0.0.1\n           /32 host LOCAL\n     |-- 192.168.1.5\n        /32 host LOCAL\n     |-- 192.168.1.255\n        /32 link BROADCAST\n";
        assert_eq!(parse_fib_trie(t), [ip("127.0.0.1"), ip("192.168.1.5")]);
        assert!(!lan_addresses().iter().any(|a| a.is_loopback() || a.is_unspecified()));
    }

    #[test]
    fn the_lan_address_can_be_given_by_hand() {
        assert_eq!(lan_override(Some("192.168.1.5, 10.0.0.8,junk,192.168.1.5")), [ip("192.168.1.5"), ip("10.0.0.8")]);
        assert!(
            lan_override(Some("junk")).is_empty() && lan_override(Some("")).is_empty() && lan_override(None).is_empty()
        );
    }

    #[test]
    fn the_qr_code_is_a_plain_svg_image() {
        let svg = qr_svg("http://192.168.1.5:8080/").unwrap();
        assert!(svg.starts_with("<svg ") && svg.ends_with("</svg>"));
        for bad in ["<script", "href", "onload", "http://www.w3.org/1999/xlink"] {
            assert!(!svg.contains(bad), "{bad}");
        }
        // Decoding is covered by round-tripping the module matrix: the same text gives the same drawing, and a
        // different text a different one.
        assert_eq!(svg, qr_svg("http://192.168.1.5:8080/").unwrap());
        assert_ne!(svg, qr_svg("http://192.168.1.6:8080/").unwrap());
        assert!(qr_svg(&"x".repeat(10_000)).is_none(), "too long for a QR code");
    }
}
