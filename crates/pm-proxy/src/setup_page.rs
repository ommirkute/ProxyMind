//! ProxyMind's own setup page, for phones and tablets.
//!
//! A device pointed at the proxy (or just opening `http://<this machine>:<proxy port>/`) can install ProxyMind's CA
//! from here. The proxy answers these requests itself:
//!
//! - the reserved host [`SETUP_HOST`] (or plain `proxymind`), however the request reaches the proxy (absolute-form,
//!   a `Host` header, or inside a CONNECT tunnel), and
//! - a request addressed to the listener's own address, which would otherwise be refused as a request loop.
//!
//! Such a request is never forwarded upstream, never recorded as target traffic, and not touched by match-and-replace
//! rules or the intercept queue. The page holds only public things (the CA certificate, its fingerprint, the proxy
//! address the client just reached) and nothing taken from the request, so there is nothing to reflect or leak: no
//! API token, no project data. It uses no scripts, and a strict Content-Security-Policy says so.

use pm_tls::CertAuthority;

use crate::SelfAddr;

/// The reserved host name that always means ProxyMind's setup page when a client asks for it through the proxy.
pub const SETUP_HOST: &str = "proxymind.setup";

/// Whether `host` is a reserved setup name (`proxymind.setup`, or `proxymind`; case and a trailing dot ignored).
pub fn is_setup_host(host: &str) -> bool {
    let h = host.trim_end_matches('.');
    h.eq_ignore_ascii_case(SETUP_HOST) || h.eq_ignore_ascii_case("proxymind")
}

/// Whether a request for `host:port` is for the setup page: a reserved name, or this listener's own address.
pub(crate) fn is_local(host: &str, port: u16, me: Option<SelfAddr>) -> bool {
    if is_setup_host(host) {
        return true;
    }
    let Some(me) = me else { return false };
    if port != me.port {
        return false;
    }
    let host = host.trim_matches(['[', ']']);
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.to_canonical() == me.ip.to_canonical(),
        Err(_) => me.ip.is_loopback() && host.eq_ignore_ascii_case("localhost"),
    }
}

/// The complete HTTP response (head and body) for a request to the setup page.
pub(crate) fn respond(ca: &CertAuthority, method: &str, target: &str, me: Option<SelfAddr>) -> Vec<u8> {
    let head_only = method.eq_ignore_ascii_case("HEAD");
    if !head_only && !method.eq_ignore_ascii_case("GET") {
        return response(
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            &[("Allow", "GET, HEAD")],
            b"GET only",
            false,
        );
    }
    let path = target.split(['?', '#']).next().unwrap_or("/");
    match path {
        "/" | "/index.html" => {
            let html = page(ca, me);
            response(200, "OK", "text/html; charset=utf-8", &[], html.as_bytes(), head_only)
        }
        "/ca.pem" => response(
            200,
            "OK",
            "application/x-pem-file",
            &[("Content-Disposition", "attachment; filename=\"proxymind-ca.pem\"")],
            ca.ca_pem().as_bytes(),
            head_only,
        ),
        // DER with the type Android and iOS recognise as "a CA certificate to install".
        "/ca.crt" | "/ca.cer" => response(
            200,
            "OK",
            "application/x-x509-ca-cert",
            &[("Content-Disposition", "attachment; filename=\"proxymind-ca.crt\"")],
            ca.ca_der(),
            head_only,
        ),
        _ => response(404, "Not Found", "text/plain; charset=utf-8", &[], b"Nothing here. Try /", head_only),
    }
}

fn response(
    status: u16,
    reason: &str,
    content_type: &str,
    extra: &[(&str, &str)],
    body: &[u8],
    head_only: bool,
) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; \
         base-uri 'none'; form-action 'none'\r\n",
        body.len()
    );
    for (k, v) in extra {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    if !head_only {
        out.extend_from_slice(body);
    }
    out
}

/// The HTML page. Everything interpolated is ours (an address we listen on, a hash we computed); nothing comes
/// from the request.
fn page(ca: &CertAuthority, me: Option<SelfAddr>) -> String {
    let proxy = match me {
        Some(m) if !m.ip.is_loopback() && !m.ip.is_unspecified() => match m.ip {
            std::net::IpAddr::V4(ip) => format!("{ip}:{}", m.port),
            std::net::IpAddr::V6(ip) => format!("[{ip}]:{}", m.port),
        },
        _ => String::new(),
    };
    let proxy_line = if proxy.is_empty() {
        "<p>Use this computer's Wi-Fi address as the proxy host, with the port of the address you opened this page on.</p>"
            .to_string()
    } else {
        format!("<p>Proxy address for this device: <code>{proxy}</code></p>")
    };
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ProxyMind setup</title>
<style>
body{{font:16px/1.5 system-ui,sans-serif;margin:0;padding:16px;max-width:42rem;margin-inline:auto;color:#1c1f24;background:#fff}}
@media (prefers-color-scheme:dark){{body{{color:#e6e8eb;background:#14161a}}a.btn{{color:#fff}}}}
h1{{font-size:1.4rem}}h2{{font-size:1.1rem;margin-top:1.6rem}}
code{{font:13px ui-monospace,monospace;word-break:break-all}}
a.btn{{display:block;margin:10px 0;padding:12px 14px;border:1px solid #3b6fd4;border-radius:8px;background:#3b6fd4;color:#fff;text-decoration:none;text-align:center}}
a.btn.alt{{background:transparent;color:#3b6fd4}}
.note{{font-size:14px;opacity:.8}}
</style>
</head>
<body>
<h1>ProxyMind setup</h1>
<p>Install ProxyMind's certificate on this device so HTTPS traffic can be inspected while you test. Only do this on devices you own or are authorised to test, and remove it when you finish.</p>
<a class="btn" href="/ca.crt" data-testid="ca-crt">Download certificate (.crt, Android and iOS)</a>
<a class="btn alt" href="/ca.pem" data-testid="ca-pem">Download certificate (.pem)</a>
<p>SHA-256 fingerprint (check it matches the one on the ProxyMind setup page):<br><code>{fp}</code></p>
{proxy_line}
<h2>Android</h2>
<ol>
<li>Download the <code>.crt</code> file above.</li>
<li>Settings, Security and privacy, More security settings, Encryption and credentials, Install a certificate, CA certificate. Pick the file (the menu names vary by phone).</li>
<li>Set the Wi-Fi proxy: long-press your network, Modify network, Advanced options, Proxy: Manual, then the host and port above.</li>
</ol>
<p class="note">Chrome trusts certificates installed this way. Many apps do not (they ignore user certificates) and will show connection errors; that is expected.</p>
<h2>iPhone and iPad</h2>
<ol>
<li>Open this page in Safari and tap the <code>.crt</code> download, then Allow.</li>
<li>Settings, General, VPN &amp; Device Management: tap the downloaded profile, Install.</li>
<li>Settings, General, About, Certificate Trust Settings: switch on full trust for ProxyMind CA.</li>
<li>Settings, Wi-Fi, (i) next to your network, Configure Proxy, Manual: the host and port above.</li>
</ol>
<p class="note">Remove the certificate and the proxy setting when the engagement ends. ProxyMind's docs have longer guides (docs/mobile.md).</p>
</body>
</html>
"#,
        fp = ca.ca_fingerprint(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me(ip: &str, port: u16) -> Option<SelfAddr> {
        Some(SelfAddr { ip: ip.parse().unwrap(), port })
    }

    #[test]
    fn reserved_names_and_the_listeners_own_address_are_local() {
        for h in ["proxymind.setup", "PROXYMIND.SETUP", "proxymind", "proxymind.setup."] {
            assert!(is_local(h, 80, None), "{h}");
            assert!(is_local(h, 8080, me("192.168.1.5", 8080)), "{h}");
        }
        assert!(is_local("192.168.1.5", 8080, me("192.168.1.5", 8080)));
        assert!(is_local("::ffff:192.168.1.5", 8080, me("192.168.1.5", 8080)));
        assert!(is_local("[fe80::1]", 8080, me("fe80::1", 8080)));
        assert!(is_local("localhost", 8080, me("127.0.0.1", 8080)));
        // Anything else, including look-alikes and other ports, goes where it was asked to.
        assert!(!is_local("192.168.1.5", 80, me("192.168.1.5", 8080)));
        assert!(!is_local("192.168.1.6", 8080, me("192.168.1.5", 8080)));
        assert!(!is_local("localhost", 8080, me("192.168.1.5", 8080)));
        assert!(!is_local("proxymind.setup.example.com", 80, None));
        assert!(!is_local("notproxymind", 80, None));
        assert!(!is_local("example.com", 8080, None));
    }
}
