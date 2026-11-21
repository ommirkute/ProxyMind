//! Ready-made match-and-replace rules for common response changes made
//! while testing: show hidden form fields, enable disabled ones, drop
//! client-side limits and checks, strip scripts or security headers.
//! Each is ordinary [`Rule`]s a person adds and can then edit; nothing
//! changes traffic until they do (ADR-0002).
//!
//! A pass changes each matching tag once, so a tag with two attributes a
//! preset removes (say `disabled readonly`) keeps the second.
//!
//! Body rules can't see inside compressed responses, so most presets come
//! with a request rule that removes `Accept-Encoding` (in-scope only).

use serde::Serialize;

use crate::rewrite::{Part, Rule};

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
pub struct Preset {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub rules: Vec<Rule>,
}

fn rule(part: Part, pattern: &str, replace: &str, comment: &str) -> Rule {
    Rule {
        part,
        pattern: pattern.into(),
        replace: replace.into(),
        regex: true,
        comment: comment.into(),
        ..Default::default()
    }
}

/// Asks in-scope servers for uncompressed responses, so body rules apply.
pub fn identity_encoding() -> Rule {
    rule(Part::RequestHeader, r"(?i)^accept-encoding:.*$", "", "Ask for uncompressed responses (so body rules apply)")
}

/// The rules of the "Remove HTTP/3 advertisements" preset (ADR-0021). `Alt-Svc` is a list of alternatives such as
/// `h3=":443"; ma=86400, h2=":443"`: only the `h3` and `h3-NN` items go, the others stay, and a header left with
/// nothing is dropped. A rule runs once per header line, so the removal is repeated for up to four h3 items (`h3`
/// and a few drafts); servers advertise one or two.
fn alt_svc_h3_rules() -> Vec<Rule> {
    const PARAMS: &str = r#"(?:\s*;\s*[A-Za-z0-9_-]+\s*=\s*(?:"[^"]*"|[^\s,;]+))*"#;
    let any = format!(r#"[A-Za-z0-9_.%-]+\s*=\s*"[^"]*"{PARAMS}"#);
    let h3 = format!(r#"h3(?:-[A-Za-z0-9]+)?\s*=\s*"[^"]*"{PARAMS}"#);
    let h = Part::ResponseHeader;
    let mut rules: Vec<Rule> = (0..4)
        .map(|_| {
            rule(
                h,
                &format!(r"(?i)^(alt-svc:\s*(?:{any}\s*,\s*)*?){h3}(?:\s*,\s*|\s*$)"),
                "$1",
                "Remove HTTP/3 advertisements (Alt-Svc h3)",
            )
        })
        .collect();
    // An h3 item that was last leaves the comma before it; a header with no item left goes.
    rules.push(rule(h, r"(?i)^(alt-svc:.*?)\s*,\s*$", "$1", "Remove HTTP/3 advertisements (Alt-Svc h3)"));
    rules.push(rule(h, r"(?i)^alt-svc:\s*$", "", "Remove HTTP/3 advertisements (Alt-Svc h3)"));
    rules
}

/// All presets, in the order the UI lists them.
pub fn presets() -> Vec<Preset> {
    let b = Part::ResponseBody;
    let h = Part::ResponseHeader;
    vec![
        Preset {
            id: "unhide_fields",
            title: "Unhide hidden form fields",
            description: "Turns <input type=\"hidden\"> into visible text fields.",
            rules: vec![
                identity_encoding(),
                rule(b, r#"(?i)(<input\b[^>]*?\btype\s*=\s*["']?)hidden\b"#, "${1}text", "Unhide hidden form fields"),
            ],
        },
        Preset {
            id: "enable_fields",
            title: "Enable disabled form fields",
            description: "Removes the disabled and readonly attributes from form controls.",
            rules: vec![
                identity_encoding(),
                rule(
                    b,
                    r#"(?i)(<(?:input|select|textarea|button|option|optgroup|fieldset)\b[^>]*?)\s+(?:disabled|readonly)(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?"#,
                    "$1",
                    "Enable disabled form fields",
                ),
            ],
        },
        Preset {
            id: "remove_limits",
            title: "Remove input length limits",
            description: "Removes maxlength from form fields.",
            rules: vec![
                identity_encoding(),
                rule(
                    b,
                    r#"(?i)(<(?:input|textarea)\b[^>]*?)\s+maxlength\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)"#,
                    "$1",
                    "Remove input length limits",
                ),
            ],
        },
        Preset {
            id: "no_validation",
            title: "Turn off form validation",
            description: "Adds novalidate to forms (required, pattern, type checks) and removes onsubmit handlers.",
            rules: vec![
                identity_encoding(),
                rule(b, r"(?i)<form\b", "<form novalidate", "Turn off HTML form validation"),
                rule(
                    b,
                    r#"(?i)(<form\b[^>]*?)\s+onsubmit\s*=\s*(?:"[^"]*"|'[^']*')"#,
                    "$1",
                    "Remove onsubmit handlers",
                ),
            ],
        },
        Preset {
            id: "remove_scripts",
            title: "Remove all JavaScript",
            description: "Deletes <script> elements (inline and external).",
            rules: vec![
                identity_encoding(),
                rule(b, r"(?is)<script\b[^>]*>.*?</script\s*>", "", "Remove script elements"),
            ],
        },
        Preset {
            id: "remove_csp",
            title: "Remove security headers",
            description: "Drops Content-Security-Policy, X-Frame-Options and Strict-Transport-Security from responses.",
            rules: vec![rule(
                h,
                r"(?i)^(?:content-security-policy(?:-report-only)?|x-frame-options|strict-transport-security):.*$",
                "",
                "Remove security headers",
            )],
        },
        Preset {
            id: "no_http3",
            title: "Remove HTTP/3 advertisements (Alt-Svc h3)",
            description: "Drops the h3 alternatives from Alt-Svc headers, so a client that is not using the proxy setting \
                          (transparent or invisible setups) does not move to QUIC and past the proxy. Other Alt-Svc \
                          values stay. History keeps the server's original response.",
            rules: alt_svc_h3_rules(),
        },
        Preset {
            id: "cookie_flags",
            title: "Remove Secure and HttpOnly from cookies",
            description: "Lets scripts in the page read session cookies, and plain-HTTP pages receive them.",
            rules: vec![
                rule(h, r"(?i)^(set-cookie:.*?);\s*secure\s*(;|$)", "$1$2", "Remove the cookie Secure flag"),
                rule(h, r"(?i)^(set-cookie:.*?);\s*httponly\s*(;|$)", "$1$2", "Remove the cookie HttpOnly flag"),
            ],
        },
    ]
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::rewrite::{Rewriter, validate};

    fn apply(id: &str, response: &str) -> String {
        let p = presets().into_iter().find(|p| p.id == id).unwrap();
        let r = Rewriter::new();
        r.set_rules(p.rules).unwrap();
        r.set_scope(Arc::new(|_, _, _, _| true));
        let out = r.apply_response("http", "x", 80, "/", response.as_bytes()).unwrap_or(response.as_bytes().to_vec());
        String::from_utf8(out).unwrap()
    }

    fn page(body: &str) -> String {
        format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}", body.len())
    }

    #[test]
    fn all_presets_are_valid() {
        for p in presets() {
            validate(&p.rules).unwrap_or_else(|e| panic!("{}: {e}", p.id));
        }
    }

    #[test]
    fn form_presets() {
        let out = apply("unhide_fields", &page(r#"<input name=t type="hidden" value=1><input type=hidden>"#));
        assert!(out.ends_with(r#"<input name=t type="text" value=1><input type=text>"#), "{out}");
        assert!(out.contains("Content-Length: 51\r\n"), "length follows: {out}");
        let out =
            apply("enable_fields", &page(r#"<input disabled name=a><select readonly="readonly"><button disabled>"#));
        assert!(out.ends_with(r#"<input name=a><select><button>"#), "{out}");
        let out = apply("remove_limits", &page(r#"<input maxlength="8" name=p><textarea maxlength=3>"#));
        assert!(out.ends_with(r#"<input name=p><textarea>"#), "{out}");
        let out = apply("no_validation", &page(r#"<form action=/x onsubmit="return check()"><input required>"#));
        assert!(out.ends_with(r#"<form novalidate action=/x><input required>"#), "{out}");
    }

    #[test]
    fn script_header_and_cookie_presets() {
        let out =
            apply("remove_scripts", &page("<p>a</p><script src=x.js></script><SCRIPT>\nalert(1)\n</script ><p>b</p>"));
        assert!(out.ends_with("<p>a</p><p>b</p>"), "{out}");
        let resp = "HTTP/1.1 200 OK\r\nContent-Security-Policy: default-src 'none'\r\nX-Frame-Options: DENY\r\n\
                    Set-Cookie: s=1; Path=/; Secure; HttpOnly\r\nSet-Cookie: t=secure-x; Secure-Note=1\r\nContent-Length: 0\r\n\r\n";
        let out = apply("remove_csp", resp);
        assert!(
            !out.contains("Content-Security-Policy") && !out.contains("X-Frame-Options") && out.contains("Set-Cookie")
        );
        let out = apply("cookie_flags", resp);
        assert!(out.contains("Set-Cookie: s=1; Path=/\r\n"), "{out}");
        assert!(out.contains("Set-Cookie: t=secure-x; Secure-Note=1\r\n"), "lookalikes stay: {out}");
    }

    fn alt_svc(value: &str) -> String {
        let resp = format!("HTTP/1.1 200 OK\r\nServer: t\r\nAlt-Svc: {value}\r\nContent-Length: 0\r\n\r\n");
        apply("no_http3", &resp)
    }

    #[test]
    fn alt_svc_preset_removes_only_h3_alternatives() {
        let none = "HTTP/1.1 200 OK\r\nServer: t\r\nContent-Length: 0\r\n\r\n";
        // Only h3: the header goes.
        assert_eq!(alt_svc(r#"h3=":443"; ma=86400"#), none);
        assert_eq!(alt_svc(r#"h3=":443"; ma=86400, h3-29=":443"; ma=86400, h3-27=":443""#), none);
        // Other alternatives stay, wherever the h3 ones were.
        let keep =
            "HTTP/1.1 200 OK\r\nServer: t\r\nAlt-Svc: h2=\"alt.example:8443\"; ma=60\r\nContent-Length: 0\r\n\r\n";
        for v in [
            r#"h3=":443"; ma=86400, h2="alt.example:8443"; ma=60"#,
            r#"h2="alt.example:8443"; ma=60, h3=":443"; ma=86400"#,
            r#"h3=":443", h2="alt.example:8443"; ma=60, h3-29=":443"; persist=1"#,
            r#"h3-29=":443", h3=":443", h2="alt.example:8443"; ma=60, h3-27=":443", h3-Q050=":443""#,
        ] {
            assert_eq!(alt_svc(v), keep, "{v}");
        }
        // Two non-h3 alternatives around an h3 one keep their order and commas.
        assert!(alt_svc(r#"quic=":1", h3=":443"; ma=1, h2=":2""#).contains("Alt-Svc: quic=\":1\", h2=\":2\"\r\n"));
        // Nothing to remove: the response is unchanged.
        for v in [r#"h2=":443"; ma=60"#, "clear", r#"quic=":443"; v="46,43""#, r#"xh3=":443""#] {
            assert!(alt_svc(v).contains(&format!("Alt-Svc: {v}\r\n")), "{v}");
        }
        // Other headers that merely mention h3 are left alone, and the body is untouched.
        let resp = "HTTP/1.1 200 OK\r\nLink: <x>; rel=\"h3=\\\"y\\\"\"\r\nX-Note: alt-svc: h3=\":443\"\r\n\
                    Content-Length: 11\r\n\r\nh3=\":443\", x";
        let r = Rewriter::new();
        r.set_rules(presets().into_iter().find(|p| p.id == "no_http3").unwrap().rules).unwrap();
        r.set_scope(Arc::new(|_, _, _, _| true));
        assert!(r.apply_response("http", "x", 80, "/", resp.as_bytes()).is_none());
        // HTTP/2 and HTTP/3 text (lower-case names) work too.
        let h3text = "HTTP/3 200\r\nalt-svc: h3=\":443\", h2=\":443\"\r\n\r\n";
        let out = r.apply_response("https", "x", 443, "/", h3text.as_bytes()).unwrap();
        assert_eq!(out, b"HTTP/3 200\r\nalt-svc: h2=\":443\"\r\n\r\n");
        // The rules only run for in-scope hosts, like the other presets.
        r.set_scope(Arc::new(|_, _, _, _| false));
        assert!(r.apply_response("http", "x", 80, "/", h3text.as_bytes()).is_none());
    }

    #[test]
    fn accept_encoding_is_removed() {
        let r = Rewriter::new();
        r.set_rules(vec![identity_encoding()]).unwrap();
        r.set_scope(Arc::new(|_, _, _, _| true));
        let out = r
            .apply_request("http", "x", 80, "/", b"GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip, br\r\n\r\n")
            .unwrap();
        assert_eq!(out, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    }
}
