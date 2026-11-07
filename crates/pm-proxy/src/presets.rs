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

#[derive(Debug, Clone, Serialize)]
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
