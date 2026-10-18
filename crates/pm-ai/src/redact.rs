//! Secret redaction with reversible placeholders.
//!
//! Before traffic is shown to a model, secrets (cookies, tokens, passwords,
//! API keys, JWTs) are replaced with placeholders such as
//! `{{secret:cookie_session_1}}`. The same secret always gets the same
//! placeholder. When an agent sends a request containing placeholders,
//! [`Redactor::unredact`] swaps the real values back in, so the model can
//! use credentials without ever seeing them.

use std::collections::HashMap;

use parking_lot::Mutex;
use regex::Regex;

/// Cookie values shorter than this are usually preferences (`theme=dark`),
/// not credentials. Named secrets (passwords, tokens) are hidden at any length.
const MIN_COOKIE_LEN: usize = 8;

#[derive(Default)]
struct Maps {
    by_secret: HashMap<String, String>,
    by_placeholder: HashMap<String, String>,
    counter: HashMap<String, usize>,
}

#[derive(Default)]
pub struct Redactor {
    maps: Mutex<Maps>,
}

fn label(s: &str) -> String {
    let l: String =
        s.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '_' }).take(32).collect();
    let l = l.trim_matches('_').to_string();
    if l.is_empty() { "value".into() } else { l }
}

struct Rules {
    cookie_header: Regex,
    set_cookie: Regex,
    auth_header: Regex,
    key_header: Regex,
    form_param: Regex,
    json_field: Regex,
    jwt: Regex,
    placeholder: Regex,
}

fn rules() -> &'static Rules {
    static R: std::sync::OnceLock<Rules> = std::sync::OnceLock::new();
    R.get_or_init(|| {
        const NAMES: &str = r"password|passwd|pwd|pass|secret|client_secret|token|access_token|refresh_token|id_token|api_?key|apikey|auth|session|sessionid|sid|otp|pin";
        Rules {
            cookie_header: Regex::new(r"(?im)^(cookie[ \t]*:)([^\r\n]*)").unwrap(),
            set_cookie: Regex::new(r"(?im)^(set-cookie[ \t]*:[ \t]*)([^=;\r\n]+)=([^;\r\n]*)").unwrap(),
            auth_header: Regex::new(r"(?im)^((?:proxy-)?authorization[ \t]*:[ \t]*)(?:(\w+)[ \t]+)?([^\r\n]+)").unwrap(),
            key_header: Regex::new(
                r"(?im)^((x-)?(api-?key|auth-?token|access-?token|session-?token|csrf-?token|xsrf-?token)[ \t]*:[ \t]*)([^\r\n]+)",
            )
            .unwrap(),
            form_param: Regex::new(&format!(r"(?i)(^|[?&\s])((?:{NAMES})[\w\-]*)=([^&\s#]+)")).unwrap(),
            json_field: Regex::new(&format!(r#"(?i)"((?:{NAMES})[\w\-]*)"\s*:\s*"([^"\\]{{1,4096}})""#)).unwrap(),
            jwt: Regex::new(r"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*").unwrap(),
            placeholder: Regex::new(r"\{\{secret:[a-z0-9_]+\}\}").unwrap(),
        }
    })
}

impl Redactor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Placeholder for a secret, creating one if needed.
    fn placeholder(&self, kind: &str, secret: &str) -> String {
        let mut m = self.maps.lock();
        if let Some(p) = m.by_secret.get(secret) {
            return p.clone();
        }
        let kind = label(kind);
        let n = m.counter.entry(kind.clone()).or_insert(0);
        *n += 1;
        let p = format!("{{{{secret:{kind}_{n}}}}}");
        m.by_secret.insert(secret.to_string(), p.clone());
        m.by_placeholder.insert(p.clone(), secret.to_string());
        p
    }

    fn sub(&self, kind: &str, secret: &str) -> String {
        self.sub_min(kind, secret, 1)
    }

    fn sub_min(&self, kind: &str, secret: &str, min_len: usize) -> String {
        if secret.len() < min_len || rules().placeholder.is_match(secret) {
            secret.to_string()
        } else {
            self.placeholder(kind, secret)
        }
    }

    /// Replaces secrets in text with placeholders.
    pub fn redact(&self, text: &str) -> String {
        let r = rules();
        let text = r.cookie_header.replace_all(text, |c: &regex::Captures| {
            let pairs: Vec<String> = c[2]
                .split(';')
                .map(|pair| match pair.split_once('=') {
                    Some((k, v)) => {
                        // Replace only the value itself; keep surrounding whitespace.
                        let core = v.trim();
                        let replaced = self.sub_min(&format!("cookie_{}", k.trim()), core, MIN_COOKIE_LEN);
                        format!("{k}={}", v.replacen(core, &replaced, 1))
                    }
                    None => pair.to_string(),
                })
                .collect();
            format!("{}{}", &c[1], pairs.join(";"))
        });
        let text = r.set_cookie.replace_all(&text, |c: &regex::Captures| {
            let v = self.sub_min(&format!("cookie_{}", c[2].trim()), &c[3], MIN_COOKIE_LEN);
            format!("{}{}={v}", &c[1], &c[2])
        });
        let text = r.auth_header.replace_all(&text, |c: &regex::Captures| {
            let scheme = c.get(2).map(|m| format!("{} ", m.as_str())).unwrap_or_default();
            format!("{}{scheme}{}", &c[1], self.sub("authorization", c[3].trim()))
        });
        let text =
            r.key_header.replace_all(&text, |c: &regex::Captures| format!("{}{}", &c[1], self.sub(&c[3], c[4].trim())));
        let text = r
            .form_param
            .replace_all(&text, |c: &regex::Captures| format!("{}{}={}", &c[1], &c[2], self.sub(&c[2], &c[3])));
        let text = r
            .json_field
            .replace_all(&text, |c: &regex::Captures| format!("\"{}\": \"{}\"", &c[1], self.sub(&c[1], &c[2])));
        let mut text = r.jwt.replace_all(&text, |c: &regex::Captures| self.sub("jwt", &c[0])).into_owned();

        // Also hide known secrets wherever else they appear (e.g. a token
        // echoed in a page). Longest first so substrings don't break them.
        let mut known: Vec<(String, String)> = {
            let m = self.maps.lock();
            m.by_secret.iter().filter(|(s, _)| s.len() >= 8).map(|(s, p)| (s.clone(), p.clone())).collect()
        };
        known.sort_by_key(|(s, _)| std::cmp::Reverse(s.len()));
        for (secret, p) in known {
            if text.contains(&secret) {
                text = text.replace(&secret, &p);
            }
        }
        text
    }

    /// Puts real values back in place of placeholders. Unknown placeholders
    /// are left as they are.
    pub fn unredact(&self, bytes: &[u8]) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(bytes) else { return bytes.to_vec() };
        if !text.contains("{{secret:") {
            return bytes.to_vec();
        }
        let m = self.maps.lock();
        rules()
            .placeholder
            .replace_all(text, |c: &regex::Captures| {
                m.by_placeholder.get(&c[0]).cloned().unwrap_or_else(|| c[0].into())
            })
            .into_owned()
            .into_bytes()
    }

    /// Placeholders in `bytes` that this redactor doesn't know.
    pub fn unknown_placeholders(&self, bytes: &[u8]) -> Vec<String> {
        let text = String::from_utf8_lossy(bytes);
        let m = self.maps.lock();
        rules()
            .placeholder
            .find_iter(&text)
            .map(|x| x.as_str().to_string())
            .filter(|p| !m.by_placeholder.contains_key(p))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_common_secrets_and_round_trips() {
        let r = Redactor::new();
        let req = "POST /login?token=abcd1234efgh HTTP/1.1\r\nCookie: session=s3cr3tvalue; theme=dark\r\n\
                   Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig\r\nX-API-Key: k-123456789\r\n\r\n\
                   username=alice&password=hunter2hunter2";
        let red = r.redact(req);
        for secret in ["abcd1234efgh", "s3cr3tvalue", "eyJhbGciOiJIUzI1NiJ9", "k-123456789", "hunter2hunter2"] {
            assert!(!red.contains(secret), "{secret} leaked:\n{red}");
        }
        assert!(red.contains("theme=dark"), "short non-secret cookie kept");
        assert!(red.contains("username=alice"));
        assert!(red.contains("{{secret:cookie_session_1}}"));
        assert_eq!(r.unredact(red.as_bytes()), req.as_bytes());
    }

    #[test]
    fn same_secret_same_placeholder_everywhere() {
        let r = Redactor::new();
        let a = r.redact("Set-Cookie: sid=abcdef123456; Path=/");
        let b = r.redact("<p>debug: your session is abcdef123456</p>");
        assert!(a.contains("{{secret:cookie_sid_1}}"));
        assert!(b.contains("{{secret:cookie_sid_1}}"), "{b}");
    }

    #[test]
    fn json_fields_and_unknown_placeholders() {
        let r = Redactor::new();
        let red = r.redact(r#"{"user":"bob","password":"pa55word!","access_token":"tok_ABCDEFGH"}"#);
        assert!(!red.contains("pa55word!") && !red.contains("tok_ABCDEFGH"), "{red}");
        assert_eq!(r.unknown_placeholders(b"{{secret:made_up_9}}"), vec!["{{secret:made_up_9}}"]);
    }
}
