//! Match-and-replace rules: user-defined edits the proxy applies to
//! traffic on the fly (ADR-0002 allows changes a user asked for).
//!
//! A rule targets one part of a request or response: the first line, the
//! headers or the body. Header rules work line by line; an empty match adds
//! the replacement as a new header, and a header replaced by nothing is
//! removed. Body rules update `Content-Length`, and a chunked body that a
//! rule changes is re-sent with `Content-Length` framing. Compressed bodies
//! are left alone, since a pattern can't see inside them.

use std::sync::Arc;

use parking_lot::RwLock;
use regex::bytes::{NoExpand, Regex};
use serde::{Deserialize, Serialize};

use crate::intercept::ScopeFn;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    RequestFirstLine,
    RequestHeader,
    RequestBody,
    ResponseFirstLine,
    ResponseHeader,
    ResponseBody,
}

impl Part {
    fn is_request(self) -> bool {
        matches!(self, Part::RequestFirstLine | Part::RequestHeader | Part::RequestBody)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    pub enabled: bool,
    pub part: Part,
    /// Text (or regex, if `regex` is set) to find. Empty on a header rule
    /// means "add `replace` as a new header".
    #[serde(rename = "match")]
    pub pattern: String,
    /// Replacement; with `regex`, `$1` and `${name}` refer to groups.
    pub replace: String,
    pub regex: bool,
    /// Apply only to in-scope targets (the default), so a rule that adds a
    /// credential can't leak it to third-party hosts.
    pub in_scope_only: bool,
    pub comment: String,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            enabled: true,
            part: Part::RequestHeader,
            pattern: String::new(),
            replace: String::new(),
            regex: false,
            in_scope_only: true,
            comment: String::new(),
        }
    }
}

struct Compiled {
    rule: Rule,
    re: Option<Regex>,
}

impl Compiled {
    fn new(rule: Rule) -> Result<Self, String> {
        let re = if rule.pattern.is_empty() {
            None
        } else {
            let src = if rule.regex { rule.pattern.clone() } else { regex::escape(&rule.pattern) };
            Some(Regex::new(&src).map_err(|e| format!("rule {:?}: {e}", rule.pattern))?)
        };
        Ok(Self { rule, re })
    }

    fn replace_in(&self, text: &[u8]) -> Option<Vec<u8>> {
        let re = self.re.as_ref()?;
        if !re.is_match(text) {
            return None;
        }
        let out = if self.rule.regex {
            re.replace_all(text, self.rule.replace.as_bytes())
        } else {
            re.replace_all(text, NoExpand(self.rule.replace.as_bytes()))
        };
        Some(out.into_owned())
    }
}

/// Checks rules without installing them; returns the first error.
pub fn validate(rules: &[Rule]) -> Result<(), String> {
    for r in rules {
        Compiled::new(r.clone())?;
        if r.pattern.is_empty() && r.part != Part::RequestHeader && r.part != Part::ResponseHeader {
            return Err("only header rules may have an empty match (it adds a header)".into());
        }
        if r.replace.contains(['\r', '\n']) && r.part != Part::RequestBody && r.part != Part::ResponseBody {
            return Err("line breaks are only allowed in body replacements".into());
        }
    }
    Ok(())
}

/// The live rule set used by the proxy.
#[derive(Default)]
pub struct Rewriter {
    rules: RwLock<Arc<Vec<Compiled>>>,
    source: RwLock<Vec<Rule>>,
    scope: RwLock<Option<ScopeFn>>,
}

impl Rewriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_rules(&self, rules: Vec<Rule>) -> Result<(), String> {
        validate(&rules)?;
        let compiled = rules.iter().cloned().map(Compiled::new).collect::<Result<Vec<_>, _>>()?;
        *self.rules.write() = Arc::new(compiled);
        *self.source.write() = rules;
        Ok(())
    }

    pub fn rules(&self) -> Vec<Rule> {
        self.source.read().clone()
    }

    /// How "in scope" is decided. Without one, in-scope-only rules never apply.
    pub fn set_scope(&self, f: ScopeFn) {
        *self.scope.write() = Some(f);
    }

    /// Applies request rules; `None` when nothing changed.
    pub fn apply_request(&self, scheme: &str, host: &str, port: u16, path: &str, raw: &[u8]) -> Option<Vec<u8>> {
        self.apply(true, scheme, host, port, path, raw)
    }

    /// Applies response rules; `None` when nothing changed. `path` is the request's.
    pub fn apply_response(&self, scheme: &str, host: &str, port: u16, path: &str, raw: &[u8]) -> Option<Vec<u8>> {
        self.apply(false, scheme, host, port, path, raw)
    }

    fn apply(&self, request: bool, scheme: &str, host: &str, port: u16, path: &str, raw: &[u8]) -> Option<Vec<u8>> {
        let rules = self.rules.read().clone();
        let mut active = rules.iter().filter(|c| c.rule.enabled && c.rule.part.is_request() == request).peekable();
        active.peek()?;
        let in_scope = std::cell::OnceCell::new();
        let scope =
            || *in_scope.get_or_init(|| self.scope.read().as_ref().is_some_and(|f| f(scheme, host, port, path)));
        let mut msg = Message::parse(raw)?;
        let mut changed = false;
        for c in active {
            if c.rule.in_scope_only && !scope() {
                continue;
            }
            changed |= msg.apply(c);
        }
        changed.then(|| msg.into_bytes())
    }
}

/// A message split into editable parts, keeping its line endings.
struct Message {
    first: Vec<u8>,
    headers: Vec<Vec<u8>>,
    eol: &'static [u8],
    body: Vec<u8>,
    body_changed: bool,
}

impl Message {
    fn parse(raw: &[u8]) -> Option<Self> {
        let end = pm_http::find_head_end(raw).ok()??;
        let (head, body) = raw.split_at(end);
        let eol: &'static [u8] = if head.windows(2).any(|w| w == b"\r\n") { b"\r\n" } else { b"\n" };
        let text = head.strip_suffix(eol).and_then(|h| h.strip_suffix(eol)).unwrap_or(head);
        let mut lines = split(text, eol).into_iter();
        let first = lines.next()?.to_vec();
        Some(Self {
            first,
            headers: lines.map(<[u8]>::to_vec).collect(),
            eol,
            body: body.to_vec(),
            body_changed: false,
        })
    }

    fn apply(&mut self, c: &Compiled) -> bool {
        match c.rule.part {
            Part::RequestFirstLine | Part::ResponseFirstLine => match c.replace_in(&self.first) {
                Some(new) => {
                    self.first = new;
                    true
                }
                None => false,
            },
            Part::RequestHeader | Part::ResponseHeader => {
                if c.re.is_none() {
                    if c.rule.replace.is_empty() {
                        return false;
                    }
                    self.headers.push(c.rule.replace.as_bytes().to_vec());
                    return true;
                }
                let mut changed = false;
                self.headers = std::mem::take(&mut self.headers)
                    .into_iter()
                    .filter_map(|h| match c.replace_in(&h) {
                        Some(new) => {
                            changed = true;
                            (!new.trim_ascii().is_empty()).then_some(new)
                        }
                        None => Some(h),
                    })
                    .collect();
                changed
            }
            Part::RequestBody | Part::ResponseBody => {
                if self.header("content-encoding").is_some_and(|v| !v.trim_ascii().eq_ignore_ascii_case(b"identity")) {
                    return false;
                }
                let chunked = self.is_chunked();
                let body = if chunked {
                    match pm_http::decode_chunked(&self.body) {
                        Some(b) => b,
                        None => return false,
                    }
                } else {
                    self.body.clone()
                };
                let Some(new) = c.replace_in(&body) else { return false };
                if chunked {
                    self.headers.retain(|h| !name_is(h, b"transfer-encoding"));
                    self.headers.push(b"Content-Length: 0".to_vec());
                }
                self.body = new;
                self.body_changed = true;
                true
            }
        }
    }

    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers.iter().find(|h| name_is(h, name.as_bytes())).map(|h| {
            let colon = h.iter().position(|&b| b == b':').unwrap_or(h.len());
            &h[(colon + 1).min(h.len())..]
        })
    }

    fn is_chunked(&self) -> bool {
        self.headers.iter().any(|h| {
            name_is(h, b"transfer-encoding") && String::from_utf8_lossy(h).to_ascii_lowercase().contains("chunked")
        })
    }

    fn into_bytes(mut self) -> Vec<u8> {
        if self.body_changed {
            let len = self.body.len();
            for h in self.headers.iter_mut().filter(|h| name_is(h, b"content-length")) {
                let colon = h.iter().position(|&b| b == b':').unwrap_or(h.len());
                h.truncate(colon);
                h.extend_from_slice(format!(": {len}").as_bytes());
            }
        }
        let mut out = self.first;
        for h in &self.headers {
            out.extend_from_slice(self.eol);
            out.extend_from_slice(h);
        }
        out.extend_from_slice(self.eol);
        out.extend_from_slice(self.eol);
        out.extend_from_slice(&self.body);
        out
    }
}

fn name_is(line: &[u8], name: &[u8]) -> bool {
    line.iter().position(|&b| b == b':').is_some_and(|c| line[..c].trim_ascii().eq_ignore_ascii_case(name))
}

fn split<'a>(text: &'a [u8], sep: &[u8]) -> Vec<&'a [u8]> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.windows(sep.len()).position(|w| w == sep) {
        out.push(&rest[..i]);
        rest = &rest[i + sep.len()..];
    }
    out.push(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rw(rules: Vec<Rule>) -> Rewriter {
        let r = Rewriter::new();
        r.set_rules(rules).unwrap();
        r.set_scope(Arc::new(|_, host, _, _| host == "in.test"));
        r
    }
    fn req(r: &Rewriter, host: &str, raw: &str) -> Option<String> {
        r.apply_request("http", host, 80, "/", raw.as_bytes()).map(|b| String::from_utf8(b).unwrap())
    }

    #[test]
    fn adds_replaces_and_removes_headers() {
        let r = rw(vec![
            Rule { pattern: String::new(), replace: "X-Test: 1".into(), ..Default::default() },
            Rule {
                pattern: "User-Agent: .*".into(),
                replace: "User-Agent: pm".into(),
                regex: true,
                ..Default::default()
            },
            Rule { pattern: "^Cookie: .*$".into(), replace: String::new(), regex: true, ..Default::default() },
        ]);
        let out = req(&r, "in.test", "GET / HTTP/1.1\r\nHost: in.test\r\nUser-Agent: curl/8\r\nCookie: a=1\r\n\r\n");
        assert_eq!(out.unwrap(), "GET / HTTP/1.1\r\nHost: in.test\r\nUser-Agent: pm\r\nX-Test: 1\r\n\r\n");
    }

    #[test]
    fn untouched_messages_and_out_of_scope_are_not_rewritten() {
        let r = rw(vec![Rule { pattern: "nothing-matches".into(), replace: "x".into(), ..Default::default() }]);
        assert_eq!(req(&r, "in.test", "GET / HTTP/1.1\r\nHost: in.test\r\n\r\n"), None);
        let r = rw(vec![Rule { replace: "Authorization: Bearer secret".into(), ..Default::default() }]);
        assert_eq!(req(&r, "third-party.test", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"), None, "credential stays in scope");
        let any = rw(vec![Rule { replace: "X-A: 1".into(), in_scope_only: false, ..Default::default() }]);
        assert!(req(&any, "third-party.test", "GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_some());
    }

    #[test]
    fn body_rules_fix_content_length_and_dechunk() {
        let r = rw(vec![Rule {
            part: Part::RequestBody,
            pattern: r#""role":"(\w+)""#.into(),
            replace: r#""role":"admin","was":"$1""#.into(),
            regex: true,
            ..Default::default()
        }]);
        let out = req(&r, "in.test", "POST / HTTP/1.1\r\nContent-Length: 15\r\n\r\n{\"role\":\"user\"}").unwrap();
        assert_eq!(out, "POST / HTTP/1.1\r\nContent-Length: 29\r\n\r\n{\"role\":\"admin\",\"was\":\"user\"}");

        let r = rw(vec![Rule {
            part: Part::ResponseBody,
            pattern: "secret".into(),
            replace: "public".into(),
            ..Default::default()
        }]);
        let resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab \r\n6\r\nsecret\r\n0\r\n\r\n";
        let out = r.apply_response("http", "in.test", 80, "/", resp.as_bytes()).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nab public");

        let gz = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 6\r\n\r\nsecret";
        assert_eq!(r.apply_response("http", "in.test", 80, "/", gz.as_bytes()), None, "compressed bodies are skipped");
    }

    #[test]
    fn literal_rules_do_not_expand_dollars_and_first_line_rules_work() {
        let r = rw(vec![
            Rule {
                part: Part::RequestFirstLine,
                pattern: "/v1/".into(),
                replace: "/v2/$1/".into(),
                ..Default::default()
            },
            Rule { part: Part::RequestFirstLine, pattern: "disabled".into(), enabled: false, ..Default::default() },
        ]);
        let out = req(&r, "in.test", "GET /v1/disabled HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(out, "GET /v2/$1/disabled HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn validation() {
        assert!(validate(&[Rule { pattern: "(".into(), regex: true, ..Default::default() }]).is_err());
        assert!(validate(&[Rule { part: Part::RequestBody, ..Default::default() }]).is_err(), "empty body match");
        assert!(
            validate(&[Rule { replace: "A: 1\r\nB: 2".into(), ..Default::default() }]).is_err(),
            "header smuggling"
        );
        assert!(validate(&[Rule { pattern: "(".into(), ..Default::default() }]).is_ok(), "literal parens are fine");
    }
}
