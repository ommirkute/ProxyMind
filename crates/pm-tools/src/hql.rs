//! A small query language for filtering HTTP history, e.g.
//!
//! ```text
//! status:>=400 -ext:png,js resp:"stack trace"
//! host:*.shop.test (method:POST OR param:id) len:>1000
//! resp~"admin\d+" respheader:set-cookie is:inscope
//! ```
//!
//! Terms are `field:value`, or `field~regex` for a regular expression
//! (add `(?i)` to ignore case); a bare word matches host, path or comment.
//! Terms side by side must all match; `OR`, `-` (or `NOT`) and parentheses
//! combine them. Values may be quoted (`"two words"`), a glob with `*`, a
//! comma list, or for numbers `>N`, `>=N`, `<N`, `<=N`, `N..M` and `4xx`.
//! Text matches ignore case.
//!
//! Evaluation needs a row's metadata ([`Meta`]); request and response bytes
//! are fetched through [`Fetch`] only when a term needs them, and terms
//! that need them run last.

use regex::{Regex, RegexBuilder};

/// Fields a query can use, with a short description (for help texts).
pub const FIELDS: &[(&str, &str)] = &[
    ("host", "host name (glob with *)"),
    ("path", "path and query"),
    ("url", "scheme://host:port/path"),
    ("method", "GET, POST… (comma list)"),
    ("status", "200, 4xx, >=500, 300..399"),
    ("ext", "file extension (comma list)"),
    ("len", "response length in bytes"),
    ("reqlen", "request length in bytes"),
    ("time", "response time in ms"),
    ("id", "exchange number"),
    ("source", "proxy, replay, fuzzer…"),
    ("actor", "who sent it, e.g. agent:claude"),
    ("identity", "test identity used"),
    ("comment", "your comment"),
    ("highlight", "highlight colour"),
    ("mime", "response Content-Type"),
    ("req", "request text (head and decoded body)"),
    ("resp", "response text (head and decoded body)"),
    ("any", "request or response text"),
    ("reqheader", "request header name, or name=value"),
    ("respheader", "response header name, or name=value"),
    ("param", "query or form parameter name"),
    ("is", "error, annotated, inscope, response, redirect"),
];

/// A row's metadata (no bytes).
#[derive(Debug, Clone, Copy, Default)]
pub struct Meta<'a> {
    pub id: i64,
    pub scheme: &'a str,
    pub host: &'a str,
    pub port: u16,
    pub method: &'a str,
    pub path: &'a str,
    pub status: Option<u16>,
    pub req_len: i64,
    pub resp_len: Option<i64>,
    pub duration_ms: Option<i64>,
    pub source: &'a str,
    pub actor: &'a str,
    pub identity: Option<&'a str>,
    pub comment: Option<&'a str>,
    pub highlight: Option<&'a str>,
    pub error: Option<&'a str>,
}

/// Loads what metadata doesn't have, on demand.
pub trait Fetch {
    /// The request: head as recorded, then the decoded body.
    fn request(&mut self) -> &[u8];
    /// The response, the same way (None: no response).
    fn response(&mut self) -> Option<&[u8]>;
    /// Whether the target is in the rules of engagement's scope.
    fn in_scope(&mut self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    /// Byte offset in the query.
    pub at: usize,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (at character {})", self.message, self.at + 1)
    }
}

/// A parsed query.
#[derive(Debug, Clone)]
pub struct Query {
    expr: Expr,
}

#[derive(Debug, Clone)]
enum Expr {
    All(Vec<Expr>),
    Any(Vec<Expr>),
    Not(Box<Expr>),
    Term(Field, Test),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Bare,
    Host,
    Path,
    Url,
    Method,
    Status,
    Ext,
    Len,
    ReqLen,
    Time,
    Id,
    Source,
    Actor,
    Identity,
    Comment,
    Highlight,
    Mime,
    Req,
    Resp,
    AnyText,
    ReqHeader,
    RespHeader,
    Param,
    Is,
}

impl Field {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "host" => Self::Host,
            "path" => Self::Path,
            "url" => Self::Url,
            "method" => Self::Method,
            "status" => Self::Status,
            "ext" => Self::Ext,
            "len" | "size" => Self::Len,
            "reqlen" => Self::ReqLen,
            "time" => Self::Time,
            "id" => Self::Id,
            "source" | "tool" => Self::Source,
            "actor" => Self::Actor,
            "identity" => Self::Identity,
            "comment" => Self::Comment,
            "highlight" => Self::Highlight,
            "mime" | "type" => Self::Mime,
            "req" | "request" => Self::Req,
            "resp" | "response" => Self::Resp,
            "any" => Self::AnyText,
            "reqheader" => Self::ReqHeader,
            "respheader" => Self::RespHeader,
            "param" => Self::Param,
            "is" => Self::Is,
            _ => return None,
        })
    }

    fn numeric(self) -> bool {
        matches!(self, Self::Status | Self::Len | Self::ReqLen | Self::Time | Self::Id)
    }

    /// Exact (case-insensitive) matches rather than "contains".
    fn exact(self) -> bool {
        matches!(self, Self::Method | Self::Ext | Self::Source | Self::Actor | Self::Identity | Self::Highlight)
    }

    /// 0: metadata; 1: the request; 2: the response.
    fn cost(self) -> u8 {
        match self {
            Self::Req | Self::ReqHeader | Self::Param => 1,
            Self::Mime | Self::Resp | Self::AnyText | Self::RespHeader | Self::Is => 2,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone)]
enum Num {
    Eq(i64),
    Gt(i64),
    Ge(i64),
    Lt(i64),
    Le(i64),
    Range(i64, i64),
}

impl Num {
    fn test(&self, v: i64) -> bool {
        match *self {
            Self::Eq(n) => v == n,
            Self::Gt(n) => v > n,
            Self::Ge(n) => v >= n,
            Self::Lt(n) => v < n,
            Self::Le(n) => v <= n,
            Self::Range(a, b) => (a..=b).contains(&v),
        }
    }
}

#[derive(Debug, Clone)]
enum Test {
    /// Lower-cased needle.
    Contains(String),
    /// Lower-cased alternatives.
    OneOf(Vec<String>),
    Re(Regex),
    Nums(Vec<Num>),
    /// Header name (lower) and optional lower-cased value needle.
    Header(String, Option<String>),
    Flag(String),
}

fn err(message: impl Into<String>, at: usize) -> ParseError {
    ParseError { message: message.into(), at }
}

// ---- tokens ----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Open,
    Close,
    Or,
    And,
    Not,
    /// Field name (if any), value, value was quoted or a regex literal.
    Word(Option<String>, String, Lit),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lit {
    Plain,
    Quoted,
    Regex,
}

/// Reads a value: quoted, or plain (up to space or paren).
fn read_value(q: &[u8], mut i: usize, regex: bool) -> Result<(String, Lit, usize), ParseError> {
    match q.get(i) {
        Some(b'"') => {
            let start = i;
            i += 1;
            let mut out = Vec::new();
            loop {
                match q.get(i) {
                    None => return Err(err("missing closing quote", start)),
                    // Only \" and \\ are escapes; other backslashes stay (regexes).
                    Some(b'\\') if matches!(q.get(i + 1), Some(b'"' | b'\\')) => {
                        out.push(q[i + 1]);
                        i += 2;
                    }
                    Some(b'"') => return Ok((String::from_utf8_lossy(&out).into_owned(), Lit::Quoted, i + 1)),
                    Some(&c) => {
                        out.push(c);
                        i += 1;
                    }
                }
            }
        }
        _ => {
            // A regex may hold balanced parentheses; a `)` beyond them ends it.
            let start = i;
            let mut depth = 0usize;
            while let Some(&c) = q.get(i) {
                match c {
                    _ if c.is_ascii_whitespace() => break,
                    b'(' if regex => depth += 1,
                    b')' if regex && depth > 0 => depth -= 1,
                    b'(' | b')' => break,
                    b'\\' if regex && q.get(i + 1).is_some() => i += 1,
                    _ => {}
                }
                i += 1;
            }
            Ok((String::from_utf8_lossy(&q[start..i]).into_owned(), Lit::Plain, i))
        }
    }
}

fn tokenize(query: &str) -> Result<Vec<(Tok, usize)>, ParseError> {
    let q = query.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < q.len() {
        let c = q[i];
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let at = i;
        match c {
            b'(' => {
                out.push((Tok::Open, at));
                i += 1;
                continue;
            }
            b')' => {
                out.push((Tok::Close, at));
                i += 1;
                continue;
            }
            b'-' | b'!' if q.get(i + 1).is_some_and(|n| !n.is_ascii_whitespace()) => {
                out.push((Tok::Not, at));
                i += 1;
                continue;
            }
            b'|' if q.get(i + 1) == Some(&b'|') => {
                out.push((Tok::Or, at));
                i += 2;
                continue;
            }
            b'&' if q.get(i + 1) == Some(&b'&') => {
                out.push((Tok::And, at));
                i += 2;
                continue;
            }
            _ => {}
        }
        // field:value?
        let mut j = i;
        while q.get(j).is_some_and(u8::is_ascii_alphabetic) {
            j += 1;
        }
        if j > i && matches!(q.get(j), Some(b':' | b'~')) {
            let name = query[i..j].to_ascii_lowercase();
            if Field::parse(&name).is_some() {
                let is_re = q[j] == b'~';
                let (v, lit, next) = read_value(q, j + 1, is_re)?;
                let lit = if is_re { Lit::Regex } else { lit };
                out.push((Tok::Word(Some(name), v, lit), at));
                i = next;
                continue;
            }
            // `http://…` and other text with a colon are plain words.
            if !matches!(name.as_str(), "http" | "https" | "ws" | "wss") && q.get(j + 1) != Some(&b'/') {
                let names: Vec<&str> = FIELDS.iter().map(|(n, _)| *n).collect();
                return Err(err(format!("unknown field {name:?} (fields: {})", names.join(", ")), at));
            }
        }
        let (v, lit, next) = read_value(q, i, false)?;
        let tok = match (lit, v.as_str()) {
            (Lit::Plain, "OR") => Tok::Or,
            (Lit::Plain, "AND") => Tok::And,
            (Lit::Plain, "NOT") => Tok::Not,
            _ => Tok::Word(None, v, lit),
        };
        out.push((tok, at));
        i = next;
    }
    Ok(out)
}

// ---- parser ------------------------------------------------------------------

struct Parser {
    toks: Vec<(Tok, usize)>,
    pos: usize,
    len: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.0)
    }

    fn at(&self) -> usize {
        self.toks.get(self.pos).map_or(self.len, |t| t.1)
    }

    fn or(&mut self) -> Result<Expr, ParseError> {
        let mut parts = vec![self.and()?];
        while self.peek() == Some(&Tok::Or) {
            self.pos += 1;
            parts.push(self.and()?);
        }
        Ok(if parts.len() == 1 { parts.remove(0) } else { Expr::Any(parts) })
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut parts = vec![self.unary()?];
        loop {
            match self.peek() {
                Some(Tok::And) => {
                    self.pos += 1;
                    parts.push(self.unary()?);
                }
                Some(Tok::Or | Tok::Close) | None => break,
                Some(_) => parts.push(self.unary()?),
            }
        }
        // Cheap tests first: metadata before request before response.
        parts.sort_by_key(cost);
        Ok(if parts.len() == 1 { parts.remove(0) } else { Expr::All(parts) })
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        let at = self.at();
        match self.toks.get(self.pos).cloned() {
            Some((Tok::Not, _)) => {
                self.pos += 1;
                Ok(Expr::Not(Box::new(self.unary()?)))
            }
            Some((Tok::Open, _)) => {
                self.pos += 1;
                let e = self.or()?;
                if self.peek() != Some(&Tok::Close) {
                    return Err(err("missing )", self.at()));
                }
                self.pos += 1;
                Ok(e)
            }
            Some((Tok::Word(field, value, lit), _)) => {
                self.pos += 1;
                term(field.as_deref(), &value, lit).map_err(|m| err(m, at))
            }
            Some((Tok::Close, _)) => Err(err("unexpected )", at)),
            Some((Tok::Or | Tok::And, _)) => Err(err("OR/AND needs a term on both sides", at)),
            None => Err(err("the query ends too early", at)),
        }
    }
}

fn cost(e: &Expr) -> u8 {
    match e {
        Expr::Term(f, _) => f.cost(),
        Expr::Not(x) => cost(x),
        Expr::All(xs) | Expr::Any(xs) => xs.iter().map(cost).max().unwrap_or(0),
    }
}

fn regex(pat: &str) -> Result<Regex, String> {
    RegexBuilder::new(pat).size_limit(1 << 20).build().map_err(|e| format!("bad regex: {e}"))
}

/// `*` globs match the whole value; other characters are literal.
fn glob(pat: &str) -> Result<Regex, String> {
    let parts: Vec<String> = pat.split('*').map(regex::escape).collect();
    regex(&format!("(?i)^{}$", parts.join(".*")))
}

fn num(v: &str, status: bool) -> Result<Num, String> {
    let bad = || format!("{v:?} is not a number, a comparison (>N, <=N) or a range (N..M)");
    let n = |s: &str| s.trim().parse::<i64>().map_err(|_| bad());
    if status && v.len() == 3 && v.ends_with("xx") {
        let d = n(&v[..1])?;
        return Ok(Num::Range(d * 100, d * 100 + 99));
    }
    Ok(if let Some(r) = v.strip_prefix(">=") {
        Num::Ge(n(r)?)
    } else if let Some(r) = v.strip_prefix("<=") {
        Num::Le(n(r)?)
    } else if let Some(r) = v.strip_prefix('>') {
        Num::Gt(n(r)?)
    } else if let Some(r) = v.strip_prefix('<') {
        Num::Lt(n(r)?)
    } else if let Some((a, b)) = v.split_once("..") {
        Num::Range(n(a)?, n(b)?)
    } else {
        Num::Eq(n(v)?)
    })
}

fn term(field: Option<&str>, value: &str, lit: Lit) -> Result<Expr, String> {
    let field = match field {
        Some(f) => Field::parse(f).ok_or_else(|| format!("unknown field {f:?}"))?,
        None => Field::Bare,
    };
    if value.is_empty() {
        return Err("missing value".into());
    }
    let test = if lit == Lit::Regex {
        if field.numeric() || field == Field::Is {
            return Err("regexes work on text fields".into());
        }
        Test::Re(regex(value)?)
    } else if field.numeric() {
        Test::Nums(value.split(',').map(|v| num(v, field == Field::Status)).collect::<Result<_, _>>()?)
    } else if field == Field::Is {
        let v = value.to_ascii_lowercase();
        if !["error", "annotated", "inscope", "response", "redirect"].contains(&v.as_str()) {
            return Err(format!("is:{v}? use error, annotated, inscope, response or redirect"));
        }
        Test::Flag(v)
    } else if matches!(field, Field::ReqHeader | Field::RespHeader) {
        let (name, val) = match value.split_once('=') {
            Some((n, v)) => (n, Some(v.to_ascii_lowercase())),
            None => (value, None),
        };
        Test::Header(name.trim().to_ascii_lowercase(), val)
    } else if lit == Lit::Plain && value.contains('*') && matches!(field, Field::Host | Field::Path | Field::Url) {
        Test::Re(glob(value)?)
    } else if field.exact() {
        Test::OneOf(value.split(',').map(|v| v.trim().trim_start_matches('.').to_ascii_lowercase()).collect())
    } else {
        Test::Contains(value.to_ascii_lowercase())
    };
    Ok(Expr::Term(field, test))
}

impl Query {
    pub fn parse(query: &str) -> Result<Self, ParseError> {
        if query.len() > 4096 {
            return Err(err("the query is longer than 4096 characters", 0));
        }
        let toks = tokenize(query)?;
        if toks.is_empty() {
            return Ok(Self { expr: Expr::All(vec![]) });
        }
        let mut p = Parser { toks, pos: 0, len: query.len() };
        let expr = p.or()?;
        if p.pos < p.toks.len() {
            return Err(err("unexpected text", p.at()));
        }
        Ok(Self { expr })
    }

    /// Whether evaluating may need the request or response bytes.
    pub fn needs_content(&self) -> bool {
        cost(&self.expr) > 0
    }

    pub fn matches(&self, m: &Meta<'_>, f: &mut dyn Fetch) -> bool {
        eval(&self.expr, m, f)
    }

    /// Lower-case needles such that every exchange this query matches contains at least one of them
    /// in its decoded request or response text; None when no such set is known.
    ///
    /// This is a necessary condition, for narrowing candidates with a full-text index only: a row that
    /// contains a needle may still not match, and `matches` stays the judge of every candidate.
    /// Only `req`, `resp` and `any` substring terms of 3 or more characters give needles (header,
    /// parameter and bare terms test normalised or parsed values, not the text). `AND` needs one
    /// child's requirement (the one with the fewest, then the longest, needles), `OR` needs all of
    /// its children's (the union), and negation gives none.
    pub fn required_literals(&self) -> Option<Vec<String>> {
        required(&self.expr)
    }
}

fn required(e: &Expr) -> Option<Vec<String>> {
    match e {
        Expr::Term(Field::Req | Field::Resp | Field::AnyText, Test::Contains(n)) if n.chars().count() >= 3 => {
            Some(vec![n.clone()])
        }
        Expr::Term(..) | Expr::Not(_) => None,
        Expr::All(xs) => xs
            .iter()
            .filter_map(required)
            .min_by_key(|v| (v.len(), std::cmp::Reverse(v.iter().map(|n| n.chars().count()).min().unwrap_or(0)))),
        Expr::Any(xs) => {
            let mut all = Vec::new();
            for x in xs {
                all.extend(required(x)?);
            }
            (!all.is_empty()).then(|| {
                all.sort();
                all.dedup();
                all
            })
        }
    }
}

fn eval(e: &Expr, m: &Meta<'_>, f: &mut dyn Fetch) -> bool {
    match e {
        Expr::All(xs) => xs.iter().all(|x| eval(x, m, f)),
        Expr::Any(xs) => xs.iter().any(|x| eval(x, m, f)),
        Expr::Not(x) => !eval(x, m, f),
        Expr::Term(field, test) => eval_term(*field, test, m, f),
    }
}

fn text_test(test: &Test, s: &str) -> bool {
    match test {
        Test::Contains(n) => s.to_ascii_lowercase().contains(n.as_str()),
        Test::OneOf(xs) => xs.iter().any(|x| s.eq_ignore_ascii_case(x)),
        Test::Re(re) => re.is_match(s),
        _ => false,
    }
}

fn bytes_test(test: &Test, b: &[u8]) -> bool {
    match test {
        Test::Contains(n) => memchr::memmem::find(&b.to_ascii_lowercase(), n.as_bytes()).is_some(),
        Test::Re(re) => re.is_match(&String::from_utf8_lossy(b)),
        _ => false,
    }
}

/// Header lines of a message (`name: value`), lower-cased.
fn header_test(raw: &[u8], name: &str, val: Option<&str>) -> bool {
    let (head, _) = pm_http::split_message(raw);
    String::from_utf8_lossy(head).lines().skip(1).any(|l| {
        let Some((n, v)) = l.split_once(':') else { return false };
        n.trim().eq_ignore_ascii_case(name) && val.is_none_or(|x| v.to_ascii_lowercase().contains(x))
    })
}

fn ext_of(path: &str) -> &str {
    let p = path.split(['?', '#']).next().unwrap_or_default();
    let last = p.rsplit('/').next().unwrap_or_default();
    last.rsplit_once('.').map_or("", |(_, e)| e)
}

fn eval_term(field: Field, test: &Test, m: &Meta<'_>, f: &mut dyn Fetch) -> bool {
    let opt = |s: Option<&str>| s.is_some_and(|s| text_test(test, s));
    let nums = |v: Option<i64>| match (test, v) {
        (Test::Nums(ns), Some(v)) => ns.iter().any(|n| n.test(v)),
        _ => false,
    };
    match field {
        Field::Bare => [m.host, m.path, m.comment.unwrap_or_default()].iter().any(|s| text_test(test, s)),
        Field::Host => text_test(test, m.host),
        Field::Path => text_test(test, m.path),
        Field::Url => {
            let url = pm_core::url(m.scheme, m.host, m.port, m.path);
            text_test(test, &url)
        }
        Field::Method => text_test(test, m.method),
        Field::Ext => text_test(test, ext_of(m.path)),
        Field::Source => text_test(test, m.source),
        Field::Actor => text_test(test, m.actor),
        Field::Identity => opt(m.identity),
        Field::Comment => opt(m.comment),
        Field::Highlight => opt(m.highlight),
        Field::Status => nums(m.status.map(i64::from)),
        Field::Len => nums(m.resp_len),
        Field::ReqLen => nums(Some(m.req_len)),
        Field::Time => nums(m.duration_ms),
        Field::Id => nums(Some(m.id)),
        Field::Req => bytes_test(test, f.request()),
        Field::Resp => f.response().is_some_and(|r| bytes_test(test, r)),
        Field::AnyText => bytes_test(test, f.request()) || f.response().is_some_and(|r| bytes_test(test, r)),
        Field::ReqHeader | Field::RespHeader => {
            let Test::Header(name, val) = test else { return false };
            let raw = if field == Field::ReqHeader { Some(f.request()) } else { f.response() };
            raw.is_some_and(|r| header_test(r, name, val.as_deref()))
        }
        Field::Mime => f.response().is_some_and(|r| {
            let (head, _) = pm_http::split_message(r);
            pm_http::parse_response_head(head)
                .ok()
                .and_then(|h| {
                    pm_http::header(&h.headers, "content-type").map(|v| String::from_utf8_lossy(v).into_owned())
                })
                .is_some_and(|ct| text_test(test, &ct))
        }),
        Field::Param => param_names(m.path, f.request()).iter().any(|n| match test {
            Test::Contains(x) => n.eq_ignore_ascii_case(x),
            _ => text_test(test, n),
        }),
        Field::Is => {
            let Test::Flag(flag) = test else { return false };
            match flag.as_str() {
                "error" => m.error.is_some(),
                "annotated" => m.comment.is_some_and(|c| !c.is_empty()) || m.highlight.is_some(),
                "response" => m.status.is_some(),
                "redirect" => m.status.is_some_and(|s| (300..400).contains(&s)),
                "inscope" => f.in_scope(),
                _ => false,
            }
        }
    }
}

/// Names of query and URL-encoded form parameters.
fn param_names(path: &str, request: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut add = |s: &str| {
        for kv in s.split('&').filter(|kv| !kv.is_empty()) {
            out.push(kv.split('=').next().unwrap_or_default().to_string());
        }
    };
    if let Some((_, q)) = path.split_once('?') {
        add(q);
    }
    let (head, body) = pm_http::split_message(request);
    let form = String::from_utf8_lossy(head).to_ascii_lowercase().contains("x-www-form-urlencoded");
    if form && let Ok(b) = std::str::from_utf8(body) {
        add(b.trim());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Row {
        req: Vec<u8>,
        resp: Option<Vec<u8>>,
        scope: bool,
        fetched: usize,
    }

    impl Fetch for Row {
        fn request(&mut self) -> &[u8] {
            self.fetched += 1;
            &self.req
        }
        fn response(&mut self) -> Option<&[u8]> {
            self.fetched += 1;
            self.resp.as_deref()
        }
        fn in_scope(&mut self) -> bool {
            self.scope
        }
    }

    fn meta() -> Meta<'static> {
        Meta {
            id: 42,
            scheme: "https",
            host: "api.shop.test",
            port: 443,
            method: "POST",
            path: "/api/orders/7?id=7&debug=1",
            status: Some(500),
            req_len: 120,
            resp_len: Some(2048),
            duration_ms: Some(812),
            source: "proxy",
            actor: "human:local",
            identity: None,
            comment: Some("IDOR?"),
            highlight: Some("red"),
            error: None,
        }
    }

    fn row() -> Row {
        Row {
            req: b"POST /api/orders/7 HTTP/1.1\r\nHost: api.shop.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nqty=2&note=hi".to_vec(),
            resp: Some(b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\nSet-Cookie: s=1\r\n\r\n<pre>Stack trace: admin42 at Foo.bar</pre>".to_vec()),
            scope: true,
            fetched: 0,
        }
    }

    fn check(q: &str) -> bool {
        Query::parse(q).unwrap_or_else(|e| panic!("{q}: {e}")).matches(&meta(), &mut row())
    }

    #[test]
    fn required_literals_are_necessary_conditions() {
        let lits = |q: &str| Query::parse(q).unwrap().required_literals();
        let some = |v: &[&str]| Some(v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(lits("resp:\"abc\" status:200"), some(&["abc"]));
        assert_eq!(lits("resp:\"ABC\""), some(&["abc"]), "lower-cased");
        assert_eq!(lits("any:abc"), some(&["abc"]));
        assert_eq!(lits("req:\"abc\" resp:\"defgh\""), some(&["defgh"]), "longest of equals");
        assert_eq!(lits("resp:\"abc\" OR req:\"defg\""), some(&["abc", "defg"]));
        assert_eq!(lits("resp:\"abc\" OR status:200"), None);
        assert_eq!(lits("-resp:\"abc\""), None);
        assert_eq!(lits("resp:ab"), None);
        assert_eq!(lits("status:200"), None);
        assert_eq!(lits(""), None);
        assert_eq!(lits("respheader:abc reqheader:abc=def param:abc abc"), None);
        assert_eq!(lits("resp~\"abc\""), None, "regex");
        // Nested: AND inside OR needs every branch to give something.
        assert_eq!(lits("(resp:\"abc\" status:200) OR (req:\"defg\" host:x)"), some(&["abc", "defg"]));
        assert_eq!(lits("(resp:\"abc\" status:200) OR (host:x method:get)"), None);
        // OR inside AND: the OR's union, or another child that is smaller.
        assert_eq!(lits("(resp:\"abc\" OR req:\"defg\") status:200"), some(&["abc", "defg"]));
        assert_eq!(lits("(resp:\"abc\" OR req:\"defg\") resp:\"xyz\""), some(&["xyz"]));
        assert_eq!(lits("(resp:\"abc\" OR req:\"defg\") -resp:\"xyz\""), some(&["abc", "defg"]));
    }

    #[test]
    fn metadata_terms() {
        for yes in [
            "status:5xx",
            "status:>=400 method:post",
            "status:200,500",
            "status:400..599",
            "host:*.shop.test",
            "host:api",
            "url:\"https://api.shop.test/api/orders\"",
            "ext:js OR path:/orders/",
            "len:>1000 time:<1000",
            "id:42",
            "comment:idor highlight:red,blue",
            "source:proxy -source:fuzzer",
            "orders",
            "(method:GET OR method:POST) NOT status:2xx",
            "path~\"debug=\\d\"",
            "path~orders/\\d+",
            "is:annotated is:response -is:error -is:redirect",
        ] {
            assert!(check(yes), "{yes}");
        }
        for no in [
            "status:2xx",
            "host:*.other.test",
            "method:GET",
            "len:<100",
            "-status:500",
            "status:404 OR method:PUT",
            "is:error",
        ] {
            assert!(!check(no), "{no}");
        }
    }

    #[test]
    fn content_terms_and_laziness() {
        for yes in [
            "resp:\"stack trace\"",
            "resp~admin\\d+",
            "resp~(?i)STACK",
            "(resp~(?i)st(a)ck)",
            "req:qty=2",
            "any:foo.bar",
            "mime:html",
            "respheader:set-cookie",
            "respheader:content-type=html",
            "reqheader:host=shop",
            "param:debug param:qty",
            "is:inscope",
        ] {
            assert!(check(yes), "{yes}");
        }
        for no in ["resp~STACK", "mime:json", "param:missing", "respheader:location"] {
            assert!(!check(no), "{no}");
        }
        // Metadata runs first: a failing cheap term skips the bytes.
        let mut r = row();
        assert!(!Query::parse("resp:trace status:200").unwrap().matches(&meta(), &mut r));
        assert_eq!(r.fetched, 0);
        assert!(!Query::parse("status:200").unwrap().needs_content());
        assert!(Query::parse("status:200 OR resp:x").unwrap().needs_content());
    }

    #[test]
    fn errors_point_at_the_problem() {
        let e = Query::parse("status:500 stauts:200").unwrap_err();
        assert_eq!(e.at, 11);
        assert!(e.message.contains("unknown field"));
        assert!(Query::parse("status:abc").is_err());
        assert!(Query::parse("resp:\"open").is_err());
        assert!(Query::parse("resp~(").is_err());
        assert!(Query::parse("(status:200").is_err());
        assert!(Query::parse("status:200)").is_err());
        assert!(Query::parse("OR status:200").is_err());
        assert!(Query::parse("is:weird").is_err());
        assert!(Query::parse("status~5..").is_err());
        assert!(Query::parse("").unwrap().matches(&meta(), &mut row()), "empty matches all");
        assert!(!check("http://api.shop.test"), "URLs are bare words, not fields");
    }

    #[test]
    fn never_panics_on_junk() {
        let junk = [
            "((((",
            "-",
            "\"",
            "/",
            "status:",
            "a:b:c",
            "resp~",
            "x~y",
            "!!!x",
            "||",
            "&& x",
            "status:>",
            "x..y",
            "\u{0}\u{ff}",
        ];
        for j in junk {
            if let Ok(q) = Query::parse(j) {
                let _ = q.matches(&meta(), &mut row());
            }
        }
    }
}
