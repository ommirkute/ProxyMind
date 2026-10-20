//! "Copy as cURL" and reading a cURL command back into a request.
//!
//! [`to_curl`] writes a POSIX shell command that sends the same request.
//! [`parse_curl`] understands what browsers' "Copy as cURL (bash)" and
//! hand-written commands use (quotes, `$'…'`, line continuations, headers,
//! data flags, cookies, basic auth, `-G`, `--json`); options that only change
//! how curl runs are ignored, anything else is reported. Nothing is run.

use pm_http::{find_head_end, parse_request_head};

use crate::har::{UrlParts, build_request, percent_encode, split_url};

/// Quotes one shell word: `'…'` when possible, `$'…'` for control or non-UTF-8 bytes.
pub fn shell_quote(bytes: &[u8]) -> String {
    let plain = std::str::from_utf8(bytes).ok().filter(|s| !s.chars().any(|c| c.is_control()));
    if let Some(s) = plain {
        return format!("'{}'", s.replace('\'', r"'\''"));
    }
    let mut out = String::from("$'");
    let text = String::from_utf8_lossy(bytes);
    let lossless = std::str::from_utf8(bytes).is_ok();
    if lossless {
        for c in text.chars() {
            match c {
                '\\' => out.push_str(r"\\"),
                '\'' => out.push_str(r"\'"),
                '\n' => out.push_str(r"\n"),
                '\r' => out.push_str(r"\r"),
                '\t' => out.push_str(r"\t"),
                c if c.is_control() && (c as u32) < 0x100 => out.push_str(&format!("\\x{:02x}", c as u32)),
                c => out.push(c),
            }
        }
    } else {
        for &b in bytes {
            match b {
                b'\\' => out.push_str(r"\\"),
                b'\'' => out.push_str(r"\'"),
                0x20..=0x7e => out.push(b as char),
                _ => out.push_str(&format!("\\x{b:02x}")),
            }
        }
    }
    out.push('\'');
    out
}

/// A curl command for a raw request sent to `url`'s origin.
pub fn to_curl(url: &str, raw: &[u8]) -> Result<String, String> {
    let end = find_head_end(raw).map_err(|e| e.to_string())?.ok_or("incomplete request head")?;
    let head = parse_request_head(&raw[..end]).map_err(|e| e.to_string())?;
    let mut body = raw[end..].to_vec();
    let chunked = pm_http::header(&head.headers, "transfer-encoding")
        .is_some_and(|v| String::from_utf8_lossy(v).to_ascii_lowercase().contains("chunked"));
    if chunked && let Some(d) = pm_http::decode_chunked(&body) {
        body = d;
    }
    let parts = split_url(url)?;
    let mut cmd = String::from("curl");
    if head.target.contains("/.") || head.target.contains("%2e") || head.target.contains("%2E") {
        cmd.push_str(" --path-as-is");
    }
    if head.version.eq_ignore_ascii_case("HTTP/2") || head.version == "HTTP/2.0" {
        cmd.push_str(" --http2");
    }
    let default_method = if body.is_empty() { "GET" } else { "POST" };
    if head.method != default_method {
        cmd.push_str(&format!(" -X {}", shell_quote(head.method.as_bytes())));
    }
    let full = format!("{}://{}{}", parts.scheme, parts.authority(), head.target);
    cmd.push_str(&format!(" {}", shell_quote(full.as_bytes())));
    for h in &head.headers {
        let lower = h.name.to_ascii_lowercase();
        if matches!(lower.as_str(), "content-length" | "transfer-encoding" | "connection") {
            continue;
        }
        if lower == "host" && h.value.eq_ignore_ascii_case(parts.authority().as_bytes()) {
            continue;
        }
        let mut line = format!("{}: ", h.name).into_bytes();
        if h.value.is_empty() {
            // `-H 'X:'` would remove the header; `X;` sends it empty.
            line = format!("{};", h.name).into_bytes();
        } else {
            line.extend_from_slice(&h.value);
        }
        cmd.push_str(&format!(" \\\n  -H {}", shell_quote(&line)));
    }
    if !body.is_empty() {
        cmd.push_str(&format!(" \\\n  --data-binary {}", shell_quote(&body)));
    }
    Ok(cmd)
}

/// A request read from a curl command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurlRequest {
    pub url: UrlParts,
    pub method: String,
    pub raw: Vec<u8>,
    /// Options that were ignored or not understood.
    pub warnings: Vec<String>,
}

/// Splits a command line the way a POSIX shell would (quotes, escapes,
/// `$'…'`, backslash-newline). No expansion of variables or globs.
pub fn shell_words(cmd: &str) -> Result<Vec<Vec<u8>>, String> {
    let b = cmd.as_bytes();
    let mut words = Vec::new();
    let mut cur: Vec<u8> = Vec::new();
    let mut in_word = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => {
                if in_word {
                    words.push(std::mem::take(&mut cur));
                    in_word = false;
                }
                i += 1;
            }
            b'\\' => match b.get(i + 1) {
                // A backslash-newline joins lines and is not part of any word.
                Some(b'\n') => i += 2,
                Some(b'\r') if b.get(i + 2) == Some(&b'\n') => i += 3,
                Some(&n) => {
                    in_word = true;
                    cur.push(n);
                    i += 2;
                }
                None => i += 1,
            },
            b'\'' => {
                in_word = true;
                let close = b[i + 1..].iter().position(|&x| x == b'\'').ok_or("unclosed single quote")?;
                cur.extend_from_slice(&b[i + 1..i + 1 + close]);
                i += close + 2;
            }
            b'"' => {
                in_word = true;
                i += 1;
                loop {
                    match b.get(i) {
                        None => return Err("unclosed double quote".into()),
                        Some(b'"') => {
                            i += 1;
                            break;
                        }
                        Some(b'\\') if matches!(b.get(i + 1), Some(b'"' | b'\\' | b'$' | b'`')) => {
                            cur.push(b[i + 1]);
                            i += 2;
                        }
                        Some(b'\\') if b.get(i + 1) == Some(&b'\n') => i += 2,
                        Some(&x) => {
                            cur.push(x);
                            i += 1;
                        }
                    }
                }
            }
            b'$' if b.get(i + 1) == Some(&b'\'') => {
                in_word = true;
                i += 2;
                loop {
                    match b.get(i) {
                        None => return Err("unclosed $'…' quote".into()),
                        Some(b'\'') => {
                            i += 1;
                            break;
                        }
                        Some(b'\\') => {
                            let (bytes, used) = ansi_c_escape(&b[i + 1..]);
                            cur.extend_from_slice(&bytes);
                            i += 1 + used;
                        }
                        Some(&x) => {
                            cur.push(x);
                            i += 1;
                        }
                    }
                }
            }
            _ => {
                in_word = true;
                cur.push(c);
                i += 1;
            }
        }
    }
    if in_word {
        words.push(cur);
    }
    Ok(words)
}

/// One `\` escape inside `$'…'`: the bytes it stands for and how many input bytes it used.
fn ansi_c_escape(s: &[u8]) -> (Vec<u8>, usize) {
    let hex = |s: &[u8], max: usize| -> (u32, usize) {
        let n = s.iter().take(max).take_while(|c| c.is_ascii_hexdigit()).count();
        (u32::from_str_radix(std::str::from_utf8(&s[..n]).unwrap_or("0"), 16).unwrap_or(0), n)
    };
    match s.first() {
        None => (b"\\".to_vec(), 0),
        Some(b'n') => (b"\n".to_vec(), 1),
        Some(b'r') => (b"\r".to_vec(), 1),
        Some(b't') => (b"\t".to_vec(), 1),
        Some(b'a') => (vec![7], 1),
        Some(b'b') => (vec![8], 1),
        Some(b'e' | b'E') => (vec![0x1b], 1),
        Some(b'f') => (vec![0x0c], 1),
        Some(b'v') => (vec![0x0b], 1),
        Some(b'x') => {
            let (v, n) = hex(&s[1..], 2);
            if n == 0 { (b"\\x".to_vec(), 1) } else { (vec![v as u8], 1 + n) }
        }
        Some(b'u' | b'U') => {
            let (v, n) = hex(&s[1..], if s[0] == b'u' { 4 } else { 8 });
            let c = char::from_u32(v).unwrap_or('\u{fffd}');
            if n == 0 { (s[..1].to_vec(), 1) } else { (c.to_string().into_bytes(), 1 + n) }
        }
        Some(b'0'..=b'7') => {
            let n = s.iter().take(3).take_while(|c| (b'0'..=b'7').contains(c)).count();
            let v = s[..n].iter().fold(0u32, |a, d| a * 8 + u32::from(d - b'0'));
            (vec![v as u8], n)
        }
        Some(&c) => (vec![c], 1),
    }
}

/// Options that take a value and only change how curl runs.
const IGNORED_WITH_VALUE: &[&str] = &[
    "-o",
    "--output",
    "-x",
    "--proxy",
    "--connect-timeout",
    "-m",
    "--max-time",
    "--retry",
    "-w",
    "--write-out",
    "--cacert",
    "--capath",
    "-E",
    "--cert",
    "--key",
    "--resolve",
    "--connect-to",
    "--max-redirs",
    "-c",
    "--cookie-jar",
    "-U",
    "--proxy-user",
    "--limit-rate",
    "-D",
    "--dump-header",
];

/// Options without a value that only change how curl runs.
const IGNORED_FLAGS: &[&str] = &[
    "-k",
    "--insecure",
    "-L",
    "--location",
    "-s",
    "--silent",
    "-S",
    "--show-error",
    "-v",
    "--verbose",
    "-i",
    "--include",
    "--http1.1",
    "--http2",
    "--http2-prior-knowledge",
    "-g",
    "--globoff",
    "--path-as-is",
    "-N",
    "--no-buffer",
    "-f",
    "--fail",
    "--fail-with-body",
    "-#",
    "--progress-bar",
    "-q",
];

/// Short options that take a value.
const SHORT_WITH_VALUE: &[u8] = b"XHdbuAeFoxmwcEUD";

fn takes_value(opt: &str) -> bool {
    matches!(
        opt,
        "-X" | "--request"
            | "-H"
            | "--header"
            | "-d"
            | "--data"
            | "--data-raw"
            | "--data-ascii"
            | "--data-binary"
            | "--data-urlencode"
            | "--json"
            | "-b"
            | "--cookie"
            | "-u"
            | "--user"
            | "-A"
            | "--user-agent"
            | "-e"
            | "--referer"
            | "--url"
            | "-F"
            | "--form"
    ) || IGNORED_WITH_VALUE.contains(&opt)
}

/// Reads a curl command into a request.
pub fn parse_curl(cmd: &str) -> Result<CurlRequest, String> {
    let words = shell_words(cmd.trim())?;
    let mut it = words.into_iter().map(|w| String::from_utf8_lossy(&w).into_owned()).peekable();
    match it.peek() {
        Some(w) if w == "curl" || w.ends_with("/curl") || w.eq_ignore_ascii_case("curl.exe") => {
            it.next();
        }
        Some(_) => {}
        None => return Err("empty command".into()),
    }
    // Expand bundled short options (-sSL, -XPOST) into (option, value) pairs.
    let mut opts: Vec<(String, Option<String>)> = Vec::new();
    let mut positional = Vec::new();
    while let Some(w) = it.next() {
        if w == "--" {
            positional.extend(it.by_ref());
            break;
        }
        if let Some(long) = w.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) if takes_value(&format!("--{n}")) => (format!("--{n}"), Some(v.to_string())),
                _ => (w.clone(), None),
            };
            let value = if takes_value(&name) { inline.or_else(|| it.next()) } else { None };
            opts.push((name, value));
        } else if w.len() > 1 && w.starts_with('-') {
            let chars: Vec<char> = w[1..].chars().collect();
            let mut k = 0;
            while k < chars.len() {
                let c = chars[k];
                let name = format!("-{c}");
                if c.is_ascii() && SHORT_WITH_VALUE.contains(&(c as u8)) {
                    let rest: String = chars[k + 1..].iter().collect();
                    let value = if rest.is_empty() { it.next() } else { Some(rest) };
                    opts.push((name, value));
                    break;
                }
                opts.push((name, None));
                k += 1;
            }
        } else {
            positional.push(w);
        }
    }

    let mut warnings = Vec::new();
    let mut method: Option<String> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut removed: Vec<String> = Vec::new();
    let mut data: Vec<String> = Vec::new();
    let mut get = false;
    let mut head_only = false;
    let mut url: Option<String> = None;
    let mut json_body = false;
    for (opt, value) in opts {
        let need = |v: Option<String>| v.ok_or_else(|| format!("{opt} needs a value"));
        match opt.as_str() {
            "-X" | "--request" => method = Some(need(value)?.to_ascii_uppercase()),
            "-H" | "--header" => {
                let v = need(value)?;
                if v.starts_with('@') {
                    warnings.push(format!("ignored header file {v}"));
                } else if let Some(name) = v.strip_suffix(';').filter(|n| !n.contains(':')) {
                    headers.push((name.trim().to_string(), String::new()));
                } else if let Some((name, _)) = v.split_once(':')
                    && !crate::har::is_token(name.trim())
                {
                    warnings.push(format!("ignored header with a bad name {name:?}"));
                } else if let Some((name, val)) = v.split_once(':') {
                    let (name, val) = (name.trim(), val.trim());
                    if val.is_empty() {
                        removed.push(name.to_ascii_lowercase());
                    } else {
                        headers.push((name.to_string(), val.to_string()));
                    }
                } else {
                    warnings.push(format!("ignored malformed header {v:?}"));
                }
            }
            "-d" | "--data" | "--data-ascii" | "--data-binary" => {
                let v = need(value)?;
                if v.starts_with('@') {
                    warnings.push(format!("can't read file {v}: paste the data with --data-raw"));
                } else if opt == "--data-binary" {
                    data.push(v);
                } else {
                    data.push(v.replace(['\r', '\n'], ""));
                }
            }
            "--data-raw" => data.push(need(value)?),
            "--json" => {
                data.push(need(value)?);
                json_body = true;
            }
            "--data-urlencode" => {
                let v = need(value)?;
                data.push(match v.split_once('=') {
                    Some((n, c)) if !n.is_empty() => format!("{n}={}", percent_encode(c)),
                    Some((_, c)) => percent_encode(c),
                    None => percent_encode(&v),
                });
            }
            "-b" | "--cookie" => {
                let v = need(value)?;
                if v.contains('=') {
                    headers.push(("Cookie".into(), v));
                } else {
                    warnings.push(format!("ignored cookie file {v}"));
                }
            }
            "-u" | "--user" => {
                let v = need(value)?;
                headers.push(("Authorization".into(), format!("Basic {}", pm_core::base64(v.as_bytes()))));
            }
            "-A" | "--user-agent" => headers.push(("User-Agent".into(), need(value)?)),
            "-e" | "--referer" => headers.push(("Referer".into(), need(value)?)),
            "--url" => url = Some(need(value)?),
            "-G" | "--get" => get = true,
            "-I" | "--head" => head_only = true,
            "--compressed" => {
                if !headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("accept-encoding")) {
                    headers.push(("Accept-Encoding".into(), "deflate, gzip".into()));
                }
            }
            "-F" | "--form" => warnings.push(format!("ignored multipart form field {:?}", value.unwrap_or_default())),
            o if IGNORED_FLAGS.contains(&o) || IGNORED_WITH_VALUE.contains(&o) => {}
            o => warnings.push(format!("ignored option {o}")),
        }
    }
    let url = url.or_else(|| positional.first().cloned()).ok_or("no URL in the command")?;
    if positional.len() > 1 {
        warnings.push(format!("used the first of {} URLs", positional.len()));
    }
    let mut parts = split_url(&url)?;
    let joined = if json_body { data.join("") } else { data.join("&") };
    let mut body = Vec::new();
    if get || head_only {
        if !joined.is_empty() {
            parts.target.push(if parts.target.contains('?') { '&' } else { '?' });
            parts.target.push_str(&joined);
        }
    } else {
        body = joined.into_bytes();
    }
    if let Some(m) = &method
        && !crate::har::is_token(m)
    {
        return Err(format!("bad method {m:?}"));
    }
    let method = method.unwrap_or_else(|| {
        if head_only {
            "HEAD".into()
        } else if body.is_empty() {
            "GET".into()
        } else {
            "POST".into()
        }
    });
    let has = |h: &[(String, String)], n: &str| h.iter().any(|(k, _)| k.eq_ignore_ascii_case(n));
    if !body.is_empty() && !has(&headers, "content-type") {
        let ct = if json_body { "application/json" } else { "application/x-www-form-urlencoded" };
        headers.push(("Content-Type".into(), ct.into()));
    }
    if json_body && !has(&headers, "accept") {
        headers.push(("Accept".into(), "application/json".into()));
    }
    if !has(&headers, "accept") {
        headers.insert(0, ("Accept".into(), "*/*".into()));
    }
    headers.retain(|(n, _)| !removed.contains(&n.to_ascii_lowercase()));
    let host_removed = removed.iter().any(|n| n == "host");
    let mut raw = build_request(&method, &parts, &headers, &body);
    if host_removed && let Some(i) = find_subslice(&raw, b"\r\nHost: ") {
        let end = find_subslice(&raw[i + 2..], b"\r\n").map_or(raw.len(), |e| i + 2 + e);
        raw.drain(i..end);
    }
    Ok(CurlRequest { url: parts, method, raw, warnings })
}

fn find_subslice(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(c: &CurlRequest) -> String {
        String::from_utf8_lossy(&c.raw).into_owned()
    }

    #[test]
    fn reads_browser_style_commands() {
        let cmd = r#"curl 'https://shop.test/api/cart?x=1' \
  -H 'accept: application/json' \
  -H 'cookie: sid=abc; theme=dark' \
  -H $'x-note: it\'s\ta test' \
  --data-raw '{"item":3}' \
  --compressed"#;
        let c = parse_curl(cmd).unwrap();
        assert_eq!(c.method, "POST");
        assert_eq!(
            raw(&c),
            "POST /api/cart?x=1 HTTP/1.1\r\nHost: shop.test\r\naccept: application/json\r\ncookie: sid=abc; theme=dark\r\n\
             x-note: it's\ta test\r\nAccept-Encoding: deflate, gzip\r\nContent-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 10\r\n\r\n{\"item\":3}"
        );
        assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    }

    #[test]
    fn handles_options() {
        let c =
            parse_curl("curl -sSL -XPUT -u admin:pw -A ua -e http://r/ http://a.test:8080/x -d 'a=1' -d b=2").unwrap();
        let r = raw(&c);
        assert!(r.starts_with("PUT /x HTTP/1.1\r\nHost: a.test:8080\r\nAccept: */*\r\n"), "{r}");
        assert!(r.contains("Authorization: Basic YWRtaW46cHc=\r\n"));
        assert!(r.contains("User-Agent: ua\r\nReferer: http://r/\r\n"));
        assert!(r.ends_with("Content-Length: 7\r\n\r\na=1&b=2"));

        let g = parse_curl("curl -G --data-urlencode 'q=a b&c' \"http://a.test/s\" -I").unwrap();
        assert_eq!(g.method, "HEAD");
        assert_eq!(g.url.target, "/s?q=a%20b%26c");

        let j = parse_curl(r#"curl --json '{"a":1}' a.test -H 'Host:' -H 'X-Empty;' -F f=@x --weird"#).unwrap();
        let r = raw(&j);
        assert!(!r.contains("Host:"), "{r}");
        assert!(r.contains("X-Empty: \r\n") && r.contains("Content-Type: application/json\r\n"));
        assert_eq!(j.warnings.len(), 2, "{:?}", j.warnings);

        // Line breaks in the URL, method or headers can't forge request lines (found by fuzzing).
        assert!(parse_curl("\"\u{fffd}\n2\"2").is_err());
        assert!(parse_curl("curl -X 'GET /x HTTP/1.1\r\n' a.test").is_err());
        let p = parse_curl("curl 'a.test/a b\r\nX: 1' -H $'Bad Name: 1' -H $'V: a\r\nInjected: 1'").unwrap();
        assert!(raw(&p).starts_with("GET /a%20b%0D%0AX:%201 HTTP/1.1\r\n"), "{}", raw(&p));
        assert!(raw(&p).contains("V: a  Injected: 1\r\n") && !raw(&p).contains("Bad Name"));
        assert!(parse_curl("curl -k").is_err());
        assert!(parse_curl("curl 'unclosed").is_err());
        assert!(parse_curl("curl ftp://a/").is_err());
    }

    #[test]
    fn writes_commands_that_read_back() {
        let req = b"PATCH /a/../b?q=1 HTTP/1.1\r\nHost: x.test:8443\r\nX-Q: it's\r\nX-E: \r\nContent-Length: 6\r\n\r\nl1\nl2\x01";
        let cmd = to_curl("https://x.test:8443/a/../b?q=1", req).unwrap();
        assert!(cmd.starts_with("curl --path-as-is -X 'PATCH' 'https://x.test:8443/a/../b?q=1'"), "{cmd}");
        assert!(cmd.contains(r"-H 'X-Q: it'\''s'") && cmd.contains("-H 'X-E;'"));
        assert!(cmd.contains(r"--data-binary $'l1\nl2\x01'"), "{cmd}");
        let back = parse_curl(&cmd).unwrap();
        assert_eq!(back.method, "PATCH");
        assert!(raw(&back).contains("X-Q: it's\r\nX-E: \r\n"), "{}", raw(&back));
        assert!(back.raw.ends_with(b"Content-Length: 6\r\n\r\nl1\nl2\x01"), "{}", raw(&back));

        let get = to_curl("http://x.test/", b"GET / HTTP/1.1\r\nHost: other.test\r\n\r\n").unwrap();
        assert_eq!(get, "curl 'http://x.test/' \\\n  -H 'Host: other.test'");
        assert_eq!(shell_quote(b"\xff'"), r"$'\xff\''");
    }

    #[test]
    fn splits_words() {
        let w = shell_words(r#"a 'b c' "d \"e\" \$f" $'\x41é\101' g\ h"#).unwrap();
        let w: Vec<String> = w.iter().map(|x| String::from_utf8_lossy(x).into_owned()).collect();
        assert_eq!(w, ["a", "b c", "d \"e\" $f", "AéA", "g h"]);
    }
}
