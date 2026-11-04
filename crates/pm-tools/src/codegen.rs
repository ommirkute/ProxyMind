//! "Copy as code": a recorded or edited request as a Python (requests),
//! JavaScript (fetch) or PowerShell snippet that sends the same request.
//! Redirects are not followed, so the snippet shows what the server said.

use pm_http::{find_head_end, parse_request_head};
use serde::Deserialize;

use crate::har::split_url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lang {
    Python,
    Javascript,
    Powershell,
}

struct Parts {
    method: String,
    url: String,
    /// Headers to send (framing and a matching Host left out), duplicates joined.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn parts(url: &str, raw: &[u8]) -> Result<Parts, String> {
    let end = find_head_end(raw).map_err(|e| e.to_string())?.ok_or("incomplete request head")?;
    let head = parse_request_head(&raw[..end]).map_err(|e| e.to_string())?;
    let mut body = raw[end..].to_vec();
    let chunked = pm_http::header(&head.headers, "transfer-encoding")
        .is_some_and(|v| String::from_utf8_lossy(v).to_ascii_lowercase().contains("chunked"));
    if chunked && let Some(d) = pm_http::decode_chunked(&body) {
        body = d;
    }
    let u = split_url(url)?;
    let target = pm_http::split_absolute_target(&head.target).map_or(head.target.as_str(), |(_, _, p)| p);
    let mut headers: Vec<(String, String)> = Vec::new();
    for h in &head.headers {
        let lower = h.name.to_ascii_lowercase();
        if matches!(lower.as_str(), "content-length" | "transfer-encoding" | "connection") {
            continue;
        }
        if lower == "host" && h.value.eq_ignore_ascii_case(u.authority().as_bytes()) {
            continue;
        }
        let value = String::from_utf8_lossy(&h.value).into_owned();
        match headers.iter_mut().find(|(k, _)| k.eq_ignore_ascii_case(&h.name)) {
            Some((_, v)) => {
                v.push_str(if lower == "cookie" { "; " } else { ", " });
                v.push_str(&value);
            }
            None => headers.push((h.name.clone(), value)),
        }
    }
    Ok(Parts { method: head.method.clone(), url: format!("{}://{}{}", u.scheme, u.authority(), target), headers, body })
}

/// A double-quoted string literal valid in Python and JavaScript.
fn q(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

/// A single-quoted PowerShell literal (no escapes inside; `'` is doubled).
fn ps(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A snippet in `lang` that sends `raw` to `url`'s origin.
pub fn to_code(lang: Lang, url: &str, raw: &[u8]) -> Result<String, String> {
    let p = parts(url, raw)?;
    let text = std::str::from_utf8(&p.body).ok();
    Ok(match lang {
        Lang::Python => python(&p, text),
        Lang::Javascript => javascript(&p, text),
        Lang::Powershell => powershell(&p, text),
    })
}

fn python(p: &Parts, text: Option<&str>) -> String {
    let mut s = String::from("import requests\n\n");
    s.push_str(&format!("url = {}\n", q(&p.url)));
    s.push_str("headers = {\n");
    for (k, v) in &p.headers {
        s.push_str(&format!("    {}: {},\n", q(k), q(v)));
    }
    s.push_str("}\n");
    let data = if p.body.is_empty() {
        ""
    } else {
        match text {
            Some(t) => s.push_str(&format!("data = {}\n", q(t))),
            None => s.push_str(&format!("data = bytes.fromhex({})\n", q(&hex(&p.body)))),
        }
        ", data=data"
    };
    s.push_str(&format!(
        "\nresponse = requests.request({}, url, headers=headers{data}, allow_redirects=False)\n",
        q(&p.method)
    ));
    s.push_str("print(response.status_code)\nprint(response.text)\n");
    s
}

fn javascript(p: &Parts, text: Option<&str>) -> String {
    let mut s = format!("const response = await fetch({}, {{\n  method: {},\n  headers: {{\n", q(&p.url), q(&p.method));
    for (k, v) in &p.headers {
        s.push_str(&format!("    {}: {},\n", q(k), q(v)));
    }
    s.push_str("  },\n");
    if !p.body.is_empty() {
        match text {
            Some(t) => s.push_str(&format!("  body: {},\n", q(t))),
            None => s.push_str(&format!(
                "  body: Uint8Array.from({}.match(/../g), (h) => parseInt(h, 16)),\n",
                q(&hex(&p.body))
            )),
        }
    }
    s.push_str("  redirect: \"manual\",\n});\nconsole.log(response.status, await response.text());\n");
    s
}

fn powershell(p: &Parts, text: Option<&str>) -> String {
    let mut s = String::from("$headers = @{\n");
    let mut content_type = None;
    let mut user_agent = None;
    for (k, v) in &p.headers {
        match k.to_ascii_lowercase().as_str() {
            "content-type" => content_type = Some(v),
            "user-agent" => user_agent = Some(v),
            _ => s.push_str(&format!("    {} = {}\n", ps(k), ps(v))),
        }
    }
    s.push_str("}\n");
    let mut args = format!("-Uri {} -Method {} -Headers $headers", ps(&p.url), ps(&p.method));
    if let Some(ct) = content_type {
        args.push_str(&format!(" -ContentType {}", ps(ct)));
    }
    if let Some(ua) = user_agent {
        args.push_str(&format!(" -UserAgent {}", ps(ua)));
    }
    if !p.body.is_empty() {
        match text {
            Some(t) => s.push_str(&format!("$body = {}\n", ps(t))),
            None => s.push_str(&format!("$body = [Convert]::FromHexString({})\n", ps(&hex(&p.body)))),
        }
        args.push_str(" -Body $body");
    }
    s.push_str(&format!(
        "$response = Invoke-WebRequest {args} -MaximumRedirection 0 -SkipHttpErrorCheck -ErrorAction SilentlyContinue\n"
    ));
    s.push_str("$response.StatusCode\n$response.Content\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &[u8] = b"POST /api/login?next=%2F HTTP/1.1\r\nHost: shop.test\r\nUser-Agent: UA \"x\"\r\n\
        Content-Type: application/json\r\nCookie: a=1\r\nCookie: b=2\r\nContent-Length: 17\r\n\r\n{\"user\":\"o'neil\"}";

    #[test]
    fn python_snippet() {
        let s = to_code(Lang::Python, "https://shop.test", RAW).unwrap();
        assert!(s.contains("url = \"https://shop.test/api/login?next=%2F\"\n"), "{s}");
        assert!(s.contains("    \"User-Agent\": \"UA \\\"x\\\"\",\n"));
        assert!(s.contains("    \"Cookie\": \"a=1; b=2\",\n"));
        assert!(!s.contains("Content-Length") && !s.contains("\"Host\""));
        assert!(s.contains("data = \"{\\\"user\\\":\\\"o'neil\\\"}\"\n"));
        assert!(s.contains("requests.request(\"POST\", url, headers=headers, data=data, allow_redirects=False)"));
    }

    #[test]
    fn javascript_and_powershell_snippets() {
        let js = to_code(Lang::Javascript, "https://shop.test", RAW).unwrap();
        assert!(js.starts_with(
            "const response = await fetch(\"https://shop.test/api/login?next=%2F\", {\n  method: \"POST\","
        ));
        assert!(js.contains("  body: \"{\\\"user\\\":\\\"o'neil\\\"}\",\n") && js.contains("redirect: \"manual\""));
        let p = to_code(Lang::Powershell, "https://shop.test", RAW).unwrap();
        assert!(p.contains("$body = '{\"user\":\"o''neil\"}'\n"), "{p}");
        assert!(p.contains("-ContentType 'application/json' -UserAgent 'UA \"x\"' -Body $body"));
        assert!(p.contains("    'Cookie' = 'a=1; b=2'\n"));
    }

    #[test]
    fn binary_bodies_and_get() {
        let raw = b"PUT /f HTTP/1.1\r\nHost: other.test\r\nContent-Length: 3\r\n\r\n\x00\xff\x10";
        let s = to_code(Lang::Python, "http://x.test:8080", raw).unwrap();
        assert!(s.contains("data = bytes.fromhex(\"00ff10\")") && s.contains("\"Host\": \"other.test\""), "{s}");
        let get = to_code(Lang::Python, "http://x.test", b"GET / HTTP/1.1\r\nHost: x.test\r\n\r\n").unwrap();
        assert!(get.contains("headers=headers, allow_redirects=False") && !get.contains("data"));
    }
}
