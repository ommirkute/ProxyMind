//! Automatic proving for template injection, NoSQL operator injection, XXE,
//! CORS and Host-header injection, against a small local app with a
//! vulnerable and a fixed version of each bug and look-alike traps. The app is
//! written for this test; the proofs must not depend on it (they are generic).

use std::collections::HashMap;
use std::sync::Arc;

use pm_service::pm_policy::{Actor, Policy, Roe};
use pm_service::pm_store::Store;
use pm_service::{NewFinding, ReplayRequest, ReplayResult, Service, run_regression};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn human() -> Actor {
    Actor::parse("human:omkar").unwrap()
}

struct Req {
    path: String,
    query: Vec<(String, String)>,
    headers: HashMap<String, String>,
    body: String,
}

fn decode(s: &str) -> String {
    let b = s.replace('+', " ");
    let b = b.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) = u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn read_request(c: &mut tokio::net::TcpStream) -> Option<Req> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = c.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let target = lines.next()?.split(' ').nth(1)?.to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    while buf.len() < head_end + len {
        let n = c.read(&mut chunk).await.ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&buf[head_end..]).into_owned();
    let (path, q) = target.split_once('?').unwrap_or((&target, ""));
    let query = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(k), decode(v))
        })
        .collect();
    Some(Req { path: path.to_string(), query, headers, body })
}

/// `{{A*B}}` evaluated, as a template engine would.
fn render_braces(s: &str) -> String {
    let mut out = s.to_string();
    while let Some(start) = out.find("{{") {
        let Some(len) = out[start..].find("}}") else { break };
        let inner = &out[start + 2..start + len];
        let value = match inner.split_once('*') {
            Some((a, b)) => match (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
                (Ok(a), Ok(b)) => (a * b).to_string(),
                _ => String::new(),
            },
            None => String::new(),
        };
        out.replace_range(start..start + len + 2, &value);
    }
    out
}

/// Any `A*B` in the text replaced by its product, delimiters or not: a page
/// that computes from whatever it is given (the trap for the control).
fn calculate_everything(s: &str) -> String {
    let digits = |x: &str| x.chars().all(|c| c.is_ascii_digit()) && !x.is_empty();
    s.split(|c: char| !(c.is_ascii_digit() || c == '*'))
        .filter_map(|t| t.split_once('*').filter(|(a, b)| digits(a) && digits(b)))
        .map(|(a, b)| (a.parse::<u64>().unwrap_or(0) * b.parse::<u64>().unwrap_or(0)).to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

const ITEMS: &[(&str, &str)] = &[
    ("apple", "A crisp red apple from the orchard on the hill, picked this morning and packed by hand."),
    ("banana", "A ripe yellow banana shipped from the coast, sweet and soft, sold by the bunch only."),
    ("cherry", "Dark cherries in a small basket, best eaten the same day; ask for the seasonal discount."),
    ("date", "Medjool dates, sticky and rich, imported in wooden crates and sold by weight at the counter."),
];

fn items_page(names: &[&str]) -> String {
    let rows: Vec<String> =
        ITEMS.iter().filter(|(n, _)| names.contains(n)).map(|(n, d)| format!("<li><b>{n}</b> {d}</li>")).collect();
    format!("<html><body><h1>Results ({})</h1><ul>{}</ul></body></html>", rows.len(), rows.join(""))
}

/// The NoSQL-backed search: operators in `q[...]` keys reach the query.
fn search(query: &[(String, String)], operators: bool) -> String {
    let all: Vec<&str> = ITEMS.iter().map(|(n, _)| *n).collect();
    let get = |k: &str| query.iter().filter(|(qk, _)| qk == k).map(|(_, v)| v.as_str()).collect::<Vec<_>>();
    if let Some(v) = get("q").first() {
        return items_page(&all.iter().copied().filter(|n| n == v).collect::<Vec<_>>());
    }
    if !operators {
        return items_page(&[]);
    }
    let pick = |f: &dyn Fn(&str) -> bool| all.iter().copied().filter(|n| f(n)).collect::<Vec<_>>();
    if let Some(v) = get("q[$eq]").first() {
        return items_page(&pick(&|n| n == *v));
    }
    if let Some(v) = get("q[$ne]").first() {
        return items_page(&pick(&|n| n != *v));
    }
    let ins = get("q[$in][]");
    if !ins.is_empty() {
        return items_page(&pick(&|n| ins.contains(&n)));
    }
    let nins = get("q[$nin][]");
    if !nins.is_empty() {
        return items_page(&pick(&|n| !nins.contains(&n)));
    }
    items_page(&[])
}

/// An XML endpoint whose parser expands external entities (when `expand`)
/// and echoes the item back.
fn xml_order(body: &str, expand: bool) -> String {
    let item = body.split("<item>").nth(1).and_then(|r| r.split("</item>").next()).unwrap_or_default().to_string();
    let entity = body.split("<!ENTITY pmx SYSTEM \"").nth(1).and_then(|r| r.split('"').next());
    let text = match (expand, entity) {
        (true, Some(uri)) if item.contains("&pmx;") => match uri {
            "file:///etc/passwd" => item.replace("&pmx;", "root:x:0:0:root:/root:/bin/bash"),
            _ => item.replace("&pmx;", ""),
        },
        _ => item.replace('&', "&amp;"),
    };
    format!("<result><ordered>{text}</ordered><status>queued for the kitchen</status></result>")
}

/// The app. `fixed`: every bug patched.
async fn app(fixed: bool) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    // Guestbook entries, shared by every connection.
    let board: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let board = board.clone();
            tokio::spawn(async move {
                let Some(r) = read_request(&mut c).await else { return };
                let q = |k: &str| r.query.iter().find(|(qk, _)| qk == k).map(|(_, v)| v.clone()).unwrap_or_default();
                let mut extra = String::new();
                let mut ctype = "text/html";
                let body = match r.path.as_str() {
                    "/tpl" if !fixed => format!("<p>Hello {}</p>", render_braces(&q("name"))),
                    "/tpl" => format!("<p>Hello {}</p>", q("name").replace('<', "&lt;")),
                    "/calc" => format!("<p>Results: {}</p>", calculate_everything(&q("name"))),
                    "/items" => search(&r.query, !fixed),
                    "/items-safe" => search(&r.query, false),
                    "/order" => xml_order(&r.body, !fixed),
                    "/api/me" | "/api/public" => {
                        let origin = r.headers.get("origin").cloned();
                        match (fixed, origin) {
                            (false, Some(o)) => {
                                extra = format!("Access-Control-Allow-Origin: {o}\r\n");
                                if r.path == "/api/me" {
                                    extra.push_str("Access-Control-Allow-Credentials: true\r\n");
                                }
                            }
                            _ => extra = "Access-Control-Allow-Origin: https://shop.example\r\n".into(),
                        }
                        "{\"user\":\"alice\",\"email\":\"alice@shop.example\"}".into()
                    }
                    "/reset" => {
                        let host = match (fixed, r.headers.get("x-forwarded-host")) {
                            (false, Some(h)) => h.clone(),
                            _ => "shop.example".into(),
                        };
                        format!("<p>We sent a link: <a href=\"https://{host}/reset?t=91c2\">reset</a></p>")
                    }
                    // Stored XSS: entries are shown on /board, unencoded unless fixed.
                    "/sign" => {
                        let msg = r.body.split('&').find_map(|p| p.strip_prefix("message=")).map(decode);
                        board.lock().unwrap().push(msg.unwrap_or_default());
                        "<p>Thanks for signing.</p>".into()
                    }
                    "/board" => {
                        let rows: Vec<String> = board
                            .lock()
                            .unwrap()
                            .iter()
                            .map(|m| if fixed { m.replace('&', "&amp;").replace('<', "&lt;") } else { m.clone() })
                            .map(|m| format!("<li>{m}</li>"))
                            .collect();
                        format!("<!doctype html><html><body><ul>{}</ul></body></html>", rows.join(""))
                    }
                    // DOM XSS: a same-origin script writes the URL's name into the page.
                    "/hi" => {
                        "<!doctype html><html><body><p id=msg></p><script src=/hi.js></script></body></html>".into()
                    }
                    "/hi.js" => {
                        ctype = "application/javascript";
                        let sink = if fixed { "textContent" } else { "innerHTML" };
                        format!(
                            "const n = new URLSearchParams(location.search).get('name') || 'guest';\n\
                             document.getElementById('msg').{sink} = 'Hi ' + n;"
                        )
                    }
                    "/share" => {
                        let host = if fixed {
                            "shop.example".to_string()
                        } else {
                            r.headers.get("host").cloned().unwrap_or_default()
                        };
                        format!("<p>Share this: <a href=\"http://{host}/p/1\">link</a></p>")
                    }
                    // Echoes the request headers back (a debug page): not Host injection.
                    "/echo" => {
                        let mut h: Vec<String> = r.headers.iter().map(|(k, v)| format!("{k}: {v}")).collect();
                        h.sort();
                        format!("<pre>{}</pre>", h.join("\n"))
                    }
                    _ => "not found".into(),
                };
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = c.write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}")
}

async fn setup() -> (Arc<Service>, String) {
    let url = app(false).await;
    let roe = format!(
        "version: 1\nscope:\n  include: [\"{url}/\"]\ntiers:\n  human:\n    active_intrusive: allow\n    destructive: allow\n"
    );
    let s = Arc::new(Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap());
    (s, url)
}

async fn record(s: &Service, url: &str, raw: String) -> i64 {
    let req = ReplayRequest { url: Some(url.into()), raw: Some(raw), ..Default::default() };
    match s.replay_send(&human(), req).await.unwrap() {
        ReplayResult::Sent { exchange_id, .. } => exchange_id,
        other => panic!("{other:?}"),
    }
}

async fn get(s: &Service, url: &str, path: &str) -> i64 {
    record(s, url, format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")).await
}

async fn suspect(s: &Service, class: &str, title: &str, evidence: i64) -> i64 {
    let f = NewFinding {
        title: title.into(),
        vuln_class: class.into(),
        severity: "high".into(),
        description: "suspected by the sweep".into(),
        url: None,
        evidence: vec![evidence],
        hypothesis_id: None,
    };
    s.finding_create(&human(), f).unwrap()["id"].as_i64().unwrap()
}

async fn prove(s: &Service, class: &str, title: &str, evidence: i64) -> pm_service::FindingProve {
    let id = suspect(s, class, title, evidence).await;
    s.finding_prove(&human(), id).await.unwrap()
}

#[tokio::test]
async fn template_injection_is_proven_by_evaluated_arithmetic_and_not_by_echo_or_a_calculator() {
    let (s, url) = setup().await;
    let tpl = get(&s, &url, "/tpl?name=guest").await;
    let r = prove(&s, "ssti", "Template injection in GET /tpl (query name)", tpl).await;
    assert!(r.proven, "{:?}", r.reasons);
    assert_eq!(r.oracle.as_deref(), Some("expression"));

    // Computes `A*B` from any input: the bare-numbers control catches it.
    let calc = get(&s, &url, "/calc?name=guest").await;
    let r = prove(&s, "ssti", "Template injection in GET /calc (query name)", calc).await;
    assert!(!r.proven, "a calculator is not template injection: {:?}", r.reasons);

    // The fixed app echoes the expression without evaluating it.
    let fixed = app(true).await;
    let t = s.regression_tests().unwrap().tests.into_iter().find(|t| t.oracle == "expression").expect("a test");
    assert_eq!(run_regression(&t, None, true, &|_| None).await.outcome, "vulnerable");
    assert_eq!(run_regression(&t, Some(&fixed), true, &|_| None).await.outcome, "fixed");
}

#[tokio::test]
async fn nosql_operator_injection_is_proven_by_a_true_false_split() {
    let (s, url) = setup().await;
    let items = get(&s, &url, "/items?q=apple").await;
    let r = prove(&s, "nosqli", "NoSQL injection in GET /items (query q)", items).await;
    assert!(r.proven, "{:?}", r.reasons);
    assert_eq!(r.oracle.as_deref(), Some("boolean_injection"));

    let safe = get(&s, &url, "/items-safe?q=apple").await;
    let r = prove(&s, "nosqli", "NoSQL injection in GET /items-safe (query q)", safe).await;
    assert!(!r.proven, "operators never reach the query: {:?}", r.reasons);
}

#[tokio::test]
async fn xxe_is_proven_by_reading_a_known_file_through_an_entity() {
    let (s, url) = setup().await;
    let body = "<?xml version=\"1.0\"?>\n<order><item>Coffee</item><qty>2</qty></order>";
    let raw = format!(
        "POST /order HTTP/1.1\r\nHost: x\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let order = record(&s, &url, raw).await;
    let r = prove(&s, "xxe", "XXE in POST /order (body)", order).await;
    assert!(r.proven, "{:?}", r.reasons);
    assert_eq!(r.oracle.as_deref(), Some("path_traversal"));

    // Against the fixed parser the exported test says fixed.
    let fixed = app(true).await;
    let t = s.regression_tests().unwrap().tests.into_iter().find(|t| t.finding.vuln_class == "xxe").expect("a test");
    assert_eq!(run_regression(&t, None, true, &|_| None).await.outcome, "vulnerable");
    assert_eq!(run_regression(&t, Some(&fixed), true, &|_| None).await.outcome, "fixed");
}

#[tokio::test]
async fn cors_is_proven_only_when_any_origin_is_trusted_with_credentials() {
    let (s, url) = setup().await;
    let me = get(&s, &url, "/api/me").await;
    let r = prove(&s, "cors", "CORS misconfiguration in GET /api/me", me).await;
    assert!(r.proven, "{:?}", r.reasons);
    assert_eq!(r.oracle.as_deref(), Some("marker"));

    // Reflects the origin but sends no credentials: not readable cross-site with a session.
    let public = get(&s, &url, "/api/public").await;
    let r = prove(&s, "cors", "CORS misconfiguration in GET /api/public", public).await;
    assert!(!r.proven, "{:?}", r.reasons);

    let fixed = app(true).await;
    let t = s.regression_tests().unwrap().tests.into_iter().find(|t| t.finding.vuln_class == "cors").expect("a test");
    assert_eq!(t.marker_kind.as_deref(), Some("cors"));
    assert_eq!(run_regression(&t, None, true, &|_| None).await.outcome, "vulnerable");
    assert_eq!(run_regression(&t, Some(&fixed), true, &|_| None).await.outcome, "fixed");
}

#[tokio::test]
async fn host_header_injection_needs_the_marker_in_a_link_not_an_echo() {
    let (s, url) = setup().await;
    let reset = get(&s, &url, "/reset").await;
    let r = prove(&s, "host_header_injection", "Host header injection in GET /reset", reset).await;
    assert!(r.proven, "{:?}", r.reasons);

    // Links built from the Host header itself.
    let share = get(&s, &url, "/share").await;
    let r = prove(&s, "host_header_injection", "Host header injection in GET /share", share).await;
    assert!(r.proven, "{:?}", r.reasons);

    // A page that prints the request headers shows the marker, but not as a host.
    let echo = get(&s, &url, "/echo").await;
    let r = prove(&s, "host_header_injection", "Host header injection in GET /echo", echo).await;
    assert!(!r.proven, "an echo of the headers is not Host injection: {:?}", r.reasons);
}

/// The false-proof guard (roadmap Phase 0.3): every class the automatic step
/// proves, tried on every endpoint of the fixed app, proves nothing.
#[tokio::test]
async fn no_class_is_proven_anywhere_on_the_fixed_app() {
    let fixed = app(true).await;
    let roe = format!(
        "version: 1\nscope:\n  include: [\"{fixed}/\"]\ntiers:\n  human:\n    active_intrusive: allow\n    destructive: allow\n"
    );
    let s = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let xml = "<?xml version=\"1.0\"?>\n<order><item>Coffee</item><qty>2</qty></order>";
    let mut evidence = Vec::new();
    for path in [
        "/tpl?name=guest",
        "/calc?name=guest",
        "/items?q=apple",
        "/api/me",
        "/api/public",
        "/reset",
        "/share",
        "/echo",
        "/hi?name=guest",
    ] {
        evidence.push((path.to_string(), get(&s, &fixed, path).await));
    }
    let raw = format!(
        "POST /order HTTP/1.1\r\nHost: x\r\nContent-Type: application/xml\r\nContent-Length: {}\r\n\r\n{xml}",
        xml.len()
    );
    evidence.push(("POST /order".into(), record(&s, &fixed, raw).await));
    let classes = [
        "xss",
        "dom_xss",
        "sqli",
        "command_injection",
        "path_traversal",
        "open_redirect",
        "crlf",
        "ssrf",
        "ssti",
        "nosqli",
        "xxe",
        "cors",
        "host_header_injection",
        "idor",
    ];
    let mut proven = Vec::new();
    for (path, ex) in &evidence {
        for class in classes {
            let r = prove(&s, class, &format!("{class} suspected in {path}"), *ex).await;
            if r.proven {
                proven.push(format!("{class} on {path}: {:?}", r.reasons));
            }
        }
    }
    assert!(proven.is_empty(), "false proofs on the fixed app:\n{}", proven.join("\n"));
}

fn chromium() -> bool {
    let found = pm_service::pm_browser::find_chromium().is_some();
    if !found {
        eprintln!("no Chromium found; set PROXYMIND_CHROMIUM to run this test");
    }
    found
}

/// A suspected stored XSS: the submission, then the page that shows it (the scanner's evidence order).
async fn stored_finding(s: &Service, url: &str) -> i64 {
    let body = "name=alice&message=hello";
    let raw = format!(
        "POST /sign HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let sign = record(s, url, raw).await;
    let board = get(s, url, "/board").await;
    let f = NewFinding {
        title: "Stored input shown unencoded on another page (stored XSS) in POST /sign (form message)".into(),
        vuln_class: "stored_xss".into(),
        severity: "high".into(),
        description: "suspected by the scanner".into(),
        url: None,
        evidence: vec![sign, board],
        hypothesis_id: None,
    };
    s.finding_create(&human(), f).unwrap()["id"].as_i64().unwrap()
}

#[tokio::test]
async fn stored_xss_is_proven_when_the_stored_script_runs_on_the_page_that_shows_it() {
    if !chromium() {
        return;
    }
    let (s, url) = setup().await;
    let id = stored_finding(&s, &url).await;
    let r = s.finding_prove(&human(), id).await.unwrap();
    assert!(r.proven, "{:?}", r.reasons);
    assert_eq!(r.oracle.as_deref(), Some("reflection"));

    // The fixed app encodes what it shows: stored, shown, but never run.
    let fixed = app(true).await;
    let roe = format!(
        "version: 1\nscope:\n  include: [\"{fixed}/\"]\ntiers:\n  human:\n    active_intrusive: allow\n    destructive: allow\n"
    );
    let s2 = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let id = stored_finding(&s2, &fixed).await;
    let r = s2.finding_prove(&human(), id).await.unwrap();
    assert!(!r.proven, "{:?}", r.reasons);
}

#[tokio::test]
async fn dom_xss_is_proven_when_the_page_script_runs_the_url_value() {
    if !chromium() {
        return;
    }
    let (s, url) = setup().await;
    let hi = get(&s, &url, "/hi?name=guest").await;
    let r = prove(&s, "dom_xss", "DOM-based XSS in GET /hi (query name)", hi).await;
    assert!(r.proven, "{:?}", r.reasons);
    assert_eq!(r.oracle.as_deref(), Some("reflection"));

    // The fixed page writes the value as text.
    let fixed = app(true).await;
    let roe = format!(
        "version: 1\nscope:\n  include: [\"{fixed}/\"]\ntiers:\n  human:\n    active_intrusive: allow\n    destructive: allow\n"
    );
    let s2 = Service::new(Store::open_in_memory().unwrap(), Policy::new(Roe::parse(&roe).unwrap())).unwrap();
    let hi = get(&s2, &fixed, "/hi?name=guest").await;
    let r = prove(&s2, "dom_xss", "DOM-based XSS in GET /hi (query name)", hi).await;
    assert!(!r.proven, "{:?}", r.reasons);
}
