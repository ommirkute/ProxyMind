//! Crawler logic, without I/O: find links and forms in HTML, read
//! robots.txt and sitemaps, and keep the frontier (what to fetch next).
//!
//! The service layer fetches pages through the policy gate; this crate
//! only decides what to look at. HTML here is the target's and untrusted:
//! the scanner is a small tolerant tokenizer that never panics and never
//! executes anything.

pub mod discover;

use std::collections::{HashSet, VecDeque};

use serde::Serialize;
use url::Url;

/// A form found on a page. Forms are reported, never submitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Form {
    pub page: String,
    pub method: String,
    pub action: String,
    pub inputs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Extracted {
    pub links: Vec<Url>,
    pub forms: Vec<Form>,
}

/// Attributes that hold URLs.
const URL_ATTRS: &[&str] = &["href", "src", "action", "formaction", "data-url", "data-href"];

/// Links and forms in an HTML page. Relative URLs are resolved against
/// `base` (or a `<base href>`); fragments are dropped; `javascript:`,
/// `mailto:`, `data:` and similar are ignored.
pub fn extract(base: &Url, html: &str) -> Extracted {
    let mut base = base.clone();
    let mut out = Extracted::default();
    let mut seen = HashSet::new();
    let mut form: Option<Form> = None;
    for tag in tags(html) {
        match tag.name.as_str() {
            "base" => {
                if let Some(b) = tag.attr("href").and_then(|h| base.join(h).ok()) {
                    base = b;
                }
                continue;
            }
            "form" => {
                if let Some(f) = form.take() {
                    out.forms.push(f);
                }
                let action = tag.attr("action").and_then(|a| resolve(&base, a)).unwrap_or_else(|| strip(&base));
                form = Some(Form {
                    page: base.to_string(),
                    method: tag.attr("method").unwrap_or("get").to_ascii_uppercase(),
                    action: action.to_string(),
                    inputs: Vec::new(),
                });
            }
            "/form" => {
                if let Some(f) = form.take() {
                    out.forms.push(f);
                }
                continue;
            }
            "input" | "select" | "textarea" | "button" => {
                if let (Some(f), Some(n)) = (form.as_mut(), tag.attr("name"))
                    && !f.inputs.iter().any(|i| i == n)
                {
                    f.inputs.push(n.to_string());
                }
            }
            _ => {}
        }
        // A form's action is a page to look at too (GET forms only are
        // followed by the crawler, without parameters).
        for a in URL_ATTRS {
            let posts = tag.attr("method").is_some_and(|m| !m.eq_ignore_ascii_case("get"));
            if tag.name == "form" && *a == "action" && posts {
                continue;
            }
            if let Some(u) = tag.attr(a).and_then(|v| resolve(&base, v))
                && seen.insert(u.to_string())
            {
                out.links.push(u);
            }
        }
    }
    if let Some(f) = form.take() {
        out.forms.push(f);
    }
    out
}

fn strip(u: &Url) -> Url {
    let mut u = u.clone();
    u.set_fragment(None);
    u
}

fn resolve(base: &Url, v: &str) -> Option<Url> {
    let v = decode_entities(v.trim());
    if v.is_empty() || v.starts_with('#') {
        return None;
    }
    let lower = v.to_ascii_lowercase();
    if ["javascript:", "mailto:", "data:", "tel:", "blob:", "about:", "vbscript:"].iter().any(|p| lower.starts_with(p))
    {
        return None;
    }
    let u = base.join(&v).ok()?;
    matches!(u.scheme(), "http" | "https").then(|| strip(&u))
}

fn decode_entities(s: &str) -> String {
    s.replace("&amp;", "&").replace("&#38;", "&").replace("&quot;", "\"").replace("&#x2F;", "/").replace("&#47;", "/")
}

#[derive(Debug)]
struct Tag {
    name: String,
    attrs: Vec<(String, String)>,
}

impl Tag {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// Start and end tags with their attributes. Comments, `<script>` and
/// `<style>` contents are skipped.
fn tags(html: &str) -> Vec<Tag> {
    let b = html.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(off) = html[i..].find('<') {
        i += off + 1;
        if html[i..].starts_with("!--") {
            i = html[i..].find("-->").map_or(b.len(), |e| i + e + 3);
            continue;
        }
        let start = i;
        let closing = b.get(i) == Some(&b'/');
        if closing {
            i += 1;
        }
        let name_end =
            html[i..].find(|c: char| c.is_ascii_whitespace() || c == '>' || c == '/').map_or(b.len(), |e| i + e);
        let name = html[i..name_end].to_ascii_lowercase();
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            i = start;
            continue;
        }
        i = name_end;
        let mut attrs = Vec::new();
        // Attributes until '>'.
        loop {
            while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
                i += 1;
            }
            if i >= b.len() || b[i] == b'>' {
                i = (i + 1).min(b.len());
                break;
            }
            let k_end = html[i..]
                .find(|c: char| c.is_ascii_whitespace() || c == '=' || c == '>' || c == '/')
                .map_or(b.len(), |e| i + e);
            let key = html[i..k_end].to_ascii_lowercase();
            i = k_end.max(i + 1).min(b.len());
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            let mut value = String::new();
            if i < b.len() && b[i] == b'=' {
                i += 1;
                while i < b.len() && b[i].is_ascii_whitespace() {
                    i += 1;
                }
                if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                    let q = b[i] as char;
                    let v_end = html[i + 1..].find(q).map_or(b.len(), |e| i + 1 + e);
                    value = html[i + 1..v_end].to_string();
                    i = (v_end + 1).min(b.len());
                } else {
                    let v_end =
                        html[i..].find(|c: char| c.is_ascii_whitespace() || c == '>').map_or(b.len(), |e| i + e);
                    value = html[i..v_end].to_string();
                    i = v_end;
                }
            }
            if !key.is_empty() {
                attrs.push((key, value));
            }
        }
        let name = if closing { format!("/{name}") } else { name };
        // Skip raw text elements.
        if name == "script" || name == "style" {
            let close = format!("</{name}");
            i = html[i..].to_ascii_lowercase().find(&close).map_or(b.len(), |e| i + e);
        }
        out.push(Tag { name, attrs });
    }
    out
}

/// Paths named in robots.txt (Allow/Disallow without wildcards) and its
/// Sitemap URLs: often the most interesting places on a site.
pub fn robots(base: &Url, text: &str) -> (Vec<Url>, Vec<Url>) {
    let (mut paths, mut sitemaps) = (Vec::new(), Vec::new());
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match k.as_str() {
            "allow" | "disallow" if v.starts_with('/') && !v.contains(['*', '$']) => {
                if let Ok(u) = base.join(v)
                    && !paths.contains(&u)
                {
                    paths.push(u);
                }
            }
            "sitemap" => {
                if let Ok(u) = Url::parse(v) {
                    sitemaps.push(u);
                }
            }
            _ => {}
        }
    }
    (paths, sitemaps)
}

/// `<loc>` URLs in a sitemap.
pub fn sitemap(xml: &str) -> Vec<Url> {
    xml.split("<loc>")
        .skip(1)
        .filter_map(|s| s.split("</loc>").next())
        .filter_map(|s| Url::parse(decode_entities(s.trim()).as_str()).ok())
        .collect()
}

/// Links a crawler must not follow because they change state: log out,
/// delete, and the like.
pub fn risky(u: &Url) -> Option<&'static str> {
    let s = format!("{}?{}", u.path(), u.query().unwrap_or("")).to_ascii_lowercase();
    const WORDS: &[(&str, &str)] = &[
        ("logout", "logs out"),
        ("log-out", "logs out"),
        ("log_out", "logs out"),
        ("signout", "logs out"),
        ("sign-out", "logs out"),
        ("sign_out", "logs out"),
        ("delete", "deletes"),
        ("remove", "removes"),
        ("destroy", "destroys"),
        ("unsubscribe", "unsubscribes"),
        ("reset", "resets"),
        ("revoke", "revokes"),
        ("disable", "disables"),
        ("cancel", "cancels"),
    ];
    WORDS.iter().find(|(w, _)| s.contains(w)).map(|(_, why)| *why)
}

/// The most distinct URLs a crawl keeps track of.
pub const MAX_KNOWN_URLS: usize = 100_000;

/// Breadth-first frontier with de-duplication and limits.
#[derive(Debug)]
pub struct Frontier {
    queue: VecDeque<(Url, usize)>,
    seen: HashSet<String>,
    pub max_depth: usize,
    /// Keep `#/…` and `#!/…` fragments: single-page apps route with them.
    keep_routes: bool,
}

impl Frontier {
    pub fn new(start: Url, max_depth: usize) -> Self {
        let mut f = Frontier { queue: VecDeque::new(), seen: HashSet::new(), max_depth, keep_routes: false };
        f.push(start, 0);
        f
    }

    /// Like [`Frontier::new`], but `#/route` fragments make different pages
    /// (for crawling in a browser, where the app's router reads them).
    pub fn keeping_routes(start: Url, max_depth: usize) -> Self {
        let mut f = Frontier { queue: VecDeque::new(), seen: HashSet::new(), max_depth, keep_routes: true };
        f.push(start, 0);
        f
    }

    /// Adds a URL if it is new and not too deep. Returns whether it was added.
    pub fn push(&mut self, u: Url, depth: usize) -> bool {
        let route = u.fragment().filter(|f| self.keep_routes && (f.starts_with('/') || f.starts_with("!/")));
        let u = match route {
            Some(f) => {
                let mut x = strip(&u);
                x.set_fragment(Some(f));
                x
            }
            None => strip(&u),
        };
        // Link farms and calendar-style traps can offer endless new URLs.
        if depth > self.max_depth || self.seen.len() >= MAX_KNOWN_URLS || !self.seen.insert(u.to_string()) {
            return false;
        }
        self.queue.push_back((u, depth));
        true
    }

    pub fn pop(&mut self) -> Option<(Url, usize)> {
        self.queue.pop_front()
    }

    pub fn pending(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn extracts_links_and_forms() {
        let html = r##"<html><head><link href="/style.css"><script src=app.js></script>
            <script>var x = "<a href='/not-a-link'>";</script></head><body>
            <!-- <a href="/commented"> -->
            <a href="/a?x=1&amp;y=2#frag">A</a> <A HREF='b'>B</A> <a href=c/d>C</a>
            <a href="javascript:alert(1)">J</a> <a href="mailto:x@y">M</a> <a href="#top">T</a>
            <a href="https://other.example/x">O</a> <a href="/a?x=1&y=2">dup</a>
            <img src="/img.png"/>
            <form action="/search" method=get><input name=q><input name="q"><select name=sort></select></form>
            <form method="POST"><input name=user><button formaction="/alt">Go</button></form>
            </body></html>"##;
        let e = extract(&u("http://shop.test/dir/page"), html);
        let links: Vec<String> = e.links.iter().map(Url::to_string).collect();
        assert_eq!(
            links,
            vec![
                "http://shop.test/style.css",
                "http://shop.test/dir/app.js",
                "http://shop.test/a?x=1&y=2",
                "http://shop.test/dir/b",
                "http://shop.test/dir/c/d",
                "https://other.example/x",
                "http://shop.test/img.png",
                "http://shop.test/search",
                "http://shop.test/alt",
            ]
        );
        assert_eq!(e.forms.len(), 2);
        assert_eq!(
            (e.forms[0].method.as_str(), e.forms[0].action.as_str(), e.forms[0].inputs.clone()),
            ("GET", "http://shop.test/search", vec!["q".to_string(), "sort".to_string()])
        );
        assert_eq!((e.forms[1].method.as_str(), e.forms[1].action.as_str()), ("POST", "http://shop.test/dir/page"));
    }

    #[test]
    fn base_href_and_garbage() {
        let e = extract(&u("http://a.test/x/y"), "<base href='/root/'><a href=z>");
        assert_eq!(e.links[0].as_str(), "http://a.test/root/z");
        // Never panics on junk, including Unicode whitespace (U+0085, found by fuzzing).
        let fuzzed = String::from_utf8_lossy(b"<9\n\xff==\xbf<9,<\xc2\x85\n\n\xbf<9,,\xef\xbf\xff=\x00\n\n");
        let _ = extract(&u("http://a.test/"), &fuzzed);
        let _ = extract(&u("http://a.test/"), "<a\u{85}href=x\u{a0}b=\u{2003}c>");
        for junk in
            ["<", "<a", "<a href", "<a href=", "<a href='", "<<>>", "<!--", "<a/b=c>", "é<a href=é>", "<script>"]
        {
            let _ = extract(&u("http://a.test/"), junk);
        }
    }

    #[test]
    fn robots_and_sitemaps() {
        let (paths, maps) = robots(
            &u("http://a.test/"),
            "User-agent: *\nDisallow: /admin/\nDisallow: /*.php$\nAllow: /public # ok\nSitemap: http://a.test/sitemap.xml\n",
        );
        assert_eq!(
            paths.iter().map(Url::as_str).collect::<Vec<_>>(),
            vec!["http://a.test/admin/", "http://a.test/public"]
        );
        assert_eq!(maps[0].as_str(), "http://a.test/sitemap.xml");
        let locs =
            sitemap("<urlset><url><loc> http://a.test/p?a=1&amp;b=2 </loc></url><url><loc>bad</loc></url></urlset>");
        assert_eq!(locs.iter().map(Url::as_str).collect::<Vec<_>>(), vec!["http://a.test/p?a=1&b=2"]);
    }

    #[test]
    fn risky_links_and_frontier() {
        assert_eq!(risky(&u("http://a.test/account/logout")), Some("logs out"));
        assert_eq!(risky(&u("http://a.test/item?action=Delete&id=1")), Some("deletes"));
        assert_eq!(risky(&u("http://a.test/products")), None);
        let mut f = Frontier::new(u("http://a.test/"), 1);
        assert!(!f.push(u("http://a.test/#x"), 1), "same page");
        assert!(f.push(u("http://a.test/b"), 1));
        assert!(!f.push(u("http://a.test/c"), 2), "too deep");
        assert_eq!(f.pop().unwrap().0.as_str(), "http://a.test/");
        assert_eq!(f.pending(), 1);
    }

    #[test]
    fn route_fragments_are_pages_when_asked() {
        let mut plain = Frontier::new(u("http://x/"), 3);
        assert!(!plain.push(u("http://x/#/contact"), 1));
        let mut spa = Frontier::keeping_routes(u("http://x/"), 3);
        assert!(spa.push(u("http://x/#/contact"), 1));
        assert!(spa.push(u("http://x/#!/about"), 1));
        assert!(!spa.push(u("http://x/#top"), 1), "plain anchors are still the same page");
        assert!(!spa.push(u("http://x/#/contact"), 1));
    }
}
