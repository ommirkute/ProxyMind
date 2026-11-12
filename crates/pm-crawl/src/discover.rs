//! Content discovery (forced browsing): candidate paths from a word list,
//! and telling real pages from a server's "soft 404s".

use url::Url;

/// Common hidden files and folders. Short on purpose: a first look, not a
/// brute force. Users can pass their own list.
pub const BUILTIN_WORDS: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".git/HEAD",
    ".git/config",
    ".svn/entries",
    ".hg/hgrc",
    ".DS_Store",
    ".htaccess",
    ".htpasswd",
    ".well-known/security.txt",
    ".well-known/openid-configuration",
    "admin",
    "admin/",
    "administrator",
    "api",
    "api/v1",
    "api/v2",
    "api/docs",
    "api-docs",
    "api/swagger.json",
    "backup",
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "backups/",
    "bak",
    "config",
    "config.json",
    "config.yml",
    "config.php.bak",
    "console",
    "crossdomain.xml",
    "dashboard",
    "db.sql",
    "debug",
    "dev",
    "docs",
    "dump.sql",
    "env",
    "files/",
    "ftp/",
    "graphql",
    "graphiql",
    "health",
    "healthz",
    "info.php",
    "internal",
    "jenkins",
    "login",
    "manage",
    "management",
    "metrics",
    "monitoring",
    "old",
    "openapi.json",
    "openapi.yaml",
    "phpinfo.php",
    "phpmyadmin/",
    "private",
    "prometheus",
    "robots.txt",
    "server-status",
    "server-info",
    "sitemap.xml",
    "staging",
    "status",
    "swagger",
    "swagger-ui.html",
    "swagger.json",
    "swagger/index.html",
    "test",
    "tmp",
    "upload",
    "uploads/",
    "v1",
    "v2",
    "web.config",
    "wp-admin/",
    "wp-login.php",
    "actuator",
    "actuator/env",
    "actuator/health",
    "actuator/heapdump",
    "_debug",
    "__debug__/",
    "trace.axd",
    "elmah.axd",
    // Endpoints that take a URL or a file name (redirects, fetchers,
    // downloads): where SSRF, open redirects and path traversal live.
    "download",
    "redirect",
    "go",
    "out",
    "fetch",
    "proxy",
    "preview",
    "render",
];

/// Folders a robots.txt asks crawlers to stay out of (`Disallow: /admin/`),
/// worth a look with content discovery. Only plain folders: patterns with
/// `*` or `$` inside, the root and query strings are left out. At most 8.
pub fn robots_dirs(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some((key, value)) = line.split_once(':') else { continue };
        if !key.trim().eq_ignore_ascii_case("disallow") {
            continue;
        }
        let v = value.trim().trim_end_matches(['*', '$']);
        let plain = v.starts_with('/') && v.len() > 1 && v.ends_with('/');
        if plain && !v.contains(['*', '$', '?', '#']) && !v.contains("..") && !out.iter().any(|o| o == v) {
            out.push(v.to_string());
        }
        if out.len() == 8 {
            break;
        }
    }
    out
}

/// Other API versions of known paths: when an app uses `/api/v3/…`, its
/// `/api/login` may also answer as `/api/v1/login` or `/api/v2/login`
/// (old versions often lack newer checks). Takes path templates and
/// returns `(known, sibling)` pairs for templates without parameters, for
/// versions 1 up to one past the highest seen (at most 5). At most 24.
pub fn version_siblings(templates: &[String]) -> Vec<(String, String)> {
    let is_version = |s: &str| s.len() >= 2 && s.starts_with('v') && s[1..].chars().all(|c| c.is_ascii_digit());
    // Prefixes (the segments before a version) and the versions seen under each.
    let mut prefixes: std::collections::BTreeMap<String, std::collections::BTreeSet<u32>> = Default::default();
    for t in templates {
        let segs: Vec<&str> = t.split('/').filter(|s| !s.is_empty()).collect();
        if let Some(k) = segs.iter().position(|s| is_version(s))
            && let Ok(n) = segs[k][1..].parse::<u32>()
        {
            prefixes.entry(format!("/{}", segs[..k].join("/")).replace("//", "/")).or_default().insert(n);
        }
    }
    let known: std::collections::BTreeSet<&str> = templates.iter().map(String::as_str).collect();
    let mut out = Vec::new();
    for (prefix, versions) in &prefixes {
        let top = versions.iter().max().copied().unwrap_or(1).saturating_add(1).min(5);
        let base = if prefix == "/" { String::new() } else { prefix.clone() };
        for t in templates.iter().filter(|t| !t.contains('{')) {
            let Some(rest) = t.strip_prefix(&format!("{base}/")) else { continue };
            // The path after the version (or after the prefix, unversioned).
            let tail = match rest.split_once('/') {
                Some((v, tail)) if is_version(v) => tail,
                _ if is_version(rest) => continue,
                _ => rest,
            };
            if tail.is_empty() {
                continue;
            }
            for n in 1..=top {
                let sibling = format!("{base}/v{n}/{tail}");
                if !known.contains(sibling.as_str()) && !out.iter().any(|(_, s)| *s == sibling) {
                    out.push((t.clone(), sibling));
                }
                if out.len() == 24 {
                    return out;
                }
            }
        }
    }
    out
}

/// Most candidates in one run.
pub const MAX_CANDIDATES: usize = 5000;

/// Candidate URLs under `base` (a directory: a trailing `/` is added), from
/// `words` and each word with each extension. Words that are absolute URLs,
/// climb out of the base (`..`) or contain a query are dropped.
pub fn candidates(base: &Url, words: &[String], extensions: &[String]) -> Vec<Url> {
    let mut dir = base.clone();
    dir.set_query(None);
    dir.set_fragment(None);
    if !dir.path().ends_with('/') {
        let p = format!("{}/", dir.path());
        dir.set_path(&p);
    }
    let mut out: Vec<Url> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut add = |w: &str, out: &mut Vec<Url>| {
        let w = w.trim().trim_start_matches('/');
        if w.is_empty()
            || w.contains("://")
            || w.contains(['?', '#', '\\'])
            || w.split('/').any(|seg| seg == ".." || seg == ".")
            || w.chars().any(|c| c.is_control() || c == ' ')
        {
            return;
        }
        if let Ok(u) = dir.join(w)
            && u.as_str().starts_with(dir.as_str())
            && seen.insert(u.to_string())
            && out.len() < MAX_CANDIDATES
        {
            out.push(u);
        }
    };
    for w in words {
        add(w, &mut out);
        let last = w.rsplit('/').next().unwrap_or_default();
        if !w.ends_with('/') && !last.contains('.') {
            for e in extensions {
                let e = e.trim().trim_start_matches('.');
                if !e.is_empty() && e.chars().all(|c| c.is_ascii_alphanumeric()) {
                    add(&format!("{w}.{e}"), &mut out);
                }
            }
        }
    }
    out
}

/// What a missing page looks like on this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotFound {
    pub status: u16,
    pub length: usize,
    /// Redirect target with the probe token removed, if it redirected.
    pub location: Option<String>,
    /// The body with the probe token removed, for comparison.
    pub body: Vec<u8>,
}

impl NotFound {
    /// Builds a fingerprint from a probe response; `token` is the random
    /// part of the probe path, removed so it doesn't skew comparison.
    pub fn new(status: u16, location: Option<&str>, body: &[u8], token: &str) -> Self {
        let body = strip(body, token.as_bytes());
        Self { status, length: body.len(), location: location.map(|l| l.replace(token, "")), body }
    }

    /// True when a response looks like this "not found" page: same status,
    /// same redirect, and a body of near-identical size and content.
    /// `word` is the requested candidate, which a soft 404 page may echo.
    pub fn matches(&self, status: u16, location: Option<&str>, body: &[u8], word: &str) -> bool {
        if status != self.status {
            return false;
        }
        if (300..400).contains(&status) {
            let loc = location.map(|l| l.replace(word, ""));
            return loc == self.location;
        }
        let body = strip(body, word.as_bytes());
        let (a, b) = (body.len() as f64, self.length as f64);
        if (a - b).abs() > (b * 0.1).max(32.0) {
            return false;
        }
        similarity(&body, &self.body) >= 0.9
    }
}

fn strip(body: &[u8], needle: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return body.to_vec();
    }
    let mut out = Vec::with_capacity(body.len());
    let mut i = 0;
    while i < body.len() {
        if body[i..].starts_with(needle) {
            i += needle.len();
        } else {
            out.push(body[i]);
            i += 1;
        }
    }
    out
}

/// Share of 4-byte shingles two bodies have in common (Jaccard), from
/// their first 64 KB.
fn similarity(a: &[u8], b: &[u8]) -> f64 {
    use std::collections::HashSet;
    let shingles = |x: &[u8]| -> HashSet<[u8; 4]> {
        x[..x.len().min(64 * 1024)].windows(4).map(|w| [w[0], w[1], w[2], w[3]]).collect()
    };
    let (sa, sb) = (shingles(a), shingles(b));
    if sa.is_empty() && sb.is_empty() {
        return if a == b { 1.0 } else { 0.0 };
    }
    let inter = sa.intersection(&sb).count() as f64;
    inter / (sa.len() + sb.len()) as f64 * 2.0
}

/// Why a found path deserves a look, if it does.
/// Names of pages that usually take a URL or a file name, and the
/// parameter to guess for them: `(name, value)`. These pages often answer
/// 404 (or an error) until the parameter is there.
pub const PARAM_WORDS: &[&str] = &[
    "download",
    "redirect",
    "go",
    "out",
    "fetch",
    "proxy",
    "preview",
    "render",
    "link",
    "url",
    "image",
    "img",
    "callback",
    "webhook",
    "load",
    "file",
    "files",
    "export",
    "attachment",
    "view",
    "read",
    "doc",
    "document",
    "include",
    "template",
];

/// The parameter a page named `word` probably takes, with a harmless
/// value: a URL that resolves nowhere, or an ordinary file name.
pub fn param_for(word: &str) -> Option<(&'static str, &'static str)> {
    let w = word.to_ascii_lowercase();
    const URLS: &[&str] = &[
        "redirect", "go", "out", "fetch", "proxy", "preview", "render", "link", "url", "image", "img", "callback",
        "webhook", "load",
    ];
    const FILES: &[&str] = &[
        "download",
        "file",
        "files",
        "export",
        "attachment",
        "view",
        "read",
        "doc",
        "document",
        "include",
        "template",
    ];
    if URLS.contains(&w.as_str()) {
        Some(("url", "http://proxymind-probe.invalid/"))
    } else if FILES.contains(&w.as_str()) {
        Some(("file", "index.html"))
    } else {
        None
    }
}

pub fn interesting(path: &str) -> Option<&'static str> {
    let p = path.to_ascii_lowercase();
    const MARKERS: &[(&str, &str)] = &[
        (".git/", "source control metadata"),
        (".svn", "source control metadata"),
        (".hg/", "source control metadata"),
        (".env", "environment file (often secrets)"),
        (".htpasswd", "password file"),
        ("backup", "backup"),
        (".bak", "backup"),
        (".sql", "database dump"),
        (".zip", "archive"),
        (".tar", "archive"),
        ("phpinfo", "server configuration"),
        ("info.php", "server configuration"),
        ("server-status", "server status page"),
        ("actuator", "Spring Boot actuator"),
        ("heapdump", "memory dump"),
        ("debug", "debug endpoint"),
        ("console", "admin console"),
        ("admin", "admin area"),
        ("swagger", "API description"),
        ("openapi", "API description"),
        ("api-docs", "API description"),
        ("graphql", "GraphQL endpoint"),
        ("metrics", "metrics"),
        ("ftp/", "file share"),
        ("config", "configuration"),
        ("web.config", "configuration"),
    ];
    MARKERS.iter().find(|(m, _)| p.contains(m)).map(|(_, why)| *why)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_guesses() {
        assert_eq!(param_for("Fetch"), Some(("url", "http://proxymind-probe.invalid/")));
        assert_eq!(param_for("download"), Some(("file", "index.html")));
        assert_eq!(param_for("about"), None);
        assert!(PARAM_WORDS.iter().all(|w| param_for(w).is_some()));
    }

    fn w(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn builds_candidates_under_the_base() {
        let base = Url::parse("https://a.test/app?x=1").unwrap();
        let c = candidates(
            &base,
            &w(&["admin", "/backup", "x.php", "dir/", "../etc/passwd", "http://evil/", "a?b", "admin"]),
            &w(&["bak", ".old", "b@d"]),
        );
        let got: Vec<&str> = c.iter().map(Url::as_str).collect();
        assert_eq!(
            got,
            [
                "https://a.test/app/admin",
                "https://a.test/app/admin.bak",
                "https://a.test/app/admin.old",
                "https://a.test/app/backup",
                "https://a.test/app/backup.bak",
                "https://a.test/app/backup.old",
                "https://a.test/app/x.php",
                "https://a.test/app/dir/",
            ]
        );
        let builtin: Vec<String> = BUILTIN_WORDS.iter().map(|s| s.to_string()).collect();
        let all = candidates(&Url::parse("http://a.test/").unwrap(), &builtin, &[]);
        assert_eq!(all.len(), BUILTIN_WORDS.len(), "no duplicates, nothing dropped");
    }

    #[test]
    fn soft_404s() {
        let page = |p: &str| format!("<html><h1>Not found</h1><p>The page /{p} does not exist.</p></html>");
        let nf = NotFound::new(200, None, page("pm-x1y2z3").as_bytes(), "pm-x1y2z3");
        assert!(nf.matches(200, None, page("admin").as_bytes(), "admin"), "same page, echoing the path");
        assert!(!nf.matches(200, None, b"<html><h1>Admin</h1><form>...</form></html>", "admin"));
        assert!(!nf.matches(403, None, page("admin").as_bytes(), "admin"));

        let r = NotFound::new(302, Some("/login?next=/pm-abc"), b"", "pm-abc");
        assert!(r.matches(302, Some("/login?next=/admin"), b"", "admin"), "redirects everything to login");
        assert!(!r.matches(302, Some("/admin/"), b"", "admin"));

        let real404 = NotFound::new(404, None, b"Cannot GET /pm-q9z", "pm-q9z");
        assert!(real404.matches(404, None, b"Cannot GET /admin", "admin"));
        assert!(!real404.matches(200, None, b"Cannot GET /admin", "admin"));
    }

    #[test]
    fn interesting_paths() {
        assert_eq!(interesting("/.git/config"), Some("source control metadata"));
        assert_eq!(interesting("/backup.zip"), Some("backup"));
        assert_eq!(interesting("/about"), None);
    }

    #[test]
    fn robots_folders() {
        let t = "User-agent: *\nDisallow: /api/admin/\nDisallow: /api/internal/ # keep out\nDisallow: /*.bak$\n\
                 Disallow: /\nDisallow: /private\ndisallow: /old/*\nAllow: /public/\nDisallow: /api/admin/\n";
        assert_eq!(robots_dirs(t), vec!["/api/admin/", "/api/internal/", "/old/"]);
    }

    #[test]
    fn api_version_siblings() {
        let t: Vec<String> =
            ["/api/login", "/api/v3/profile", "/api/orders/{id}", "/api/v3"].iter().map(|s| s.to_string()).collect();
        let s = version_siblings(&t);
        let siblings: Vec<&str> = s.iter().map(|(_, b)| b.as_str()).collect();
        assert_eq!(
            siblings,
            vec![
                "/api/v1/login",
                "/api/v2/login",
                "/api/v3/login",
                "/api/v4/login",
                "/api/v1/profile",
                "/api/v2/profile",
                "/api/v4/profile"
            ]
        );
        assert_eq!(s[1].0, "/api/login");
        assert!(version_siblings(&["/api/login".to_string()]).is_empty());
    }
}
