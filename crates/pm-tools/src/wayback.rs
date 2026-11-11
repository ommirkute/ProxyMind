//! Reads the Internet Archive's CDX answers (`output=json`): the URLs it has
//! seen for a site, with status, type and capture time. Untrusted input:
//! malformed rows are skipped.

use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capture {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mime: String,
    /// YYYYMMDDhhmmss
    pub timestamp: String,
    /// Why it deserves a look (backup, config, API, admin…), if it does.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

/// Why a historical URL deserves a look.
pub fn interesting(url: &str) -> Option<&'static str> {
    let lower = url.to_ascii_lowercase();
    let path = lower.split(['?', '#']).next().unwrap_or_default();
    const FILES: &[(&str, &str)] = &[
        (".bak", "backup"),
        (".old", "backup"),
        (".zip", "archive"),
        (".tar.gz", "archive"),
        (".sql", "database dump"),
        (".env", "environment file"),
        (".config", "configuration"),
        (".yml", "configuration"),
        (".yaml", "configuration"),
        (".log", "log file"),
        (".map", "source map"),
        (".json", "data or configuration"),
        (".xml", "data or configuration"),
    ];
    if let Some((_, note)) = FILES.iter().find(|(ext, _)| path.ends_with(ext)) {
        return Some(note);
    }
    const PATHS: &[(&str, &str)] = &[
        ("/admin", "admin area"),
        ("/api/", "API"),
        ("/graphql", "API"),
        ("/swagger", "API description"),
        ("/debug", "debug"),
        ("/internal", "internal"),
        ("/backup", "backup"),
        ("/.git", "source control"),
    ];
    if let Some((_, note)) = PATHS.iter().find(|(p, _)| path.contains(p)) {
        return Some(note);
    }
    lower.contains('?').then_some("takes parameters")
}

/// Captures from a CDX JSON answer (`[["original","statuscode","mimetype","timestamp"], [...], ...]`).
pub fn parse_cdx(text: &str) -> Vec<Capture> {
    let Ok(Value::Array(rows)) = serde_json::from_str::<Value>(text) else { return Vec::new() };
    let mut it = rows.into_iter();
    let Some(Value::Array(head)) = it.next() else { return Vec::new() };
    let col = |name: &str| head.iter().position(|h| h.as_str() == Some(name));
    let (Some(u), s, m, t) = (col("original"), col("statuscode"), col("mimetype"), col("timestamp")) else {
        return Vec::new();
    };
    let get =
        |row: &[Value], i: Option<usize>| i.and_then(|i| row.get(i)).and_then(Value::as_str).unwrap_or("").to_string();
    it.filter_map(|r| {
        let Value::Array(row) = r else { return None };
        let url = get(&row, Some(u));
        if !(url.starts_with("http://") || url.starts_with("https://")) || url.len() > 2048 {
            return None;
        }
        let note = interesting(&url);
        Some(Capture { status: get(&row, s).parse().ok(), mime: get(&row, m), timestamp: get(&row, t), note, url })
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cdx_rows() {
        let text = r#"[["original","statuscode","mimetype","timestamp"],
            ["https://shop.test/backup.zip","200","application/zip","20190101000000"],
            ["https://shop.test/search?q=x","200","text/html","20200101000000"],
            ["https://shop.test/about","-","warc/revisit","20210101000000"],
            ["javascript:alert(1)","200","text/html","20210101000000"],
            "junk"]"#;
        let c = parse_cdx(text);
        assert_eq!(c.len(), 3);
        assert_eq!((c[0].note, c[0].status), (Some("archive"), Some(200)));
        assert_eq!(c[1].note, Some("takes parameters"));
        assert_eq!((c[2].note, c[2].status), (None, None));
        assert!(parse_cdx("not json").is_empty() && parse_cdx("[]").is_empty());
    }
}
