//! Matching text in messages: literal (optionally case-insensitive) or a
//! regular expression, with short snippets around each match.

use regex::bytes::{Regex, RegexBuilder};

/// Longest pattern accepted.
pub const MAX_PATTERN: usize = 1000;

#[derive(Debug, Clone)]
pub enum Matcher {
    Literal { needle: Vec<u8>, case_sensitive: bool },
    Regex(Regex),
}

impl Matcher {
    pub fn new(pattern: &str, regex: bool, case_sensitive: bool) -> Result<Self, String> {
        if pattern.is_empty() {
            return Err("empty search".into());
        }
        if pattern.len() > MAX_PATTERN {
            return Err(format!("search longer than {MAX_PATTERN} characters"));
        }
        if regex {
            let re = RegexBuilder::new(pattern)
                .case_insensitive(!case_sensitive)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 22)
                .build()
                .map_err(|e| format!("bad regex: {e}"))?;
            return Ok(Self::Regex(re));
        }
        let needle =
            if case_sensitive { pattern.as_bytes().to_vec() } else { pattern.to_ascii_lowercase().into_bytes() };
        Ok(Self::Literal { needle, case_sensitive })
    }

    /// Byte ranges of up to `max` non-overlapping matches.
    pub fn find(&self, hay: &[u8], max: usize) -> Vec<(usize, usize)> {
        match self {
            Self::Regex(re) => {
                re.find_iter(hay).filter(|m| !m.is_empty()).take(max).map(|m| (m.start(), m.end())).collect()
            }
            Self::Literal { needle, case_sensitive } => {
                let lowered;
                let hay = if *case_sensitive {
                    hay
                } else {
                    lowered = hay.to_ascii_lowercase();
                    &lowered[..]
                };
                let finder = memchr::memmem::Finder::new(needle);
                let mut out = Vec::new();
                let mut at = 0;
                while out.len() < max {
                    let Some(i) = finder.find(&hay[at..]) else { break };
                    out.push((at + i, at + i + needle.len()));
                    at += i + needle.len();
                }
                out
            }
        }
    }
}

/// A short, single-line excerpt around `range`, plus where the match sits in it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Snippet {
    pub text: String,
    /// Character offsets of the match within `text`.
    pub start: usize,
    pub end: usize,
}

/// Up to `context` bytes either side of the match; line breaks shown as ⏎.
pub fn snippet(hay: &[u8], range: (usize, usize), context: usize) -> Snippet {
    let (s, e) = (range.0.min(hay.len()), range.1.min(hay.len()));
    let from = s.saturating_sub(context);
    let to = (e + context).min(hay.len());
    let clean = |b: &[u8]| -> String {
        String::from_utf8_lossy(b)
            .chars()
            .map(|c| match c {
                '\r' => '\u{0}',
                '\n' => '⏎',
                c if c.is_control() => '·',
                c => c,
            })
            .filter(|&c| c != '\u{0}')
            .collect()
    };
    let before = clean(&hay[from..s]);
    let hit = clean(&hay[s..e]);
    let after = clean(&hay[e..to]);
    let lead = if from > 0 { "…" } else { "" };
    let tail = if to < hay.len() { "…" } else { "" };
    let start = lead.chars().count() + before.chars().count();
    let end = start + hit.chars().count();
    Snippet { text: format!("{lead}{before}{hit}{after}{tail}"), start, end }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_and_regex() {
        let hay = b"Set-Cookie: SID=abc\r\n\r\n{\"email\":\"Alice@Example.com\",\"x\":\"alice@example.com\"}";
        let m = Matcher::new("alice@", false, false).unwrap();
        assert_eq!(m.find(hay, 10).len(), 2);
        assert_eq!(Matcher::new("alice@", false, true).unwrap().find(hay, 10).len(), 1);
        let re = Matcher::new(r"[a-z]+@[a-z]+\.com", true, false).unwrap();
        assert_eq!(re.find(hay, 1).len(), 1);
        assert!(Matcher::new("(", true, false).is_err());
        assert!(Matcher::new("", false, false).is_err());
        // Empty regex matches are ignored rather than reported everywhere.
        assert!(Matcher::new("x*", true, true).unwrap().find(b"abc", 10).is_empty());
    }

    #[test]
    fn snippets() {
        let hay = b"0123456789\r\nkey=SECRET; more text here";
        let r = Matcher::new("secret", false, false).unwrap().find(hay, 1)[0];
        let s = snippet(hay, r, 6);
        assert_eq!(s.text, "…⏎key=SECRET; more…");
        let chars: Vec<char> = s.text.chars().collect();
        assert_eq!(chars[s.start..s.end].iter().collect::<String>(), "SECRET");
        assert_eq!(snippet(b"\xffab", (1, 2), 5).text, "\u{fffd}ab");
    }
}
