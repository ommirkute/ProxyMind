//! Line diff (longest common subsequence) for the Comparer. Large inputs
//! are cut so the quadratic table stays small.

use serde::Serialize;

/// Lines compared from each side at most.
pub const MAX_LINES: usize = 2000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "op", content = "text", rename_all = "snake_case")]
pub enum Line {
    Same(String),
    Removed(String),
    Added(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineDiff {
    pub lines: Vec<Line>,
    pub added: usize,
    pub removed: usize,
    /// Inputs were longer than MAX_LINES and were cut.
    pub truncated: bool,
}

pub fn diff(a: &str, b: &str) -> LineDiff {
    let la: Vec<&str> = a.lines().collect();
    let lb: Vec<&str> = b.lines().collect();
    let truncated = la.len() > MAX_LINES || lb.len() > MAX_LINES;
    let (la, lb) = (&la[..la.len().min(MAX_LINES)], &lb[..lb.len().min(MAX_LINES)]);
    let (n, m) = (la.len(), lb.len());
    // lcs[i][j] = LCS length of la[i..] and lb[j..]
    let mut lcs = vec![0u32; (n + 1) * (m + 1)];
    let at = |i: usize, j: usize| i * (m + 1) + j;
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[at(i, j)] =
                if la[i] == lb[j] { lcs[at(i + 1, j + 1)] + 1 } else { lcs[at(i + 1, j)].max(lcs[at(i, j + 1)]) };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut lines = Vec::new();
    while i < n && j < m {
        if la[i] == lb[j] {
            lines.push(Line::Same(la[i].into()));
            i += 1;
            j += 1;
        } else if lcs[at(i + 1, j)] >= lcs[at(i, j + 1)] {
            lines.push(Line::Removed(la[i].into()));
            i += 1;
        } else {
            lines.push(Line::Added(lb[j].into()));
            j += 1;
        }
    }
    lines.extend(la[i..].iter().map(|l| Line::Removed((*l).into())));
    lines.extend(lb[j..].iter().map(|l| Line::Added((*l).into())));
    let added = lines.iter().filter(|l| matches!(l, Line::Added(_))).count();
    let removed = lines.iter().filter(|l| matches!(l, Line::Removed(_))).count();
    LineDiff { lines, added, removed, truncated }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffs_lines() {
        let d = diff("a\nb\nc\nd", "a\nc\nd\ne");
        assert_eq!(
            d.lines,
            vec![
                Line::Same("a".into()),
                Line::Removed("b".into()),
                Line::Same("c".into()),
                Line::Same("d".into()),
                Line::Added("e".into())
            ]
        );
        assert_eq!((d.added, d.removed, d.truncated), (1, 1, false));
        assert_eq!(diff("", "x").added, 1);
        let big = "x\n".repeat(MAX_LINES + 5);
        assert!(diff(&big, "x").truncated);
    }
}
