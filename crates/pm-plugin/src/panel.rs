//! Panels: views a plugin adds to the UI. A panel is a command that gets
//! recorded exchanges (JSON lines, like a passive plugin) and prints one
//! JSON object: `{"title", "text", "columns", "rows"}`. ProxyMind
//! validates and clips it, and the UI shows it as text and a table, never
//! as markup or script from the plugin.

use serde::{Deserialize, Serialize};

use crate::{ExchangeLine, Installed, PluginError, Result, run, run_err, valid_name};

pub const MAX_PANELS: usize = 10;
const MAX_COLUMNS: usize = 20;
const MAX_ROWS: usize = 1000;
const MAX_CELL: usize = 500;
const MAX_TEXT: usize = 20_000;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Panel {
    /// Lowercase letters, digits and dashes.
    pub id: String,
    pub title: String,
    /// Program and arguments, as for passive plugins.
    pub command: Vec<String>,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// What a panel shows, after validation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PanelData {
    pub title: String,
    pub text: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

#[derive(Deserialize)]
struct RawPanel {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    columns: Vec<serde_json::Value>,
    #[serde(default)]
    rows: Vec<Vec<serde_json::Value>>,
}

fn cell(v: &serde_json::Value, max: usize) -> String {
    let s = match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    };
    let s: String = s.chars().filter(|c| !c.is_control() || *c == ' ').collect();
    if s.chars().count() <= max { s } else { format!("{}…", s.chars().take(max).collect::<String>()) }
}

pub fn validate(panels: &[Panel]) -> Result<()> {
    if panels.len() > MAX_PANELS {
        return Err(PluginError::Invalid(format!("at most {MAX_PANELS} panels")));
    }
    for p in panels {
        if !valid_name(&p.id) || p.title.trim().is_empty() || p.command.is_empty() {
            return Err(PluginError::Invalid(format!(
                "panel {:?}: needs an id (lowercase, digits, dashes), a title and a command",
                p.id
            )));
        }
    }
    Ok(())
}

/// Parses a panel's output (one JSON object; text after it is ignored).
pub fn parse(out: &str, fallback_title: &str) -> std::result::Result<PanelData, String> {
    let start = out.find('{').ok_or("the panel printed no JSON object")?;
    let mut de = serde_json::Deserializer::from_str(&out[start..]).into_iter::<RawPanel>();
    let raw = de.next().ok_or("the panel printed no JSON object")?.map_err(|e| format!("panel output: {e}"))?;
    let columns: Vec<String> = raw.columns.iter().take(MAX_COLUMNS).map(|c| cell(c, 80)).collect();
    let width = columns.len().max(raw.rows.iter().map(Vec::len).max().unwrap_or(0)).min(MAX_COLUMNS);
    let rows = raw
        .rows
        .iter()
        .take(MAX_ROWS)
        .map(|r| (0..width).map(|i| r.get(i).map(|v| cell(v, MAX_CELL)).unwrap_or_default()).collect())
        .collect();
    Ok(PanelData {
        title: cell(&serde_json::Value::String(raw.title.unwrap_or_else(|| fallback_title.into())), 120),
        text: raw
            .text
            .map(|t| t.chars().filter(|c| !c.is_control() || matches!(c, '\n' | '\t')).take(MAX_TEXT).collect())
            .unwrap_or_default(),
        columns,
        rows,
    })
}

/// Runs panel `id` of plugin `p` over `exchanges`.
pub fn run_panel(p: &Installed, id: &str, exchanges: &[ExchangeLine]) -> Result<PanelData> {
    let panel = p
        .manifest
        .panels
        .iter()
        .find(|x| x.id == id)
        .ok_or_else(|| PluginError::Invalid(format!("plugin {} has no panel {id}", p.manifest.name)))?;
    let input: Vec<u8> =
        exchanges.iter().filter_map(|x| serde_json::to_string(x).ok()).flat_map(|l| (l + "\n").into_bytes()).collect();
    let out = run(p, &panel.command, panel.timeout_seconds.unwrap_or(60), input)?;
    parse(&String::from_utf8_lossy(&out), &panel.title).map_err(|why| run_err(p, why))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_validated_and_clipped() {
        let d = parse("log line\n{\"title\":\"Hosts\",\"text\":\"a\\u0007b\\nc\",\"columns\":[\"host\",\"n\"],\"rows\":[[\"a.test\",3],[\"b.test\"]]}", "x").unwrap();
        assert_eq!(d.title, "Hosts");
        assert_eq!(d.text, "ab\nc", "control characters are dropped, new lines kept");
        assert_eq!(d.rows, vec![vec!["a.test".to_string(), "3".into()], vec!["b.test".into(), String::new()]]);
        let long = format!("{{\"rows\":[[\"{}\"]]}}", "x".repeat(2000));
        assert_eq!(parse(&long, "Fallback").unwrap().rows[0][0].chars().count(), MAX_CELL + 1);
        assert_eq!(parse(&long, "Fallback").unwrap().title, "Fallback");
        assert!(parse("nothing", "x").is_err());
    }
}
