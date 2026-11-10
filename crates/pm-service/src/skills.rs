//! Skills: testing playbooks for agents (and people). Each is Markdown with
//! a small header (`name`, `title`, `description`, `args`) and steps that
//! use ProxyMind's tools, so whatever an agent does while following one
//! still goes through the policy gate. Built-in skills ship in the binary;
//! users add their own as `<home>/skills/<name>.md` (a user skill with a
//! built-in's name replaces it). Served over MCP as prompts and through
//! the `skills_list` / `skill_get` tools, the REST API and the CLI.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{Result, Service, ServiceError};

const BUILTIN: &[&str] = &[
    include_str!("../skills/idor_sweep.md"),
    include_str!("../skills/triage_findings.md"),
    include_str!("../skills/ssrf_hunt.md"),
    include_str!("../skills/js_recon.md"),
    include_str!("../skills/auth_review.md"),
    include_str!("../skills/jwt_audit.md"),
    include_str!("../skills/race_conditions.md"),
    include_str!("../skills/file_upload.md"),
];

/// Most user skills read, and the largest one.
const MAX_USER_SKILLS: usize = 100;
const MAX_SKILL_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Skill {
    pub name: String,
    pub title: String,
    pub description: String,
    /// Arguments the text takes (`{{name}}`); all optional.
    pub args: Vec<String>,
    /// "builtin" or "user".
    pub source: &'static str,
    #[serde(skip)]
    body: String,
}

/// Reads one skill file: `---` header lines `key: value`, `---`, then the body.
pub fn parse(text: &str, source: &'static str) -> Option<Skill> {
    let text = text.trim_start_matches('\u{feff}');
    let rest = text.strip_prefix("---")?;
    let (head, body) = rest.split_once("\n---")?;
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    for line in head.lines() {
        if let Some((k, v)) = line.split_once(':') {
            fields.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let name = fields.get("name")?.clone();
    let valid = |s: &str| !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid(&name) {
        return None;
    }
    let args = fields
        .get("args")
        .map(|a| a.split(',').map(|x| x.trim().to_string()).filter(|x| valid(x)).collect())
        .unwrap_or_default();
    Some(Skill {
        title: fields.get("title").cloned().unwrap_or_else(|| name.clone()),
        description: fields.get("description").cloned().unwrap_or_default(),
        name,
        args,
        source,
        body: body.trim_start_matches(['-', '\n', '\r']).trim().to_string(),
    })
}

impl Skill {
    /// The text with `{{arg}}` filled. An argument not given becomes empty
    /// (`focus` turns into a sentence when given).
    pub fn render(&self, args: &BTreeMap<String, String>) -> String {
        let mut out = self.body.clone();
        for a in &self.args {
            let v = args.get(a).map(|v| v.trim()).unwrap_or_default();
            let filled = match (a.as_str(), v.is_empty()) {
                (_, true) => String::new(),
                ("focus", false) => format!("Focus on: {v}."),
                _ => v.to_string(),
            };
            out = out.replace(&format!("{{{{{a}}}}}"), &filled);
        }
        out
    }
}

impl Service {
    /// Built-in skills, then the user's (which replace a built-in of the same name).
    pub fn skills_list(&self) -> Result<Vec<Skill>> {
        let mut all: Vec<Skill> = BUILTIN.iter().filter_map(|t| parse(t, "builtin")).collect();
        if let Some(home) = self.plugin_home.get()
            && let Ok(dir) = std::fs::read_dir(home.join("skills"))
        {
            let mut files: Vec<_> =
                dir.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "md")).collect();
            files.sort();
            for path in files.into_iter().take(MAX_USER_SKILLS) {
                let Ok(meta) = std::fs::metadata(&path) else { continue };
                if meta.len() as usize > MAX_SKILL_BYTES {
                    continue;
                }
                let Some(s) = std::fs::read_to_string(&path).ok().and_then(|t| parse(&t, "user")) else { continue };
                all.retain(|b| b.name != s.name);
                all.push(s);
            }
        }
        Ok(all)
    }

    /// One skill's text with its arguments filled.
    pub fn skill_get(&self, name: &str, args: &BTreeMap<String, String>) -> Result<(Skill, String)> {
        let skill = self
            .skills_list()?
            .into_iter()
            .find(|s| s.name == name)
            .ok_or_else(|| ServiceError::NotFound(format!("skill {name}")))?;
        let text = skill.render(args);
        Ok((skill, text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_parse_and_render() {
        let all: Vec<Skill> = BUILTIN.iter().filter_map(|t| parse(t, "builtin")).collect();
        assert_eq!(all.len(), BUILTIN.len(), "every built-in skill parses");
        let idor = all.iter().find(|s| s.name == "idor_sweep").unwrap();
        assert_eq!(idor.args, ["focus"]);
        let mut a = BTreeMap::new();
        let plain = idor.render(&a);
        assert!(!plain.contains("{{") && plain.starts_with("Goal:"), "{plain}");
        a.insert("focus".into(), "the /api/orders endpoints".into());
        assert!(idor.render(&a).contains("Focus on: the /api/orders endpoints."));
    }

    #[test]
    fn bad_headers_are_refused() {
        assert!(parse("no header", "user").is_none());
        assert!(parse("---\nname: ../evil\n---\nx", "user").is_none());
        let s = parse("---\nname: mine\nargs: target, bad-name\n---\nTest {{target}}.", "user").unwrap();
        assert_eq!(s.args, ["target"]);
        assert_eq!(s.title, "mine");
    }
}
