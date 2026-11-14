//! Attack paths: findings and observations chained into a route to impact
//! ("token in a script → admin API → read any order"). Agents record them
//! (an AI scan's are tied to its run); people can delete them. The graph
//! view merges paths that share a step, so overlapping chains show as one
//! picture.

use std::collections::BTreeMap;

use pm_policy::{Actor, ActorKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::findings::SEVERITIES;
use crate::{Result, Service, ServiceError, scan_of};

const MAX_STEPS: usize = 12;
const MAX_TEXT: usize = 300;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttackStep {
    /// What happens at this step ("read the API key from /static/app.js").
    pub text: String,
    /// The finding this step is, if it is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<i64>,
    /// An exchange that shows the step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exchange_id: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewAttackPath {
    pub title: String,
    /// What an attacker gains at the end.
    pub impact: String,
    /// critical, high, medium, low or info: the severity of the whole chain.
    pub severity: String,
    pub steps: Vec<AttackStep>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackPath {
    pub id: i64,
    /// The AI scan that recorded it, if one did.
    pub scan_id: Option<i64>,
    pub title: String,
    pub impact: String,
    pub severity: String,
    pub steps: Vec<AttackStep>,
    pub actor: String,
    pub created_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<i64>,
    /// The finding's severity, if the step is a finding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Where the node sits from the start of its paths (0 = entry point).
    pub depth: usize,
    /// The node ends at least one path (the impact).
    pub impact: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    /// Paths that take this edge.
    pub paths: Vec<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub paths: Vec<AttackPath>,
}

fn decode(r: &serde_json::Map<String, Value>) -> AttackPath {
    let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    AttackPath {
        id: r.get("id").and_then(Value::as_i64).unwrap_or_default(),
        scan_id: r.get("scan_id").and_then(Value::as_i64),
        title: s("title"),
        impact: s("impact"),
        severity: s("severity"),
        steps: serde_json::from_str(&s("steps")).unwrap_or_default(),
        actor: s("actor"),
        created_ms: r.get("created_ms").and_then(Value::as_i64).unwrap_or_default(),
    }
}

/// A node's key: the finding when there is one, else the normalized text.
fn key(step: &AttackStep) -> String {
    match step.finding_id {
        Some(f) => format!("finding:{f}"),
        None => format!("step:{}", step.text.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase()),
    }
}

fn clip(s: &str, n: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= n { t.to_string() } else { format!("{}…", t.chars().take(n).collect::<String>()) }
}

impl Service {
    /// Records an attack path (2 to 12 steps). Steps that name a finding
    /// must name one that exists.
    pub fn attack_path_create(&self, actor: &Actor, p: NewAttackPath) -> Result<AttackPath> {
        let severity = p.severity.trim().to_ascii_lowercase();
        if !SEVERITIES.contains(&severity.as_str()) {
            return Err(ServiceError::Invalid(format!("severity must be one of {}", SEVERITIES.join(", "))));
        }
        if p.title.trim().is_empty() || p.impact.trim().is_empty() {
            return Err(ServiceError::Invalid("an attack path needs a title and an impact".into()));
        }
        if !(2..=MAX_STEPS).contains(&p.steps.len()) {
            return Err(ServiceError::Invalid(format!("an attack path has 2 to {MAX_STEPS} steps")));
        }
        let mut steps = Vec::new();
        for st in &p.steps {
            if st.text.trim().is_empty() {
                return Err(ServiceError::Invalid("every step needs text".into()));
            }
            if let Some(f) = st.finding_id {
                self.finding_get(f).map_err(|_| ServiceError::Invalid(format!("there is no finding {f}")))?;
            }
            steps.push(AttackStep { text: clip(&st.text, MAX_TEXT), ..st.clone() });
        }
        let now = pm_core::now_ms();
        let mut row = serde_json::Map::new();
        for (k, v) in [
            ("scan_id", json!(scan_of(actor))),
            ("title", json!(clip(&p.title, 200))),
            ("impact", json!(clip(&p.impact, 1000))),
            ("severity", json!(severity)),
            ("steps", json!(serde_json::to_string(&steps).unwrap_or_default())),
            ("actor", json!(actor.id())),
            ("created_ms", json!(now)),
        ] {
            row.insert(k.into(), v);
        }
        let id = self.store.write(|db| db.insert_row("attack_paths", &row))?;
        self.audit(&actor.id(), "attack_path_create", json!({ "id": id, "steps": steps.len() }), "allow")?;
        if let Some(scan) = scan_of(actor) {
            let _ = self.ai_scan_log(scan, "chain", &format!("attack path #{id}: {}", clip(&p.title, 160)));
        }
        Ok(decode(&self.store.read(|db| db.row("attack_paths", id))?.unwrap_or_default()))
    }

    /// Paths, newest first; only one scan's when `scan_id` is given.
    pub fn attack_path_list(&self, scan_id: Option<i64>) -> Result<Vec<AttackPath>> {
        let rows = match scan_id {
            Some(s) => self.store.read(|db| db.rows("attack_paths", Some(("scan_id", &json!(s))), 1000))?,
            None => self.store.read(|db| db.rows("attack_paths", None, 1000))?,
        };
        Ok(rows.iter().map(decode).collect())
    }

    /// Deletes a path (people only).
    pub fn attack_path_delete(&self, actor: &Actor, id: i64) -> Result<()> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only people delete attack paths".into()));
        }
        if !self.store.write(|db| db.delete_row("attack_paths", id))? {
            return Err(ServiceError::NotFound(format!("attack path {id}")));
        }
        self.audit(&actor.id(), "attack_path_delete", json!({ "id": id }), "allow")
    }

    /// The paths as one graph: shared steps become one node.
    pub fn attack_graph(&self, scan_id: Option<i64>) -> Result<AttackGraph> {
        let paths = self.attack_path_list(scan_id)?;
        let mut nodes: BTreeMap<String, GraphNode> = BTreeMap::new();
        let mut edges: BTreeMap<(String, String), Vec<i64>> = BTreeMap::new();
        let mut severity_of: BTreeMap<i64, Option<String>> = BTreeMap::new();
        for p in paths.iter().rev() {
            let mut prev: Option<String> = None;
            for (i, st) in p.steps.iter().enumerate() {
                let k = key(st);
                let severity = st.finding_id.and_then(|f| {
                    severity_of
                        .entry(f)
                        .or_insert_with(|| {
                            self.finding_get(f).ok().and_then(|v| v["severity"].as_str().map(str::to_string))
                        })
                        .clone()
                });
                let last = i + 1 == p.steps.len();
                let n = nodes.entry(k.clone()).or_insert_with(|| GraphNode {
                    id: k.clone(),
                    label: clip(&st.text, 80),
                    finding_id: st.finding_id,
                    severity,
                    depth: i,
                    impact: false,
                });
                n.depth = n.depth.max(i);
                n.impact |= last;
                if let Some(from) = prev.replace(k.clone())
                    && from != k
                {
                    let e = edges.entry((from, k)).or_default();
                    if !e.contains(&p.id) {
                        e.push(p.id);
                    }
                }
            }
        }
        let mut nodes: Vec<GraphNode> = nodes.into_values().collect();
        nodes.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.id.cmp(&b.id)));
        let edges = edges.into_iter().map(|((from, to), paths)| GraphEdge { from, to, paths }).collect();
        Ok(AttackGraph { nodes, edges, paths })
    }

    /// Markdown for the report: one section per path.
    pub(crate) fn attack_paths_markdown(&self, scan_id: Option<i64>) -> Result<String> {
        let paths = self.attack_path_list(scan_id)?;
        if paths.is_empty() {
            return Ok(String::new());
        }
        let mut md = String::from("## Attack paths\n\n");
        for p in paths.iter().rev() {
            md.push_str(&format!("### {} ({})\n\n", p.title, p.severity));
            for (i, st) in p.steps.iter().enumerate() {
                let refs: Vec<String> =
                    [st.finding_id.map(|f| format!("finding #{f}")), st.exchange_id.map(|e| format!("exchange #{e}"))]
                        .into_iter()
                        .flatten()
                        .collect();
                let refs = if refs.is_empty() { String::new() } else { format!(" ({})", refs.join(", ")) };
                md.push_str(&format!("{}. {}{refs}\n", i + 1, st.text));
            }
            md.push_str(&format!("\n**Impact:** {}\n\n", p.impact));
        }
        Ok(md)
    }
}
