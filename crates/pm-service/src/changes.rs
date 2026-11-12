//! What changed since the last test: saved snapshots of the app model
//! (operations, parameters, statuses, whether they need credentials) and a
//! comparison with the current model, so a retest starts from the new and
//! changed endpoints and the earlier findings on them.
//!
//! Operations are matched by method and path template, not origin, so a
//! snapshot taken on staging compares with a production engagement.

use std::collections::{BTreeMap, BTreeSet};

use pm_policy::{Actor, ActorKind};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError};

/// The parts of an operation a snapshot keeps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpShape {
    pub method: String,
    pub template: String,
    pub origin: String,
    pub kind: String,
    pub params: BTreeSet<String>,
    pub statuses: BTreeSet<u16>,
    pub authenticated: bool,
}

impl OpShape {
    fn key(&self) -> String {
        format!("{} {}", self.method, self.template)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotInfo {
    pub id: i64,
    pub name: String,
    pub created_ms: i64,
    pub actor: String,
    pub operations: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct OpChange {
    /// `METHOD /template`
    pub operation: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub params_added: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub params_removed: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub statuses_added: Vec<u16>,
    /// "now sent with credentials" / "now sent without credentials"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetestItem {
    pub operation: String,
    pub why: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelChanges {
    /// What the current model is compared with.
    pub since: String,
    pub added: Vec<OpShape>,
    pub removed: Vec<OpShape>,
    pub changed: Vec<OpChange>,
    pub unchanged: usize,
    /// Where a retest should start: new and changed operations, and earlier
    /// findings on changed or removed ones.
    pub retest: Vec<RetestItem>,
}

fn template_fits(template: &str, path: &str) -> bool {
    let p: Vec<&str> = path.split(['?', '#']).next().unwrap_or("").trim_end_matches('/').split('/').collect();
    let t: Vec<&str> = template.trim_end_matches('/').split('/').collect();
    t.len() == p.len() && t.iter().zip(&p).all(|(a, b)| a == b || (a.starts_with('{') && a.ends_with('}')))
}

impl Service {
    /// The current model's operations, as a snapshot keeps them.
    pub fn model_shapes(&self) -> Result<Vec<OpShape>> {
        Ok(self
            .model()?
            .operations
            .iter()
            .map(|o| OpShape {
                method: o.method.clone(),
                template: o.template.clone(),
                origin: o.origin.clone(),
                kind: o.kind.clone(),
                params: o.query_params.iter().chain(&o.body_params).cloned().collect(),
                statuses: o.statuses.keys().copied().collect(),
                authenticated: o.authenticated,
            })
            .collect())
    }

    /// Saves the current model under `name` (people only).
    pub fn model_snapshot_save(&self, actor: &Actor, name: &str) -> Result<SnapshotInfo> {
        if actor.kind != ActorKind::Human {
            return Err(ServiceError::Invalid("only people save model snapshots".into()));
        }
        let name = name.trim();
        if name.is_empty() || name.len() > 100 {
            return Err(ServiceError::Invalid("give the snapshot a name (up to 100 characters)".into()));
        }
        let shapes = self.model_shapes()?;
        let mut row = serde_json::Map::new();
        for (k, v) in [
            ("name", json!(name)),
            ("created_ms", json!(pm_core::now_ms())),
            ("actor", json!(actor.id())),
            ("data", json!(serde_json::to_string(&shapes).unwrap_or_default())),
        ] {
            row.insert(k.into(), v);
        }
        let id = self.store.lock().insert_row("model_snapshots", &row)?;
        self.audit(&actor.id(), "model_snapshot", json!({ "id": id, "name": name, "operations": shapes.len() }), "ok")?;
        Ok(SnapshotInfo {
            id,
            name: name.into(),
            created_ms: pm_core::now_ms(),
            actor: actor.id(),
            operations: shapes.len(),
        })
    }

    pub fn model_snapshot_list(&self) -> Result<Vec<SnapshotInfo>> {
        Ok(self
            .store
            .lock()
            .rows("model_snapshots", None, 200)?
            .iter()
            .map(|r| {
                let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
                let ops: Vec<OpShape> = serde_json::from_str(&s("data")).unwrap_or_default();
                SnapshotInfo {
                    id: r.get("id").and_then(Value::as_i64).unwrap_or_default(),
                    name: s("name"),
                    created_ms: r.get("created_ms").and_then(Value::as_i64).unwrap_or_default(),
                    actor: s("actor"),
                    operations: ops.len(),
                }
            })
            .collect())
    }

    fn snapshot_shapes(&self, id: i64) -> Result<(String, Vec<OpShape>)> {
        let r = self
            .store
            .lock()
            .row("model_snapshots", id)?
            .ok_or_else(|| ServiceError::NotFound(format!("snapshot {id}")))?;
        let s = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        Ok((s("name"), serde_json::from_str(&s("data")).unwrap_or_default()))
    }

    /// What changed since snapshot `id`.
    pub fn model_changes(&self, id: i64) -> Result<ModelChanges> {
        let (name, before) = self.snapshot_shapes(id)?;
        self.model_changes_from(&format!("snapshot \"{name}\""), &before)
    }

    /// What changed compared with `before` (e.g. another project's
    /// `model_shapes`), described as `since`.
    pub fn model_changes_from(&self, since: &str, before: &[OpShape]) -> Result<ModelChanges> {
        let merge = |ops: &[OpShape]| {
            let mut m: BTreeMap<String, OpShape> = BTreeMap::new();
            for o in ops {
                m.entry(o.key())
                    .and_modify(|x| {
                        x.params.extend(o.params.iter().cloned());
                        x.statuses.extend(o.statuses.iter().copied());
                        x.authenticated |= o.authenticated;
                    })
                    .or_insert_with(|| o.clone());
            }
            m
        };
        let (old, new) = (merge(before), merge(&self.model_shapes()?));
        let added: Vec<OpShape> = new.iter().filter(|(k, _)| !old.contains_key(*k)).map(|(_, v)| v.clone()).collect();
        let removed: Vec<OpShape> = old.iter().filter(|(k, _)| !new.contains_key(*k)).map(|(_, v)| v.clone()).collect();
        let mut changed = Vec::new();
        let mut unchanged = 0;
        for (k, n) in &new {
            let Some(o) = old.get(k) else { continue };
            let c = OpChange {
                operation: k.clone(),
                params_added: n.params.difference(&o.params).cloned().collect(),
                params_removed: o.params.difference(&n.params).cloned().collect(),
                statuses_added: n.statuses.difference(&o.statuses).copied().collect(),
                auth: match (o.authenticated, n.authenticated) {
                    (false, true) => Some("now sent with credentials".into()),
                    (true, false) => Some("now sent without credentials".into()),
                    _ => None,
                },
                kind: (o.kind != n.kind).then(|| format!("{} → {}", o.kind, n.kind)),
            };
            if c.params_added.is_empty()
                && c.params_removed.is_empty()
                && c.statuses_added.is_empty()
                && c.auth.is_none()
                && c.kind.is_none()
            {
                unchanged += 1;
            } else {
                changed.push(c);
            }
        }
        // Where to start: new operations, changes, and earlier findings on what changed.
        let findings = self.finding_list(None)?;
        let on = |template: &str| -> Vec<i64> {
            findings
                .iter()
                .filter(|f| f["status"] != "false_positive")
                .filter(|f| {
                    url::Url::parse(f["url"].as_str().unwrap_or("")).is_ok_and(|u| template_fits(template, u.path()))
                })
                .filter_map(|f| f["id"].as_i64())
                .collect()
        };
        let mut retest = Vec::new();
        for a in &added {
            let why = if a.params.is_empty() {
                "new endpoint".to_string()
            } else {
                format!("new endpoint, parameters: {}", a.params.iter().cloned().collect::<Vec<_>>().join(", "))
            };
            retest.push(RetestItem { operation: a.key(), why, findings: vec![] });
        }
        for c in &changed {
            let mut why = Vec::new();
            if !c.params_added.is_empty() {
                why.push(format!("new parameters: {}", c.params_added.join(", ")));
            }
            if let Some(a) = &c.auth {
                why.push(a.clone());
            }
            if let Some(k) = &c.kind {
                why.push(format!("kind changed ({k})"));
            }
            if !c.statuses_added.is_empty() {
                why.push(format!("new statuses: {:?}", c.statuses_added));
            }
            if !c.params_removed.is_empty() {
                why.push(format!("parameters gone: {}", c.params_removed.join(", ")));
            }
            let template = c.operation.split_once(' ').map_or("", |(_, t)| t);
            retest.push(RetestItem { operation: c.operation.clone(), why: why.join("; "), findings: on(template) });
        }
        for r in &removed {
            let f = on(&r.template);
            if !f.is_empty() {
                retest.push(RetestItem {
                    operation: r.key(),
                    why: "gone from the app: check the earlier findings are really fixed".into(),
                    findings: f,
                });
            }
        }
        Ok(ModelChanges { since: since.into(), added, removed, changed, unchanged, retest })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_fit() {
        assert!(template_fits("/api/orders/{id}", "/api/orders/7"));
        assert!(!template_fits("/api/orders/{id}", "/api/orders"));
    }
}
