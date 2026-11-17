//! Workflow runs (roadmap 2.2). A workflow's definition is a project setting; each run of it is a row here, so the
//! history survives a restart and a run that paused for an approval can be resumed later.
//!
//! The store keeps the run's JSON as written by `pm-service` (steps, variables, sent exchange ids) and a few
//! columns to list and find runs by. It never looks inside `record`.

use anyhow::Result;
use rusqlite::{OptionalExtension, params};

use crate::Store;

/// A run to insert.
#[derive(Debug, Clone, Default)]
pub struct NewWorkflowRun {
    pub workflow_id: i64,
    pub workflow_name: String,
    pub actor: String,
    /// How it started: `manual`, `exchange` or `fuzzer`.
    pub trigger: String,
    pub start_exchange: Option<i64>,
    pub status: String,
    pub started_ms: i64,
    pub record: String,
}

/// One stored run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowRunRow {
    pub id: i64,
    pub workflow_id: i64,
    pub workflow_name: String,
    pub actor: String,
    pub trigger: String,
    pub start_exchange: Option<i64>,
    pub status: String,
    pub started_ms: i64,
    pub duration_ms: Option<i64>,
    /// The approval a paused run waits for.
    pub approval_id: Option<String>,
    pub record: String,
}

const COLS: &str = "id, workflow_id, workflow_name, actor, trigger, start_exchange, status, started_ms, duration_ms, \
                    approval_id, record";

fn row_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<WorkflowRunRow> {
    Ok(WorkflowRunRow {
        id: r.get(0)?,
        workflow_id: r.get(1)?,
        workflow_name: r.get(2)?,
        actor: r.get(3)?,
        trigger: r.get(4)?,
        start_exchange: r.get(5)?,
        status: r.get(6)?,
        started_ms: r.get(7)?,
        duration_ms: r.get(8)?,
        approval_id: r.get(9)?,
        record: r.get(10)?,
    })
}

impl Store {
    pub fn insert_workflow_run(&mut self, r: &NewWorkflowRun) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO workflow_runs (workflow_id, workflow_name, actor, trigger, start_exchange, status, started_ms,
                                        record)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                r.workflow_id,
                r.workflow_name,
                r.actor,
                r.trigger,
                r.start_exchange,
                r.status,
                r.started_ms,
                r.record
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Writes a run's new state.
    pub fn update_workflow_run(
        &mut self,
        id: i64,
        status: &str,
        duration_ms: Option<i64>,
        approval_id: Option<&str>,
        record: &str,
    ) -> Result<()> {
        self.conn.execute(
            "UPDATE workflow_runs SET status = ?2, duration_ms = ?3, approval_id = ?4, record = ?5 WHERE id = ?1",
            params![id, status, duration_ms, approval_id, record],
        )?;
        Ok(())
    }

    pub fn get_workflow_run(&self, id: i64) -> Result<Option<WorkflowRunRow>> {
        Ok(self.conn.query_row(&format!("SELECT {COLS} FROM workflow_runs WHERE id = ?1"), [id], row_of).optional()?)
    }

    /// Runs, newest first; of one workflow or all.
    pub fn list_workflow_runs(&self, workflow_id: Option<i64>, limit: usize) -> Result<Vec<WorkflowRunRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLS} FROM workflow_runs WHERE (?1 IS NULL OR workflow_id = ?1) ORDER BY id DESC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![workflow_id, limit.clamp(1, 1000) as i64], row_of)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The run that waits for this approval.
    pub fn find_workflow_run_by_approval(&self, approval_id: &str) -> Result<Option<WorkflowRunRow>> {
        Ok(self
            .conn
            .query_row(
                &format!("SELECT {COLS} FROM workflow_runs WHERE approval_id = ?1 ORDER BY id DESC LIMIT 1"),
                [approval_id],
                row_of,
            )
            .optional()?)
    }

    /// Keeps the newest `keep` runs and deletes the rest. Returns how many were deleted.
    pub fn prune_workflow_runs(&mut self, keep: usize) -> Result<usize> {
        Ok(self.conn.execute(
            "DELETE FROM workflow_runs WHERE id <= (SELECT id FROM workflow_runs ORDER BY id DESC LIMIT 1 OFFSET ?1)",
            [keep as i64],
        )?)
    }

    /// Deletes every run of a workflow (when the workflow is deleted).
    pub fn delete_workflow_runs_of(&mut self, workflow_id: i64) -> Result<usize> {
        Ok(self.conn.execute("DELETE FROM workflow_runs WHERE workflow_id = ?1", [workflow_id])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(wf: i64, status: &str) -> NewWorkflowRun {
        NewWorkflowRun {
            workflow_id: wf,
            workflow_name: format!("wf{wf}"),
            actor: "human:t".into(),
            trigger: "manual".into(),
            start_exchange: Some(3),
            status: status.into(),
            started_ms: 1000,
            record: "{}".into(),
        }
    }

    #[test]
    fn runs_are_listed_found_by_approval_and_pruned_to_the_newest() {
        let mut s = Store::open_in_memory().unwrap();
        let a = s.insert_workflow_run(&run(1, "running")).unwrap();
        s.update_workflow_run(a, "pending_approval", Some(5), Some("ap_1"), "{\"x\":1}").unwrap();
        for _ in 0..4 {
            s.insert_workflow_run(&run(2, "ok")).unwrap();
        }
        let got = s.get_workflow_run(a).unwrap().unwrap();
        assert_eq!(
            (got.status.as_str(), got.duration_ms, got.approval_id.as_deref()),
            ("pending_approval", Some(5), Some("ap_1"))
        );
        assert_eq!(got.record, "{\"x\":1}");
        assert_eq!(s.find_workflow_run_by_approval("ap_1").unwrap().unwrap().id, a);
        assert!(s.find_workflow_run_by_approval("nope").unwrap().is_none());
        assert_eq!(s.list_workflow_runs(Some(2), 10).unwrap().len(), 4);
        assert_eq!(s.list_workflow_runs(None, 3).unwrap().len(), 3);
        assert_eq!(s.prune_workflow_runs(3).unwrap(), 2, "the oldest two go");
        assert!(s.get_workflow_run(a).unwrap().is_none());
        assert_eq!(s.list_workflow_runs(None, 10).unwrap().len(), 3);
        assert_eq!(s.delete_workflow_runs_of(2).unwrap(), 3);
    }
}
