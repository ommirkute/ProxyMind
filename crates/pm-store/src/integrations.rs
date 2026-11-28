//! Delivery log of integrations (roadmap 3.5): one row per send to Jira, GitHub, GitLab, Slack or a webhook.
//!
//! A row says what was attempted and how it ended (status, HTTP status, attempts, the host). It never holds a body,
//! a header or a secret; `detail` is a short note written by `pm-service` (an issue key, or why it failed).

use anyhow::Result;
use rusqlite::params;
use serde::Serialize;

use crate::Store;

/// Most rows kept per integration.
pub const KEEP_DELIVERIES: usize = 200;

/// A delivery to insert.
#[derive(Debug, Clone, Default)]
pub struct NewDelivery {
    pub integration: String,
    pub ts_ms: i64,
    /// `event` (a notification), `issue` (a created or updated issue) or `test`.
    pub kind: String,
    /// The event name (`finding_proven`, ...), or `create_issue` / `update_issue` / `test`.
    pub event: String,
    pub finding_id: Option<i64>,
    /// `ok`, `failed` or `skipped` (rate limited, disabled).
    pub status: String,
    pub http_status: Option<u16>,
    pub attempts: u32,
    pub host: String,
    pub detail: String,
    pub actor: String,
}

/// One stored delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
pub struct DeliveryRow {
    pub id: i64,
    pub integration: String,
    pub ts_ms: i64,
    pub kind: String,
    pub event: String,
    pub finding_id: Option<i64>,
    pub status: String,
    pub http_status: Option<u16>,
    pub attempts: u32,
    pub host: String,
    pub detail: String,
    pub actor: String,
}

const COLS: &str =
    "id, integration, ts_ms, kind, event, finding_id, status, http_status, attempts, host, detail, actor";

fn row_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<DeliveryRow> {
    Ok(DeliveryRow {
        id: r.get(0)?,
        integration: r.get(1)?,
        ts_ms: r.get(2)?,
        kind: r.get(3)?,
        event: r.get(4)?,
        finding_id: r.get(5)?,
        status: r.get(6)?,
        http_status: r.get::<_, Option<i64>>(7)?.and_then(|n| u16::try_from(n).ok()),
        attempts: r.get::<_, i64>(8)?.max(0) as u32,
        host: r.get(9)?,
        detail: r.get(10)?,
        actor: r.get(11)?,
    })
}

impl Store {
    /// Stores a delivery and trims that integration's log to the newest [`KEEP_DELIVERIES`] rows.
    pub fn insert_delivery(&mut self, d: &NewDelivery) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO integration_deliveries
                 (integration, ts_ms, kind, event, finding_id, status, http_status, attempts, host, detail, actor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                d.integration,
                d.ts_ms,
                d.kind,
                d.event,
                d.finding_id,
                d.status,
                d.http_status.map(i64::from),
                i64::from(d.attempts),
                d.host,
                d.detail,
                d.actor
            ],
        )?;
        let id = self.conn.last_insert_rowid();
        self.conn.execute(
            "DELETE FROM integration_deliveries WHERE integration = ?1 AND id <=
                 (SELECT id FROM integration_deliveries WHERE integration = ?1 ORDER BY id DESC LIMIT 1 OFFSET ?2)",
            params![d.integration, KEEP_DELIVERIES as i64],
        )?;
        Ok(id)
    }

    /// Deliveries, newest first; of one integration or all.
    pub fn list_deliveries(&self, integration: Option<&str>, limit: usize) -> Result<Vec<DeliveryRow>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {COLS} FROM integration_deliveries WHERE (?1 IS NULL OR integration = ?1) ORDER BY id DESC LIMIT ?2"
        ))?;
        let rows = stmt.query_map(params![integration, limit.clamp(1, 1000) as i64], row_of)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The newest failed delivery of an integration that is newer than its newest successful one (the "last
    /// error"); `None` when the last delivery worked or there is none.
    pub fn last_delivery_error(&self, integration: &str) -> Result<Option<DeliveryRow>> {
        let newest = self.list_deliveries(Some(integration), 1)?;
        Ok(newest.into_iter().next().filter(|d| d.status == "failed"))
    }

    /// Deletes an integration's log (when it is deleted).
    pub fn delete_deliveries_of(&mut self, integration: &str) -> Result<usize> {
        Ok(self.conn.execute("DELETE FROM integration_deliveries WHERE integration = ?1", [integration])?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(name: &str, status: &str, n: i64) -> NewDelivery {
        NewDelivery {
            integration: name.into(),
            ts_ms: n,
            kind: "event".into(),
            event: "finding_proven".into(),
            status: status.into(),
            attempts: 1,
            host: "hooks.example".into(),
            actor: "integration:test".into(),
            ..Default::default()
        }
    }

    #[test]
    fn log_is_per_integration_trimmed_and_reports_the_last_error() {
        let mut s = Store::open_in_memory().unwrap();
        for i in 0..(KEEP_DELIVERIES as i64 + 20) {
            s.insert_delivery(&d("a", "ok", i)).unwrap();
        }
        s.insert_delivery(&d("b", "failed", 1)).unwrap();
        assert_eq!(s.list_deliveries(Some("a"), 1000).unwrap().len(), KEEP_DELIVERIES);
        assert_eq!(s.list_deliveries(Some("a"), 1).unwrap()[0].ts_ms, KEEP_DELIVERIES as i64 + 19);
        assert_eq!(s.list_deliveries(None, 1000).unwrap().len(), KEEP_DELIVERIES + 1);
        assert!(s.last_delivery_error("a").unwrap().is_none());
        assert_eq!(s.last_delivery_error("b").unwrap().unwrap().status, "failed");
        s.insert_delivery(&d("b", "ok", 2)).unwrap();
        assert!(s.last_delivery_error("b").unwrap().is_none(), "a later success clears it");
        assert_eq!(s.delete_deliveries_of("a").unwrap(), KEEP_DELIVERIES);
    }
}
