//! Organizer: exchanges kept aside to come back to, each with a status and
//! a note. It only stores references; nothing is sent.

use pm_core::now_ms;
use pm_policy::Actor;
use pm_store::{ExchangeSummary, Row};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, Service, ServiceError};

/// Statuses an item can have.
pub const ORGANIZER_STATUSES: &[&str] = &["new", "in_progress", "postponed", "done", "ignored"];
const MAX_ITEMS: u64 = 20_000;
const MAX_NOTE: usize = 10_000;

#[derive(Debug, Clone, Serialize)]
pub struct OrganizerItem {
    pub id: i64,
    pub exchange_id: i64,
    pub status: String,
    pub note: String,
    pub actor: String,
    pub created_ms: i64,
    pub updated_ms: i64,
    /// The exchange as it is now (missing if it was deleted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exchange: Option<ExchangeSummary>,
}

/// Changes to an item; unset fields stay as they are.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OrganizerUpdate {
    pub status: Option<String>,
    pub note: Option<String>,
}

fn check_status(s: &str) -> Result<()> {
    if ORGANIZER_STATUSES.contains(&s) {
        Ok(())
    } else {
        Err(ServiceError::Invalid(format!("status must be one of {}", ORGANIZER_STATUSES.join(", "))))
    }
}

fn check_note(n: &str) -> Result<()> {
    if n.len() > MAX_NOTE {
        return Err(ServiceError::Invalid(format!("note is longer than {MAX_NOTE} bytes")));
    }
    Ok(())
}

impl Service {
    fn organizer_item(&self, row: &Row, actor: &Actor) -> OrganizerItem {
        let s = |k: &str| row.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let n = |k: &str| row.get(k).and_then(Value::as_i64).unwrap_or_default();
        let exchange_id = n("exchange_id");
        let mut exchange = self.store.read(|db| db.get_exchange(exchange_id)).ok().flatten().map(|e| e.summary);
        if let (Some(r), Some(e)) = (self.redactor_for(actor), exchange.as_mut()) {
            e.path = r.redact(&e.path);
        }
        OrganizerItem {
            id: n("id"),
            exchange_id,
            status: s("status"),
            note: s("note"),
            actor: s("actor"),
            created_ms: n("created_ms"),
            updated_ms: n("updated_ms"),
            exchange,
        }
    }

    /// Puts an exchange in the Organizer (audited).
    pub fn organizer_add(&self, actor: &Actor, exchange_id: i64, note: &str) -> Result<OrganizerItem> {
        check_note(note)?;
        if self.store.read(|db| db.get_exchange(exchange_id))?.is_none() {
            return Err(ServiceError::NotFound(format!("exchange {exchange_id}")));
        }
        if self.store.read(|db| db.count_rows("organizer", None))? >= MAX_ITEMS {
            return Err(ServiceError::Invalid(format!("the Organizer holds at most {MAX_ITEMS} items")));
        }
        let now = now_ms();
        let mut row = Row::new();
        row.insert("exchange_id".into(), json!(exchange_id));
        row.insert("status".into(), json!("new"));
        row.insert("note".into(), json!(note));
        row.insert("actor".into(), json!(actor.id()));
        row.insert("created_ms".into(), json!(now));
        row.insert("updated_ms".into(), json!(now));
        let id = self.store.write(|db| db.insert_row("organizer", &row))?;
        self.audit(&actor.id(), "organizer_add", json!({ "id": id, "exchange_id": exchange_id }), "allow")?;
        row.insert("id".into(), json!(id));
        Ok(self.organizer_item(&row, actor))
    }

    /// Items, newest first, optionally only those with `status`.
    pub fn organizer_list(&self, actor: &Actor, status: Option<&str>) -> Result<Vec<OrganizerItem>> {
        if let Some(s) = status {
            check_status(s)?;
        }
        let filter = status.map(|s| json!(s));
        let rows =
            self.store.read(|db| db.rows("organizer", filter.as_ref().map(|v| ("status", v)), MAX_ITEMS as usize))?;
        Ok(rows.iter().map(|r| self.organizer_item(r, actor)).collect())
    }

    /// Changes an item's status or note (audited).
    pub fn organizer_update(&self, actor: &Actor, id: i64, u: &OrganizerUpdate) -> Result<OrganizerItem> {
        let mut changes = Row::new();
        if let Some(s) = &u.status {
            check_status(s)?;
            changes.insert("status".into(), json!(s));
        }
        if let Some(n) = &u.note {
            check_note(n)?;
            changes.insert("note".into(), json!(n));
        }
        changes.insert("updated_ms".into(), json!(now_ms()));
        if !self.store.write(|db| db.update_row("organizer", id, &changes))? {
            return Err(ServiceError::NotFound(format!("organizer item {id}")));
        }
        self.audit(&actor.id(), "organizer_update", json!({ "id": id, "status": u.status }), "allow")?;
        let row = self
            .store
            .read(|db| db.row("organizer", id))?
            .ok_or_else(|| ServiceError::NotFound(format!("organizer item {id}")))?;
        Ok(self.organizer_item(&row, actor))
    }

    /// Removes an item (the exchange stays in history; audited).
    pub fn organizer_delete(&self, actor: &Actor, id: i64) -> Result<()> {
        if !self.store.write(|db| db.delete_row("organizer", id))? {
            return Err(ServiceError::NotFound(format!("organizer item {id}")));
        }
        self.audit(&actor.id(), "organizer_delete", json!({ "id": id }), "allow")?;
        Ok(())
    }
}
