//! Reading history: search and token-budgeted views.

use pm_ai::{ExchangeView, View, render_exchange};
use pm_policy::Actor;
use pm_store::{ExchangeSummary, HistoryFilter};
use serde::Serialize;

use crate::{Result, Service, ServiceError};

/// One page of history search results.
#[derive(Debug, Clone, Serialize)]
pub struct ExchangePage {
    pub exchanges: Vec<ExchangeSummary>,
    /// Pass as `before_id` to get the next (older) page, if there may be more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before_id: Option<i64>,
}

impl Service {
    /// Searches history (a `read` action: always allowed, not audited).
    pub fn history_search(&self, actor: &Actor, filter: &HistoryFilter) -> Result<ExchangePage> {
        let limit = filter.limit.unwrap_or(50).clamp(1, 500);
        let mut rows = if filter.in_scope == Some(true) {
            self.in_scope_rows(filter, limit)?
        } else {
            self.store.lock().search_exchanges(filter)?
        };
        if let Some(r) = self.redactor_for(actor) {
            for row in &mut rows {
                row.path = r.redact(&row.path);
            }
        }
        let next_before_id = (rows.len() == limit).then(|| rows.last().map(|r| r.id)).flatten();
        Ok(ExchangePage { exchanges: rows, next_before_id })
    }

    /// Rows whose targets are in scope, reading pages until `limit` are found
    /// (at most 20 000 rows looked at).
    fn in_scope_rows(&self, filter: &HistoryFilter, limit: usize) -> Result<Vec<ExchangeSummary>> {
        let mut f = filter.clone();
        f.limit = Some(500);
        let mut out = Vec::new();
        for _ in 0..40 {
            let page = self.store.lock().search_exchanges(&f)?;
            let n = page.len();
            let last = page.last().map(|r| r.id);
            for r in page {
                let ok = pm_policy::Target::from_parts(&r.scheme, &r.host, r.port, &r.path)
                    .is_ok_and(|t| self.policy.scope_check(&t).is_ok());
                if ok && out.len() < limit {
                    out.push(r);
                }
            }
            if out.len() >= limit || n < 500 {
                break;
            }
            // Paging forward (after_id) keeps going up; otherwise go back in time.
            match (filter.after_id, last) {
                (Some(_), _) => break,
                (None, Some(l)) => f.before_id = Some(l),
                (None, None) => break,
            }
        }
        Ok(out)
    }

    /// Sets or clears an exchange's highlight and comment (shown in history to everyone).
    pub fn exchange_annotate(
        &self,
        actor: &Actor,
        id: i64,
        highlight: Option<&str>,
        comment: Option<&str>,
    ) -> Result<ExchangeSummary> {
        let mut store = self.store.lock();
        if !store.annotate(id, highlight, comment).map_err(|e| ServiceError::Invalid(format!("{e:#}")))? {
            return Err(ServiceError::NotFound(format!("exchange {id}")));
        }
        let mut row = store.get_exchange(id)?.ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?.summary;
        drop(store);
        if let Some(r) = self.redactor_for(actor) {
            row.path = r.redact(&row.path);
        }
        Ok(row)
    }

    /// One exchange as a view sized for a model or a UI.
    pub fn exchange_get(&self, actor: &Actor, id: i64, view: View, max_tokens: usize) -> Result<ExchangeView> {
        let ex = self.store.lock().get_exchange(id)?.ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
        Ok(render_exchange(&ex, view, max_tokens, self.redactor_for(actor)))
    }

    /// Raw bytes of an exchange's request, with secrets replaced for agents.
    pub fn exchange_raw_request(&self, actor: &Actor, id: i64) -> Result<String> {
        let ex = self.store.lock().get_exchange(id)?.ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
        let text = String::from_utf8_lossy(&ex.request).into_owned();
        Ok(match self.redactor_for(actor) {
            Some(r) => r.redact(&text),
            None => text,
        })
    }
}

/// Most bytes of UI state kept per key (e.g. Repeater tabs).
pub const UI_STATE_MAX: usize = 8 * 1024 * 1024;

impl Service {
    /// Saved UI state for this project (e.g. Repeater tabs), if any.
    pub fn ui_state_get(&self, key: &str) -> Result<serde_json::Value> {
        check_ui_key(key)?;
        Ok(self
            .store
            .lock()
            .get_setting(&format!("ui:{key}"))?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(serde_json::Value::Null))
    }

    /// Saves UI state for this project. People only: it's their workspace.
    pub fn ui_state_put(&self, actor: &Actor, key: &str, value: &serde_json::Value) -> Result<()> {
        check_ui_key(key)?;
        if actor.kind != pm_policy::ActorKind::Human {
            return Err(ServiceError::Invalid("only people have UI state".into()));
        }
        let text = value.to_string();
        if text.len() > UI_STATE_MAX {
            return Err(ServiceError::Invalid(format!("UI state larger than {} MB", UI_STATE_MAX / 1024 / 1024)));
        }
        self.store.lock().set_setting(&format!("ui:{key}"), &text)?;
        Ok(())
    }
}

fn check_ui_key(key: &str) -> Result<()> {
    let ok =
        !key.is_empty() && key.len() <= 40 && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok { Ok(()) } else { Err(ServiceError::Invalid(format!("bad UI state key {key:?}"))) }
}
