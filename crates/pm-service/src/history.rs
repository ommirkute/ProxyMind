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
        let mut rows = self.store.lock().search_exchanges(filter)?;
        if let Some(r) = self.redactor_for(actor) {
            for row in &mut rows {
                row.path = r.redact(&row.path);
            }
        }
        let next_before_id = (rows.len() == limit).then(|| rows.last().map(|r| r.id)).flatten();
        Ok(ExchangePage { exchanges: rows, next_before_id })
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
