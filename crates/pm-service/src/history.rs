//! Reading history: search and token-budgeted views.

use pm_ai::{ExchangeView, View, render_exchange};
use pm_policy::Actor;
use pm_store::{ExchangeSummary, HistoryFilter};
use pm_tools::hql;
use serde::Serialize;

use crate::{Result, Service, ServiceError};

/// One page of history search results.
#[derive(Debug, Clone, Serialize)]
pub struct ExchangePage {
    pub exchanges: Vec<ExchangeSummary>,
    /// Pass as `before_id` to get the next (older) page, if there may be more.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before_id: Option<i64>,
    /// With a query: how many exchanges were looked at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned: Option<usize>,
}

/// How long one query page may take before it returns what it has.
const QUERY_BUDGET: std::time::Duration = std::time::Duration::from_millis(1500);

/// Bytes for a query, loaded on first use.
struct Lazy<'a> {
    svc: &'a Service,
    actor: &'a Actor,
    row: &'a ExchangeSummary,
    loaded: Option<(Vec<u8>, Option<Vec<u8>>)>,
    scope: Option<bool>,
}

impl Lazy<'_> {
    fn load(&mut self) -> &(Vec<u8>, Option<Vec<u8>>) {
        if self.loaded.is_none() {
            let ex = self.svc.store.read(|db| db.get_exchange(self.row.id)).ok().flatten();
            let redactor = self.svc.redactor_for(self.actor);
            let prep = |raw: &[u8]| {
                let hay = crate::search::searchable(raw);
                match redactor {
                    Some(r) => r.redact(&String::from_utf8_lossy(&hay)).into_bytes(),
                    None => hay,
                }
            };
            self.loaded = Some(match ex {
                Some(ex) => (prep(&ex.request), ex.response.as_deref().map(prep)),
                None => (Vec::new(), None),
            });
        }
        self.loaded.as_ref().expect("loaded above")
    }
}

impl hql::Fetch for Lazy<'_> {
    fn request(&mut self) -> &[u8] {
        &self.load().0
    }

    fn response(&mut self) -> Option<&[u8]> {
        self.load().1.as_deref()
    }

    fn in_scope(&mut self) -> bool {
        let (svc, r) = (self.svc, self.row);
        *self.scope.get_or_insert_with(|| {
            pm_policy::Target::from_parts(&r.scheme, &r.host, r.port, &r.path)
                .is_ok_and(|t| svc.policy.scope_check(&t).is_ok())
        })
    }
}

fn meta(r: &ExchangeSummary) -> hql::Meta<'_> {
    hql::Meta {
        id: r.id,
        scheme: &r.scheme,
        host: &r.host,
        port: r.port,
        method: &r.method,
        path: &r.path,
        status: r.status,
        req_len: r.req_len,
        resp_len: r.resp_len,
        duration_ms: r.duration_ms,
        source: &r.source,
        actor: &r.actor_id,
        identity: r.identity.as_deref(),
        comment: r.comment.as_deref(),
        highlight: r.highlight.as_deref(),
        error: r.error.as_deref(),
    }
}

impl Service {
    /// Searches history (a `read` action: always allowed, not audited).
    pub fn history_search(&self, actor: &Actor, filter: &HistoryFilter) -> Result<ExchangePage> {
        let limit = filter.limit.unwrap_or(50).clamp(1, 500);
        if let Some(q) = filter.q.as_deref().filter(|q| !q.trim().is_empty()) {
            let query = hql::Query::parse(q).map_err(|e| ServiceError::Invalid(format!("query: {e}")))?;
            return self.query_rows(actor, filter, &query, limit);
        }
        let mut rows = if filter.in_scope == Some(true) {
            self.in_scope_rows(filter, limit)?
        } else {
            self.store.read(|db| db.search_exchanges(filter))?
        };
        if let Some(r) = self.redactor_for(actor) {
            for row in &mut rows {
                row.path = r.redact(&row.path);
            }
        }
        let next_before_id = (rows.len() == limit).then(|| rows.last().map(|r| r.id)).flatten();
        Ok(ExchangePage { exchanges: rows, next_before_id, scanned: None })
    }

    /// Rows matching a query (and the other filters), newest first. Stops
    /// after `limit` matches or the time budget; `next_before_id` then says
    /// where to continue.
    ///
    /// Content terms use the full-text index as a pre-filter (`query_candidates`): only rows it
    /// names are loaded and evaluated, and `Query::matches` still decides each of them.
    fn query_rows(
        &self,
        actor: &Actor,
        filter: &HistoryFilter,
        query: &hql::Query,
        limit: usize,
    ) -> Result<ExchangePage> {
        let deadline = std::time::Instant::now() + QUERY_BUDGET;
        let mut f = filter.clone();
        f.q = None;
        f.limit = Some(500);
        let candidates = self.query_candidates(actor, filter, query)?;
        let (mut out, mut scanned, mut last, mut more) = (Vec::new(), 0usize, None, true);
        let eval = |row: &ExchangeSummary| {
            let mut lazy = Lazy { svc: self, actor, row, loaded: None, scope: None };
            (filter.in_scope != Some(true) || hql::Fetch::in_scope(&mut lazy)) && query.matches(&meta(row), &mut lazy)
        };
        match candidates {
            // Paging back: fetch the candidates' summaries, 500 at a time, newest first.
            Some(ids) if filter.after_id.is_none() => {
                more = false;
                let chunks: Vec<&[i64]> = ids.chunks(500).collect();
                'chunks: for (i, chunk) in chunks.iter().enumerate() {
                    f.ids = Some(chunk.to_vec());
                    let page = self.store.read(|db| db.search_exchanges(&f))?;
                    for row in &page {
                        scanned += 1;
                        last = Some(row.id);
                        if eval(row) {
                            out.push(row.clone());
                        }
                        if out.len() >= limit || std::time::Instant::now() > deadline {
                            let at_end = i + 1 == chunks.len() && Some(row.id) == page.last().map(|r| r.id);
                            more = !(out.len() < limit && at_end);
                            break 'chunks;
                        }
                    }
                }
            }
            // Otherwise pages of 500 rows by metadata. With `after_id` that is one page (as always);
            // rows the index rules out are skipped without loading them.
            _ => {
                let only: Option<std::collections::HashSet<i64>> = candidates.map(|ids| ids.into_iter().collect());
                'pages: while more {
                    let page = self.store.read(|db| db.search_exchanges(&f))?;
                    more = page.len() == 500 && filter.after_id.is_none();
                    for row in &page {
                        scanned += 1;
                        last = Some(row.id);
                        if only.as_ref().is_none_or(|s| s.contains(&row.id)) && eval(row) {
                            out.push(row.clone());
                        }
                        if out.len() >= limit || std::time::Instant::now() > deadline {
                            more = !(out.len() < limit && Some(row.id) == page.last().map(|r| r.id) && !more);
                            break 'pages;
                        }
                    }
                    f.before_id = last;
                }
            }
        }
        if let Some(r) = self.redactor_for(actor) {
            for row in &mut out {
                row.path = r.redact(&row.path);
            }
        }
        let next_before_id = if more { last } else { None };
        Ok(ExchangePage { exchanges: out, next_before_id, scanned: Some(scanned) })
    }

    /// Ids (newest first, within `before_id`/`after_id`) that may match the query, from the full-text
    /// index; None when every row has to be looked at: the query has no content term every match needs,
    /// the caller already limited `ids`, a needle is too short or too common for the index, or (for
    /// agents) one could match a redaction placeholder, which the index never saw.
    fn query_candidates(&self, actor: &Actor, filter: &HistoryFilter, query: &hql::Query) -> Result<Option<Vec<i64>>> {
        let Some(needles) = query.required_literals().filter(|_| filter.ids.is_none()) else { return Ok(None) };
        if self.redactor_for(actor).is_some() && needles.iter().any(|n| crate::search::may_match_placeholder(n, false))
        {
            return Ok(None);
        }
        let mut ids: Vec<i64> = Vec::new();
        for n in &needles {
            let Some(found) = self.store.read(|db| db.text_candidates(n))? else { return Ok(None) };
            ids.extend(found);
        }
        ids.sort_unstable_by(|a, b| b.cmp(a));
        ids.dedup();
        let (before, after) = (filter.before_id, filter.after_id);
        ids.retain(|&id| before.is_none_or(|b| id < b) && after.is_none_or(|a| id > a));
        Ok(Some(ids))
    }

    /// Rows whose targets are in scope, reading pages until `limit` are found
    /// (at most 20 000 rows looked at).
    fn in_scope_rows(&self, filter: &HistoryFilter, limit: usize) -> Result<Vec<ExchangeSummary>> {
        let mut f = filter.clone();
        f.limit = Some(500);
        let mut out = Vec::new();
        for _ in 0..40 {
            let page = self.store.read(|db| db.search_exchanges(&f))?;
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
        let mut row = self.store.write(|store| -> Result<_> {
            if !store.annotate(id, highlight, comment).map_err(|e| ServiceError::Invalid(format!("{e:#}")))? {
                return Err(ServiceError::NotFound(format!("exchange {id}")));
            }
            Ok(store.get_exchange(id)?.ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?.summary)
        })?;
        if let Some(r) = self.redactor_for(actor) {
            row.path = r.redact(&row.path);
        }
        Ok(row)
    }

    /// One exchange as a view sized for a model or a UI.
    pub fn exchange_get(&self, actor: &Actor, id: i64, view: View, max_tokens: usize) -> Result<ExchangeView> {
        let ex = self
            .store
            .read(|db| db.get_exchange(id))?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
        Ok(render_exchange(&ex, view, max_tokens, self.redactor_for(actor)))
    }

    /// Raw bytes of an exchange's request, with secrets replaced for agents.
    pub fn exchange_raw_request(&self, actor: &Actor, id: i64) -> Result<String> {
        let ex = self
            .store
            .read(|db| db.get_exchange(id))?
            .ok_or_else(|| ServiceError::NotFound(format!("exchange {id}")))?;
        let text = String::from_utf8_lossy(&ex.request).into_owned();
        Ok(match self.redactor_for(actor) {
            Some(r) => r.redact(&text),
            None => text,
        })
    }
}

/// Most bytes of UI state kept per key (e.g. Replay tabs).
pub const UI_STATE_MAX: usize = 8 * 1024 * 1024;

impl Service {
    /// Saved UI state for this project (e.g. Replay tabs), if any.
    pub fn ui_state_get(&self, key: &str) -> Result<serde_json::Value> {
        check_ui_key(key)?;
        Ok(self
            .store
            .read(|db| db.get_setting(&format!("ui:{key}")))?
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
        self.store.write(|db| db.set_setting(&format!("ui:{key}"), &text))?;
        Ok(())
    }
}

fn check_ui_key(key: &str) -> Result<()> {
    let ok =
        !key.is_empty() && key.len() <= 40 && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if ok { Ok(()) } else { Err(ServiceError::Invalid(format!("bad UI state key {key:?}"))) }
}
