//! Project storage.
//!
//! One SQLite file per project. Request and response bytes are stored as
//! zstd-compressed blobs keyed by their blake3 hash, so identical bodies
//! (static files, repeated replays) are stored once.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;

/// Schema migrations, applied in order. Never edit a released entry;
/// add a new one instead.
const MIGRATIONS: &[&str] = &[
    r#"
CREATE TABLE blobs (
    hash      BLOB PRIMARY KEY,
    raw_len   INTEGER NOT NULL,
    zstd_data BLOB NOT NULL
) WITHOUT ROWID;

CREATE TABLE exchanges (
    id          INTEGER PRIMARY KEY,
    ts_ms       INTEGER NOT NULL,
    duration_ms INTEGER,
    source      TEXT NOT NULL,      -- proxy | replay | agent | scanner | plugin
    actor_id    TEXT NOT NULL,      -- e.g. human:local, agent:claude-1
    scheme      TEXT NOT NULL,
    host        TEXT NOT NULL,
    port        INTEGER NOT NULL,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    status      INTEGER,
    req_hash    BLOB NOT NULL REFERENCES blobs(hash),
    resp_hash   BLOB REFERENCES blobs(hash),
    req_len     INTEGER NOT NULL,
    resp_len    INTEGER,
    error       TEXT,
    tags        TEXT NOT NULL DEFAULT '[]',
    notes       TEXT
);
CREATE INDEX exchanges_host ON exchanges(host);
CREATE INDEX exchanges_ts ON exchanges(ts_ms);
"#,
    r#"
-- Append-only, hash-chained audit log (see pm-policy::audit).
CREATE TABLE audit_log (
    seq       INTEGER PRIMARY KEY,
    ts_ms     INTEGER NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    detail    TEXT NOT NULL,
    decision  TEXT NOT NULL,
    prev_hash BLOB NOT NULL,
    hash      BLOB NOT NULL
);
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"#,
    r#"
-- Actions waiting for (or decided by) a human. Shared between processes,
-- so an MCP server and a human's CLI or UI see the same queue.
CREATE TABLE approvals (
    id          TEXT PRIMARY KEY,
    created_ms  INTEGER NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    tier        TEXT NOT NULL,
    target      TEXT,
    summary     TEXT NOT NULL,
    params      TEXT NOT NULL,
    params_hash TEXT NOT NULL,
    status      TEXT NOT NULL,      -- pending | approved | denied | used
    decided_by  TEXT,
    decided_ms  INTEGER
);
CREATE INDEX approvals_status ON approvals(status);
"#,
    r#"
-- Project settings shared by every process, e.g. the rules of engagement.
CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#,
    r#"
-- Test identities (users/roles) and their credentials.
CREATE TABLE identities (
    name       TEXT PRIMARY KEY,
    role       TEXT NOT NULL,
    data       TEXT NOT NULL,      -- JSON: auth material, health check, login recipe
    created_by TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'unknown',  -- unknown | ok | logged_out
    updated_ms INTEGER NOT NULL
);
-- Which identity's credentials an exchange was sent with.
ALTER TABLE exchanges ADD COLUMN identity TEXT;
-- Results of authorization checks: one row per (exchange, identity) test.
CREATE TABLE authz_results (
    id            INTEGER PRIMARY KEY,
    exchange_id   INTEGER NOT NULL,
    method        TEXT NOT NULL,
    url           TEXT NOT NULL,
    identity      TEXT NOT NULL,
    verdict       TEXT NOT NULL,   -- denied | same_as_owner | allowed_different | inconclusive | error
    status        INTEGER,
    similarity    REAL,
    evidence_id   INTEGER,
    summary       TEXT NOT NULL,
    checked_by    TEXT NOT NULL,
    checked_ms    INTEGER NOT NULL
);
CREATE INDEX authz_results_exchange ON authz_results(exchange_id);
"#,
];

/// A stored test identity. `data` holds credentials: never show it to agents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityRow {
    pub name: String,
    pub role: String,
    pub data: String,
    pub created_by: String,
    pub status: String,
    pub updated_ms: i64,
}

/// One authorization-check result.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AuthzRow {
    pub id: i64,
    pub exchange_id: i64,
    pub method: String,
    pub url: String,
    pub identity: String,
    pub verdict: String,
    pub status: Option<u16>,
    pub similarity: Option<f64>,
    pub evidence_id: Option<i64>,
    pub summary: String,
    pub checked_by: String,
    pub checked_ms: i64,
}

/// An action waiting for, or decided by, a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalRow {
    pub id: String,
    pub created_ms: i64,
    pub actor: String,
    pub action: String,
    pub tier: String,
    /// URL the action targets, if any.
    pub target: Option<String>,
    pub summary: String,
    /// The exact parameters (JSON text) the approval covers.
    pub params: String,
    pub params_hash: String,
    pub status: String,
    pub decided_by: Option<String>,
    pub decided_ms: Option<i64>,
}

/// One audit log entry. Hashing and verification live in `pm-policy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditRecord {
    pub seq: i64,
    pub ts_ms: i64,
    pub actor: String,
    pub action: String,
    /// JSON text describing the action.
    pub detail: String,
    pub decision: String,
    #[serde(serialize_with = "hex_bytes")]
    pub prev_hash: Vec<u8>,
    #[serde(serialize_with = "hex_bytes")]
    pub hash: Vec<u8>,
}

fn hex_bytes<S: serde::Serializer>(b: &[u8], s: S) -> std::result::Result<S::Ok, S::Error> {
    s.serialize_str(&b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}

/// A finished (or failed) request/response pair to record.
#[derive(Debug, Clone)]
pub struct NewExchange {
    pub ts_ms: i64,
    pub duration_ms: Option<i64>,
    pub source: String,
    pub actor_id: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
    pub error: Option<String>,
    /// Identity whose credentials were used (None = as recorded / as given).
    pub identity: Option<String>,
}

/// One row of history, without the raw bytes.
#[derive(Debug, Clone, Serialize)]
pub struct ExchangeSummary {
    pub id: i64,
    pub ts_ms: i64,
    pub duration_ms: Option<i64>,
    pub source: String,
    pub actor_id: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    pub req_len: i64,
    pub resp_len: Option<i64>,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
}

/// A full exchange including the raw bytes.
#[derive(Debug, Clone)]
pub struct Exchange {
    pub summary: ExchangeSummary,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
}

/// Filters for searching history. All set fields must match.
#[derive(Debug, Clone, Default, serde::Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistoryFilter {
    /// Host contains this text (case-insensitive).
    pub host: Option<String>,
    /// Path (including query) contains this text (case-insensitive).
    pub path: Option<String>,
    pub method: Option<String>,
    pub status: Option<u16>,
    /// e.g. proxy, replay
    pub source: Option<String>,
    /// e.g. agent:claude-1
    pub actor: Option<String>,
    /// Only exchanges with an id greater than this (for paging forward).
    pub after_id: Option<i64>,
    /// Only exchanges with an id less than this (for paging back).
    pub before_id: Option<i64>,
    /// Maximum rows (default 50, max 500).
    pub limit: Option<usize>,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("opening project {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        // The proxy, an MCP server and the CLI may use one project at once.
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let mut store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        let version: i64 = self.conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let version = usize::try_from(version).unwrap_or(0);
        if version > MIGRATIONS.len() {
            anyhow::bail!("project was created by a newer ProxyMind (schema {version})");
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(version) {
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", (i + 1) as i64)?;
            tx.commit()?;
        }
        Ok(())
    }

    fn put_blob(tx: &rusqlite::Transaction<'_>, data: &[u8]) -> Result<Vec<u8>> {
        let hash = blake3::hash(data).as_bytes().to_vec();
        let exists: Option<i64> =
            tx.query_row("SELECT 1 FROM blobs WHERE hash = ?1", [&hash], |r| r.get(0)).optional()?;
        if exists.is_none() {
            let compressed = zstd::encode_all(data, 3)?;
            tx.execute(
                "INSERT INTO blobs (hash, raw_len, zstd_data) VALUES (?1, ?2, ?3)",
                params![hash, data.len() as i64, compressed],
            )?;
        }
        Ok(hash)
    }

    fn get_blob(&self, hash: &[u8]) -> Result<Vec<u8>> {
        let data: Vec<u8> = self.conn.query_row("SELECT zstd_data FROM blobs WHERE hash = ?1", [hash], |r| r.get(0))?;
        Ok(zstd::decode_all(data.as_slice())?)
    }

    pub fn insert_exchange(&mut self, ex: &NewExchange) -> Result<i64> {
        let tx = self.conn.transaction()?;
        let req_hash = Self::put_blob(&tx, &ex.request)?;
        let resp_hash = ex.response.as_deref().map(|r| Self::put_blob(&tx, r)).transpose()?;
        tx.execute(
            "INSERT INTO exchanges (ts_ms, duration_ms, source, actor_id, scheme, host, port, method, path,
                                    status, req_hash, resp_hash, req_len, resp_len, error, identity)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                ex.ts_ms,
                ex.duration_ms,
                ex.source,
                ex.actor_id,
                ex.scheme,
                ex.host,
                ex.port,
                ex.method,
                ex.path,
                ex.status,
                req_hash,
                resp_hash,
                ex.request.len() as i64,
                ex.response.as_ref().map(|r| r.len() as i64),
                ex.error,
                ex.identity,
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    const SUMMARY_COLS: &'static str = "id, ts_ms, duration_ms, source, actor_id, scheme, host, port, method, path, \
                                        status, req_len, resp_len, error, identity";

    fn summary_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ExchangeSummary> {
        Ok(ExchangeSummary {
            id: r.get(0)?,
            ts_ms: r.get(1)?,
            duration_ms: r.get(2)?,
            source: r.get(3)?,
            actor_id: r.get(4)?,
            scheme: r.get(5)?,
            host: r.get(6)?,
            port: r.get(7)?,
            method: r.get(8)?,
            path: r.get(9)?,
            status: r.get(10)?,
            req_len: r.get(11)?,
            resp_len: r.get(12)?,
            error: r.get(13)?,
            identity: r.get(14)?,
        })
    }

    /// Most recent exchanges first, optionally filtered by host substring.
    pub fn list_exchanges(&self, limit: usize, host_contains: Option<&str>) -> Result<Vec<ExchangeSummary>> {
        let sql = format!(
            "SELECT {} FROM exchanges WHERE (?1 IS NULL OR instr(host, ?1) > 0) ORDER BY id DESC LIMIT ?2",
            Self::SUMMARY_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![host_contains, limit as i64], Self::summary_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Searches history, newest first.
    pub fn search_exchanges(&self, f: &HistoryFilter) -> Result<Vec<ExchangeSummary>> {
        let sql = format!(
            "SELECT {} FROM exchanges WHERE
                (?1 IS NULL OR instr(lower(host), lower(?1)) > 0) AND
                (?2 IS NULL OR instr(lower(path), lower(?2)) > 0) AND
                (?3 IS NULL OR upper(method) = upper(?3)) AND
                (?4 IS NULL OR status = ?4) AND
                (?5 IS NULL OR source = ?5) AND
                (?6 IS NULL OR actor_id = ?6) AND
                (?7 IS NULL OR id > ?7) AND
                (?8 IS NULL OR id < ?8)
             ORDER BY id DESC LIMIT ?9",
            Self::SUMMARY_COLS
        );
        let limit = f.limit.unwrap_or(50).clamp(1, 500) as i64;
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![f.host, f.path, f.method, f.status, f.source, f.actor, f.after_id, f.before_id, limit],
            Self::summary_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn get_exchange(&self, id: i64) -> Result<Option<Exchange>> {
        let sql = format!("SELECT {}, req_hash, resp_hash FROM exchanges WHERE id = ?1", Self::SUMMARY_COLS);
        let row = self
            .conn
            .query_row(&sql, [id], |r| {
                Ok((Self::summary_from_row(r)?, r.get::<_, Vec<u8>>(15)?, r.get::<_, Option<Vec<u8>>>(16)?))
            })
            .optional()?;
        let Some((summary, req_hash, resp_hash)) = row else {
            return Ok(None);
        };
        Ok(Some(Exchange {
            summary,
            request: self.get_blob(&req_hash)?,
            response: resp_hash.map(|h| self.get_blob(&h)).transpose()?,
        }))
    }

    /// Appends an audit record. `rec.seq` must be one more than the last.
    pub fn append_audit(&mut self, rec: &AuditRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO audit_log (seq, ts_ms, actor, action, detail, decision, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![rec.seq, rec.ts_ms, rec.actor, rec.action, rec.detail, rec.decision, rec.prev_hash, rec.hash],
        )?;
        Ok(())
    }

    fn audit_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRecord> {
        Ok(AuditRecord {
            seq: r.get(0)?,
            ts_ms: r.get(1)?,
            actor: r.get(2)?,
            action: r.get(3)?,
            detail: r.get(4)?,
            decision: r.get(5)?,
            prev_hash: r.get(6)?,
            hash: r.get(7)?,
        })
    }

    pub fn last_audit(&self) -> Result<Option<AuditRecord>> {
        Ok(self
            .conn
            .query_row(
                "SELECT seq, ts_ms, actor, action, detail, decision, prev_hash, hash
                 FROM audit_log ORDER BY seq DESC LIMIT 1",
                [],
                Self::audit_from_row,
            )
            .optional()?)
    }

    /// All audit records in order. Loads everything; fine for verification
    /// of logs up to a few million entries.
    pub fn audit_records(&self) -> Result<Vec<AuditRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, ts_ms, actor, action, detail, decision, prev_hash, hash FROM audit_log ORDER BY seq",
        )?;
        let rows = stmt.query_map([], Self::audit_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn insert_approval(&mut self, a: &ApprovalRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO approvals (id, created_ms, actor, action, tier, target, summary, params, params_hash, status,
                                    decided_by, decided_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                a.id,
                a.created_ms,
                a.actor,
                a.action,
                a.tier,
                a.target,
                a.summary,
                a.params,
                a.params_hash,
                a.status,
                a.decided_by,
                a.decided_ms
            ],
        )?;
        Ok(())
    }

    const APPROVAL_COLS: &'static str =
        "id, created_ms, actor, action, tier, target, summary, params, params_hash, status, decided_by, decided_ms";

    fn approval_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRow> {
        Ok(ApprovalRow {
            id: r.get(0)?,
            created_ms: r.get(1)?,
            actor: r.get(2)?,
            action: r.get(3)?,
            tier: r.get(4)?,
            target: r.get(5)?,
            summary: r.get(6)?,
            params: r.get(7)?,
            params_hash: r.get(8)?,
            status: r.get(9)?,
            decided_by: r.get(10)?,
            decided_ms: r.get(11)?,
        })
    }

    pub fn get_approval(&self, id: &str) -> Result<Option<ApprovalRow>> {
        let sql = format!("SELECT {} FROM approvals WHERE id = ?1", Self::APPROVAL_COLS);
        Ok(self.conn.query_row(&sql, [id], Self::approval_from_row).optional()?)
    }

    /// Approvals with this status (or all), newest first.
    pub fn list_approvals(&self, status: Option<&str>, limit: usize) -> Result<Vec<ApprovalRow>> {
        let sql = format!(
            "SELECT {} FROM approvals WHERE (?1 IS NULL OR status = ?1) ORDER BY created_ms DESC LIMIT ?2",
            Self::APPROVAL_COLS
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![status, limit as i64], Self::approval_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Moves an approval from `from` to `to` atomically. Returns false if it
    /// was not in state `from` (or, when `params_hash` is given, if the hash
    /// differs), so two processes can't both decide or use it.
    pub fn transition_approval(
        &mut self,
        id: &str,
        from: &str,
        to: &str,
        decided_by: Option<&str>,
        params_hash: Option<&str>,
        now_ms: i64,
    ) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE approvals SET status = ?3,
                    decided_by = COALESCE(?4, decided_by),
                    decided_ms = CASE WHEN ?4 IS NULL THEN decided_ms ELSE ?6 END
             WHERE id = ?1 AND status = ?2 AND (?5 IS NULL OR params_hash = ?5)",
            params![id, from, to, decided_by, params_hash, now_ms],
        )?;
        Ok(n == 1)
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        Ok(self.conn.query_row("SELECT value FROM settings WHERE key = ?1", [key], |r| r.get(0)).optional()?)
    }

    pub fn set_setting(&mut self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn upsert_identity(&mut self, row: &IdentityRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO identities (name, role, data, created_by, status, updated_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(name) DO UPDATE SET role = excluded.role, data = excluded.data,
                 status = excluded.status, updated_ms = excluded.updated_ms",
            params![row.name, row.role, row.data, row.created_by, row.status, row.updated_ms],
        )?;
        Ok(())
    }

    fn identity_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<IdentityRow> {
        Ok(IdentityRow {
            name: r.get(0)?,
            role: r.get(1)?,
            data: r.get(2)?,
            created_by: r.get(3)?,
            status: r.get(4)?,
            updated_ms: r.get(5)?,
        })
    }

    pub fn get_identity(&self, name: &str) -> Result<Option<IdentityRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT name, role, data, created_by, status, updated_ms FROM identities WHERE name = ?1",
                [name],
                Self::identity_from_row,
            )
            .optional()?)
    }

    pub fn list_identities(&self) -> Result<Vec<IdentityRow>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, role, data, created_by, status, updated_ms FROM identities ORDER BY name")?;
        let rows = stmt.query_map([], Self::identity_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn delete_identity(&mut self, name: &str) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM identities WHERE name = ?1", [name])? == 1)
    }

    pub fn insert_authz(&mut self, r: &AuthzRow) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO authz_results (exchange_id, method, url, identity, verdict, status, similarity, evidence_id,
                                        summary, checked_by, checked_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                r.exchange_id,
                r.method,
                r.url,
                r.identity,
                r.verdict,
                r.status,
                r.similarity,
                r.evidence_id,
                r.summary,
                r.checked_by,
                r.checked_ms
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Latest result per (exchange, identity), optionally for one exchange.
    pub fn authz_results(&self, exchange_id: Option<i64>) -> Result<Vec<AuthzRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, exchange_id, method, url, identity, verdict, status, similarity, evidence_id, summary,
                    checked_by, checked_ms
             FROM authz_results a
             WHERE (?1 IS NULL OR exchange_id = ?1)
               AND id = (SELECT max(id) FROM authz_results b
                         WHERE b.exchange_id = a.exchange_id AND b.identity = a.identity)
             ORDER BY exchange_id, identity",
        )?;
        let rows = stmt.query_map([exchange_id], |r| {
            Ok(AuthzRow {
                id: r.get(0)?,
                exchange_id: r.get(1)?,
                method: r.get(2)?,
                url: r.get(3)?,
                identity: r.get(4)?,
                verdict: r.get(5)?,
                status: r.get(6)?,
                similarity: r.get(7)?,
                evidence_id: r.get(8)?,
                summary: r.get(9)?,
                checked_by: r.get(10)?,
                checked_ms: r.get(11)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn count_exchanges(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT count(*) FROM exchanges", [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(path: &str, body: &[u8]) -> NewExchange {
        NewExchange {
            ts_ms: 1,
            duration_ms: Some(5),
            source: "proxy".into(),
            actor_id: "human:local".into(),
            scheme: "https".into(),
            host: "example.com".into(),
            port: 443,
            method: "GET".into(),
            path: path.into(),
            status: Some(200),
            request: format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n\r\n").into_bytes(),
            response: Some(body.to_vec()),
            error: None,
            identity: None,
        }
    }

    #[test]
    fn round_trips_raw_bytes_and_dedups_blobs() {
        let mut s = Store::open_in_memory().unwrap();
        let body = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        let a = s.insert_exchange(&sample("/a", body)).unwrap();
        s.insert_exchange(&sample("/b", body)).unwrap();
        let ex = s.get_exchange(a).unwrap().unwrap();
        assert_eq!(ex.response.as_deref(), Some(&body[..]));
        assert_eq!(ex.summary.path, "/a");
        let blobs: i64 = s.conn.query_row("SELECT count(*) FROM blobs", [], |r| r.get(0)).unwrap();
        assert_eq!(blobs, 3, "two requests + one shared response");
        assert_eq!(s.list_exchanges(10, Some("example")).unwrap().len(), 2);
        assert_eq!(s.list_exchanges(10, Some("nope")).unwrap().len(), 0);
    }

    #[test]
    fn search_filters_combine() {
        let mut s = Store::open_in_memory().unwrap();
        s.insert_exchange(&sample("/api/Orders/1", b"x")).unwrap();
        let mut post = sample("/api/orders", b"y");
        post.method = "POST".into();
        post.status = Some(201);
        s.insert_exchange(&post).unwrap();
        let f = |f: HistoryFilter| s.search_exchanges(&f).unwrap().len();
        assert_eq!(f(HistoryFilter { path: Some("orders".into()), ..Default::default() }), 2);
        assert_eq!(f(HistoryFilter { method: Some("post".into()), ..Default::default() }), 1);
        assert_eq!(f(HistoryFilter { status: Some(200), host: Some("EXAMPLE".into()), ..Default::default() }), 1);
        assert_eq!(f(HistoryFilter { after_id: Some(1), ..Default::default() }), 1);
    }

    #[test]
    fn audit_log_is_append_only() {
        let mut s = Store::open_in_memory().unwrap();
        let rec = AuditRecord {
            seq: 1,
            ts_ms: 1,
            actor: "agent:a".into(),
            action: "replay_send".into(),
            detail: "{}".into(),
            decision: "allow".into(),
            prev_hash: vec![0; 32],
            hash: vec![1; 32],
        };
        s.append_audit(&rec).unwrap();
        assert_eq!(s.last_audit().unwrap(), Some(rec.clone()));
        assert!(s.append_audit(&rec).is_err(), "duplicate seq");
        assert!(s.conn.execute("UPDATE audit_log SET decision = 'deny'", []).is_err());
        assert!(s.conn.execute("DELETE FROM audit_log", []).is_err());
    }
}
