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
const MIGRATIONS: &[&str] = &[r#"
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
"#];

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
}

/// A full exchange including the raw bytes.
#[derive(Debug, Clone)]
pub struct Exchange {
    pub summary: ExchangeSummary,
    pub request: Vec<u8>,
    pub response: Option<Vec<u8>>,
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
                                    status, req_hash, resp_hash, req_len, resp_len, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
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
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    const SUMMARY_COLS: &'static str = "id, ts_ms, duration_ms, source, actor_id, scheme, host, port, method, path, \
                                        status, req_len, resp_len, error";

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

    pub fn get_exchange(&self, id: i64) -> Result<Option<Exchange>> {
        let sql = format!("SELECT {}, req_hash, resp_hash FROM exchanges WHERE id = ?1", Self::SUMMARY_COLS);
        let row = self
            .conn
            .query_row(&sql, [id], |r| {
                Ok((Self::summary_from_row(r)?, r.get::<_, Vec<u8>>(14)?, r.get::<_, Option<Vec<u8>>>(15)?))
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
}
