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
    r#"
-- Hypothesis ledger.
CREATE TABLE hypotheses (
    id         INTEGER PRIMARY KEY,
    operation  TEXT NOT NULL,
    param      TEXT NOT NULL DEFAULT '',
    vuln_class TEXT NOT NULL,
    rationale  TEXT NOT NULL,
    status     TEXT NOT NULL,
    actor      TEXT NOT NULL,
    notes      TEXT NOT NULL DEFAULT '[]',
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
-- Which hypothesis an exchange was sent to test.
ALTER TABLE exchanges ADD COLUMN hypothesis_id INTEGER;
CREATE INDEX exchanges_hypothesis ON exchanges(hypothesis_id);
-- Proof runs: inputs are kept so any proof can be re-run.
CREATE TABLE proofs (
    id           INTEGER PRIMARY KEY,
    oracle       TEXT NOT NULL,
    inputs       TEXT NOT NULL,
    proven       INTEGER NOT NULL,
    confidence   TEXT NOT NULL,
    reasons      TEXT NOT NULL,
    details      TEXT NOT NULL,
    exchange_ids TEXT NOT NULL,
    finding_id   INTEGER,
    actor        TEXT NOT NULL,
    created_ms   INTEGER NOT NULL
);
CREATE TABLE findings (
    id            INTEGER PRIMARY KEY,
    title         TEXT NOT NULL,
    vuln_class    TEXT NOT NULL,
    severity      TEXT NOT NULL,
    status        TEXT NOT NULL,   -- suspected | proven | confirmed | false_positive | reported
    url           TEXT NOT NULL,
    description   TEXT NOT NULL,
    hypothesis_id INTEGER,
    proof_id      INTEGER,
    evidence      TEXT NOT NULL DEFAULT '[]',
    actor         TEXT NOT NULL,
    created_ms    INTEGER NOT NULL,
    updated_ms    INTEGER NOT NULL
);
CREATE TABLE oast_interactions (
    id       INTEGER PRIMARY KEY,
    token    TEXT NOT NULL,
    protocol TEXT NOT NULL,
    remote   TEXT NOT NULL,
    method   TEXT NOT NULL,
    path     TEXT NOT NULL,
    raw      TEXT NOT NULL,
    ts_ms    INTEGER NOT NULL
);
CREATE INDEX oast_interactions_token ON oast_interactions(token);
"#,
    r#"
-- WebSocket messages seen on an upgraded exchange.
CREATE TABLE ws_messages (
    id          INTEGER PRIMARY KEY,
    exchange_id INTEGER NOT NULL REFERENCES exchanges(id),
    ts_ms       INTEGER NOT NULL,
    from_client INTEGER NOT NULL,
    opcode      INTEGER NOT NULL,
    len         INTEGER NOT NULL,
    payload     BLOB NOT NULL,
    truncated   INTEGER NOT NULL,
    compressed  INTEGER NOT NULL
);
CREATE INDEX ws_messages_exchange ON ws_messages(exchange_id, id);
"#,
    r#"
-- Conversations with the built-in assistant (messages as JSON).
CREATE TABLE assistant_chats (
    id         INTEGER PRIMARY KEY,
    title      TEXT NOT NULL,
    messages   TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
"#,
    r#"
-- Crawl-and-audit tasks (request, progress and operations done as JSON),
-- so they can be resumed after a restart.
CREATE TABLE scan_tasks (
    id         TEXT PRIMARY KEY,
    actor      TEXT NOT NULL,
    status     TEXT NOT NULL,
    data       TEXT NOT NULL,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
-- Scans that start on their own (definition as JSON).
CREATE TABLE scan_schedules (
    id          INTEGER PRIMARY KEY,
    created_by  TEXT NOT NULL,
    data        TEXT NOT NULL,
    enabled     INTEGER NOT NULL,
    next_run_ms INTEGER NOT NULL
);
"#,
    r#"
-- Finding workflow: the last retest (JSON) and how many duplicates were merged in.
ALTER TABLE findings ADD COLUMN retest TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN duplicates INTEGER NOT NULL DEFAULT 0;
"#,
    r#"
-- Collaborator payloads: tokens handed out for out-of-band tests, so
-- interactions can be shown under the payload that caused them.
CREATE TABLE oast_payloads (
    id         INTEGER PRIMARY KEY,
    token      TEXT NOT NULL UNIQUE,
    note       TEXT NOT NULL DEFAULT '',
    actor      TEXT NOT NULL,
    created_ms INTEGER NOT NULL
);
-- Organizer: exchanges kept aside for later, with a status and a note.
CREATE TABLE organizer (
    id          INTEGER PRIMARY KEY,
    exchange_id INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'new',
    note        TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL,
    created_ms  INTEGER NOT NULL,
    updated_ms  INTEGER NOT NULL
);
CREATE INDEX organizer_exchange ON organizer(exchange_id);
"#,
    r#"
-- Out-of-band probes the scanner sent: a callback that arrives after the
-- scan stopped waiting still becomes a finding (see Service::record_oast).
CREATE TABLE oast_probes (
    id          INTEGER PRIMARY KEY,
    token       TEXT NOT NULL,
    check_name  TEXT NOT NULL,
    vuln_class  TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    url         TEXT NOT NULL DEFAULT '',
    point       TEXT NOT NULL DEFAULT '',
    payload     TEXT NOT NULL DEFAULT '',
    exchange_id INTEGER NOT NULL,
    actor       TEXT NOT NULL,
    deadline_ms INTEGER NOT NULL,
    finding_id  INTEGER,
    created_ms  INTEGER NOT NULL
);
CREATE INDEX oast_probes_token ON oast_probes(token);
"#,
];

/// A stored row of one of the JSON-ish engagement tables (hypotheses,
/// proofs, findings, OAST interactions): column name → value.
pub type Row = serde_json::Map<String, serde_json::Value>;

/// A stored crawl-and-audit task; `data` is the service's JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanTaskRow {
    pub id: String,
    pub actor: String,
    pub status: String,
    pub data: String,
    pub created_ms: i64,
    pub updated_ms: i64,
}

/// A stored scan schedule; `data` is the service's JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleRow {
    pub id: i64,
    pub created_by: String,
    pub data: String,
    pub enabled: bool,
    pub next_run_ms: i64,
}

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
    /// Hypothesis this exchange was sent to test.
    pub hypothesis_id: Option<i64>,
}

/// A WebSocket message to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWsMessage {
    pub exchange_id: i64,
    pub ts_ms: i64,
    /// Sent by the client (browser) rather than the server.
    pub from_client: bool,
    pub opcode: u8,
    /// Full length (decompressed, when it could be inflated).
    pub len: u64,
    /// The payload, possibly cut short (see `truncated`).
    pub payload: Vec<u8>,
    pub truncated: bool,
    /// Still compressed: permessage-deflate data that couldn't be inflated.
    pub compressed: bool,
}

/// A stored WebSocket message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WsMessageRow {
    pub id: i64,
    pub exchange_id: i64,
    pub ts_ms: i64,
    pub from_client: bool,
    pub opcode: u8,
    pub len: u64,
    #[serde(skip)]
    pub payload: Vec<u8>,
    pub truncated: bool,
    pub compressed: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hypothesis_id: Option<i64>,
    /// Row colour set by a person: red, orange, yellow, green, blue, purple, gray.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highlight: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

/// The columns the site map needs.
#[derive(Debug, Clone)]
pub struct SiteRow {
    pub id: i64,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
}

/// Row colours for [`Store::annotate`].
pub const HIGHLIGHTS: &[&str] = &["red", "orange", "yellow", "green", "blue", "purple", "gray"];

/// A WebSocket message with its connection's target, for the history across connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WsHistoryRow {
    #[serde(flatten)]
    pub message: WsMessageRow,
    pub host: String,
    pub path: String,
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
    /// Exchanges sent while testing this hypothesis.
    pub hypothesis_id: Option<i64>,
    /// Exchanges sent with this identity's credentials.
    pub identity: Option<String>,
    /// Only exchanges with an id greater than this (for paging forward).
    pub after_id: Option<i64>,
    /// Only exchanges with an id less than this (for paging back).
    pub before_id: Option<i64>,
    /// Maximum rows (default 50, max 500).
    pub limit: Option<usize>,
    /// Status classes to show, e.g. "2,3" for 2xx and 3xx ("0" means no response).
    pub status_class: Option<String>,
    /// File extensions to hide, comma-separated, e.g. "png,jpg,css,js".
    pub hide_ext: Option<String>,
    /// Only rows with a highlight or a comment.
    pub annotated: Option<bool>,
    /// Only targets in the rules of engagement (applied by the service).
    pub in_scope: Option<bool>,
    /// Host, path or comment contains this text (case-insensitive).
    pub text: Option<String>,
    /// A history query (`pm_tools::hql`), applied by the service.
    pub q: Option<String>,
}

pub struct Store {
    conn: Connection,
}

/// The highlight stored in an exchange's tags (`["highlight:red"]`).
fn highlight_of(tags: &str) -> Option<String> {
    let v: Vec<String> = serde_json::from_str(tags).ok()?;
    v.iter().find_map(|t| t.strip_prefix("highlight:").map(str::to_string))
}

/// Creates a new, empty file only its owner can read (on Unix), for copies
/// of project data. Fails if the file exists.
pub fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path)
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        // A sealed project (pm-vault) must be unlocked first.
        let mut head = [0u8; 8];
        if std::fs::File::open(path).and_then(|mut f| std::io::Read::read_exact(&mut f, &mut head)).is_ok()
            && &head == b"PMLOCK1\0"
        {
            anyhow::bail!(
                "{} is a locked project; run `proxymind project unlock {}` first",
                path.display(),
                path.display()
            );
        }
        // A project holds traffic and credentials: a new one is readable by
        // its owner only (SQLite gives the -wal and -shm files the same mode).
        if !path.exists() {
            let _ = create_private(path);
        }
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
            let tx = self.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
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
        // IMMEDIATE takes the write lock up front (waiting on busy_timeout). A
        // deferred one reads first and fails at once (SQLITE_BUSY_SNAPSHOT)
        // if another connection commits in between, losing the exchange.
        let tx = self.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let req_hash = Self::put_blob(&tx, &ex.request)?;
        let resp_hash = ex.response.as_deref().map(|r| Self::put_blob(&tx, r)).transpose()?;
        tx.execute(
            "INSERT INTO exchanges (ts_ms, duration_ms, source, actor_id, scheme, host, port, method, path,
                                    status, req_hash, resp_hash, req_len, resp_len, error, identity, hypothesis_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
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
                ex.hypothesis_id,
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    const SUMMARY_COLS: &'static str = "id, ts_ms, duration_ms, source, actor_id, scheme, host, port, method, path, \
                                        status, req_len, resp_len, error, identity, hypothesis_id, tags, notes";

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
            hypothesis_id: r.get(15)?,
            highlight: highlight_of(&r.get::<_, String>(16)?),
            comment: r.get::<_, Option<String>>(17)?.filter(|c| !c.is_empty()),
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
        use rusqlite::types::Value as V;
        let mut conds: Vec<String> = Vec::new();
        let mut args: Vec<V> = Vec::new();
        // `@` marks where the value goes (SQL text may contain `?` itself).
        let mut add = |cond: &str, v: V| {
            args.push(v);
            conds.push(cond.replace('@', &format!("?{}", args.len())));
        };
        let text = |s: &Option<String>| s.as_ref().filter(|x| !x.is_empty()).map(|x| V::Text(x.clone()));
        if let Some(v) = text(&f.host) {
            add("instr(lower(host), lower(@)) > 0", v);
        }
        if let Some(v) = text(&f.path) {
            add("instr(lower(path), lower(@)) > 0", v);
        }
        if let Some(v) = text(&f.method) {
            add("upper(method) = upper(@)", v);
        }
        if let Some(v) = f.status {
            add("status = @", V::Integer(i64::from(v)));
        }
        if let Some(v) = text(&f.source) {
            add("source = @", v);
        }
        if let Some(v) = text(&f.actor) {
            add("actor_id = @", v);
        }
        if let Some(v) = f.after_id {
            add("id > @", V::Integer(v));
        }
        if let Some(v) = f.before_id {
            add("id < @", V::Integer(v));
        }
        if let Some(v) = f.hypothesis_id {
            add("hypothesis_id = @", V::Integer(v));
        }
        if let Some(v) = text(&f.identity) {
            add("identity = @", v);
        }
        if let Some(v) = text(&f.text) {
            add("(instr(lower(host || ' ' || path || ' ' || coalesce(notes, '')), lower(@)) > 0)", v);
        }
        if let Some(classes) = text(&f.status_class) {
            add("instr(@, CAST(coalesce(status / 100, 0) AS TEXT)) > 0", classes);
        }
        if let Some(exts) = f.hide_ext.as_deref() {
            // The path before any query, lower-cased, must not end in .ext.
            for ext in exts.split(',').map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase()) {
                if !ext.is_empty() && ext.len() <= 10 && ext.chars().all(|c| c.is_ascii_alphanumeric()) {
                    add(
                        "lower(substr(path, 1, instr(path || '?', '?') - 1)) NOT LIKE @ ESCAPE '\\'",
                        V::Text(format!("%.{ext}")),
                    );
                }
            }
        }
        if f.annotated == Some(true) {
            conds.push("(tags != '[]' OR coalesce(notes, '') != '')".into());
        }
        let limit = f.limit.unwrap_or(50).clamp(1, 500) as i64;
        args.push(V::Integer(limit));
        let where_ = if conds.is_empty() { "1".to_string() } else { conds.join(" AND ") };
        let sql = format!(
            "SELECT {} FROM exchanges WHERE {where_} ORDER BY id DESC LIMIT ?{}",
            Self::SUMMARY_COLS,
            args.len()
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(args), Self::summary_from_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Sets (or clears, with None) an exchange's highlight and comment.
    pub fn annotate(&mut self, id: i64, highlight: Option<&str>, comment: Option<&str>) -> Result<bool> {
        if let Some(h) = highlight {
            anyhow::ensure!(HIGHLIGHTS.contains(&h), "unknown highlight {h:?}; use {}", HIGHLIGHTS.join(", "));
        }
        let tags = match highlight {
            Some(h) => serde_json::json!([format!("highlight:{h}")]).to_string(),
            None => "[]".to_string(),
        };
        let comment = comment.map(str::trim).filter(|c| !c.is_empty());
        if let Some(c) = comment {
            anyhow::ensure!(c.len() <= 2000, "comment longer than 2000 characters");
        }
        let n = self
            .conn
            .execute("UPDATE exchanges SET tags = ?1, notes = ?2 WHERE id = ?3", params![tags, comment, id])?;
        Ok(n == 1)
    }

    /// WebSocket messages across all connections, newest first.
    pub fn ws_history(&self, host: Option<&str>, before_id: Option<i64>, limit: usize) -> Result<Vec<WsHistoryRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.id, m.exchange_id, m.ts_ms, m.from_client, m.opcode, m.len, m.payload, m.truncated, m.compressed,
                    e.host, e.path
             FROM ws_messages m JOIN exchanges e ON e.id = m.exchange_id
             WHERE (?1 IS NULL OR instr(lower(e.host), lower(?1)) > 0) AND (?2 IS NULL OR m.id < ?2)
             ORDER BY m.id DESC LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![host, before_id, limit.clamp(1, 1000) as i64], |r| {
            Ok(WsHistoryRow {
                message: WsMessageRow {
                    id: r.get(0)?,
                    exchange_id: r.get(1)?,
                    ts_ms: r.get(2)?,
                    from_client: r.get(3)?,
                    opcode: r.get(4)?,
                    len: u64::try_from(r.get::<_, i64>(5)?).unwrap_or(0),
                    payload: r.get(6)?,
                    truncated: r.get(7)?,
                    compressed: r.get(8)?,
                },
                host: r.get(9)?,
                path: r.get(10)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// (id, scheme, host, port, method, path, status) of up to `limit` exchanges,
    /// newest first, optionally only hosts containing `host` (for the site map).
    pub fn site_rows(&self, host: Option<&str>, limit: usize) -> Result<Vec<SiteRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, scheme, host, port, method, path, status FROM exchanges
             WHERE (?1 IS NULL OR instr(lower(host), lower(?1)) > 0) ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![host, limit as i64], |r| {
            Ok(SiteRow {
                id: r.get(0)?,
                scheme: r.get(1)?,
                host: r.get(2)?,
                port: r.get(3)?,
                method: r.get(4)?,
                path: r.get(5)?,
                status: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn get_exchange(&self, id: i64) -> Result<Option<Exchange>> {
        let sql = format!("SELECT {}, req_hash, resp_hash FROM exchanges WHERE id = ?1", Self::SUMMARY_COLS);
        let row = self
            .conn
            .query_row(&sql, [id], |r| {
                Ok((Self::summary_from_row(r)?, r.get::<_, Vec<u8>>(18)?, r.get::<_, Option<Vec<u8>>>(19)?))
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

    pub fn insert_ws_message(&mut self, m: &NewWsMessage) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO ws_messages (exchange_id, ts_ms, from_client, opcode, len, payload, truncated, compressed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                m.exchange_id,
                m.ts_ms,
                m.from_client,
                m.opcode,
                i64::try_from(m.len).unwrap_or(i64::MAX),
                m.payload,
                m.truncated,
                m.compressed
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Messages of one exchange in order, starting after `after_id`.
    pub fn ws_messages(&self, exchange_id: i64, after_id: Option<i64>, limit: usize) -> Result<Vec<WsMessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, exchange_id, ts_ms, from_client, opcode, len, payload, truncated, compressed
             FROM ws_messages WHERE exchange_id = ?1 AND id > ?2 ORDER BY id LIMIT ?3",
        )?;
        let rows = stmt.query_map(params![exchange_id, after_id.unwrap_or(0), limit.clamp(1, 1000) as i64], |r| {
            Ok(WsMessageRow {
                id: r.get(0)?,
                exchange_id: r.get(1)?,
                ts_ms: r.get(2)?,
                from_client: r.get(3)?,
                opcode: r.get(4)?,
                len: u64::try_from(r.get::<_, i64>(5)?).unwrap_or(0),
                payload: r.get(6)?,
                truncated: r.get(7)?,
                compressed: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn ws_message_count(&self, exchange_id: i64) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT count(*) FROM ws_messages WHERE exchange_id = ?1", [exchange_id], |r| r.get(0))?)
    }

    pub fn create_chat(&mut self, title: &str, now_ms: i64) -> Result<i64> {
        self.conn.execute(
            "INSERT INTO assistant_chats (title, messages, created_ms, updated_ms) VALUES (?1, '[]', ?2, ?2)",
            params![title, now_ms],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn save_chat(&mut self, id: i64, messages: &str, now_ms: i64) -> Result<()> {
        let n = self.conn.execute(
            "UPDATE assistant_chats SET messages = ?2, updated_ms = ?3 WHERE id = ?1",
            params![id, messages, now_ms],
        )?;
        anyhow::ensure!(n == 1, "no chat {id}");
        Ok(())
    }

    /// (title, messages JSON, created_ms, updated_ms)
    pub fn get_chat(&self, id: i64) -> Result<Option<(String, String, i64, i64)>> {
        Ok(self
            .conn
            .query_row("SELECT title, messages, created_ms, updated_ms FROM assistant_chats WHERE id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .optional()?)
    }

    /// Newest first: (id, title, updated_ms).
    pub fn list_chats(&self, limit: usize) -> Result<Vec<(i64, String, i64)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, title, updated_ms FROM assistant_chats ORDER BY updated_ms DESC, id DESC LIMIT ?1")?;
        let rows = stmt.query_map([limit.clamp(1, 500) as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Writes a consistent single-file copy of the project (WAL included)
    /// to `path`, which must not exist yet.
    pub fn snapshot_to(&self, path: &Path) -> Result<()> {
        let p = path.to_str().context("snapshot path is not valid UTF-8")?;
        // VACUUM INTO accepts an empty file: make it owner-only first.
        create_private(path).with_context(|| format!("creating {}", path.display()))?;
        self.conn.execute("VACUUM INTO ?1", [p])?;
        Ok(())
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

    pub fn upsert_scan_task(&mut self, r: &ScanTaskRow) -> Result<()> {
        self.conn.execute(
            "INSERT INTO scan_tasks (id, actor, status, data, created_ms, updated_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET status = excluded.status, data = excluded.data,
                 updated_ms = excluded.updated_ms",
            params![r.id, r.actor, r.status, r.data, r.created_ms, r.updated_ms],
        )?;
        Ok(())
    }

    /// The newest tasks first.
    pub fn list_scan_tasks(&self, limit: usize) -> Result<Vec<ScanTaskRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, actor, status, data, created_ms, updated_ms FROM scan_tasks
             ORDER BY created_ms DESC, rowid DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |r| {
            Ok(ScanTaskRow {
                id: r.get(0)?,
                actor: r.get(1)?,
                status: r.get(2)?,
                data: r.get(3)?,
                created_ms: r.get(4)?,
                updated_ms: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Saves a schedule; id 0 inserts a new one. Returns the id.
    pub fn save_schedule(&mut self, r: &ScheduleRow) -> Result<i64> {
        if r.id == 0 {
            self.conn.execute(
                "INSERT INTO scan_schedules (created_by, data, enabled, next_run_ms) VALUES (?1, ?2, ?3, ?4)",
                params![r.created_by, r.data, r.enabled, r.next_run_ms],
            )?;
            return Ok(self.conn.last_insert_rowid());
        }
        self.conn.execute(
            "UPDATE scan_schedules SET data = ?2, enabled = ?3, next_run_ms = ?4 WHERE id = ?1",
            params![r.id, r.data, r.enabled, r.next_run_ms],
        )?;
        Ok(r.id)
    }

    /// Moves a due schedule's next run from `due` to `next`, only if no one
    /// else did first. Two processes on one project tick the same
    /// schedules; the one whose claim succeeds starts the run.
    pub fn claim_schedule(&mut self, id: i64, due: i64, next: i64) -> Result<bool> {
        Ok(self.conn.execute(
            "UPDATE scan_schedules SET next_run_ms = ?3 WHERE id = ?1 AND next_run_ms = ?2 AND enabled",
            params![id, due, next],
        )? == 1)
    }

    pub fn list_schedules(&self) -> Result<Vec<ScheduleRow>> {
        let mut stmt =
            self.conn.prepare("SELECT id, created_by, data, enabled, next_run_ms FROM scan_schedules ORDER BY id")?;
        let rows = stmt.query_map([], |r| {
            Ok(ScheduleRow {
                id: r.get(0)?,
                created_by: r.get(1)?,
                data: r.get(2)?,
                enabled: r.get(3)?,
                next_run_ms: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn delete_schedule(&mut self, id: i64) -> Result<bool> {
        Ok(self.conn.execute("DELETE FROM scan_schedules WHERE id = ?1", [id])? == 1)
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

    /// Ids of exchanges with a response recorded after `after`, oldest first.
    pub fn exchange_ids_after(&self, after: i64, limit: usize) -> Result<Vec<i64>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM exchanges WHERE id > ?1 AND resp_hash IS NOT NULL ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map([after, limit as i64], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The highest exchange id (0 when there are none).
    pub fn max_exchange_id(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COALESCE(MAX(id), 0) FROM exchanges", [], |r| r.get(0))?)
    }

    /// The most recent `limit` exchanges with their bytes, oldest first.
    pub fn recent_exchanges(&self, limit: usize) -> Result<Vec<Exchange>> {
        let ids: Vec<i64> = {
            let mut stmt = self.conn.prepare("SELECT id FROM exchanges ORDER BY id DESC LIMIT ?1")?;
            let rows = stmt.query_map([limit as i64], |r| r.get(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        let mut out = Vec::with_capacity(ids.len());
        for id in ids.into_iter().rev() {
            if let Some(ex) = self.get_exchange(id)? {
                out.push(ex);
            }
        }
        Ok(out)
    }

    // ---- engagement tables (hypotheses, proofs, findings, OAST) ----------
    //
    // These are written through a small, explicit column list per table so
    // callers can't touch other tables or columns.

    fn table_columns(table: &str) -> Option<&'static [&'static str]> {
        Some(match table {
            "hypotheses" => &[
                "operation",
                "param",
                "vuln_class",
                "rationale",
                "status",
                "actor",
                "notes",
                "created_ms",
                "updated_ms",
            ],
            "proofs" => &[
                "oracle",
                "inputs",
                "proven",
                "confidence",
                "reasons",
                "details",
                "exchange_ids",
                "finding_id",
                "actor",
                "created_ms",
            ],
            "findings" => &[
                "title",
                "vuln_class",
                "severity",
                "status",
                "url",
                "description",
                "hypothesis_id",
                "proof_id",
                "evidence",
                "actor",
                "retest",
                "duplicates",
                "created_ms",
                "updated_ms",
            ],
            "oast_interactions" => &["token", "protocol", "remote", "method", "path", "raw", "ts_ms"],
            "oast_payloads" => &["token", "note", "actor", "created_ms"],
            "oast_probes" => &[
                "token",
                "check_name",
                "vuln_class",
                "title",
                "severity",
                "url",
                "point",
                "payload",
                "exchange_id",
                "actor",
                "deadline_ms",
                "finding_id",
                "created_ms",
            ],
            "organizer" => &["exchange_id", "status", "note", "actor", "created_ms", "updated_ms"],
            _ => return None,
        })
    }

    fn to_sql(v: &serde_json::Value) -> rusqlite::types::Value {
        use rusqlite::types::Value as V;
        match v {
            serde_json::Value::Null => V::Null,
            serde_json::Value::Bool(b) => V::Integer(i64::from(*b)),
            serde_json::Value::Number(n) => match n.as_i64() {
                Some(i) => V::Integer(i),
                None => V::Real(n.as_f64().unwrap_or(0.0)),
            },
            serde_json::Value::String(s) => V::Text(s.clone()),
            other => V::Text(other.to_string()),
        }
    }

    /// Inserts a row; unknown columns are rejected. Returns the new id.
    pub fn insert_row(&mut self, table: &str, row: &Row) -> Result<i64> {
        let cols = Self::table_columns(table).ok_or_else(|| anyhow::anyhow!("unknown table {table}"))?;
        if let Some(bad) = row.keys().find(|k| !cols.contains(&k.as_str())) {
            anyhow::bail!("unknown column {bad} for {table}");
        }
        let names: Vec<&String> = row.keys().collect();
        let sql = format!(
            "INSERT INTO {table} ({}) VALUES ({})",
            names.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
            (1..=names.len()).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ")
        );
        let values: Vec<rusqlite::types::Value> = names.iter().map(|k| Self::to_sql(&row[*k])).collect();
        self.conn.execute(&sql, rusqlite::params_from_iter(values))?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Updates columns of one row by id. Returns false if there is no such row.
    pub fn update_row(&mut self, table: &str, id: i64, changes: &Row) -> Result<bool> {
        let cols = Self::table_columns(table).ok_or_else(|| anyhow::anyhow!("unknown table {table}"))?;
        if let Some(bad) = changes.keys().find(|k| !cols.contains(&k.as_str())) {
            anyhow::bail!("unknown column {bad} for {table}");
        }
        if changes.is_empty() {
            return Ok(true);
        }
        let names: Vec<&String> = changes.keys().collect();
        let sets: Vec<String> = names.iter().enumerate().map(|(i, k)| format!("{k} = ?{}", i + 2)).collect();
        let sql = format!("UPDATE {table} SET {} WHERE id = ?1", sets.join(", "));
        let mut values: Vec<rusqlite::types::Value> = vec![rusqlite::types::Value::Integer(id)];
        values.extend(names.iter().map(|k| Self::to_sql(&changes[*k])));
        Ok(self.conn.execute(&sql, rusqlite::params_from_iter(values))? == 1)
    }

    /// Rows of a table, optionally where `column = value`, newest first.
    /// How many rows a table has (matching `filter`, if given).
    pub fn count_rows(&self, table: &str, filter: Option<(&str, &serde_json::Value)>) -> Result<u64> {
        let cols = Self::table_columns(table).ok_or_else(|| anyhow::anyhow!("unknown table {table}"))?;
        let n: i64 = match filter {
            Some((col, v)) => {
                if col != "id" && !cols.contains(&col) {
                    anyhow::bail!("unknown column {col} for {table}");
                }
                self.conn.query_row(
                    &format!("SELECT COUNT(*) FROM {table} WHERE {col} = ?1"),
                    [Self::to_sql(v)],
                    |r| r.get(0),
                )?
            }
            None => self.conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?,
        };
        Ok(n.max(0) as u64)
    }

    pub fn rows(&self, table: &str, filter: Option<(&str, &serde_json::Value)>, limit: usize) -> Result<Vec<Row>> {
        let cols = Self::table_columns(table).ok_or_else(|| anyhow::anyhow!("unknown table {table}"))?;
        let mut all: Vec<&str> = vec!["id"];
        all.extend_from_slice(cols);
        let (where_sql, params): (String, Vec<rusqlite::types::Value>) = match filter {
            Some((col, v)) => {
                if col != "id" && !cols.contains(&col) {
                    anyhow::bail!("unknown column {col} for {table}");
                }
                (format!("WHERE {col} = ?1"), vec![Self::to_sql(v)])
            }
            None => (String::new(), vec![]),
        };
        let sql =
            format!("SELECT {} FROM {table} {where_sql} ORDER BY id DESC LIMIT {}", all.join(", "), limit.min(10_000));
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
            let mut m = Row::new();
            for (i, c) in all.iter().enumerate() {
                use rusqlite::types::ValueRef;
                let v = match r.get_ref(i)? {
                    ValueRef::Null => serde_json::Value::Null,
                    ValueRef::Integer(x) => serde_json::json!(x),
                    ValueRef::Real(x) => serde_json::json!(x),
                    ValueRef::Text(t) => serde_json::Value::String(String::from_utf8_lossy(t).into_owned()),
                    ValueRef::Blob(_) => serde_json::Value::Null,
                };
                m.insert((*c).to_string(), v);
            }
            Ok(m)
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Deletes one row of an engagement table. Returns false if there was none.
    pub fn delete_row(&mut self, table: &str, id: i64) -> Result<bool> {
        Self::table_columns(table).ok_or_else(|| anyhow::anyhow!("unknown table {table}"))?;
        Ok(self.conn.execute(&format!("DELETE FROM {table} WHERE id = ?1"), [id])? == 1)
    }

    pub fn row(&self, table: &str, id: i64) -> Result<Option<Row>> {
        Ok(self.rows(table, Some(("id", &serde_json::json!(id))), 1)?.into_iter().next())
    }

    pub fn count_exchanges(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT count(*) FROM exchanges", [], |r| r.get(0))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn new_projects_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pm-store-mode-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.pmproj");
        let _ = std::fs::remove_file(&path);
        let mut s = Store::open(&path).unwrap();
        s.set_setting("x", "y").unwrap();
        for f in ["p.pmproj", "p.pmproj-wal"] {
            let mode = std::fs::metadata(dir.join(f)).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "{f} is {mode:o}");
        }
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_due_schedule_is_claimed_once() {
        let mut s = Store::open_in_memory().unwrap();
        let row =
            ScheduleRow { id: 0, created_by: "human:t".into(), data: "{}".into(), enabled: true, next_run_ms: 100 };
        let id = s.save_schedule(&row).unwrap();
        assert!(s.claim_schedule(id, 100, 200).unwrap());
        assert!(!s.claim_schedule(id, 100, 200).unwrap(), "a second process sees it taken");
        s.save_schedule(&ScheduleRow { id, enabled: false, next_run_ms: 300, ..row }).unwrap();
        assert!(!s.claim_schedule(id, 300, 400).unwrap(), "disabled");
    }

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
            hypothesis_id: None,
        }
    }

    #[test]
    fn concurrent_writers_never_lose_exchanges() {
        // Two connections to one project, like the proxy's recorder and the
        // UI's service: every insert must land while the other one writes.
        let dir = std::env::temp_dir().join(format!("pm-store-conc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.pmproj");
        let mut a = Store::open(&path).unwrap();
        let mut b = Store::open(&path).unwrap();
        let writer = std::thread::spawn(move || {
            for i in 0..300 {
                b.set_setting("busy", &i.to_string()).unwrap();
                b.insert_exchange(&sample(&format!("/b/{i}"), b"HTTP/1.1 200 OK\r\n\r\nb")).unwrap();
            }
        });
        for i in 0..300 {
            a.insert_exchange(&sample(&format!("/a/{i}"), format!("HTTP/1.1 200 OK\r\n\r\n{i}").as_bytes())).unwrap();
        }
        writer.join().unwrap();
        assert_eq!(a.count_exchanges().unwrap(), 600);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn annotations_and_history_filters() {
        let mut s = Store::open_in_memory().unwrap();
        let ok = b"HTTP/1.1 200 OK\r\n\r\n";
        let a = s.insert_exchange(&sample("/app.js?v=1", ok)).unwrap();
        let b = s.insert_exchange(&sample("/api/users", ok)).unwrap();
        let mut c = sample("/logo.PNG", ok);
        c.status = Some(404);
        let c = s.insert_exchange(&c).unwrap();
        let mut d = sample("/down", ok);
        d.status = None;
        s.insert_exchange(&d).unwrap();

        assert!(s.annotate(b, Some("red"), Some("  look here  ")).unwrap());
        assert!(s.annotate(b, Some("pink"), None).is_err());
        assert!(!s.annotate(9999, None, None).unwrap());
        let got = s.get_exchange(b).unwrap().unwrap();
        assert_eq!(
            (got.summary.highlight.as_deref(), got.summary.comment.as_deref()),
            (Some("red"), Some("look here"))
        );
        assert_eq!(got.request, sample("/api/users", ok).request, "raw bytes still load after the new columns");

        fn ids(s: &Store, f: HistoryFilter) -> Vec<i64> {
            s.search_exchanges(&f).unwrap().iter().map(|r| r.id).collect()
        }
        assert_eq!(ids(&s, HistoryFilter { annotated: Some(true), ..Default::default() }), [b]);
        assert_eq!(ids(&s, HistoryFilter { text: Some("LOOK".into()), ..Default::default() }), [b]);
        let hidden = ids(&s, HistoryFilter { hide_ext: Some("png, js,bad ext".into()), ..Default::default() });
        assert!(!hidden.contains(&a) && !hidden.contains(&c) && hidden.contains(&b), "{hidden:?}");
        assert_eq!(ids(&s, HistoryFilter { status_class: Some("4".into()), ..Default::default() }), [c]);
        assert_eq!(
            ids(&s, HistoryFilter { status_class: Some("0".into()), ..Default::default() }).len(),
            1,
            "no response"
        );
        assert!(s.annotate(b, None, None).unwrap());
        assert!(ids(&s, HistoryFilter { annotated: Some(true), ..Default::default() }).is_empty());
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
