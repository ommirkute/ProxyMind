//! Raw TCP and TLS streams (roadmap 2.6): one row per relayed connection and its chunks in order.
//!
//! The proxy relays bytes it cannot read as HTTP (SSH, databases, a custom protocol, TLS that carries one) without
//! changing them; this module only stores a copy. Chunk bytes go into `blobs` like message bodies (zstd, one copy
//! per distinct content). A stream is opened, gets chunks as they cross the proxy and is ended; its row shows the
//! running totals while it is open and the exact ones at the end.

use std::collections::HashMap;

use anyhow::Result;
use rusqlite::{OptionalExtension, params};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::Store;

/// Most bytes of one stream kept in the project. Later bytes are still relayed and counted, and the stream is marked
/// `truncated`.
pub const STREAM_RECORD_CAP: u64 = 16 << 20;
/// Most chunks kept for one stream (a protocol that sends one byte at a time must not make millions of rows).
pub const STREAM_CHUNK_CAP: u64 = 50_000;

/// A stream to record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewStream {
    pub start_ms: i64,
    /// The target's name or address as the client asked for it.
    pub host: String,
    pub port: u16,
    /// The IP address (no port) of the client; None for streams ProxyMind opened itself.
    pub client_addr: Option<String>,
    /// The bytes recorded are the decrypted ones of a TLS connection.
    pub tls: bool,
    /// The TLS server name used towards the target.
    pub sni: Option<String>,
    /// The ALPN protocol agreed (a protocol other than HTTP), if any.
    pub alpn: Option<String>,
    /// `proxy` (relayed for a client) or `stream_replay`.
    pub source: String,
    pub actor_id: String,
    /// The stream this one replays.
    pub replay_of: Option<i64>,
}

/// One piece of a stream, as it was read from one side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewChunk {
    pub ts_ms: i64,
    pub to_server: bool,
    /// Bytes on the wire.
    pub len: u64,
    /// The bytes kept (all of them, or a prefix when the recording cap cut the chunk).
    pub data: Vec<u8>,
}

/// How a stream ended.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamEnd {
    pub end_ms: i64,
    pub bytes_to_server: u64,
    pub bytes_to_client: u64,
    pub truncated: bool,
    /// `client_closed`, `server_closed`, `error`, `timeout` (replay) or `limit` (replay).
    pub ended: String,
    pub error: Option<String>,
}

/// A change to the stream tables; `u64` is the writer's key for the stream (see [`Store::apply_stream_ops`]).
#[derive(Debug, Clone)]
pub enum StreamOp {
    Open(u64, NewStream),
    Chunk(u64, NewChunk),
    End(u64, StreamEnd),
}

/// What a stream observer is told: ids and the scope fields, never bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedStream {
    pub id: i64,
    /// `https` when the stream is TLS, else `http` (what a scope rule is matched against).
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// `started`, `chunks` or `ended`.
    pub what: &'static str,
}

/// Called with the streams a `StoreHandle::write` changed (see `StoreHandle::set_on_streams`).
pub type StreamObserver = Box<dyn Fn(&[CommittedStream]) + Send + Sync>;

/// One stream, without its chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct StreamRow {
    pub id: i64,
    pub start_ms: i64,
    /// Absent while the stream is open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_ms: Option<i64>,
    pub host: String,
    pub port: u16,
    /// The client's IP address; absent for streams ProxyMind opened itself.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_addr: Option<String>,
    /// The chunks are the decrypted bytes of a TLS connection.
    pub tls: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// The ALPN protocol agreed, when it was not HTTP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    /// `proxy` or `stream_replay`.
    pub source: String,
    pub actor_id: String,
    /// Bytes sent towards the server and towards the client (all of them, also those past the recording cap).
    pub bytes_to_server: u64,
    pub bytes_to_client: u64,
    /// Chunks stored.
    pub chunks: u64,
    /// The recording cap was reached: later bytes were relayed and counted but not kept.
    pub truncated: bool,
    /// How it ended: `client_closed`, `server_closed`, `error`, `timeout` or `limit`; absent while open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The stream this one replays.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replay_of: Option<i64>,
}

/// A stored chunk with its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamChunkRow {
    pub id: i64,
    pub stream_id: i64,
    pub ts_ms: i64,
    pub to_server: bool,
    /// Bytes on the wire.
    pub len: u64,
    /// The bytes kept (fewer than `len` when the recording cap cut the chunk).
    pub data: Vec<u8>,
}

/// Filters of the stream list. Unknown keys are refused.
#[derive(Debug, Clone, Default, Deserialize, Serialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct StreamFilter {
    /// Only targets whose host contains this text (case-insensitive).
    pub host: Option<String>,
    /// Only this target port.
    pub port: Option<u16>,
    /// Only streams from this client: an IP address, or a device name set on the Proxy setup page.
    pub client: Option<String>,
    /// Only streams that started at or after this time (milliseconds since 1970).
    pub since_ms: Option<i64>,
    /// Only streams that started at or before this time (milliseconds since 1970).
    pub until_ms: Option<i64>,
    /// With true: only TLS streams; with false: only plain ones.
    pub tls: Option<bool>,
    /// Only streams with an id less than this (older ones; for paging back, pass `next_before_id`).
    pub before_id: Option<i64>,
    /// Most rows (default 50, max 500).
    #[schemars(range(min = 1, max = 500))]
    pub limit: Option<usize>,
    /// Only streams from these client IPs: `client` with a device name resolved (set by the service, never by
    /// clients).
    #[serde(skip)]
    #[schemars(skip)]
    pub clients: Option<Vec<String>>,
}

const COLS: &str = "id, start_ms, end_ms, host, port, client_addr, tls, sni, alpn, source, actor_id, bytes_to_server, \
                    bytes_to_client, chunk_count, truncated, ended, error, replay_of";

fn row_of(r: &rusqlite::Row<'_>) -> rusqlite::Result<StreamRow> {
    let n = |i: usize| -> rusqlite::Result<u64> { Ok(u64::try_from(r.get::<_, i64>(i)?).unwrap_or(0)) };
    Ok(StreamRow {
        id: r.get(0)?,
        start_ms: r.get(1)?,
        end_ms: r.get(2)?,
        host: r.get(3)?,
        port: r.get(4)?,
        client_addr: r.get(5)?,
        tls: r.get(6)?,
        sni: r.get(7)?,
        alpn: r.get(8)?,
        source: r.get(9)?,
        actor_id: r.get(10)?,
        bytes_to_server: n(11)?,
        bytes_to_client: n(12)?,
        chunks: n(13)?,
        truncated: r.get(14)?,
        ended: r.get(15)?,
        error: r.get(16)?,
        replay_of: r.get(17)?,
    })
}

fn i(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

impl Store {
    /// Applies stream writes in one IMMEDIATE transaction, in order. `ids` maps the writer's keys to row ids: `Open`
    /// adds an entry, `End` removes it, `Chunk` and `End` for a key without an entry are skipped (the stream was not
    /// recorded). On an error nothing is stored and `ids` is unchanged. Returns the row ids of the streams opened.
    pub fn apply_stream_ops(&mut self, ids: &mut HashMap<u64, i64>, ops: Vec<StreamOp>) -> Result<Vec<i64>> {
        let tx = self.conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut live = ids.clone();
        let mut opened = Vec::new();
        let mut notes: Vec<CommittedStream> = Vec::new();
        // Scope fields of the streams touched, for the notes.
        let mut targets: HashMap<i64, (String, String, u16)> = HashMap::new();
        for op in ops {
            match op {
                StreamOp::Open(key, s) => {
                    tx.execute(
                        "INSERT INTO streams (start_ms, host, port, client_addr, tls, sni, alpn, source, actor_id, replay_of)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            s.start_ms,
                            s.host,
                            s.port,
                            s.client_addr,
                            s.tls,
                            s.sni,
                            s.alpn,
                            s.source,
                            s.actor_id,
                            s.replay_of
                        ],
                    )?;
                    let id = tx.last_insert_rowid();
                    live.insert(key, id);
                    opened.push(id);
                    let scheme = if s.tls { "https" } else { "http" };
                    targets.insert(id, (scheme.into(), s.host, s.port));
                    notes.push(note(id, &targets, "started"));
                }
                StreamOp::Chunk(key, c) => {
                    let Some(&id) = live.get(&key) else { continue };
                    let hash = if c.data.is_empty() { None } else { Some(Self::put_blob(&tx, &c.data)?) };
                    tx.execute(
                        "INSERT INTO stream_chunks (stream_id, ts_ms, to_server, len, stored_len, data_hash)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![id, c.ts_ms, c.to_server, i(c.len), c.data.len() as i64, hash],
                    )?;
                    // Running totals while the stream is open; `End` writes the exact ones.
                    tx.execute(
                        "UPDATE streams SET chunk_count = chunk_count + 1,
                                bytes_to_server = bytes_to_server + ?2, bytes_to_client = bytes_to_client + ?3
                         WHERE id = ?1",
                        params![id, if c.to_server { i(c.len) } else { 0 }, if c.to_server { 0 } else { i(c.len) }],
                    )?;
                    if let std::collections::hash_map::Entry::Vacant(v) = targets.entry(id)
                        && let Some(t) = stream_target(&tx, id)?
                    {
                        v.insert(t);
                    }
                    notes.push(note(id, &targets, "chunks"));
                }
                StreamOp::End(key, e) => {
                    let Some(id) = live.remove(&key) else { continue };
                    tx.execute(
                        "UPDATE streams SET end_ms = ?2, bytes_to_server = ?3, bytes_to_client = ?4, truncated = ?5,
                                ended = ?6, error = ?7 WHERE id = ?1",
                        params![
                            id,
                            e.end_ms,
                            i(e.bytes_to_server),
                            i(e.bytes_to_client),
                            e.truncated,
                            e.ended,
                            e.error
                        ],
                    )?;
                    if let std::collections::hash_map::Entry::Vacant(v) = targets.entry(id)
                        && let Some(t) = stream_target(&tx, id)?
                    {
                        v.insert(t);
                    }
                    notes.push(note(id, &targets, "ended"));
                }
            }
        }
        tx.commit()?;
        *ids = live;
        if let Some(list) = self.committed_streams.as_mut() {
            list.extend(notes);
        }
        Ok(opened)
    }

    /// Stores a whole stream at once (replay): the row, its chunks in order and its end. Returns the stream's id.
    pub fn record_stream(&mut self, s: &NewStream, chunks: Vec<NewChunk>, end: StreamEnd) -> Result<i64> {
        let mut ops = vec![StreamOp::Open(0, s.clone())];
        ops.extend(chunks.into_iter().map(|c| StreamOp::Chunk(0, c)));
        ops.push(StreamOp::End(0, end));
        let opened = self.apply_stream_ops(&mut HashMap::new(), ops)?;
        opened.first().copied().ok_or_else(|| anyhow::anyhow!("stream was not stored"))
    }

    pub fn get_stream(&self, id: i64) -> Result<Option<StreamRow>> {
        Ok(self.conn.query_row(&format!("SELECT {COLS} FROM streams WHERE id = ?1"), [id], row_of).optional()?)
    }

    /// Streams, newest first.
    pub fn list_streams(&self, f: &StreamFilter) -> Result<Vec<StreamRow>> {
        let text = |o: &Option<String>| o.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let clients = match (&f.clients, text(&f.client)) {
            (Some(list), _) => Some(serde_json::to_string(list)?),
            (None, Some(c)) => Some(serde_json::to_string(&[c])?),
            (None, None) => None,
        };
        let sql = format!(
            "SELECT {COLS} FROM streams
             WHERE (?1 IS NULL OR instr(lower(host), lower(?1)) > 0)
               AND (?2 IS NULL OR port = ?2)
               AND (?3 IS NULL OR client_addr IN (SELECT value FROM json_each(?3)))
               AND (?4 IS NULL OR start_ms >= ?4)
               AND (?5 IS NULL OR start_ms <= ?5)
               AND (?6 IS NULL OR tls = ?6)
               AND (?7 IS NULL OR id < ?7)
             ORDER BY id DESC LIMIT ?8"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![
                text(&f.host),
                f.port,
                clients,
                f.since_ms,
                f.until_ms,
                f.tls,
                f.before_id,
                f.limit.unwrap_or(50).clamp(1, 500) as i64
            ],
            row_of,
        )?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Chunks of a stream in order, after chunk id `after_id`. `to_server`: only that direction.
    pub fn stream_chunks(
        &self,
        stream_id: i64,
        after_id: Option<i64>,
        limit: usize,
        to_server: Option<bool>,
    ) -> Result<Vec<StreamChunkRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT c.id, c.ts_ms, c.to_server, c.len, b.zstd_data FROM stream_chunks c
             LEFT JOIN blobs b ON b.hash = c.data_hash
             WHERE c.stream_id = ?1 AND c.id > ?2 AND (?3 IS NULL OR c.to_server = ?3)
             ORDER BY c.id LIMIT ?4",
        )?;
        let rows =
            stmt.query_map(params![stream_id, after_id.unwrap_or(0), to_server, limit.clamp(1, 5000) as i64], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, bool>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<Vec<u8>>>(4)?,
                ))
            })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, ts_ms, to_server, len, z) = row?;
            let data = match z {
                Some(z) => zstd::decode_all(z.as_slice())?,
                None => Vec::new(),
            };
            out.push(StreamChunkRow { id, stream_id, ts_ms, to_server, len: u64::try_from(len).unwrap_or(0), data });
        }
        Ok(out)
    }

    pub fn count_streams(&self) -> Result<u64> {
        let n: i64 = self.conn.query_row("SELECT count(*) FROM streams", [], |r| r.get(0))?;
        Ok(n.max(0) as u64)
    }
}

/// The scope fields of a stored stream (`https` for TLS, else `http`, host, port).
fn stream_target(tx: &rusqlite::Transaction<'_>, id: i64) -> Result<Option<(String, String, u16)>> {
    Ok(tx
        .query_row("SELECT tls, host, port FROM streams WHERE id = ?1", [id], |r| {
            Ok((if r.get::<_, bool>(0)? { "https" } else { "http" }.to_string(), r.get(1)?, r.get(2)?))
        })
        .optional()?)
}

fn note(id: i64, targets: &HashMap<i64, (String, String, u16)>, what: &'static str) -> CommittedStream {
    let (scheme, host, port) = targets.get(&id).cloned().unwrap_or_default();
    CommittedStream { id, scheme, host, port, what }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_project(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("pm-streams-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("p.pmproj");
        (dir, path)
    }

    fn stream(host: &str) -> NewStream {
        NewStream {
            start_ms: 1000,
            host: host.into(),
            port: 2525,
            client_addr: Some("10.0.0.7".into()),
            source: "proxy".into(),
            actor_id: "human:local".into(),
            ..Default::default()
        }
    }

    fn chunk(ts: i64, to_server: bool, data: &[u8]) -> NewChunk {
        NewChunk { ts_ms: ts, to_server, len: data.len() as u64, data: data.to_vec() }
    }

    fn end(ts: i64, up: u64, down: u64) -> StreamEnd {
        StreamEnd {
            end_ms: ts,
            bytes_to_server: up,
            bytes_to_client: down,
            ended: "client_closed".into(),
            ..Default::default()
        }
    }

    #[test]
    fn chunks_come_back_in_order_with_directions_and_totals() {
        let mut s = Store::open_in_memory().unwrap();
        let mut ids = HashMap::new();
        s.apply_stream_ops(
            &mut ids,
            vec![StreamOp::Open(7, stream("mail.test")), StreamOp::Chunk(7, chunk(1, false, b"220 hi\r\n"))],
        )
        .unwrap();
        // The stream is open: running totals, no end.
        let open = s.get_stream(1).unwrap().unwrap();
        assert_eq!((open.end_ms, open.ended.clone(), open.chunks, open.bytes_to_client), (None, None, 1, 8));
        s.apply_stream_ops(
            &mut ids,
            vec![
                StreamOp::Chunk(7, chunk(2, true, b"EHLO me\r\n")),
                StreamOp::Chunk(7, chunk(3, false, &[0, 1, 2, 255])),
                StreamOp::End(7, end(9, 9, 12)),
                // A key that was never opened (not recorded) is skipped.
                StreamOp::Chunk(99, chunk(4, true, b"x")),
            ],
        )
        .unwrap();
        assert!(ids.is_empty(), "End forgets the key");
        let row = s.get_stream(1).unwrap().unwrap();
        assert_eq!((row.end_ms, row.ended.as_deref(), row.chunks), (Some(9), Some("client_closed"), 3));
        assert_eq!((row.bytes_to_server, row.bytes_to_client, row.truncated), (9, 12, false));
        assert_eq!(row.client_addr.as_deref(), Some("10.0.0.7"));
        let chunks = s.stream_chunks(1, None, 100, None).unwrap();
        let got: Vec<(bool, Vec<u8>)> = chunks.iter().map(|c| (c.to_server, c.data.clone())).collect();
        assert_eq!(
            got,
            [(false, b"220 hi\r\n".to_vec()), (true, b"EHLO me\r\n".to_vec()), (false, vec![0, 1, 2, 255])]
        );
        assert_eq!(s.stream_chunks(1, Some(chunks[0].id), 1, None).unwrap()[0].data, b"EHLO me\r\n");
        assert_eq!(s.stream_chunks(1, None, 100, Some(true)).unwrap().len(), 1);
    }

    #[test]
    fn identical_chunks_share_one_blob_and_cut_chunks_keep_their_wire_length() {
        let mut s = Store::open_in_memory().unwrap();
        let big = vec![b'a'; 4096];
        s.record_stream(
            &stream("a.test"),
            vec![
                chunk(1, true, &big),
                chunk(2, true, &big),
                NewChunk { ts_ms: 3, to_server: false, len: 100_000, data: big[..10].to_vec() },
            ],
            StreamEnd { truncated: true, ..end(5, 8192, 100_000) },
        )
        .unwrap();
        let blobs: i64 = s.conn.query_row("SELECT count(*) FROM blobs", [], |r| r.get(0)).unwrap();
        assert_eq!(blobs, 2, "two distinct contents (the repeat is stored once)");
        let c = s.stream_chunks(1, None, 10, None).unwrap();
        assert_eq!((c[2].len, c[2].data.len()), (100_000, 10));
        assert!(s.get_stream(1).unwrap().unwrap().truncated);
    }

    #[test]
    fn list_filters_and_pages() {
        let mut s = Store::open_in_memory().unwrap();
        let mk = |host: &str, port: u16, tls: bool, client: &str, start: i64| NewStream {
            host: host.into(),
            port,
            tls,
            start_ms: start,
            client_addr: Some(client.into()),
            ..stream(host)
        };
        for st in [
            mk("db.test", 5432, false, "10.0.0.1", 100),
            mk("Mail.test", 465, true, "10.0.0.2", 200),
            mk("mail.test", 25, false, "10.0.0.1", 300),
        ] {
            s.record_stream(&st, vec![], end(st.start_ms + 1, 0, 0)).unwrap();
        }
        let ids = |f: StreamFilter| s.list_streams(&f).unwrap().iter().map(|r| r.id).collect::<Vec<_>>();
        assert_eq!(ids(StreamFilter::default()), [3, 2, 1], "newest first");
        assert_eq!(ids(StreamFilter { host: Some("MAIL".into()), ..Default::default() }), [3, 2]);
        assert_eq!(ids(StreamFilter { port: Some(5432), ..Default::default() }), [1]);
        assert_eq!(ids(StreamFilter { client: Some("10.0.0.1".into()), ..Default::default() }), [3, 1]);
        assert_eq!(ids(StreamFilter { tls: Some(true), ..Default::default() }), [2]);
        assert_eq!(ids(StreamFilter { since_ms: Some(150), until_ms: Some(250), ..Default::default() }), [2]);
        assert_eq!(ids(StreamFilter { before_id: Some(3), limit: Some(1), ..Default::default() }), [2]);
    }

    #[test]
    fn a_failed_write_stores_nothing_and_keeps_the_key_map() {
        let mut s = Store::open_in_memory().unwrap();
        let mut ids = HashMap::new();
        // The second stream points at a replay target that does not exist: the foreign key fails the whole batch.
        let bad = NewStream { replay_of: Some(999), ..stream("b.test") };
        let r = s.apply_stream_ops(&mut ids, vec![StreamOp::Open(1, stream("a.test")), StreamOp::Open(2, bad)]);
        assert!(r.is_err());
        assert!(ids.is_empty());
        assert_eq!(s.count_streams().unwrap(), 0);
    }

    /// A project made before streams existed opens, keeps its rows and takes streams.
    #[test]
    fn stream_migration_upgrades_an_existing_project() {
        let (dir, path) = temp_project("migration");
        {
            let mut s = Store::open(&path).unwrap();
            s.set_setting("keep", "me").unwrap();
        }
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch("DROP TABLE stream_chunks; DROP TABLE streams;").unwrap();
            conn.pragma_update(None, "user_version", (crate::MIGRATIONS.len() - 1) as i64).unwrap();
        }
        let mut s = Store::open(&path).unwrap();
        assert_eq!(s.get_setting("keep").unwrap().as_deref(), Some("me"));
        assert_eq!(s.count_streams().unwrap(), 0);
        let id = s.record_stream(&stream("x.test"), vec![chunk(1, true, b"hi")], end(2, 2, 0)).unwrap();
        assert_eq!(s.stream_chunks(id, None, 10, None).unwrap()[0].data, b"hi");
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_observer_hears_started_chunks_and_ended_once_per_write() {
        let h = crate::StoreHandle::new(Store::open_in_memory().unwrap());
        let seen = std::sync::Arc::new(parking_lot::Mutex::new(Vec::<(i64, String, &'static str)>::new()));
        let log = seen.clone();
        assert!(h.set_on_streams(Box::new(move |rows| {
            log.lock().extend(rows.iter().map(|r| (r.id, format!("{}://{}:{}", r.scheme, r.host, r.port), r.what)));
        })));
        assert!(!h.set_on_streams(Box::new(|_| {})), "installed once");
        let mut ids = HashMap::new();
        h.write(|s| {
            s.apply_stream_ops(
                &mut ids,
                vec![
                    StreamOp::Open(1, NewStream { tls: true, ..stream("t.test") }),
                    StreamOp::Chunk(1, chunk(1, true, b"a")),
                    StreamOp::Chunk(1, chunk(2, false, b"b")),
                ],
            )
        })
        .unwrap();
        h.write(|s| {
            s.apply_stream_ops(&mut ids, vec![StreamOp::Chunk(1, chunk(3, true, b"c")), StreamOp::End(1, end(4, 2, 1))])
        })
        .unwrap();
        let got = seen.lock().clone();
        let t = "https://t.test:2525".to_string();
        assert_eq!(
            got,
            [(1, t.clone(), "started"), (1, t.clone(), "chunks"), (1, t.clone(), "chunks"), (1, t, "ended")]
        );
    }
}
