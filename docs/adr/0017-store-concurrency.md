# ADR-0017: Store concurrency: a read pool and one writer

**Status:** Accepted (2026-11-14, roadmap work package 1.1)

## Context
Roadmap work package 1.1 removes the "one database connection per process" gap. What the code does today:

- `Service` holds `store: Mutex<Store>` (`crates/pm-service/src/lib.rs`, `parking_lot::Mutex`, a blocking lock). There are 192 `store.lock()` call sites in 47 files under `crates/pm-service/src` (8 in `lib.rs`; the most in `proof.rs` 15, `identity.rs` 13, `scan.rs` 10). Reads and writes take the same lock.
- `Store` (`crates/pm-store/src/lib.rs`) wraps one `rusqlite::Connection`. `Store::open` / `Store::open_in_memory` call `init`, which sets `busy_timeout` to 10 s, `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, then `migrate()`. Migrations are an append-only `MIGRATIONS` list applied in `IMMEDIATE` transactions and tracked in `user_version`. `insert_exchange` also uses an `IMMEDIATE` transaction.
- Writers: the proxy `Recorder` (`crates/pm-proxy/src/lib.rs`, `Recorder::spawn`) already runs its own writer thread on its own `Store` connection, fed by a `std::sync::mpsc::sync_channel` of 4096 records. Everything else writes through the service mutex: `Service::audit` (`lib.rs`: `last_audit`, `audit::next_record`, `append_audit` under one lock), replay, race and WebSocket replay inserts (`replay.rs`, `race.rs`, `ws_replay.rs`, `group.rs`), HAR import (`traffic.rs`, a loop of `insert_exchange` under one lock), findings, scans, settings (`set_setting`).
- Readers: `history_search`, `history_search_text` (`search.rs`: pages of summaries, then `self.store.lock().get_exchange(..)` per row, decoding bodies in between), the UI and API queries, reports, `Service::status` and `verify_audit` (`audit_records()` reads the whole log).

So there are already two write connections to one file (recorder and service), contending on SQLite's write lock with a 10 s busy timeout, while every service read waits behind every other service call. Under WAL, readers do not block the writer, so the mutex, not SQLite, is what makes a long read hurt other service calls.

## Decision
Keep SQLite, rusqlite and one `.pmproj` file. Put the store behind a `StoreHandle` in `pm-store` with two sides:

- **Read pool.** N read-only connections (`SQLITE_OPEN_READ_ONLY`, same pragmas except `journal_mode`), N = min(4, cores), in a small hand-written pool (a `Vec` plus `parking_lot::Mutex` and `Condvar`; no new dependency). `handle.read(|s| ..)` borrows a connection for the closure only. Each call sees one consistent WAL snapshot.
- **One writer.** A single writer thread owns the only write connection and receives `WriteCmd` values over a bounded channel (capacity 4096, as the recorder's today). `handle.write(|s| ..)` boxes a closure, sends it with a `oneshot` reply and waits for the result (the call is synchronous for `pm-service` callers, so its public API does not change). Typed commands (`InsertExchange`, `AppendAudit`, ...) replace closures where batching matters.
- **Read-your-writes.** The writer replies only after `COMMIT`. A read started after the reply sees the row under WAL, because the pool takes its snapshot when a read transaction begins, not when the connection is created. Reads never reuse an open read transaction across calls.
- **Recorder.** `Recorder::spawn` stops owning a `Store`; it sends `InsertExchange` / `InsertWsMessage` commands to the shared writer. The writer drains up to 256 commands or 20 ms of queue into one `IMMEDIATE` transaction (one commit, one fsync-equivalent), then replies to each. Blobs are still hashed and compressed (`put_blob`) inside the transaction; moving zstd out of the writer, onto the sender, is allowed later if it shows up in profiles.
- **Audit chain.** `Service::audit` becomes one write command that reads the last record, computes `next_record` and appends, all inside the writer. One writer serializes the chain, so `seq` and `prev_hash` stay correct even with batching; an audit command is never merged out of order with commands queued before it. `audit_log.seq` stays a primary key as a backstop.
- **Backpressure.** The channel is bounded. When it is full, senders wait (as `SyncSender::send` does today); traffic is never dropped silently. For the proxy this means requests slow down instead of memory growing. The wait is counted and exposed (queue depth, longest wait) in status, and a `warn` is logged once a wait passes 1 s. A failed write is logged and counted as today, and also surfaces in status as "recording errors". Dropping is not an option; if the disk is truly stuck, the limit is the existing 64 MB `RECORD_CAP` per response plus the bounded queue.
- **Sealed projects.** `pm-vault` seals a snapshot (`snapshot_to`, `VACUUM INTO`, ADR-0013) of an unlocked file; it never touches live connections. `Store::open` still rejects a `PMLOCK1` file before any connection opens. Snapshots run as a read on the pool, so they no longer block the writer. If transparent encryption (SQLCipher) arrives later, every pool connection and the writer must be keyed with the same `PRAGMA key` in `init`; this ADR does not depend on it.
- **In-memory stores (tests).** `open_in_memory` uses a named shared-cache URI (`file:pm-<uuid>?mode=memory&cache=shared`) so the pool and the writer see one database. Shared-cache uses table locks and can return `SQLITE_LOCKED`, so the handle falls back to a single connection (reads and writes through one mutex, the current behaviour) if that proves flaky; tests that need pool behaviour use a temp file instead. WAL does not apply to memory databases.
- **Migrations.** `migrate()` runs on the writer connection before the pool opens, at `open` time, as now. There is no live migration: a schema change always happens before readers exist.

## Migration path
Each step keeps `pm-service`'s public API unchanged (ADR-0005) and ships on its own.

1. **`StoreHandle` over the existing mutex.** Add `read(|s| ..)` and `write(|s| ..)`; replace the 192 `self.store.lock()` uses mechanically (`read` for `&self` methods of `Store`, `write` for `&mut self`). Behaviour is identical. Test: the whole existing suite; a grep test that no `store.lock()` remains.
2. **Reads on the pool.** Open N read-only connections for file projects; `read` uses them, `write` still uses the mutex connection. Test: a long `history_search_text` no longer delays `Service::status`; read-your-writes after a write returns; tests on `open_in_memory` keep the single-connection path.
3. **Writes on the writer task.** Move `write` to the writer thread and channel; port `Service::audit` to one command. Test: concurrent audit calls from many threads give `verify_audit` success with contiguous `seq`; a full-queue test shows senders wait and nothing is lost.
4. **Batch and merge the recorder.** `Recorder` sends to the shared writer; group commits. Test: byte-exact proxy tests (ADR-0002) unchanged, WebSocket links to `exchange_id` still correct, 100k-insert throughput up against the one-transaction-per-row baseline.

## Alternatives considered
- **Keep the mutex.** Simplest, but a content search or report holds back every other call, and the recorder's separate connection still fights the service's for the write lock. Fails the 1.1 target.
- **r2d2 / deadpool-sqlite pools.** Pool both reads and writes; they do not give us a single ordered writer or batching, and add a dependency for about 60 lines of code. SQLite allows one writer anyway, so a writer pool only moves the contention to `busy_timeout`.
- **Postgres or another server database.** Real concurrent writers, but the owner wants single-file offline projects that can be copied and handed over (ADR-0004, ADR-0013). A team backend may sit behind the same `StoreHandle` interface later; not now.
- **sqlx (async).** Its SQLite driver runs on a worker thread per connection anyway, brings compile-time query checking we do not use, and would make every store call `async`, rippling through 47 files and `pm-service`'s sync API. Not worth it.

## Consequences
- Reads scale with cores and never queue behind writes; recorder writes are batched, so the proxy path pays for fewer commits.
- ADR-0004's line "writes go through a dedicated writer thread" becomes true for all writes, not only the recorder's.
- **Risks.**
  - A read closure must not be held across an `.await` or while calling `write`. The pool is sync-only and the closures are not `Send` futures, so this is mostly enforced by the types; a `write` from inside a `read` is a self-deadlock if the pool is exhausted, so the debug build panics on nested use (thread-local flag).
  - A slow write closure (HAR import of thousands of rows, VACUUM) stalls every other write, including recording. Bulk work is split into chunks of at most 500 rows per command, and `snapshot_to` is a read.
  - Closures sent to the writer must not call back into `Service` (it would wait on its own queue).
  - Clean-shutdown must drain the queue; the join handle is awaited as `Recorder::spawn` callers do today.
  - A reader opened before a commit does not see it. Any code that writes and then reads must wait for the write reply, which `write` guarantees by being synchronous.
  - WAL growth: a reader holding a snapshot for minutes blocks checkpoints. Reads are short-lived; the pool adds a periodic `wal_checkpoint(PASSIVE)` from the writer.
- **Full-text index (1.4).** Since 2026-11-14 a background indexer per `Service` writes the full-text index in batches on its own connection, so recording doesn't pay for it. It is a second writer, competing with the recorder for the write lock (stalls up to about 180 ms on the recorder's thread in the debug benchmark). With the single writer, indexing moves into the writer's batches and that thread goes away; WAL checkpoints move to the writer as well (measured: p99 insert stall 8 ms -> 0.4 ms when checkpoints leave the insert path).
- **Verification (1.6).** The benchmark records 2,000 requests a second through the proxy while `history_search_text` runs over the 1M-exchange project, and measures the time from `Recorder::record` to the enqueue for each request. Pass: no enqueue waits over 50 ms, no loss (row count equals request count), `verify_audit` passes. Numbers go in the docs and are tracked weekly.
