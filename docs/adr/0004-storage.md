# ADR-0004: SQLite project files

**Status:** Accepted

## Context
A project holds hundreds of thousands to millions of exchanges, needs fast search, and must be easy to copy, archive and hand over to a client, like a `.burp` file.

## Decision
- One SQLite database per project (`*.pmproj`), WAL mode, schema migrations tracked with `user_version`.
- Request and response bytes are stored in a `blobs` table, zstd-compressed and keyed by blake3 hash, so repeated content is stored once.
- Writes go through a dedicated writer thread fed by a channel, so the proxy never waits on disk.
- Full-text search (FTS5) will be added in M1/M2.

## Consequences
- Portable single file; mature tooling; no server to run.
- One writer at a time. That is fine for a desktop tool; a team server (later) will use a different backend behind the same interface.
