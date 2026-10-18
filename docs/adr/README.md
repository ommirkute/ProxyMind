# Architecture decision records

Short records of decisions that are hard to reverse. Each one says what was decided, why, and what it costs. To change a decision, add a new ADR that supersedes the old one; don't edit accepted ADRs.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-rust-core.md) | Rust for the core | Accepted |
| [0002](0002-raw-http.md) | Own raw HTTP/1.x parser that keeps exact bytes | Accepted |
| [0003](0003-tls-backend.md) | rustls (ring), with optional OpenSSL later for legacy targets | Accepted |
| [0004](0004-storage.md) | SQLite project file + compressed, deduplicated blobs | Accepted |
| [0005](0005-single-service-layer.md) | One service layer behind a policy gate for every client | Accepted |
| [0006](0006-ui-tauri.md) | Tauri 2 + React + TypeScript for the UI | Amended by 0008 |
| [0007](0007-license.md) | AGPL-3.0 core, Apache-2.0 SDKs | Accepted |
| [0008](0008-web-ui-first.md) | Web UI served by the binary first; Tauri shell later | Accepted |
