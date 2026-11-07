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
| [0009](0009-http2-as-text.md) | HTTP/2 as text, sent with the h2 crate | Accepted |
| [0010](0010-assistant-is-an-agent.md) | The built-in assistant is an agent like any other | Accepted |
| [0011](0011-xss-proofs-offline-browser.md) | XSS proofs render the recorded response in an offline headless browser | Accepted |
| [0012](0012-desktop-shell.md) | The desktop app runs the local stack in-process and shows the web UI | Accepted |
| [0013](0013-sealed-projects.md) | Projects are encrypted at rest by sealing, before transparent encryption | Accepted |
| [0014](0014-plugins.md) | Plugins act through the gate or analyse recordings, and are installed per user | Extended by 0015 |
| [0015](0015-active-plugins-and-sandbox.md) | Active-check plugins propose requests that ProxyMind sends; plugin processes run sandboxed | Extended by 0016 |
| [0016](0016-signed-plugins-and-panels.md) | Signed plugins, install-time integrity checks, and data-only plugin panels; no WASM runtime yet | Accepted |
