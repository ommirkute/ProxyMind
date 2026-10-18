# ADR-0008: Web UI first, desktop shell later

**Status:** Accepted (amends ADR-0006)

## Context
ADR-0006 chose Tauri 2 + React for a desktop UI. Tauri needs the platform webview and GUI libraries to build and test, which most CI runners and remote development environments don't have, and the UI must talk to ProxyMind only through its public API (ADR-0005) anyway.

## Decision
- Build the UI as a React + TypeScript web app (Vite), served by the `proxymind` binary itself: `proxymind ui` starts the proxy and the REST API and serves the UI on `127.0.0.1:7777`.
- The built UI is compiled into the binary; without Node.js a placeholder page is embedded so `cargo build` always works.
- Test the UI in a real browser (Playwright + Chromium) in CI.
- A Tauri desktop shell remains planned. It will wrap the same web UI with no changes to it.

## Consequences
- One UI codebase for local use, remote/team use and the future desktop app.
- Users open a browser tab instead of a native window for now.
- The API had to be hardened for browsers: loopback only, Host check against DNS rebinding, token exchanged for an HttpOnly SameSite=Strict cookie, custom header required for state changes, strict CSP.
