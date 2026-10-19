# ADR-0012: The desktop app runs the local stack in-process and shows the web UI

**Status:** Accepted (implements ADR-0006 as amended by ADR-0008)

## Context
ADR-0008 made the web UI the product and kept a Tauri shell for later. A desktop app should feel native (one window, a tray icon) without a second UI or a second way into the core.

## Decision
- `desktop/` is a Tauri 2 app that starts the same stack as `proxymind ui` inside its own process: the API on a random loopback port, the proxy on `127.0.0.1:8080` when it's free (otherwise the UI runs without it and the title says so), the project from the first argument, `PROXYMIND_PROJECT` or `~/.proxymind/desktop.pmproj`.
- The window opens the UI's login link. The page is a remote `http://127.0.0.1` page, so it has **no Tauri IPC**: it talks to `/api/v1` exactly like a browser tab, with the same token, Host check and CSP. The only bundled page is a static setup page shown when the project can't be opened.
- `desktop/` is outside the main workspace (`exclude` in `Cargo.toml`): building ProxyMind never needs WebKitGTK. CI builds and lints it in its own Linux job.

## Consequences
- No UI code is duplicated, and the desktop app can't do anything the API doesn't allow.
- Native extras so far: a tray menu (open, quit) showing the CA certificate path. Project pickers, a CA install helper and installers (`tauri build`) are next.
- macOS and Windows builds aren't in CI yet.
