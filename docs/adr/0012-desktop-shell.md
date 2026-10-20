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
- Native extras: a tray menu (open, switch project, trust the CA for this user, quit); installers are built by `cargo tauri build` in releases.
- The project picker is a *local* app page (`static/setup.html`) and the only page that may call the app's commands (`list_projects`, `open_project`, `create_project`). The ProxyMind UI stays a remote page with no IPC, so target content shown there can never reach native code. Switching projects saves the choice to `~/.proxymind/desktop.json` and restarts the app, rather than running two stacks (the proxy port can't be shared).
- Trusting the CA uses the operating system's own per-user store and prompt (`security add-trusted-cert` on macOS, `certutil -user -addstore Root` on Windows, the NSS database on Linux); it never asks for administrator rights. The Proxy setup page in the web UI covers the same steps by hand, with the certificate's SHA-256 fingerprint to compare.
- CI lints the app on Linux, macOS and Windows; tagged releases ship unsigned installers for all three (code signing is next).
