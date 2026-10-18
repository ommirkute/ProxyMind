# ADR-0006: Tauri 2 + React + TypeScript for the UI

**Status:** Accepted

## Context
The desktop UI must handle huge tables (a million-row history), raw request editing and live updates, and the same UI should later work in a browser for headless and team use.

## Decision
- Tauri 2 desktop shell with a React + TypeScript + Vite frontend.
- TanStack Table with virtualisation for history; Monaco for raw request/response editing; TanStack Query for API calls.
- The UI talks to the core only through the public API (ADR-0005), so the same frontend can be served as a web app.

## Consequences
- Small app bundle compared with Electron; shared code between desktop and web.
- Uses the system webview, so rendering differs slightly across platforms. Needs UI testing on macOS, Windows and Linux.
