# ADR-0014: Plugins act through the gate or analyse recordings, and are installed per user

**Status:** Accepted

## Context
ProxyMind should be extensible by people who don't write Rust, without a second, unguarded path to targets (ADR-0005) and without trusting code that arrives inside a project file.

## Decision
- **Acting plugins** are MCP clients: `proxymind mcp --actor plugin:<name>`. They use the same tools and the same policy gate as agents, with stricter default tiers (active-safe needs approval, anything more is denied unless the ROE says otherwise).
- **Passive-check plugins** analyse recorded traffic and send nothing themselves. A plugin is a directory with `proxymind-plugin.yaml` naming a command. The passive scan runs it in its directory, writes one JSON line per exchange (ids, target, status, raw request and response in base64) to its stdin and reads one JSON line per issue from its stdout. Output is capped (8 MB, 2000 issues, a timeout), every issue is validated (known exchange id, check name, severity), clipped and labelled `<plugin>/<check>`. A failing plugin becomes an info issue, not an error.
- Plugins are installed **per user** (`proxymind plugin add <dir>` → `~/.proxymind/plugins.json`), never per project, so a project from someone else can't make your machine run code. They run as you: install only code you trust.
- Plugin issues are leads like the built-in passive checks; findings still need a proof.

## Consequences
- Any language works; `examples/plugins/jwt-check` (Python) shows the protocol.
- No sandbox yet: plugins have the user's permissions. Running them in a container or under OS sandboxing is future work, as are active-check plugins that propose requests for the gate to send.
