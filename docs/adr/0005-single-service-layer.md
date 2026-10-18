# ADR-0005: One service layer behind a policy gate

**Status:** Accepted

## Context
Humans (UI, CLI), agents (MCP, REST) and plugins all need the same capabilities. If any of them can reach lower crates directly, scope and rules-of-engagement enforcement can be bypassed, for example by a prompt-injected agent.

## Decision
- `pm-service` is the only place actions happen. `pm-api`, `pm-mcp`, `pm-cli` and the UI call it and nothing below it.
- Every call carries an **actor** (`human:alice`, `agent:claude-1`, `plugin:x`) and passes through `pm-policy`, which checks scope, the ROE file, rate limits and action tiers, asks for approval when required, and writes the audit log.
- The UI gets no private shortcuts: anything a human can do, an agent can request, and the same rules apply.

## Consequences
- Scope enforcement can be tested in one place and cannot be skipped by a client.
- Slight extra indirection for simple features. Worth it.
- Crates lower in the stack must never import higher ones; CI will check this.
