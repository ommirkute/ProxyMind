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
- **The gate governs agents that reach ProxyMind only through MCP (or a scoped API path), not agents that can run commands.** An agent that can run shell commands or read files as the same operating-system user can read `~/.proxymind/api-token` and call the REST API as the human (change the rules of engagement, approve its own requests), edit the project file and rebuild the audit chain (it is unkeyed), and read the CA key. This decision assumed the agent is confined to MCP tools; that is true of a client with no shell and no file tools, or of ProxyMind running as another user with only the MCP stdio pipe given to the agent, and false of most coding agents as they are usually set up. `docs/agents.md` ("What the policy gate does and doesn't contain") says so to users and gives that guidance. Code mitigations come in Phase 3: per-agent scoped tokens, a project server that holds the project and the rules, and a keyed audit chain (ADR-0022; threat model F-1). Added 2026-11-21.
- A project file is active content, so the gate also depends on which project it reads its rules from: a project this installation does not trust (one that came from somewhere else) is opened in safe mode and the gate refuses every action by a non-person until a person has reviewed and trusted it (ADR-0022 step 0; threat model F-2).
