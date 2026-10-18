# RFC 0001: Service API and MCP tools

**Status:** Draft  ·  **Milestones:** M2 (v0), extended through M6

## Summary

Defines the one service layer (`pm-service`) that every client uses, how actions are classified and approved, and how the same operations appear over REST and MCP. Writing this before any UI code keeps humans and agents on equal footing (ADR-0005).

## Principles

1. **One API, many clients.** REST, MCP, CLI and the UI are thin adapters over the same service calls.
2. **Every call has an actor.** `human:<name>`, `agent:<id>`, `plugin:<id>`, `scanner`. The actor is set by the adapter from its credentials, never from the request body.
3. **Every call has a tier.** The policy gate uses it with the ROE file to decide: allow, require approval, or deny.
4. **Responses are token-aware.** Anything that returns traffic accepts `view` and `max_tokens`.
5. **Target content is labelled untrusted.** Agent-facing responses wrap target-originated text so models can tell data from instructions.

## Action tiers

| Tier | Examples | Default for agents |
|---|---|---|
| `read` | search history, read model, list findings | allow |
| `passive` | analysis on stored data, diffing | allow |
| `active_safe` | replay a GET, authz check with GET | allow |
| `active_intrusive` | payload fuzzing, parameter tampering | approve |
| `destructive` | DELETE, state-changing payloads on sensitive endpoints | deny |

The ROE file can change these per actor type. Out-of-scope targets are always denied, whatever the tier.

## Approvals

A call that needs approval returns:

```json
{ "status": "pending_approval", "approval_id": "apr_01J...", "summary": "Send 400 requests testing SQL injection on `sort` (GET /api/products)", "tier": "active_intrusive" }
```

The human approves or denies in the UI or CLI. The agent polls `approval_status` or listens on the event stream. Approved calls run with the original parameters; they can't be changed after approval.

## Views

`exchange_get(id, view, max_tokens)`:

| View | Contents |
|---|---|
| `summary` | method, URL, status, sizes, content types, notable headers, a short body preview (about 100 tokens) |
| `headers` | full request and response headers, no bodies |
| `full` | everything, truncated to `max_tokens` while keeping forms, JSON keys, errors and reflected input |

When redaction is on (ROE `data.redact_before_llm`), secrets become placeholders such as `{{secret:session_cookie_1}}`. Agents can use placeholders in requests; the service swaps the real values back in when sending.

## Operations (v0 in bold)

| Area | Operation | Tier |
|---|---|---|
| History | **`history_search(query, limit)`**, **`exchange_get(id, view, max_tokens)`** | read |
| Replay | **`replay_send(raw \| exchange_id + edits, identity?)`** | by method and target |
| Replay | `replay_send_parallel(requests[], single_packet)` | active_intrusive |
| Scope | **`roe_get()`** | read |
| Model | `model_operations(filter)`, `model_objects(type)`, `operation_get(id)` | read |
| Identity | `identity_list()`, `replay_as(exchange_id, identity)` | active_safe or higher |
| Diff | `diff_exchanges(a, b)` | passive |
| AuthZ | `authz_matrix(filter)`, `authz_check(operation, identities[])` | active_safe |
| Ledger | `hypothesis_create(...)`, `hypothesis_update(id, status, note)`, `coverage_gaps(filter)` | read/passive |
| Proof | `oast_payload(hypothesis_id)`, `proof_run(oracle, inputs)`, `finding_create(...)`, `finding_list(filter)` | varies |
| Safety | **`approval_status(id)`**, `agents_stop()` (humans only) | read |

## REST mapping

`/v1/...` with JSON bodies; the OpenAPI spec is generated from the Rust types (`utoipa`). Example: `POST /v1/replay/send`, `GET /v1/exchanges/{id}?view=summary&max_tokens=500`. Auth: random bearer token per install; server binds to `127.0.0.1` by default.

Live events (new exchanges, approval decisions, findings) are streamed over `GET /v1/events` (WebSocket or SSE).

## MCP mapping

Each operation becomes an MCP tool with the same name and a JSON schema generated from the same Rust types. MCP resources expose the ROE file and the app model summary. One MCP prompt, `start_engagement`, explains the workflow: read the ROE, look at the model, create hypotheses, test, prove, record findings.

## Audit

Every call, including denied ones, is appended to the hash-chained audit log: actor, operation, parameters hash, decision, timestamp. `proxymind audit verify` checks the chain.

## Open questions

- Should agents be able to propose ROE changes (always needing human approval), or never touch the ROE?
- Per-agent token budgets: enforce in the service layer or leave to the agent runtime?
- Streaming large results to agents: pagination only, or resource links?
