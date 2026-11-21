# Workflows

A **workflow** is a saved, named chain of steps for the multi-request jobs you would otherwise do by hand: log in, read a token out of the answer, call an API with it, check the result. It works on a **current exchange** (the one you start on, then the answer to each send) and runs on demand, by itself on new proxied traffic, or on every result of a Fuzzer attack.

Workflows build on what is already there: extraction is the session handling extractor (regex, JSON pointer, header, cookie) plus HTML inputs; transforms are the same operations as the editors' inline transforms (`ui/src/transforms.ts`), implemented again in `pm_tools::transform` with test vectors both sides run; conditions are HTTP-history style tests or an HQL query; every send is a gated send like Replay's.

- Page: **Workflows** (Testing). Right-click an exchange in HTTP history, **Run workflow…**.
- CLI: `proxymind workflow list` and `proxymind workflow run <name> [--exchange N] [--approval ID]`.
- REST: see [API](#rest-api). MCP tools: `workflow_list`, `workflow_get`, `workflow_run`.
- Not supported: loops, branches and jumps. Steps run once, in order. That is what makes the limits real.

## Limits

| Limit | Value |
|---|---|
| Steps in a workflow | 50 |
| Sends in a workflow, and in a run | 20 |
| Time of a run (waiting for an approval does not count) | 120 s |
| Variables in a run | 100, each at most 16 KB |
| Workflows in a project | 100 |
| Runs kept | the newest 200 |
| Automatic runs per workflow | 1 to 60 per minute (default 6), 4 at once in all |

## Variables

`{{name}}` in a request template, an edit value, a transform or a text test is replaced by the variable's value. A variable that is not set is an error and **nothing is sent**: a half-filled request never goes out. A workflow is checked when it is saved: every `{{name}}` must be set by an earlier step.

Names are letters, digits and `_`, not starting with a digit. Names starting with `current_` are the workflow's own, set from the current exchange at the start and after every send: `current_exchange`, `current_scheme`, `current_host`, `current_port`, `current_method`, `current_path`, `current_status`.

`{{secret:NAME}}` placeholders (the project's secret store) are not variables; they work in request templates as they do in Replay.

Values come from responses, so they are untrusted:

- A variable never holds a carriage return, a line feed or NUL, whether it was extracted, built from a template or produced by a decoding (`url_decode` of `%0d%0a` fails the step). A value cannot add a header or a second request.
- The target of a send cannot contain variables: a response cannot choose where the next request goes.
- The request is classified and gated **when it is built**, after the values are in. A value that turns a request into `DROP TABLE users` is classified as destructive, which is refused for agents and needs approval for people, like the same request typed into Replay.
- Messages in a run (the `message` of each step, assertion text, `reason`) never quote the target. Variable values are the one place target text appears.

## Steps

Every step has a `type`. A step is a JSON object; the page builds the same.

### `match`

Stop the run (status `stopped`, with the reason) unless the **current exchange** fits. It is how a workflow says what it is for.

```json
{"type": "match", "method": "POST", "path_contains": "/api/login", "status": "2xx",
 "message": "only successful logins"}
```

A condition has these tests; every test that is set must hold, and at least one is required:

| Field | Meaning |
|---|---|
| `status` | `200`, `2xx`, `200..299` (or `200-299`) or a list: `200,302,4xx` |
| `method` | `POST`, or `GET,HEAD` |
| `path_contains` | text in the path and query (`{{var}}` allowed) |
| `header`, `header_contains` | the header is present; one of its values contains the text (case-insensitive) |
| `body_contains`, `body_regex` | in the decoded body (de-chunked, decompressed); the regex is a Rust regex |
| `hql` | a history query on the exchange: `status:200 resp:"token" is:inscope` (see HTTP history's help) |
| `var`, `var_equals`, `var_contains`, `var_matches` | a variable: alone it must be set and not empty |
| `side` | `request` or `response` (default) for `header`, `body_contains`, `body_regex` |
| `negate` | pass when the tests do **not** all hold |
| `message` | what a failed `assert` says, or why a `match` stopped the run |

### `assert`

The same condition. A failed assert marks the run `failed` and is listed in `assertions`, but **the run goes on**: later steps still run (there is no stop-the-world), so one run shows every check that failed.

```json
{"type": "assert", "status": "200", "body_contains": "{{name}}", "message": "the order is alice's"}
```

### `extract`

Read a value from the current exchange into a variable.

```json
{"type": "extract", "name": "token", "kind": "json", "expr": "/token"}
```

| `kind` | `expr` is | Notes |
|---|---|---|
| `regex` (default) | a regular expression | `group` picks the capture group; default is group 1 if the pattern has one, else the whole match. Looks at the head and the decoded body |
| `json` | a JSON pointer, `/data/token` | numbers and booleans become their text |
| `header` | a header name | |
| `cookie` | a cookie name | `Set-Cookie` of a response, `Cookie` of a request |
| `html_input` | an input's `name` (or `id`) | its `value`, entities decoded: the hidden CSRF field |

`side` is `response` (default) or `request`. When nothing is found the run fails at this step, unless `"optional": true` (the variable stays unset and the run goes on).

### `transform`

Set a variable from a template, then apply operations in order.

```json
{"type": "transform", "name": "basic", "value": "{{user}}:{{password}}", "ops": ["base64_encode"]}
```

Operations (the same as the editor's Transform menu, strict like it: a bad input fails the step): `url_encode`, `url_decode`, `url_encode_full`, `url_decode_full`, `base64_encode`, `base64_decode`, `base64url_encode`, `base64url_decode`, `html_encode`, `html_decode`, `hex_encode`, `hex_decode`, `unicode_encode`, `unicode_encode_all`, `unicode_decode`, `json_escape`, `json_unescape`, `md5`, `sha1`, `sha256`. With no `ops`, the variable is just the filled-in template.

### `send`

Build a request and send it **through the gate**. Its response becomes the current exchange.

```json
{"type": "send", "url": "http://127.0.0.1:8081",
 "raw": "GET /api/orders/{{id}} HTTP/1.1\r\nHost: shop\r\nAuthorization: Bearer {{token}}\r\n\r\n"}
```

Or resend the current exchange's request with edits:

```json
{"type": "send", "edits": [
  {"op": "set_header", "name": "X-Token", "value": "{{token}}"},
  {"op": "set_param", "name": "page", "value": "2"},
  {"op": "replace_text", "find": "/orders/1001", "replace": "/orders/{{id}}"}
]}
```

| Field | Meaning |
|---|---|
| `url` | `scheme://host[:port]`; default the current exchange's server; **no variables** |
| `raw` | a whole request with `{{var}}` and `{{secret:NAME}}`; default the current exchange's request |
| `edits` | applied in order after the template is filled in: `set_header`, `remove_header`, `set_param` (query, form body or top-level JSON; added where it belongs when missing), `replace_text` (`regex: true` for a pattern; fails when nothing matches, so a typo is not a silent no-op) |
| `identity` | send with this test identity's credentials (`anonymous` for none); a login recipe re-logs in when the session looks gone |
| `fix_content_length` | default true |

With no current exchange (a run that starts without one) a send needs `url` and `raw`.

**How a send is gated and recorded.** Each send is one `gate_send_with` call, action `workflow_send`, exactly like `replay_send`: the target must be in scope (a denied send ends the run with status `denied` and the reasons), the tier comes from the method and the payload classifier, an agent needing approval pauses the run, rate limits and the DNS check apply, identity credentials and `{{secret:…}}` are filled in at send time, and the request and its audit record carry the actor. The exchange is recorded in history with source `workflow` and the actor who ran it. Session handling rules apply to workflow sends without an identity, as they do to Replay.

## Runs

A run is stored (`workflow_runs`, the newest 200) and has: who ran it and how it started (`manual`, `exchange` or `fuzzer`), the starting exchange, a `status`, the steps that ran (result, a message without target content, the exchange a send made, time), the variables at the end, every exchange it sent, assertion results and the duration.

| Status | Meaning |
|---|---|
| `ok` | every step ran, every assertion held |
| `failed` | an assertion failed, a step could not run (nothing extracted, a bad transform, a send error, an unset variable) or a limit was reached |
| `stopped` | a `match` did not fit |
| `denied` | the gate refused a send (scope, tier, actor) |
| `pending_approval` | a send waits for a person's approval |

**Approvals pause the run, they do not restart it.** An agent's send that needs approval returns `pending_approval` with `pending.approval_id`. After a person approves it, the agent calls `workflow_run` again with the same `workflow` and `exchange_id` plus `approval_id`: the run continues from that send, with its saved variables and current exchange, so earlier steps (a login, say) are not sent a second time. The approval covers those exact bytes, the workflow and the step; it is single-use, and a run does not continue on a workflow edited since or after a day. Several sends needing approval give several rounds. A call before the approval is decided leaves the run waiting.

Events: `workflows` topic (`workflow_changed`, `workflow_run_changed`: ids and state words only), so the page updates without polling. Agents get only their own runs' events.

## Who can do what

| | People | Agents (MCP) |
|---|---|---|
| list, read, run workflows; read runs | yes | yes (their own runs; templates and values hidden, see below) |
| create, edit, delete | yes, audited | no (audited as a denial) |
| turn the per-exchange trigger on or off | yes, audited | no |

What agents see: names, step kinds, tests and extraction rules, but in `send` steps the request template shows only the request line and header names (values, query values and body hidden, `[body hidden, N bytes]`) and edit and transform values are hidden unless they are only references like `{{token}}` or `Bearer {{token}}`. In a run, variable values are hidden when their name suggests a secret (`token`, `session`, `csrf`, `password`, `key`, `auth`, `cookie`, …) and all others are redacted and wrapped as untrusted target content. People see everything. The audit log keeps step kinds, never request text.

## Per-exchange trigger

A workflow whose **first step is a `match`** that looks at the exchange (not only variables) can run by itself on each new proxied exchange that fits it. It is off by default; **only a person turns it on** (Workflows page, "On new traffic", or `PUT /workflows/{id}/trigger`), it is audited, and **editing the steps turns it off again**. Runs go through the gate as the person who turned it on.

Design: the proxy never calls a workflow. When the recorder commits an exchange, the service publishes an `exchange_recorded` event on the event bus (ADR-0018) and moves on; `Service::run_workflow_triggers` (started by `proxymind ui` and the desktop app next to the scheduler) is a separate task that receives the event, and only then reads the exchange, checks the first `match`, and starts the run on its own task. A slow workflow cannot slow a response down (a test sends browser traffic through the real proxy while a workflow takes 1.5 s to run). Only exchanges with source `proxy` and in scope start workflows, so what workflows, Replay or scans send never starts another run.

Rate cap: `max_per_minute` (1 to 60, default 6) per workflow, sliding minute, and at most 4 automatic runs at once. Exchanges past either limit are **skipped, not queued** (the page shows the count). Events lost while the task is busy or the bus lags are not replayed: a trigger is best effort, not a guarantee that every matching exchange runs.

## From the Fuzzer

`FuzzerRequest.workflow` (the Fuzzer page's **Workflow on each result**; the CLI and MCP `fuzzer_run` take `workflow`) names a workflow to run on each result, with the result's exchange as the current one: extract a value, assert on every answer. The result row gets `workflow`: the run id, its status, the reason and the variables, and the page shows them in a column. Minimal by design: the baseline is not a result, and the attack does not stop when a run fails. The workflow's definition is part of what the attack's approval covers; its own sends are gated one by one as the actor who runs the attack, so one that needs approval shows `pending_approval` in the row (continue it from the Workflows page).

## REST API

All under `/api/v1`; bodies and results are in `docs/api/openapi.json`.

| Route | |
|---|---|
| `GET /workflows`, `POST /workflows` | list; create (`{name, description, steps}`) |
| `GET /workflows/{id}`, `PUT`, `DELETE` | by id or name; replace; delete (and its runs) |
| `PUT /workflows/{id}/trigger` | `{enabled, max_per_minute?}` |
| `POST /workflows/{id}/run` | `{exchange_id?, approval_id?}` → the run |
| `GET /workflows/runs?workflow=&limit=`, `GET /workflows/runs/{id}` | run history |

## Example: log in, then read an order

```json
{
  "name": "login-and-orders",
  "description": "Log in as alice, read an order with the token, check the answer",
  "steps": [
    {"type": "send", "url": "http://127.0.0.1:8081",
     "raw": "POST /api/login HTTP/1.1\r\nHost: shop\r\nContent-Type: application/json\r\n\r\n{\"username\":\"alice\",\"password\":\"alice123\"}"},
    {"type": "assert", "status": "200"},
    {"type": "extract", "name": "token", "kind": "json", "expr": "/token"},
    {"type": "transform", "name": "auth", "value": "Bearer {{token}}"},
    {"type": "send", "url": "http://127.0.0.1:8081",
     "raw": "GET /api/orders/1001 HTTP/1.1\r\nHost: shop\r\nAuthorization: {{auth}}\r\n\r\n"},
    {"type": "assert", "status": "200", "body_contains": "alice", "message": "alice reads her own order"}
  ]
}
```

Put passwords in `{{secret:NAME}}` placeholders rather than the template when agents will run the workflow.

## Where it lives

- Definitions: the project setting `workflows` (a JSON list: small, edited by people, saved as a whole like session rules and custom checks).
- Runs: table `workflow_runs` (migration 24): they pile up, survive a restart, and a paused run is resumed from its row.
- Code: `pm_tools::transform` (operations), `pm-service/src/workflow.rs` (model, validation, conditions, extraction, edits, the engine with a fake-able `Host`), `pm-service/src/workflow_service.rs` (storage, gate, runs, triggers, fuzzer).
