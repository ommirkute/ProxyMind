# ADR-0020: Traffic hooks run in long-lived sandboxed plugin processes; plugin API v2 declares permissions

**Status:** Accepted (2026-11-16, roadmap Phase 2 work packages 2.1 and 2.9). Extends ADR-0014, ADR-0015 and ADR-0016.

## Context
Roadmap 2.1 asks for request and response hooks in the proxy, with time and memory limits, that change traffic in
flight and record the change next to the original. Roadmap 2.9 asks for a versioned plugin SDK whose manifest declares
permissions that the policy gate enforces. The roadmap left open whether hooks get a new WebAssembly runtime or reuse
the sandboxed plugin processes of ADR-0015 and ADR-0016.

Constraints:
- **The proxy path is latency-sensitive.** Starting a sandboxed process per request costs tens of milliseconds
  (`unshare`, `prlimit`, interpreter start), far too slow for traffic.
- **Bytes stay exact (ADR-0002).** A hook is "a rule asked for a change", so it may change bytes, but ProxyMind itself
  must not fix them up behind it (no recomputed `Content-Length`, no re-chunking).
- **Plugins run per user, never per project (ADR-0014),** and target content is untrusted.
- ADR-0016 kept WASM out of the core binary because of its size; nothing has changed that.

## Decision

### Hooks (2.1)
- **Long-lived workers.** A plugin that declares hooks gets one worker process per hook kind, started on first use in
  the same sandbox as other plugin processes (cleared environment, Linux user and network namespaces, `prlimit` on CPU,
  memory, files). It reads one JSON line per call from stdin and writes one JSON line per answer to stdout:
  `{"v":2,"id":N,"phase":"request"|"response","exchange":{...},"raw":"<base64>"}` →
  `{"id":N,"action":"pass"}` or `{"id":N,"action":"replace","raw":"<base64>","note":"..."}` or `{"id":N,"action":"drop"}`
  (`drop` only for requests, answered with ProxyMind's 403 like a dropped intercept).
- **Limits.** Each call has a deadline (manifest `timeout_ms`, default 200 ms, at most 2 s) and a size cap (8 MB per
  message; bigger, streamed, SSE and WebSocket traffic bypasses hooks and the record says so). At most a few calls are in
  flight per worker; when they're full, traffic bypasses the hook rather than waiting.
- **Failure is fail-open by default.** A timeout, crash, malformed answer or a replacement that `pm-http` can't parse
  forwards the original bytes, notes the failure on the exchange, and after 5 failures in a minute the hook is paused
  until a person resumes it. A manifest may ask for fail-closed (`on_error: drop`) for hooks whose purpose is blocking;
  the person sees that when turning the plugin on.
- **Order.** Match-and-replace rules run first, then hooks in the order the person lists them, then intercept (so a held
  request shows what the hooks made of it). Responses run hooks in the same order before the client gets them.
- **Scope.** Hooks see only exchanges that are in scope and match the manifest's `match` (hosts, path prefixes,
  methods, content types). They never see out-of-scope traffic.
- **Recording.** When any rule or hook changes a message, the exchange keeps the original bytes as received alongside
  the bytes as sent, plus which rules and hooks changed it (an append-only migration adds the columns). History shows
  both and a diff. Agents get the same, redacted and marked untrusted.
- **Turning hooks on is a person's act, audited.** Hooks change the person's own traffic, like match-and-replace
  rules, so individual calls aren't gated; enabling, pausing, resuming and reordering are. Agents can't turn hooks on.

### Plugin API v2 (2.9)
- **Versioned manifest.** `api: 2` in `proxymind-plugin.yaml` opts into v2; manifests without it keep v1 behaviour
  (passive checks, active checks, panels), unchanged.
- **Declared permissions.** A v2 manifest lists what the plugin may do: `hooks.request`, `hooks.response`,
  `checks.passive`, `checks.active`, `panels`, `history.read` (panels and checks that read beyond the exchanges they are
  given). The service refuses anything not declared, the UI shows the list when the plugin is installed and when it
  changes, and a changed permission list needs the person to accept it again (the integrity record of ADR-0016 already
  notices the manifest changed).
- **Enforced in `pm-service`.** Permission checks sit in the service layer next to the policy gate, so the API, MCP,
  CLI and UI can't route around them. Active checks still go through the gate as `plugin_check` (ADR-0015).
- **SDK.** Small helpers in the Python and TypeScript SDKs read and write the v2 frames and declare handlers, with an
  example hook plugin in `examples/plugins/` and a test that runs it through the proxy.

### Not chosen
- **A WebAssembly runtime (wasmtime or wasmi) now.** It would give the same isolation on every OS and fast calls, but
  adds a large dependency and a second plugin model. Long-lived workers make process plugins fast enough; WASM stays
  open for when cross-platform isolation is required.
- **A process per call.** Too slow for the proxy path.
- **Declarative rules only.** Match-and-replace already covers fixed rewrites; hooks exist for logic rules can't
  express (signing requests, re-encrypting bodies, custom protocols).

## Consequences
- Plugin authors can sign or rewrite traffic in any language, with the same sandbox and signatures as other plugins.
- A slow or broken hook can't stall browsing: it is bypassed or paused, and the record says what happened.
- Hooks off cost nothing on the proxy path; with hooks on, the Phase 2 gate (benchmark at most 10% worse) applies to
  traffic that bypasses them, and their own cost is the plugin's.
- On macOS and Windows, hook workers are not network-isolated (ADR-0015); signatures and declared permissions are the
  protection there.
- New storage columns and a migration; history, replay and evidence packs learn to show original and sent bytes.

## Migration
1. Store: original/sent bytes and the list of changes (migration); recorder and history show both. Match-and-replace
   rules start using it, which already improves today's record of rewritten traffic.
   **Done.** Principle: the primary recorded bytes are always what the target saw or produced, because passive checks,
   the scanner, proofs, reports and evidence read them (a rule that strips CSP for the browser must not make a check
   report CSP missing). So `request` is the request as sent to the server and `response` is the response as the server
   sent it (unchanged from before); the client's side is stored beside them, only when the bytes differ: `request_original`
   (the request as the client sent it) and `response_delivered` (the response as delivered to the client). Migration 22
   adds `req_orig_hash`, `resp_deliv_hash` (hashes into `blobs`, so deduplicated and compressed like `req_hash` and
   `resp_hash`) and `changes` (JSON list of `{phase, by, name, note?}`; `by` is `rule`, `intercept` or later `hook`).
   Full-text indexing still reads only `request` and `response`. Rules and intercept edits fill them on the HTTP/1.1
   and HTTP/2 paths (WebSocket handshakes go through the same step; WebSocket messages are not touched by rules). A
   rule that matches without changing the bytes, or an edit that ends where it began, records nothing. History marks
   edited rows (`is:modified`), the exchange view lists the changes and diffs them (request: client's to sent;
   response: server's to delivered), and agents get the same, redacted and untrusted. Evidence packs and reports still
   embed `request` and `response` only.

2. Plugin API v2: manifest `api: 2`, permissions, enforcement in `pm-service`, install and UI review.
3. Hook workers in `pm-plugin` (protocol, deadlines, bypass, pause), wired into the proxy after rules and before
   intercept; UI to turn on, order, pause and resume.
4. SDK helpers, an example hook plugin, a browser test and a proxy test with a hook that times out.
