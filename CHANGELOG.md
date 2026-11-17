# Changelog

All notable changes to ProxyMind. Versions follow [semantic versioning](https://semver.org/); before 1.0, a minor
version may change project files, APIs and the CLI.

## Unreleased

### Added

- **Raw TCP and TLS streams are recorded and can be replayed.** Protocols that are not HTTP (databases, mail, SSH,
  a custom protocol), arriving through a CONNECT tunnel, SOCKS5 or a transparent listener, are still relayed byte for
  byte, and now each connection is also stored as a **stream**: target, client, start and end, bytes each way, TLS or
  plain, how it ended, and its chunks in order with direction and time (up to 16 MB per stream; after that the bytes are
  relayed and counted only, and the stream is marked cut). A protocol inside TLS that is not HTTP is no longer an error:
  after interception the decrypted bytes are recorded as a TLS stream, and ALPN values other than `h2` and `http/1.1`
  are passed to the target. The same recording settings as for HTTP apply (only in-scope, only chosen devices); TLS
  pass-through tunnels stay unrecorded. New **Streams** page (Proxy, next to WebSockets history) with a text and a hex
  view, search inside a stream and live updates; **Replay stream** sends the client's chunks (edited if you like) to
  the same target on a new connection and records what comes back. Replay is a send like any other: the target must be
  in scope, agents need approval for sending bytes, and it is audited. API: `GET /streams`, `/streams/{id}`,
  `/streams/{id}/chunks`, `POST /streams/{id}/replay`; MCP tools `stream_list`, `stream_get` and `stream_replay`; a
  `streams` event topic. Needs a project migration (new tables; older ProxyMind versions cannot open the project after).
- **SOCKS5, transparent mode and per-host upstream proxies.** A listener can now be a **SOCKS5 server** (Setup,
  "3. Proxy listeners": type SOCKS5, optionally with a username and password). curl `--socks5-hostname`, browsers and
  Android SOCKS apps can use it; their web traffic, including HTTPS and HTTP/2, is recorded and changed by your rules,
  hooks and the intercept queue just like proxy traffic, and other protocols (SSH, databases) pass through untouched and
  unrecorded. Only CONNECT is served: BIND and UDP are refused. On Linux an HTTP listener can be **transparent**: with
  an iptables or nftables redirect, a device or program with no proxy settings is sent through ProxyMind to wherever it
  was going (HTTPS by its server name, HTTP by its Host header); the option is greyed out on macOS and Windows, which
  are not supported yet. The single upstream proxy became an ordered list of **upstream rules** (Settings, Network):
  per host name, wildcard or CIDR range, go direct or through an HTTP or SOCKS5 proxy, each with its own login; the
  first match wins and the page can tell you which rule a host would use. Older projects load unchanged. As before,
  ProxyMind connects to the address it checked against the denied networks unless a rule lets the proxy resolve names.
  New guide: [docs/capture.md](docs/capture.md) with the iptables and nftables commands, SOCKS5 client examples and
  upstream chains.
- **Plugins can change traffic in flight (plugin API 2).** A plugin that says `api: 2` in its manifest lists the
  permissions it needs (`hooks.request`, `hooks.response`, `checks.passive`, `checks.active`, `panels`,
  `history.read`) and may only use those. A new plugin, or an update that asks for different permissions, stays off
  until you accept them on the Plugins page (or with `proxymind plugin accept`). A *request hook* or *response hook* is
  a small program ProxyMind keeps running in the plugin sandbox; it sees each matching in-scope message (by host,
  path, method and content type) after your match-and-replace rules and before the intercept queue, and may replace it,
  or drop a request. What it returns is sent exactly as given. A hook that is slow, crashes or answers nonsense is
  skipped and the original goes through (or is blocked, if the plugin asks for that); five failures in a minute pause
  it until you resume it. The Plugins page turns hooks on and off, reorders them, pauses and resumes them and shows
  recent failures, live. History keeps the browser's version beside what was sent, and the Changes tab names the
  hook. Streamed (server-sent events), WebSocket and over-8 MB messages are not given to hooks. Includes the
  `sign-request` example (adds an HMAC `X-Signature` header), Python and TypeScript helpers, and
  [docs/plugins.md](docs/plugins.md). Existing plugins keep working unchanged.
- **Set up a phone or tablet from a QR code.** The Proxy setup page has a new *Phone or tablet* section with the
  address to open on the phone (built from this computer's network address and the proxy's port), a QR code for it, and
  the proxy address to enter in the phone's Wi-Fi settings. The proxy itself serves that page, so it works before the
  phone has any proxy setting: it offers the CA certificate as `.crt` and `.pem` downloads with its fingerprint and
  short Android and iOS steps. Once the phone's proxy is set, `http://proxymind.setup/` shows the same page. These
  requests are never forwarded or recorded. If the proxy only listens on this computer, the section says so and how to
  add a listener on all interfaces. New guide: [docs/mobile.md](docs/mobile.md) (Android 14 and later, iOS, which apps
  trust a user certificate).
- **See and filter traffic per device.** History records which device (client address) each request came from, shows
  it in a new *Client* column, and can filter by it, also in the query language (`client:192.168.1.23`,
  `client:"Pixel 8"`). You can give an address a name on the Proxy setup page. *Record only* a chosen device or devices
  to keep just their traffic in history (other devices are still proxied). Also in the API (`/setup/mobile`, `/devices`,
  `client` on `/exchanges`, `record_devices` on `/history/recording`). Existing projects are upgraded on opening;
  older rows simply have no client.
- **Inline transforms in the Replay and Intercept editors.** Select text and URL-, Base64-, HTML-entity-, hex-,
  Unicode-escape- or JSON-string-encode or decode it, or hash it (MD5, SHA-1, SHA-256), with a before-and-after
  preview, chaining, an Undo list and Ctrl+Z (Ctrl+Shift+T or Alt+Shift+T opens the menu). Runs in the browser.
- **gRPC and Protobuf traffic is readable and editable.** Requests and responses with a gRPC, gRPC-Web (also the
  base64 text form) or Protobuf content type get a **Protobuf** view in HTTP history, Replay and the Fuzzer: one field
  per line, nested messages indented, strings and numbers shown the way they most likely were meant (a number can
  also be read as signed, zigzag, float or double in a comment). A gRPC call with several messages shows each one, and
  gRPC-Web trailers or a `grpc-status` header show the call's status. No `.proto` file is needed; field names are
  not part of the wire format, so fields show as numbers.
- **Edit and replay a gRPC call.** Opening a gRPC request in Replay shows the head as text and the message as
  editable Protobuf text. Sent unedited, the original bytes go out untouched; edited, the text is turned back into
  Protobuf, framed again, and Content-Length is fixed (HTTP/2 requests get none added). Messages that were compressed
  are sent uncompressed after an edit. Race and Send group carry the message too.
- **A Protobuf tool in the API and for agents:** `POST /api/v1/tools/protobuf/decode` and `/encode`, an MCP tool
  `protobuf_decode` (agents get the text as untrusted content, with secrets replaced), `request_protobuf` and
  `response_protobuf` on `GET /api/v1/exchanges/{id}`, and `body_b64` on `replay_send`, `race_send` and `replay_group`
  for bodies that are not text.
- The demo shop has a small gRPC call (`/grpc/demo.Greeter/SayHello`) to try this on, and the decoder has a fuzz
  target that runs nightly.
- **History keeps both sides when a rule or an edit changed the traffic.** The record itself still shows what the
  server saw and sent: the request as sent to the server and the response as the server sent it. When a
  match-and-replace rule or an edit in the intercept queue changes a request, History also keeps the request as the
  browser sent it; when it changes a response, it keeps the copy the browser received. It lists what changed them (the
  rule's comment or a short description, or "intercept editor"). Edited rows show an *edited* mark in a new column;
  the exchange has **Original request** and **Delivered response** views and a **Changes** view with a line-by-line
  diff for each changed message. Find them with `is:modified` in the query bar. A rule that matches but leaves the
  bytes as they were records nothing. What goes over the wire is unchanged; only the record is richer. Scans, passive
  checks, proofs, reports and evidence keep reading the server's response, so a rule that removes a security header
  for the browser does not make a check report it missing. Also in the API (`request_original`, `response_delivered`,
  `changes` and `diffs` on `GET /api/v1/exchanges/{id}`, `modified` on history rows) and for agents, whose view of an
  exchange shows them with secrets replaced and marked as untrusted content. Existing projects are upgraded on
  opening; older rows simply have none of these. Evidence packs and reports still embed the server's response and the
  request as sent.

## 0.2.0 (2026-11-15)

First release since 0.1.0. Everything below ships in it; the version number did not change while it was prepared.

### Changed

- **Cloud models are allowed by default.** Most people use a cloud model (Anthropic, OpenAI) with the Assistant and the
  AI scan, so the rules of engagement now allow them unless they say `data.allow_cloud_models: false`. Secrets are still
  replaced before any model sees traffic (`redact_before_llm`, on by default). Engagements whose data must stay on the
  machine set `allow_cloud_models: false` and only local model servers (Ollama, LM Studio, vLLM) are used, as before.

### API contracts

- **An OpenAPI document for the REST API,** generated from the Rust types (`docs/api/openapi.json`, `cargo xtask contracts`).
- **Typed clients.** The same command generates TypeScript types (`ui/src/api-types.gen.ts`, `sdk/typescript/src/types.gen.ts`)
  and Python `TypedDict`s (`sdk/python/proxymind/types.py`) from the API description. The TypeScript SDK exports them and
  its methods return them; the Python SDK's methods are annotated with them. Types only: no runtime change.
- **Every MCP tool's input schema now comes from the Rust types** the server reads the arguments into, so what an agent
  is told and what the server accepts cannot differ. The schemas of 65 tools were written by hand before. As a result
  an argument a tool does not list is now refused with an error naming it (14 tools already did this); `history_grep`
  lists all the history filters it always accepted, and `scan_active` lists two checks it already ran.
- **The OpenAPI document now covers every route of the REST API** (175 operations): each one lists its query
  parameters or request body and what it answers with. 125 answer with a full schema; the rest say in words which keys
  they return, or are downloads and the event stream. A test fails if a route is added or removed without the document
  following. Nothing the API accepts or returns has changed.
- **Agents see 8 more fields, by name.** `history_search` now lists `status_class`, `hide_ext`, `annotated`, `identity`,
  `hypothesis_id` and `text`, and `scan_task_start` lists `browser` and `record_findings`. They already worked, but the
  tool descriptions did not mention them, so agents never used them. The input schemas of these 14 MCP tools
  (`history_search`, `scan_task_start`, `engage_*`, `ws_send`, `replay_send`, `authz_check`, `model_get`, `proof_run`,
  `finding_create`, `finding_update`) are now generated from the same Rust types as the API, so they cannot drift
  apart again, and they carry the real limits (for example `max_requests` 1 to 2000).

### Live events

- **Typed events on the event stream.** `GET /api/v1/events?topics=exchanges,findings` streams `event: <topic>`,
  `id: <seq>`, `data: <json>` for the topics `exchanges`, `findings`, `scans`, `proofs`, `intercept`, `approvals`,
  `audit`, `collaborator`, `websockets`, `fuzzer` and `ai_scan` (`topics=all` for every topic you may read; list `counters` to get the old event too).
  Events carry ids and short summaries only, are sent after the change has been saved, and an agent only receives
  those for hosts in scope, with secrets in host names replaced. A client that falls behind gets one `resync` event
  and should refetch what it shows; an unknown topic is a 400. Without `topics` the stream is unchanged (a
  `counters` event), but it now follows the new events instead of querying the project every 700 ms, and `/status`
  counts rows instead of loading them.
- **The UI updates from server events.** Intercept, Collaborator and WebSocket views no longer poll: a held
  request, a callback or a new WebSocket message shows as soon as the server reports it.
- **Scans, the Fuzzer and AI scans update from events too.** New `scan_state_changed` (every state change of a
  crawl-and-audit task), `fuzzer_progress` and `ai_scan_changed` events (ids and state words only, at most one per
  250 ms per run, the final state always sent) replace the last progress timers: no page polls any more. Agents
  only receive scan and fuzzer events for runs they started.

### Performance

- **Content search uses a full-text index.** History text search checks only the exchanges a trigram index
  names as candidates, then verifies them as before, so results are unchanged: over 100,000 exchanges a search
  that scanned 5,000 bodies (0.9 s) takes about 1 ms. New traffic is indexed in the background in batches, so
  recording keeps its speed; exchanges not indexed yet are always checked. Existing projects are indexed in the
  background after upgrading. Regex and inverted searches still scan.
- **History queries with content terms use the full-text index.** `req:`, `resp:` and `any:` terms (alone, with
  other terms, or in an `OR` of content terms) load only the exchanges the index names, then evaluate them as
  before, so results and paging are unchanged: `resp:"user996@shop.test"` over 30,000 exchanges takes 17 ms
  instead of 1.5 s (which was the query time limit). Regex, negated and short (under 3 characters) terms still scan.
- **Creating findings no longer slows down as findings grow.** Each new finding listed every finding to look for a
  duplicate (25 per second at 10,000 findings); it now looks up findings at the same URL through an index (about
  2,000 per second). Duplicates older than the newest 1,000 findings, which were missed, now merge too.
- **One write connection per process, and reads that don't wait for it.** The proxy's recorder writes through the
  service's connection in batches of up to 256 exchanges (it used one transaction each, on a second connection that
  competed for the write lock); reads use a pool of read-only connections; the full-text indexer writes in short
  batches between them and WAL checkpoints run on their own connection, off the recording path. Recording while
  searching: about 1,800 -> about 5,000 exchanges a second (debug build); the proxy waits at most a few milliseconds
  to hand an exchange to the recorder. A recorder whose writer thread stopped now says so instead of losing traffic
  silently.
- A repeatable large-project benchmark (`crates/pm-service/tests/scale.rs`, sized by `PM_SCALE_EXCHANGES` and
  `PM_SCALE_FINDINGS`) prints one machine-readable `SCALE` line.

### Proof

- **Automatic proving.** A new step turns the scanner's *suspected* findings into *proven* ones: it picks the oracle
  that fits each finding's class, rebuilds the request from its evidence and runs it through the policy gate. SQL
  injection is proven by a boolean true/false split (or the timing oracle), command injection by timing, SSRF by an
  out-of-band callback, reflected XSS in the headless browser, path traversal by reading known files while a bogus
  name reads nothing, and open redirect and CRLF by a fresh random marker reaching the redirect target or a response
  header. IDOR and BFLA reuse the differential oracle. It runs at the end of `proxymind bench auto` (skip with
  `--no-prove`), as `proxymind findings prove [id]`, over the API (`POST /api/v1/findings/{id}/prove`,
  `POST /api/v1/findings/prove`), as the MCP tool `finding_prove`, and from an **Auto-prove** button on the Findings
  page. Also exposed as new `proof_run` oracles `sql_error`, `boolean_injection`, `path_traversal` and `marker`.
  SDKs gain `finding_prove` / `findings_prove_all` (Python) and `findingProve` / `findingsProveAll` (TypeScript).
- **Five more classes proven automatically,** each with a control that rules out a look-alike:
  - **Template injection** by a new `expression` oracle: arithmetic on two fresh pairs of random numbers comes back
    as the products, while the same numbers without template syntax do not (so a page that computes from any input
    is not mistaken for a template engine).
  - **NoSQL operator injection** by a true/false split: `$eq` of the original value answers like the original,
    `$ne` of it does not (also `$in`/`$nin`).
  - **XXE** by an external entity that reads a known file into an element's text while a bogus file reads nothing,
    or by an out-of-band callback from a parameter entity (blind XXE).
  - **CORS** by a new `cors` marker kind: an `Origin` carrying a fresh random host is echoed in
    `Access-Control-Allow-Origin` with credentials allowed. Reflection without credentials is not counted.
  - **Host-header injection** by the `host` marker sent in `X-Forwarded-Host`, `X-Host` or a forged `Host` (the
    request still goes to the target's address).
  - **Stored XSS** in the headless browser: the payload is stored by the submission and must run on the page that
    shows it (the reflection oracle's new `view_raw`).
  - **DOM XSS** in the headless browser: the XSS proof now renders the page with its own same-origin scripts, so a
    value a script writes into the page counts.
  - **SQL injection in a header the recorded request lacks** (e.g. `User-Agent`): the header is added to the
    baseline too, so only the payload differs.
  - **IDOR in a GraphQL query sent by POST:** the differential oracle re-sends a POST only when it is a GraphQL
    query (no mutation or subscription), and counts a 2xx answer with only errors as refused.

  The `host` marker kind is stricter: the marker must come back in an absolute URL (`//marker`) or a redirect, not
  just anywhere in the page, so a debug page that prints request headers is no longer a proof. Template-injection
  and CORS proofs export as regression tests too.
- **Regression tests for the new proofs.** Findings proven by error-based or boolean SQL injection, path traversal
  or a marker (open redirect, header injection) now export as CI regression tests too: the test re-sends the
  proof's requests and judges the answers the way the proof did. They use a second test format
  (`proxymind-regression-2`) so an older runner refuses them instead of misjudging them.

### Fixed

- **Pretty and Render showed the wrong body** in Replay, HTTP history and the Fuzzer. They read the text prepared for
  models, which keeps only the visible text of an HTML page (no tags) and is cut to a token budget, so Render drew
  plain text instead of the page, Pretty showed HTML without its markup, and a large JSON body was cut in the middle and
  could not be indented. They now use the decoded body itself (de-chunked and decompressed, all of it, markup kept):
  `GET /api/v1/exchanges/{id}` returns it as `request_body` and `response_body`.
- **The UI went blank after leaving the Assistant page, or when a chat reply arrived,** in current Chrome and
  Chromium. An effect returned `scrollIntoView()`'s value, which these browsers now make a Promise, and React called
  it as the effect's cleanup. A page error now also stays inside the page area (with "Try again") instead of
  blanking the whole UI.
- **Denied networks could be bypassed through an upstream HTTP proxy for HTTPS.** Tunnels went by host name, so the
  proxy resolved the name again and could reach an address ProxyMind never checked (DNS rebinding). Checked
  tunnels now `CONNECT` to the checked address; TLS still uses the name. Proxies that only allow named hosts can
  turn on "let the proxy resolve names" (`remote_dns`), now offered for HTTP proxies too. Plain HTTP through an
  HTTP proxy still goes by name (the proxy takes the Host from the target).
- **Network settings:** the "Connect directly to" list dropped new lines while typing, so a second host couldn't be
  entered; it now keeps them and drops empty lines when you leave the field or save.
- **Narrow windows:** tab strips (Engagement tools, Fuzzer, HTTP history) wrapped past their panel and the last tabs
  could not be clicked; they now wrap onto a second row. The header keeps the current sub-tab in view, and the
  scanner issue tables no longer let one long URL or payload squeeze the other columns.
- **Live progress** for crawl-and-audit tasks, Fuzzer attacks and AI scans no longer stops for good after one failed
  poll (a dropped connection or a server hiccup); it retries with backoff. Sessions and Network show "Loading…"
  instead of an empty page while they load.
- **End-to-end test:** finds the newest preinstalled Chromium instead of one fixed build.
- **Regression tests said "fixed" when they could not tell.** With credentials the app no longer accepted (an
  expired token: 401, or a redirect to the login page), `proxymind regress run` printed "fixed" and exited 0, so a
  CI job with a stale secret went green while the bug was still there. That is now an error (exit 1), and so is a
  server that fails (5xx). Tests carry the identity's health check and send it before calling anything fixed, for
  apps that answer an expired session with 403 or an ordinary page. Unknown test kinds are refused, not guessed at.
- **A regression run with a missing secret passed.** A test whose `PM_AUTH_*` variable was not set was skipped and
  the run exited 0, so a CI job that lost a secret looked like "all fixed". Skipped tests now make the run exit 2
  with a message naming the cause; `proxymind regress run --allow-skipped` keeps the old behaviour for local runs.
- **Exported regression tests could hold a session cookie.** A proof made from a recorded request (as automatic
  proving makes them) names no identity, so the request went into the test file with the session it was recorded
  with. Credentials are now always replaced by an `{{auth:NAME}}` placeholder: the owning identity's, or
  `{{auth:session}}`. If you exported tests from automatically proven findings before this, re-export them and
  treat the sessions in the old files as exposed.
- **Three MCP tools were never offered to agents.** `custom_checks`, `custom_scan` and `dom_test` had handlers and
  documentation but no entry in `tools/list`, which is all a client shows a model. They are listed now (79 tools),
  and a test keeps the list and the handlers in step.
- Proofs for error-based SQL injection, path traversal and Host-header reflection read the response body after
  de-chunking and decompressing it (a compressed response could hide the marker and miss a proof).
- Discovery's guessed-parameter probe sent the path without its query.
- Absolute-form targets with an empty path are split correctly.
- The out-of-band deadline uses one clock, so a callback at the deadline counts.


### AI testing

- **AI scan**: an autonomous agent goes from recon to chained findings under the rules of engagement, with an
  attack graph, live steering (pause, redirect, add notes), an independent verifier for each finding and
  business-logic tests.
- **Cost meter** with a budget, a **prompt-injection guard** for target content shown to the model, **explain and
  fix** for findings, presets for local models, **memory** across engagements, learning from your verdicts, traffic
  **triage** and **parallel workers**.
- Model **API keys can be set in the UI** (stored in the project vault) for both the AI scan and the assistant.
- **Skills (playbooks)** for agents over MCP.

### Proof and reporting

- **Signed evidence packs** (`proxymind evidence`) with a coverage proof, checked offline by `proxymind verify`.
- **Proven findings as CI regression tests**: `proxymind regress export|run`.
- **Authorization matrix**: every readable operation as every identity and anonymously, as one grid; IDOR, missing
  function-level checks and missing authentication flagged and proven with the differential oracle.
- **What changed since the last test**: model snapshots and a diff that names new, changed and removed endpoints
  and the earlier findings to retest (`proxymind changes`).

### Recon and scanning

- Passive recon: **DNS records** and **Wayback** history.
- **JavaScript endpoint mining**; parameters a page reads but nothing sends are found and scanned.
- Discovery tries common names of pages that take a URL or a file, also inside API folders, and sends them once
  with a likely parameter; the sweep now scans parameterised pages that fail on their value (a `?file=` that is not
  found, a `?url=` that does not resolve). VulnShop: 33/38 → 35/38 (SSRF and path traversal), no new false
  positives.
- Out-of-band callbacks that arrive late are still counted.
- Opt-in update check.

## 0.1.0 (2026-11-07)

First public release: intercepting proxy, history, replay, fuzzer, scanner, crawler, discovery, identities and
authorization checks, the proof engine, MCP server, web UI, desktop app, Python and TypeScript SDKs.
