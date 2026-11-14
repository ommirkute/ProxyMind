# Changelog

All notable changes to ProxyMind. Versions follow [semantic versioning](https://semver.org/); before 1.0, a minor
version may change project files, APIs and the CLI.

## Unreleased

### Live events

- **Typed events on the event stream.** `GET /api/v1/events?topics=exchanges,findings` streams `event: <topic>`,
  `id: <seq>`, `data: <json>` for the topics `exchanges`, `findings`, `scans`, `proofs`, `intercept`, `approvals`,
  `audit` and `collaborator` (`topics=all` for every topic you may read; list `counters` to get the old event too).
  Events carry ids and short summaries only, are sent after the change has been saved, and an agent only receives
  those for hosts in scope, with secrets in host names replaced. A client that falls behind gets one `resync` event
  and should refetch what it shows; an unknown topic is a 400. Without `topics` the stream is unchanged (a
  `counters` event), but it now follows the new events instead of querying the project every 700 ms, and `/status`
  counts rows instead of loading them.

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

## 0.2.0 (2026-11-12)

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

### Fixes

- Discovery's guessed-parameter probe sent the path without its query.
- Absolute-form targets with an empty path are split correctly.
- The out-of-band deadline uses one clock, so a callback at the deadline counts.

## 0.1.0 (2026-11-07)

First public release: intercepting proxy, history, replay, fuzzer, scanner, crawler, discovery, identities and
authorization checks, the proof engine, MCP server, web UI, desktop app, Python and TypeScript SDKs.
