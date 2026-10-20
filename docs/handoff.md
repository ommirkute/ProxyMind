# ProxyMind: handoff for a new working session

Read this first, then `CLAUDE.md` (rules), `docs/plan.md` (roadmap) and `docs/adr/` (decisions). Everything below reflects `main` plus the XSS-proof work (reflection oracle).

## 1. What ProxyMind is

An open-source, AI-native intercepting proxy for authorized web security testing: a Burp-style tool where humans and AI agents (over MCP or the built-in assistant) work on the same project, under a policy gate that enforces the rules of engagement. Its differences: any model including local ones, **no proof, no finding** (the tool verifies findings itself), a live app model with multi-identity authorization testing, a hypothesis ledger and coverage map, and open benchmarks.

- Repo: `ommirkute/ProxyMind`, default branch `main`. Licence AGPL-3.0 core (ADR-0007).
- Rust workspace (edition 2024, MSRV 1.88, `unsafe` forbidden, line width 120) plus a React + TypeScript web UI in `ui/`, built into the binary.
- One binary: `proxymind` (crate `pm-cli`).

## 2. Architecture

```
            browser / device                AI agent (Claude Code, …)       web UI (React)
                   │                                 │ MCP (stdio)               │ REST + SSE
                   ▼                                 ▼                           ▼
  ┌──────────── pm-proxy ───────────┐          pm-mcp ──┐      pm-assistant ─┐   pm-api
  │ CONNECT / TLS MITM (pm-tls)     │                   │   (agent:assistant)│     │
  │ HTTP/1.1 (pm-http, byte-exact)  │                   ▼                    ▼     ▼
  │ HTTP/2 (h2) · WebSockets        │            ┌──────────── pm-service ────────────┐
  │ intercept queue · match/replace │◄──hooks────│ the ONLY entry point for actions   │
  │ transparent mode · loop guard   │            │ every send → pm-policy gate        │
  └──────────────┬──────────────────┘            │ (scope, tiers, approvals, rate     │
                 │ Recorder (single writer)      │  limits, DNS check, audit chain)   │
                 ▼                               └──┬───────────┬──────────┬──────────┘
            pm-store (SQLite project file, blobs)    │           │          │
                                                 pm-replay   pm-identity  pm-model / pm-ledger
                                                 (send engine, pm-diff     pm-proof / pm-oast / pm-browser
                                                  HTTP/2, race, pm-ai (views, redaction,
                                                  upstream proxy) untrusted tagging)
```

Rules that shape everything (ADR-0005, CLAUDE.md):
- **One service layer.** API, MCP, CLI, UI and the assistant all call `pm-service`; every action that touches a target goes through `pm-policy`. Lower crates never import higher ones.
- **Byte-exact traffic** (ADR-0002). `pm-http` is sans-I/O and never rewrites bytes; the only automatic change is absolute-form → origin-form targets. Any other change happens only because the user asked (rules, intercept edits, WebSocket intercept stripping compression).
- **Target content is untrusted**, including when shown to a model (wrapped in `<untrusted_target_content>`, prompt-injection signals flagged).
- **Migrations in `pm-store` are append-only.**

### Crates (`crates/`)

| Crate | What it does | Key files |
|---|---|---|
| `pm-core` | Shared helpers (time, URL/authority, base64) | `lib.rs` |
| `pm-http` | Sans-I/O HTTP/1.x parser; HTTP/2 text form; WebSocket frames | `lib.rs`, `h2text.rs`, `ws.rs` |
| `pm-tls` | CA, per-host leaf certs, upstream TLS, client certs | `lib.rs` |
| `pm-store` | SQLite schema + compressed, deduplicated blobs | `lib.rs` (`MIGRATIONS`) |
| `pm-replay` | Send engine: connect (direct / upstream HTTP / SOCKS5), TLS, HTTP/2, parallel + race sends | `lib.rs`, `net.rs`, `h2send.rs`, `race.rs` |
| `pm-proxy` | Listener, CONNECT, MITM, HTTP/2 server side, intercept queue, rewrite rules, WebSocket relay, transparent mode | `lib.rs`, `h2_server.rs`, `intercept.rs`, `rewrite.rs`, `ws_relay.rs` |
| `pm-policy` | ROE file, scope matching (bypass-resistant), tiers (method + payload-aware), rate limits, approvals, hash-chained audit | `lib.rs`, `roe.rs`, `audit.rs`, `payload.rs` |
| `pm-ai` | Token-budgeted exchange views, secret redaction with placeholders, untrusted tagging | `lib.rs`, `body.rs` |
| `pm-identity` | Test identities, login recipes, health checks, auth swap | `lib.rs` |
| `pm-diff` | Semantic diff with learned noise | `lib.rs` |
| `pm-model` | App model: path templating, objects, ownership | `lib.rs` |
| `pm-ledger` | Hypotheses + coverage map | `lib.rs` |
| `pm-openapi` | OpenAPI 3 / Swagger 2 parsing (pure): operations, example requests, `$ref` resolution | `lib.rs` |
| `pm-graphql` | GraphQL introspection → operations, example documents and requests (pure) | `lib.rs` |
| `pm-tools` | Decoder codecs, line diff, sequencer statistics, token extraction, HAR and cURL, content search, site map (pure) | `codec.rs`, `linediff.rs`, `sequencer.rs`, `har.rs`, `curl.rs`, `search.rs`, `sitemap.rs` |
| `pm-scan` | Passive checks (pure) over one exchange, and active checks: insertion points, probes, analysis | `lib.rs`, `active.rs` |
| `pm-plugin` | Plugin manifests, the per-user registry, the passive JSON-lines protocol and runner | `lib.rs` |
| `pm-vault` | Passphrase sealing of project files (Argon2id, chunked ChaCha20-Poly1305) | `lib.rs` |
| `pm-crawl` | Crawler logic (pure): HTML links/forms, robots.txt, sitemaps, risky-link filter, frontier | `lib.rs` |
| `pm-fuzz` | Intruder logic (pure): § positions, attack modes, payload sets, anomaly detection | `lib.rs` |
| `pm-proof` | Oracles: differential authz, timing (Mann-Whitney), OAST, reflection (XSS verdict, payload templates) | `lib.rs` |
| `pm-browser` | Headless Chromium over CDP (own WebSocket codec): renders a recorded response offline, blocks every other request, reports binding calls and dialogs | `lib.rs` |
| `pm-oast` | HTTP callback listener, authoritative DNS responder (sans-I/O parser), token helpers | `lib.rs`, `dns.rs` |
| `pm-service` | The service layer (history, replay, ws replay, race, intercept, rules, network, identities, authz, model, ledger, proofs, findings, approvals, assistant storage) | one module per area in `src/` |
| `pm-mcp` | MCP server over stdio; 39 tools | `lib.rs` (instructions), `tools.rs` |
| `pm-assistant` | Built-in assistant: Anthropic + OpenAI-compatible wire formats, tool loop through `pm_mcp::call_tool` as `agent:assistant` | `lib.rs`, `llm.rs` |
| `pm-api` | axum REST API + SSE event stream, token auth, serves `ui/dist` | `lib.rs`, `routes.rs` |
| `pm-cli` | `proxymind` binary | `main.rs`, `bench.rs` |
| `pm-demo` | VulnShop: deliberately vulnerable demo target with ground truth VS-1…VS-13 | `lib.rs` |

### Request paths

- **Browser traffic:** `pm-proxy` reads a request → match/replace rules → intercept queue (humans only) → `Sender` (`pm-replay`) → response → rules/intercept for the response → back to the client; the `Recorder` (single writer thread) stores the exchange. WebSocket upgrades are relayed byte for byte with a decoded copy logged, or message-by-message when WebSocket interception was on at upgrade time.
- **Agent / API / assistant action:** `pm-service` builds an `Outgoing` → `gate_send_with()` asks `pm-policy` (scope + tier + window + approval) → rate-limit slot → secrets un-redacted, identity applied → `Sender` with a DNS check (`policy.check_resolved`) → exchange recorded with the actor's id → a redacted, token-budgeted view goes back.
- **Approvals:** a gated action returns `pending_approval` with an id; a human approves (UI/CLI); the agent repeats the call with identical arguments plus `approval_id`. The approval is bound to a hash of the parameters and is single-use.

### Interfaces

- **CLI:** `proxy`, `ui`, `mcp`, `history`, `show`, `roe`, `rules`, `network`, `assistant`, `audit`, `oast-server`, `model`, `coverage`, `hypotheses`, `findings`, `plugin` (`add`, `list`, `remove`), `project` (`lock`, `unlock`), `bench` (`score --app`, `auto`), `scan`, `scan-active`, `openapi`, `decode`, `compare`, `sequencer`, `crawl`, `intruder`, `proof` (`authz`, `timing`, `xss`, `browser`, `show`, `rerun`), `bench`, `report`, `approvals`, `identity`, `authz`, `demo-target`.
- **MCP tools (39):** `roe_get history_search history_grep site_map graphql_import discover_content exchange_get exchange_raw_request ws_messages ws_send scan_active scan_issues openapi_import import_har curl_parse decode compare_exchanges sequencer_run crawl intruder_run race_send replay_send identity_list identity_capture identity_check authz_check authz_results authz_candidates model_get hypothesis_create hypothesis_update hypothesis_list coverage proof_run proof_get finding_create finding_update finding_list approval_status`. Documented in `docs/agents.md` and RFC 0001.
- **REST API** (`/api/v1`, token auth): status, events (SSE), exchanges (+ `/ws`), replay, `ws/replay`, race, intruder, crawl, `scan/issues`, `scan/active`, `openapi` (+ `/import`), `tools/decode|compare|sequencer`, approvals, identities, authz, model, coverage, hypotheses, findings, proofs (+ rerun), audit (+ verify), report, intercept (settings, forward, drop, forward-all), match-replace, network, assistant (config, chats, send).
- **Web UI pages** (`ui/src/pages`): History (viewer, WebSocket tab with replay, HAR import/export, Copy as cURL), Site map & Search, Assistant, Intercept, Match & replace, Repeater (with Race bar and Paste cURL), Intruder, Tools (Decoder, Comparer, Sequencer), Approvals, Identities & Authz, Model & Coverage (with Crawl, content discovery, OpenAPI and GraphQL import), Issues, Findings, Audit log, Engagement (view and edit the ROE), Network, Proxy setup (CA download and steps).

### Storage (`pm-store` tables)

`blobs, exchanges, audit_log, approvals, settings, identities, authz_results, hypotheses, proofs, findings, oast_interactions, ws_messages, assistant_chats`. The `settings` table holds the ROE, match-and-replace rules, network config, assistant config, and the OAST public URL (intercept settings live in memory only). Add tables only by appending a new migration.

## 3. What's done

All of this has automated tests and passes CI on Linux, macOS and Windows plus a Chromium end-to-end test.

- **Proxy:** HTTP/1.1 (byte-exact), HTTP/2 to browsers and servers with downgrade (ADR-0009: HTTP/2 shown as text with `HTTP/2` in the request line), CONNECT + TLS interception, transparent mode (Host routing, TLS without CONNECT via SNI, loop guard), upstream HTTP/SOCKS5 proxy and per-host client certificates.
- **Manual tools:** intercept queue (requests, responses, WebSocket messages), match-and-replace rules, Repeater (send as any identity), race testing (HTTP/2 single-packet attack, last-byte fallback), WebSocket logging/replay/intercept.
- **Safety:** ROE with bypass-resistant scope, tiers per actor kind, rate limits, DNS-rebinding check, single-use parameter-bound approvals, blake3 hash-chained audit log.
- **Engine:** identities with re-login, semantic diff, authorization checks and matrix, app model with suggested tests, hypothesis ledger and coverage, proof engine (differential authz, timing, HTTP OAST, reflected XSS in an offline headless browser; ADR-0011) with re-runnable proofs, findings and reports (Markdown, HTML, JSON, SARIF).
- **AI:** MCP server, token-budgeted views, redaction, untrusted tagging; built-in assistant (local by default; cloud only with `data.allow_cloud_models`; keys from env vars; every model call audited; ADR-0010).
- **Demo/bench:** VulnShop (VS-1 IDOR, VS-2 BFLA, VS-3 time-based SQLi, VS-4 SSRF, VS-5 race, VS-6 reflected XSS, VS-7 error-based SQLi, VS-8 open redirect, VS-9 path traversal, VS-10 SSTI, VS-11 sequential reset codes, VS-12 GraphQL IDOR, VS-13 exposed .git/config; `/app/*` is a soft-404 trap; `/help`, `/out` and `/docs` are traps), ground truth in `bench/ground-truth/vulnshop.yaml`, `proxymind bench score`, `bench/demo.sh`, an end-to-end test where an agent finds and proves bugs over MCP.

## 4. What's next, and how to do each

Order from `docs/plan.md`. B and C need things the cloud sandbox doesn't have (noted below); the rest of A is fully doable in the sandbox and is the recommended next phase.

### A. More oracles and payload awareness (recommended next)

1. ✅ **Done: XSS proofs in a headless browser (`reflection` oracle).** How it was built, for reference and for follow-ups (stored XSS: render a *different* exchange than the one sent; DOM XSS: serve same-origin subresources from history instead of blocking them):
   - Flow: `proof_run` with `oracle: "reflection"` → gate as active-intrusive → send the request with a payload carrying a unique token, e.g. `<img src=x onerror=pmProof('TOKEN')>` → render **the recorded response** in headless Chromium, not a live re-fetch.
   - Rendering: launch Chromium headless with `--remote-debugging-port=0`, read `DevToolsActivePort`, speak CDP over WebSocket (the frame encoder/decoder already exist in `pm_http::ws`; or use a CDP crate after a `cargo deny` check). Use `Fetch.enable` to fulfil the main document with the recorded response body and **block every other request** (no side effects, no traffic outside scope). `Runtime.addBinding("pmProof")`; a `Runtime.bindingCalled` event with the token proves execution. Also catch `Page.javascriptDialogOpening` for `alert` payloads.
   - Where: verdict logic in `pm-proof` (pure); browser driving in a new crate (e.g. `pm-browser`) so lower crates stay I/O-free; dispatch in `pm-service/src/proof.rs` next to `prove_oast`. Find the browser via a setting or `PROXYMIND_CHROMIUM`; in the sandbox it's under `/opt/pw-browsers`.
   - Test: add a reflected-XSS endpoint to VulnShop (VS-6 + ground truth + `class_family` mapping in `pm-cli/src/bench.rs`), plus an HTML-encoded look-alike as a false-positive trap.
2. ✅ **Done: DNS OAST.** (`pm_oast::dns`, `{{oast_dns}}`, `oast-server --dns --domain [--dns-answer]`; domain stored as the `oast_dns_domain` setting.)
   - Add a minimal authoritative DNS responder to `pm-oast` (UDP; parse the query name; if it's `<token>.<oast-domain>`, record an interaction with `protocol: "dns"` and answer an A record pointing at the OAST HTTP host).
   - Keep the parser sans-I/O and fuzzable; add golden tests with hand-built packets.
   - CLI: `oast-server --dns 0.0.0.0:53 --domain oast.example.com`. Payloads get `{{oast_dns}}`; `prove_oast` accepts either protocol. Needs an NS delegation in real use; tests use a local UDP client.
3. ✅ **Done: payload-aware tiers** (`pm_policy::payload`, `Tier::for_http_request`, applied in `gate_send_with`, `gate_proof` and WebSocket sends). Classify what a request does, not just its method: destructive SQL (`DROP`, `DELETE FROM`, `TRUNCATE`), OS-command and file-write patterns, and bulk actions raise the tier. Put the classifier in `pm-policy` (pure, well tested), call it in `gate_send_with` and take the max of method tier and payload tier. Add scope-bypass-style adversarial tests.

### B. Benchmarks on real apps (M6)
✅ **Foundation done:** `bench/run.sh <app>`, profiles in `bench/apps/`, ground truth for vampi/juice-shop (verified) and crapi (unverified), `bench score --app`, `bench auto`, nightly `bench` job. Docker works in the sandbox (start `dockerd` by hand) but disk is tight (crAPI didn't fit). Next: a crAPI profile and run, agent scoring, slug-style ids in the model (VAmPI scores 0 because of it). Original notes:
`bench/docker-compose.yml` already lists Juice Shop and VAmPI; crAPI uses its own compose.
- **Ground truth:** write `bench/ground-truth/{juice-shop,crapi,vampi}.yaml` in the VulnShop format, pinning image versions.
- **Runner:** a script (`bench/run.sh`) that starts the app, runs a scripted browse through the proxy, drives an agent or the assistant, then `proxymind bench score`.
- **CI:** a nightly GitHub Actions workflow (Ubuntu runners have Docker even though this sandbox can't pull images) that publishes scores as an artifact and in the README.

### C. Desktop shell (Tauri 2)
✅ **Foundation done** (`desktop/`, ADR-0012; excluded from the workspace; CI job `desktop`). In the sandbox: `apt-get install libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libxdo-dev xvfb`, build in `desktop/`, run under `Xvfb :77` and screenshot with ImageMagick `import`. CI lints it on all three OSes; releases bundle installers (`cargo tauri build`). Its `Cargo.lock` is separate: refresh it with `cargo metadata` in `desktop/` after adding workspace dependencies. Project picker (`static/setup.html`, the only page with IPC; prefs in `~/.proxymind/desktop.json`; switching restarts the app) and CA trust from the tray are done; `xdotool` can click in the Xvfb window for checks. Next: code signing. Original notes:
ADR-0006/0008: wrap the existing web UI, don't rewrite it.
- **Layout:** a `desktop/` crate starts the `pm-api` router in-process on `127.0.0.1:0` and opens a webview at `/auth?token=…`.
- **Native extras:** tray icon (proxy on/off), CA install helper, file pickers for projects.
- **Build:** on Linux it needs `libwebkit2gtk-4.1-dev` and friends, so build and test in a CI job (`apt-get install`). It can't be checked visually in the sandbox.

### D. Later
Transparent project encryption (sealing is done: `project lock/unlock`, ADR-0013), installers, `h2spec`, more active checks (blind/time-based, OAST-based), plugin sandboxing and active-check plugins. (Intruder, crawler, passive scanner and plugin foundation: done, basic.)

## 5. How to work on it

### SDKs
TypeScript: `sdk/typescript` (no runtime dependencies): `npm ci && npm run build && PROXYMIND=../../target/debug/proxymind npm test` (also in the CI `ui` job). Python:
`sdk/python` (Apache-2.0, no dependencies). Tests start a real `proxymind ui` and VulnShop: `PROXYMIND=target/debug/proxymind python3 -m unittest discover -s sdk/python/tests` (also in the CI `ui` job). Add a method to both SDKs when you add an API route.

### Releases, container, fuzzing
**Actions minutes are limited** (2,000 per month on the owner's plan). Pushes run CI on Linux only, docs-only pushes are skipped, and a newer push cancels the older run; pull requests and manual runs cover macOS and Windows. Nightly is manual only. Batch several features per push.

See `docs/releasing.md`: tag `v*` → `.github/workflows/release.yml` (binaries, checksums, SBOM, attestations, GHCR image). `.github/workflows/nightly.yml` fuzzes parsers (`fuzz/`, needs nightly + cargo-fuzz) and builds the image. In the sandbox, `dockerd` can be started by hand and builds work with `--secret id=extra_ca,src=/root/.ccr/ca-bundle.crt` and the proxy as build args.

### Commands (run all before pushing)

```bash
cargo build
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --workspace
cargo deny check
cd ui && npm ci && npm run build      # cargo build embeds ui/dist
npm run test:e2e                      # needs a built binary (target/debug/proxymind); uses Chromium
```

### Patterns to follow when adding a feature
1. Pure logic in the lowest crate that fits (parsers and verdicts sans-I/O, with unit tests).
2. A `pm-service` method that gates the action (`gate_send_with`, choosing the tier; approvals must cover every parameter that changes what is sent) and records what was sent.
3. Expose it in `pm-mcp/src/tools.rs` (description written for a model, `deny_unknown_fields` arg structs), `pm-api/src/routes.rs`, and the UI. Update `docs/agents.md` when tools change.
4. Integration tests against VulnShop or small local servers in `tests/`, and a step in `ui/tests/e2e.mjs` for UI work.
5. Update `docs/plan.md` (Status / Next) and the README; add an ADR for hard-to-reverse decisions.

### Environment pitfalls seen in the cloud sandbox
- **Disk fills up.** `target/` grew past 30 GB, and a full disk shows up as `ld … Bus error`. Build with `CARGO_INCREMENTAL=0`, and run `cargo clean` if space runs low.
- **Chromium** is preinstalled at `/opt/pw-browsers`; never run `playwright install`. The e2e HTTP/2 step needs `openssl` on PATH.
- **`localhost` resolves to IPv4 only in the sandbox** but to `::1` first on CI runners. Tests that use `localhost` must work with both (this caused a CI-only failure once).
- **The UI e2e Intercept step (`held-drop`) timed out once locally** and passed on reruns; watch for it in CI.
- **Windows CI is the slowest job** (≈7 min). Keep timing assertions generous and prove ordering instead of tight durations.
- **No `gh` CLI.** Use the GitHub MCP tools (load them with ToolSearch) for PRs and CI logs.
- **Git:** develop on the branch the session assigns. Commit messages end with the attribution trailers from the session's instructions. Don't put model identifiers in repo files. Open PRs only when asked. `main` gets merges of PRs (merge commits).

### Status of the session that wrote this
Two breadth-first passes added, each with tests: XSS proofs (headless Chromium), DNS OAST, payload-aware tiers, Intruder, crawler, passive and active scanners, OpenAPI import, Decoder/Comparer/Sequencer, report exports (HTML/JSON/SARIF), plugins (passive-check protocol), sealed projects, a Tauri desktop app with installers in releases, a Docker image, a signed release workflow, nightly fuzzing (10 targets) and benchmarks, real-app ground truth (VAmPI, Juice Shop verified; crAPI unverified) and a Python SDK. VulnShop now has VS-1…VS-13. A third pass is under way: HAR/cURL import and export and history search with a site map, GraphQL, content discovery, an engagement page, a proxy setup page the desktop project picker and CA helper, and a TypeScript SDK (done). The third foundation pass is complete; next are deep dives (see below).

Good next deep dives: an agent-driven benchmark run; slug-style ids in the app model (VAmPI scores 0 on the baseline because of it); stored/DOM XSS proofs; blind (time/OAST) active checks; crAPI; code signing; plugin sandboxing; transparent project encryption.
