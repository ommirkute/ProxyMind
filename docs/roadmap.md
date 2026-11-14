# Roadmap: gaps and implementation plan

Written 2026-11-14. The working copy, with comments, is a shared doc; this file is the version the code follows.
Update the status columns here as work lands.

ProxyMind already leads on proof, governance (the policy gate and audit log) and AI integration. To lead overall it
needs team collaboration, traffic scripting, HTTP/3 and gRPC, a self-hostable callback server and wider proof
coverage, on a store and event layer that scales.

## Decisions

| Decision | Choice | Since |
| --- | --- | --- |
| Version and releases | Stay on 0.2.0 until the Phase 4 gate; record changes under "Unreleased" in `CHANGELOG.md`; no tags or releases until then | 2026-11-13 |
| Licensing | Every feature stays open source, team features included | 2026-11-14 |
| Signing certificates | Bought once the app has all planned features; signing (4.1) waits until then | 2026-11-14 |
| Out of scope | Detection or WAF evasion, stealth scanning, mass internet scanning | Standing |

Recommendations still to confirm when their phase starts: a reader pool plus one writer task for the store (1.1),
contracts generated from the Rust types (1.3), local accounts and OIDC both (3.1), a capped API key used only by the
benchmark job for AI scan scoring (4.7).

## Where ProxyMind stands

| Capability | ProxyMind | Burp Suite Pro | Caido | OWASP ZAP | mitmproxy |
| --- | --- | --- | --- | --- | --- |
| Intercept, replay, fuzz | Yes | Yes | Yes | Yes | Intercept and replay |
| Automated scanning | Passive and active checks, crawl and audit, YAML custom checks | Passive and active, custom checks | Not stated | Packaged scans | No |
| Proof that a finding is real | Stored, re-runnable oracles | Not stated | Not stated | Not stated | No |
| Out-of-band testing | Local DNS, HTTP, SMTP listener | Built in | Not stated | Not stated | No |
| Scripting live traffic | Regex match and replace only | Extensions | Workflows | Not stated | Python addons |
| Protocols | HTTP/1.1, HTTP/2, WebSockets | HTTP/2, WebSockets | Not stated | Not stated | Adds HTTP/3 |
| Team collaboration | None | Not stated | Teams offering | Not stated | No |
| AI and agents | MCP (79 tools), assistant, AI scan inside the policy gate | Not stated | Agents | Not stated | No |
| Policy gate and tamper-evident audit | Yes | Not stated | Not stated | Not stated | No |

"Not stated" means the vendor page checked did not say. Sources: [Burp Suite Pro
features](https://portswigger.net/burp/pro/features), [Caido](https://caido.io/), [ZAP
automation](https://www.zaproxy.org/docs/automate/), [mitmproxy modes](https://docs.mitmproxy.org/stable/concepts/modes/),
[mitmproxy 11](https://www.mitmproxy.org/posts/releases/mitmproxy-11/).

## Feature gaps, ranked

| Rank | Gap | Phase |
| --- | --- | --- |
| 1 | Proof coverage: more classes proven automatically | 0 |
| 2 | Team collaboration: shared projects, roles, assignment, comments | 3 |
| 3 | Scripting live traffic and workflows | 2 |
| 4 | Protocols: HTTP/3, gRPC with Protobuf, raw TCP | 2 |
| 5 | Self-hostable callback (OAST) server | 3 |
| 6 | Capture modes and mobile onboarding | 2 |
| 7 | Extension platform: versioned plugin API, registry | 2, 4 |
| 8 | Integrations: Jira, GitHub Issues, Slack, webhooks | 3 |
| 9 | Regression runner hardening | 0 |
| 10 | Inline transforms in Replay | 2 |
| 11 | AI scan scored on the benchmarks | 4 |
| 12 | Signed installers and auto-update | 4 |

## Architecture gaps

| Gap | Evidence | Fix (phase) |
| --- | --- | --- |
| One database connection per process | `store: Mutex<Store>` in `pm-service/src/lib.rs`: every read and write takes one lock | Read pool plus one writer task fed by a channel (1) |
| No event bus | The UI's live stream polls counters every 700 ms (`pm-api/src/routes.rs`) | Typed events broadcast from the service; SSE topics and webhooks subscribe (1) |
| Hand-written contracts | REST routes, MCP schemas and both SDKs are kept in step by hand | Schemas derived from the Rust types; OpenAPI, SDK types and MCP schemas generated; CI fails on drift (1) |
| History search scans content | No full-text index in `pm-store` | SQLite FTS5 filled by the recorder; HQL content terms use it (1) |
| One very large service crate | `pm-service` is about 21,500 lines | Domains in their own crates behind the one `pm-service` facade (ADR-0005 holds) (1) |
| Single user, single project | The API acts as one person fixed at start-up; one project per process | Users, roles and a project registry; authorization on every route (3) |
| No inline traffic hook | Live traffic changes only through regex rules (`pm-proxy/src/rewrite.rs`) | A hook interface run by the WASM plugin runtime with time and memory limits (2) |
| HTTP/1.1 and HTTP/2 only | No QUIC stack, no decoders for non-HTTP streams | QUIC and HTTP/3 on both sides, pluggable stream decoders, raw TCP relay (2) |
| One long end-to-end script | `ui/tests/e2e.mjs` runs as one sequence | Sections isolated so one failure doesn't hide the rest (0) |

## Phase 0: finish what is in flight

| Work package | What | Status |
| --- | --- | --- |
| 0.1 Regress hardening | A test skipped for an unset `PM_AUTH_*` variable makes `regress run` exit 2; `--allow-skipped` for local runs | Done 2026-11-14 |
| 0.2 More proof kinds | Template injection (`expression` oracle), NoSQL operator injection (boolean split), XXE (entity file read, or blind via OAST), CORS (`cors` marker kind), Host-header injection (`host` marker in `X-Forwarded-Host`) ; also stored and DOM XSS (headless browser), SQL injection in a header the recorded request lacks, IDOR in GraphQL queries sent by POST | Done 2026-11-14 |
| 0.3 False-proof guard | Every automatic class tried on every endpoint of a fixed app proves nothing (`crates/pm-service/tests/prove_more.rs`); found and fixed a boolean-SQLi false proof on pages that echo their input | Done 2026-11-14 for the test app; crAPI and the VAmPI/Juice Shop runs still to do in CI |
| 0.4 End-to-end isolation | Each section of `ui/tests/e2e.mjs` runs on its own: a failure is counted with a screenshot and the next section runs | Done 2026-11-14. Sections share state (identities, findings, settings made earlier), so they run in order; running them in parallel would need each section to build its own state, which costs more than the 6 minutes it would save |
| 0.5 Benchmark images | "Bench images" workflow copies the images to GHCR; `BENCH_REGISTRY` selects the mirror; the nightly job uses it once filled | Done 2026-11-14. Nightly can also run only the benchmarks (about 15 minutes). Both need PR #25 on `main` before they can be started |
| 0.6 Docs | Version, licensing and certificate decisions recorded; this file | Done 2026-11-14 |

**Gate:** VulnShop at 15 or more of 38 findings proven, no false proofs on three apps, all checks green. Status
2026-11-14: VulnShop 15/38 proven with no false positives; VAmPI and Juice Shop still to re-measure in CI.

## Phase 1: foundations for scale

No new features: this removes the limits that would block Phases 2 and 3. Write an ADR for 1.1, 1.2 and 1.3 first.

| Work package | What | Done when |
| --- | --- | --- |
| 1.1 Store concurrency | Read-only connection pool (WAL) and one writer task fed by a bounded channel; recorder writes batched in transactions | 2,000 requests a second recorded while a content search runs, no stall over 50 ms |
| 1.2 Event bus | A typed `Event` enum broadcast from the service; SSE topics with per-event payloads; the UI stops polling | No timers left in the UI's live view |
| 1.3 Typed contracts | JSON schemas derived from the Rust types; OpenAPI, UI types, SDK types and MCP schemas generated; CI drift check | The hand-written MCP schemas are gone |
| 1.4 Full-text search | FTS5 over decoded text, filled by the writer task; backfill through a new (append-only) migration | Content search on 1M exchanges under 200 ms |
| 1.5 Service split | Domains (scanning, proof, regress, sessions, AI) in their own crates behind the facade | Facade API unchanged; one domain rebuilds in under 30 s |
| 1.6 Large-project benchmark | 1M exchanges, 10k issues: ingest, search, UI first paint, memory | Numbers in the docs, tracked weekly |

**Gate:** the 1M-exchange benchmark meets the targets, and the byte-exact traffic tests still pass.

## Phase 2: protocols, capture and scripting

Every parser change follows ADR-0002 (bytes unchanged unless a user or rule changes them) and gets a fuzz target.

| Work package | What |
| --- | --- |
| 2.1 Traffic hooks | Request and response hooks in the proxy, run by the WASM plugin runtime with time, memory and fuel limits; changes recorded next to the original |
| 2.2 Workflows | Saved chains of steps (match, extract, transform, send, assert), run on demand, per exchange or from the fuzzer, through the policy gate |
| 2.3 Inline transforms | Encode, decode and hash in the editor with a reversible preview |
| 2.4 HTTP/3 | QUIC on the client and upstream sides, Alt-Svc handling, HTTP/3 in history and replay |
| 2.5 gRPC and Protobuf | Pure decoder in `pm-http`; schema-less view as the fallback; edit and replay |
| 2.6 Raw TCP and TLS | Relay non-HTTP streams with hex and text views; replay a stream |
| 2.7 Capture modes | Transparent mode (Linux, macOS), SOCKS5, upstream chains with per-host rules |
| 2.8 Mobile onboarding | CA certificate page with a QR code; Android 14+ and iOS guides; per-device scoping |
| 2.9 Plugin API v2 | Versioned SDK for hooks, manifest with declared permissions enforced by the policy gate |

**Gate:** byte-exact tests for every new protocol, fuzz targets in CI, the Phase 1 benchmark no more than 10% worse.

## Phase 3: teams and integrations

Starts with an ADR on identity and a written threat model.

| Work package | What |
| --- | --- |
| 3.1 Identity ADR | Local accounts with passkeys, OIDC, or both; sessions; how the API token fits |
| 3.2 Users and roles | Owner, tester, viewer; authorization in `pm-service` for every action; audit of who did what |
| 3.3 Project server | One server, many projects, each with its own scope and rules of engagement |
| 3.4 Shared work | Assignment, comments on exchanges and issues, presence over the event bus |
| 3.5 Integrations | Jira, GitHub Issues, GitLab, Slack, webhooks, SARIF and JUnit; secrets in the OS keychain or environment |
| 3.6 Hosted callback server | Self-hostable OAST server (DNS, HTTP, SMTP) with per-project tokens |
| 3.7 CI scanning mode | `proxymind ci`: scope file, crawl, scan, prove, SARIF, fail on new proven issues against a baseline |

**Gate:** threat model, a security review of login and authorization, no open high-severity findings.

## Phase 4: polish and distribution

| Work package | What |
| --- | --- |
| 4.1 Signed installers | Notarized macOS builds, signed Windows MSI, deb and rpm with checksums and provenance (after the certificates are bought) |
| 4.2 Auto-update | Signed release metadata; asks before installing; can be turned off |
| 4.3 Encrypted projects by default | Key from the OS keychain; a clear export path |
| 4.4 Plugin registry | Reviewed, signed plugins with declared permissions; install from the UI |
| 4.5 Documentation site | Guides, generated API and MCP references, recipes |
| 4.6 Public benchmarks | Scheduled runs on VulnShop, crAPI, VAmPI and Juice Shop: found, proven, false proofs |
| 4.7 AI scan scoring | The AI scan on the same benchmarks with a fixed budget |

**Gate:** a release candidate installs cleanly on macOS, Windows and Linux and the benchmark page is live. The
version changes only here.
