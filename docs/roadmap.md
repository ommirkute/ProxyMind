# Roadmap: gaps and implementation plan

Written 2026-11-14. The working copy, with comments, is a shared doc; this file is the version the code follows.
Update the status columns here as work lands.

As of 2026-11-17 (end of Phase 2; the ProxyMind column is updated, the others are as checked on 2026-11-14).
ProxyMind already leads on proof, governance (the policy gate and audit log) and AI integration. To lead overall it
needs team collaboration, traffic scripting, HTTP/3 and gRPC, a self-hostable callback server and wider proof
coverage, on a store and event layer that scales.

## Decisions

| Decision | Choice | Since |
| --- | --- | --- |
| Version and releases | Stay on 0.2.0 until the Phase 4 gate; record changes under "Unreleased" in `CHANGELOG.md`; no tags or releases until then | 2026-11-13 |
| Licensing | Every feature stays open source, team features included | 2026-11-14 |
| Signing certificates | Bought once the app has all planned features; signing (4.1) waits until then | 2026-11-14 |
| Identity (3.1) | Local accounts (passkeys, password + TOTP) first, then OIDC; invite only; viewers see redacted traffic; fix threat-model F-1/F-2 first | 2026-11-21 |
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
| Scripting live traffic | Match and replace, plugin traffic hooks (2.1), saved workflows (2.2) | Extensions | Workflows | Not stated | Python addons |
| Protocols | HTTP/1.1, HTTP/2, HTTP/3 to targets, WebSockets, gRPC/Protobuf, raw TCP/TLS streams; SOCKS5 and transparent capture | HTTP/2, WebSockets | Not stated | Not stated | Adds HTTP/3 |
| Team collaboration | None | Not stated | Teams offering | Not stated | No |
| AI and agents | MCP (87 tools), assistant, AI scan inside the policy gate | Not stated | Agents | Not stated | No |
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
| Service calls share one store lock | `store: Mutex<Store>` in `pm-service/src/lib.rs` (192 call sites): every service read and write takes one lock. The proxy recorder writes on its own connection, so two writers also contend for SQLite's write lock; the audit chain relies on the mutex for its order | Read pool plus one writer that also takes the recorder's writes (1, ADR-0017) |
| No event bus | The UI's live stream polls counters every 700 ms per open stream (`pm-api/src/routes.rs`), each tick loading up to 10,000 findings to count them; three pages keep their own timers | Typed events broadcast from the service; SSE topics and webhooks subscribe (1, ADR-0018) |
| Hand-written contracts | REST routes, MCP schemas, both SDKs and the UI types are kept in step by hand; about two thirds of REST bodies use structs private to `routes.rs` and every handler returns untyped JSON | Schemas derived from the Rust types; OpenAPI, SDK, UI and MCP schemas generated; CI fails on drift (1, ADR-0019) |
| History search scans content | No full-text index in `pm-store` | SQLite FTS5 filled by the recorder; HQL content terms use it (1) |
| One very large service crate | `pm-service` is about 21,500 lines | Domains in their own crates behind the one `pm-service` facade (ADR-0005 holds) (1) |
| Single user, single project | The API acts as one person fixed at start-up; one project per process | Users, roles and a project registry; authorization on every route (3) |
| No inline traffic hook | Live traffic changes only through regex rules (`pm-proxy/src/rewrite.rs`); plugins run as sandboxed processes per check, and there is no WASM runtime yet (ADR-0016) | A hook interface with time and memory limits: a WASM runtime, or the existing sandboxed plugin processes (2, needs an ADR) |
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
2026-11-14: VulnShop 20/38 proven with no false positives; VAmPI and Juice Shop still to re-measure in CI.

## Phase 1: foundations for scale

No new features: this removes the limits that would block Phases 2 and 3. Write an ADR for 1.1, 1.2 and 1.3 first.

| Work package | What | Done when |
| --- | --- | --- |
| 1.1 Store concurrency | Read-only connection pool (WAL) and one writer task fed by a bounded channel; recorder writes batched in transactions | 2,000 requests a second recorded while a content search runs, no stall over 50 ms |
| 1.2 Event bus | A typed `Event` enum broadcast from the service; SSE topics with per-event payloads; the UI stops polling | No timers left in the UI's live view |
| 1.3 Typed contracts | JSON schemas derived from the Rust types; OpenAPI, UI types, SDK types and MCP schemas generated; CI drift check | The hand-written MCP schemas are gone. **Done 2026-11-15** (ADR-0019 steps 1-7): OpenAPI for all 175 operations, all 79 MCP tool schemas, TypeScript and Python types generated by `cargo xtask contracts`; `--check` runs in CI |
| 1.4 Full-text search | FTS5 over decoded text, filled by the writer task; backfill through a new (append-only) migration | Content search on 1M exchanges under 200 ms. **Step 1 done 2026-11-14** (plain-text search, see below); **Step 2 done 2026-11-14**: HQL content terms (`req:`/`resp:`/`any:`) pre-filter through the index; `resp:"user996@shop.test"` over 30,000 exchanges 1,500 ms -> 17 ms (debug) |
| 1.5 Service split | Domains (scanning, proof, regress, sessions, AI) in their own crates behind the facade | Facade API unchanged; one domain rebuilds in under 30 s. **Met by measurement 2026-11-16, split deferred:** editing a function body in `pm-service/src/proof.rs` rebuilds the `proxymind` binary in 25 s (debug, 4 cores). Of that, `pm-service` itself is 5.9 s; `pm-api` (9.0 s) and the `pm-cli` binary (9.3 s) are the rest, and every crate above the service rebuilds whatever is split below it, so splitting saves at most about 6 s. Revisit if the service crate grows past the target. |
| 1.6 Large-project benchmark | 1M exchanges, 10k issues: ingest, search, UI first paint, memory | Numbers in the docs, tracked weekly. **Done 2026-11-16:** release numbers below; the Nightly workflow's `scale` job runs it (manual, with the other benchmarks) and keeps the `SCALE` line. UI first paint is not measured yet. |

**Baseline (2026-11-14, debug build, 100k exchanges, 10k findings; `crates/pm-service/tests/scale.rs`):** inserts
2,172/s; recording while a content search runs 2,241/s with the worst insert stall 20.6 ms (p99 1.3 ms), already under
the 1.1 target because the recorder writes on its own connection; slowest metadata query 1.5 s (a response-content
term); one content search over 5,000 bodies 0.9 s; RSS 27 MB after loading. **Finding creation is quadratic** (every
create lists all findings to check duplicates): 10,000 findings took 393 s, 25/s. So the order changes: fix finding
creation first, then full-text search (1.4); the store split (1.1) matters most for service-path writes (imports,
replay, races, audit) that share the service lock, which the next benchmark round must measure. Real numbers need a
release build and 1M exchanges.

**1.4 step 1 (2026-11-14):** a contentless trigram FTS5 index (positions-free: about 0.6x the text on JSON-like
traffic) pre-filters plain-text content search; every candidate is still verified, so results are unchanged. Writing
the index inside each one-row insert halved recording (per-commit index work: 43,869 vs 3,048 rows/s in raw SQLite),
so file projects index in a background thread in batches, and exchanges not yet indexed are always candidates.
Debug build, 30k exchanges: recording 2,700-3,160 inserts/s (unchanged from no index), content search 0.8 ms (was
902 ms over 5,000 bodies). While recording and searching at once, the recorder's writer thread still sees stalls up
to about 180 ms (p99 8 ms): the indexer and SQLite's WAL checkpoints compete with it for the write lock. The proxy
doesn't wait on those (it only enqueues; the queue holds 4,096 exchanges, about 2 s at 2,000/s), so the 1.1 target
as ADR-0017 defines it holds. Moving checkpoints into the indexer cut p99 to 0.4 ms and doubled throughput but let the
indexer starve the recorder (max stalls up to 3 s), so it wasn't kept; the real fix is ADR-0017's single writer, which
does the indexing in its own batches.

**1M-exchange release run (2026-11-16, 4 cores, 1,000,000 exchanges, 10,000 findings; 13.6 min in all):**

| Measure | Result | Target |
| --- | --- | --- |
| Recording while content searches run (saturated) | 5,821 exchanges/s | 2,000/s: met |
| Proxy blocked handing an exchange to the recorder, paced at 2,000/s (ADR-0017's stall) | max 5.7 ms, p99 0.0 ms | 50 ms: met |
| Enqueue to commit (when a recorded exchange becomes visible), paced at 2,000/s | p50 3.0 ms, p99 65.5 ms, max 95.2 ms | not a gate; was max 20.6 ms at 100k |
| Plain-text content search (index) | 2.3 ms; 166 ms for a needle with 50 hits | 200 ms: met |
| History query `resp:"user996@shop.test"` (index) | 204.6 ms | 200 ms: just over |
| Slowest metadata query (`path~"users/99[0-9]/" time:>800`, a regex scan) | 1,242 ms | none |
| Site map 407 ms; rare text filter 342 ms; other filters and paging | 0.6 to 30 ms | none |
| Findings created through the service | 2,041/s | none |
| Audited service writes during back-to-back regex searches | 1,057/s, p99 5.4 ms, max 73.4 ms | none |
| Loading: sequential one-transaction inserts | 2,982/s (335 s); the background indexer caught up 255 s later | none |
| Resident memory after loading | 18 MB | none |

The Phase 1 gate is met on the targets it names (recording rate, proxy stall, content search), and the byte-exact
traffic tests pass. Follow-ups, none blocking: commit latency grows with project size (p99 65 ms at 1M against
1.3 ms at 100k: checkpoints and index batches on the one write connection), the index-backed `resp:` query is at the
limit, and regex path queries, the site map and the text filter still scan.

**Gate:** the 1M-exchange benchmark meets the targets, and the byte-exact traffic tests still pass.

## Phase 2: protocols, capture and scripting

Every parser change follows ADR-0002 (bytes unchanged unless a user or rule changes them) and gets a fuzz target.

| Work package | What |
| --- | --- |
| 2.1 Traffic hooks | **Done** (ADR-0020). Request and response hooks in the proxy with time and memory limits (an ADR first: a new WASM runtime or the existing sandboxed plugin processes, ADR-0015/0016); changes recorded next to the original. Long-lived sandboxed workers, JSON lines, 200 ms default deadline, bypass and pause on failure, HTTP/1.1 and HTTP/2; Plugins page controls |
| 2.2 Workflows | Saved chains of steps (match, extract, transform, send, assert), run on demand, per exchange or from the fuzzer, through the policy gate. **Done 2026-11-17** (`docs/workflows.md`): definitions in the project setting `workflows`, runs in table `workflow_runs` (migration 24, newest 200); engine and model in `pm-service/src/workflow.rs` (fake-able `Host`, limits 50 steps / 20 sends / 120 s, no loops), storage, gate, triggers and fuzzer glue in `workflow_service.rs`, strict transforms in `pm_tools::transform` (vectors shared with `ui/tests/transforms.test.mjs`). Each send is a `workflow_send` through `gate_send_with` (approval binds the bytes; a run that needs approval pauses and resumes from that step); per-exchange trigger (people only, audited, off by default, first step must be a `match`, event-bus driven, per-minute cap, loop guard by source); Fuzzer option `workflow`; Workflows page, History right-click, `proxymind workflow`, REST `/workflows…`, MCP `workflow_list`/`workflow_get`/`workflow_run`, SDK methods, `workflows` event topic. Not yet: loops and branches (by design), workflow import/export, a UI for resuming from the Approvals page, per-step timeouts |
| 2.3 Inline transforms | Encode, decode and hash in the editor with a reversible preview. **Done 2026-11-16:** browser-side transforms (`ui/src/transforms.ts`, menu `ui/src/TransformMenu.tsx`) in the Replay and Intercept editors, with preview, chaining, Undo and native Ctrl+Z; smart decode via `/tools/decode`; unit tests `npm run test:unit` |
| 2.4 HTTP/3 | QUIC on the client and upstream sides, Alt-Svc handling, HTTP/3 in history and replay. **Done 2026-11-17, upstream side** (ADR-0021): `quinn` 0.11 + `h3` 0.0.8 + `h3-quinn` 0.0.10 on the workspace's rustls/ring (18 new crates, all MIT/Apache-2.0, no C), only in `pm-replay`. `HTTP/3` in a request line is sent over QUIC (`pm-replay/src/h3send.rs`); text form `pm_http::h3text` (same shape as HTTP/2: `HTTP/3`, `host:` for `:authority`, fuzz target `http3_text`); the QUIC sockets connect to exactly the addresses the policy check saw (up to 4 raced, SNI = host name), verify setting, timeouts and a 64 MB body limit as for HTTP/2; hosts routed through an HTTP or SOCKS5 upstream rule are refused for HTTP/3 (QUIC is UDP), never sent direct; streaming, race and parallel sends refuse HTTP/3 text. History records the text form and labels the protocol; `Alt-Svc` h3 advertisements show an "offers HTTP/3" chip with "Send with HTTP/3" (History to Replay, Replay); response preset "Remove HTTP/3 advertisements (Alt-Svc h3)" (opt-in, original kept); Replay's Protocol selector; MCP `replay_send` and REST `/replay` take the protocol from the request line (no new fields). Tests: in-process HTTP/3 server (`pm-replay/tests/common/h3_server.rs`, also the `h3_server` example the browser test starts). **Not yet:** the client-side QUIC listener for transparent mode (needs original-destination UDP sockets, an h3 server module and a per-SNI certificate resolver; block UDP/443 and use the preset meanwhile, `docs/capture.md`), CONNECT-UDP (MASQUE) upstream proxies, HTTP/3 in race and parallel sends, a connection pool and 0-RTT, WebSockets over HTTP/3, frame-level tooling |
| 2.5 gRPC and Protobuf | Pure decoder in `pm-http`; schema-less view as the fallback; edit and replay. **Done 2026-11-16:** `pm_http::protobuf` (decoder, text format, encoder, gRPC and gRPC-Web framing), Protobuf view in History, Replay and the Fuzzer, edit-and-replay in Replay (`body_b64` on replay, race and group), `protobuf_decode` for agents, fuzz target in the nightly matrix. Not yet: `.proto` schemas, streaming views, HTTP/2 trailers |
| 2.6 Raw TCP and TLS | Relay non-HTTP streams with hex and text views; replay a stream. **Done 2026-11-17:** non-HTTP streams through CONNECT, SOCKS5 and transparent listeners, and non-HTTP protocols inside intercepted TLS (decrypted bytes recorded, custom ALPN values passed to the target), are recorded as streams (migration 23, chunks in order with direction and time, 16 MB cap per stream, in-scope and device recording settings apply); API `/streams`, Streams page with text and hex views, search and live updates (`streams` topic); replay through the policy gate (`POST /streams/{id}/replay`, MCP `stream_list`, `stream_get`, `stream_replay`). Not yet: UDP, STARTTLS upgrades, protocol decoders, CLI commands and SDK methods |
| 2.7 Capture modes | Transparent mode (Linux, macOS), SOCKS5, upstream chains with per-host rules. **Done 2026-11-17** (Linux only for transparent mode): SOCKS5 listener (`ListenerKind::Socks5`; pure parser `pm_http::socks5`, I/O in `pm-proxy/src/capture.rs`; CONNECT with IPv4/IPv6/domain, optional RFC 1929 login, BIND/UDP refused with code 7, 10 s handshake limit, 255-byte login limit; after the handshake the stream goes through the CONNECT path, so TLS interception, h2, WebSockets, pass-through and the setup page behave the same; non-HTTP streams are relayed unrecorded and counted, server-first protocols detected), `upstream_rules` (ordered `{match: globs and CIDRs, via: direct, http://… or socks5://…, username, password, remote_dns}`, first match wins, old `upstream` loads as rules, `POST /network/upstream/resolve`), transparent listeners (`pm_proxy::transparent`: `SO_ORIGINAL_DST` and TPROXY through the `nix` crate, no `unsafe`; HTTP by Host, TLS by SNI, original address for where to connect), Listeners and Network pages, `docs/capture.md`, fuzz target `socks5_handshake`. Not supported: transparent mode on macOS (`pf` `DIOCNATLOOK`, no safe crate) and Windows; SOCKS5 BIND and UDP ASSOCIATE; raw TCP recording and non-HTTP protocols inside TLS were added by 2.6 |
| 2.8 Mobile onboarding | CA certificate page with a QR code; Android 14+ and iOS guides; per-device scoping. **Done 2026-11-16:** the proxy answers `http://proxymind.setup/` (and its own address) with a script-free CA page (`pm_proxy::setup_page`: `.crt` DER and `.pem` downloads, fingerprint, steps), never forwarded or recorded; `GET /setup/mobile` returns LAN URLs and a server-drawn QR code (SVG via the `qrcode` crate, shown as an `<img>`); `client_addr` on exchanges (migration 21), `client` filter and HQL `client:`, device names (`/devices`, project setting `devices`), `record_devices` next to in-scope recording; guide `docs/mobile.md`. Not yet: SOCKS5 or a PAC file for apps that ignore the Wi-Fi proxy, IPv6 addresses in the QR URL, automatic device names |
| 2.9 Plugin API v2 | **Done** (ADR-0020). Versioned SDK for hooks, manifest with declared permissions enforced by the policy gate. `api: 2` manifests, accepted-permission review, enforcement in `pm-service`, Python and TypeScript helpers, `docs/plugins.md`, example `sign-request` |

**Gate:** byte-exact tests for every new protocol, fuzz targets in CI, the Phase 1 benchmark no more than 10% worse.

**Phase 2 gate (2026-11-17): met.** All nine work packages are done (2.4's client-side QUIC listener and
transparent mode on macOS and Windows are deferred, see ADR-0021 and `docs/capture.md`). Each new protocol has
byte-exact tests and a fuzz target in the Nightly matrix (`protobuf_decode`, `socks5_handshake`, `http3_text`).
The 1M-exchange release benchmark, rerun on the Phase 2 code, is no worse on any measure:

| Measure | Phase 1 (2026-11-16) | Phase 2 (2026-11-17) |
| --- | --- | --- |
| Recording while content searches run | 5,821/s | 7,541/s |
| Proxy hand-off to the recorder, paced at 2,000/s | max 5.7 ms | max 3.9 ms |
| Enqueue to commit, paced at 2,000/s | p99 65.5 ms, max 95.2 ms | p99 51.7 ms, max 80.3 ms |
| Plain-text content search; with 50 hits | 2.3 ms; 166 ms | 1.3 ms; 78.7 ms |
| `resp:"user996@shop.test"` | 204.6 ms | 107.6 ms |
| Regex path query; site map; rare text filter | 1,242; 407; 342 ms | 968; 204; 280 ms |
| Sequential inserts; findings created | 2,982/s; 2,041/s | 3,856/s; 2,730/s |
| Audited service writes during regex searches | 1,057/s, p99 5.4 ms | 1,560/s, p99 4.3 ms |

Both runs used the same 4-core cloud container type, but not the same machine, and the Phase 2 run shared the CPU
with a build for part of the time, so the gains are mostly machine variance: the result is "not worse", not "faster".


## Phase 3: teams and integrations

Starts with an ADR on identity and a written threat model.

| Work package | What |
| --- | --- |
| 3.1 Identity ADR | Local accounts with passkeys, OIDC, or both; sessions; how the API token fits. ADR-0022 accepted 2026-11-21 (local accounts first, then OIDC; invite only; viewers see redacted traffic), threat model in `docs/threat-model.md` |
| 3.2 Users and roles | Owner, tester, viewer; authorization in `pm-service` for every action; audit of who did what |
| 3.3 Project server | One server, many projects, each with its own scope and rules of engagement |
| 3.4 Shared work | Assignment, comments on exchanges and issues, presence over the event bus |
| 3.5 Integrations | Jira, GitHub Issues, GitLab, Slack, webhooks, SARIF and JUnit; secrets in the OS keychain or environment. **Done 2026-11-17** (`docs/integrations.md`): issues from findings for Jira (REST v2), GitHub and GitLab with redacted text and reproduction, key and URL kept on the finding (migration 25), duplicates refused or updated; Slack and signed (HMAC-SHA256) versioned webhook notifications from the event bus (finding proven, status changed, scan finished, summary) with a rate limit, bounded retries and a delivery log; secrets in a private file in the home folder or `env:NAME`, never in the project (**the OS keychain was evaluated and not used**: it needs a Secret Service daemon that headless Linux and CI lack; see the doc); outbound requests use the sender with TLS always verified, no redirects, a private/loopback/link-local refusal with a per-integration allow, and integrations from a project file stay off until a person enables them in this install (F-2); people-only configuration, agents can list names. SARIF and JUnit come from CI mode (3.7). Not done: keychain backend, agent-triggered sends, syncing tracker status back |
| 3.6 Hosted callback server | Self-hostable OAST server (DNS, HTTP, SMTP) with per-project tokens |
| 3.7 CI scanning mode | `proxymind ci`: scope file, crawl, scan, prove, SARIF, fail on new proven issues against a baseline. **Done 2026-11-17** (`docs/ci.md`, `examples/ci/`): ROE file required and the target must be in scope; fresh in-memory project (or `--project`, with F-2 handled: nothing from the file is started and network, session and OAST settings are ignored while it runs); optional identities (`--identity-file` with `${ENV}` references), OpenAPI import, discovery, crawl and scan with a profile, automatic proving (`pm-service/src/ci.rs`, reusing scan tasks, `auto_discover`, `auto_prove`); baseline with a stable fingerprint `v1\|issue\|METHOD\|normalised path\|point` (`pm_tools::ci`), `--write-baseline`, fixed findings only reported; SARIF 2.1.0 (`partialFingerprints`, `baselineState`), JUnit, JSON, stdout summary; exit 0 / 1 / 2 (2 = could not finish, never clean; findings win over 2); new actor kind `ci` with ROE section `tiers.ci` (defaults: safe GETs allowed, intrusive `approve`, destructive `deny`; nothing is ever approved, skipped work is reported and fails the run unless `--allow-skipped`); `--max-requests` and `--budget-minutes` as hard caps (counted in `Service::transmit`); TLS verified unless `--insecure`. Tests: `crates/pm-cli/tests/ci.rs` (9, against VulnShop), `pm_tools::ci` unit tests, `crates/pm-policy/tests/ci_actor.rs`. Not yet: OAST in CI runs, scanning only what a pull request changed, pull request comments, GitLab's own security report format |

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
