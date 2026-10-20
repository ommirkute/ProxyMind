# ProxyMind build plan: v0.1

Target: first public release in about **6 months with a core team of 3**. v0.1 builds the four things that set ProxyMind apart (app model, multi-identity testing, proof-checked findings, hypothesis ledger) on a solid proxy core. Scanner, Intruder, crawler and plugins come after v0.1.

## Positioning

PortSwigger's Burp AT (public beta, July 2026) already offers agents inside Burp with allow/approve/block controls, enforcement outside the model, and an audit trail. Those are now **table stakes**. ProxyMind's differences:

1. **Open source, any model, any agent**, including fully offline local models.
2. **No proof, no finding:** the tool verifies findings itself.
3. **Live app model and multi-identity testing** with an automatic authorization matrix.
4. **Hypothesis ledger and coverage map** shared by humans and agents.
5. **Open, reproducible benchmarks.**
6. **No licence or AI-credit costs.**

## Status

**Done** (all with automated tests, CI on Linux/macOS/Windows):

- Proxy setup page (`/api/v1/setup`, `/api/v1/ca.pem`): proxy address, CA download with its SHA-256 fingerprint, per-OS and per-tool steps. Desktop app: project picker (recent projects, create a project from target URLs), Switch project and Trust the CA (per-user store) in the tray (ADR-0012)
- Engagement page (`/api/v1/roe`, `proxymind roe use`): view the rules in force with a who-may-do-what table, edit and validate the YAML, save (humans only, audited with before/after BLAKE3 hashes); changes apply at once to the gate, rate limits and the proxy's scope checks, and other processes on the project (MCP servers, the desktop app) pick them up within two seconds
- Content discovery (`pm_crawl::discover`, Model page, `proxymind discover`, `/api/v1/discover`, MCP `discover_content`): a built-in list of common hidden paths or your own words with extensions, GET only, in scope, risky paths skipped, the server's not-found page fingerprinted per path shape so soft 404s aren't reported; VulnShop gained VS-13 (an exposed `.git/config` with a deploy token) and a single-page-app soft-404 trap under `/app/`
- GraphQL (`pm-graphql`, Model page, `proxymind graphql`, `/api/v1/graphql/import`, MCP `graphql_import`): introspection results (pasted, recorded or fetched through the gate) become operations with example documents, variables and requests; a passive check flags introspection; VulnShop serves `/graphql` with VS-12 (the invoice resolver skips the ownership check the REST endpoint has)
- Site map and content search (`pm_tools::{search,sitemap}`, Site map & Search page, `proxymind search/sitemap`, `/api/v1/search`, `/sitemap`, MCP `history_grep`, `site_map`): literal or regex, case options, request/response/both, decoded bodies, paging; agents match against redacted text so search can't confirm secrets
- HAR import/export and cURL (`pm_tools::{har,curl}`, History and Repeater, `proxymind import/export/curl`, `/api/v1/import/har`, `/export/har`, `/exchanges/{id}/curl`, `/tools/curl`, MCP `import_har`, `curl_parse`): imports send nothing and are tagged `source: import`; exports and cURL for agents have secrets replaced
- TypeScript SDK (`sdk/typescript`, Apache-2.0, no runtime dependencies, platform `fetch`): the same surface as the Python SDK plus live events as an async iterator; typed errors (`ApiError`, `Denied`, `PendingApproval`); integration tests against the real binary in CI
- Python SDK (`sdk/python`, Apache-2.0, stdlib only): typed errors (`ApiError`, `Denied`, `PendingApproval`), approval waiting, live events, every main API action; integration tests against the real binary in CI
- Decoder, Comparer and Sequencer (Tools page, `decode`/`compare`/`sequencer` CLI, MCP `decode`, `compare_exchanges`, `sequencer_run`): codec chains and smart decode, LCS line diffs plus semantic diff, token randomness (per-position entropy, constant positions, duplicates, counters; statistics only, never the tokens). VulnShop gained VS-11 (sequential reset codes)
- Report exports: Markdown, JSON, SARIF 2.1.0 and a self-contained HTML page (everything escaped, its own `default-src 'none'` CSP), all from one structured report; `proxymind report --format` / `--out x.html`, `/api/v1/report?format=`, download buttons on the Findings page
- OpenAPI import (`openapi_import`, Model page, `proxymind openapi`): OpenAPI 3 and Swagger 2, JSON or YAML, local-only `$ref`s with depth and cycle limits, example requests with bodies from schemas; optional gated sending of GET examples; VulnShop serves /openapi.json
- Active scanner (`scan_active`, Issues page and History, `proxymind scan-active`): insertion points in query, form, JSON and numeric path values; checks for SQL errors, unencoded reflection (handed to the reflection oracle), open redirect, path traversal and SSTI against a fresh baseline; one approval per scan. VulnShop gained VS-7…VS-10 and two traps
- Plugins (ADR-0014): acting plugins are MCP clients as `plugin:<name>` under stricter tiers; passive-check plugins are any executable speaking a JSON-lines protocol, installed per user (`proxymind plugin add`), merged into the Issues list; example `examples/plugins/jwt-check`
- Desktop app (`desktop/`, Tauri 2, ADR-0012): runs the proxy and API in-process and shows the same web UI (remote page, no IPC), tray menu, setup page when the project can't open; built and linted in its own CI job
- Sealed projects (ADR-0013): `proxymind project lock/unlock` encrypts a consistent snapshot with Argon2id + chunked ChaCha20-Poly1305 (`pm-vault`); locked files are refused with a hint everywhere a project opens
- Real-app benchmarks (M6): ground truth for VAmPI and Juice Shop reproduced by hand against pinned images, crAPI from its challenge list (not yet run), `bench/run.sh` (browse as two users, crawl, `bench auto`, passive scan, optional agent, score), `bench score --app`, a model-free baseline (`bench auto`: discovery with API-description import, access-control leaks checked and proven, an active-scanner sweep; scores VulnShop 4/13, Juice Shop 3/8, VAmPI 2/7, no false positives) and a nightly job posting scores
- Release engineering: Dockerfile (UI + Chromium, non-root, `--bind-any` for containers), a tag-triggered release workflow (binaries for 3 OSes, SHA256SUMS, SPDX SBOM, Sigstore build-provenance attestations, GHCR image), and nightly fuzzing of 10 parser targets plus an image smoke test (`docs/releasing.md`). Fuzzing already found and fixed a crawler panic on Unicode whitespace and header injection through a pasted cURL URL
- Passive scanner (`scan_issues`, Issues page, `proxymind scan`): checks over recorded traffic for security headers, cookie flags, CORS, version disclosure, DB errors and stack traces, secrets, directory listings and passwords over HTTP; grouped per origin and path template; one click turns an issue into a finding (still unproven)
- Crawler (`crawl`, Model page, `proxymind crawl`): GET-only, per-URL scope check, skips state-changing links and risky payloads, robots.txt and sitemaps, forms listed not submitted; pages feed the app model
- Intruder (`intruder_run`, UI page, `proxymind intruder`): §-marked positions, sniper / battering ram / pitchfork / cluster bomb, payload lists, number ranges, brute forcer, null payloads, case variants and built-in lists, processing rules (prefix/suffix/replace/encode/hash), grep (text or regex), extract columns and reflection, background attacks with pause/resume/cancel, concurrency and throttle, anomalies against the baseline; one approval covers the whole attack (template, payloads, mode); at least intrusive, raised by any payload
- Payload-aware tiers: a pure classifier in `pm-policy` (destructive SQL, OS commands, file writes, bulk actions; undoes multi-level percent-encoding, JSON escapes, SQL comments) raises the tier of any send; approvals say why. Never lowers a tier
- DNS OAST: a minimal authoritative DNS responder (sans-I/O parser, golden tests) records `<token>.<domain>` lookups; payloads use `{{oast_dns}}`; `oast-server --dns --domain`
- XSS proofs (`reflection` oracle): the payload request carries a fresh token; the recorded response is rendered offline in headless Chromium (`pm-browser`, DevTools protocol over our own WebSocket codec) with every other request blocked; proven only when the script runs and returns the token (ADR-0011). VulnShop gained VS-6 (reflected XSS) and an HTML-encoding look-alike

- Race-condition testing (`race_send`, Repeater → Race): HTTP/2 single-packet attack (all final frames in one TCP packet) with last-byte sync for HTTP/1.1 servers; at least active-intrusive; responses grouped. VulnShop gained VS-5 (gift card race)
- Transparent (invisible) mode: origin-form HTTP routed by Host, TLS without CONNECT recognised by SNI; requests back to the proxy itself refused
- Proxy core: HTTP/1.1 and HTTP/2 (to browsers and servers, downgrading when a server lacks it; ADR-0009), CONNECT + TLS interception, byte-exact forwarding, history in a SQLite project file
- WebSocket message logging: frames decoded from a copy of the relayed bytes (fragmentation, masking, permessage-deflate), shown in the UI and to agents (`ws_messages`, redacted and tagged as untrusted); WebSocket replay on a new connection through the policy gate (`ws_send`, History → WebSocket tab); WebSocket intercept (hold, edit or drop messages both ways on connections opened while it's on; those open without compression so edits can't break the stream)
- Policy gate: ROE file, scope with bypass-resistant matching, dates and windows, tiers, rate limits, DNS-rebinding check, persistent single-use approvals, hash-chained audit log
- Agent interface: MCP server (39 tools), token-budgeted views, secret redaction with placeholders, untrusted-content tagging
- Identities with health checks and automatic re-login; replay as any identity; semantic diff with learned noise
- Authorization checks; app model (operations, objects, ownership) with suggested tests
- Hypothesis ledger and coverage map
- Proof engine (differential authz, timing, OAST) with re-runnable proofs; findings workflow; Markdown report
- VulnShop demo target, ground truth, `bench score`, demo script, and an end-to-end test where an agent finds and proves bugs purely over MCP

- REST API with live events, hardened for browsers; web UI (history, viewer, Repeater, approvals, identities and authz, model and coverage, findings and proofs, audit) built into the binary and tested in Chromium in CI (ADR-0008)
- Intercept-and-edit queue: hold requests and responses by scope, host, path and type; edit, forward or drop from the UI; edits and drops are audited, and the project keeps the server's original responses. Humans only: agents use Repeater through the policy gate
- Upstream proxy (HTTP CONNECT / absolute-form, SOCKS5 with optional remote DNS, login, bypass list) and client certificates per host (mutual TLS), shared live by proxy, Repeater, agents and proofs; policy address checks still apply
- Extra proxy listeners (more ports or interfaces, invisible clients, per-listener redirect with force TLS), hostname resolution overrides and TLS pass-through hosts
- Session handling: cookie jar, macros with variable extraction, rules per tool and host (jar cookies, set header/cookie/parameter, run a macro before each request or when logged out, then resend)
- Built-in assistant (`pm-assistant`): Anthropic and OpenAI-compatible APIs (Ollama, LM Studio, vLLM), local by default, cloud only with `allow_cloud_models`; acts as `agent:assistant` through the same MCP tools and policy gate; chats saved in the project; every model call audited; UI page and `proxymind assistant ask`
- Match-and-replace rules for first line, headers and bodies (literal or regex), in scope only by default, saved in the project, audited, live-reloaded by a running proxy

**Next, in order:**

1. **Desktop shell** (Tauri): done, linted on all OSes, installers in releases, project picker, CA trust helper; next: code signing
2. **Benchmarks on real apps** (M6): done for VAmPI and Juice Shop (baseline); next: run crAPI, score agents, publish scores in the README
3. **More oracles**: stored and DOM XSS proofs (reflection proofs, DNS OAST and payload-aware tiers are done)
4. Transparent project encryption (sealing is done), installers (signed releases, SBOMs and the Docker image are done)

## Team roles

- **A:** proxy and networking
- **B:** engine (model, identity, proof)
- **C:** UI, API, MCP, DevOps

## Milestones

| Milestone | Weeks | Work | Exit criteria |
|---|---|---|---|
| **M0 Foundations** | 1–2 | Repo, CI, licence, ADRs 0001–0007, RFC 0001, ROE schema, proxy spike | CI green; spike proxies HTTPS and records to SQLite ✅ |
| **M1 Proxy core** | 3–8 | A: HTTP/2 (ALPN), WebSocket frame logging, upstream/SOCKS proxy, connection pooling, client certs. B: FTS search, history filters. C: history REST API | Browse Juice Shop and crAPI with no breakage; byte-exact replay corpus; < 5 ms p50 overhead |
| **M2 Safety + manual tools** (policy gate ✅ done early) | 7–12 | B: `pm-policy` (scope, ROE, rate limits, tiers, approvals, hash-chained audit). C: Tauri UI (history, viewer, intercept, Repeater, scope), MCP v0. A: `pm-replay`, single-packet sends, parser fuzzing | Claude Code can search and replay over MCP; out-of-scope requests refused by test suite; `audit verify` passes |
| **M3 Identities + diff** | 11–16 | B: identities, login recipes, keep-alive, auth swap. A: semantic diff + noise mask. C: identities panel, authz matrix UI | Sessions stay alive 1 h unattended; matrix fills itself for 3 identities |
| **M4 App model + ledger** | 13–18 | B: endpoint templating, objects, ownership, params. A: object-swap testing. C: ledger, coverage map, MCP tools | ≥ 90% of crAPI endpoints templated correctly; coverage map shows untested areas |
| **M5 Proof engine** | 17–20 | B: differential-authz, OAST and timing oracles; findings workflow. A: OAST server. C: findings UI, proof re-run | Known crAPI IDOR/BOLA issues proven with 0 false proofs |
| **M6 AI layer + bench** | 19–22 | C: LLM views, redaction, untrusted tagging, full MCP toolset. B: benchmark harness and scoring. A: performance | An agent finds and proves known access-control bugs on crAPI and Juice Shop; results published |
| **M7 Release v0.1** | 22–24 | Hardening, docs, signed installers, Docker image, demo video | Quick start under 10 minutes; demo recorded |

## The v0.1 demo

> Browse crAPI as two users for 5 minutes. ProxyMind builds the app model and authorization matrix on its own. Connect Claude Code over MCP. Within minutes the agent reports **proven** broken-access-control findings, each with a one-click re-run, a coverage map of what was tested, and an audit log showing it never left scope.

## Component notes

### Proxy core (`pm-http`, `pm-tls`, `pm-proxy`)
Raw bytes preserved (ADR-0002). CA per install (ADR-0003). Race testing uses the HTTP/2 single-packet attack.

### Policy gate (`pm-policy`): built before any agent API
ROE file (`examples/roe.yaml`, `schemas/roe.schema.json`), action tiers, token-bucket rate limits per host and actor, approvals, blake3 hash-chained audit log, kill switch. Must resist scope-bypass tricks: encoded hosts, redirects, `Host` header mismatch, IP vs name, DNS rebinding.

### Multi-identity (`pm-identity`)
Identity = name, role, auth material, login recipe (recorded requests + extraction rules), health check. Keep-alive detects logout (401, login redirect, cleared cookie) and re-runs the recipe. `replay_as` swaps cookies, Authorization header and CSRF token.

### Semantic diff (`pm-diff`)
Send the same request twice to find noisy fields; structural JSON diff ignoring them; visible-text diff for HTML. Returns a similarity score and a short model-readable summary.

### App model (`pm-model`)
Path-segment classification (number, UUID, hex, slug) → templates → operations. Objects named from path segments and JSON keys. Ownership from creation or first appearance in a user's own listing. Incremental; user-correctable. Workflows and business rules come after v0.1.

### Authorization matrix
Operation × identity → `denied` / `allowed` / `leaks`. `leaks` (another user's data returned) goes to the proof engine. Object-swap testing uses the model's ownership data.

### Hypothesis ledger (`pm-ledger`)
Every test runs under a hypothesis (operation, param, vulnerability class, reason); every exchange sent is linked to it. Coverage = operation × param × class → untested / testing / refuted / confirmed.

### Proof engine (`pm-proof`)

| Oracle | Proves | How |
|---|---|---|
| `differential_authz` | IDOR, BOLA | owner vs attacker response similarity, owner-only marker present, anonymous request denied |
| `oast` | SSRF, blind injection, XXE | unique callback token received |
| `timing` | blind/time-based injection | ≥ 20 interleaved samples, Mann-Whitney U, p < 0.01 plus minimum effect size |
| `reflection` | XSS | headless browser renders the recorded response offline and confirms the payload ran |

Each proof stores inputs and a re-run recipe.

### AI layer (`pm-ai`) and MCP (`pm-mcp`)
Views with token budgets, secret redaction with placeholders, untrusted-content tagging, providers (Anthropic, OpenAI-compatible, Ollama). MCP tools listed in [RFC 0001](rfc/0001-service-api.md).

## Testing

- Unit and golden-file tests per crate; end-to-end proxy tests against local servers.
- `cargo-fuzz` on parsers (nightly CI).
- `h2spec` for HTTP/2.
- Scope-bypass test suite that must never pass.
- `bench/`: Juice Shop, crAPI, VAmPI, DVWA with ground-truth vulnerability lists; scored nightly on detection, false proofs, requests and model cost.

## Securing ProxyMind itself

API on `127.0.0.1` with a per-install token; CA key 0600 and never exported unless asked; project encryption (v0.2); `cargo deny` in CI; signed releases and SBOMs.

## Risks

| Risk | Mitigation |
|---|---|
| Raw parser edge cases | Fuzzing, golden files, real-traffic corpus |
| App model unreliable on messy apps | User corrections in UI; accuracy measured on bench |
| MFA / complex SSO breaks login recipes | v0.1: cookie/token import and simple forms; prompt for manual re-login |
| Burp AT adds similar features | Ship early; open source, local models and public benchmarks are hard for a closed product to match |
| Schedule pressure | Cut HTTP/2 polish, timing oracle and some UI before cutting proof or authz |
