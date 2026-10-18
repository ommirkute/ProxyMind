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

- Proxy core: HTTP/1.1, CONNECT + TLS interception, byte-exact forwarding, WebSocket pass-through, history in a SQLite project file
- Policy gate: ROE file, scope with bypass-resistant matching, dates and windows, tiers, rate limits, DNS-rebinding check, persistent single-use approvals, hash-chained audit log
- Agent interface: MCP server (22 tools), token-budgeted views, secret redaction with placeholders, untrusted-content tagging
- Identities with health checks and automatic re-login; replay as any identity; semantic diff with learned noise
- Authorization checks; app model (operations, objects, ownership) with suggested tests
- Hypothesis ledger and coverage map
- Proof engine (differential authz, timing, OAST) with re-runnable proofs; findings workflow; Markdown report
- VulnShop demo target, ground truth, `bench score`, demo script, and an end-to-end test where an agent finds and proves bugs purely over MCP

- REST API with live events, hardened for browsers; web UI (history, viewer, Repeater, approvals, identities and authz, model and coverage, findings and proofs, audit) built into the binary and tested in Chromium in CI (ADR-0008)

**Next, in order:**

1. **Proxy depth** (M1/M2): intercept-and-edit queue, HTTP/2, match-and-replace, WebSocket frame logging, upstream/SOCKS proxy, client certificates
2. **Desktop shell** (Tauri) around the web UI
3. **Benchmarks on real apps** (M6): crAPI, Juice Shop, VAmPI ground truth; nightly scores in the README
4. **Built-in AI assistant** in pm-ai (Anthropic, OpenAI-compatible, Ollama), honouring `allow_cloud_models`
5. **More oracles and payload awareness**: reflection proofs in a headless browser, DNS OAST, payload-aware tiers
6. Project encryption, signed releases, installers

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
Raw bytes preserved (ADR-0002). CA per install (ADR-0003). Next: HTTP/2, WebSocket frames, intercept queue, match-and-replace rules, upstream proxy, invisible mode, client certificates.

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
| `reflection` (later) | XSS | headless browser confirms execution |

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
