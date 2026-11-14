# Next session: status and plan

Written 2026-11-12, right after version 0.2.0 was merged to `main` (PR #21). Read `CLAUDE.md`, then
`docs/handoff.md` (architecture, crates, pitfalls), then this file. This file replaces the older plan; everything it
listed is done.

## 0. Owner decisions and the roadmap (2026-11-14)

- **Version stays 0.2.0** until the roadmap's Phase 4 gate. Don't bump it, tag or release; record changes under
  "Unreleased" in `CHANGELOG.md`.
- **Every feature stays open source**, team features included.
- **Signing certificates** (Apple, Windows) are bought once the app has all planned features; signing waits.
- The plan to follow is `docs/roadmap.md` (five phases with gates). Phase 0 is in progress; its table there has the
  status of each work package.

## 1. Where things stand

- `main` is at **0.2.0** and green on Linux CI. The **v0.2.0 release is not published yet**: the owner creates the
  tag and release in the GitHub UI (tag pushes from the cloud sandbox are refused). Publishing runs
  `.github/workflows/release.yml` (binaries for Linux, macOS and Windows, checksums, SBOM, Docker image).
- No open pull requests. No work in progress. The session branch equals `main`.
- Benchmarks without a model (`bench/README.md`): **VulnShop 35/38** (**12 proven** after the automatic prove step,
  up from 2), **VAmPI 8/8** (≥1 proven, prove step not re-measured — Docker Hub rate-limited this sandbox),
  **Juice Shop 9/9** (≥1 proven, same), **0 false positives** on VulnShop.
- `CHANGELOG.md` lists what 0.2.0 added since 0.1.0.

## 2. What ProxyMind does today (all working, all with tests)

Everything goes through one service layer (`pm-service`) and the policy gate (`pm-policy`, rules of engagement,
tiers, approvals, audit chain). The API (`pm-api`), MCP server (`pm-mcp`), CLI (`pm-cli`) and web UI (`ui/`) are thin
layers over it.

| Area | What works | Where |
|---|---|---|
| Proxy | HTTP/1.1, HTTP/2, WebSocket, TLS interception with a local CA, intercept and edit, match-and-replace rules, invisible mode, extra listeners, hostname overrides, TLS pass-through. Traffic is byte-exact (ADR-0002) | `pm-http`, `pm-tls`, `pm-proxy` |
| History | Query language, saved filters, full-text search, site map, WebSocket history, notes and highlights, HAR and cURL import and export, 100k-exchange scale | `pm-store`, `pm-service` |
| Replay and Fuzzer | Tabs and history, inspector, HTTP/2 pseudo-headers; background attacks, payload types and processing, grep extract, recursive grep | `pm-replay`, `pm-fuzz` |
| Sessions and identities | Cookie jar, macros, session rules, recorded logins, session-expiry detection and re-login | `pm-identity` |
| Authorization | Per-request checks as other identities, differential oracle, **authorization matrix** (role × endpoint grid: IDOR, BFLA, missing login; proven on request) | `pm-service/src/authz_matrix.rs`, `pm-diff` |
| App model | Operations with templates, parameters, statuses; OpenAPI and GraphQL import; **snapshots and "what changed since the last test"** | `pm-model`, `pm-service/src/changes.rs` |
| Discovery and crawl | Wordlist discovery with soft-404 fingerprints, hidden folders, API version siblings, pages that take a URL or file (also inside API folders), HTTP crawler, browser-driven crawl for JavaScript apps, JavaScript endpoint mining, hidden-parameter discovery | `pm-crawl`, `pm-browser`, `pm-service/src/discover.rs`, `auto.rs` |
| Scanner | Passive checks; active checks: SQL injection (error, boolean, time, out-of-band), command injection, SSTI, XSS (reflected, stored, DOM), path traversal, open redirect, XXE, SSRF, NoSQL/LDAP/XPath, CRLF, Host header, CORS, auth bypass, JWT, GraphQL, cache poisoning and deception, mass assignment, prototype pollution, OAuth, deserialization; with approval: request smuggling, file upload, races, ReDoS, cross-user writes. Profiles, saved tasks, pause and resume, schedules. Custom checks in YAML | `pm-scan`, `pm-service/src/scan*.rs` |
| Out-of-band | DNS, HTTP and SMTP listeners, payloads in Replay and Fuzzer, late callbacks counted | `pm-oast` |
| Proof engine | Oracles: differential authorization, reflection (XSS in headless Chromium), timing, out-of-band. Hypothesis ledger; findings linked to proofs | `pm-proof`, `pm-ledger` |
| Findings and reports | Issue library (CWE, OWASP), statuses, retest, duplicate merging; HTML, Markdown, PDF, JSON, SARIF; saved templates | `pm-service` |
| Evidence | **Signed evidence packs** with a coverage proof, checked offline by `proxymind verify`; **proven findings as CI regression tests** (`regress export|run`) | `pm-service/src/evidence.rs`, `regress.rs`, `pm-tools` |
| AI | Assistant (chat agent using the same tools), **AI scan** (recon to chained findings, attack graph, live steering, verifier, business-logic tests), cost meter and budget, prompt-injection guard, explain-and-fix, local-model presets, memory across engagements, verdict learning, triage, parallel workers, skills over MCP. API keys set in the UI and kept in the vault | `pm-ai`, `pm-assistant`, `pm-vault`, `pm-service/src/ai_scan.rs`, `attack_paths.rs`, `memory.rs` |
| Recon | Passive DNS records and Wayback history | `pm-tools`, `pm-service/src/recon.rs` |
| Tools | Decoder, Comparer, token analyzer (FIPS 140-2 tests), Organizer, global search | `pm-tools` |
| Plugins | Passive and active checks over a process protocol, sandbox, UI panels, WASM runtime, signed manifests | `pm-plugin` (ADR-0014 to 0016) |
| Shipping | Web UI embedded in the binary, Tauri desktop app with installers, Docker image, signed release workflow, SBOM, nightly fuzzing, opt-in update check, Python and TypeScript SDKs, sealed (encrypted) projects | `desktop/`, `sdk/`, `.github/workflows/` |

Known limits:

- The automatic **prove** step (3.2) now proves most VulnShop findings (12/38, up from 2). Remaining gaps: VAmPI and
  Juice Shop need re-measuring in CI (Docker Hub rate-limited this sandbox), and some classes still have no automatic
  oracle (header-based time SQLi, NoSQL operator, GraphQL-over-POST IDOR, XXE, host-header, stored/DOM XSS, and the
  token/cache/OAuth/deserialization classes). Pushing VulnShop from 12 toward 15+ means adding those.
- VulnShop still misses three planted bugs: VS-10 (SSTI on `/greet`, which nothing links to), VS-11 (reset codes
  that count up; the benchmark never visits the endpoint) and VS-5 (gift-card race that needs a code the app never
  shows).
- The AI scan has never been scored on the benchmarks (that needs a model API key).
- Pull-request CI runs on Linux only. macOS and Windows run on `main` and by hand.
- No team mode, no HTTP/3 or gRPC, no code signing for macOS and Windows, no auto-update.
- `docs/handoff.md` section 4 ("What's next") is out of date; this file is the plan. Sections 1, 2 and 5 are current.

## 3. Plan, in order

### 3.1 Publish 0.2.0 and check the release (owner plus a short session)

1. Owner: run CI by hand on `main` (Actions → CI → Run workflow) so macOS and Windows are covered.
2. Owner: create release `v0.2.0` on `main` in the GitHub UI, with the 0.2.0 section of `CHANGELOG.md` as notes.
3. Session: read the release workflow run with the GitHub tools; fix anything that fails in a PR. Check that the
   assets exist (five binaries, `SHA256SUMS`, SBOM, desktop installers) and that the update check
   (`pm-service/src/update.rs`) sees 0.2.0 as the newest release.

### 3.2 Prove more of what the scanner finds — **largely done** (2026-11-12)

Goal was: VulnShop proven from 2/38 to at least 15/38, no false proofs. **Delivered: VulnShop 2/38 → 12/38, 0 false
positives.** The automatic prove step is in `pm-service/src/prove_auto.rs` (`auto_prove`, `finding_prove`), runs at the
end of `bench auto` (skip with `--no-prove`), and is exposed as `proxymind findings prove [id]`,
`POST /api/v1/findings/{id}/prove` and `/findings/prove`, MCP `finding_prove`, and an Auto-prove button on the
Findings page (both SDKs too). New pure oracles live in `pm-proof` with unit tests: `boolean_injection`,
`sql_error` (error-based), `path_traversal`, `marker` (open redirect / CRLF / host); their sends are in
`pm-service/src/proof.rs`, gated like every other send, and link to findings with `link_proof`. Tests:
`crates/pm-service/tests/prove_auto.rs` (each oracle proves a real VulnShop bug and rejects its trap).

**Follow-ups to push past 12 toward 15+ (and to finish the measurement):**
- Re-measure VAmPI and Juice Shop in CI and fill `bench/README.md` (this sandbox was Docker-Hub rate-limited).
- Add oracles for the classes still suspected: header-based time SQLi (needs to add the insertion-point header to the
  request, e.g. User-Agent; VS-15), GraphQL-over-POST IDOR (VS-12) and stored/DOM XSS (VS-23/VS-25, render a
  different exchange). Done 2026-11-14 (roadmap Phase 0.2): template injection (`expression` oracle), NoSQL operator
  injection (boolean split with `$eq`/`$ne`), XXE (entity file read, or blind via OAST), CORS (`cors` marker kind)
  and Host-header injection (`host` marker in `X-Forwarded-Host`, `X-Host` or `Host`); VulnShop 15/38 proven; tests in `crates/pm-service/tests/prove_more.rs`
  against a purpose-built app with fixed versions and traps.
- Done 2026-11-13: every proof kind except out-of-band now exports as a CI regression test (9 of 9 proven findings
  in a VulnShop run, it was 4), the runner no longer calls a test "fixed" when the credentials stopped working or
  the server fails, and exported files never hold the recorded session. See the handoff's "Regression tests for CI".
- Done 2026-11-14: a test whose credential variable is not set is still `skipped`, but the run now exits 2 (a CI
  job that loses its secrets no longer goes green having tested nothing); `--allow-skipped` keeps exit 0 for local
  runs.

### 3.3 The last VulnShop misses, without fitting the scanner to VulnShop

- VS-11: when the model has a password-reset or code-issuing operation, request several codes for a test account
  and run the token analyzer on them (sequential or low-entropy codes are a finding). The benchmark must also visit
  the reset endpoint once (`bench/apps/vulnshop.sh`), as a tester would.
- VS-10: leave it unless a general signal appears (for example a page name found in JavaScript or in a sitemap). Do
  not add words like `greet` to the wordlist.
- VS-5: leave it; it needs a secret the app does not reveal.

### 3.4 Score the AI scan (needs a model API key from the owner)

- Add `bench/run.sh --agent` (or a new script) that runs `ai-scan` on each app with a budget, then scores with the
  same ground truth. Record found, proven, false positives, cost and time in `bench/README.md`.
- Ask for the key with the credential form; never put it in files or commits.
- Use the results to tune prompts, the verifier and the worker count.

### 3.5 Later, in this order

1. **Team mode**: a shared project server (`proxymind serve --team`), users and roles, per-user audit, assigning
   and commenting on findings. Write an ADR on sign-in first (OIDC or local accounts).
2. **Hosted out-of-band server**: a deployable `pm-oast` with per-project tokens and polling.
3. **Protocols**: HTTP/3, gRPC (with optional `.proto` upload), better WebSocket fuzzing.
4. **Shipping**: project encryption on by default, code signing for macOS and Windows (needs certificates from the
   owner), signed auto-update in the desktop app.
5. **Benchmarks**: verify the crAPI ground truth and add it to the table.

### 3.6 Small clean-ups worth doing early

- Rewrite `docs/handoff.md` section 4 to point here, and trim its "Status of the session" text.
- `the_baseline_discovers_imports_and_sweeps` (in `crates/pm-service/tests/discover.rs`) takes about 150 seconds;
  see if it can run on a smaller sweep.
- Add macOS and Windows jobs to pull-request CI only if Actions minutes allow (see the handoff).

## 4. How to work (rules that caused trouble before)

- **Branch and PRs**: develop on the branch the session assigns. The owner lets the session open PRs and merge them
  once CI is green. After a merge, restart the branch from `origin/main` and force-push with lease. The owner makes
  tags and releases.
- **Checks before every push** (CI runs the same):

  ```bash
  cargo fmt --all
  CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo clippy -q --all-targets -- -D warnings
  CARGO_INCREMENTAL=0 cargo test -q --no-fail-fast; echo "exit $?"   # read the exit code, not a grep of the output
  cd ui && npm run build && cd .. && cargo build && cd ui && npm run test:e2e && cd ..
  git checkout -q ui/tsconfig.tsbuildinfo
  ```

  Build the UI before `cargo build`: the binary embeds `ui/dist`.
- **Disk**: `target/` passes 20 GB and the disk fills up. Always set `CARGO_INCREMENTAL=0`; when space runs low,
  delete `target/`, old benchmark folders in the scratchpad and Docker images. Don't run a benchmark and a rebuild
  at the same time (the benchmark uses `target/debug/proxymind`).
- **Benchmarks**: `WORK=<scratch>/vs-$(date +%s) BENCH_NO_START=1 PROXYMIND=$PWD/target/debug/proxymind
  bench/run.sh vulnshop` (VulnShop starts itself). VAmPI and Juice Shop need `dockerd` running and
  `cd bench && docker compose up -d vampi juice-shop`. Each run takes 10 to 20 minutes; run them in the background.
  After a scanner change, run all three and compare every finding with the ground truth to count false positives.
- **Changing discovery or the sweep** changes request counts; `crates/pm-service/tests/discover.rs` asserts them.
- **Adding a feature**: pure logic in the lowest crate with unit tests → a gated `pm-service` method → MCP tool,
  API route, CLI command, UI → an integration test and an e2e step → docs (`README.md`, `docs/agents.md`,
  `docs/handoff.md`, `CHANGELOG.md` under a new "Unreleased" heading).
- **Version bumps**: every place is listed in `docs/releasing.md`.
- **Standing rules from the owner**: keep the word "Burp" out of the UI and code comments (factual comparisons in
  docs are fine) and never reverse-engineer it; no model names in commits, PRs or code; no secrets in commits;
  don't inspect or use the sandbox's proxy credentials; don't fit the scanner to VulnShop.
