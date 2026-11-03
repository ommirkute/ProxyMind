# Next session: implementation plan

Written 2026-10-24 at the end of a session. Read `docs/handoff.md` first, then this.

GitHub Actions minutes run out until **November 1**. Until then, run every local check before each push (list at the end).

## Where things stand

Done and pushed:

- Scanner steps 1 to 4b.
- UI redesign.
- Built-in browser (`ui --open-browser`, `POST /browser/open`).
- Browser-driven crawling (`crawl --browser`).

Pushed in the last commit:

- **SPA hash routes in browser crawls.**
  - `pm_crawl::Frontier::keeping_routes` keeps `#/…` and `#!/…` fragments as separate pages; plain anchors still collapse.
  - `pm-browser` `page_key` keeps route fragments when deciding whether a click left the page.
  - Unit tests for both.
- **Task 43** (recorded logins and session-expiry detection), now finished (see section 1):
  - `pm-identity`:
    - `LoginStep.extract` (`LoginExtract{name, regex}`) and `LoginStep.set_headers` (templates like `Bearer {{v1}}`).
    - `LoggedOut{statuses, location_contains, body_contains}` and `Identity.logged_out`.
    - `Identity::looks_logged_out`, `response_text`.
    - `LoginStep` and `Identity` now derive `Default`.
  - `pm-service/src/identity.rs`: `identity_login` runs multi-step recipes. It keeps a per-run cookie jar, sends those cookies to later steps, substitutes `{{vars}}` and applies `set_headers`. Old one-step recipes behave as before.
  - `pm-service/src/replay.rs`: `send_as` re-logs in when `ident.looks_logged_out(resp)`, so it uses the learned signature.
  - `pm-service/src/login_record.rs` (new):
    - `history_mark()` returns the newest exchange id.
    - `identity_record_login(actor, name, role, from, to)` reads the proxy exchanges in the window (in scope, no static files). It takes credentials from the last request that has them, then works backwards to find the steps that set those cookies or return those tokens, plus the steps they depend on. It turns values passed between steps into `{{vN}}` extractions, sets a health check from a later authenticated GET, and saves the identity. Humans only.
    - `identity_learn_logged_out(actor, name)` logs in and sends the health check with and without credentials. It keeps what tells the two answers apart: a redirect path, a 401/419/440 status, or a body marker. When the health check also passes while logged out, it adds `expect_contains`.

## 1. Task 43: recorded logins and session expiry — done

Finished on 2026-10-24: integration test (`crates/pm-service/tests/login_record.rs`), API, CLI, MCP (`identity_learn_logged_out`), the Authz page's "Record a login" card with an e2e step, and re-login counts plus a "session lost" stop in crawl-and-audit tasks. See the handoff section "Recorded logins and session expiry". Not done: `bench/run.sh` doesn't learn logged-out looks (its identities have no health checks); an option there is to record each user's login from the browse step.

## 2. Task 44: scan profiles, scheduling and resume — done

Finished on 2026-10-24: built-in and saved profiles, tasks saved in the project with pause/resume (including after a restart), hourly/daily/weekly schedules with a ticker in the UI server and desktop app, API/CLI/MCP, the Dashboard → Scans page and an e2e step. See the handoff section "Scan profiles, resume and schedules". Left for later: time zones other than UTC.

## 3. Task 45: issue library and report templates — done

Finished on 2026-10-24: a 48-entry issue library with CWE and OWASP mappings, findings filled in from it, duplicate merging, fixed / accepted-risk statuses, retest, executive / technical / compliance templates plus saved MiniJinja templates, HTML / Markdown / PDF output, API/CLI/MCP, and the UI report builder and Issue library page. See the handoff section "Issue library, finding workflow and report templates". Left for later: a Word (.docx) export; per-finding comments and assignment (belongs with team use).

## 4. Task 46: plugin platform — part 1 done (2026-11-03)

Done: active-check plugins through the gate, the sandbox (clean env; Linux: no network, resource limits), the Plugins page, API/CLI/MCP/SDK (see the handoff, ADR-0015). A Python helper (`proxymind.plugin`) exists. Still open from the list below: UI panels, a WASM runtime, signed manifests, a TypeScript helper.


- Plugins today are passive checks over a process protocol (`crates/pm-plugin`; see `docs/adr`). Extend the protocol:
  - `active_check`: a plugin returns probes, and the service sends them through the policy gate (tiers apply).
  - `on_request` / `on_response` hooks (like match-replace rules) that can only read, unless the ROE allows them to change requests.
  - UI panels: a plugin can declare a panel that the UI renders in a sandboxed iframe (`sandbox="allow-scripts"`, postMessage to a narrow API with no tokens).
- **Sandbox**:
  - Run plugin processes with no network (all traffic goes through the service), resource limits, and a timeout.
  - On Linux use seccomp/landlock where available; elsewhere fall back to process limits.
  - Or add a WASM runtime (`wasmtime`) for portable plugins, which would be the preferred long-term path; write an ADR first.
- **Manifest**: permissions (tiers, hosts, panels), version, signature (optional). Add install, enable and disable in the UI and CLI.
- **SDK**: plugin helpers in the Python and TypeScript SDKs, plus an example active check.

## 5. Second tier (later sessions, in order)

1. **Team use**: a shared project server mode (`proxymind serve --team`), users and roles, per-user audit, finding assignment and comments. Start with an ADR on auth (OIDC or local accounts).
2. **Hosted OAST**: a deployable `pm-oast` server (DNS + HTTP + SMTP) with per-project tokens and polling. Clients can use self-hosted or our hosted instance.
3. **Protocols**: HTTP/3 (quinn) proxying, gRPC (h2 + protobuf decoding with optional `.proto` upload), and better WebSocket fuzzing.
4. **Shipping**: transparent project encryption by default, code signing for macOS and Windows (needs certificates from the user), auto-update (Tauri updater, signed), and a release checklist run.
5. **Benchmarks**: crAPI ground truth (verify it), an agent-driven benchmark with scoring (needs a model API key), and tracking scores over time in `bench/README.md`.

## Small follow-ups noticed

- The Juice Shop browser crawl visited only about 6 pages before the hash-route fix. Re-run `bench/run.sh juice-shop` and record the page count and score. Scores on 2026-10-26: VulnShop 25/38, VAmPI 5/8, Juice Shop 9/9, 0 false positives (see bench/README.md).
- Chromium still makes two Google calls that we cannot block (documented in handoff).
- On November 1, re-run CI on the latest commit of the branch.

## Local checks before each push

```bash
cargo fmt --all
CARGO_INCREMENTAL=0 cargo clippy --all-targets -- -D warnings
cargo build && cargo test --no-fail-fast
cd ui && npm run build && cd .. && cargo build && cd ui && npm run test:e2e && cd ..
PROXYMIND=target/debug/proxymind python3 -m unittest discover -s sdk/python/tests
cd sdk/typescript && npm run build && PROXYMIND=../../target/debug/proxymind npm test && cd ../..
# desktop, only when its code changes:
cd desktop && cargo clippy --all-targets -- -D warnings && cd .. && rm -rf desktop/target
```
