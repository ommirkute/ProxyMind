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
- **Start of task 43** (recorded logins and session-expiry detection). The service code compiles and its unit tests pass, but it is not wired to any interface yet:
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

## 1. Finish task 43: recorded logins and session expiry (about half a session)

1. **Integration test**, new file `crates/pm-service/tests/login_record.rs`:
   - A small app:
     - `GET /login` sets a `pre` cookie and returns a hidden CSRF token.
     - `POST /login` needs `pre` and the CSRF token, then sets `sid` and returns `{"token":…}`.
     - `GET /api/me` needs `sid` and the bearer token. Without them it returns **200** with "Please sign in".
     - A switch on the app expires all sessions.
   - Insert recorded `proxy` exchanges with `store.insert_exchange`: login GET, login POST, a `.js` file, `/api/me`, and a post-login `POST /api/cart`.
   - Assert that the recipe has 2 steps (the cart POST is left out), a CSRF variable, and `set_headers` Authorization.
   - Assert that `identity_login` works against the live app.
   - Assert that `identity_learn_logged_out` finds "Please sign in" and sets `expect_contains`.
   - Expire the sessions, then check that `replay_send` as the identity logs in again by itself (count the logins).
2. **API** in `crates/pm-api/src/routes.rs`:
   - `GET /history/mark` → `{id}`.
   - `POST /identities/record-login {name, role?, from, to?}`.
   - `POST /identities/{name}/learn-logged-out`.
   - Add `logged_out` (bool) to `IdentityInfo`.
3. **CLI** in `crates/pm-cli/src/main.rs`, `IdentityAction`:
   - `record-login --name --from [--to] [--role]`.
   - `learn-logged-out --name`.
   - `mark`.
4. **MCP**: add `identity_learn_logged_out` only. Recording stays human-only because recipes hold passwords.
5. **UI**, Authz page, Identities panel:
   - A "Record login" card: name and role inputs, a **Start** button (saves the mark, offers "Open browser"), and a **Stop & save** button (calls record-login, then learn-logged-out when a health check exists).
   - Show the steps, the variables and the notes.
   - A "Learn logged-out look" button per identity, and a "logged-out signature" chip.
   - Add an e2e step that records a VulnShop login done through the browser (`PROXYMIND_BROWSER_HEADLESS=1`), or that drives the API directly.
6. **Scans**:
   - In `scan_task.rs`, count re-logins (notes from `send_as`) and show them in the task view.
   - If re-logins fail twice in a row, pause the task with a "session lost" status instead of scanning logged out.
7. **Bench**: in `bench/run.sh`, after capturing identities, run `identity learn-logged-out` for alice and bob (it is skipped when they have no health check).
8. **Docs**: a `handoff.md` section, plus updates to `plan.md` and `scanner-matrix.md` (session handling row).

## 2. Task 44: scan profiles, scheduling and resume (about one session)

- **Profiles**:
  - `ScanProfile{name, checks, max_requests, rate, insertion points, approval checks, browser}` stored as a project setting (`scan_profiles`).
  - Built-in profiles: `light` (passive + safe), `default`, `thorough` (all, including approval checks), `api-only`.
  - `ScanTaskRequest.profile` fills in any fields left empty.
- **Resume**:
  - Persist each scan task's plan and progress in pm-store with a new append-only migration `scan_tasks`: id, request JSON, a per-target done set, issues so far, status.
  - On start-up, tasks that were running come back as `paused`; `POST /scan/tasks/{id}/resume` skips targets already done.
  - Also add pause and cancel.
- **Scheduling**:
  - A `schedules` table: cron-like `every` (hourly, daily HH:MM, weekly), profile, scope or start URL.
  - A tokio ticker in `pm-service` starts tasks as the human who made the schedule, through the policy gate.
  - Desktop and `proxymind ui` run the ticker; the CLI gets `schedule add|list|rm`.
- **UI**: a Scans page under Dashboard with tasks (pause, resume, cancel), profiles (an editor) and schedules.
- **Tests**:
  - A resume after a simulated restart sends no duplicate requests.
  - A schedule fires once per period (use an injectable clock).

## 3. Task 45: issue library and report templates (about half a session)

- **Issue library** (`crates/pm-scan/src/library.rs`): one entry per issue type, with:
  - title, severity, confidence defaults, CWE, CAPEC, OWASP Top 10 2021 / API Top 10 2023 mapping;
  - background, impact, remediation, references.

  Write the text ourselves; do not copy Burp's issue text. `ScanIssue` and findings carry `issue_type`, and the report fills in from the library.
- **Report templates**:
  - Built-in: executive summary, technical detail, compliance mapping (OWASP).
  - Custom templates: a project setting holding a small template language. Prefer a vetted crate such as `minijinja` (check its license) to rolling our own.
  - Output HTML, Markdown and PDF (print HTML through the headless Chromium we already ship with pm-browser).
- **Finding workflow**: states (new, confirmed, false positive, fixed, accepted risk), a retest button that replays the proof, and dedupe across scans.
- **UI**: a library browser and a report builder (choose template, filters, preview).

## 4. Task 46: plugin platform (about one to two sessions)

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

- The Juice Shop browser crawl visited only about 6 pages before the hash-route fix. Re-run `bench/run.sh juice-shop` and record the page count and score. The last scores were VulnShop 24/38, VAmPI 3/8 and Juice Shop 4/9, with 0 false positives.
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
