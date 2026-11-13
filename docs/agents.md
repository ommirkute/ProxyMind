# Using ProxyMind with AI agents

ProxyMind includes an MCP server, so any MCP client (Claude Code, Claude Desktop, Cursor, your own agent) can read recorded traffic and send requests, under the rules of engagement you set.

## 1. Record some traffic

```bash
proxymind proxy -p engagement.pmproj
# Browse the target through 127.0.0.1:8080 with the ProxyMind CA installed.
```

## 2. Set the rules of engagement

```bash
cp examples/roe.yaml roe.yaml   # edit scope, dates, windows, tiers
proxymind -p engagement.pmproj roe use roe.yaml
```

The ROE is stored in the project, so the proxy, the MCP server and your terminal all use the same rules.

## 3. Connect your agent

**Claude Code:**

```bash
claude mcp add proxymind -- proxymind -p /full/path/engagement.pmproj mcp --actor agent:claude
```

**Any MCP client** (`.mcp.json` or the client's settings):

```json
{
  "mcpServers": {
    "proxymind": {
      "command": "proxymind",
      "args": ["-p", "/full/path/engagement.pmproj", "mcp", "--actor", "agent:claude"]
    }
  }
}
```

`--actor` is how the agent appears in history and the audit log. Use a different name per agent if you run several.

## 4. Approve risky actions

By default agents may send GET/HEAD/OPTIONS requests on their own, need approval for other methods, and may not send DELETE. When an action needs approval, the agent is told to ask you. In another terminal:

```bash
proxymind -p engagement.pmproj approvals watch     # asks y/N for each new request
# or
proxymind -p engagement.pmproj approvals list
proxymind -p engagement.pmproj approvals approve apr_1a2b3c4d5e6f
```

Each approval covers exactly one action with exactly the parameters shown, and can be used once.

## Identities and authorization checks

Broken access control is the most common serious web bug, so ProxyMind makes testing it routine.

```bash
# Browse once as each user through the proxy, then capture their sessions from history:
proxymind identity capture alice --from 3        # exchange 3 was made as alice
proxymind identity capture bob --from 6
# Optional: keep sessions alive automatically
proxymind identity health alice --from 3 --expect-contains alice@example.com   # a GET that proves you're logged in
proxymind identity login alice --from 1                                         # the recorded login request
# Replay alice's request as bob and as an anonymous user:
proxymind authz check 4 --as bob
```

Verdicts: `denied`, `same_as_owner` (bob got alice's data: possible IDOR/BOLA), `allowed_different`, `inconclusive`. Timestamps, request IDs and other values that change on every response are learned and ignored, so the comparison is about meaning, not bytes. Agents can do the same with `identity_capture`, `authz_check` and `replay_send` with `identity`.

## Try it on the demo target

```bash
proxymind demo-target                 # VulnShop on http://127.0.0.1:8899 (deliberately vulnerable)
```

Users are `alice/alice123`, `bob/bob123` and `admin/admin123`. It contains planted bugs (IDOR, missing admin check, time-based SQL injection, SSRF) next to correctly protected endpoints, so you can see both true findings and correct denials.

## Tools

| Tool | What it does |
|---|---|
| `roe_get` | Scope, limits and the agent's permissions |
| `history_search` | Search recorded traffic (host, path, method, status, source, actor; paging) |
| `exchange_get` | One exchange as `summary`, `headers` or `full`, within a token budget |
| `exchange_raw_request` | Raw request text, ready to edit and resend |
| `ws_messages` | WebSocket messages of an upgraded exchange (who sent what), redacted and tagged as untrusted |
| `scan_active` | Active checks on one recorded request: SQL errors, unencoded reflection, open redirect, path traversal, template injection in every query/form/JSON/numeric-path value; leads with evidence and `prove_with` hints. One approval covers all probes |
| `plugin_list` | The user's plugins (passive and/or active, on or off) and what the plugin sandbox does on this machine |
| `plugin_check` | Run an active-check plugin on one recorded exchange: its proposed requests (that exchange's host only) go through the gate as one batch, at least intrusive, so you usually get `pending_approval` listing the exact requests; retry with `approval_id`. Returns the plugin's issues (leads) and the exchanges sent |
| `scan_issues` | Passive scan of recorded traffic (sends nothing): security headers, cookies, CORS, version disclosure, database errors, secrets, directory listings, plus installed passive-check plugins (`<plugin>/<check>`); grouped, most severe first. Leads to test, not findings |
| `openapi_import` | Import an OpenAPI 3 / Swagger 2 description (text or a recorded spec response): operations with example requests and auth; optionally send the GET examples so the model learns them |
| `history_grep` | Find text (or a regex) in recorded requests and responses with decoded bodies (a part such as `response_body` or `request_headers`, `invert`, `in_scope`); secrets are replaced before matching, snippets are untrusted |
| `ws_grep` | Find text in recorded WebSocket messages (direction, scope, inverted); snippets are untrusted |
| `engage_comments` / `engage_scripts` / `engage_js_endpoints` / `engage_analyze` / `engage_references` | Engagement tools over recorded traffic (send nothing): comments, scripts, endpoints the JavaScript mentions (new ones first), the target's URLs and parameters, what links to a page |
| `recon_dns` / `recon_wayback` | Passive recon for a host in scope (sends nothing to the target): DNS records with notes (SPF, DMARC, CAA, CNAMEs to services where a deleted resource can be claimed), and the URLs the Internet Archive captured, interesting ones first |
| `engage_logic` | Business-logic test candidates from recorded traffic (prices, quantities, discounts, limits, identities, roles, workflow state) with abuse cases, and flow-like URLs (sends nothing) |
| `traffic_triage` | Recorded requests worth testing, ranked, each with why and what to try (object ids, URL/file/command parameters, reflected input, JWTs, uploads, GraphQL, open APIs, admin paths, errors); sends nothing |
| `memory_save` / `memory_list` | Notes for later scans of a host in scope, and people's verdicts on findings there |
| `attack_path_record` / `attack_path_list` | Record a chain of findings and observations that leads to an impact (2 to 12 steps); shown as a graph and in the report |
| `engage_csrf_poc` / `engage_clickjacking` | A CSRF proof page for a recorded request; whether a page can be framed, with a test page |
| `collaborator_payload` / `collaborator_interactions` | Out-of-band payloads to place by hand, and the callbacks they caused (untrusted) |
| `organizer_add` / `organizer_list` / `organizer_update` | Keep exchanges aside with a status and a note, for people or agents to come back to |
| `site_map` | Recorded traffic as a tree per origin with counts, methods, statuses and in-scope flags |
| `graphql_import` | Read a GraphQL schema (introspection JSON, a recorded introspection response, or `fetch: true` through the gate) into queries, mutations and subscriptions with example documents, variables and requests for `replay_send` |
| `discover_content` | Forced browsing: GET common hidden paths (or your words, with extensions) under a folder, in scope only, skipping log-out/delete-looking paths; soft 404s are learned and filtered; one approval per run |
| `import_har` | Add the exchanges of a HAR file (text) to history as `source: import`; nothing is sent, bodies are rebuilt decoded |
| `curl_parse` | Read a curl command into a raw request and url for `replay_send`; nothing is sent, unsupported options come back as warnings |
| `decode` | Encode/decode locally (chains or a smart decode of JWT, URL, HTML, base64, hex, unicode layers); nothing is sent |
| `compare_exchanges` | Semantic response similarity and line diffs of two recorded exchanges |
| `token_analyzer_run` | Token randomness: re-send a token-issuing request and analyse the tokens (statistics only, never the tokens) |
| `crawl` | Discover pages from a URL: GET only, in scope only, skips links that log out or delete, reads robots.txt and sitemaps; pages feed history and the app model; forms are listed, never submitted |
| `fuzzer_run` | Fuzz a request: positions marked `§like this§`, payload sets (lists, number ranges, built-in lists), four attack modes; returns per-request status/length/time/grep/reflection and the anomalies. One approval covers the whole attack |
| `dom_test` | DOM XSS on a recorded page's own scripts, offline: which source (URL, fragment, window.name, postMessage, parameters, storage) reaches which sink, plus prototype pollution through the URL |
| `custom_checks` / `custom_scan` | List the project's YAML scan checks, and run them (or a check you write) on a recorded request; one approval covers the run |
| `replay_group` | Send 2–20 different requests to one server, in sequence (a multi-step flow) or at the same moment (a race across endpoints); one approval covers the group |
| `race_send` | Race-condition test: send copies of a request so they arrive together (HTTP/2 single-packet or last-byte sync); responses grouped |
| `ws_send` | Open a new WebSocket like a recorded one, send messages and get every message both ways (sending needs approval by default) |
| `replay_send` | Send a request (new, resent or edited) through the policy gate. Write `HTTP/2` in the request line to send it over HTTP/2 |
| `identity_list` | Test identities and their session status (names only, never values) |
| `identity_capture` | Create an identity from the cookies/auth headers of a recorded request |
| `identity_check` | Check a session, logging in again automatically if a login recipe exists |
| `authz_check` | Re-send a recorded GET as other identities and anonymously; compare with the owner's response |
| `authz_results` | Latest authorization-check results |
| `model_get` | The app model: operations (`GET /api/orders/{id}`), params, identities seen, objects and owners |
| `authz_candidates` | Suggested access-control tests: objects owned by one identity, to try as others |
| `hypothesis_create` / `hypothesis_update` / `hypothesis_list` | The shared ledger of what is being tested and what was ruled out |
| `coverage` | Each operation × relevant vulnerability class, untested and high-priority first |
| `finding_create` / `finding_update` / `finding_list` | Record findings with evidence; agents can't mark them proven or confirmed |
| `finding_prove` | Pick the oracle that fits a finding's class and prove it: boolean/time-based (SQLi), out-of-band (SSRF), the browser (XSS), two-file reads (path traversal), a fresh marker (open redirect/CRLF), the differential oracle (IDOR/BFLA) |
| `proof_run` / `proof_get` | Have ProxyMind verify a finding: `differential_authz`, `timing`, `oast`, `reflection`, `sql_error`, `boolean_injection`, `path_traversal` or `marker` |
| `approval_status` | Check whether a human approved a pending action |

Also available: the `proxymind://roe` resource and the `start_engagement` prompt.

## AI scan (an agent on its own)

The **AI scan** page (or `proxymind ai-scan start`) runs the model set on the Assistant page through a whole assessment: recon, scanning, exploitation to proof of concept, chaining findings into attack paths, and a Markdown report. It acts as `agent:ai-scan-<n>`, so the rules of engagement apply as to any agent: out-of-scope requests are refused, destructive steps wait in Approvals, and every action is audited.

- **Model:** any model the assistant supports. Cloud models (Anthropic, OpenAI) need `data.allow_cloud_models: true` in the rules of engagement and an API key: save it on the Assistant page (or set the environment variable it names).
- **Budget:** model calls (default 150), minutes (default 60) and, optionally, dollars: set your provider's prices (USD per million input and output tokens) in the assistant settings and a "max USD" on the scan. The page shows tokens used and the cost so far; older tool results are shortened so long runs fit the model's context. Stop it from the page or with `proxymind ai-scan stop <n>`.
- **Progress:** the page shows the phase, an activity log (tool calls, loopbacks, approvals waited on) and the findings; `proxymind ai-scan status <n>` does the same in a terminal.
- **Steer it:** type a message on the page while it runs ("focus on checkout", "skip /admin", "why did you try that?"), or `proxymind ai-scan say <n> "…"`. The agent reads it with its next step and still can't step outside the rules of engagement.
- **Attack paths:** in the chaining phase the agent records each chain with `attack_path_record` (steps linked to findings and exchanges). The page draws them as a graph; any agent can record them, and they're a section of the project report. `proxymind ai-scan paths <n>` prints them.
- **Verification:** when a scan ends normally, ProxyMind retests every finding its agent created (its proof, or its scanner check) and appends the result to the report, so a finding that no longer reproduces is marked before you read it.
- **Prompt-injection guard:** every tool result is checked for target text that tries to instruct the model ("ignore previous instructions", fake system turns, "AI agents must…"). When some is found, a warning goes in front of the result, the activity log shows it and the audit log records it. This applies to the assistant's chats too.
- **Memory across scans:** agents save notes about a host with `memory_save` (a login that works, endpoints worth revisiting, dead ends, techniques). The next AI scan of that host starts from them and from your verdicts on earlier findings there; findings you marked false positive aren't reported again without new evidence, and `finding_create` warns when a new finding matches one you rejected. The AI scan page lists the notes (delete any you don't want kept); `proxymind ai-scan memory [host]` prints them.
- **Worker agents:** after recon the lead agent can hand focused, independent tasks to up to 3 workers at once (8 per scan) with `ai_scan_delegate`. They act as `agent:ai-scan-<n>-w<k>` under the same rules, record their own findings (counted and verified with the scan's), share its cost budget and stop when it stops. A cheaper "worker model" can be set on the Assistant page.
- **Where to start:** `traffic_triage` (Engagement tools → "Worth testing") ranks recorded requests by what makes them worth testing, with what to try.
 the agent runs `engage_logic` (parameters that look like prices, quantities, coupons, limits, roles or workflow state, with abuse cases) and follows the `business_logic` skill. Engagement tools → "Logic tests" shows you the same list.
- **Report:** download it as Markdown or `proxymind ai-scan report <n> --out report.md`.
- **The prompt:** see it on the page or with `proxymind ai-scan prompt`. Replace it with `~/.proxymind/ai-scan-prompt.md` (keep `{{target}}`, `{{scope}}` and `{{focus}}`). Limits never come from the prompt: they're enforced by ProxyMind.
- **Not covered:** port scanning, subdomain enumeration, search-engine dorking, TLS cipher scans and source-code scanning aren't ProxyMind tools; the agent lists them in the report for a person to run.

## Skills (testing playbooks)

ProxyMind ships playbooks an agent can follow, as MCP prompts (your client's prompt or slash-command menu) and as the `skills_list` / `skill_get` tools: `idor_sweep`, `triage_findings`, `ssrf_hunt`, `js_recon`, `auth_review`, `jwt_audit`, `race_conditions`, `file_upload` and `business_logic`. Each takes an optional `focus` ("the /api/orders endpoints"). They only describe steps with ProxyMind's tools, so everything still goes through the rules of engagement; the ones that change data say to ask first.

Add your own as `~/.proxymind/skills/<name>.md` (a file with a built-in's name replaces it):

```markdown
---
name: checkout_review
title: Checkout review
description: Price, quantity and coupon tampering in the checkout flow.
args: focus
---
Goal: … {{focus}}
1. …
```

`proxymind skills` lists them and `proxymind skills <name> --focus "…"` prints one; the Assistant page has a Playbook picker.

## Proofs: "no proof, no finding"

A finding only becomes **proven** when ProxyMind checks it itself:

| Oracle | Proves | Proven when |
|---|---|---|
| `differential_authz` | IDOR/BOLA, missing role checks | the owner's request works twice, an anonymous request is refused, and a different, not more privileged identity gets the same data (noise ignored; owner details such as emails raise confidence) |
| `timing` | time-based injection | payload responses are slower than interleaved baseline responses with p < 0.01 (Mann-Whitney U) *and* by at least `min_effect_ms` |
| `oast` | SSRF, blind injection | the target calls back with a unique token: an HTTP request to `{{oast}}`, or a DNS lookup of `{{oast_dns}}` (`<token>.<your domain>`). Run `proxymind oast-server` (add `--dns 0.0.0.0:53 --domain oast.example.com` and an NS record delegating that domain to it for DNS), or start the MCP server with `--oast-listen 127.0.0.1:8085` (use a public URL the target can reach) |
| `reflection` | reflected XSS | a headless browser rendering the **recorded** response runs the payload and hands back a fresh token (through `pmProof()` or a dialog). Put `{{xss_url}}` (percent-encoded default payload), `{{xss}}` (unencoded) or `{{token}}` (inside your own payload, e.g. `<svg onload=alert('{{token}}')>`) in `raw`. Rendering is offline: the page's other requests are all blocked, and the response's own CSP applies. Needs Chromium or Chrome (found automatically, or set `PROXYMIND_CHROMIUM`; `proxymind proof browser` shows which one is used) |

Proofs keep their inputs, so `proxymind proof rerun <id>` repeats one during a retest. Payload oracles (`timing`, `oast`, `reflection`) count as intrusive, so agents need approval by default.

**Tiers follow the payload, not just the method.** A GET whose query or body carries destructive SQL (`DROP TABLE`, `DELETE FROM`, `INTO OUTFILE`), destructive OS commands (`rm -rf`, `shutdown`) or a delete mutation is *destructive* (refused for agents by default); command-injection probes, SQL writes and bulk actions are *intrusive*. Encoding tricks (double percent-encoding, comments, JSON escapes) are undone first. The approval request says what was found.

## Evidence packs and coverage proof

**Evidence & coverage** (under the Dashboard group) or `proxymind evidence --out pack.zip` builds one ZIP for the client:

- `report.html` and `report.md`;
- the exact request and response bytes behind every finding, proof and attack path (`--all` adds all in-scope traffic, up to 5000 exchanges);
- `findings.json`, `proofs.json`, `attack_paths.json`, `coverage.json`;
- the hash-chained audit log (`audit.jsonl`) and the rules of engagement (`roe.yaml`);
- `manifest.json`, which lists every file's SHA-256 and every recorded exchange, signed (`manifest.sig`) with this installation's Ed25519 key (kept in your ProxyMind folder, readable only by you).

Send the client your key's fingerprint separately (it is shown on the page). They check the pack with `proxymind verify pack.zip` or the page's upload box, without needing your project:

| Check | What it means |
|---|---|
| signature | The manifest is signed by the key with that fingerprint, and wasn't changed since. |
| files | Every file matches its hash in the manifest; nothing is missing or added. |
| audit log | The audit chain is intact and is the one the manifest names. |
| scope | Every request ProxyMind's tools sent (scanner, Replay, agents, proofs) and every allowed action was inside `roe.yaml`. Out-of-scope pages the tester's own browser visited through the proxy are counted separately. If the rules changed during the engagement, the check says so. |
| evidence | Each finding's evidence exchanges are in the pack. |

What it doesn't prove: that the signer was honest before signing. It proves the pack is unchanged and consistent with itself, and tells the client whose key signed it.

The **coverage proof** (`proxymind coverage --all`, the same page, MCP `coverage`) lists every operation in the app model against the vulnerability classes that apply to it, marked vulnerable, tested, open or untested, with who tested each and how: scanner checks (only the checks that actually ran), authorization checks, proofs and hypotheses. Untested cells come first.

## Regression tests for CI

Every proven finding can become a small test that the development team runs in CI until it is fixed: **Evidence & coverage → Regression tests** or `proxymind regress export --out tests.zip`. The ZIP holds one JSON file per finding, a README and an example GitHub Actions workflow.

```bash
export PM_AUTH_BOB="Cookie: session=…"        # credentials, from CI secrets
proxymind regress run tests/ --target https://staging.example.com --junit results.xml
```

- **What becomes a test:** findings proven by differential authorization (another user's request still returns the owner's data), reflection (a fresh payload still comes back unencoded), timing (the delay payload is still slower than the baseline), error-based or boolean SQL injection, path traversal, and a marker (open redirect, header injection): those four re-send the proof's own requests and judge the answers as the proof did. Out-of-band proofs need a callback server, and unproven findings have nothing to re-check; the export lists them with the reason.
- **Results:** each test reports still vulnerable, fixed, skipped (e.g. a credential variable isn't set) or error. The exit code is 1 if any finding is still there or a test errored. `--junit` writes a report for CI dashboards, `--json` prints the results.
- **Fixed means fixed:** a test that can't tell is an error, never "fixed". That covers credentials the app no longer accepts (an expired token answers 401, or a redirect to the login page, whatever the bug) and a server that fails (5xx). When the identity has a health check, the test carries it and sends it before calling anything fixed, for apps that answer an expired session with 403 or an ordinary page.
- **Safety:** credentials never go in the files (`{{auth:NAME}}` lines are filled from `PM_AUTH_NAME`): that holds for the session a request was recorded with too, which becomes its identity's placeholder (or `{{auth:session}}` when no saved identity owns it). Delete the line from a test whose page needs no login. The runner needs no project and sends only to `--target` (or the origin each test was recorded on). `--insecure` accepts self-signed test certificates. Only run tests against systems you are allowed to test.

## Authorization matrix

**Identities & Authz → Authorization matrix**, `proxymind authz matrix [--prove]` or MCP `authz_matrix` replays every readable (GET/HEAD) operation in the app model as every identity and anonymously, and shows a role × endpoint grid: owner, same data, own data, denied. A cell where someone else gets the owner's data is flagged:

- **idor**: another user reads the owner's object (`/api/orders/{id}`);
- **bfla**: a lower role gets what a privileged role (admin, staff, support…) gets, or a normal user reads an `/admin` path;
- **no_auth**: the operation answers with the same data without credentials.

With `prove`, each flag is proven with the differential oracle, and proven ones become findings linked to their proof. Requests that change state are skipped (test them with `replay_send` per identity), and so are logout links. Every request goes through the rules of engagement.

## What changed since the last test

At the end of a test, save a snapshot of the app model: **Model → Changes since the last test**, or `proxymind changes --save "Q3 test"`. Next time, compare with it (`proxymind changes`, the same panel, or MCP `model_changes`) to get new, removed and changed operations (parameters added or gone, new statuses, credentials now sent or not) and a retest list that names earlier findings on changed or removed endpoints. `proxymind changes --since last-year.pmproj` compares with another project instead. Operations are matched by method and path template, so a staging snapshot compares with production.

## What the agent sees

- **Secrets are hidden.** Cookies, tokens, passwords and API keys appear as placeholders such as `{{secret:cookie_session_1}}`. The agent can use placeholders in requests; ProxyMind swaps the real values in when sending. Turn this off with `data.redact_before_llm: false` in the ROE.
- **Target content is marked as untrusted.** Response text is wrapped in `<untrusted_target_content>`, and phrases that look like prompt injection are listed in `possible_prompt_injection`.
- **Everything is audited.** `proxymind audit list` shows each action, its decision and why; `proxymind audit verify` proves the log wasn't edited.
