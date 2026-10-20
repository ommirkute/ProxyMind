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
| `scan_issues` | Passive scan of recorded traffic (sends nothing): security headers, cookies, CORS, version disclosure, database errors, secrets, directory listings, plus installed passive-check plugins (`<plugin>/<check>`); grouped, most severe first. Leads to test, not findings |
| `openapi_import` | Import an OpenAPI 3 / Swagger 2 description (text or a recorded spec response): operations with example requests and auth; optionally send the GET examples so the model learns them |
| `decode` | Encode/decode locally (chains or a smart decode of JWT, URL, HTML, base64, hex, unicode layers); nothing is sent |
| `compare_exchanges` | Semantic response similarity and line diffs of two recorded exchanges |
| `sequencer_run` | Token randomness: re-send a token-issuing request and analyse the tokens (statistics only, never the tokens) |
| `crawl` | Discover pages from a URL: GET only, in scope only, skips links that log out or delete, reads robots.txt and sitemaps; pages feed history and the app model; forms are listed, never submitted |
| `intruder_run` | Fuzz a request: positions marked `§like this§`, payload sets (lists, number ranges, built-in lists), four attack modes; returns per-request status/length/time/grep/reflection and the anomalies. One approval covers the whole attack |
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
| `proof_run` / `proof_get` | Have ProxyMind verify a finding: `differential_authz`, `timing`, `oast` or `reflection` |
| `approval_status` | Check whether a human approved a pending action |

Also available: the `proxymind://roe` resource and the `start_engagement` prompt.

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

## What the agent sees

- **Secrets are hidden.** Cookies, tokens, passwords and API keys appear as placeholders such as `{{secret:cookie_session_1}}`. The agent can use placeholders in requests; ProxyMind swaps the real values in when sending. Turn this off with `data.redact_before_llm: false` in the ROE.
- **Target content is marked as untrusted.** Response text is wrapped in `<untrusted_target_content>`, and phrases that look like prompt injection are listed in `possible_prompt_injection`.
- **Everything is audited.** `proxymind audit list` shows each action, its decision and why; `proxymind audit verify` proves the log wasn't edited.
