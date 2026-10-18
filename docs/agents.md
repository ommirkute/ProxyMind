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
| `replay_send` | Send a request (new, resent or edited) through the policy gate |
| `identity_list` | Test identities and their session status (names only, never values) |
| `identity_capture` | Create an identity from the cookies/auth headers of a recorded request |
| `identity_check` | Check a session, logging in again automatically if a login recipe exists |
| `authz_check` | Re-send a recorded GET as other identities and anonymously; compare with the owner's response |
| `authz_results` | Latest authorization-check results |
| `approval_status` | Check whether a human approved a pending action |

Also available: the `proxymind://roe` resource and the `start_engagement` prompt.

## What the agent sees

- **Secrets are hidden.** Cookies, tokens, passwords and API keys appear as placeholders such as `{{secret:cookie_session_1}}`. The agent can use placeholders in requests; ProxyMind swaps the real values in when sending. Turn this off with `data.redact_before_llm: false` in the ROE.
- **Target content is marked as untrusted.** Response text is wrapped in `<untrusted_target_content>`, and phrases that look like prompt injection are listed in `possible_prompt_injection`.
- **Everything is audited.** `proxymind audit list` shows each action, its decision and why; `proxymind audit verify` proves the log wasn't edited.
