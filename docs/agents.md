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

## Tools

| Tool | What it does |
|---|---|
| `roe_get` | Scope, limits and the agent's permissions |
| `history_search` | Search recorded traffic (host, path, method, status, source, actor; paging) |
| `exchange_get` | One exchange as `summary`, `headers` or `full`, within a token budget |
| `exchange_raw_request` | Raw request text, ready to edit and resend |
| `replay_send` | Send a request (new, resent or edited) through the policy gate |
| `approval_status` | Check whether a human approved a pending action |

Also available: the `proxymind://roe` resource and the `start_engagement` prompt.

## What the agent sees

- **Secrets are hidden.** Cookies, tokens, passwords and API keys appear as placeholders such as `{{secret:cookie_session_1}}`. The agent can use placeholders in requests; ProxyMind swaps the real values in when sending. Turn this off with `data.redact_before_llm: false` in the ROE.
- **Target content is marked as untrusted.** Response text is wrapped in `<untrusted_target_content>`, and phrases that look like prompt injection are listed in `possible_prompt_injection`.
- **Everything is audited.** `proxymind audit list` shows each action, its decision and why; `proxymind audit verify` proves the log wasn't edited.
