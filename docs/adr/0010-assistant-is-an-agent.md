# ADR-0010: The built-in assistant is an agent like any other

**Status:** Accepted

## Context
Many testers won't wire up an external agent. A built-in assistant lowers the bar, but a second, privileged path to the target would undo the policy gate (ADR-0005), and sending traffic to cloud models can break an engagement's data rules.

## Decision
- The assistant (`pm-assistant`) acts as `agent:assistant` and uses exactly the MCP tool set through `pm_mcp::call_tool`, so scope, tiers, approvals, rate limits, redaction, untrusted-content tagging and audit apply unchanged.
- Two wire formats cover the field: Anthropic Messages and OpenAI Chat Completions (also Ollama, LM Studio, vLLM). Calls go through ProxyMind's own sender (no extra HTTP client); cloud calls follow the project's network settings, local ones are direct.
- Local by default. A model server that isn't loopback, private or link-local counts as cloud and is refused unless the ROE sets `data.allow_cloud_models: true`; refusals are audited.
- API keys come from an environment variable named in the settings, never from the project file. Every model call is audited (provider, host, model, bytes sent; never content).
- Each message runs at most `max_steps` model calls. Chats are saved in the project.

## Consequences
- No new trust boundary: anything the assistant can do, an MCP agent could already do.
- No streaming yet: a long tool loop shows its result when it finishes.
- Tools that need approval pause the assistant's plan until the human approves and says to continue.
