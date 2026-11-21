# Integrations

ProxyMind can send a finding to **Jira**, **GitHub** or **GitLab** as an issue, and tell **Slack** or any **webhook**
when something happens (roadmap 3.5). Set them up on **Settings → Integrations**, or by API (`/api/v1/integrations`).
`proxymind integration list|test|send-finding` covers the rest from a terminal.

Integrations send data off your machine, so the design starts from what must not leave: your credentials, and the
target's secrets (session cookies, tokens, passwords). Read "Security" before you point one at a new place.

## What each kind does

| Kind | Does | Needs |
| --- | --- | --- |
| `jira` | Create or update an issue per finding (REST API v2) | server URL, project key, an API token + email (Jira Cloud) or a personal access token (Server, Data Center) |
| `github` | Create or update an issue per finding | `owner/repo`, a token; for GitHub Enterprise Server the API base (`https://ghe.example.com/api/v3`) |
| `gitlab` | Create or update an issue per finding | project id or `group/project`, a token; the server URL for self-managed GitLab |
| `slack` | Post a message for the events you pick | an incoming webhook URL |
| `webhook` | POST signed JSON for the events you pick | a URL; optionally a signing secret and custom headers |

### Token permissions (the least each needs)

- **Jira Cloud:** an API token for an account that may *Create issues* (and *Edit issues*, for updates) in the project.
  Enter the account's email in the Email field. **Jira Server / Data Center:** a personal access token of such an
  account, with the Email field empty (sent as a Bearer token).
- **GitHub:** a fine-grained token limited to the one repository with *Issues: read and write* (and *Metadata: read*,
  which is implied). A classic token needs `repo` (private) or `public_repo`. Labels are only applied when you list
  some; GitHub creates missing ones only for people with push access.
- **GitLab:** a project access token with the `api` scope and the Reporter role or above (Developer for labels).
- **Slack:** create an app with *Incoming Webhooks*, add one for the channel, and use its URL. The URL is the
  credential: it goes in the *Webhook URL* field and is never shown again.
- **Webhook:** none; your receiver decides.

## Secrets: where they live

The project file holds only the non-secret part of an integration (kind, URL, project, events, how each secret is
kept). Secrets are never in it, never returned by the API (you see `saved`/`environment` and, for long ones, the last
four characters), never in the audit log or delivery log, and never shown to agents.

A secret is one of:

- **Saved** in `<home>/integration-secrets.json` (mode 0600, written atomically, like `model-keys.json`). Each saved
  secret remembers the server it was saved for and is only ever sent there: change an integration's address and the
  saved token is dropped (enter it again), and a project file that rewrites the address cannot make it send your token
  elsewhere.
- **An environment reference**, `env:NAME` (for example `env:JIRA_TOKEN`), read when it is used. Use this in CI-like or
  shared setups.

The OS keychain is not used. We evaluated the `keyring` crate (MIT/Apache-2.0, fine for `deny.toml`): on Linux its
useful backend needs a running Secret Service (GNOME Keyring or KWallet over D-Bus), which headless machines,
containers and CI runners do not have, and the alternatives are not persistent. It would pull in a large,
platform-specific dependency tree for a feature that must fall back to a file in those cases anyway. The secret store is
one small module (`integrations.rs`: `integration_secret`, `secrets_write`), so a keychain backend can be added behind
it later; `env:NAME` already covers "outside the project file and outside ProxyMind's files".

## Create an issue from a finding

On **Findings**, select a finding and use **Create issue in…** (it lists your Jira, GitHub and GitLab integrations that
are on), or `proxymind integration send-finding <finding> <integration>`, or `POST /api/v1/findings/{id}/issue`.

What is sent (all of it redacted, see below):

| Field | Jira | GitHub | GitLab |
| --- | --- | --- | --- |
| Title | `summary`: `[High] <title>` | `title` | `title` |
| Body | `description` (wiki markup) | `body` (Markdown) | `description` (Markdown) |
| Labels | `labels` (only those you configured) | `labels` | `labels` (comma list) |
| Other | `project.key`, `issuetype.name` | | |

The body has: severity, status, ProxyMind finding id, issue class with CWE and OWASP categories (from the issue
library), the URL, the description, the proof summary (check, confidence, reasons), the **reproduction** (up to four
recorded requests, head and a short text body, as `http`), the remediation from the library, and the ids of the evidence
exchanges. No response bodies are sent.

The created issue's key and URL are stored on the finding (`issue_links`, migration 25) and shown on the Findings page.
Sending again is **refused** while an issue exists for that integration; with `update` (the button then says *Update
issue in…*) the same issue is updated (`PUT /rest/api/2/issue/{key}`, `PATCH /repos/{o}/{r}/issues/{n}`,
`PUT /projects/:id/issues/:iid`). Two sends of one finding to one integration cannot run at once. Issue creation is not
retried automatically (a POST that timed out may have worked); look at the tracker, then send again.

## Notifications (Slack and webhooks)

Pick events per integration:

| Event | When |
| --- | --- |
| `finding_proven` | a proof run proved a finding (once, until its status moves away from `proven`) |
| `finding_status_changed` | a finding's status changed to anything but `proven` (people set `confirmed`, `false_positive`, `reported`, `fixed`, `accepted_risk`; a retest can reopen) |
| `scan_finished` | a scan task ended: `done`, `failed` or `cancelled` |
| `ci_summary` | at the same time: counts of the project's findings by severity and status, and the ten most severe open ones |

They come from the event bus (no polling) and are sent by `proxymind ui` and the desktop app while they run. Each
integration has a rate limit (default 20 a minute, 1 to 60): the excess is skipped and logged as `skipped`. A send is
retried for connection errors, timeouts, `408`, `429` and `5xx` with a doubling wait (1 s, 2 s, 4 s, at most 4
attempts); `4xx`, redirects, certificate errors and refused destinations are final. The outcome of every send is in the
integration's **delivery log** (last 200) and the last failure shows on its card.

### Webhook payload (version 1)

`POST` with `Content-Type: application/json` and these headers:

| Header | Value |
| --- | --- |
| `X-ProxyMind-Event` | the event name |
| `X-ProxyMind-Delivery` | the delivery's unique id (same as `id` in the body) |
| `X-ProxyMind-Timestamp` | when it was made, RFC 3339 (same as `ts` in the body) |
| `X-ProxyMind-Signature` | `sha256=<hex>`: HMAC-SHA256 of the **exact body bytes** with your signing secret (only when a secret is set) |
| your custom headers | values are kept like secrets |

```json
{
  "v": 1,
  "id": "9f0c…",
  "ts": "2026-11-17T12:00:00Z",
  "event": "finding_proven",
  "engagement": "Acme Q4",
  "data": {
    "finding": {
      "id": 7, "title": "Any user can read any order", "severity": "high", "status": "proven",
      "vuln_class": "idor", "url": "https://app.test/api/orders/1001", "description": "…",
      "issue": { "id": "idor", "name": "…", "cwe": ["CWE-639"], "owasp": "A01:2021 Broken Access Control" },
      "proof": { "oracle": "differential_authz", "confidence": "high", "reasons": ["…"] },
      "exchange_ids": [12, 15],
      "issue_links": [{ "integration": "team-jira", "key": "SEC-12", "url": "https://…/browse/SEC-12" }]
    },
    "previous_status": "suspected"
  }
}
```

`data` has exactly one of `finding` (with `previous_status` for status changes), `scan`
(`task_id, url, state, pages_crawled, targets_done, targets_total, requests, issues, error`), `summary`
(`findings, proven, by_severity[{name,count}], by_status[{name,count}], top[{id,title,severity,status}]`) or `message`
(`event: "test"`). Version 1 only ever gains fields; a change that is not additive gets `"v": 2`. The machine-readable
schema is `pm_service::WebhookPayload` (JSON Schema via `schemars`). No request or response text is in event payloads.

**Verify it** in the receiver: recompute `HMAC-SHA256(secret, raw_body)`, compare in constant time, then reject a
delivery whose `ts` is older than a few minutes or whose `id` you have already seen (replay protection: the timestamp
and id are inside the signed body).

Slack gets `{"text": "...", "blocks": [...]}` with the same facts; target-derived text is escaped (`&`, `<`, `>`), so it
cannot make a mention or a link.

## Security

- **Redaction.** Every string that leaves (title, description, URL, proof reasons, request text) goes through the same
  redactor as agent views and reports shown to a model: cookie headers, `Set-Cookie`, `Authorization` and key headers,
  password/token/secret form and JSON fields, JWTs, and any secret value it has seen are replaced by
  `{{secret:name_n}}`. The integration's own secrets are scrubbed too. The redactor is pattern based (threat model F-6):
  a secret in an unnamed field or a URL path is not caught, so read the reproduction before you share a finding widely.
  Finding text is target content, so Markdown mentions (`@name`) and GitLab quick actions (`/close`) are defanged,
  evidence sits in code fences that cannot be closed from inside, Jira text goes in `{noformat}`.
- **Destinations (SSRF).** Integration requests are not target traffic: they are not in history and not checked against
  the rules of engagement. They go through ProxyMind's sender with your network settings, **TLS verification always
  on** (there is no insecure option), timeouts, and no redirects. A name that resolves to a private, loopback,
  shared (100.64/10) or unique-local address is refused unless *Allow private destinations* is on for that integration
  (an office Jira, a test receiver); link-local addresses (the cloud metadata service) are refused even then. Plain
  `http://` is only accepted for a private address you allowed; everything else needs `https://`. The check runs on the
  addresses actually connected to, so DNS rebinding does not help.
- **Project files (threat model F-2).** Whether an integration may send is decided in *your* home directory
  (`<home>/integration-trust.json`), not by the project. A project you open from someone else may name integrations,
  even as enabled; they send nothing, and Test and Send are refused, until you press *Turn on* here. Turning on trusts
  exactly what you saw: if the file later changes the address, project, events, private-destination flag or where a
  secret comes from, the integration is off again until you review it.
- **Who may do what.** Only people configure, enable, test and delete integrations, read the delivery log and send
  findings; the same calls by an agent, plugin, scanner or CI actor are refused and audited. Agents (MCP
  `integration_list`) can learn the **names and kinds** of integrations and whether each is on, nothing else: no
  address, project or secret, and there is deliberately no tool to send. A prompt-injected agent therefore cannot
  exfiltrate findings through an integration. Notifications are sent by the event loop as `scanner:integrations`, only
  for integrations a person turned on.
- **Audit.** Configuring (`integration_set`, `integration_enable`, `integration_delete`) records names, kinds, host,
  events and where secrets are kept, never values. Every send (`integration_send`) records the integration, event, host,
  HTTP status and attempts, never a body, header or secret.
- Responses from the server are read for the issue key only; an error shows at most 200 characters of the server's
  answer, with secrets scrubbed. A link the server returns is only kept if it is `http(s)`.

## Not done

- OS keychain storage (see above); a keychain backend is a small addition behind the secret store.
- Agents cannot send findings (a gated tool could be added with an approval, as for other sends).
- Updating a Jira issue's status or comments, closing the tracker issue when the finding is fixed, pulling status
  back from the tracker.
- Per-event Slack message customisation; SARIF/JUnit upload to a URL (CI mode covers it).
