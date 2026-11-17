# Writing plugins

A plugin is a folder with a `proxymind-plugin.yaml` and any program that speaks JSON lines. Plugins are installed per
user, never per project (`proxymind plugin add <folder>`), run in a sandbox (cleared environment, no network and
resource limits on Linux, see [ADR-0015](adr/0015-active-plugins-and-sandbox.md)), can be signed
([ADR-0016](adr/0016-signed-plugins-and-panels.md)), and stop running if a file changes after install.

| Kind | Manifest | What it does |
| --- | --- | --- |
| Passive check | `passive:` | Reads recorded exchanges (one JSON line each), reports issues. |
| Active check | `active:` | Proposes requests for one exchange; ProxyMind sends them through the policy gate and hands back the responses. |
| Panel | `panels:` | A view on the Plugins page, shown as text and a table. |
| Hook (API 2) | `hooks:` | Sees requests and responses in flight and may replace them. |

The first three are described in [ADR-0014](adr/0014-plugins.md) and [ADR-0015](adr/0015-active-plugins-and-sandbox.md);
the examples in [`examples/plugins`](../examples/plugins) show each. This page is the reference for plugin API 2
([ADR-0020](adr/0020-traffic-hooks-and-plugin-api-v2.md)).

## Manifest v2

```yaml
name: sign-request            # lowercase letters, digits, dashes
version: 0.1.0
description: Adds an X-Signature header.
api: 2                        # opts in; without it the manifest is version 1 and works as before
permissions: [hooks.request]  # what the plugin may do (below)
hooks:
  request:                    # and/or `response:`
    command: ["python3", "hook.py"]       # run in the plugin's folder, "./x" is relative to it
    match:                                # all optional; empty means everything in scope
      hosts: ["*.example.com"]            # `*` matches any run of characters; host name only
      paths: ["/api/"]                    # path prefixes (the path as recorded, with its query)
      methods: ["POST"]                   # for response hooks: the method of the request
      content_types: ["application/json"] # the message's own Content-Type; `text/*` works
    timeout_ms: 200           # per call; default 200, at most 2000
    on_error: pass            # pass (default): the original goes through | drop: block the message
```

Permissions (a fixed set; an unknown one is an install error):

| Permission | Allows |
| --- | --- |
| `hooks.request` | a `hooks.request` section |
| `hooks.response` | a `hooks.response` section |
| `checks.passive` | a `passive:` section |
| `checks.active` | an `active:` section |
| `panels` | `panels:` |
| `history.read` | panels being given recorded exchanges |

A v2 manifest that uses something it did not declare is refused at install, and `pm-service` refuses it again at run
time. `permissions:` and `hooks:` in a manifest without `api: 2` are an error.

### Review

The registry records the permission list a person accepted. A new v2 plugin is installed **off**; so is an update whose
permissions differ from what was accepted. A person accepts on the Plugins page (*Accept permissions and turn on*) or
with `proxymind plugin accept <name>`; that turns the plugin on. Hooks then need their own switch on the Plugins page
(*Traffic hooks*). Only people can accept permissions, turn plugins or hooks on, reorder, pause and resume them;
agents are refused, and every one of these is audited. A hook with `on_error: drop` is shown as blocking traffic when
it fails.

## Hooks

### Where hooks run

For a request: match-and-replace rules, then hooks in the order the person set, then the intercept queue (so a held
request shows what the hooks made of it). For a response: rules, then hooks, then the client gets it. Hooks only see
in-scope exchanges (by the rules of engagement) that match their `match`. With no hook on, the proxy does no extra
work. HTTP/1.1 and HTTP/2 are both covered.

### Protocol

ProxyMind starts one worker per (plugin, hook kind) on the first matching message and keeps it running. One JSON
object per line in each direction (UTF-8, `\n` ends a line). **Stdout is for answers only**; stderr is discarded.

ProxyMind to the hook:

```json
{"v":2,"id":7,"phase":"request","exchange":{"method":"POST","url":"https://a.example.com/api/x","scheme":"https","host":"a.example.com","port":443,"path":"/api/x"},"raw":"<base64>"}
```

`phase` is `request` or `response` (responses also have `exchange.status`). `raw` is the whole message as bytes on the
wire (HTTP/2 messages in ProxyMind's HTTP/2 text form, like History shows them).

The hook answers with the same `id`:

```json
{"id":7,"action":"pass"}
{"id":7,"action":"replace","raw":"<base64>","note":"added X-Signature"}
{"id":7,"action":"drop"}
```

- `pass`: forward the message unchanged.
- `replace`: forward `raw` **exactly as given**. ProxyMind does not recompute `Content-Length` or re-chunk; the
  replacement must be a message `pm-http` can parse (a request line or status line, headers, a blank line), else it
  counts as a failure. `note` (at most 200 characters) is recorded.
- `drop`: requests only. The client gets ProxyMind's 403. A response hook answering `drop` is a failure.

### Limits and failure

- **Deadline** `timeout_ms` per call (the first call to a fresh worker gets 500 ms more for startup).
- **Size**: messages over 8 MB are not given to hooks. Neither are server-sent events, responses declared over 8 MB,
  HTTP/1.1 responses that run until the connection closes, upgraded connections and WebSocket messages. The exchange
  records a `bypassed:` note instead.
- **In flight**: at most 4 calls per worker; when they are in flight the message bypasses the hook instead of waiting.
- **Failure is fail-open**: a timeout, crash, malformed answer or unparseable replacement forwards the original and
  adds a `failed:` note to the exchange. With `on_error: drop` the message is blocked instead (request: 403, response:
  502 from ProxyMind). After 5 failures within 60 seconds the hook is **paused** (visible on the Plugins page and in
  `GET /plugins`) until a person resumes it. A paused hook sees nothing.
- A hook that returns after its deadline is ignored (answers are matched by `id`). A worker with several unanswered
  calls is restarted.
- The worker runs with a cleared environment, in the plugin's folder, without network (Linux), with CPU, memory and file
  limits. Treat message contents as untrusted input.

### Recording

History keeps the request as the server got it and the response as the server sent it; when a hook (or a rule or the
intercept editor) changed a message, the browser's side is kept next to it (*Original request*, *Delivered response*)
with a diff. The Changes tab lists `{phase, by: "hook", name: "<plugin>/<kind>", note}`. A hook that was bypassed or
failed leaves an entry whose note starts with `bypassed:` or `failed:`; the row is not marked as edited.

### API

`GET /api/v1/plugins` lists plugins with `api`, `permissions`, `accepted_permissions`, `needs_review` and `hooks`
(state `off`, `on`, `paused` or `unavailable`, order, deadline, recent failures). `POST /plugins/{name}/accept` accepts
permissions; `PUT /plugins/{name}/hooks/{kind}` takes `{"action": "enable" | "disable" | "pause" | "resume" | "up" |
"down"}`. The `plugins` event topic (`plugins_changed`) says when to refetch.

## Python helper

`sdk/python/proxymind/plugin.py` (standard library only; a plugin runs without ProxyMind's package installed, so copy
this one file next to your hook, as `examples/plugins/sign-request` does):

```python
from proxymind_plugin import hook, serve, Replace, add_header

@hook("request")
def sign(call):                    # call.raw, call.body, call.method, call.url, call.host, call.path, call.status
    return Replace(add_header(call.raw, "X-Signature", "..."), note="signed")   # or None (pass), or DROP

serve()                            # reads frames from stdin until ProxyMind closes it
```

`add_header` and `set_header_bytes` change only the header block and leave every other byte alone. An exception in a
handler ends the process, which ProxyMind counts as a failure (it forwards the original).

## TypeScript helper

`@proxymind/client/plugin` (Node 18+, no dependencies):

```ts
import { serve, replace, addHeader, DROP } from "@proxymind/client/plugin";

serve({
  request: (call) => replace(addHeader(call.raw, "X-Signature", "..."), "signed"), // undefined passes
});
```

`call.raw` is a `Buffer`; `bodyOf` and `header` read a message. Handlers may be async.

## Example

[`examples/plugins/sign-request`](../examples/plugins/sign-request): adds `X-Signature`, the hex HMAC-SHA256 of the body
with a key from `signing.key` in the plugin folder, to POST, PUT and PATCH requests.
