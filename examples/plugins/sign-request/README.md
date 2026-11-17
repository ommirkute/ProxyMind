# sign-request

A traffic hook for ProxyMind (plugin API 2, [ADR-0020](../../../docs/adr/0020-traffic-hooks-and-plugin-api-v2.md)).
It adds an `X-Signature` header, the hex HMAC-SHA256 of the request body, to `POST`, `PUT` and `PATCH` requests that
go through the proxy. The key is the first line of `signing.key` in this folder.

```
proxymind plugin add examples/plugins/sign-request
proxymind plugin accept sign-request        # you read and accept the permission it asks for: hooks.request
proxymind ui                                # Plugins page: turn the request hook on
```

Only in-scope traffic reaches the hook (the rules of engagement decide). History keeps the request the browser sent
and the request the server got, and the exchange's Changes tab names `sign-request/request`.

`proxymind_plugin.py` is a copy of `sdk/python/proxymind/plugin.py` (a plugin runs without ProxyMind's Python package
installed); a test keeps the two identical. Editing any file after install stops the plugin until you install it
again (`proxymind plugin add`).
