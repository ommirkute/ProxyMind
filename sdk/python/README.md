# proxymind (Python)

A small, dependency-free client for the [ProxyMind](https://github.com/ommirkute/proxymind) REST API. Apache-2.0 (the ProxyMind core is AGPL-3.0; this SDK isn't, so you can use it in any integration).

```bash
pip install ./sdk/python
proxymind ui            # in another terminal: starts the proxy, UI and API
```

```python
from proxymind import Client, PendingApproval

pm = Client()   # http://127.0.0.1:7777; token from PROXYMIND_TOKEN or ~/.proxymind/api-token

for ex in pm.history(path="/api/orders", limit=20):
    print(ex["id"], ex["method"], ex["path"], ex.get("status"))

try:
    r = pm.replay(exchange_id=42, identity="bob")
except PendingApproval as p:
    print("waiting for a human:", p.summary)
    pm.wait_for_approval(p.approval_id)

leads = pm.scan_active(exchange_id=42)["issues"]
print(pm.report("sarif"))
```

Everything goes through ProxyMind's policy gate and audit log. The API acts as the person who started `proxymind ui`; for an autonomous agent, use the MCP server (`proxymind mcp --actor agent:<name>`) so it gets an agent's limits.

Run the tests (they start a real `proxymind` and VulnShop): `PROXYMIND=../../target/debug/proxymind python3 -m unittest discover -s tests`.
