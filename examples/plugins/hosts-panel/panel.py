"""A ProxyMind panel: requests per host.

ProxyMind writes one JSON line per recorded exchange to stdin and reads one
JSON object from stdout: {"title", "text", "columns", "rows"}. A column
named exchange_id becomes a link to that exchange.
"""
import json
import sys
from collections import defaultdict

hosts = defaultdict(lambda: {"requests": 0, "errors": 0, "example": None})
for line in sys.stdin:
    try:
        x = json.loads(line)
    except ValueError:
        continue
    h = hosts[f'{x["scheme"]}://{x["host"]}:{x["port"]}']
    h["requests"] += 1
    if (x.get("status") or 0) >= 400:
        h["errors"] += 1
    h["example"] = h["example"] or x["exchange_id"]

rows = sorted(([k, v["requests"], v["errors"], v["example"]] for k, v in hosts.items()), key=lambda r: -r[1])
print(json.dumps({
    "title": "Requests per host",
    "text": f"{sum(r[1] for r in rows)} requests to {len(rows)} hosts.",
    "columns": ["host", "requests", "4xx/5xx", "exchange_id"],
    "rows": rows,
}))
