#!/usr/bin/env python3
"""ProxyMind active-check plugin: hidden debug switches.

ProxyMind runs this twice with one JSON object on stdin:

  {"phase": "probe", "exchange": {...}}
      Write one line per request to send: {"raw": "<HTTP request>", "note": "..."}.
      ProxyMind sends them to the exchange's host through its policy gate.
  {"phase": "judge", "exchange": {...}, "results": [{...}, ...]}
      Each result has index, note, exchange_id, status, request and response
      (base64). Write issues: {"exchange_id": 1, "check": "...", "title": "...",
      "severity": "medium", "evidence": "..."}.

The plugin never touches the network itself (and can't, under the sandbox).
"""
import base64
import json
import sys

SWITCHES = ["debug=1", "debug=true", "test=1", "dev=1", "verbose=1", "internal=1", "admin=1", "trace=1"]
TELLING = [b"password", b"secret", b"internal", b"stack", b"trace", b"debug", b"token", b"redis://", b"postgres://"]


def split(raw: bytes):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    return lines[0], lines[1:], body


def body_of(b64):
    if not b64:
        return b""
    return base64.b64decode(b64).partition(b"\r\n\r\n")[2]


def status_of(b64):
    try:
        return int(base64.b64decode(b64).split(b" ", 2)[1])
    except Exception:
        return None


def probe(x):
    first, headers, _ = split(base64.b64decode(x["request"]))
    method, target, version = first.decode("latin-1").split(" ", 2)
    if method not in ("GET", "HEAD") or not target.startswith("/"):
        return
    keep = [h for h in headers if not h.lower().startswith((b"content-length:", b"transfer-encoding:"))]
    head = "\r\n".join(h.decode("latin-1") for h in keep)
    for s in SWITCHES:
        sep = "&" if "?" in target else "?"
        line = f"{method} {target}{sep}{s} {version}"
        print(json.dumps({"raw": f"{line}\r\n{head}\r\n\r\n", "note": f"adds {s}"}))


def judge(x, results):
    base = body_of(x.get("response"))
    base_status = status_of(x.get("response"))
    for r in results:
        body = body_of(r.get("response"))
        if not body or r.get("status") != base_status:
            continue
        new = [w.decode() for w in TELLING if w in body.lower() and w not in base.lower()]
        grew = len(body) > len(base) * 1.1 + 20
        if new and grew:
            print(json.dumps({
                "exchange_id": r["exchange_id"],
                "check": "debug_switch",
                "title": f"Hidden debug switch: {r['note'].removeprefix('adds ')}",
                "severity": "medium",
                "evidence": f"response grew {len(base)} -> {len(body)} bytes and now mentions: {', '.join(new)}",
            }))


def main():
    msg = json.loads(sys.stdin.readline())
    if msg["phase"] == "probe":
        probe(msg["exchange"])
    elif msg["phase"] == "judge":
        judge(msg["exchange"], msg["results"])


if __name__ == "__main__":
    main()
