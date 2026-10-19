#!/usr/bin/env python3
"""ProxyMind passive-check plugin: JWT weaknesses.

Protocol: one JSON object per line on stdin (an exchange: exchange_id,
scheme, host, port, method, path, status, request and response as base64);
write one JSON object per issue on stdout:
  {"exchange_id": 1, "check": "jwt_alg_none", "title": "...", "severity": "high", "evidence": "..."}
The plugin sends nothing over the network.
"""
import base64
import json
import re
import sys

JWT = re.compile(rb"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*")


def b64url(part):
    part = part + b"=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def issues(x):
    seen = set()
    req = base64.b64decode(x.get("request", ""))
    head = req.split(b"\r\n\r\n", 1)[0]
    for m in JWT.finditer(head):
        token = m.group(0)
        if token in seen:
            continue
        seen.add(token)
        try:
            header, claims = b64url(token.split(b".")[0]), b64url(token.split(b".")[1])
        except Exception:
            continue
        alg = str(header.get("alg", ""))
        short = token[:24].decode() + "…"
        if alg.lower() == "none":
            yield "jwt_alg_none", "JWT sent with alg none", "high", f"alg={alg} in {short}"
        elif alg.startswith("HS"):
            yield "jwt_hmac", "JWT signed with a shared secret (try cracking it)", "info", f"alg={alg} in {short}"
        if "exp" not in claims:
            yield "jwt_no_expiry", "JWT without an expiry", "low", f"no exp claim in {short}"


def main():
    for line in sys.stdin:
        try:
            x = json.loads(line)
        except ValueError:
            continue
        for check, title, severity, evidence in issues(x):
            print(json.dumps({"exchange_id": x["exchange_id"], "check": check, "title": title,
                              "severity": severity, "evidence": evidence}))


if __name__ == "__main__":
    main()
