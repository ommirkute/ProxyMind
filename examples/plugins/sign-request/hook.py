#!/usr/bin/env python3
"""ProxyMind request hook: adds `X-Signature: <hex HMAC-SHA256 of the body>` to each request it is given.

The key is the first line of `signing.key` in this folder (change it before real use). The hook runs in
ProxyMind's sandbox: no network, a clean environment, only this folder. Everything else in the request is left
exactly as it was.
"""
import hashlib
import hmac
import os

from proxymind_plugin import Replace, add_header, hook, serve

KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signing.key")
with open(KEY_FILE, "rb") as f:
    KEY = f.read().split(b"\n")[0].strip()


@hook("request")
def sign(call):
    if call.header("X-Signature") is not None:
        return None  # already signed
    signature = hmac.new(KEY, call.body, hashlib.sha256).hexdigest()
    return Replace(add_header(call.raw, "X-Signature", signature), note="added X-Signature")


serve()
