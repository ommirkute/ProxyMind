"""The hook helpers speak ProxyMind's hook protocol (plugin API 2): one JSON line in, one JSON line out."""
import base64
import hashlib
import hmac
import io
import json
import os
import subprocess
import sys
import unittest

from proxymind.plugin import DROP, HookCall, Replace, add_header, b64decode, b64encode, serve, set_header_bytes

HERE = os.path.dirname(os.path.abspath(__file__))
REQ = b"POST /api/x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\nhi"


def frame(n: int, phase: str, raw: bytes, status=None) -> str:
    ex = {"method": "POST", "url": "http://a.test/api/x", "scheme": "http", "host": "a.test", "port": 80,
          "path": "/api/x"}
    if status:
        ex["status"] = status
    return json.dumps({"v": 2, "id": n, "phase": phase, "exchange": ex, "raw": b64encode(raw)}) + "\n"


def answers(handler_kwargs, frames):
    out = io.StringIO()
    serve(stdin=io.StringIO("".join(frames)), stdout=out, **handler_kwargs)
    return [json.loads(line) for line in out.getvalue().splitlines()]


class HookHelperTest(unittest.TestCase):
    def test_answers(self):
        def request(call):
            self.assertIsInstance(call, HookCall)
            self.assertEqual((call.method, call.host, call.path, call.body), ("POST", "a.test", "/api/x", b"hi"))
            self.assertEqual(call.header("content-length"), b"2")
            if call.header("X-Drop"):
                return DROP
            if call.header("X-Pass"):
                return None
            return Replace(add_header(call.raw, "X-Sig", "abc"), note="signed")

        got = answers({"request": request}, [frame(1, "request", REQ),
                                              frame(2, "request", add_header(REQ, "X-Drop", "1")),
                                              frame(3, "request", add_header(REQ, "X-Pass", "1")),
                                              frame(4, "response", b"HTTP/1.1 200 OK\r\n\r\n", status=200)])
        self.assertEqual([a["action"] for a in got], ["replace", "drop", "pass", "pass"])
        self.assertEqual([a["id"] for a in got], [1, 2, 3, 4])
        self.assertEqual(b64decode(got[0]["raw"]), b"POST /api/x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\nX-Sig: abc\r\n\r\nhi")
        self.assertEqual(got[0]["note"], "signed")

    def test_header_helpers_keep_other_bytes(self):
        self.assertEqual(add_header(REQ, "X-A", "1"), REQ.replace(b"\r\n\r\nhi", b"\r\nX-A: 1\r\n\r\nhi"))
        out = set_header_bytes(add_header(REQ, "x-a", "1"), "X-A", "2")
        self.assertEqual(out.count(b"X-A"), 1)
        self.assertTrue(out.endswith(b"X-A: 2\r\n\r\nhi"))
        self.assertEqual(add_header(b"no head end", "X", "1"), b"no head end")
        self.assertEqual(b64decode(b64encode(b"\x00\xff")), b"\x00\xff")


class SignRequestExampleTest(unittest.TestCase):
    EXAMPLE = os.path.join(HERE, "..", "..", "..", "examples", "plugins", "sign-request")

    def test_the_vendored_helper_matches_the_sdk(self):
        with open(os.path.join(HERE, "..", "proxymind", "plugin.py"), "rb") as a, \
                open(os.path.join(self.EXAMPLE, "proxymind_plugin.py"), "rb") as b:
            self.assertEqual(a.read(), b.read(), "copy sdk/python/proxymind/plugin.py into the example")

    def test_the_example_signs_the_body(self):
        key = open(os.path.join(self.EXAMPLE, "signing.key"), "rb").read().split(b"\n")[0].strip()
        p = subprocess.run([sys.executable, "hook.py"], cwd=self.EXAMPLE, input=frame(1, "request", REQ),
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stderr)
        a = json.loads(p.stdout)
        sig = hmac.new(key, b"hi", hashlib.sha256).hexdigest()
        self.assertEqual(b64decode(a["raw"]), add_header(REQ, "X-Signature", sig))


if __name__ == "__main__":
    unittest.main()
