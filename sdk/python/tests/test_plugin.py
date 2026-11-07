"""The plugin helper speaks ProxyMind's plugin protocol (no server needed)."""
import base64
import io
import json
import unittest

from proxymind.plugin import Issue, run, set_header, with_query


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


REQ = b"GET /api/products?x=1 HTTP/1.1\r\nHost: shop\r\nCookie: s=1\r\n\r\n"
EXCHANGE = {"exchange_id": 7, "method": "GET", "host": "shop", "path": "/api/products?x=1", "status": 200,
            "request": b64(REQ), "response": b64(b"HTTP/1.1 200 OK\r\n\r\n{}")}


class PluginHelperTest(unittest.TestCase):
    def test_rewrites(self):
        self.assertTrue(with_query(REQ, "debug=1").startswith("GET /api/products?x=1&debug=1 HTTP/1.1\r\nHost: shop"))
        self.assertIn("\r\nX-Test: a\r\n\r\n", set_header(REQ, "X-Test", "a"))
        self.assertEqual(set_header(REQ, "cookie", "s=2").count("ookie:"), 1)

    def test_phases(self):
        out = io.StringIO()
        run(probe=lambda x: [(with_query(x.request, "debug=1"), "debug")],
            stdin=io.StringIO(json.dumps({"phase": "probe", "exchange": EXCHANGE}) + "\n"), stdout=out)
        probe = json.loads(out.getvalue())
        self.assertEqual(probe["note"], "debug")
        self.assertIn("?x=1&debug=1 ", probe["raw"])

        result = {"index": 0, "note": "debug", "exchange_id": 9, "status": 200, "elapsed_ms": 3,
                  "request": b64(REQ), "response": b64(b"HTTP/1.1 200 OK\r\n\r\n{\"password\":1}")}
        out = io.StringIO()
        run(judge=lambda x, rs: [Issue(r.exchange_id, "leak", "Leak", "high") for r in rs if b"password" in r.body],
            stdin=io.StringIO(json.dumps({"phase": "judge", "exchange": EXCHANGE, "results": [result]}) + "\n"),
            stdout=out)
        self.assertEqual(json.loads(out.getvalue()), {"exchange_id": 9, "check": "leak", "title": "Leak",
                                                       "severity": "high", "evidence": ""})

        out = io.StringIO()
        run(passive=lambda x: [Issue(x.exchange_id, "seen", "Seen")], stdin=io.StringIO(json.dumps(EXCHANGE) + "\n"),
            stdout=out)
        self.assertEqual(json.loads(out.getvalue())["exchange_id"], 7)


if __name__ == "__main__":
    unittest.main()
