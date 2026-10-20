"""Integration tests: a real `proxymind ui` and VulnShop on loopback.

Set PROXYMIND to the binary (default: ../../target/debug/proxymind)."""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from proxymind import ApiError, Client, Denied, PendingApproval  # noqa: E402

BIN = os.environ.get("PROXYMIND") or str(Path(__file__).resolve().parents[3] / "target" / "debug" / "proxymind")


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"nothing on port {port}")


@unittest.skipUnless(os.path.exists(BIN), f"no proxymind binary at {BIN}")
class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        home, project = os.path.join(cls.dir, "home"), os.path.join(cls.dir, "p.pmproj")
        cls.shop, ui = free_port(), free_port()
        base = [BIN, "-p", project, "--home", home]
        cls.procs = [subprocess.Popen(base + ["demo-target", "--listen", f"127.0.0.1:{cls.shop}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)]
        roe = os.path.join(cls.dir, "roe.yaml")
        Path(roe).write_text(f'version: 1\nscope:\n  include: ["http://127.0.0.1:{cls.shop}/"]\n')
        subprocess.run(base + ["roe", "use", roe], check=True, capture_output=True)
        cls.procs.append(subprocess.Popen(base + ["ui", "--no-proxy", "--listen", f"127.0.0.1:{ui}", "--as", "human:sdk"],
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        wait_port(cls.shop)
        wait_port(ui)
        cls.url = f"http://127.0.0.1:{cls.shop}"
        cls.pm = Client(f"http://127.0.0.1:{ui}", token=Path(home, "api-token").read_text().strip())

    @classmethod
    def tearDownClass(cls):
        for p in cls.procs:
            p.terminate()
            p.wait(timeout=10)

    def get(self, path):
        r = self.pm.replay(url=self.url, raw=f"GET {path} HTTP/1.1\r\nHost: shop\r\n\r\n")
        self.assertEqual(r["status"], "sent")
        return r["exchange_id"]

    def test_replay_history_and_reports(self):
        ex = self.get("/api/products")
        self.assertTrue(any(e["id"] == ex for e in self.pm.history(path="/api/products")))
        self.assertIn("Coffee", self.pm.exchange(ex)["response"])
        self.assertEqual(self.pm.status()["you_are"], "human:sdk")
        self.assertIn('"version": "2.1.0"', self.pm.report("sarif"))
        self.assertTrue(self.pm.audit_verify()["intact"])

    def test_scans_tools_and_errors(self):
        ex = self.get("/greet?name=ann")
        checks = [i["check"] for i in self.pm.scan_active(ex)["issues"]]
        self.assertIn("ssti", checks)
        self.assertEqual(self.pm.decode("JTNDc2NyaXB0JTNF")[-1]["output"], "<script>")
        self.assertIsInstance(self.pm.issues(), list)
        with self.assertRaises(ApiError) as e:
            self.pm.exchange(999999)
        self.assertEqual(e.exception.status, 404)
        with self.assertRaises(Denied):
            self.pm.replay(url="http://example.org", raw="GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")

    def test_har_and_curl(self):
        ex = self.get("/api/products")
        cmd = self.pm.curl(ex)
        self.assertTrue(cmd.startswith("curl "))
        parsed = self.pm.curl_parse(cmd)
        self.assertEqual(parsed["url"], self.url)
        har = self.pm.export_har(ids=[ex])
        self.assertEqual(len(har["log"]["entries"]), 1)
        har["log"]["entries"][0]["request"]["url"] = "https://elsewhere.test/copied"
        r = self.pm.import_har(json.dumps(har))
        self.assertEqual(r["imported"], 1)
        self.assertTrue(self.pm.history(source="import", path="/copied"))

    def test_pending_approval_flow(self):
        # Destructive payloads need a human's approval even for a human actor.
        with self.assertRaises(PendingApproval) as p:
            self.pm.replay(url=self.url, raw="GET /api/products/search?q=1;DROP%20TABLE%20users HTTP/1.1\r\nHost: shop\r\n\r\n")
        approval = p.exception.approval_id
        self.assertTrue(any(a["id"] == approval and a["status"] == "pending" for a in self.pm.approvals()))
        self.pm.deny(approval)
        self.assertEqual(self.pm.wait_for_approval(approval, timeout=5, poll=0.2), "denied")


if __name__ == "__main__":
    unittest.main()
