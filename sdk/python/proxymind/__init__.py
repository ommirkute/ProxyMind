"""Python client for the ProxyMind REST API.

    from proxymind import Client
    pm = Client()                      # http://127.0.0.1:7777, token from ~/.proxymind/api-token
    for ex in pm.history(path="/api/orders"):
        print(ex["id"], ex["method"], ex["path"], ex.get("status"))
    r = pm.replay(url="https://app.example.com", raw="GET /api/me HTTP/1.1\\r\\nHost: app.example.com\\r\\n\\r\\n")

The API acts as the human who started `proxymind ui`: what this client does
is attributed to that person and goes through the same policy gate. For an
automated agent, use the MCP server with an `agent:` actor instead.

Licensed under the Apache License 2.0 (unlike the AGPL core), so it can be
used in any integration.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterator, Optional

__all__ = ["Client", "ApiError", "Denied", "PendingApproval"]
__version__ = "0.1.0"


class ApiError(Exception):
    """The API refused a request (bad input, not found, forbidden…)."""

    def __init__(self, status: int, message: str):
        super().__init__(f"{status}: {message}")
        self.status = status
        self.message = message


class Denied(ApiError):
    """The policy gate refused the action (out of scope, tier not allowed…)."""

    def __init__(self, reasons: list):
        super().__init__(403, "; ".join(reasons) or "denied")
        self.reasons = reasons


class PendingApproval(Exception):
    """An action needs a human's approval first (see Client.wait_for_approval)."""

    def __init__(self, approval_id: str, summary: str):
        super().__init__(f"needs approval {approval_id}: {summary}")
        self.approval_id = approval_id
        self.summary = summary


def _default_token() -> Optional[str]:
    if os.environ.get("PROXYMIND_TOKEN"):
        return os.environ["PROXYMIND_TOKEN"].strip()
    home = Path(os.environ.get("PROXYMIND_HOME") or Path.home() / ".proxymind")
    try:
        return (home / "api-token").read_text().strip()
    except OSError:
        return None


class Client:
    def __init__(self, base_url: str = "http://127.0.0.1:7777", token: Optional[str] = None, timeout: float = 120.0):
        self.base_url = base_url.rstrip("/")
        self.token = token or _default_token()
        if not self.token:
            raise ValueError("no API token: pass token=, set PROXYMIND_TOKEN, or run `proxymind ui` once")
        self.timeout = timeout
        # Talk to the local API directly, never through a system proxy.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    # ------------------------------------------------------------ plumbing --

    def request(self, method: str, path: str, body: Any = None, query: Optional[dict] = None, raw: bool = False) -> Any:
        url = f"{self.base_url}/api/v1{path}"
        if query:
            q = {k: v for k, v in query.items() if v is not None}
            if q:
                url += "?" + urllib.parse.urlencode(q)
        data = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if method != "GET":
            headers["X-ProxyMind"] = "1"
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                payload = resp.read()
        except urllib.error.HTTPError as e:
            text = e.read().decode(errors="replace")
            try:
                text = json.loads(text).get("error", text)
            except (ValueError, AttributeError):
                pass
            raise ApiError(e.code, text) from None
        if raw:
            return payload.decode(errors="replace")
        return json.loads(payload) if payload else None

    def _get(self, _route: str, **query: Any) -> Any:
        return self.request("GET", _route, query=query)

    def _post(self, path: str, body: Any = None) -> Any:
        return self.request("POST", path, body=body if body is not None else {})

    @staticmethod
    def _check(result: Any) -> Any:
        """Raises PendingApproval or Denied for results that didn't run."""
        if isinstance(result, dict) and result.get("status") == "pending_approval":
            raise PendingApproval(result.get("approval_id", ""), result.get("summary", ""))
        if isinstance(result, dict) and result.get("status") == "denied":
            raise Denied(result.get("reasons", []))
        return result

    @staticmethod
    def _args(**kw: Any) -> dict:
        return {k: v for k, v in kw.items() if v is not None}

    # ------------------------------------------------------------- reading --

    def status(self) -> dict:
        return self._get("/status")

    def history(self, **filters: Any) -> list:
        """Recorded exchanges, newest first. Filters: host, path, method, status, source, limit, before_id…"""
        return self._get("/exchanges", **filters)["exchanges"]

    def exchange(self, exchange_id: int) -> dict:
        return self._get(f"/exchanges/{exchange_id}")

    def model(self, **filters: Any) -> dict:
        return self._get("/model", **filters)

    def coverage(self, all: bool = False) -> dict:
        return self._get("/coverage", all=str(all).lower())

    def issues(self, **filters: Any) -> list:
        """Passive scan of recorded traffic (sends nothing). Filters: host, min_severity, limit."""
        return self._get("/scan/issues", **filters)

    def findings(self) -> list:
        return self._get("/findings")

    def finding(self, finding_id: int) -> dict:
        return self._get(f"/findings/{finding_id}")

    def proof(self, proof_id: int) -> dict:
        return self._get(f"/proofs/{proof_id}")

    def approvals(self, status: Optional[str] = None) -> list:
        """Approvals, all by default; status: pending, approved, denied, used."""
        return self._get("/approvals", status=status or "all")

    def audit_verify(self) -> dict:
        return self._get("/audit/verify")

    def report(self, format: str = "md") -> str:
        """The report as text: md, json, sarif or html."""
        return self.request("GET", "/report", query={"format": format}, raw=True)

    def events(self) -> Iterator[dict]:
        """Live counters (exchanges, findings, approvals…) as they change. Blocks."""
        req = urllib.request.Request(f"{self.base_url}/api/v1/events", headers={"Authorization": f"Bearer {self.token}"})
        with self._opener.open(req, timeout=None) as resp:
            for line in resp:
                line = line.decode(errors="replace").strip()
                if line.startswith("data:"):
                    yield json.loads(line[5:].strip())

    # ------------------------------------------------------------- acting --

    def replay(self, raw: Optional[str] = None, url: Optional[str] = None, exchange_id: Optional[int] = None,
               identity: Optional[str] = None, approval_id: Optional[str] = None, **extra: Any) -> dict:
        """Send a request through the policy gate. Raises PendingApproval if a human must approve."""
        body = self._args(raw=raw, url=url, exchange_id=exchange_id, identity=identity, approval_id=approval_id, **extra)
        return self._check(self._post("/replay", body))

    def intruder(self, raw: str, payload_sets: list, url: Optional[str] = None, **extra: Any) -> dict:
        """Fuzz positions marked §like this§. payload_sets: [{"list": [...]}, {"numbers": "1-10"}, {"builtin": "sqli"}]."""
        return self._check(self._post("/intruder", self._args(raw=raw, payload_sets=payload_sets, url=url, **extra)))

    def crawl(self, url: str, **extra: Any) -> dict:
        return self._check(self._post("/crawl", self._args(url=url, **extra)))

    def scan_active(self, exchange_id: int, checks: Optional[list] = None, **extra: Any) -> dict:
        return self._check(self._post("/scan/active", self._args(exchange_id=exchange_id, checks=checks, **extra)))

    def openapi_import(self, spec: Optional[str] = None, exchange_id: Optional[int] = None, **extra: Any) -> dict:
        return self._check(self._post("/openapi/import", self._args(spec=spec, exchange_id=exchange_id, **extra)))

    def authz_check(self, exchange_id: int, identities: list, include_anonymous: bool = True) -> dict:
        return self._post("/authz/check", {"exchange_id": exchange_id, "identities": identities, "include_anonymous": include_anonymous})

    def create_finding(self, title: str, vuln_class: str, severity: str, evidence: list, description: str = "", url: Optional[str] = None) -> dict:
        return self._post("/findings", self._args(title=title, vuln_class=vuln_class, severity=severity, evidence=evidence, description=description, url=url))

    def prove(self, oracle: str, **inputs: Any) -> dict:
        """Run a proof: differential_authz, timing, oast or reflection (see docs/agents.md for inputs)."""
        return self._check(self._post("/proofs", self._args(oracle=oracle, **inputs)))

    def decode(self, text: str, ops: Optional[list] = None) -> list:
        """Encode/decode locally; no ops means a smart decode. Returns the steps."""
        return self._post("/tools/decode", {"input": text, "ops": ops or []})["steps"]

    def compare(self, a: int, b: int) -> dict:
        return self._post("/tools/compare", {"a": a, "b": b})

    def sequencer(self, exchange_id: int, locator: str, samples: int = 100, **extra: Any) -> dict:
        return self._check(self._post("/tools/sequencer", self._args(exchange_id=exchange_id, locator=locator, samples=samples, **extra)))

    def import_har(self, har: str) -> dict:
        """Adds a HAR file's exchanges (text) to history; sends nothing. Returns {imported, exchange_ids, skipped}."""
        return self._post("/import/har", {"har": har})

    def export_har(self, ids: Optional[list] = None, **filters: Any) -> dict:
        """History as a HAR document: exactly ids, or everything matching history filters (host, path, limit…)."""
        return self._post("/export/har", self._args(ids=ids, **filters))

    def curl(self, exchange_id: int) -> str:
        """A curl command that sends the same request as a recorded exchange."""
        return self._get(f"/exchanges/{exchange_id}/curl")["command"]

    def curl_parse(self, command: str) -> dict:
        """Reads a curl command into {url, method, raw, warnings}, ready for replay(); sends nothing."""
        return self._post("/tools/curl", {"command": command})

    def approve(self, approval_id: str) -> dict:
        return self._post(f"/approvals/{approval_id}/approve")

    def deny(self, approval_id: str) -> dict:
        return self._post(f"/approvals/{approval_id}/deny")

    def wait_for_approval(self, approval_id: str, timeout: float = 600, poll: float = 2.0) -> str:
        """Waits until a human approves or denies; returns "approved" or "denied"."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for a in self.approvals():
                if a.get("id") == approval_id and a.get("status") in ("approved", "denied", "used"):
                    return "denied" if a["status"] == "denied" else "approved"
            time.sleep(poll)
        raise TimeoutError(f"approval {approval_id} still pending after {timeout} s")
