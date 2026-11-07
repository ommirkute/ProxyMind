"""Helpers for writing ProxyMind plugins in Python (standard library only).

A passive plugin reads recorded exchanges and reports issues; an active
plugin proposes requests for one exchange, ProxyMind sends them through its
policy gate, then the plugin judges the responses. See ADR-0014/0015.

    from proxymind.plugin import run, Issue, with_query

    def probe(x):                     # x: Exchange
        yield with_query(x.request, "debug=1"), "adds debug=1"

    def judge(x, results):            # results: list of Result
        for r in results:
            if b"password" in r.body and b"password" not in x.body:
                yield Issue(r.exchange_id, "debug_switch", "Debug switch", "medium", r.note)

    run(probe=probe, judge=judge)

The plugin runs sandboxed: no environment secrets and (on Linux) no network.
"""
import base64
import json
import sys
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

__all__ = ["Exchange", "Result", "Issue", "run", "split", "body_of", "with_query", "set_header"]


def _bytes(b64: Optional[str]) -> bytes:
    return base64.b64decode(b64) if b64 else b""


def split(raw: bytes):
    """(request or status line, header lines, body) of a raw HTTP/1.x message."""
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    return lines[0], lines[1:], body


def body_of(raw: bytes) -> bytes:
    return raw.partition(b"\r\n\r\n")[2]


def status_of(raw: bytes) -> Optional[int]:
    try:
        return int(raw.split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None


@dataclass
class Exchange:
    """A recorded exchange, as ProxyMind sends it."""
    exchange_id: int
    method: str
    host: str
    path: str
    status: Optional[int]
    request: bytes
    response: bytes

    @property
    def body(self) -> bytes:
        return body_of(self.response)

    @classmethod
    def parse(cls, x: dict) -> "Exchange":
        return cls(x["exchange_id"], x.get("method", ""), x.get("host", ""), x.get("path", ""), x.get("status"),
                   _bytes(x.get("request")), _bytes(x.get("response")))


@dataclass
class Result:
    """What one proposed request got back."""
    index: int
    note: str
    exchange_id: int
    status: Optional[int]
    elapsed_ms: int
    request: bytes
    response: bytes
    error: Optional[str] = None

    @property
    def body(self) -> bytes:
        return body_of(self.response)

    @classmethod
    def parse(cls, r: dict) -> "Result":
        return cls(r["index"], r.get("note", ""), r.get("exchange_id", 0), r.get("status"), r.get("elapsed_ms", 0),
                   _bytes(r.get("request")), _bytes(r.get("response")), r.get("error"))


@dataclass
class Issue:
    exchange_id: int
    check: str
    title: str
    severity: str = "info"  # info, low, medium or high
    evidence: str = ""

    def line(self) -> str:
        return json.dumps({"exchange_id": self.exchange_id, "check": self.check, "title": self.title,
                           "severity": self.severity, "evidence": self.evidence})


def with_query(request: bytes, extra: str) -> str:
    """The request with `extra` (e.g. "debug=1") added to its query string, as text."""
    first, headers, body = split(request)
    method, target, version = first.decode("latin-1").split(" ", 2)
    sep = "&" if "?" in target else "?"
    lines = [f"{method} {target}{sep}{extra} {version}"] + [h.decode("latin-1") for h in headers]
    return "\r\n".join(lines) + "\r\n\r\n" + body.decode("latin-1")


def set_header(request: bytes, name: str, value: str) -> str:
    """The request with header `name` set to `value` (replaced or added), as text."""
    first, headers, body = split(request)
    kept = [h.decode("latin-1") for h in headers if not h.lower().startswith(name.lower().encode() + b":")]
    lines = [first.decode("latin-1")] + kept + [f"{name}: {value}"]
    return "\r\n".join(lines) + "\r\n\r\n" + body.decode("latin-1")


Probe = Callable[[Exchange], Iterable]
Judge = Callable[[Exchange, list], Iterable[Issue]]
Passive = Callable[[Exchange], Iterable[Issue]]


def run(probe: Optional[Probe] = None, judge: Optional[Judge] = None, passive: Optional[Passive] = None,
        stdin=None, stdout=None) -> None:
    """Reads ProxyMind's input and calls your functions.

    - passive(exchange) yields Issues, once per recorded exchange.
    - probe(exchange) yields requests to send: text, or (text, note).
    - judge(exchange, results) yields Issues.
    """
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        phase = msg.get("phase")
        if phase == "probe" and probe:
            for p in probe(Exchange.parse(msg["exchange"])) or []:
                raw, note = (p, "") if isinstance(p, str) else p
                stdout.write(json.dumps({"raw": raw, "note": note}) + "\n")
        elif phase == "judge" and judge:
            results = [Result.parse(r) for r in msg.get("results", [])]
            for i in judge(Exchange.parse(msg["exchange"]), results) or []:
                stdout.write(i.line() + "\n")
        elif phase is None and passive:
            for i in passive(Exchange.parse(msg)) or []:
                stdout.write(i.line() + "\n")
    stdout.flush()
