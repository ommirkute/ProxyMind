// The hook helpers speak ProxyMind's hook protocol: one JSON line in, one JSON line out. No binary needed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { serve, replace, addHeader, bodyOf, header, DROP, parseCall, answer } from "../dist/plugin.js";

const REQ = Buffer.from("POST /api/x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\n\r\nhi");
const frame = (id, phase, raw, status) =>
  JSON.stringify({
    v: 2, id, phase,
    exchange: { method: "POST", url: "http://a.test/api/x", scheme: "http", host: "a.test", port: 80, path: "/api/x", ...(status ? { status } : {}) },
    raw: raw.toString("base64"),
  }) + "\n";

test("header helpers keep every other byte", () => {
  assert.equal(addHeader(REQ, "X-A", "1").toString(), "POST /api/x HTTP/1.1\r\nHost: a.test\r\nContent-Length: 2\r\nX-A: 1\r\n\r\nhi");
  assert.equal(bodyOf(REQ).toString(), "hi");
  assert.equal(header(REQ, "content-length"), "2");
  assert.equal(header(REQ, "nope"), undefined);
  assert.deepEqual(addHeader(Buffer.from("no head end"), "X", "1"), Buffer.from("no head end"));
});

test("serve answers pass, replace and drop", async () => {
  const input = new PassThrough();
  const lines = [];
  const done = serve(
    {
      request: (c) => {
        assert.equal(c.host, "a.test");
        assert.equal(bodyOf(c.raw).toString(), "hi");
        if (header(c.raw, "X-Drop")) return DROP;
        if (header(c.raw, "X-Pass")) return undefined;
        return replace(addHeader(c.raw, "X-Sig", "abc"), "signed");
      },
    },
    input,
    { write: (s) => lines.push(s) },
  );
  input.write(frame(1, "request", REQ));
  input.write(frame(2, "request", addHeader(REQ, "X-Drop", "1")));
  input.write(frame(3, "request", addHeader(REQ, "X-Pass", "1")));
  input.write(frame(4, "response", Buffer.from("HTTP/1.1 200 OK\r\n\r\n"), 200));
  input.end();
  await done;
  const got = lines.map((l) => JSON.parse(l));
  assert.deepEqual(got.map((a) => a.action), ["replace", "drop", "pass", "pass"]);
  assert.deepEqual(got.map((a) => a.id), [1, 2, 3, 4]);
  assert.equal(Buffer.from(got[0].raw, "base64").toString(), addHeader(REQ, "X-Sig", "abc").toString());
  assert.equal(got[0].note, "signed");
});

test("frames parse and answers encode", () => {
  const c = parseCall(frame(9, "response", Buffer.from("HTTP/1.1 404 Not Found\r\n\r\n"), 404));
  assert.equal(c.status, 404);
  assert.equal(c.phase, "response");
  assert.equal(JSON.parse(answer(c, "HTTP/1.1 200 OK\r\n\r\n")).action, "replace");
});
