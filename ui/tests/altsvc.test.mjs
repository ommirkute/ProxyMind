// Unit tests for src/altsvc.ts (Alt-Svc advertisements of HTTP/3). Run with `npm run test:unit`.
import assert from "node:assert/strict";
import * as A from "../src/altsvc.ts";
import { toProtocol } from "../src/http.ts";

let failures = 0;
const test = (name, fn) => {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${name}\n       ${e.message.split("\n").join("\n       ")}`);
  }
};

test("parses alternatives with parameters, ignoring clear", () => {
  const v = A.parseAltSvc('h3=":443"; ma=86400, h3-29=":8443"; ma=3600; persist=1, h2="alt.example:443", clear');
  assert.equal(v.length, 3);
  assert.deepEqual([v[0].protocol, v[0].authority, v[0].maxAge], ["h3", ":443", 86400]);
  assert.deepEqual([v[2].protocol, v[2].authority, v[2].maxAge], ["h2", "alt.example:443", undefined]);
});

test("commas and semicolons inside quotes belong to the value", () => {
  const q = A.parseAltSvc('h3="a,b:443"; ma="60", quic=":1"');
  assert.deepEqual([q[0].authority, q[0].maxAge, q.length], ["a,b:443", 60, 2]);
  assert.deepEqual([A.parseAltSvc("clear"), A.parseAltSvc(""), A.parseAltSvc("h3=")], [[], [], []]);
});

test("finds HTTP/3 alternatives in HTTP/1.1, HTTP/2 and HTTP/3 responses, across several headers", () => {
  const h1 = 'HTTP/1.1 200 OK\r\nAlt-Svc: h3=":443"; ma=60\r\nalt-svc: h2=":443", h3-29=":443"\r\n\r\nbody alt-svc: h3=":1"';
  assert.deepEqual(A.altSvcH3(h1).map((a) => a.protocol), ["h3", "h3-29"]);
  assert.equal(A.altSvcH3('HTTP/2 200\nalt-svc: h3=":443"\n\n').length, 1);
  assert.equal(A.altSvcH3('HTTP/3 200\r\nalt-svc: h3=":443"\r\n\r\n').length, 1);
  assert.equal(A.altSvcH3('HTTP/1.1 200 OK\r\nAlt-Svc: h2=":443"\r\n\r\n').length, 0);
  assert.equal(A.altSvcH3('HTTP/1.1 200 OK\r\nX-Note: alt-svc: h3=":443"\r\n\r\n').length, 0);
  assert.equal(A.altSvcH3(null).length, 0);
});

test("the target of an alternative", () => {
  const alt = (authority) => ({ protocol: "h3", authority });
  assert.equal(A.altTarget("https://shop.test:8443", alt(":443")), "https://shop.test:443");
  assert.equal(A.altTarget("http://shop.test", alt(":8443")), "https://shop.test:8443");
  assert.equal(A.altTarget("https://shop.test", alt("edge.shop.test:4433")), "https://edge.shop.test:4433");
  assert.equal(A.altTarget("https://shop.test", alt("[::1]:443")), "https://[::1]:443");
  assert.equal(A.altTarget("not a url", alt(":443")), "not a url");
});

test("a request is written for HTTP/3 like for HTTP/2 (lower-case names, no connection headers)", () => {
  const raw = "GET /a?b=1 HTTP/1.1\nHost: shop.test\nConnection: keep-alive\nAccept: */*\n\n";
  const h3 = toProtocol(raw, "HTTP/3");
  assert.ok(h3.startsWith("GET /a?b=1 HTTP/3\n"), h3);
  assert.ok(h3.includes("host: shop.test") && h3.includes("accept: */*") && !/connection/i.test(h3), h3);
  assert.ok(toProtocol(h3, "HTTP/1.1").startsWith("GET /a?b=1 HTTP/1.1\n") && toProtocol(h3, "HTTP/1.1").includes("Host: shop.test"));
});

if (failures) {
  console.log(`${failures} failed`);
  process.exit(1);
}
console.log("all passed");
