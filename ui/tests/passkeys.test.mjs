// Unit tests for src/passkeys.ts (base64url and the conversion of the server's options). Run with `npm run test:unit`.
import assert from "node:assert/strict";
import * as P from "../src/passkeys.ts";

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

test("base64url matches Node's for every length and round-trips", () => {
  for (let n = 0; n < 70; n++) {
    const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 255);
    const enc = P.bytesToB64url(bytes);
    assert.equal(enc, Buffer.from(bytes).toString("base64url"), `length ${n}`);
    assert.deepEqual([...P.b64urlToBytes(enc)], [...bytes], `length ${n}`);
  }
  assert.equal(P.bytesToB64url(new TextEncoder().encode("foobar")), "Zm9vYmFy");
  // ArrayBuffers (what the browser returns) work as well as views.
  assert.equal(P.bytesToB64url(Uint8Array.from([251, 255, 254]).buffer), "-__-");
});

test("base64url decoding is strict", () => {
  for (const bad of ["Zm9vYg==", "Zm9v+g", "Zm9v/g", "Zm 9v", "Z", "Zm9vYmFyZ", "éAAA"]) {
    assert.throws(() => P.b64urlToBytes(bad), /base64url/, JSON.stringify(bad));
  }
});

test("the options of the server become buffers", () => {
  const create = P.creationOptions({
    rp: { id: "pm.example.com", name: "ProxyMind" },
    user: { id: "AQID", name: "owner", displayName: "Owner" },
    challenge: "BAUG",
    pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    excludeCredentials: [{ type: "public-key", id: "Bwg" }],
    authenticatorSelection: { userVerification: "required" },
  });
  assert.deepEqual([...new Uint8Array(create.user.id)], [1, 2, 3]);
  assert.deepEqual([...new Uint8Array(create.challenge)], [4, 5, 6]);
  assert.deepEqual([...new Uint8Array(create.excludeCredentials[0].id)], [7, 8]);
  assert.equal(create.attestation, "none");
  assert.equal(create.authenticatorSelection.userVerification, "required");
  const get = P.requestOptions({ challenge: "BAUG", rpId: "pm.example.com", allowCredentials: [] });
  assert.deepEqual([...new Uint8Array(get.challenge)], [4, 5, 6]);
  assert.equal(get.userVerification, "required");
  assert.deepEqual(get.allowCredentials, []);
});

test("a page is at the right host for an RP id when it is the id or below it", () => {
  assert.equal(P.atRpHost("pm.example.com", "pm.example.com"), true);
  assert.equal(P.atRpHost("example.com", "pm.example.com"), true);
  assert.equal(P.atRpHost("pm.example.com", "example.com"), false);
  assert.equal(P.atRpHost("pm.example.com", "evilpm.example.com"), false);
  assert.equal(P.atRpHost("localhost", "127.0.0.1"), false);
  assert.equal(P.atRpHost(null, "localhost"), false);
});

if (failures) {
  console.log(`${failures} test(s) failed`);
  process.exit(1);
}
