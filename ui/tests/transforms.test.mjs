// Unit tests for src/transforms.ts. Run with `npm run test:unit`. Node strips the TypeScript types itself
// (the npm script passes --experimental-strip-types, which newer Node versions no longer need), so nothing is
// re-implemented here and no dependency is added.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import * as T from "../src/transforms.ts";

let failures = 0;
const test = async (name, fn) => {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (e) {
    failures++;
    console.log(`  FAIL ${name}\n       ${e.message.split("\n").join("\n       ")}`);
  }
};
const val = async (id, input) => {
  const r = await T.transform(id, input);
  assert.ok(r.ok, `${id}(${JSON.stringify(input)}) failed: ${r.error}`);
  return r.value;
};
const err = async (id, input) => {
  const r = await T.transform(id, input);
  assert.equal(r.ok, false, `${id}(${JSON.stringify(input)}) should fail, gave ${JSON.stringify(r.value)}`);
  assert.ok(r.error.length > 0);
};
const bytes = (s) => new TextEncoder().encode(s);

await test("MD5 vectors (RFC 1321)", () => {
  assert.equal(T.md5(bytes("")), "d41d8cd98f00b204e9800998ecf8427e");
  assert.equal(T.md5(bytes("a")), "0cc175b9c0f1b6a831c399e269772661");
  assert.equal(T.md5(bytes("abc")), "900150983cd24fb0d6963f7d28e17f72");
  assert.equal(T.md5(bytes("message digest")), "f96b697d7cb7938d525a2f31aaf161d0");
  assert.equal(T.md5(bytes("abcdefghijklmnopqrstuvwxyz")), "c3fcd3d76192e4007dfb496cca67e13b");
  assert.equal(
    T.md5(bytes("12345678901234567890123456789012345678901234567890123456789012345678901234567890")),
    "57edf4a22be3c955ac49da2e2107b67a",
  );
});

await test("MD5 agrees with node:crypto across padding boundaries and UTF-8", async () => {
  for (const n of [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000]) {
    const s = "a".repeat(n);
    assert.equal(T.md5(bytes(s)), createHash("md5").update(s).digest("hex"), `length ${n}`);
  }
  assert.equal(await val("md5", "héllo ✓ 😀"), createHash("md5").update("héllo ✓ 😀").digest("hex"));
  assert.equal(await val("md5", "abc"), "900150983cd24fb0d6963f7d28e17f72");
});

await test("SHA-1 and SHA-256 vectors", async () => {
  assert.equal(await val("sha256", "abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(await val("sha256", ""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.equal(await val("sha1", "abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
  assert.equal(await val("sha256", "é"), createHash("sha256").update("é").digest("hex"));
});

await test("URL encode/decode, component and full", async () => {
  assert.equal(await val("url_encode", "a b&c=d/e?f#g+h"), "a%20b%26c%3Dd%2Fe%3Ff%23g%2Bh");
  assert.equal(await val("url_encode_full", "https://x.test/a b?q=1&r=é#f"), "https://x.test/a%20b?q=1&r=%C3%A9#f");
  assert.equal(await val("url_decode", "a%20b%26c%3Dd%2Fe%3Ff%23g%2Bh"), "a b&c=d/e?f#g+h");
  assert.equal(await val("url_decode_full", "https://x.test/a%20b?q=1%262"), "https://x.test/a b?q=1%262");
  assert.equal(await val("url_decode", "%C3%A9"), "é");
  await err("url_decode", "100%");
  await err("url_decode", "%ZZ");
  await err("url_decode", "%C3");
  await err("url_encode", "\ud800");
});

await test("Base64 of ASCII and non-ASCII UTF-8", async () => {
  assert.equal(await val("base64_encode", "abc"), "YWJj");
  assert.equal(await val("base64_encode", "ab"), "YWI=");
  assert.equal(await val("base64_encode", "é"), "w6k=");
  assert.equal(await val("base64_encode", "héllo wörld ✓"), Buffer.from("héllo wörld ✓").toString("base64"));
  assert.equal(await val("base64_encode", "héllo wörld ✓"), "aMOpbGxvIHfDtnJsZCDinJM=");
  assert.equal(await val("base64_decode", "aMOpbGxvIHfDtnJsZCDinJM="), "héllo wörld ✓");
  assert.equal(await val("base64_decode", "YW Jj\n"), "abc");
  assert.equal(await val("base64_decode", "YWI"), "ab");
  assert.equal(await val("base64_encode", "😀"), "8J+YgA==");
  assert.equal(await val("base64_decode", "8J+YgA=="), "😀");
  assert.equal(await val("base64_encode", ""), "");
  const big = "x".repeat(100000);
  assert.equal(await val("base64_decode", await val("base64_encode", big)), big);
});

await test("Base64 URL-safe uses - and _ and drops padding", async () => {
  assert.equal(await val("base64url_encode", "???>>>"), "Pz8_Pj4-");
  assert.equal(await val("base64_encode", "???>>>"), "Pz8/Pj4+");
  assert.equal(await val("base64url_decode", "Pz8_Pj4-"), "???>>>");
  assert.equal(await val("base64url_encode", "ab"), "YWI");
});

await test("Base64 decode rejects bad input", async () => {
  await err("base64_decode", "not base64!");
  await err("base64_decode", "A");
  await err("base64_decode", "YWJjZ");
  await err("base64_decode", "/w=="); // 0xff: valid Base64 but not UTF-8 text
});

await test("HTML entities", async () => {
  assert.equal(await val("html_encode", `<a href="x" t='y'>&</a>`), "&lt;a href=&quot;x&quot; t=&#39;y&#39;&gt;&amp;&lt;/a&gt;");
  assert.equal(await val("html_decode", "&lt;b&gt; &amp;amp; &quot;&apos;"), `<b> &amp; "'`);
  assert.equal(await val("html_decode", "&#65;&#x42;&#x1F600;"), "AB😀");
  assert.equal(await val("html_decode", "&unknownentity; &"), "&unknownentity; &");
  const s = `<script>alert("1&2")</script>`;
  assert.equal(await val("html_decode", await val("html_encode", s)), s);
  await err("html_decode", "&#1114112;");
  await err("html_decode", "&#xD800;");
});

await test("Hex encode/decode round trips", async () => {
  assert.equal(await val("hex_encode", "abc"), "616263");
  assert.equal(await val("hex_encode", "é"), "c3a9");
  assert.equal(await val("hex_decode", "616263"), "abc");
  assert.equal(await val("hex_decode", "61 62:63"), "abc");
  assert.equal(await val("hex_decode", "0x61,0x62\\x63"), "abc");
  assert.equal(await val("hex_decode", "C3A9"), "é");
  for (const s of ["", "GET / HTTP/1.1\r\n", "日本語 ✓ 😀"]) assert.equal(await val("hex_decode", await val("hex_encode", s)), s);
  await err("hex_decode", "6162g");
  await err("hex_decode", "616");
  await err("hex_decode", "ff"); // not UTF-8
});

await test("Unicode escapes", async () => {
  assert.equal(await val("unicode_encode", "aé✓"), "a\\u00e9\\u2713");
  assert.equal(await val("unicode_encode", "😀"), "\\ud83d\\ude00");
  assert.equal(await val("unicode_encode_all", "a<"), "\\u0061\\u003c");
  assert.equal(await val("unicode_decode", "a\\u00e9\\u2713"), "aé✓");
  assert.equal(await val("unicode_decode", "\\ud83d\\ude00"), "😀");
  assert.equal(await val("unicode_decode", "\\u{1F600}"), "😀");
  assert.equal(await val("unicode_decode", "\\u003cscript\\u003e"), "<script>");
  for (const s of ["", "plain", "日本語 😀"]) assert.equal(await val("unicode_decode", await val("unicode_encode_all", s)), s);
  await err("unicode_decode", "\\u12");
  await err("unicode_decode", "\\uZZZZ");
  await err("unicode_decode", "\\u{110000}");
});

await test("JSON string escape/unescape", async () => {
  assert.equal(await val("json_escape", 'a"b\\c\nd\te'), 'a\\"b\\\\c\\nd\\te');
  assert.equal(await val("json_escape", "\u0001é"), "\\u0001é");
  assert.equal(await val("json_unescape", 'a\\"b\\\\c\\nd\\te'), 'a"b\\c\nd\te');
  assert.equal(await val("json_unescape", "\\u00e9\\ud83d\\ude00\\/"), "é😀/");
  const s = 'x"\\\n\r\t\u0007y';
  assert.equal(await val("json_unescape", await val("json_escape", s)), s);
  await err("json_unescape", 'a"b'); // raw quote
  await err("json_unescape", "bad \\q escape");
  await err("json_unescape", "line\nbreak");
  await err("json_unescape", "trailing\\");
});

await test("unknown operations fail and the catalogue is consistent", async () => {
  await err("nope", "x");
  const ids = new Set();
  for (const op of T.TRANSFORMS) {
    assert.ok(!ids.has(op.id), `duplicate ${op.id}`);
    ids.add(op.id);
    const r = await T.transform(op.id, "abc");
    assert.equal(typeof r.ok, "boolean"); // none throws
  }
  assert.deepEqual(T.TRANSFORMS.filter((o) => !o.reversible).map((o) => o.id), ["md5", "sha1", "sha256"]);
});

await test("shared vectors with the server (crates/pm-tools/testdata/transform_vectors.json)", async () => {
  // The same file is run by pm_tools::transform's tests, so the browser's transforms and the workflow engine's
  // cannot disagree about a result or about what fails.
  const vectors = JSON.parse(readFileSync(new URL("../../crates/pm-tools/testdata/transform_vectors.json", import.meta.url), "utf8"));
  assert.ok(vectors.length >= 100);
  const seen = new Set();
  for (const v of vectors) {
    seen.add(v.op);
    const r = await T.transform(v.op, v.input);
    if (v.error) assert.equal(r.ok, false, `${v.op}(${JSON.stringify(v.input)}) should fail`);
    else {
      assert.ok(r.ok, `${v.op}(${JSON.stringify(v.input)}) failed: ${r.error}`);
      assert.equal(r.value, v.output, `${v.op}(${JSON.stringify(v.input)})`);
    }
  }
  for (const op of T.TRANSFORMS) assert.ok(seen.has(op.id), `no shared vector for ${op.id}`);
});

console.log(failures ? `\n${failures} test(s) failed` : "\nAll transform tests passed");
process.exit(failures ? 1 : 0);
