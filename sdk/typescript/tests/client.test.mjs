// Integration tests: a real `proxymind ui` and VulnShop.
//   npm run build && PROXYMIND=../../target/debug/proxymind npm test
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { Client, ApiError, Denied, PendingApproval } from "../dist/index.js";

const BIN = process.env.PROXYMIND ?? new URL("../../../target/debug/proxymind", import.meta.url).pathname;
const skip = !existsSync(BIN) && `no proxymind binary at ${BIN}`;

const freePort = () =>
  new Promise((res) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
const waitPort = async (port) => {
  for (let i = 0; i < 300; i++) {
    const ok = await new Promise((res) => {
      const s = net.connect(port, "127.0.0.1", () => (s.end(), res(true)));
      s.on("error", () => res(false));
    });
    if (ok) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`nothing on port ${port}`);
};

let pm, url, procs = [];
before(async () => {
  if (skip) return;
  const dir = mkdtempSync(join(tmpdir(), "pm-ts-sdk-"));
  const [shop, ui] = [await freePort(), await freePort()];
  const base = ["-p", join(dir, "p.pmproj"), "--home", join(dir, "home")];
  procs.push(spawn(BIN, [...base, "demo-target", "--listen", `127.0.0.1:${shop}`], { stdio: "ignore" }));
  writeFileSync(join(dir, "roe.yaml"), `version: 1\nscope:\n  include: ["http://127.0.0.1:${shop}/"]\n`);
  execFileSync(BIN, [...base, "roe", "use", join(dir, "roe.yaml")]);
  procs.push(spawn(BIN, [...base, "ui", "--no-proxy", "--listen", `127.0.0.1:${ui}`, "--as", "human:sdk"], { stdio: "ignore" }));
  await waitPort(shop);
  await waitPort(ui);
  url = `http://127.0.0.1:${shop}`;
  pm = await Client.connect({ baseUrl: `http://127.0.0.1:${ui}`, token: readFileSync(join(dir, "home", "api-token"), "utf8").trim() });
});
after(() => procs.forEach((p) => p.kill()));

const get = async (path) => {
  const r = await pm.replay({ url, raw: `GET ${path} HTTP/1.1\r\nHost: shop\r\n\r\n` });
  assert.equal(r.status, "sent");
  return r.exchange_id;
};

test("replay, history and reports", { skip }, async () => {
  const ex = await get("/api/products");
  assert.ok((await pm.history({ path: "/api/products" })).some((e) => e.id === ex));
  assert.match((await pm.exchange(ex)).response, /Coffee/);
  assert.equal((await pm.status()).you_are, "human:sdk");
  assert.match(await pm.report("sarif"), /"version": "2.1.0"/);
  assert.equal((await pm.auditVerify()).intact, true);
  assert.equal((await pm.annotate(ex, { highlight: "blue", comment: "ts" })).highlight, "blue");
  assert.deepEqual((await pm.history({ annotated: true })).map((e) => e.id), [ex]);
  await pm.annotate(ex);
  assert.deepEqual(await pm.wsHistory(), []);
});

test("scans, tools and errors", { skip }, async () => {
  const ex = await get("/greet?name=ann");
  assert.ok((await pm.scanActive(ex)).issues.some((i) => i.check === "ssti"));
  assert.equal((await pm.decode("JTNDc2NyaXB0JTNF")).at(-1).output, "<script>");
  await assert.rejects(pm.exchange(999999), (e) => e instanceof ApiError && e.status === 404);
  await assert.rejects(pm.replay({ url: "http://example.org", raw: "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n" }), Denied);
});

test("approvals", { skip }, async () => {
  const raw = 'POST /api/orders HTTP/1.1\r\nHost: shop\r\nContent-Type: application/json\r\n\r\n{"product_id":1,"qty":1}';
  // A human's POST is allowed outright under the default rules; DELETE needs approval.
  const del = "DELETE /api/orders/1001 HTTP/1.1\r\nHost: shop\r\n\r\n";
  let pending;
  try {
    await pm.replay({ url, raw: del });
  } catch (e) {
    pending = e;
  }
  assert.ok(pending instanceof PendingApproval, String(pending));
  await pm.approve(pending.approvalId);
  assert.equal(await pm.waitForApproval(pending.approvalId, 5000, 100), "approved");
  assert.equal((await pm.replay({ url, raw: del, approval_id: pending.approvalId })).status, "sent");
  assert.equal((await pm.replay({ url, raw, fix_content_length: true })).status, "sent");
});

test("HAR, cURL, search and site map", { skip }, async () => {
  const ex = await get("/api/products");
  const cmd = await pm.curl(ex);
  assert.ok(cmd.startsWith("curl "));
  assert.equal((await pm.curlParse(cmd)).url, url);
  const har = await pm.exportHar({ ids: [ex] });
  har.log.entries[0].request.url = "https://elsewhere.test/ts-copied";
  assert.equal((await pm.importHar(JSON.stringify(har))).imported, 1);
  assert.equal((await pm.history({ source: "import", path: "/ts-copied" })).length, 1);
  assert.ok((await pm.search("coffee", { part: "response" })).hits.length > 0);
  assert.ok((await pm.siteMap()).some((s) => s.origin === url));
});

test("rules of engagement, discovery and GraphQL", { skip }, async () => {
  const current = await pm.roe();
  await assert.rejects(pm.checkRoe("version: 1\nscope:\n  include: []\n"), ApiError);
  assert.equal((await pm.setRoe(current.text + "engagement:\n  name: ts\n")).summary.engagement.name, "ts");
  await pm.setRoe(current.text);
  const d = await pm.discover(`${url}/`, { words: [".git/config", "nothing-here"] });
  assert.deepEqual(d.found.map((f) => f.url), [`${url}/.git/config`]);
  const g = await pm.graphqlImport({ url: `${url}/graphql`, fetch: true });
  assert.deepEqual(g.operations.map((o) => o.name), ["me", "invoice", "products"]);
});

test("live events", { skip }, async () => {
  const ac = new AbortController();
  const it = pm.events(ac.signal);
  const first = (await it.next()).value;
  assert.equal(typeof first.exchanges, "number");
  ac.abort();
});
