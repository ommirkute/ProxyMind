// Browser end-to-end test of the ProxyMind UI against VulnShop.
//
//   npm run build && (cd .. && cargo build) && npm run test:e2e
//
// Uses the real `proxymind` binary (PROXYMIND, default ../target/debug/proxymind)
// and Chromium (CHROMIUM, default: Playwright's bundled path).
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { chromium } from "playwright-core";

const BIN = process.env.PROXYMIND ?? new URL("../../target/debug/proxymind", import.meta.url).pathname;
const SHOTS = process.env.SCREENSHOTS ?? join(tmpdir(), "proxymind-ui-shots");
const dir = mkdtempSync(join(tmpdir(), "pm-ui-e2e-"));
const project = join(dir, "ui.pmproj");
const children = [];
let failures = 0;

const freePort = () =>
  new Promise((res) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pm = (...args) => execFileSync(BIN, ["-p", project, "--home", join(dir, "home"), ...args], { encoding: "utf8" });
function start(args, onLine) {
  const c = spawn(BIN, ["-p", project, "--home", join(dir, "home"), ...args], { stdio: ["pipe", "pipe", "pipe"] });
  c.stdout.on("data", (d) => onLine?.(String(d)));
  children.push(c);
  return c;
}
function check(cond, msg) {
  if (cond) console.log(`  ✓ ${msg}`);
  else {
    console.log(`  ✗ ${msg}`);
    failures++;
  }
}
/** One request through the proxy (absolute-form), returns the raw response. */
function viaProxy(proxyPort, shopPort, raw) {
  return new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, "127.0.0.1", () => s.write(raw.replace(" /", ` http://127.0.0.1:${shopPort}/`)));
    let out = "";
    s.on("data", (d) => (out += d));
    s.on("end", () => resolve(out));
    s.on("error", reject);
    setTimeout(() => s.destroy(), 5000);
  });
}
async function browseAs(proxy, shop, user, paths) {
  const body = JSON.stringify({ username: user, password: `${user}123` });
  const login = await viaProxy(proxy, shop, `POST /api/login HTTP/1.1\r\nHost: shop\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
  const session = login.split("session=")[1].split(";")[0];
  for (const p of paths) await viaProxy(proxy, shop, `GET ${p} HTTP/1.1\r\nHost: shop\r\nCookie: session=${session}\r\n\r\n`);
}

try {
  mkdirSync(SHOTS, { recursive: true });
  const [shop, proxy, ui] = [await freePort(), await freePort(), await freePort()];
  start(["demo-target", "--listen", `127.0.0.1:${shop}`]);
  writeFileSync(join(dir, "roe.yaml"), `version: 1\nscope:\n  include: ["http://127.0.0.1:${shop}/"]\n`);
  pm("roe", "use", join(dir, "roe.yaml"));
  let link = "";
  start(["ui", "--listen", `127.0.0.1:${ui}`, "--proxy", `127.0.0.1:${proxy}`, "--as", "human:tester"], (l) => {
    const m = l.match(/Open: (\S+)/);
    if (m) link = m[1];
  });
  for (let i = 0; i < 50 && !link; i++) await sleep(100);
  if (!link) throw new Error("proxymind ui did not print a login link");

  await browseAs(proxy, shop, "alice", ["/api/me", "/api/orders", "/api/orders/1001", "/api/invoices/5001"]);
  await browseAs(proxy, shop, "bob", ["/api/me"]);

  const exe = process.env.CHROMIUM ?? ["/opt/pw-browsers/chromium-1194/chrome-linux/chrome"].find(existsSync);
  const browser = await chromium.launch({ executablePath: exe });
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const consoleErrors = [];
  page.on("console", (m) => m.type() === "error" && consoleErrors.push(m.text()));
  page.on("pageerror", (e) => consoleErrors.push(String(e)));

  console.log("History");
  await page.goto(link);
  await page.waitForSelector('[role="row"][data-testid^="row-"]');
  check((await page.locator('[data-testid^="row-"]').count()) === 7, "history lists the 7 proxied requests");
  await page.screenshot({ path: join(SHOTS, "1-history.png") });

  // Capture alice from her /api/me request and bob from his.
  const rowFor = async (path, nth) => {
    await page.getByLabel("Path", { exact: true }).fill(path);
    await sleep(500);
    const rows = page.locator('[data-testid^="row-"]');
    const n = await rows.count();
    return rows.nth(n - 1 - nth); // newest first, so count from the end
  };
  for (const [who, nth] of [["alice", 0], ["bob", 1]]) {
    await (await rowFor("/api/me", nth)).click();
    await page.getByRole("button", { name: "Capture identity…" }).click();
    await page.getByLabel("Identity name").fill(who);
    await page.getByRole("button", { name: "Capture", exact: true }).click();
    await page.waitForSelector(`text=Identity "${who}" captured`);
  }
  check(true, "captured alice and bob from history");
  const order = await rowFor("/api/orders/1001", 0);
  const orderId = Number((await order.getAttribute("data-testid")).replace("row-", ""));
  await order.click();
  const shown = await page
    .locator('[data-testid="exchange-detail"] pre.raw', { hasText: "alice@vulnshop.test" })
    .first()
    .waitFor({ timeout: 5000 })
    .then(() => true, () => false);
  check(shown, "viewer shows the response");
  await page.screenshot({ path: join(SHOTS, "2-history-detail.png") });

  console.log("Authorization check");
  await page.getByRole("button", { name: "Authorization check…" }).click();
  await page.getByRole("checkbox", { name: "bob" }).check();
  await page.getByTestId("run-authz").click();
  await page.waitForSelector('[data-testid="authz-results"] >> text=same as owner');
  check(true, "bob gets alice's order: same as owner");
  check(await page.locator('[data-testid="authz-results"]').first().textContent().then((t) => t.includes("denied")), "anonymous is denied");
  await page.screenshot({ path: join(SHOTS, "3-authz.png") });

  console.log("Findings and proof");
  await page.getByRole("button", { name: "Findings" }).click();
  await page.getByRole("button", { name: "New finding" }).click();
  await page.getByLabel("Title").fill("Any user can read any order");
  await page.getByLabel("Severity").selectOption("high");
  await page.getByLabel("Evidence").fill(String(orderId));
  await page.getByRole("button", { name: "Save" }).click();
  await page.getByLabel("Attacker").selectOption("bob");
  await page.getByTestId("prove").click();
  await page.waitForSelector('[data-testid="proof-result"]');
  check(await page.getByTestId("proof-result").textContent().then((t) => t.startsWith("Proven")), "ProxyMind proves the IDOR");
  await page.waitForSelector('[data-testid="findings"] >> text=proven');
  check(true, "finding status becomes proven");
  await page.screenshot({ path: join(SHOTS, "4-findings.png") });

  console.log("Repeater");
  await page.goto(link.replace(/\/auth.*/, `/#/repeater/${orderId}`));
  await page.getByLabel("Send as").selectOption("anonymous");
  await page.getByTestId("send").click();
  await page.waitForSelector('[data-testid="replay-result"]');
  check(await page.getByTestId("replay-result").textContent().then((t) => t.includes("401")), "anonymous replay gets 401");
  await page.screenshot({ path: join(SHOTS, "5-repeater.png") });

  console.log("Approvals (an agent asks over MCP)");
  const mcp = start(["mcp", "--actor", "agent:claude"]);
  const replies = [];
  mcp.stdout.on("data", (d) => replies.push(...String(d).split("\n").filter(Boolean)));
  const rpc = (id, method, params) => mcp.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  rpc(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "1" } });
  rpc(2, "tools/call", { name: "replay_send", arguments: { url: `http://127.0.0.1:${shop}`, raw: "POST /api/orders HTTP/1.1\nHost: x\n\n{\"product_id\":1,\"qty\":-5}" } });
  for (let i = 0; i < 50 && replies.length < 2; i++) await sleep(100);
  await page.getByRole("button", { name: /^Approvals/ }).click();
  await page.waitForSelector('[data-testid="approvals-badge"]');
  check(true, "sidebar shows a pending approval badge (live update)");
  await page.screenshot({ path: join(SHOTS, "6-approvals.png") });
  await page.getByRole("button", { name: "Approve" }).click();
  await page.waitForSelector("text=Nothing is waiting for approval.");
  check(true, "approved from the UI");

  console.log("Intercept");
  await page.getByRole("button", { name: /^Intercept/ }).click();
  await page.getByLabel("Path filter").fill("/api/products/search");
  await page.getByRole("button", { name: "Apply" }).click();
  await page.getByTestId("intercept-toggle").click();
  await page.waitForSelector("text=Intercept is ON");
  const search = (q) => viaProxy(proxy, shop, `GET /api/products/search?q=${q} HTTP/1.1\r\nHost: shop\r\n\r\n`);
  const edited = search("held-original"); // waits in the queue until forwarded
  await page.waitForSelector('[data-testid="intercept-badge"]');
  await page.locator('[data-testid="intercept-queue"]', { hasText: "held-original" }).waitFor();
  check(true, "request is held and the sidebar shows a badge");
  const editor = page.getByLabel("Held message");
  await editor.fill((await editor.inputValue()).replace("held-original", "held-edited"));
  await page.screenshot({ path: join(SHOTS, "6b-intercept.png") });
  await page.getByTestId("intercept-forward").click();
  check((await edited).startsWith("HTTP/1.1 200"), "edited request is forwarded and answered");
  const dropped = search("held-drop");
  await page.locator('[data-testid="intercept-queue"]', { hasText: "held-drop" }).waitFor();
  await page.getByTestId("intercept-drop").click();
  check((await dropped).startsWith("HTTP/1.1 403"), "dropped request gets 403 from ProxyMind");
  await page.getByTestId("intercept-toggle").click();
  await page.waitForSelector("text=Intercept is OFF");
  await page.getByRole("button", { name: "History" }).click();
  await page.getByLabel("Path", { exact: true }).fill("held-");
  await sleep(500);
  const heldRows = await page.locator('[data-testid^="row-"]').allTextContents();
  check(heldRows.length === 1 && heldRows[0].includes("held-edited"), "history records the edited request only");

  console.log("Match and replace");
  await page.getByRole("button", { name: "Match & replace" }).click();
  await page.getByRole("button", { name: "Add rule" }).click();
  await page.getByLabel("Rule 1 replace").fill("X-E2E: rewritten");
  await page.getByRole("button", { name: "Add rule" }).click();
  await page.getByLabel("Rule 2 part").selectOption("response_body");
  await page.getByLabel("Rule 2 match").fill("results");
  await page.getByLabel("Rule 2 replace").fill("REWRITTEN");
  await page.getByTestId("rules-save").click();
  await page.waitForSelector("text=Saved 2 rule(s)");
  await page.screenshot({ path: join(SHOTS, "6c-rules.png") });
  const rewritten = await search("rules-check");
  check(rewritten.includes("REWRITTEN") && !rewritten.includes("results"), "response rule rewrites what the client gets");
  await page.getByRole("button", { name: "History" }).click();
  await page.getByLabel("Path", { exact: true }).fill("rules-check");
  await sleep(500);
  await page.locator('[data-testid^="row-"]').first().click();
  await page.getByRole("tab", { name: "request" }).click();
  const sent = await page
    .locator('[data-testid="exchange-detail"] pre.raw', { hasText: "X-E2E: rewritten" })
    .first()
    .waitFor({ timeout: 5000 })
    .then(() => true, () => false);
  check(sent, "history shows the request as sent, with the added header");

  console.log("WebSocket (a real browser chats through the proxy)");
  const loginBody = JSON.stringify({ username: "alice", password: "alice123" });
  const login = await viaProxy(proxy, shop, `POST /api/login HTTP/1.1\r\nHost: shop\r\nContent-Type: application/json\r\nContent-Length: ${loginBody.length}\r\n\r\n${loginBody}`);
  const session = login.split("session=")[1].split(";")[0];
  // "<-loopback>" makes Chromium use the proxy for 127.0.0.1 too.
  const viaPm = await browser.newContext({ proxy: { server: `http://127.0.0.1:${proxy}`, bypass: "<-loopback>" } });
  await viaPm.addCookies([{ name: "session", value: session, domain: "127.0.0.1", path: "/" }]);
  const chat = await viaPm.newPage();
  await chat.goto(`http://127.0.0.1:${shop}/api/products`);
  const chatReplies = await chat.evaluate(
    (url) =>
      new Promise((resolve, reject) => {
        const got = [];
        const ws = new WebSocket(url);
        ws.onmessage = (e) => {
          got.push(JSON.parse(e.data).text);
          if (got.length === 1) ws.send("Where is order 1001?");
          if (got.length === 2) ws.close(1000, "bye");
        };
        ws.onclose = () => resolve(got);
        ws.onerror = () => reject(new Error("WebSocket error"));
        setTimeout(() => reject(new Error("WebSocket timeout")), 5000);
      }),
    `ws://127.0.0.1:${shop}/ws/support`,
  );
  check(chatReplies.length === 2 && chatReplies[1].includes("Where is order 1001?"), "browser WebSocket works through the proxy");
  await viaPm.close();
  await page.getByRole("button", { name: "History" }).click();
  await page.getByLabel("Path", { exact: true }).fill("/ws/support");
  await sleep(500);
  await page.locator('[data-testid^="row-"]').first().click();
  const wsLogged = await page
    .locator('[data-testid="ws-messages"]', { hasText: "Where is order 1001?" })
    .waitFor({ timeout: 8000 })
    .then(() => true, () => false);
  check(wsLogged, "History shows the WebSocket messages both ways");
  await page.screenshot({ path: join(SHOTS, "6d-websocket.png") });

  console.log("HTTP/2 (Chromium ↔ ProxyMind ↔ an HTTP/2 server)");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-days", "1",
    "-keyout", join(dir, "h2.key"), "-out", join(dir, "h2.crt")], { stdio: "ignore" });
  const { createSecureServer } = await import("node:http2");
  const { readFileSync } = await import("node:fs");
  const h2srv = createSecureServer({ key: readFileSync(join(dir, "h2.key")), cert: readFileSync(join(dir, "h2.crt")) }, (req, res) => {
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<title>h2</title><p id="v">server saw HTTP/${req.httpVersion} ${req.url}</p>`);
  });
  await new Promise((r) => h2srv.listen(0, "127.0.0.1", r));
  const h2port = h2srv.address().port;
  const viaPm2 = await browser.newContext({
    proxy: { server: `http://127.0.0.1:${proxy}`, bypass: "<-loopback>" },
    ignoreHTTPSErrors: true, // trust ProxyMind's interception certificate
  });
  const h2page = await viaPm2.newPage();
  await h2page.goto(`https://localhost:${h2port}/h2-check`);
  const seen = await h2page.locator("#v").textContent();
  const hop = await h2page.evaluate(() => performance.getEntriesByType("navigation")[0].nextHopProtocol);
  check(hop === "h2" && seen === "server saw HTTP/2.0 /h2-check", `browser and server both speak HTTP/2 through ProxyMind (${hop}; ${seen})`);
  await viaPm2.close();
  h2srv.close();
  await page.getByRole("button", { name: "History" }).click();
  await page.getByLabel("Path", { exact: true }).fill("/h2-check");
  await sleep(500);
  await page.locator('[data-testid^="row-"]').first().click();
  await page.getByRole("tab", { name: "request" }).click();
  const h2text = await page
    .locator('[data-testid="exchange-detail"] pre.raw', { hasText: "GET /h2-check HTTP/2" })
    .waitFor({ timeout: 5000 })
    .then(() => true, () => false);
  check(h2text, "History shows the request in HTTP/2 text form");

  console.log("Network: upstream proxy");
  // A minimal upstream HTTP proxy that records request lines and forwards.
  const upstreamSeen = [];
  const upstream = net.createServer((c) => {
    let buf = Buffer.alloc(0);
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) return;
      c.off("data", onData);
      const line = buf.subarray(0, buf.indexOf("\r\n")).toString();
      upstreamSeen.push(line);
      const u = new URL(line.split(" ")[1]);
      const s = net.connect(Number(u.port), u.hostname, () => {
        // Like a real proxy: origin-form towards the server.
        s.write(Buffer.concat([Buffer.from(line.replace(`${u.protocol}//${u.host}`, "")), buf.subarray(buf.indexOf("\r\n"))]));
        c.pipe(s).pipe(c);
      });
      s.on("error", () => c.destroy());
    };
    c.on("data", onData);
    c.on("error", () => {});
  });
  await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
  await page.getByRole("button", { name: "Network" }).click();
  await page.getByTestId("upstream-toggle").check();
  await page.getByLabel("Proxy host").fill("127.0.0.1");
  await page.getByLabel("Proxy port").fill(String(upstream.address().port));
  await page.getByLabel("Bypass list").fill("");
  await page.getByTestId("network-save").click();
  await page.waitForSelector("text=Saved. The proxy");
  await page.screenshot({ path: join(SHOTS, "6e-network.png") });
  const viaUpstream = await search("via-upstream");
  check(viaUpstream.startsWith("HTTP/1.1 200") && upstreamSeen.some((l) => l.includes("q=via-upstream")), "traffic goes through the upstream proxy");
  await page.getByTestId("upstream-toggle").uncheck();
  await page.getByTestId("network-save").click();
  await page.waitForSelector("text=Saved. The proxy");
  const n = upstreamSeen.length;
  await search("direct-again");
  check(upstreamSeen.length === n, "turning it off connects directly again");
  upstream.close();

  console.log("Model, coverage and audit");
  await page.getByRole("button", { name: "Model & Coverage" }).click();
  await page.locator('[data-testid="operations"] strong', { hasText: "/api/orders/{id}" }).waitFor();
  check(true, "model shows /api/orders/{id}");
  await page.screenshot({ path: join(SHOTS, "7-model.png"), fullPage: true });
  await page.getByRole("button", { name: "Audit log" }).click();
  await page.waitForSelector('[data-testid="audit-verify"]');
  check(await page.getByTestId("audit-verify").textContent().then((t) => t.includes("intact")), "audit log verified intact");
  await page.screenshot({ path: join(SHOTS, "8-audit.png") });

  // A fresh browser without the cookie is refused.
  const other = await browser.newPage();
  await other.goto(link.replace(/\/auth.*/, "/"));
  await other.waitForSelector("text=Not signed in");
  check(true, "a browser without the token sees 'Not signed in'");

  check(consoleErrors.length === 0, `no console errors${consoleErrors.length ? ": " + consoleErrors.join(" | ") : ""}`);
  await browser.close();
} catch (e) {
  console.error(e);
  failures++;
} finally {
  for (const c of children) c.kill();
}
console.log(failures ? `\n${failures} check(s) failed` : `\nAll UI checks passed. Screenshots: ${SHOTS}`);
process.exit(failures ? 1 : 0);
