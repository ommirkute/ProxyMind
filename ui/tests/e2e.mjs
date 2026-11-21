// Browser end-to-end test of the ProxyMind UI against VulnShop.
//
//   npm run build && (cd .. && cargo build) && npm run test:e2e
//
// Uses the real `proxymind` binary (PROXYMIND, default ../target/debug/proxymind)
// and Chromium (CHROMIUM, default: Playwright's bundled path).
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, existsSync, readdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import http from "node:http";
import { X509Certificate, createHmac } from "node:crypto";
import { chromium } from "playwright-core";

const BIN = process.env.PROXYMIND ?? new URL("../../target/debug/proxymind", import.meta.url).pathname;
const SHOTS = process.env.SCREENSHOTS ?? join(tmpdir(), "proxymind-ui-shots");
// ProxyMind's own browser window opens headless here (no display in CI).
process.env.PROXYMIND_BROWSER_HEADLESS ??= "1";
// CI runners (non-root Ubuntu) can't use Chromium's sandbox for Playwright's build: the built-in
// browser window would abort. The test runs in a throwaway machine, so run it without the sandbox.
process.env.PROXYMIND_CHROMIUM_NO_SANDBOX ??= "1";
// The machine's LAN address for phones: fixed, so the mobile section does not depend on the runner's network.
process.env.PROXYMIND_LAN_ADDR ??= "192.0.2.10";
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
/** Goes to a page by its route (the top tabs and sub-tabs are tested separately). */
let page;
async function open(id) {
  await page.evaluate((h) => (window.location.hash = h), `#/${id}`);
  await page.waitForFunction((h) => window.location.hash === h, `#/${id}`);
}
function check(cond, msg) {
  if (cond) console.log(`  ✓ ${msg}`);
  else {
    console.log(`  ✗ ${msg}`);
    failures++;
  }
}
/**
 * Runs one part of the test. If it throws, the failure is counted, a screenshot is saved and the page is reloaded,
 * and the next part still runs: one broken page doesn't hide the state of the others.
 */
async function section(name, body) {
  console.log(name);
  try {
    await body();
  } catch (e) {
    failures++;
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    console.log(`  ✗ ${name} stopped: ${String(e?.message ?? e).split("\n")[0]} (screenshot failed-${slug}.png)`);
    await page?.screenshot({ path: join(SHOTS, `failed-${slug}.png`), fullPage: true }).catch(() => {});
    await page?.keyboard.press("Escape").catch(() => {});
    await page?.reload().catch(() => {});
  }
}
/**
 * Runs `body` with the page's timers frozen: Playwright's fake clock is paused, so no setTimeout/setInterval callback
 * in the page can fire (and none can be re-armed). A page that polls on a timer cannot get its progress while this
 * runs; one driven by server events can. Time flows again afterwards.
 */
async function withFrozenTimers(body) {
  const now = Date.now();
  await page.clock.install({ time: now });
  await page.clock.pauseAt(now + 60_000);
  try {
    await body();
  } finally {
    await page.clock.resume();
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
/**
 * The id of the newest recorded exchange whose path contains `path`. The proxy records in the background, in short
 * batches, so a request sent a moment ago may not be listed yet: poll for up to 5 s. Returns null if it never shows.
 */
function recordedId(path) {
  return page.evaluate(async (path) => {
    for (let i = 0; i < 50; i++) {
      const q = new URLSearchParams({ path, limit: "1" });
      const row = (await (await fetch(`/api/v1/exchanges?${q}`)).json()).exchanges[0];
      if (row) return row.id;
      await new Promise((r) => setTimeout(r, 100));
    }
    return null;
  }, path);
}
/** One raw request straight to a port (an invisible client), returns the raw response. */
function rawTo(port, raw) {
  return new Promise((resolve, reject) => {
    const s = net.connect(port, "127.0.0.1", () => s.write(raw));
    let out = "";
    s.on("data", (d) => (out += d));
    s.on("end", () => resolve(out));
    s.on("error", reject);
    setTimeout(() => s.destroy(), 5000);
  });
}
/**
 * A minimal SOCKS5 client (RFC 1928, login per RFC 1929) over node:net, no dependencies. Resolves with the connected
 * socket, or rejects with `socks5 refused: ...` saying which step the server turned the client away at.
 */
function socks5Connect(proxyPort, host, port, login) {
  return new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, "127.0.0.1");
    let buf = Buffer.alloc(0);
    let stage = "greeting";
    const fail = (why) => {
      s.destroy();
      reject(new Error(`socks5 refused: ${why}`));
    };
    const request = () => {
      const name = Buffer.from(host);
      stage = "reply";
      s.write(Buffer.concat([Buffer.from([5, 1, 0, 3, name.length]), name, Buffer.from([port >> 8, port & 255])]));
    };
    s.on("connect", () => s.write(login ? Buffer.from([5, 2, 0, 2]) : Buffer.from([5, 1, 0])));
    s.on("error", reject);
    s.on("close", () => stage !== "done" && reject(new Error("socks5 refused: connection closed")));
    s.on("data", function onData(d) {
      buf = Buffer.concat([buf, d]);
      if (stage === "greeting" && buf.length >= 2) {
        const method = buf[1];
        buf = buf.subarray(2);
        if (method === 0xff) return fail("no acceptable method");
        if (method === 2) {
          const u = Buffer.from(login.username);
          const p = Buffer.from(login.password);
          stage = "login";
          s.write(Buffer.concat([Buffer.from([1, u.length]), u, Buffer.from([p.length]), p]));
        } else request();
      }
      if (stage === "login" && buf.length >= 2) {
        const ok = buf[1] === 0;
        buf = buf.subarray(2);
        if (!ok) return fail("login rejected");
        request();
      }
      if (stage === "reply" && buf.length >= 10) {
        if (buf[1] !== 0) return fail(`reply code ${buf[1]}`);
        stage = "done";
        s.off("data", onData);
        resolve(s);
      }
    });
    setTimeout(() => stage !== "done" && fail("timeout"), 5000);
  });
}
/** One raw request through a SOCKS5 server, returns the raw response. */
async function viaSocks5(proxyPort, host, port, raw, login) {
  const s = await socks5Connect(proxyPort, host, port, login);
  return new Promise((resolve, reject) => {
    let out = "";
    s.on("data", (d) => (out += d));
    s.on("end", () => resolve(out));
    s.on("error", reject);
    s.write(raw);
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
  // proxymind renders XSS proofs in the same Chromium the test drives.
  // A preinstalled Playwright Chromium (newest build; older builds use chrome-linux/, newer chrome-linux64/).
  const preinstalled = () => {
    try {
      return readdirSync("/opt/pw-browsers")
        .filter((d) => /^chromium-\d+$/.test(d))
        .sort((a, b) => Number(b.slice(9)) - Number(a.slice(9)))
        .flatMap((d) => ["chrome-linux64", "chrome-linux"].map((sub) => `/opt/pw-browsers/${d}/${sub}/chrome`))
        .find(existsSync);
    } catch {
      return undefined;
    }
  };
  const exe = process.env.CHROMIUM ?? preinstalled();
  const browserPath = exe ?? chromium.executablePath();
  if (existsSync(browserPath)) process.env.PROXYMIND_CHROMIUM ??= browserPath;
  const [shop, proxy, ui] = [await freePort(), await freePort(), await freePort()];
  // Receivers for the integrations section: a webhook, and a GitHub that creates issues. They record what they get.
  const [hookPort, ghPort] = [await freePort(), await freePort()];
  const hookGot = [];
  const ghGot = [];
  const receiver = (log, port, answer) =>
    http
      .createServer((req, res) => {
        let body = "";
        req.on("data", (d) => (body += d));
        req.on("end", () => {
          log.push({ method: req.method, url: req.url, headers: req.headers, body });
          const [code, out] = answer(req);
          res.writeHead(code, { "content-type": "application/json" });
          res.end(out);
        });
      })
      .listen(port, "127.0.0.1");
  const receivers = [
    receiver(hookGot, hookPort, () => [200, "{}"]),
    receiver(ghGot, ghPort, (r) =>
      r.method === "POST" ? [201, JSON.stringify({ number: 42, html_url: "https://github.com/acme/app/issues/42" })] : [200, JSON.stringify({ full_name: "acme/app" })]),
  ];
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

  const browser = await chromium.launch({ executablePath: exe });
  page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const consoleErrors = [];
  page.on("console", (m) => m.type() === "error" && consoleErrors.push(`${m.text()}${m.location()?.url ? ` (${m.location().url})` : ""}`));
  const failedResponses = [];
  page.on("response", async (r) => {
    if (r.status() < 400) return;
    const body = await r.text().catch(() => "");
    failedResponses.push(`${r.status()} ${r.request().method()} ${r.url()} ${body.slice(0, 300)}`);
  });
  page.on("pageerror", (e) => consoleErrors.push(String(e)));

  // Shared between sections (each section runs on its own: a failure is recorded and the next one runs).
  let rowFor, order, orderId, shown, frame, target, search, edited, login, session, n, model;
  await section("History", async () => {
    await page.goto(link);
    // The proxy records on a background thread: wait for all 7 to arrive (live updates add them).
    await page.waitForFunction(() => document.querySelectorAll('[data-testid^="row-"]').length >= 7, null, { timeout: 15000 }).catch(() => {});
    check((await page.locator('[data-testid^="row-"]').count()) === 7, "history lists the 7 proxied requests");
    await page.screenshot({ path: join(SHOTS, "1-history.png") });

    // Capture alice from her /api/me request and bob from his.
    rowFor = async (path, nth) => {
      await page.getByLabel("Filter", { exact: true }).fill(path);
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
  });

  await section("Overview", async () => {
    await open("overview");
    await page.getByRole("heading", { name: "Overview" }).waitFor();
    check(await page.locator(".stat").count() === 4, "the overview shows the workspace at a glance");
    await page.screenshot({ path: join(SHOTS, "0-overview.png") });
    await page.getByRole("button", { name: /^Theme:/ }).click();
    await page.getByRole("button", { name: /^Theme:/ }).click();
    check(await page.evaluate(() => document.documentElement.dataset.theme) === "dark", "the theme can be switched to dark");
    await sleep(400);
    await page.screenshot({ path: join(SHOTS, "0-overview-dark.png") });
    await open("history");
    await page.screenshot({ path: join(SHOTS, "0-history-dark.png") });
    await page.getByRole("button", { name: /^Theme:/ }).click();
    await page.keyboard.press("Control+k");
    await page.getByLabel("Go to", { exact: true }).fill("replay");
    await page.screenshot({ path: join(SHOTS, "0-palette.png") });
    await page.keyboard.press("Enter");
    check(await page.evaluate(() => location.hash) === "#/replay", "the command palette jumps to a page");
  });

  await section("Proxy: top tabs, HTTP history tools", async () => {
    await page.getByTestId("tab-dashboard").click();
    await page.getByRole("button", { name: "Findings" }).waitFor();
    await page.getByTestId("tab-proxy").click();
    await page.getByRole("button", { name: "HTTP history" }).click();
    check(await page.evaluate(() => location.hash) === "#/history", "top tab and sub-tab open HTTP history");
    await page.getByLabel("Filter", { exact: true }).fill("");
    await sleep(400);
    const firstRow = page.locator('[data-testid^="row-"]').first();
    await firstRow.click({ button: "right" });
    await page.getByLabel("Highlight red").first().click();
    await page.waitForSelector('[data-testid^="row-"].hl-red');
    page.once("dialog", (d) => d.accept("check this one"));
    await page.locator('[data-testid^="row-"].hl-red').click({ button: "right" });
    await page.getByRole("menuitem", { name: /comment/ }).click();
    await page.locator('[data-testid="comment-cell"]', { hasText: "check this one" }).waitFor();
    check(true, "right-click menu highlights and comments a row");
    await page.getByTestId("annotated-only").check();
    await sleep(500);
    check((await page.locator('[data-testid^="row-"]').count()) === 1, "filter shows only annotated rows");
    await page.getByTestId("annotated-only").uncheck();
    await sleep(400);
    await page.getByRole("columnheader", { name: /Status/ }).click();
    check(await page.getByRole("columnheader", { name: /Status/ }).getAttribute("aria-sort") === "ascending", "columns sort");
    await page.getByRole("columnheader", { name: /^#/ }).click();
    await page.locator('[data-testid^="row-"]').first().click();
    await page.getByRole("tab", { name: "Response", exact: true }).click();
    await page.locator('[data-testid="response-view"]').getByRole("button", { name: "Hex" }).click();
    await page.locator('[data-testid="response-view"] pre', { hasText: "00000000  48 54 54 50" }).waitFor();
    check(true, "hex view shows the exact bytes");
    await page.locator('[data-testid="response-view"]').getByRole("button", { name: "Pretty" }).click();
    await page.locator('[data-testid="response-view"]').getByLabel("Search in message").fill("HTTP/1.1");
    check(await page.locator('[data-testid="response-view"] [data-testid="search-count"]').textContent() === "1 match", "search in a message counts matches");
    await page.getByLabel("Query", { exact: true }).fill('path:/api/orders/ resp:"alice@"');
    await page.getByLabel("Query", { exact: true }).press("Enter");
    await page.waitForSelector('[data-testid="query-scanned"]');
    const qRows = await page.locator('[data-testid^="row-"]').allTextContents();
    check(qRows.length > 0 && qRows.every((t) => t.includes("/api/orders/")), `a query filters by path and response text (${qRows.length} rows)`);
    page.once("dialog", (d) => d.accept("alice orders"));
    await page.getByTestId("save-filter").click();
    await page.getByLabel("Query", { exact: true }).fill("stauts:200");
    await page.getByLabel("Query", { exact: true }).press("Enter");
    await page.locator(".error", { hasText: "unknown field" }).waitFor();
    // The browser logs the expected 400; it is matched by its URL at the end, whenever it arrives.
    check(true, "a mistyped field is reported");
    // New traffic while the bad query is shown must not re-send it (live updates wait for a good query).
    const typoErrors = () => consoleErrors.filter((e) => e.includes("q=stauts%3A200")).length;
    await sleep(500);
    const errorsAfterTypo = typoErrors();
    const lastId = await page.evaluate(async () => (await (await fetch("/api/v1/status")).json()).counters?.last_exchange_id ?? 0);
    await viaProxy(proxy, shop, "GET /api/products HTTP/1.1\r\nHost: shop\r\n\r\n");
    await page.waitForFunction(
      async (id) => ((await (await fetch("/api/v1/status")).json()).counters?.last_exchange_id ?? 0) > id,
      lastId,
    );
    await sleep(2500);
    check(typoErrors() === errorsAfterTypo, "live updates don't re-send a mistyped query");
    await page.getByLabel("Saved filters").selectOption("alice orders");
    await page.waitForFunction(() => document.querySelector('input[aria-label="Query"]').value.includes("alice@"));
    await page.waitForSelector('[data-testid="query-scanned"]');
    check(true, "a saved filter comes back from the list");
    await page.getByRole("button", { name: "Query help" }).click();
    await page.getByTestId("query-help").waitFor();
    await page.screenshot({ path: join(SHOTS, "1c-history-query.png") });
    await page.getByRole("button", { name: "Query help" }).click();
    await page.getByTestId("clear-query").click();
    await sleep(400);
    await viaProxy(proxy, shop, "GET /openapi.json HTTP/1.1\r\nHost: shop\r\nConnection: close\r\n\r\n");
    const capped = await page.evaluate(async () => {
      for (let i = 0; i < 20; i++) {
        const big = (await (await fetch("/api/v1/exchanges?q=len:>1500&limit=1")).json()).exchanges[0];
        if (big) {
          const d = await (await fetch(`/api/v1/exchanges/${big.id}?max=1024`)).json();
          return d.response_truncated > 1500 && d.response.length <= 1024 ? "ok" : JSON.stringify(d).slice(0, 200);
        }
        await new Promise((r) => setTimeout(r, 200));
      }
      return "none";
    });
    check(capped === "ok", `big messages can be fetched cut short (${capped})`);
    await page.screenshot({ path: join(SHOTS, "1b-history-tools.png") });
    order = await rowFor("/api/orders/1001", 0);
    orderId = Number((await order.getAttribute("data-testid")).replace("row-", ""));
    await order.click();
    shown = await page
      .locator('[data-testid="exchange-detail"] pre.raw', { hasText: "alice@vulnshop.test" })
      .first()
      .waitFor({ timeout: 5000 })
      .then(() => true, () => false);
    check(shown, "viewer shows the response");
    await page.screenshot({ path: join(SHOTS, "2-history-detail.png") });
  });

  await section("Authorization check", async () => {
    await page.getByRole("button", { name: "Authorization check…" }).click();
    await page.getByRole("checkbox", { name: "bob" }).check();
    await page.getByTestId("run-authz").click();
    await page.waitForSelector('[data-testid="authz-results"] >> text=same as owner');
    check(true, "bob gets alice's order: same as owner");
    check(await page.locator('[data-testid="authz-results"]').first().textContent().then((t) => t.includes("denied")), "anonymous is denied");

    await page.screenshot({ path: join(SHOTS, "3-authz.png") });
  });

  const HOOK_SECRET = "e2e-signing-secret-0123456789";
  const GH_TOKEN = "ghp_e2eTokenValue0123456789abcdef";
  await section("Integrations: set up a webhook and a GitHub repository", async () => {
    await open("integrations");
    await page.getByTestId("add-integration").click();
    await page.getByLabel("Integration kind").selectOption("webhook");
    await page.getByLabel("Integration name").fill("e2e-hook");
    await page.getByLabel("Integration URL").fill(`http://127.0.0.1:${hookPort}/hook`);
    await page.getByLabel("Integration signing secret").fill(HOOK_SECRET);
    await page.getByLabel("Event Finding proven").check();
    await page.getByTestId("save-integration").click();
    await page.getByTestId("integration-e2e-hook").waitFor();
    // Private destinations are off by default: the first test is refused, and nothing reaches the receiver.
    await page.getByTestId("send-test-e2e-hook").click();
    await page.waitForFunction(() => document.querySelector('[data-testid="integration-error"]')?.textContent?.includes("private or loopback"));
    check(hookGot.length === 0, "a loopback destination is refused until it is allowed for that integration");
    await page.getByRole("button", { name: "Edit" }).click();
    await page.getByLabel("Allow private destinations").check();
    await page.getByTestId("save-integration").click();
    await page.waitForFunction(() => document.querySelector('[data-testid="integration-e2e-hook"]')?.textContent?.includes("private destinations allowed"));
    await page.getByTestId("send-test-e2e-hook").click();
    await page.waitForFunction(() => document.querySelector('[data-testid="deliveries-e2e-hook"]')?.textContent?.includes("test"));
    for (let i = 0; i < 50 && !hookGot.length; i++) await sleep(100);
    check(hookGot.length === 1 && JSON.parse(hookGot[0].body).event === "test", "Send test posts a test event to the webhook");
    const sig = "sha256=" + createHmac("sha256", HOOK_SECRET).update(hookGot[0].body).digest("hex");
    check(hookGot[0].headers["x-proxymind-signature"] === sig, "the test event is signed with HMAC-SHA256 over the body");
    check(!(await page.content()).includes(HOOK_SECRET), "the signing secret is never shown in the page");
    check((await page.getByTestId("integration-e2e-hook").textContent()).includes("signing_secret: saved"), "the page says where the secret is kept");

    await page.getByTestId("add-integration").click();
    await page.getByLabel("Integration kind").selectOption("github");
    await page.getByLabel("Integration name").fill("e2e-gh");
    await page.getByLabel("Integration URL").fill(`http://127.0.0.1:${ghPort}`);
    await page.getByLabel("Integration project").fill("acme/app");
    await page.getByLabel("Integration token").fill(GH_TOKEN);
    await page.getByLabel("Allow private destinations").check();
    await page.getByTestId("save-integration").click();
    await page.getByTestId("integration-e2e-gh").waitFor();
    await page.getByTestId("send-test-e2e-gh").click();
    await page.waitForFunction(() => document.querySelector('[data-testid="deliveries-e2e-gh"]')?.textContent?.includes("test"));
    check(ghGot.length === 1 && ghGot[0].url === "/repos/acme/app" && ghGot[0].headers.authorization === `Bearer ${GH_TOKEN}`, "the GitHub test reads the repository with the token");
    check(!(await page.content()).includes(GH_TOKEN), "the token is never shown in the page");
    await page.screenshot({ path: join(SHOTS, "integrations.png") });
  });

  await section("Findings and proof", async () => {
    await open("findings");
    await page.getByRole("button", { name: "New finding" }).click();
    await page.getByLabel("Title").fill("Any user can read any order");
    await page.getByLabel("Severity").selectOption("high");
    await page.getByLabel("Evidence").fill(String(orderId));
    await page.getByRole("button", { name: "Save" }).click();
    // A suspected finding offers Auto-prove (pick an oracle by class) before it is proven.
    await page.getByTestId("auto-prove").waitFor({ timeout: 15000 });
    check(true, "a suspected finding offers Auto-prove");
    await page.getByLabel("Attacker").selectOption("bob");
    await page.getByTestId("prove").click();
    await page.waitForSelector('[data-testid="proof-result"]');
    check(await page.getByTestId("proof-result").textContent().then((t) => t.startsWith("Proven")), "ProxyMind proves the IDOR");
    await page.waitForSelector('[data-testid="findings"] >> text=proven');
    check(true, "finding status becomes proven");
    await page.screenshot({ path: join(SHOTS, "4-findings.png") });
    for (const f of ["html", "sarif"]) {
      const [dl] = await Promise.all([page.waitForEvent("download"), page.getByTestId(`report-${f}`).click()]);
      const text = await (await dl.createReadStream()).toArray().then((c) => Buffer.concat(c).toString());
      check(f === "html" ? text.includes("Any user can read any order") && text.includes("default-src 'none'") : JSON.parse(text).version === "2.1.0", `${f} report downloads`);
    }
  });

  await section("Issue library, retest and report builder", async () => {
    await page.getByTestId("issue-card").waitFor();
    check(await page.getByTestId("issue-card").textContent().then((t) => t.includes("Broken object level authorization") && t.includes("CWE-639")),
      "the finding shows its issue library entry");
    await page.getByTestId("retest").click();
    await page.waitForSelector('[data-testid="retest-result"]', { timeout: 30000 });
    check(await page.getByTestId("retest-result").textContent().then((t) => t.includes("reproduced") && t.includes("proof still holds")),
      "retest re-runs the proof");
    await open("evidence");
    await page.getByTestId("evidence-fingerprint").waitFor();
    const [packDl] = await Promise.all([page.waitForEvent("download"), page.getByTestId("evidence-download").click()]);
    const packPath = join(dir, "evidence.zip");
    await packDl.saveAs(packPath);
    await page.getByLabel("Evidence pack file").setInputFiles(packPath);
    await page.locator('[data-testid="evidence-verdict"]', { hasText: "verified" }).waitFor({ timeout: 15000 });
    check(await page.getByTestId("evidence-verdict").textContent().then((t) => t.includes("signature") && t.includes("hash chain intact")), "an evidence pack downloads and verifies (signature, files, audit chain, scope)");
    await page.getByTestId("regress-summary").waitFor();
    check(await page.getByTestId("regress-summary").textContent().then((t) => /^[1-9]\d* test/.test(t.trim())), "the proven IDOR becomes a CI regression test");
    await page.getByTestId("coverage-summary").waitFor();
    check(await page.getByTestId("coverage-summary").textContent().then((t) => /\d+(\.\d+)?% tested/.test(t)), "the coverage proof shows how much was tested");
    await page.screenshot({ path: join(SHOTS, "4b-evidence.png") });
    await open("findings");
    await page.locator('[data-testid="report-builder"] summary').first().click();
    await page.getByLabel("Report template").selectOption("executive");
    await page.getByLabel("Report format").selectOption("md");
    {
      const [dl] = await Promise.all([page.waitForEvent("download"), page.getByTestId("report-download").click()]);
      const text = await (await dl.createReadStream()).toArray().then((c) => Buffer.concat(c).toString());
      check(text.includes("executive summary") && text.includes("Overall risk:** high"), "executive Markdown report downloads");
    }
    await page.getByLabel("Report template").selectOption("compliance");
    await page.getByLabel("Report format").selectOption("html");
    await page.getByTestId("report-preview").click();
    frame = page.frameLocator('iframe[title="Report preview"]');
    await frame.locator("text=A01:2021 Broken Access Control").first().waitFor({ timeout: 10000 });
    check(true, "compliance report preview groups findings by OWASP category");
    await page.screenshot({ path: join(SHOTS, "4c-report-builder.png"), fullPage: true });
    await open("library");
    await page.getByLabel("Search the library").fill("CWE-89");
    await page.locator('[data-testid="library"] strong', { hasText: "SQL injection" }).first().click();
    await page.getByTestId("issue-card").getByText("parameterised queries").first().waitFor();
    check(true, "the issue library is searchable by CWE");
    await page.screenshot({ path: join(SHOTS, "4d-library.png") });
    await open("findings");
  });

  await section("XSS proof", async () => {
    await page.getByRole("button", { name: "New finding" }).click();
    await page.getByLabel("Title").fill("Reflected XSS in search");
    await page.getByLabel("Class").selectOption("xss");
    await page.getByLabel("Evidence").fill(String(orderId));
    await page.getByRole("button", { name: "Save" }).click();
    await page.getByLabel("XSS request").fill("GET /search?q={{xss_url}} HTTP/1.1\nHost: shop\n\n");
    await page.getByTestId("prove-xss").click();
    await page.waitForSelector('[data-testid="proof-result"]', { timeout: 60000 });
    check(await page.getByTestId("proof-result").textContent().then((t) => t.startsWith("Proven") && t.includes("ran the injected script")),
      "a headless browser runs the reflected payload");
    await page.screenshot({ path: join(SHOTS, "4b-xss-proof.png") });
  });

  await section("Replay", async () => {
    await page.goto(link.replace(/\/auth.*/, `/#/replay/${orderId}`));
    await page.locator(".rtab.active", { hasText: `#${orderId}` }).waitFor();
    check(await page.evaluate(() => location.hash) === "#/replay", "a request sent from History opens in its own tab");
    await page.getByLabel("Send as").selectOption("anonymous");
    await page.getByTestId("send").click();
    await page.waitForSelector('[data-testid="replay-result"]');
    check(await page.getByTestId("replay-result").textContent().then((t) => t.includes("401")), "anonymous replay gets 401");
    // Second send as written, then back to the first: history per tab.
    await page.getByLabel("Send as").selectOption("");
    await page.getByLabel("Raw request").press("Control+Enter");
    await page.locator('[data-testid="replay-result"]', { hasText: "200" }).waitFor();
    await page.getByLabel("Previous request").click();
    await page.locator('[data-testid="replay-result"]', { hasText: "401" }).waitFor();
    check(true, "Ctrl+Enter sends, and ‹ › step through the tab's history");
    await page.getByLabel("Next request").click();
    await page.locator('[data-testid="replay-result"]', { hasText: "200" }).waitFor();
    // Pretty and Render read the decoded body (not the model view, which is cut and keeps no markup).
    await page.locator('[data-testid="replay-response"] button', { hasText: "Pretty" }).click();
    check(await page.locator('[data-testid="replay-response"] pre').textContent().then((t) => /\{\n {2}"/.test(t)), "Replay's Pretty view indents the JSON response");
    await page.getByLabel("Raw request").fill(`GET /search?q=pretty-check HTTP/1.1\nHost: shop\n\n`);
    await page.getByTestId("send").click();
    await page.locator('[data-testid="replay-result"]', { hasText: "200" }).waitFor();
    await page.locator('[data-testid="replay-response"] pre', { hasText: "pretty-check" }).waitFor();
    check(await page.locator('[data-testid="replay-response"] pre').textContent().then((t) => t.includes("<h1>Search</h1>")), "Replay's Pretty view shows an HTML response with its tags");
    await page.locator('[data-testid="replay-response"] button', { hasText: "Render" }).click();
    check(await page.getByTestId("render-frame").contentFrame().locator("h1").textContent() === "Search", "Replay's Render view draws the HTML page");
    await page.locator('[data-testid="replay-response"] button', { hasText: "Pretty" }).click();
    // Inspector: edit a header value in place.
    await page.getByLabel("Raw request").fill(`GET /search?q=shoes&page=1 HTTP/1.1\nHost: shop\nCookie: a=1; theme=dark\n\n`);
    // The raw request is re-rendered after each edit: wait for it rather than read it at once.
    const rawBecomes = (pred) =>
      page
        .waitForFunction(`(() => { const v = document.querySelector('[aria-label="Raw request"]')?.value ?? ""; return ${pred}; })()`, null, { timeout: 5000 })
        .then(() => true, () => false);
    const qField = page.getByLabel("Query parameters q");
    await qField.fill("boots");
    await qField.press("Enter");
    check(await rawBecomes('v.startsWith("GET /search?q=boots&page=1 ")'), "Inspector edits a query parameter");
    await page.getByLabel("Cookies theme").fill("light");
    await page.getByLabel("Cookies theme").press("Enter");
    check(await rawBecomes('v.includes("Cookie: a=1; theme=light")'), "Inspector edits a cookie");
    await page.getByLabel("Protocol").selectOption("HTTP/2");
    await page.getByLabel("HTTP/2 pseudo-headers :path").fill("/search?q=h2");
    await page.getByLabel("HTTP/2 pseudo-headers :path").press("Enter");
    await page.getByLabel("HTTP/2 pseudo-headers :authority").fill("other.test");
    await page.getByLabel("HTTP/2 pseudo-headers :authority").press("Enter");
    check(await rawBecomes('v.startsWith("GET /search?q=h2 HTTP/2\\n") && v.includes("host: other.test") && v.includes("cookie: a=1")'),
      "Inspector switches to HTTP/2 and edits :path and :authority");
    await page.getByLabel("Protocol").selectOption("HTTP/1.1");
    // Inline transforms: select a value in the raw editor, preview Base64, apply, undo.
    const rawEditor = page.getByLabel("Raw request");
    await rawEditor.fill(`GET /search?q=boots&page=1 HTTP/1.1\nHost: shop\n\n`);
    const selectRaw = (text) =>
      rawEditor.evaluate((el, t) => { el.focus(); const i = el.value.indexOf(t); el.setSelectionRange(i, i + t.length); }, text);
    await page.getByTestId("transform-open").click();
    check(await page.getByTestId("transform-need-selection").isVisible(), "Transform without a selection explains that one is needed");
    await page.getByTestId("transform-close").click();
    await selectRaw("boots");
    await page.getByRole("button", { name: "Transform", exact: true }).click();
    check(await page.getByTestId("transform-before").textContent() === "boots", "Transform shows the selected text as the 'before'");
    // The preview re-renders after each choice; wait for the expected text, not just the element (it stays mounted).
    const afterBecomes = (text) =>
      page
        .waitForFunction((t) => document.querySelector('[data-testid="transform-after"]')?.textContent === t, text, { timeout: 5000 })
        .then(() => true, () => false);
    await page.getByLabel("Transform operation").selectOption("base64_encode");
    check(await afterBecomes("Ym9vdHM="), "Transform previews the Base64 of the selection");
    check(await rawBecomes('v.startsWith("GET /search?q=boots&page=1 ")'), "the preview does not change the raw request");
    await page.getByTestId("transform-apply").click();
    check(await rawBecomes('v.startsWith("GET /search?q=Ym9vdHM=&page=1 ")'), "Apply replaces the selection with the encoded value");
    check(await rawEditor.evaluate((el) => el.value.slice(el.selectionStart, el.selectionEnd)) === "Ym9vdHM=", "the applied result stays selected for chaining");
    await page.getByLabel("Transform operation").selectOption("url_encode");
    check(await afterBecomes("Ym9vdHM%3D"), "a second transform chains onto the result");
    await page.getByTestId("transform-apply").click();
    check(await rawBecomes('v.startsWith("GET /search?q=Ym9vdHM%3D&page=1 ")'), "the chained transform is applied");
    await page.getByTestId("transform-undo").click();
    check(await rawBecomes('v.startsWith("GET /search?q=Ym9vdHM=&page=1 ")'), "Undo restores the previous text");
    await page.getByTestId("transform-undo").click();
    check(await rawBecomes('v.startsWith("GET /search?q=boots&page=1 ")'), "a second Undo restores the original text");
    check(await page.getByTestId("transform-undo").isDisabled(), "Undo is disabled when the stack is empty");
    await page.getByLabel("Transform operation").selectOption("base64_decode");
    // The preview is computed after the choice renders: wait for it like the other previews above.
    const decodeError = await page.getByTestId("transform-error").waitFor({ timeout: 5000 }).then(() => true, () => false);
    check(decodeError && await page.getByTestId("transform-apply").isDisabled(),
      "an invalid decode shows an error in the preview and cannot be applied");
    await page.getByTestId("transform-close").click();
    await page.getByRole("button", { name: "New tab" }).click();
    check((await page.locator(".rtab").count()) >= 3, "tabs can be added");
    await page.screenshot({ path: join(SHOTS, "5-replay.png") });
    await sleep(900); // saved after a short pause
    await page.reload();
    await page.locator(".rtab", { hasText: `#${orderId}` }).waitFor();
    check(true, "Replay tabs survive a reload (saved in the project)");
  });

  await section("cURL and HAR", async () => {
    await page.goto(link.replace(/\/auth.*/, `/#/history/${orderId}`));
    await page.getByTestId("copy-curl").click();
    await page.waitForSelector('[data-testid="curl-command"]');
    const curlCmd = await page.getByTestId("curl-command").textContent();
    check(curlCmd.startsWith("curl ") && curlCmd.includes("/api/orders/"), "copy as cURL");
    await page.goto(link.replace(/\/auth.*/, "/#/replay"));
    await page.getByTestId("paste-curl").click();
    await page.getByLabel("cURL command").fill(curlCmd);
    await page.getByTestId("parse-curl").click();
    await page.waitForFunction(() => document.querySelector('[aria-label="Target"]')?.value.startsWith("http"));
    target = await page.getByLabel("Target").inputValue();
    check(target === `http://127.0.0.1:${shop}`, `pasted cURL fills the target (${target})`);
    await page.goto(link.replace(/\/auth.*/, "/#/history"));
    const har = { log: { version: "1.2", entries: [{ startedDateTime: "2024-01-01T00:00:00Z", time: 1,
      request: { method: "GET", url: "https://imported.test/from-har", headers: [] },
      response: { status: 204, headers: [], content: { text: "" } } }] } };
    await page.getByTestId("import-har").setInputFiles({ name: "x.har", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(har)) });
    await page.waitForSelector('[data-testid="import-note"]');
    check(await page.getByTestId("import-note").textContent().then((t) => t.startsWith("Imported 1 exchanges")), "HAR import");
    await page.locator("text=/from-har").first().waitFor();
    check(true, "imported exchange is listed");
    const [dl] = await Promise.all([page.waitForEvent("download"), page.getByTestId("export-har").click()]);
    check(dl.suggestedFilename() === "proxymind.har", "HAR export downloads a file");
    await page.getByLabel("Source").selectOption(""); // filters persist per browser
  });

  await section("Site map and search", async () => {
    await open("sitemap");
    await page.locator('[data-testid="sitemap-node"][data-path="/api/orders"]').first().waitFor({ state: "attached" });
    check(true, "site map shows /api/orders");
    await page.getByLabel("Search text").fill("alice@");
    await page.getByTestId("search").click();
    await page.waitForSelector('[data-testid="search-summary"]');
    check(await page.getByTestId("search-hit").count() > 0, "content search finds alice's email in responses");
    check(await page.locator('[data-testid="search-hit"] mark').first().textContent() === "alice@", "the match is highlighted");
    await page.screenshot({ path: join(SHOTS, "5c-sitemap.png") });
  });

  await section("Global search, Organizer, engagement tools, Collaborator", async () => {
    await open("search");
    await page.getByLabel("Global search").fill("alice@");
    await page.getByLabel("Search in").selectOption("response_body");
    await page.getByTestId("global-search").click();
    await page.locator('[data-testid="search-hit"]').first().waitFor();
    check(await page.locator('[data-testid="search-hit"] mark').first().textContent() === "alice@", "global search finds text in response bodies");
    await page.getByLabel("Search in").selectOption("request_headers");
    await page.getByTestId("global-search").click();
    await page.waitForFunction(() => document.querySelectorAll('[data-testid="search-hit"]').length === 0);
    check(true, "searching only request headers leaves out response matches");
    await page.getByLabel("Search in").selectOption("both");
    await open("history");
    await page.getByTestId(`row-${orderId}`).click({ button: "right" });
    await page.getByText("Send to Organizer").click();
    await open("organizer");
    await page.locator('[data-testid="organizer-item"]').first().waitFor();
    await page.locator('[aria-label^="Status of"]').first().selectOption("in_progress");
    await page.getByLabel("Organizer status").selectOption("in_progress");
    await page.locator('[data-testid="organizer-item"]').first().waitFor();
    check(true, "an exchange sent to the Organizer gets a status");
    await page.getByLabel("Organizer status").selectOption("");
    await page.goto(link.replace(/\/auth.*/, `/#/engage/clickjack:${orderId}`));
    await page.getByTestId("engage-clickjack").click();
    await page.waitForSelector('[data-testid="engage-clickjack-verdict"]');
    check(await page.getByTestId("engage-code").inputValue().then((v) => v.includes("<iframe")), "clickjacking check builds a test page");
    await page.getByTestId("engage-tab-analyze").click();
    await page.getByLabel("in scope only").uncheck();
    await page.getByTestId("engage-analyze").click();
    await page.waitForSelector('[data-testid="engage-analysis"]');
    check(await page.getByTestId("engage-analysis").textContent().then((t) => /\d+ requests/.test(t)), "analyze target summarises recorded traffic");
    await page.getByTestId("engage-tab-endpoints").click();
    await page.getByTestId("engage-endpoints").click();
    await page.waitForSelector('[data-testid="engage-endpoint-summary"]');
    check(await page.getByTestId("engage-endpoint-summary").textContent().then((t) => /\d+ endpoint/.test(t)), "JS endpoints lists what recorded scripts mention");
    await page.getByTestId("engage-tab-triage").click();
    await page.getByTestId("engage-triage").click();
    await page.locator('[data-testid="engage-triage-list"]').waitFor();
    check(await page.getByTestId("engage-triage-list").textContent().then((t) => t.includes("idor")), "Worth testing ranks recorded requests (object ids flagged)");
    await page.getByTestId("engage-tab-logic").click();
    await page.getByTestId("engage-logic").click();
    await page.locator('[data-testid="engage-logic-list"], .empty').first().waitFor();
    check(true, "the business-logic tab lists candidates from recorded traffic");
    await page.getByTestId("engage-tab-dns").click();
    await page.getByLabel("DNS host").fill("not-in-scope.example");
    await page.getByTestId("recon-dns").click();
    await page.getByText("isn't in scope").waitFor();
    check(true, "DNS recon refuses a host outside the scope");
    await page.goto(link.replace(/\/auth.*/, "/#/about"));
    await page.locator('[data-testid="about-version"]', { hasText: "0." }).waitFor();
    check(!(await page.getByTestId("update-toggle").isChecked()), "the update check is off until the user turns it on");
    await open("replay");
    await page.getByLabel("Raw request").fill("GET /search?q=a+b HTTP/1.1\nHost: shop\n\n");
    await page.getByTestId("request-transform").selectOption("method");
    await page.waitForFunction(() => document.querySelector('[aria-label="Raw request"]').value.startsWith("POST /search "));
    await page.getByTestId("request-transform").selectOption("json");
    await page.waitForFunction(() => document.querySelector('[aria-label="Raw request"]').value.endsWith('{"q":"a b"}'));
    check(true, "Replay changes the method and the body encoding");
    await open("collaborator");
    await page.getByLabel("Collaborator listen").fill("127.0.0.1:0");
    await page.getByTestId("collab-start").click();
    await page.waitForSelector('[data-testid="collab-status"]');
    await page.getByLabel("Payload note").fill("blind ssrf in avatar url");
    await page.getByTestId("collab-new").click();
    await page.waitForSelector('[data-testid="collab-payload"]');
    const payloadUrl = (await page.getByTestId("collab-payload").textContent()).trim();
    check(payloadUrl.startsWith("http://127.0.0.1:"), `a payload URL is handed out (${payloadUrl})`);
    await fetch(payloadUrl).catch(() => {});
    await page.locator('[data-testid="collab-interactions"] td', { hasText: "blind ssrf in avatar url" }).first().waitFor({ timeout: 10000 });
    check(true, "the callback shows up under the payload's note");
    await page.getByTestId("smtp-start").click();
    await page.locator('[data-testid="collab-status"]', { hasText: "mail to" }).waitFor();
    await page.getByLabel("Payload note").fill("reset mail");
    await page.getByTestId("collab-new").click();
    await page.locator('[data-testid="collab-payload"]', { hasText: "@[127.0.0.1]" }).waitFor();
    const mailTo = (await page.getByTestId("collab-payload").textContent()).match(/[0-9a-f]{20}@\[127\.0\.0\.1\]/)[0];
    const smtpAddr = (await page.getByTestId("collab-status").textContent()).match(/mail to (127\.0\.0\.1:\d+)/)[1];
    await new Promise((resolve) => {
      const [h, p] = smtpAddr.split(":");
      const sock = net.connect(Number(p), h, () => sock.write(`HELO t\r\nMAIL FROM:<a@b>\r\nRCPT TO:<${mailTo}>\r\nDATA\r\nhi\r\n.\r\nQUIT\r\n`));
      sock.on("data", () => {});
      sock.on("close", resolve);
      sock.on("error", resolve);
    });
    await page.locator('[data-testid="collab-interactions"] td', { hasText: "reset mail" }).first().waitFor({ timeout: 10000 });
    check(true, "mail to a payload address shows up as an interaction");
    await page.screenshot({ path: join(SHOTS, "5d-collaborator.png") });
    await viaProxy(proxy, shop, "GET /search?q=render-check HTTP/1.1\r\nHost: shop\r\n\r\n");
    const htmlId = await recordedId("render-check");
    await open(`history/${htmlId}`);
    await page.locator('[data-testid="response-view"] button', { hasText: "Render" }).click();
    const renderFrame = page.getByTestId("render-frame");
    const srcdoc = await renderFrame.getAttribute("srcdoc");
    check(await renderFrame.getAttribute("sandbox") === "" && srcdoc.includes("default-src 'none'"), "HTML responses render sandboxed, without scripts or network");
    // The page itself, markup and all (not the model view's visible text, which drops every tag).
    check(srcdoc.includes("<h1>Search</h1>") && srcdoc.includes("<li>Coffee</li>"), "Render draws the page's own HTML");
    check(await renderFrame.contentFrame().locator("h1").textContent() === "Search", "the rendered page shows its heading");
    await page.locator('[data-testid="response-view"] button', { hasText: "Pretty" }).click();
    check(await page.locator('[data-testid="response-view"] pre').textContent().then((t) => t.includes("<title>Search</title>")), "Pretty shows the HTML with its tags");
    await page.getByTestId(`row-${htmlId}`).click({ button: "right" });
    await page.getByText("Copy as Python requests").click();
    await page.locator("text=Code copied.").first().waitFor();
    check(true, "Copy as Python requests");
    await open("rules");
    await page.getByTestId("rules-preset").selectOption("unhide_fields");
    check(await page.locator('[data-testid="rules"] tbody tr').count() >= 2, "a response-modification preset adds its rules");
    await page.getByRole("button", { name: "Discard changes" }).click();
  });

  await section("Fuzzer", async () => {
    await page.goto(link.replace(/\/auth.*/, `/#/fuzzer/${orderId}`));
    await page.waitForFunction(() => document.querySelector('textarea[aria-label="Request"]')?.value.includes("/api/orders"));
    await page.getByLabel("Request").fill("GET /api/orders?id=1&q=x HTTP/1.1\nHost: shop\nCookie: s=abc\n\n");
    await page.getByTestId("auto-mark").click();
    check((await page.getByLabel("Request").inputValue()).includes("?id=§1§&q=§x§") && (await page.getByLabel("Request").inputValue()).includes("s=§abc§"), "Auto-mark marks query values and cookies");
    await page.getByLabel("Request").fill("GET /api/orders/§2001§ HTTP/1.1\nHost: shop\n\n");
    await page.getByLabel("Mode").selectOption("one_at_a_time");
    await page.getByLabel("Send as").selectOption("bob");
    await page.getByLabel("Payload type").selectOption("list");
    await page.getByLabel("Payloads", { exact: true }).fill("1001\n1002\n9999");
    await page.getByLabel("Grep").fill("alice@");
    await page.getByRole("button", { name: "Add extract" }).click();
    await page.getByLabel("Extract 1 regex").fill("([a-z]+@[a-z.]+)");
    // ADR-0018: with every page timer frozen, the attack's progress and end still arrive (as `fuzzer` events).
    const attackFetches = [];
    const onRequest = (r) => /\/api\/v1\/fuzzer\/attacks\/[0-9a-f]+/.test(r.url()) && r.method() === "GET" && attackFetches.push(r.url());
    page.on("request", onRequest);
    await withFrozenTimers(async () => {
      await page.getByTestId("fuzzer-run").click();
      await page.waitForFunction(() => document.querySelector('[data-testid="fuzzer-summary"]')?.textContent?.includes("· done ·"), null, { timeout: 30000 });
    });
    page.off("request", onRequest);
    check(attackFetches.length > 0, `the attack's progress and end arrive without any page timer (${attackFetches.length} fetch(es), each after an event)`);
    check(await page.getByTestId("fuzzer-summary").textContent().then((t) => t.startsWith("3 requests")), "an attack sends 3 requests in the background");
    check((await page.getByTestId("extract-cell").allTextContents()).some((t) => t.startsWith("alice@")), "an extract column shows alice's email");
    check((await page.getByTestId("anomaly").count()) === 3, "alice's orders (grep) and the 404 stand out");
    await page.screenshot({ path: join(SHOTS, "5b-fuzzer.png") });
  });

  await section("Approvals (an agent asks over MCP)", async () => {
    const mcp = start(["mcp", "--actor", "agent:claude"]);
    const replies = [];
    mcp.stdout.on("data", (d) => replies.push(...String(d).split("\n").filter(Boolean)));
    const rpc = (id, method, params) => mcp.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    rpc(1, "initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "1" } });
    rpc(2, "tools/call", { name: "replay_send", arguments: { url: `http://127.0.0.1:${shop}`, raw: "POST /api/orders HTTP/1.1\nHost: x\n\n{\"product_id\":1,\"qty\":-5}" } });
    for (let i = 0; i < 50 && replies.length < 2; i++) await sleep(100);
    await open("approvals");
    await page.waitForSelector('[data-testid="approvals-badge"]');
    check(true, "sidebar shows a pending approval badge (live update)");
    await page.screenshot({ path: join(SHOTS, "6-approvals.png") });
    await page.getByRole("button", { name: "Approve" }).click();
    await page.waitForSelector("text=Nothing is waiting for approval.");
    check(true, "approved from the UI");
  });

  await section("Intercept", async () => {
    await open("intercept");
    await page.getByLabel("Path filter").fill("/api/products/search");
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByTestId("intercept-toggle").click();
    await page.waitForSelector("text=Intercept is ON");
    search = (q) => viaProxy(proxy, shop, `GET /api/products/search?q=${q} HTTP/1.1\r\nHost: shop\r\n\r\n`);
    // ADR-0018: the page learns of a held request from a server event, not a timer. Time from sending the
    // request to its row being on screen (this includes the proxy round trip and the 250 ms-class event path).
    const sentAt = Date.now();
    edited = search("held-original"); // waits in the queue until forwarded
    await page.locator('[data-testid="intercept-queue"]', { hasText: "held-original" }).waitFor();
    const shownIn = Date.now() - sentAt;
    check(shownIn < 1500, `a newly held request shows on the Intercept page within 1.5 s (${shownIn} ms)`);
    await page.waitForSelector('[data-testid="intercept-badge"]');
    check(true, "request is held and the sidebar shows a badge");
    const editor = page.getByLabel("Held message");
    await editor.fill((await editor.inputValue()).replace("held-original", "held-edited"));
    await page.screenshot({ path: join(SHOTS, "6b-intercept.png") });
    await page.getByTestId("intercept-forward").click();
    check((await edited).startsWith("HTTP/1.1 200"), "edited request is forwarded and answered");
    // One request forwarded and the next arriving leaves the held count at 1 -> 0 -> 1: only events see that.
    const droppedAt = Date.now();
    const dropped = search("held-drop");
    await page.locator('[data-testid="intercept-queue"]', { hasText: "held-drop" }).waitFor();
    const droppedShownIn = Date.now() - droppedAt;
    check(droppedShownIn < 1500, `the next held request shows within 1.5 s as well (${droppedShownIn} ms)`);
    await page.getByTestId("intercept-drop").click();
    check((await dropped).startsWith("HTTP/1.1 403"), "dropped request gets 403 from ProxyMind");
    await page.getByTestId("intercept-toggle").click();
    await page.waitForSelector("text=Intercept is OFF");
    await open("history");
    await page.getByLabel("Filter", { exact: true }).fill("held-");
    await sleep(500);
    const heldRows = await page.locator('[data-testid^="row-"]').allTextContents();
    check(heldRows.length === 1 && heldRows[0].includes("held-edited"), "history records the edited request only");
  });

  await section("Match and replace", async () => {
    await open("rules");
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
    await open("history");
    await page.getByLabel("Filter", { exact: true }).fill("rules-check");
    await sleep(500);
    await page.locator('[data-testid^="row-"]').first().click();
    await page.getByRole("tab", { name: "Request", exact: true }).click();
    const sent = await page
      .locator('[data-testid="exchange-detail"] pre.raw', { hasText: "X-E2E: rewritten" })
      .first()
      .waitFor({ timeout: 5000 })
      .then(() => true, () => false);
    check(sent, "history shows the request as sent, with the added header");

    // ADR-0020: the rules changed this exchange, so History marks it and keeps what was received next to it.
    const row = page.locator('[data-testid^="row-"]').first();
    check(await row.getByTestId("modified-mark").isVisible(), "history marks the rewritten row as edited");
    check(await page.getByTestId("modified-note").isVisible(), "the exchange says it was changed in flight");
    await page.getByTestId("tab-original_request").click();
    const origReq = await page.getByTestId("original-request-view").locator("pre.raw").first().textContent();
    check(origReq.includes("/api/products/search?q=rules-check") && !origReq.includes("X-E2E"), "the Original request tab has no added header (as the browser sent it)");
    await page.getByRole("tab", { name: "Response", exact: true }).click();
    const serverResp = await page.getByTestId("response-view").locator("pre.raw").first().textContent();
    check(serverResp.includes("results") && !serverResp.includes("REWRITTEN"), "History's Response tab still shows what the server sent");
    await page.getByTestId("tab-delivered_response").click();
    const deliveredResp = await page.getByTestId("delivered-response-view").locator("pre.raw").first().textContent();
    check(deliveredResp.includes("REWRITTEN") && !deliveredResp.includes("results"), "the Delivered response tab shows the rewritten copy the browser got");
    await page.getByTestId("tab-changes").click();
    const changesText = await page.getByTestId("changes-list").textContent();
    check(changesText.includes("add request header X-E2E") && changesText.includes("response body matching results"), "the changes name both rules");
    const added = await page.getByTestId("request-diff").locator('[data-op="added"]').allTextContents();
    check(added.length === 1 && added[0].includes("X-E2E: rewritten"), "the diff shows the added header");
    const removed = await page.getByTestId("response-diff").locator('[data-op="removed"]').allTextContents();
    check(removed.some((l) => l.includes("results")), "the diff shows what the response rule replaced");
    await page.screenshot({ path: join(SHOTS, "6d-original-and-diff.png") });
    await page.getByLabel("Query", { exact: true }).fill("is:modified");
    await page.getByTestId("apply-query").click();
    await sleep(500);
    check(await page.locator('[data-testid^="row-"]').count() >= 1 && (await page.locator('[data-testid="modified-mark"]').count()) === (await page.locator('[data-testid^="row-"]').count()), "is:modified lists only edited rows");
    await page.getByTestId("clear-query").click();
  });

  await section("WebSocket (a real browser chats through the proxy)", async () => {
    const loginBody = JSON.stringify({ username: "alice", password: "alice123" });
    login = await viaProxy(proxy, shop, `POST /api/login HTTP/1.1\r\nHost: shop\r\nContent-Type: application/json\r\nContent-Length: ${loginBody.length}\r\n\r\n${loginBody}`);
    session = login.split("session=")[1].split(";")[0];
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
    await open("history");
    await page.getByLabel("Filter", { exact: true }).fill("/ws/support");
    await sleep(500);
    await page.locator('[data-testid^="row-"]').first().click();
    const wsLogged = await page
      .locator('[data-testid="ws-messages"]', { hasText: "Where is order 1001?" })
      .waitFor({ timeout: 8000 })
      .then(() => true, () => false);
    check(wsLogged, "History shows the WebSocket messages both ways");
    await open("wshistory");
    await page.locator('[data-testid="ws-history"] tr', { hasText: "Where is order 1001?" }).first().waitFor();
    check(true, "WebSockets history lists messages across connections");
    await open("history");
    await page.getByLabel("Filter", { exact: true }).fill("/ws/support");
    await sleep(500);
    await page.locator('[data-testid^="row-"]').first().click();
    await page.getByRole("tab", { name: "WebSocket" }).click().catch(() => {});
    await page.screenshot({ path: join(SHOTS, "6d-websocket.png") });
    await page.getByRole("button", { name: "Replay on a new connection…" }).click();
    await page.getByLabel("Messages to send").fill("replayed from the UI");
    await page.getByLabel("Wait (ms)").fill("400");
    await page.getByTestId("ws-replay-send").click();
    const replayed = await page.getByTestId("ws-replay-result").textContent({ timeout: 10000 }).catch(() => "");
    check(/recorded as exchange #\d+/.test(replayed), `WebSocket replay opens a new connection and records it (${replayed.trim()})`);
    await page.getByTestId("ws-replay-result").getByRole("link", { name: "Open it" }).click();
    const replyShown = await page
      .locator('[data-testid="ws-messages"]', { hasText: "we got: replayed from the UI" })
      .waitFor({ timeout: 8000 })
      .then(() => true, () => false);
    check(replyShown, "the replayed session shows the server's answer");
  });

  await section("WebSocket intercept (edit a browser's message in the queue)", async () => {
    await open("intercept");
    await page.getByLabel("Path filter").fill("/ws/support");
    await page.getByLabel("WebSocket messages").check();
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByTestId("intercept-toggle").click();
    await page.waitForSelector("text=Intercept is ON");
    const viaPm3 = await browser.newContext({ proxy: { server: `http://127.0.0.1:${proxy}`, bypass: "<-loopback>" } });
    await viaPm3.addCookies([{ name: "session", value: session, domain: "127.0.0.1", path: "/" }]);
    const chat3 = await viaPm3.newPage();
    await chat3.goto(`http://127.0.0.1:${shop}/api/products`);
    const intercepted = chat3.evaluate(
      (url) =>
        new Promise((resolve, reject) => {
          const got = [];
          const ws = new WebSocket(url);
          ws.onmessage = (e) => {
            got.push(JSON.parse(e.data).text);
            if (got.length === 1) ws.send("typed in the browser");
            if (got.length === 2) ws.close(1000, "bye");
          };
          ws.onclose = () => resolve(got);
          ws.onerror = () => reject(new Error("WebSocket error"));
          setTimeout(() => resolve(got), 20000);
        }),
      `ws://127.0.0.1:${shop}/ws/support`,
    );
    const queue = page.getByTestId("intercept-queue");
    // "requests" is on too, so the upgrade request itself is held first.
    await queue.locator("tr", { hasText: "/ws/support" }).first().waitFor({ timeout: 10000 });
    await queue.locator("tr", { hasText: "request" }).first().click();
    await page.getByTestId("intercept-forward").click();
    // The server's greeting is held on its way to the browser.
    await queue.locator("tr", { hasText: "WS ← server" }).first().waitFor({ timeout: 10000 });
    await queue.locator("tr", { hasText: "WS ← server" }).first().click();
    await page.getByTestId("intercept-forward").click();
    // The browser's message is held on its way to the server: edit it.
    await queue.locator("tr", { hasText: "WS → server" }).first().waitFor({ timeout: 10000 });
    await queue.locator("tr", { hasText: "WS → server" }).first().click();
    check((await page.getByLabel("Held message").inputValue()) === "typed in the browser", "the browser's WebSocket message is held");
    await page.getByLabel("Held message").fill("edited in ProxyMind");
    await page.screenshot({ path: join(SHOTS, "6e-ws-intercept.png") });
    await page.getByTestId("intercept-forward").click();
    await queue.locator("tr", { hasText: "WS ← server" }).first().waitFor({ timeout: 10000 });
    await queue.locator("tr", { hasText: "WS ← server" }).first().click();
    await page.getByTestId("intercept-forward").click();
    const wsGot = await intercepted;
    check(wsGot.length === 2 && wsGot[1].includes("we got: edited in ProxyMind"), `the server answered the edited message (${wsGot[1] ?? "nothing"})`);
    await viaPm3.close();
    await page.getByLabel("WebSocket messages").uncheck();
    await page.getByLabel("Path filter").fill("");
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByTestId("intercept-toggle").click();
    await page.waitForSelector("text=Intercept is OFF");
  });

  await section("Race condition (Replay races VulnShop's one-time gift card)", async () => {
    await open("replay");
    await page.getByLabel("Target").fill(`http://127.0.0.1:${shop}`);
    const card = '{"code":"WELCOME10"}';
    await page.getByLabel("Raw request").fill(
      `POST /api/giftcard/redeem HTTP/1.1\nHost: 127.0.0.1:${shop}\nCookie: session=${session}\nContent-Type: application/json\nContent-Length: ${card.length}\n\n${card}`,
    );
    await page.getByLabel("Race count").fill("6");
    await page.getByTestId("race").click();
    const raceText = await page.getByTestId("race-result").textContent({ timeout: 15000 }).catch(() => "");
    const wins = Number((raceText.match(/(\d+) succeeded/) ?? [])[1] ?? 0);
    check(wins > 1, `racing 6 redemptions credits the card ${wins} times`);
    await page.screenshot({ path: join(SHOTS, "6g-race.png") });
    // A group: the redemption (already used) then the profile, one after another, in two tabs.
    await page.getByTitle("Duplicate this tab").click();
    await page.getByLabel("Raw request").fill(`GET /api/me HTTP/1.1\nHost: 127.0.0.1:${shop}\nCookie: session=${session}\n\n`);
    await page.getByTestId("group-open").click();
    const boxes = page.locator('[data-testid="group-panel"] input[aria-label^="Group tab"]');
    const nBoxes = await boxes.count();
    for (let i = 0; i < nBoxes; i++) await boxes.nth(i).uncheck();
    await boxes.nth(nBoxes - 2).check();
    await boxes.nth(nBoxes - 1).check();
    await page.getByTestId("group-send").click();
    await page.waitForSelector('[data-testid="group-result"]');
    const groupRows = await page.locator('[data-testid="group-result"] tbody tr').allTextContents();
    check(groupRows.length === 2 && groupRows[0].includes("409") && groupRows[1].includes("200"),
      `a group sends two tabs in order (${groupRows.join(" / ")})`);
    await page.screenshot({ path: join(SHOTS, "6h-group.png") });
  });

  await section("gRPC and Protobuf (view, edit in Replay)", async () => {
    // A unary gRPC call through the proxy: one framed message, field 1 = "world" (ASCII only, so a JS string is safe).
    const framed = "\x00\x00\x00\x00\x07\x0a\x05world";
    await viaProxy(
      proxy,
      shop,
      `POST /grpc/demo.Greeter/SayHello HTTP/1.1\r\nHost: shop\r\nContent-Type: application/grpc\r\nContent-Length: ${framed.length}\r\n\r\n${framed}`,
    );
    const gid = await recordedId("/grpc/demo.Greeter/SayHello");
    check(gid != null, "the gRPC call is recorded");
    await page.goto(link.replace(/\/auth.*/, `/#/history/${gid}`));
    await page.getByTestId("response-view").waitFor();
    // History: the response has a Protobuf view with the decoded fields and the status from the headers.
    await page.getByTestId("response-view").getByRole("button", { name: "Protobuf" }).click();
    const shownResponse = await page.getByTestId("protobuf-text").textContent();
    check(shownResponse.includes('1: "Hello, world"') && shownResponse.includes("2: 5") && shownResponse.includes("grpc-status: 0"),
      "History decodes a gRPC response in the Protobuf view");
    await page.getByRole("tab", { name: "Request", exact: true }).click();
    await page.getByTestId("request-view").getByRole("button", { name: "Protobuf" }).click();
    check(await page.getByTestId("protobuf-text").textContent().then((t) => t.includes("@message") && t.includes('1: "world"')),
      "History decodes the gRPC request in the Protobuf view");
    await page.screenshot({ path: join(SHOTS, "6i-protobuf-history.png") });

    // Replay: the request opens with the head as text and the message as editable text.
    await page.goto(link.replace(/\/auth.*/, `/#/replay/${gid}`));
    const editor = page.getByTestId("protobuf-editor");
    await editor.waitFor();
    const original = await editor.inputValue();
    check(original.includes("@message") && original.includes('1: "world"'), "Replay shows the gRPC request as Protobuf text");
    // Unedited, the original bytes are sent: the server greets "world".
    await page.getByTestId("send").click();
    await page.locator('[data-testid="replay-result"]', { hasText: "200" }).waitFor();
    await page.locator('[data-testid="replay-response"] button', { hasText: "Protobuf" }).click();
    await page.locator('[data-testid="replay-response"] [data-testid="protobuf-text"]', { hasText: "Hello, world" }).waitFor();
    check(true, "an unedited gRPC request is replayed as it was");
    // Edited: the text is encoded, re-framed, and Content-Length follows.
    await editor.fill('@message\n1: "galaxy"\n');
    await page.getByTestId("send").click();
    await page.locator('[data-testid="replay-response"] [data-testid="protobuf-text"]', { hasText: "Hello, galaxy" }).waitFor({ timeout: 10000 });
    check(await page.locator('[data-testid="replay-response"] [data-testid="protobuf-text"]').textContent().then((t) => t.includes("2: 6")),
      "editing a field in Replay changes what the server answers (re-encoded and re-framed)");
    await page.screenshot({ path: join(SHOTS, "6j-protobuf-replay.png") });
  });

  await section("HTTP/2 (Chromium ↔ ProxyMind ↔ an HTTP/2 server)", async () => {
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
    await open("history");
    await page.getByLabel("Filter", { exact: true }).fill("/h2-check");
    await sleep(500);
    await page.locator('[data-testid^="row-"]').first().click();
    await page.getByRole("tab", { name: "Request", exact: true }).click();
    const h2text = await page
      .locator('[data-testid="exchange-detail"] pre.raw', { hasText: "GET /h2-check HTTP/2" })
      .waitFor({ timeout: 5000 })
      .then(() => true, () => false);
    check(h2text, "History shows the request in HTTP/2 text form");
  });

  await section("HTTP/3 (Replay ↔ an in-process HTTP/3 server)", async () => {
    // The test server is an example of pm-replay (quinn + h3 with a self-signed certificate). Build it if the
    // binary is not there yet (CI builds it next to the proxymind binary).
    const h3bin = join(BIN, "..", "examples", "h3_server");
    if (!existsSync(h3bin)) {
      execFileSync("cargo", ["build", "-p", "pm-replay", "--example", "h3_server"], { cwd: join(BIN, "..", "..", ".."), stdio: "ignore" });
    }
    const h3 = spawn(h3bin, ["127.0.0.1:0"], { stdio: ["ignore", "pipe", "inherit"] });
    children.push(h3);
    const h3port = await new Promise((resolve, reject) => {
      let out = "";
      h3.stdout.on("data", (d) => {
        out += d;
        const m = out.match(/h3 listening on 127\.0\.0\.1:(\d+)/);
        if (m) resolve(Number(m[1]));
      });
      h3.on("exit", () => reject(new Error("the HTTP/3 test server stopped")));
      setTimeout(() => reject(new Error("the HTTP/3 test server did not start")), 20000);
    });
    const putRoe = (text) =>
      page.evaluate(async (text) => (await fetch("/api/v1/roe", { method: "PUT", headers: { "content-type": "application/json", "x-proxymind": "1" }, body: JSON.stringify({ text }) })).status, text);
    const originalRoe = await page.evaluate(async () => (await (await fetch("/api/v1/roe")).json()).text);
    try {
      check((await putRoe(`version: 1\nscope:\n  include: ["http://127.0.0.1:${shop}/", "https://localhost:${h3port}/"]\n`)) === 200, "the HTTP/3 server is added to the scope");
      await open("replay");
      await page.getByLabel("New tab").click();
      await page.getByLabel("Target").fill(`https://localhost:${h3port}`);
      await page.getByLabel("Raw request").fill(`GET /h3-check?x=1 HTTP/1.1\nHost: localhost:${h3port}\naccept: */*\n\n`);
      await page.getByLabel("Protocol").selectOption("HTTP/3");
      const rawBecomes = (pred) =>
        page
          .waitForFunction(`(() => { const v = document.querySelector('[aria-label="Raw request"]')?.value ?? ""; return ${pred}; })()`, null, { timeout: 5000 })
          .then(() => true, () => false);
      check(await rawBecomes('v.startsWith("GET /h3-check?x=1 HTTP/3\\n") && v.includes("host: localhost:")'), "Replay's Protocol selector writes the request for HTTP/3");
      check(await page.getByLabel("HTTP/3 pseudo-headers :path").inputValue() === "/h3-check?x=1", "the Inspector shows HTTP/3 pseudo-headers");
      await page.getByTestId("send").click();
      await page.locator('[data-testid="replay-result"]', { hasText: "201" }).waitFor({ timeout: 15000 });
      const answer = await page.locator('[data-testid="replay-response"] pre.raw').first().textContent();
      check(answer.startsWith("HTTP/3 201") && answer.includes("x-proto: h3") && answer.includes("x-sni: localhost") && answer.includes(`GET /h3-check?x=1 localhost:${h3port}`),
        "a Replay request with HTTP/3 reaches the server over QUIC (the response is shown as HTTP/3 text, SNI is the host name)");
      check(await page.locator('[data-testid="replay-result"]').getByText("offers HTTP/3").isVisible(), "Replay marks a response that advertises HTTP/3 (Alt-Svc)");
      check(await page.getByTestId("send-http3").count() === 0, "no \"Send with HTTP/3\" offer when the request already uses it");

      // History: the exchange is recorded with the HTTP/3 text form, and Alt-Svc is shown.
      await open("history");
      await page.getByLabel("Filter", { exact: true }).fill("/h3-check");
      await sleep(500);
      await page.locator('[data-testid^="row-"]').first().click();
      await page.getByRole("tab", { name: "Request", exact: true }).click();
      const h3text = await page
        .locator('[data-testid="exchange-detail"] pre.raw', { hasText: "GET /h3-check?x=1 HTTP/3" })
        .waitFor({ timeout: 5000 })
        .then(() => true, () => false);
      check(h3text, "History shows the request in HTTP/3 text form");
      const detail = page.getByTestId("exchange-detail");
      check((await detail.getByText("HTTP/3", { exact: true }).count()) > 0 && await detail.getByText("offers HTTP/3").isVisible(), "History labels the protocol and shows \"offers HTTP/3\"");
      await page.getByTestId("replay-http3").click();
      await page.locator(".rtab.active", { hasText: "#" }).waitFor();
      check(await rawBecomes('v.startsWith("GET /h3-check?x=1 HTTP/3\\n")'), "\"Send with HTTP/3\" opens Replay with the request written for HTTP/3");
      await page.screenshot({ path: join(SHOTS, "6k-http3.png") });

      // The preset that removes the advertisement is offered on the Rules page.
      await open("rules");
      const titles = await page.getByTestId("rules-preset").locator("option").allTextContents();
      check(titles.includes("Remove HTTP/3 advertisements (Alt-Svc h3)"), "the Rules page offers the \"Remove HTTP/3 advertisements\" preset");
    } finally {
      await putRoe(originalRoe);
      h3.kill();
    }
  });

  await section("Network: upstream proxy", async () => {
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
    await open("network");
    // One rule without a match covers every host.
    await page.getByTestId("add-upstream-rule").click();
    await page.getByLabel("Rule 1 via", { exact: true }).selectOption("http");
    await page.getByLabel("Rule 1 proxy host").fill("127.0.0.1");
    await page.getByLabel("Rule 1 proxy port").fill(String(upstream.address().port));
    await page.getByTestId("network-save").click();
    await page.waitForSelector("text=Saved. The proxy");
    await page.screenshot({ path: join(SHOTS, "6e-network.png") });
    const viaUpstream = await search("via-upstream");
    check(viaUpstream.startsWith("HTTP/1.1 200") && upstreamSeen.some((l) => l.includes("q=via-upstream")), "traffic goes through the upstream proxy");
    // Per-host rules: 127.0.0.1 goes direct, everything else through the proxy; the first match wins.
    const resolve = async (host) => {
      await page.getByLabel("Host to test").fill(host);
      await page.getByTestId("resolve-go").click();
      return (await page.getByTestId("resolve-result").textContent()).trim();
    };
    await page.getByTestId("add-upstream-rule").click();
    await page.getByLabel("Rule 1 match").fill("127.0.0.1, *.lab.test");
    await page.getByLabel("Rule 1 via", { exact: true }).selectOption("direct");
    check((await page.getByTestId("upstream-rule").count()) === 2, "a rule is added before the catch-all rule");
    let r = await resolve("a.lab.test");
    check(r.startsWith("Rule 1 (matched *.lab.test): direct"), `the resolve tool names the matching rule (${r})`);
    r = await resolve("elsewhere.example");
    check(r.startsWith("Rule 2 (matches every host): via http://127.0.0.1:"), `other hosts fall to the last rule (${r})`);
    await page.getByTestId("network-save").click();
    await page.waitForSelector("text=Saved. The proxy");
    r = await resolve("127.0.0.1");
    check(r.startsWith("Rule 1 (matched 127.0.0.1): direct"), "the saved rules resolve the same way");
    n = upstreamSeen.length;
    const direct127 = await search("direct-by-rule");
    check(direct127.startsWith("HTTP/1.1 200") && upstreamSeen.length === n, "a host with its own direct rule bypasses the upstream proxy");
    // Order matters: moving the catch-all up makes it win (tried on the unsaved draft).
    await page.getByLabel("Move rule 1 down").click();
    r = await resolve("127.0.0.1");
    check(r.startsWith("Rule 1 (matches every host): via http://127.0.0.1:"), "reordering changes which rule wins");
    await page.getByLabel("Move rule 1 down").click();
    // A catch-all that is not last is refused on save.
    await page.getByLabel("Move rule 1 down").click();
    await page.getByTestId("network-save").click();
    await page.locator("text=must be the last").first().waitFor({ timeout: 5000 });
    check(true, "a catch-all rule that is not last is refused with a reason");
    await page.getByRole("button", { name: "Discard changes" }).click();
    await page.getByLabel("Delete rule 1").click();
    await page.getByLabel("Delete rule 1").click();
    await page.getByTestId("network-save").click();
    await page.waitForSelector("text=Saved. The proxy");
    n = upstreamSeen.length;
    await search("direct-again");
    check(upstreamSeen.length === n, "deleting the rules connects directly again");
    upstream.close();
  });

  await section("Assistant (mock OpenAI-compatible model server)", async () => {
    const { createServer } = await import("node:http");
    const modelCalls = [];
    model = createServer((req, res) => {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        const parsed = JSON.parse(body);
        modelCalls.push(parsed);
        const toolMsg = parsed.messages.find((m) => m.role === "tool");
        const call = (name, args) => ({ choices: [{ message: { role: "assistant", content: null, tool_calls: [{ id: `c${modelCalls.length}`, type: "function", function: { name, arguments: JSON.stringify(args) } }] } }] });
        const tools = parsed.messages.filter((m) => m.role === "tool").length;
        const aiScan = String(parsed.messages[0]?.content ?? "").includes("AI scan agent");
        const explain = String(parsed.messages[0]?.content ?? "").includes("senior application security engineer");
        const reply = explain
          ? { choices: [{ message: { role: "assistant", content: "## What is wrong\nOrders load by id with no owner check (e2e)." } }], usage: { prompt_tokens: 900, completion_tokens: 40 } }
          : aiScan
          ? tools === 0 ? call("ai_scan_phase", { phase: "recon", notes: "e2e run" })
            : tools === 1 ? call("attack_path_record", { title: "e2e chain", impact: "read any order", severity: "high", steps: [{ text: "Order ids are sequential" }, { text: "Orders load without an owner check" }] })
            : tools === 2 ? call("ai_scan_report", { markdown: "# Report\n\n## Executive summary\nThe e2e scan found nothing." })
            : { choices: [{ message: { role: "assistant", content: "Done." } }] }
          : toolMsg
          ? { choices: [{ message: { role: "assistant", content: "Alice opened /api/orders/1001 (her own order)." } }] }
          : { choices: [{ message: { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "history_search", arguments: JSON.stringify({ path: "/api/orders/", limit: 5 }) } }] } }] };
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(reply));
      });
    });
    await new Promise((r) => model.listen(0, "127.0.0.1", r));
    await open("assistant");
    await page.waitForSelector('[data-testid="assistant-problem"]');
    check(true, "without a model the page explains what to set up");
    await page.getByRole("main").getByRole("button", { name: "Settings" }).click();
    await page.getByRole("button", { name: "Ollama (local)" }).click();
    await page.getByLabel("Base URL").fill(`http://127.0.0.1:${model.address().port}/v1`);
    await page.getByLabel("Model", { exact: true }).fill("mock-model");
    await page.getByTestId("assistant-save").click();
    await page.waitForSelector('[data-testid="assistant-problem"]', { state: "detached" });
    await page.getByLabel("Message").fill("Which orders did alice look at?");
    await page.getByTestId("assistant-send").click();
    await page.locator('[data-testid="assistant-transcript"] .bubble.assistant', { hasText: "Alice opened /api/orders/1001" }).waitFor({ timeout: 15000 });
    check(await page.getByTestId("tool-call").first().textContent().then((t) => t.includes("history_search")), "the assistant called a tool and answered");
    const toolResult = modelCalls[1]?.messages.find((m) => m.role === "tool")?.content ?? "";
    check(toolResult.includes("/api/orders/1001"), "the tool ran against real history (through the policy gate)");
    await page.getByLabel("Playbook").selectOption("idor_sweep");
    await page.getByLabel("Playbook focus").fill("the orders API");
    await page.getByTestId("playbook-use").click();
    await page.waitForFunction(() => document.querySelector('[aria-label="Message"]').value.includes("Focus on: the orders API."));
    check(true, "a playbook fills the message box with its steps");
    await page.getByLabel("Message").fill("");
    await page.screenshot({ path: join(SHOTS, "6f-assistant.png") });
    // Leaving the Assistant used to blank the whole app: an effect returned scrollIntoView's
    // Promise (current browsers), which React then called as the effect's cleanup.
    await open("sessions");
    await page.getByTestId("session-save").waitFor({ timeout: 5000 }).catch(() => {});
    check((await page.getByTestId("session-save").isVisible()) && (await page.getByTestId("page-error").count()) === 0,
      "leaving the Assistant leaves the app working");
    await open("aiscan");
    await page.locator('[data-testid="ai-scan-model"]', { hasText: "mock-model" }).waitFor();
    await page.getByLabel("AI scan steps").fill("10");
    await page.getByTestId("ai-scan-start").click();
    await page.locator('[data-testid="ai-scan-report"]', { hasText: "The e2e scan found nothing." }).waitFor({ timeout: 15000 });
    // The report appears before the scan ends: ProxyMind still retests its findings.
    await page.locator('[data-testid="ai-scan-status"]', { hasText: "done" }).waitFor({ timeout: 30000 }).catch(() => {});
    check(await page.getByTestId("ai-scan-status").textContent().then((t) => t.includes("done")), "an AI scan runs to a report");
    check(await page.getByTestId("ai-scan-log").textContent().then((t) => t.includes("e2e run")), "its phases show in the activity log");
    await page.getByTestId("attack-graph").waitFor();
    await page.getByTestId("attack-graph").locator("xpath=../..").screenshot({ path: join(SHOTS, "6h-attack-graph.png") });
    check(await page.getByTestId("attack-path-list").textContent().then((t) => t.includes("e2e chain") && t.includes("Orders load without an owner check")), "the scan's attack path shows as a graph");
    check(await page.getByTestId("ai-scan-cost").textContent().then((t) => /tokens/.test(t)), "the scan shows the tokens it used");
    await page.screenshot({ path: join(SHOTS, "6g-ai-scan.png") });
    await open("findings");
    await page.locator('[data-testid="findings"] tbody tr').first().click();
    await page.getByTestId("explain").click();
    await page.locator('[data-testid="explanation"]', { hasText: "no owner check (e2e)" }).waitFor({ timeout: 15000 });
    check(true, "Explain & fix writes an explanation onto the finding");
    model.close();
  });

  await section("Crawl", async () => {
    await open("model");
    await page.getByRole("button", { name: "Discover pages…" }).click();
    await page.getByLabel("Crawl start URL").fill(`http://127.0.0.1:${shop}/`);
    await page.getByTestId("crawl-run").click();
    await page.waitForSelector('[data-testid="crawl-summary"]', { timeout: 60000 });
    check(await page.getByTestId("crawl-summary").textContent().then((t) => /^\d+ pages · 3 forms/.test(t)), "crawl finds pages and the three forms");
    await page.getByText("Skipped links").click();
    check((await page.getByText("the link probably logs out").count()) === 1, "the logout link is skipped");
    await page.screenshot({ path: join(SHOTS, "6b-crawl.png") });
    await page.getByLabel("Crawl start URL").fill(`http://127.0.0.1:${shop}/spa`);
    await page.getByLabel("Max pages").fill("6");
    await page.getByTestId("crawl-browser").check();
    await page.getByTestId("crawl-run").click();
    await page.waitForFunction(() => document.querySelector('[data-testid="crawl-summary"]')?.closest(".panel")?.textContent.includes("/spa/catalog"), null, { timeout: 90000 });
    const jsApi = await page.evaluate(async () => (await (await fetch("/api/v1/exchanges?path=/api/spa/catalog&limit=5")).json()).exchanges.length);
    check(jsApi > 0, "a browser crawl runs the single-page app and records the API its script calls");
    await page.screenshot({ path: join(SHOTS, "6b-crawl-browser.png") });
  });

  await section("OpenAPI import", async () => {
    await viaProxy(proxy, shop, "GET /openapi.json HTTP/1.1\r\nHost: shop\r\n\r\n");
    const specId = await recordedId("/openapi.json");
    await page.getByRole("button", { name: "Import OpenAPI…" }).click();
    await page.getByLabel("Spec exchange").fill(String(specId));
    await page.getByTestId("openapi-import").click();
    await page.waitForSelector('[data-testid="openapi-summary"]');
    check(await page.getByTestId("openapi-summary").textContent().then((t) => t.startsWith("VulnShop API 1.0: 13 operations")), "the spec's 13 operations are listed");
  });

  await section("Content discovery", async () => {
    await page.getByRole("button", { name: "Find hidden paths…" }).click();
    await page.getByLabel("Discover under").fill(`http://127.0.0.1:${shop}/`);
    await page.getByTestId("discover").click();
    await page.waitForSelector('[data-testid="discover-summary"]', { timeout: 60000 });
    check(await page.locator('[data-testid="discovered"]', { hasText: "/.git/config" }).count() === 1, "discovery finds /.git/config");
  });

  await section("GraphQL", async () => {
    await page.getByRole("button", { name: "Import GraphQL schema…" }).click();
    await page.getByLabel("GraphQL endpoint").fill(`http://127.0.0.1:${shop}/graphql`);
    await page.getByTestId("graphql-fetch").click();
    await page.waitForSelector('[data-testid="graphql-summary"]');
    check(await page.getByTestId("graphql-summary").textContent().then((t) => t.startsWith("3 operations")), "introspection lists 3 operations");
    await page.screenshot({ path: join(SHOTS, "7b-graphql.png"), fullPage: true });
    await page.getByTestId("graphql-replay-invoice").click();
    await page.waitForFunction(() => document.querySelector("textarea")?.value.includes("query Invoice"));
    check(true, "an example opens in Replay");
    await open("model");
  });

  await section("Passive issues", async () => {
    await open("issues");
    await page.waitForSelector('[data-testid="issues"]');
    check(await page.locator('[data-testid="issues"]').textContent().then((t) => t.includes("Password field on a page served over plain HTTP")), "passive scan flags the login form over HTTP");
    await page.screenshot({ path: join(SHOTS, "6c-issues.png") });
  });

  await section("Active scan", async () => {
    await viaProxy(proxy, shop, "GET /greet?name=ann HTTP/1.1\r\nHost: shop\r\n\r\n");
    const greet = await recordedId("/greet");
    check(greet !== null, "the proxied /greet request is recorded");
    await page.goto(link.replace(/\/auth.*/, `/#/issues/${greet}`));
    await page.getByTestId("active-scan").click();
    await page.waitForSelector('[data-testid="active-summary"]', { timeout: 60000 });
    check(await page.getByText("server-side template injection").count() > 0, "active scan finds the template injection");
    await page.screenshot({ path: join(SHOTS, "6d-active-scan.png") });
  });

  await section("Crawl and audit", async () => {
    await page.getByLabel("Start URL").fill(`http://127.0.0.1:${shop}/`);
    await page.getByLabel("Pages to crawl").fill("15");
    await page.getByText("quick checks only").click();
    // ADR-0018: timers frozen, the task still goes from crawling through auditing to done, on `scans` events alone.
    await withFrozenTimers(async () => {
      await page.getByTestId("audit-start").click();
      await page.waitForSelector('[data-testid="audit-progress"] b:text-is("done")', { timeout: 120000 });
    });
    check(await page.getByTestId("audit-progress").textContent().then((t) => /\d+\/\d+ operations/.test(t)), "a crawl-and-audit task reaches done with its progress shown, without any page timer");
    check(await page.getByTestId("audit-issues").textContent().then((t) => t.includes("/search")), "crawl and audit finds the reflected XSS on /search");
    await page.screenshot({ path: join(SHOTS, "6e-crawl-audit.png") });
  });

  await section("Tools", async () => {
    await open("tools");
    await page.getByLabel("Codec input").fill("JTNDc2NyaXB0JTNF");
    await page.getByTestId("decode").click();
    await page.waitForSelector('[data-testid="decode-step"]');
    check(await page.getByTestId("decode-step").last().textContent() === "<script>", "smart decode peels base64 then URL encoding");
    await viaProxy(proxy, shop, "POST /api/password/reset HTTP/1.1\r\nHost: shop\r\nContent-Length: 0\r\n\r\n");
    const resetId = await recordedId("/api/password/reset");
    await page.getByLabel("Token exchange").fill(String(resetId));
    await page.getByLabel("Samples").fill("20");
    await page.getByLabel("Token locator").fill("json:/debug_code");
    await page.getByTestId("token-analyzer").click();
    await page.waitForSelector('[data-testid="token-analyzer-result"]', { timeout: 60000 });
    check(await page.getByTestId("token-analyzer-result").textContent().then((t) => t.includes("poor") && t.includes("increasing by 1")), "token analyzer spots the counter");
    await page.screenshot({ path: join(SHOTS, "6e-tools.png"), fullPage: true });
  });

  await section("Plugins", async () => {
    let python = false;
    try {
      execFileSync("python3", ["--version"]);
      python = true;
    } catch {
      console.log("  (python3 not found: skipping the active plugin)");
    }
    if (python) {
      pm("plugin", "add", new URL("../../examples/plugins/debug-switch", import.meta.url).pathname);
      await viaProxy(proxy, shop, "GET /api/products HTTP/1.1\r\nHost: shop\r\n\r\n");
      const productsId = await page.evaluate(async () => {
        for (let i = 0; i < 50; i++) {
          const rows = (await (await fetch("/api/v1/exchanges?path=/api/products&limit=20")).json()).exchanges;
          const row = rows.find((r) => r.path === "/api/products");
          if (row) return row.id;
          await new Promise((r) => setTimeout(r, 100));
        }
        return null;
      });
      await open(`plugins/${productsId}`);
      await page.waitForSelector('[data-testid="plugin-table"]');
      check(await page.getByTestId("plugin-sandbox").textContent().then((t) => t.startsWith("Sandbox:")), "the plugin sandbox status is shown");
      await page.getByTestId("plugin-run").click();
      await page.waitForSelector('[data-testid="plugin-result"]', { timeout: 60000 });
      check(await page.getByTestId("plugin-result").textContent().then((t) => t.includes("Hidden debug switch")), "an active plugin finds the hidden debug switch");
      pm("plugin", "add", new URL("../../examples/plugins/hosts-panel", import.meta.url).pathname);
      await page.reload();
      await page.getByTestId("panel-hosts-panel-hosts").click();
      await page.waitForSelector('[data-testid="plugin-panel"] table');
      check(await page.getByTestId("plugin-panel").textContent().then((t) => t.includes(`127.0.0.1:${shop}`)), "a plugin panel shows its table");
      await page.screenshot({ path: join(SHOTS, "6f-plugins.png"), fullPage: true });
      await page.getByTestId("plugin-toggle-debug-switch").click();
      await page.getByText("Off · turn on").waitFor();
      check(/debug-switch\s+\S+\s+active\s+off/.test(pm("plugin", "list")), "turning a plugin off is saved in the user's registry");
    }
  });

  await section("Plugin hooks (API 2)", async () => {
    let python = false;
    try {
      execFileSync("python3", ["--version"]);
      python = true;
    } catch {
      console.log("  (python3 not found: skipping the hook plugin)");
    }
    if (!python) return;
    const example = new URL("../../examples/plugins/sign-request", import.meta.url).pathname;
    pm("plugin", "add", example);
    await open("plugins");
    await page.reload(); // the CLI changed the registry behind the page's back
    await page.waitForSelector('[data-testid="plugin-permissions-sign-request"]');
    check(await page.getByTestId("plugin-permissions-sign-request").textContent().then((t) => t.includes("hooks.request")), "the Plugins page lists the permissions a v2 plugin asks for");
    check(await page.getByTestId("plugin-toggle-sign-request").isDisabled(), "a v2 plugin can't be turned on before its permissions are accepted");
    check(await page.getByTestId("hook-enable-sign-request-request").isDisabled(), "its hook can't be turned on either");
    await page.screenshot({ path: join(SHOTS, "6g-plugin-review.png"), fullPage: true });
    await page.getByTestId("plugin-accept-sign-request").click();
    await page.getByTestId("plugin-toggle-sign-request").getByText("On · turn off").waitFor();
    await page.getByTestId("hook-enable-sign-request-request").click();
    await page.getByTestId("hook-state-sign-request-request").getByText("on", { exact: true }).waitFor();
    check(true, "accepting the permissions and turning the hook on works from the Plugins page");

    const body = '{"username":"hook","password":"e2e"}';
    await viaProxy(proxy, shop, `POST /api/login?e2e=hook HTTP/1.1\r\nHost: shop\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`);
    const hookId = await recordedId("e2e=hook");
    const key = readFileSync(join(example, "signing.key"), "utf8").split("\n")[0].trim();
    const signature = createHmac("sha256", key).update(body).digest("hex");
    await open("history");
    await page.getByLabel("Filter", { exact: true }).fill("e2e=hook");
    await sleep(500);
    await page.getByTestId(`row-${hookId}`).click();
    await page.getByRole("tab", { name: "Request", exact: true }).click();
    const sentReq = await page.locator('[data-testid="exchange-detail"] pre.raw', { hasText: "X-Signature" }).first().textContent();
    check(sentReq.includes(`X-Signature: ${signature}`), "History's request shows the header the hook added");
    await page.getByTestId("tab-original_request").click();
    const origHook = await page.getByTestId("original-request-view").locator("pre.raw").first().textContent();
    check(!origHook.includes("X-Signature"), "the original request is kept without it");
    await page.getByTestId("tab-changes").click();
    const hookChanges = await page.getByTestId("changes-list").textContent();
    check(hookChanges.includes("sign-request/request") && hookChanges.includes("added X-Signature"), "the Changes tab names the hook");
    await page.screenshot({ path: join(SHOTS, "6h-hook-changes.png") });

    // Pausing stops it (and resuming starts it again); turning it off leaves the other sections alone.
    await open("plugins");
    await page.getByTestId("hook-pause-sign-request-request").click();
    await page.getByTestId("hook-state-sign-request-request").getByText("paused", { exact: true }).waitFor();
    await viaProxy(proxy, shop, `POST /api/login?e2e=hook-paused HTTP/1.1\r\nHost: shop\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`);
    const pausedId = await recordedId("e2e=hook-paused");
    const pausedEx = await page.evaluate(async (id) => (await fetch(`/api/v1/exchanges/${id}`)).json(), pausedId);
    check(!pausedEx.request.includes("X-Signature") && !(pausedEx.changes ?? []).some((c) => c.by === "hook"), "a paused hook leaves traffic alone");
    await page.getByTestId("hook-pause-sign-request-request").click();
    await page.getByTestId("hook-state-sign-request-request").getByText("on", { exact: true }).waitFor();
    await page.getByTestId("hook-enable-sign-request-request").click();
    await page.getByTestId("hook-state-sign-request-request").getByText("off", { exact: true }).waitFor();
  });

  await section("Custom checks", async () => {
    await viaProxy(proxy, shop, "GET /api/products HTTP/1.1\r\nHost: shop\r\n\r\n");
    const productsId = await page.evaluate(async () => {
      const rows = (await (await fetch("/api/v1/exchanges?path=/api/products&limit=50")).json()).exchanges;
      return rows.find((r) => r.path === "/api/products" && r.method === "GET").id;
    });
    await open(`checks/${productsId}`);
    await page.getByLabel("Check YAML").fill(`id: debug-switch
title: Hidden debug switch
severity: high
run: per_request
request:
  add_query: { debug: "1" }
match:
  status: [200]
  body_contains: [db_password]
  not_in_baseline: true
`);
    await page.getByTestId("check-save").click();
    await page.locator("td", { hasText: "Hidden debug switch" }).first().waitFor();
    await page.getByTestId("check-run").click();
    await page.waitForSelector('[data-testid="check-result"]');
    check(await page.getByTestId("check-result").textContent().then((t) => t.includes("1 hit")), "a saved YAML check finds the hidden debug switch");
    await page.screenshot({ path: join(SHOTS, "7c-custom-checks.png"), fullPage: true });
  });

  await section("DOM test", async () => {
    await viaProxy(proxy, shop, "GET /welcome HTTP/1.1\r\nHost: shop\r\n\r\n");
    await viaProxy(proxy, shop, "GET /static/welcome.js HTTP/1.1\r\nHost: shop\r\n\r\n");
    const welcomeId = await page.evaluate(async () => {
      for (let i = 0; i < 50; i++) {
        const rows = (await (await fetch("/api/v1/exchanges?path=/welcome&limit=20")).json()).exchanges;
        const js = (await (await fetch("/api/v1/exchanges?path=/static/welcome.js&limit=1")).json()).exchanges;
        const w = rows.find((r) => r.path === "/welcome");
        if (w && js.length) return w.id;
        await new Promise((r) => setTimeout(r, 100));
      }
      return null;
    });
    await open(`engage/dom:${welcomeId}`);
    await page.getByTestId("engage-dom").click();
    await page.waitForSelector('[data-testid="engage-dom-result"]', { timeout: 60000 });
    const domText = await page.getByTestId("engage-dom-result").textContent();
    check(domText.includes("innerHTML") && domText.includes("exploitable") && domText.includes("name"),
      "the DOM test finds the name parameter reaching innerHTML");
    await page.screenshot({ path: join(SHOTS, "7d-dom-test.png"), fullPage: true });
  });

  await section("Engagement (rules of engagement)", async () => {
    await open("engagement");
    await page.waitForSelector('[data-testid="roe-summary"]');
    check(await page.getByTestId("roe-summary").textContent().then((t) => t.includes(`http://127.0.0.1:${shop}/`)), "the scope in force is shown");
    await page.getByLabel("ROE YAML").fill(`version: 1\nengagement:\n  name: e2e engagement\nscope:\n  include: ["http://127.0.0.1:${shop}/"]\n  exclude: ["http://127.0.0.1:${shop}/api/admin/"]\n`);
    await page.getByTestId("roe-check").click();
    await page.getByText("Preview (not saved)").waitFor();
    check(await page.getByTestId("roe-summary").textContent().then((t) => t.includes("e2e engagement") && t.includes("Excluded")), "validate previews the new rules");
    await page.getByTestId("roe-save").click();
    await page.waitForSelector('[data-testid="roe-note"]');
    await page.locator(".meta", { hasText: "e2e engagement" }).waitFor();
    check(true, "the header shows the new engagement name");
    const excluded = await page.evaluate(async (shop) => {
      const r = await fetch("/api/v1/replay", { method: "POST", headers: { "Content-Type": "application/json", "X-ProxyMind": "1" },
        body: JSON.stringify({ url: `http://127.0.0.1:${shop}`, raw: "GET /api/admin/stats HTTP/1.1\r\nHost: shop\r\n\r\n" }) });
      return (await r.json()).status;
    }, shop);
    check(excluded === "denied", `the new exclusion applies at once (${excluded})`);
    await page.screenshot({ path: join(SHOTS, "7c-engagement.png"), fullPage: true });
  });

  await section("Proxy setup", async () => {
    await open("setup");
    await page.waitForSelector('[data-testid="ca-fingerprint"]');
    const caShown = await page.getByTestId("ca-fingerprint").textContent();
    const pem = await page.evaluate(async () => (await fetch("/api/v1/ca.pem")).text());
    check(caShown === new X509Certificate(pem).fingerprint256, "the CA fingerprint matches the downloaded certificate");
    check(await page.getByTestId("setup-proxy").textContent() === `127.0.0.1:${proxy}`, "the proxy address is shown");
  });

  await section("Built-in browser", async () => {
    await page.getByLabel("Start page").fill(`http://127.0.0.1:${shop}/search?q=from-pm-browser`);
    await page.screenshot({ path: join(SHOTS, "7a-builtin-browser.png") });
    const opened = page.waitForResponse((r) => r.url().endsWith("/api/v1/browser/open"));
    await page.getByTestId("setup-open-browser").click();
    const launchResponse = await opened;
    const launch = await launchResponse.json();
    check(launchResponse.ok(), `the built-in browser starts${launchResponse.ok() ? "" : ` (${JSON.stringify(launch)})`}`);
    await page.getByTestId("toast").waitFor();
    const seenByProxy = await page.waitForFunction(async () => {
      const p = await (await fetch("/api/v1/exchanges?path=from-pm-browser&limit=5")).json();
      return p.exchanges.some((x) => x.source === "proxy" && x.status === 200);
    }, null, { timeout: 30000 }).then(() => true).catch(() => false);
    check(seenByProxy, "ProxyMind's browser goes through the proxy (the page it opened is in history)");
    if (launch.pid) { try { process.kill(launch.pid); } catch {} }

    await page.getByTestId("record-in-scope").check();
    await page.waitForFunction(async () => (await (await fetch("/api/v1/history/recording")).json()).in_scope_only === true);
    check(true, "recording only in-scope traffic can be switched on");
    await page.getByTestId("record-in-scope").uncheck();
    await page.waitForFunction(async () => (await (await fetch("/api/v1/history/recording")).json()).in_scope_only === false);
  });

  await section("Proxy listeners", async () => {
    const extra = await freePort();
    await page.getByTestId("add-listener").click();
    await page.getByLabel("Listener 1 address").fill(`127.0.0.1:${extra}`);
    await page.getByLabel("Listener 1 redirect host").fill("127.0.0.1");
    await page.getByLabel("Listener 1 redirect port").fill(String(shop));
    await page.getByTestId("listeners-save").click();
    await page.locator('[data-testid="listener-status"]', { hasText: "listening" }).waitFor({ timeout: 5000 });
    check(true, "an extra listener starts without a restart");
    const invisible = await rawTo(extra, "GET /api/products HTTP/1.1\r\nHost: device.invalid\r\nConnection: close\r\n\r\n");
    check(invisible.startsWith("HTTP/1.1 200"), "a client that ignores proxies is redirected to the target");
    await page.screenshot({ path: join(SHOTS, "7d-listeners.png"), fullPage: true });
    await page.getByLabel("Delete listener 1").click();
    await page.getByTestId("listeners-save").click();
    await page.waitForFunction(() => !document.querySelector('[data-testid="listener-status"]'));
    check(await rawTo(extra, "GET / HTTP/1.1\r\n\r\n").then(() => false, () => true), "a removed listener stops");
  });

  await section("Capture modes: SOCKS5 and transparent listeners", async () => {
    await open("setup");
    // A SOCKS5 listener with a login.
    const socks = await freePort();
    await page.getByTestId("add-listener").click();
    await page.getByLabel("Listener 1 address").fill(`127.0.0.1:${socks}`);
    await page.getByLabel("Listener 1 type").selectOption("socks5");
    await page.getByLabel("Listener 1 username").fill("scout");
    await page.getByLabel("Listener 1 password").fill("s3cret");
    await page.getByTestId("listeners-save").click();
    await page.locator('[data-testid="listener-status"]', { hasText: "SOCKS5" }).waitFor({ timeout: 5000 });
    check(true, "a SOCKS5 listener starts without a restart");
    check((await page.getByLabel("Listener 1 password").inputValue()) === "********", "its password is shown masked");
    const req = (q) => `GET /api/products/search?q=${q} HTTP/1.1\r\nHost: 127.0.0.1:${shop}\r\nConnection: close\r\n\r\n`;
    const refused = await viaSocks5(socks, "127.0.0.1", shop, req("no-login")).then(() => "", (e) => e.message);
    check(refused.includes("no acceptable method"), "a SOCKS5 client without a login is refused");
    const wrong = await viaSocks5(socks, "127.0.0.1", shop, req("bad-login"), { username: "scout", password: "nope" }).then(() => "", (e) => e.message);
    check(wrong.includes("login rejected"), "a wrong password is refused");
    const ok = await viaSocks5(socks, "127.0.0.1", shop, req("via-socks5"), { username: "scout", password: "s3cret" });
    check(ok.startsWith("HTTP/1.1 200"), "a SOCKS5 client with the login gets the response");
    await open("history");
    await page.getByLabel("Filter", { exact: true }).fill("via-socks5");
    await page.locator('[data-testid^="row-"]').first().waitFor({ timeout: 10000 });
    check(true, "the request tunnelled through SOCKS5 shows in History");
    await page.screenshot({ path: join(SHOTS, "7d2-socks5.png"), fullPage: true });
    await open("setup");
    await page.getByLabel("Delete listener 1").click();
    await page.getByTestId("listeners-save").click();
    await page.waitForFunction(() => !document.querySelector('[data-testid="listener-status"]'));
    check(await socks5Connect(socks, "127.0.0.1", shop).then((s) => (s.destroy(), false), () => true), "a removed SOCKS5 listener stops");

    // Transparent mode: Linux only, greyed out elsewhere. Without iptables a client simply connects to the
    // listener, which then behaves like an ordinary invisible client.
    const linux = process.platform === "linux";
    const tp = await freePort();
    await page.getByTestId("add-listener").click();
    await page.getByLabel("Listener 1 address").fill(`127.0.0.1:${tp}`);
    const box = page.getByLabel("Listener 1 transparent");
    check((await box.isEnabled()) === linux, linux ? "the transparent option is available on Linux" : "the transparent option is greyed out here");
    if (!linux) {
      check(await page.getByTestId("transparent-unsupported").isVisible(), "and the page says why");
    } else {
      await box.check();
      await page.getByTestId("listeners-save").click();
      await page.locator('[data-testid="listener-status"]', { hasText: "transparent" }).waitFor({ timeout: 5000 });
      const plain = await rawTo(tp, `GET /api/products HTTP/1.1\r\nHost: 127.0.0.1:${shop}\r\nConnection: close\r\n\r\n`);
      check(plain.startsWith("HTTP/1.1 200"), "a transparent listener serves a client that was not redirected");
      await page.getByLabel("Delete listener 1").click();
      await page.getByTestId("listeners-save").click();
      await page.waitForFunction(() => !document.querySelector('[data-testid="listener-status"]'));
    }
    if (!linux) await page.getByLabel("Delete listener 1").click();
  });

  await section("Raw TCP streams (a non-HTTP protocol through CONNECT, Streams page, replay)", async () => {
    // A line protocol where the server speaks first: greets, then answers each line in capitals.
    const lineServer = net.createServer((c) => {
      c.write("220 hello\r\n");
      c.on("data", (d) => c.write(String(d).toUpperCase()));
      c.on("error", () => {});
    });
    await new Promise((r) => lineServer.listen(0, "127.0.0.1", r));
    const rawPort = lineServer.address().port;
    const roeText = `version: 1\nscope:\n  include: ["http://127.0.0.1:${shop}/", "http://127.0.0.1:${rawPort}/"]\n`;
    const putRoe = (text) =>
      page.evaluate(async (text) => (await fetch("/api/v1/roe", { method: "PUT", headers: { "content-type": "application/json", "x-proxymind": "1" }, body: JSON.stringify({ text }) })).status, text);
    const originalRoe = await page.evaluate(async () => (await (await fetch("/api/v1/roe")).json()).text);
    check((await putRoe(roeText)) === 200, "the line server is added to the scope (replay checks scope)");
    // CONNECT through the proxy, wait for the greeting, send a line, read the answer.
    const talk = (line) =>
      new Promise((resolve, reject) => {
        const s = net.connect(proxy, "127.0.0.1", () => s.write(`CONNECT 127.0.0.1:${rawPort} HTTP/1.1\r\nHost: 127.0.0.1:${rawPort}\r\n\r\n`));
        let out = "";
        let sent = false;
        s.on("data", (d) => {
          out += d;
          if (!sent && out.includes("220 hello\r\n")) {
            sent = true;
            s.write(line);
          }
          if (out.includes(line.toUpperCase())) {
            s.end();
            resolve(out);
          }
        });
        s.on("error", reject);
        setTimeout(() => (s.destroy(), reject(new Error(`no answer: ${out}`))), 8000);
      });
    await open("streams");
    // With the page's timers frozen, only a server event can bring the new stream into the list.
    await withFrozenTimers(async () => {
      const out = await talk("ping the proxy\r\n");
      check(out.includes("PING THE PROXY\r\n"), "the non-HTTP stream is relayed unchanged through CONNECT");
      await page.locator('[data-testid="streams-list"] tr', { hasText: `127.0.0.1:${rawPort}` }).first().waitFor({ timeout: 8000 });
    });
    check(true, "the Streams page lists the stream without polling");
    await page.locator('[data-testid="streams-list"] tr', { hasText: `127.0.0.1:${rawPort}` }).first().click();
    const detail = page.getByTestId("stream-detail");
    await detail.waitFor();
    await page.waitForFunction(() => document.querySelector('[data-testid="stream-ended"]')?.textContent !== "open", null, { timeout: 8000 });
    const chunks = detail.getByTestId("stream-chunk");
    await chunks.nth(2).waitFor({ timeout: 8000 });
    const dirs = await chunks.evaluateAll((els) => els.map((e) => e.getAttribute("data-from")));
    check(dirs[0] === "server" && dirs.includes("client"), `chunks are in order with their directions (${dirs.join(", ")})`);
    check((await chunks.first().textContent()).includes("220 hello"), "the text view shows the server's greeting");
    await detail.getByRole("button", { name: "Hex", exact: true }).click();
    check((await detail.getByTestId("stream-chunks").textContent()).includes("32 32 30 20 68 65 6c 6c 6f"), "the hex view shows the bytes");
    await detail.getByRole("button", { name: "Text", exact: true }).click();
    await page.getByLabel("Search in stream").fill("ping the");
    check(await page.getByTestId("stream-matches").textContent().then((t) => t.startsWith("2 of ")), "search narrows the chunks of the stream");
    await page.getByLabel("Search in stream").fill("");
    await page.screenshot({ path: join(SHOTS, "7d3-streams.png"), fullPage: true });
    // Replay with an edited chunk: a new connection, recorded as a new stream.
    await detail.getByRole("button", { name: "Replay stream…" }).click();
    await page.getByLabel("Chunk 1 to send").fill("edited and replayed\r\n");
    await page.getByLabel("Listen for (ms)").fill("500");
    await page.getByTestId("stream-replay-send").click();
    const result = await page.getByTestId("stream-replay-result").textContent({ timeout: 10000 });
    check(/Sent \d+ bytes, received \d+; recorded as stream #\d+/.test(result), `replay sends the edited chunk and records a new stream (${result.trim()})`);
    await page.getByTestId("stream-replay-result").getByRole("link", { name: "Open it" }).click();
    await page.locator('[data-testid="stream-chunks"]', { hasText: "EDITED AND REPLAYED" }).waitFor({ timeout: 8000 });
    check(true, "the new stream shows the server's answer to the edited bytes");
    // Out of scope: the gate refuses.
    check((await putRoe(`version: 1\nscope:\n  include: ["http://127.0.0.1:${shop}/"]\n`)) === 200, "the line server leaves the scope");
    await page.getByRole("button", { name: "Replay stream…" }).click();
    await page.getByTestId("stream-replay-send").click();
    check(await page.getByTestId("stream-replay-denied").textContent({ timeout: 8000 }).then((t) => /scope/i.test(t)), "replay of an out-of-scope target is denied by the policy gate");
    await putRoe(originalRoe);
    lineServer.close();
  });

  await section("Mobile onboarding (setup page, QR code, devices)", async () => {
    await open("setup");
    // The main proxy listens on loopback only: a phone cannot reach it, and the page says so.
    await page.getByTestId("mobile-unreachable").waitFor();
    check((await page.getByTestId("mobile-qr").count()) === 0, "a loopback-only proxy gets no QR code, only how to fix it");
    // Add a listener on every interface (as the page suggests).
    const lan = await freePort();
    await page.getByTestId("add-listener").click();
    await page.getByLabel("Listener 1 address").fill(`0.0.0.0:${lan}`);
    await page.getByTestId("listeners-save").click();
    await page.locator('[data-testid="listener-status"]', { hasText: "listening" }).waitFor({ timeout: 5000 });
    await page.reload();
    await page.getByTestId("mobile-url").waitFor();
    const url = (await page.getByTestId("mobile-url").textContent()).trim();
    check(url === `http://${process.env.PROXYMIND_LAN_ADDR}:${lan}/`, `the page to open on the phone is shown (${url})`);
    check((await page.getByTestId("mobile-proxy").textContent()) === `${process.env.PROXYMIND_LAN_ADDR}:${lan}`, "and the proxy address to type into the phone");
    const qr = page.getByTestId("mobile-qr");
    check(
      (await qr.evaluate((i) => i.tagName === "IMG" && i.src.startsWith("data:image/svg+xml;base64,") && i.complete && i.naturalWidth > 0)) === true,
      "the QR code is an image (an <img> with a data URL), not markup in the page",
    );
    check(await page.evaluate(() => !document.querySelector(".panel svg[viewBox]")), "the SVG is never inserted into the page itself");
    check((await page.getByTestId("mobile-guide").getAttribute("href")).endsWith("docs/mobile.md"), "the setup page links the Android and iOS guide");
    await page.screenshot({ path: join(SHOTS, "7e-mobile.png"), fullPage: true });

    // The page a phone opens, fetched through the proxy by its reserved name, and straight from the listener.
    const pem = await page.evaluate(async () => (await fetch("/api/v1/ca.pem")).text());
    const fp = new X509Certificate(pem).fingerprint256;
    const hit = await rawTo(proxy, "GET http://proxymind.setup/ HTTP/1.1\r\nHost: proxymind.setup\r\nConnection: close\r\n\r\n");
    check(hit.startsWith("HTTP/1.1 200") && hit.includes('href="/ca.crt"') && hit.includes('href="/ca.pem"'), "http://proxymind.setup/ through the proxy shows the CA download links");
    check(hit.includes(fp), "and the CA fingerprint the setup page shows");
    check(!hit.includes("<script") && !/pm2_[0-9a-f]{20}/.test(hit), "with no scripts and nothing secret");
    const direct = await rawTo(lan, `GET / HTTP/1.1\r\nHost: 127.0.0.1:${lan}\r\nConnection: close\r\n\r\n`);
    check(direct.startsWith("HTTP/1.1 200") && direct.includes("ProxyMind setup"), "the listener's own address serves the same page (no proxy setting needed yet)");
    const download = (path) =>
      new Promise((resolve, reject) => {
        const r = http.request({ host: "127.0.0.1", port: proxy, path: `http://proxymind.setup${path}`, headers: { Host: "proxymind.setup" } }, (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve({ type: res.headers["content-type"], body: Buffer.concat(chunks) }));
        });
        r.on("error", reject).end();
      });
    const crt = await download("/ca.crt");
    check(crt.type === "application/x-x509-ca-cert" && new X509Certificate(crt.body).fingerprint256 === fp, "/ca.crt is the CA in DER form, as a certificate download");
    const pemDl = await download("/ca.pem");
    check(pemDl.type === "application/x-pem-file" && pemDl.body.toString() === pem, "/ca.pem is the PEM file");
    await sleep(500);
    const local = await page.evaluate(async () => (await (await fetch("/api/v1/exchanges?host=proxymind&limit=5")).json()).exchanges.length);
    check(local === 0, "none of that is recorded as target traffic");

    // Devices: a second client address (127.0.0.2, where the OS allows it) shows up, can be named and filtered.
    const from = (localAddress, raw) =>
      new Promise((resolve, reject) => {
        const sock = net.connect({ host: "127.0.0.1", port: proxy, localAddress }, () => sock.write(raw.replace(" /", ` http://127.0.0.1:${shop}/`)));
        let out = "";
        sock.on("data", (d) => (out += d));
        sock.on("end", () => resolve(out));
        sock.on("error", reject);
        setTimeout(() => sock.destroy(), 5000);
      });
    const second = "127.0.0.2";
    const reply = await from(second, "GET /api/products?from=second-device HTTP/1.1\r\nHost: shop\r\nConnection: close\r\n\r\n").catch(() => "");
    await viaProxy(proxy, shop, "GET /api/products?from=first-device HTTP/1.1\r\nHost: shop\r\nConnection: close\r\n\r\n");
    if (!reply.startsWith("HTTP/1.1 200")) {
      console.log("  (this system cannot connect from 127.0.0.2: the second-device checks are skipped)");
      check(true, "skipped: no second client address here");
      return;
    }
    check((await recordedId("from=second-device")) !== null, "traffic from a second device is recorded");
    await page.reload();
    await page.getByTestId(`device-name-${second}`).waitFor();
    check((await page.getByTestId("devices").textContent()).includes("127.0.0.1"), "the devices list shows both client addresses");
    await page.getByTestId(`device-name-${second}`).fill("Pixel 8");
    await page.getByTestId(`device-name-${second}`).press("Enter");
    await page.waitForFunction(async () => (await (await fetch("/api/v1/devices")).json()).devices.some((d) => d.name === "Pixel 8"));
    check(true, "a device can be given a name");

    await open("history");
    await page.getByLabel("Filter", { exact: true }).fill("from=");
    await page.locator('[data-testid="client-cell"]', { hasText: "Pixel 8" }).first().waitFor();
    const cells = await page.locator('[data-testid="client-cell"]').allTextContents();
    check(cells.includes("Pixel 8") && cells.includes("127.0.0.1"), `History has a Client column with the device name or address (${cells.join(", ")})`);
    await page.getByTestId("client-filter").selectOption(second);
    await page.waitForFunction(() => document.querySelectorAll('[data-testid="client-cell"]').length === 1);
    check((await page.locator('[data-testid^="row-"]').first().textContent()).includes("from=second-device"), "the device filter shows only that device's traffic");
    await page.getByTestId("client-filter").selectOption("");
    await page.getByLabel("Query", { exact: true }).fill('client:"Pixel 8"');
    await page.getByLabel("Query", { exact: true }).press("Enter");
    await page.waitForFunction(() => document.querySelectorAll('[data-testid="client-cell"]').length === 1);
    check(true, "the query language has client: (by name)");
    await page.getByLabel("Query", { exact: true }).fill("client:127.0.0.1 from=");
    await page.getByLabel("Query", { exact: true }).press("Enter");
    await sleep(600);
    check((await page.locator('[data-testid="client-cell"]').allTextContents()).every((t) => t === "127.0.0.1"), "client: also takes an address");
    await page.getByTestId("clear-query").click();
    await page.getByLabel("Filter", { exact: true }).fill("");
    await page.screenshot({ path: join(SHOTS, "7f-devices-history.png") });

    // Record only one device: the other is still proxied but not saved.
    await open("setup");
    await page.getByTestId(`device-record-${second}`).check();
    await page.waitForFunction(async (a) => (await (await fetch("/api/v1/history/recording")).json()).record_devices?.includes(a), second);
    check((await page.getByTestId("record-devices-note").textContent()).includes("Only traffic from"), "choosing a device to record is explained");
    const firstReply = await viaProxy(proxy, shop, "GET /api/products?x=not-recorded HTTP/1.1\r\nHost: shop\r\nConnection: close\r\n\r\n");
    await from(second, "GET /api/products?x=recorded HTTP/1.1\r\nHost: shop\r\nConnection: close\r\n\r\n");
    check(firstReply.startsWith("HTTP/1.1 200"), "other devices are still proxied");
    check((await recordedId("x=recorded")) !== null, "the chosen device's traffic is recorded");
    check((await recordedId("x=not-recorded")) === null, "other devices' traffic is not");
    await page.getByTestId(`device-record-${second}`).uncheck();
    await page.waitForFunction(async () => ((await (await fetch("/api/v1/history/recording")).json()).record_devices ?? []).length === 0);

    // Clean up the extra listener.
    await page.getByLabel("Delete listener 1").click();
    await page.getByTestId("listeners-save").click();
    await page.waitForFunction(() => !document.querySelector('[data-testid="listener-status"]'));
  });

  await section("Network: hostname overrides and TLS pass-through", async () => {
    await open("network");
    await page.getByTestId("add-host").click();
    await page.getByLabel("Override 1 host").fill("*.staging.invalid");
    await page.getByLabel("Override 1 address").fill("10.9.8.7");
    await page.getByLabel("TLS pass-through hosts").fill("pinned.invalid\n*.telemetry.invalid");
    await page.getByTestId("network-save").click();
    await page.waitForSelector("text=Saved. The proxy");
    const savedNet = await page.evaluate(async () => (await fetch("/api/v1/network")).json());
    check(savedNet.hosts[0].address === "10.9.8.7" && savedNet.tls_passthrough.length === 2, "overrides and pass-through hosts are saved");
    await page.getByLabel("Delete override 1").click();
    await page.getByLabel("TLS pass-through hosts").fill("");
    await page.getByTestId("network-save").click();
    await page.waitForSelector("text=Saved. The proxy");
  });

  await section("Session handling", async () => {
    await open("sessions");
    await page.getByTestId("add-macro").click();
    await page.getByLabel("Macro 1 name").fill("login");
    await page.getByLabel("Macro 1 step 1 target").fill(`http://127.0.0.1:${shop}`);
    const macroBody = JSON.stringify({ username: "alice", password: "alice123" });
    await page.getByLabel("Macro 1 step 1 request").fill(`POST /api/login HTTP/1.1\nHost: shop\nContent-Type: application/json\n\n${macroBody}`);
    await page.getByRole("button", { name: "Extract a variable" }).click();
    await page.getByLabel("Step 1 variable 1", { exact: true }).fill("token");
    await page.getByLabel("Step 1 variable 1 source").selectOption("json");
    await page.getByLabel("Step 1 variable 1 expression").fill("/token");
    await page.getByTestId("add-rule").click();
    await page.getByLabel("Rule 1 cookie jar").uncheck();
    await page.getByLabel("Rule 1 macro").selectOption("login");
    await page.getByRole("button", { name: "Add value" }).click();
    await page.getByLabel("Rule 1 set 1 name").fill("Authorization");
    await page.getByLabel("Rule 1 set 1 value").fill("Bearer {{token}}");
    await page.getByTestId("session-save").click();
    await page.waitForSelector("text=Saved. Rules apply");
    const meStatus = await page.evaluate(async (shop) => {
      const r = await fetch("/api/v1/replay", { method: "POST", headers: { "Content-Type": "application/json", "X-ProxyMind": "1" },
        body: JSON.stringify({ url: `http://127.0.0.1:${shop}`, raw: "GET /api/me HTTP/1.1\r\nHost: shop\r\n\r\n" }) });
      const j = await r.json();
      const ex = await (await fetch(`/api/v1/exchanges/${j.exchange_id}`)).json();
      return [ex.summary.status, ex.request.includes("Bearer ")];
    }, shop);
    check(meStatus[0] === 200 && meStatus[1], `a request without credentials gets logged in by the rule (${meStatus})`);
    await page.getByTestId("macro-run").click();
    await page.waitForSelector('[data-testid="macro-result"]');
    check((await page.getByTestId("macro-result").textContent()).includes("token = "), "Run now shows the variables a macro sets");
    await page.getByRole("button", { name: "Refresh" }).click();
    await page.locator('[data-testid="jar"] td', { hasText: "session" }).first().waitFor({ timeout: 5000 });
    check(true, "the cookie jar holds the session cookie from the login");
    await page.screenshot({ path: join(SHOTS, "7e-sessions.png"), fullPage: true });
    await page.getByLabel("Delete rule 1").click();
    await page.getByTestId("session-save").click();
    await page.waitForSelector("text=Saved. Rules apply");
  });

  await section("Scans: profiles, schedules, tasks", async () => {
    await open("scans");
    await page.locator('[data-testid="scan-profiles"] strong', { hasText: "api-only" }).waitFor();
    check(true, "built-in scan profiles are listed");
    await page.getByLabel("Profile name").fill("e2e-quick");
    await page.getByLabel("Profile checks").fill("reflected_input");
    await page.getByText("crawl first").click();
    await page.getByRole("button", { name: "Save profile" }).click();
    await page.locator('[data-testid="scan-profiles"] strong', { hasText: "e2e-quick" }).waitFor();
    check(true, "a saved profile joins the list");
    await page.getByLabel("Scan URL").fill(`http://127.0.0.1:${shop}/`);
    await page.getByLabel("Scan profile").selectOption("e2e-quick");
    await withFrozenTimers(async () => {
      await page.getByTestId("scan-start").click();
      await page.locator('[data-testid="scan-tasks"] td', { hasText: "e2e-quick" }).first().waitFor();
      await page.locator('[data-testid="scan-tasks"] tr', { hasText: "e2e-quick" }).filter({ hasText: "done" }).first().waitFor({ timeout: 60000 });
    });
    check(true, "a scan with a saved profile runs to the end (page timers frozen: the list follows `scans` events)");
    await page.getByLabel("Schedule name").fill("e2e nightly");
    await page.getByLabel("Schedule URL").fill(`http://127.0.0.1:${shop}/`);
    await page.getByLabel("Schedule profile").selectOption("e2e-quick");
    await page.getByLabel("Schedule frequency").selectOption("weekly");
    await page.getByLabel("Schedule day").selectOption("sun");
    await page.getByTestId("schedule-add").click();
    await page.locator('[data-testid="scan-schedules"] td', { hasText: "every sun at 02:00 UTC" }).waitFor();
    check(true, "a weekly schedule is saved");
    await page.locator('[data-testid="scan-schedules"]').getByRole("button", { name: "Run now" }).click();
    await page.locator('[data-testid="scan-tasks"] td', { hasText: "schedule #" }).first().waitFor({ timeout: 10000 });
    check(true, "Run now starts the schedule's scan");
    await page.screenshot({ path: join(SHOTS, "2c-scans.png"), fullPage: true });
  });

  await section("Recorded login", async () => {
    await open("authz");
    await page.getByLabel("Login identity name").fill("carol");
    await page.getByRole("button", { name: "Start recording" }).click();
    await page.waitForSelector("text=recording after #");
    await browseAs(proxy, shop, "alice", ["/api/me"]);
    await page.getByRole("button", { name: "Stop & save" }).click();
    await page.waitForSelector('[data-testid="record-login-result"] >> text=1-step login');
    check(true, "a login done through the proxy becomes a login recipe");
    await page.waitForSelector('[data-testid="logged-out-learned"]', { timeout: 15000 });
    const learnedText = await page.getByTestId("logged-out-learned").textContent();
    check(learnedText.includes("logged out when") || learnedText.includes("usual signs"), `logged-out look learned (${learnedText})`);
    await page.locator("td", { hasText: "knows its logged-out look" }).first().waitFor({ timeout: 5000 });
    check(true, "the identity list shows the learned logged-out look");
    await page.screenshot({ path: join(SHOTS, "3b-record-login.png"), fullPage: true });
  });

  await section("Model, coverage and audit", async () => {
    await open("model");
    await page.locator('[data-testid="operations"] strong', { hasText: "/api/orders/{id}" }).waitFor();
    check(true, "model shows /api/orders/{id}");
    await page.getByLabel("Snapshot name").fill("e2e round 1");
    await page.getByTestId("snapshot-save").click();
    await page.getByTestId("changes-compare").click();
    await page.getByTestId("changes-result").waitFor();
    check(await page.getByTestId("changes-result").textContent().then((t) => t.includes("e2e round 1") && t.includes("unchanged")), "a model snapshot compares with the current model");
    await page.screenshot({ path: join(SHOTS, "7-model.png"), fullPage: true });
    await open("authz");
    await page.getByTestId("authz-matrix-run").click();
    await page.getByTestId("authz-matrix-summary").waitFor({ timeout: 60000 });
    check(await page.getByTestId("authz-matrix").textContent().then((t) => t.includes("/api/orders/{id}") && t.includes("SAME DATA")), "the authorization matrix shows bob getting alice's order");
    check(await page.getByTestId("authz-matrix-summary").textContent().then((t) => /[1-9]\d* proven/.test(t)), "the matrix proves the flagged cell");
    await page.screenshot({ path: join(SHOTS, "3c-authz-matrix.png"), fullPage: true });
    await open("audit");
    await page.waitForSelector('[data-testid="audit-verify"]');
    check(await page.getByTestId("audit-verify").textContent().then((t) => t.includes("intact")), "audit log verified intact");
    await page.screenshot({ path: join(SHOTS, "8-audit.png") });
  });

  await section("Workflows (extract + send, run on an exchange, History, live runs, Fuzzer option)", async () => {
    const api = (method, path, body) =>
      page.evaluate(async ([method, path, body]) => {
        const r = await fetch(`/api/v1${path}`, { method, headers: { "Content-Type": "application/json", "X-ProxyMind": "1" }, body: body === undefined ? undefined : JSON.stringify(body) });
        return [r.status, await r.json()];
      }, [method, path, body]);

    // History's right-click menu opens the Workflows page with the exchange filled in.
    await open("history");
    await (await rowFor("/api/orders/1001", 0)).click({ button: "right" });
    await page.getByRole("menuitem", { name: "Run workflow…" }).click();
    await page.waitForFunction(() => window.location.hash.startsWith("#/workflows/"));
    await page.getByTestId("workflows-page").waitFor();
    // The row is alice's own request through the proxy (the oldest with this path), so its answer is her order.
    const orderEx = Number(await page.getByLabel("Run on exchange").inputValue());
    check(orderEx > 0, `Run workflow… from History fills in the exchange (#${orderEx})`);

    // Build a two-step workflow: read the order's id from the response, send a request with it.
    await page.getByTestId("wf-new").click();
    await page.getByLabel("Workflow name").fill("e2e-order-id");
    await page.getByLabel("Workflow description").fill("Read the order id, look it up as a product query");
    await page.getByLabel("Step 1 type").selectOption("extract");
    await page.getByLabel("Step 1 variable").fill("oid");
    await page.getByLabel("Step 1 kind").selectOption("json");
    await page.getByLabel("Step 1 expression").fill("/id");
    await page.getByTestId("add-send").click();
    await page.getByLabel("Step 2 request").fill("GET /api/products?order={{oid}} HTTP/1.1\nHost: shop\n\n");
    await page.getByTestId("wf-save").click();
    await page.locator('[data-testid="wf-row"]', { hasText: "e2e-order-id" }).waitFor();
    check(await page.locator('[data-testid="wf-row"]', { hasText: "e2e-order-id" }).textContent().then((t) => t.includes("extract → send")), "the saved workflow lists its steps");
    await page.screenshot({ path: join(SHOTS, "7f-workflows.png"), fullPage: true });

    // Run it on the exchange: the run shows both steps, the variable and the exchange it sent.
    await page.locator('[data-testid="wf-row"]', { hasText: "e2e-order-id" }).getByTestId("wf-run").click();
    await page.getByTestId("run-detail").waitFor();
    check(await page.getByTestId("run-status").first().textContent().then((t) => t.trim() === "ok"), "the run is ok");
    check((await page.getByTestId("run-step").count()) === 2, "the run lists its two steps");
    check(await page.getByTestId("run-variables").textContent().then((t) => t.includes("oid = 1001")), "the run shows the variable the extract set");
    const sentLink = page.getByTestId("run-step").nth(1).locator("a");
    const sentId = Number((await sentLink.textContent()).replace("#", ""));
    check(sentId > orderEx, `the send step links the exchange it made (#${sentId})`);
    await page.getByTestId("wf-run-row").first().waitFor();
    await sentLink.click();
    await page.waitForFunction((id) => window.location.hash === `#/history/${id}`, sentId);
    const [st, ex] = await api("GET", `/exchanges/${sentId}`);
    check(st === 200 && ex.summary.source === "workflow" && ex.summary.path === "/api/products?order=1001", "History has the request the workflow sent, as source workflow, with the variable filled in");

    // ADR-0018: a run started elsewhere shows up in the run history with every page timer frozen.
    await open("workflows");
    // Count only once the run list has loaded (the run above is in it), or a late first load looks like a new run.
    await page.getByTestId("wf-run-row").first().waitFor();
    const before = await page.getByTestId("wf-run-row").count();
    await withFrozenTimers(async () => {
      await api("POST", "/workflows/e2e-order-id/run", { exchange_id: orderEx });
      await page.waitForFunction((n) => document.querySelectorAll('[data-testid="wf-run-row"]').length > n, before, { timeout: 15000 });
    });
    check((await page.getByTestId("wf-run-row").count()) === before + 1, "a run started elsewhere appears in the run history without a page timer");
    await page.getByTestId("wf-run-row").first().click();
    check(await page.getByTestId("run-detail").textContent().then((t) => t.includes("sent, status 200")), "clicking a run shows its steps");

    // A match that does not fit stops the run with the reason; the trigger needs a first match step.
    await api("POST", "/workflows", { name: "e2e-only-posts", steps: [{ type: "match", method: "POST", message: "only POSTs" }, { type: "send", url: `http://127.0.0.1:${shop}`, raw: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" }] });
    await open("workflows");
    await page.locator('[data-testid="wf-row"]', { hasText: "e2e-only-posts" }).getByTestId("wf-run").click();
    await page.getByTestId("run-reason").waitFor();
    check(await page.getByTestId("run-reason").textContent().then((t) => t.includes("only POSTs")), "a failed match stops the run and says why");
    const trig = page.getByLabel("Run e2e-only-posts on new traffic");
    check(await trig.isEnabled(), "a workflow with a first match step can run on new traffic");
    check(await page.getByLabel("Run e2e-order-id on new traffic").isDisabled(), "one without cannot");
    check((await api("PUT", "/workflows/e2e-order-id/trigger", { enabled: true }))[0] === 400, "the API refuses a trigger without a first match step");

    // The Fuzzer can run a workflow on each result.
    await api("POST", "/workflows", { name: "e2e-per-result", steps: [{ type: "assert", status: "200", message: "ok" }] });
    await page.goto(link.replace(/\/auth.*/, "/#/fuzzer"));
    await page.getByLabel("Target").fill(`http://127.0.0.1:${shop}`);
    await page.getByLabel("Request").fill("GET /api/products?q=§a§ HTTP/1.1\nHost: shop\n\n");
    await page.getByLabel("Payload type").selectOption("list");
    await page.getByLabel("Payloads", { exact: true }).fill("a\nb");
    await page.getByLabel("Workflow on each result").selectOption("e2e-per-result");
    await page.getByTestId("fuzzer-run").click();
    await page.waitForFunction(() => document.querySelector('[data-testid="fuzzer-summary"]')?.textContent?.includes("· done ·"), null, { timeout: 30000 });
    await page.waitForFunction(() => document.querySelectorAll('[data-testid="workflow-cell"]').length === 2);
    check((await page.getByTestId("workflow-cell").allTextContents()).every((t) => t.startsWith("ok")), "each Fuzzer result shows what its workflow made of it");
    await page.getByLabel("Workflow on each result").selectOption("");
  });

  await section("Integrations: delivery of a proven finding, and an issue on GitHub", async () => {
    // The IDOR was proven earlier; the webhook subscribed to "finding proven" got it, redacted and signed.
    for (let i = 0; i < 50 && !hookGot.some((g) => JSON.parse(g.body).event === "finding_proven"); i++) await sleep(100);
    const proven = hookGot.find((g) => JSON.parse(g.body).event === "finding_proven");
    check(!!proven, "the webhook got the finding_proven event");
    const p = JSON.parse(proven.body);
    check(p.v === 1 && p.data.finding.status === "proven" && p.data.finding.title === "Any user can read any order", "the payload is version 1 and describes the finding");
    check(proven.headers["x-proxymind-signature"] === "sha256=" + createHmac("sha256", HOOK_SECRET).update(proven.body).digest("hex"), "the finding event is signed");
    const leak = proven.body.match(/.{0,40}(session=|Authorization:|Bearer ).{0,40}/i);
    check(!leak, `no cookie or token is in the payload${leak ? `: ${leak[0]}` : ""}`);
    await open("integrations");
    await page.waitForFunction(() => document.querySelector('[data-testid="deliveries-e2e-hook"]')?.textContent?.includes("finding_proven"));
    check(true, "the delivery log lists the finding_proven delivery");

    await open("findings");
    await page.getByTestId("findings").getByText("Any user can read any order").click();
    await page.getByTestId("create-issue").click();
    await page.waitForSelector('[data-testid="issue-link"]');
    check((await page.getByTestId("issue-link").textContent()).includes("#42"), "the finding shows the created issue's key");
    check((await page.getByTestId("issue-link").locator("a").getAttribute("href")) === "https://github.com/acme/app/issues/42", "and links to it");
    const created = ghGot.find((g) => g.method === "POST");
    check(created?.url === "/repos/acme/app/issues" && created.headers.authorization === `Bearer ${GH_TOKEN}`, "GitHub got POST /repos/acme/app/issues with the token");
    const issue = JSON.parse(created.body);
    check(issue.title.includes("Any user can read any order") && issue.body.includes("### Reproduction") && !/(session=|Bearer |Authorization: )(?!\{\{secret:)/i.test(issue.body), "the issue has the reproduction and no raw credentials");
    check((await page.getByTestId("create-issue").textContent()).includes("Update issue"), "sending again offers an update, not a duplicate");
  });

  // ADR-0018: no live page polls. The built bundle must not call setInterval at all. A polling setTimeout chain
  // cannot be told from a debounce in minified code, so it is checked two other ways: the sections above run with
  // the page's timers frozen, and the sources may call setTimeout only in the files below, each a one-shot (toast
  // dismissal, autosave and filter debounces, focusing an input, revoking a download URL). A new file that wants a
  // timer must be looked at, then added here.
  const srcDir = new URL("../src/", import.meta.url).pathname;
  const oneShot = ["App.tsx", "api.ts", "palette.tsx", "pages/AiScan.tsx", "pages/Engage.tsx", "pages/History.tsx", "pages/Replay.tsx", "pages/WsHistory.tsx"];
  const withTimeout = readdirSync(srcDir, { recursive: true })
    .map((f) => String(f).replace(/\\/g, "/"))
    .filter((f) => /\.tsx?$/.test(f) && readFileSync(join(srcDir, f), "utf8").includes("setTimeout("))
    .sort();
  check(JSON.stringify(withTimeout) === JSON.stringify([...oneShot].sort()), `setTimeout appears only in the known one-shot files (${withTimeout.join(", ")})`);
  const assets = new URL("../dist/assets/", import.meta.url).pathname;
  const bundles = readdirSync(assets).filter((f) => f.endsWith(".js"));
  const withInterval = bundles.filter((f) => readFileSync(join(assets, f), "utf8").includes("setInterval("));
  check(bundles.length > 0 && withInterval.length === 0, `the UI bundle has no setInterval( (${bundles.length} file(s) checked${withInterval.length ? "; found in " + withInterval.join(", ") : ""})`);

  // A fresh browser without the cookie is refused.
  const other = await browser.newPage();
  await other.goto(link.replace(/\/auth.*/, "/"));
  await other.waitForSelector("text=Not signed in");
  check(true, "a browser without the token sees 'Not signed in'");

  const unexpected = consoleErrors.filter((e) => !e.includes("q=stauts%3A200") && !e.includes("/api/v1/recon/dns") && !(e.includes("400 (Bad Request)") && e.includes("/workflows/e2e-order-id/trigger")) && !(e.includes("400 (Bad Request)") && e.endsWith("/api/v1/network)")));
  check(unexpected.length === 0, `no console errors${unexpected.length ? ": " + unexpected.join(" | ") : ""}`);
  if (failedResponses.length) console.log(`  (failed requests during the run: ${failedResponses.join(" | ")})`);
  await browser.close();
} catch (e) {
  console.error(e);
  failures++;
} finally {
  for (const c of children) c.kill();
  for (const r of typeof receivers === "undefined" ? [] : receivers) r.close();
}
console.log(failures ? `\n${failures} check(s) failed` : `\nAll UI checks passed. Screenshots: ${SHOTS}`);
process.exit(failures ? 1 : 0);
