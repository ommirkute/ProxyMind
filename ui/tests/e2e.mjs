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
import { X509Certificate } from "node:crypto";
import { chromium } from "playwright-core";

const BIN = process.env.PROXYMIND ?? new URL("../../target/debug/proxymind", import.meta.url).pathname;
const SHOTS = process.env.SCREENSHOTS ?? join(tmpdir(), "proxymind-ui-shots");
// ProxyMind's own browser window opens headless here (no display in CI).
process.env.PROXYMIND_BROWSER_HEADLESS ??= "1";
// CI runners (non-root Ubuntu) can't use Chromium's sandbox for Playwright's build: the built-in
// browser window would abort. The test runs in a throwaway machine, so run it without the sandbox.
process.env.PROXYMIND_CHROMIUM_NO_SANDBOX ??= "1";
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
async function browseAs(proxy, shop, user, paths) {
  const body = JSON.stringify({ username: user, password: `${user}123` });
  const login = await viaProxy(proxy, shop, `POST /api/login HTTP/1.1\r\nHost: shop\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body}`);
  const session = login.split("session=")[1].split(";")[0];
  for (const p of paths) await viaProxy(proxy, shop, `GET ${p} HTTP/1.1\r\nHost: shop\r\nCookie: session=${session}\r\n\r\n`);
}

try {
  mkdirSync(SHOTS, { recursive: true });
  // proxymind renders XSS proofs in the same Chromium the test drives.
  const exe = process.env.CHROMIUM ?? ["/opt/pw-browsers/chromium-1194/chrome-linux/chrome"].find(existsSync);
  const browserPath = exe ?? chromium.executablePath();
  if (existsSync(browserPath)) process.env.PROXYMIND_CHROMIUM ??= browserPath;
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

  console.log("History");
  await page.goto(link);
  // The proxy records on a background thread: wait for all 7 to arrive (live updates add them).
  await page.waitForFunction(() => document.querySelectorAll('[data-testid^="row-"]').length >= 7, null, { timeout: 15000 }).catch(() => {});
  check((await page.locator('[data-testid^="row-"]').count()) === 7, "history lists the 7 proxied requests");
  await page.screenshot({ path: join(SHOTS, "1-history.png") });

  // Capture alice from her /api/me request and bob from his.
  const rowFor = async (path, nth) => {
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

  console.log("Overview");
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

  console.log("Proxy: top tabs, HTTP history tools");
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
  await page.getByRole("tab", { name: "Response" }).click();
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
  await open("findings");
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
  for (const f of ["html", "sarif"]) {
    const [dl] = await Promise.all([page.waitForEvent("download"), page.getByTestId(`report-${f}`).click()]);
    const text = await (await dl.createReadStream()).toArray().then((c) => Buffer.concat(c).toString());
    check(f === "html" ? text.includes("Any user can read any order") && text.includes("default-src 'none'") : JSON.parse(text).version === "2.1.0", `${f} report downloads`);
  }

  console.log("Issue library, retest and report builder");
  await page.getByTestId("issue-card").waitFor();
  check(await page.getByTestId("issue-card").textContent().then((t) => t.includes("Broken object level authorization") && t.includes("CWE-639")),
    "the finding shows its issue library entry");
  await page.getByTestId("retest").click();
  await page.waitForSelector('[data-testid="retest-result"]', { timeout: 30000 });
  check(await page.getByTestId("retest-result").textContent().then((t) => t.includes("reproduced") && t.includes("proof still holds")),
    "retest re-runs the proof");
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
  const frame = page.frameLocator('iframe[title="Report preview"]');
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

  console.log("XSS proof");
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

  console.log("Replay");
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
  // Inspector: edit a header value in place.
  await page.getByLabel("Raw request").fill(`GET /search?q=shoes&page=1 HTTP/1.1\nHost: shop\nCookie: a=1; theme=dark\n\n`);
  const qField = page.getByLabel("Query parameters q");
  await qField.fill("boots");
  await qField.press("Enter");
  check(await page.getByLabel("Raw request").inputValue().then((v) => v.startsWith("GET /search?q=boots&page=1 ")), "Inspector edits a query parameter");
  await page.getByLabel("Cookies theme").fill("light");
  await page.getByLabel("Cookies theme").press("Enter");
  check(await page.getByLabel("Raw request").inputValue().then((v) => v.includes("Cookie: a=1; theme=light")), "Inspector edits a cookie");
  await page.getByLabel("Protocol").selectOption("HTTP/2");
  await page.getByLabel("HTTP/2 pseudo-headers :path").fill("/search?q=h2");
  await page.getByLabel("HTTP/2 pseudo-headers :path").press("Enter");
  await page.getByLabel("HTTP/2 pseudo-headers :authority").fill("other.test");
  await page.getByLabel("HTTP/2 pseudo-headers :authority").press("Enter");
  const h2raw = await page.getByLabel("Raw request").inputValue();
  check(h2raw.startsWith("GET /search?q=h2 HTTP/2\n") && h2raw.includes("host: other.test") && h2raw.includes("cookie: a=1"),
    "Inspector switches to HTTP/2 and edits :path and :authority");
  await page.getByLabel("Protocol").selectOption("HTTP/1.1");
  await page.getByRole("button", { name: "New tab" }).click();
  check((await page.locator(".rtab").count()) >= 3, "tabs can be added");
  await page.screenshot({ path: join(SHOTS, "5-replay.png") });
  await sleep(900); // saved after a short pause
  await page.reload();
  await page.locator(".rtab", { hasText: `#${orderId}` }).waitFor();
  check(true, "Replay tabs survive a reload (saved in the project)");

  console.log("cURL and HAR");
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
  const target = await page.getByLabel("Target").inputValue();
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

  console.log("Site map and search");
  await open("sitemap");
  await page.locator('[data-testid="sitemap-node"][data-path="/api/orders"]').first().waitFor({ state: "attached" });
  check(true, "site map shows /api/orders");
  await page.getByLabel("Search text").fill("alice@");
  await page.getByTestId("search").click();
  await page.waitForSelector('[data-testid="search-summary"]');
  check(await page.getByTestId("search-hit").count() > 0, "content search finds alice's email in responses");
  check(await page.locator('[data-testid="search-hit"] mark').first().textContent() === "alice@", "the match is highlighted");
  await page.screenshot({ path: join(SHOTS, "5c-sitemap.png") });

  console.log("Global search, Organizer, engagement tools, Collaborator");
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
  const htmlId = await page.evaluate(async () => (await (await fetch("/api/v1/exchanges?path=render-check&limit=1")).json()).exchanges[0].id);
  await open(`history/${htmlId}`);
  await page.locator('[data-testid="response-view"] button', { hasText: "Render" }).click();
  const renderFrame = page.getByTestId("render-frame");
  check(await renderFrame.getAttribute("sandbox") === "" && (await renderFrame.getAttribute("srcdoc")).includes("default-src 'none'"), "HTML responses render sandboxed, without scripts or network");
  await page.locator('[data-testid="response-view"] button', { hasText: "Pretty" }).click();
  await page.getByTestId(`row-${htmlId}`).click({ button: "right" });
  await page.getByText("Copy as Python requests").click();
  await page.locator("text=Code copied.").first().waitFor();
  check(true, "Copy as Python requests");
  await open("rules");
  await page.getByTestId("rules-preset").selectOption("unhide_fields");
  check(await page.locator('[data-testid="rules"] tbody tr').count() >= 2, "a response-modification preset adds its rules");
  await page.getByRole("button", { name: "Discard changes" }).click();

  console.log("Fuzzer");
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
  await page.getByTestId("fuzzer-run").click();
  await page.waitForFunction(() => document.querySelector('[data-testid="fuzzer-summary"]')?.textContent?.includes("· done ·"));
  check(await page.getByTestId("fuzzer-summary").textContent().then((t) => t.startsWith("3 requests")), "an attack sends 3 requests in the background");
  check((await page.getByTestId("extract-cell").allTextContents()).some((t) => t.startsWith("alice@")), "an extract column shows alice's email");
  check((await page.getByTestId("anomaly").count()) === 3, "alice's orders (grep) and the 404 stand out");
  await page.screenshot({ path: join(SHOTS, "5b-fuzzer.png") });

  console.log("Approvals (an agent asks over MCP)");
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

  console.log("Intercept");
  await open("intercept");
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
  await open("history");
  await page.getByLabel("Filter", { exact: true }).fill("held-");
  await sleep(500);
  const heldRows = await page.locator('[data-testid^="row-"]').allTextContents();
  check(heldRows.length === 1 && heldRows[0].includes("held-edited"), "history records the edited request only");

  console.log("Match and replace");
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

  console.log("WebSocket intercept (edit a browser's message in the queue)");
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

  console.log("Race condition (Replay races VulnShop's one-time gift card)");
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
  await open("history");
  await page.getByLabel("Filter", { exact: true }).fill("/h2-check");
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
  await open("network");
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

  console.log("Assistant (mock OpenAI-compatible model server)");
  const { createServer } = await import("node:http");
  const modelCalls = [];
  const model = createServer((req, res) => {
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
  await page.getByLabel("Model").fill("mock-model");
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

  console.log("Crawl");
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

  console.log("OpenAPI import");
  await viaProxy(proxy, shop, "GET /openapi.json HTTP/1.1\r\nHost: shop\r\n\r\n");
  const specId = await page.evaluate(async () => (await (await fetch("/api/v1/exchanges?path=/openapi.json&limit=1")).json()).exchanges[0].id);
  await page.getByRole("button", { name: "Import OpenAPI…" }).click();
  await page.getByLabel("Spec exchange").fill(String(specId));
  await page.getByTestId("openapi-import").click();
  await page.waitForSelector('[data-testid="openapi-summary"]');
  check(await page.getByTestId("openapi-summary").textContent().then((t) => t.startsWith("VulnShop API 1.0: 13 operations")), "the spec's 13 operations are listed");

  console.log("Content discovery");
  await page.getByRole("button", { name: "Find hidden paths…" }).click();
  await page.getByLabel("Discover under").fill(`http://127.0.0.1:${shop}/`);
  await page.getByTestId("discover").click();
  await page.waitForSelector('[data-testid="discover-summary"]', { timeout: 60000 });
  check(await page.locator('[data-testid="discovered"]', { hasText: "/.git/config" }).count() === 1, "discovery finds /.git/config");

  console.log("GraphQL");
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

  console.log("Passive issues");
  await open("issues");
  await page.waitForSelector('[data-testid="issues"]');
  check(await page.locator('[data-testid="issues"]').textContent().then((t) => t.includes("Password field on a page served over plain HTTP")), "passive scan flags the login form over HTTP");
  await page.screenshot({ path: join(SHOTS, "6c-issues.png") });

  console.log("Active scan");
  await viaProxy(proxy, shop, "GET /greet?name=ann HTTP/1.1\r\nHost: shop\r\n\r\n");
  const greet = await page.evaluate(async () => {
    const r = await fetch("/api/v1/exchanges?path=/greet&limit=1");
    return (await r.json()).exchanges[0].id;
  });
  await page.goto(link.replace(/\/auth.*/, `/#/issues/${greet}`));
  await page.getByTestId("active-scan").click();
  await page.waitForSelector('[data-testid="active-summary"]', { timeout: 60000 });
  check(await page.getByText("server-side template injection").count() > 0, "active scan finds the template injection");
  await page.screenshot({ path: join(SHOTS, "6d-active-scan.png") });

  console.log("Crawl and audit");
  await page.getByLabel("Start URL").fill(`http://127.0.0.1:${shop}/`);
  await page.getByLabel("Pages to crawl").fill("15");
  await page.getByText("quick checks only").click();
  await page.getByTestId("audit-start").click();
  await page.waitForSelector('[data-testid="audit-progress"] b:text-is("done")', { timeout: 120000 });
  check(await page.getByTestId("audit-issues").textContent().then((t) => t.includes("/search")), "crawl and audit finds the reflected XSS on /search");
  await page.screenshot({ path: join(SHOTS, "6e-crawl-audit.png") });

  console.log("Tools");
  await open("tools");
  await page.getByLabel("Codec input").fill("JTNDc2NyaXB0JTNF");
  await page.getByTestId("decode").click();
  await page.waitForSelector('[data-testid="decode-step"]');
  check(await page.getByTestId("decode-step").last().textContent() === "<script>", "smart decode peels base64 then URL encoding");
  await viaProxy(proxy, shop, "POST /api/password/reset HTTP/1.1\r\nHost: shop\r\nContent-Length: 0\r\n\r\n");
  const resetId = await page.evaluate(async () => {
    // The proxy records in the background: wait for the row.
    for (let i = 0; i < 50; i++) {
      const row = (await (await fetch("/api/v1/exchanges?path=/api/password/reset&limit=1")).json()).exchanges[0];
      if (row) return row.id;
      await new Promise((r) => setTimeout(r, 100));
    }
    return null;
  });
  await page.getByLabel("Token exchange").fill(String(resetId));
  await page.getByLabel("Samples").fill("20");
  await page.getByLabel("Token locator").fill("json:/debug_code");
  await page.getByTestId("token-analyzer").click();
  await page.waitForSelector('[data-testid="token-analyzer-result"]', { timeout: 60000 });
  check(await page.getByTestId("token-analyzer-result").textContent().then((t) => t.includes("poor") && t.includes("increasing by 1")), "token analyzer spots the counter");
  await page.screenshot({ path: join(SHOTS, "6e-tools.png"), fullPage: true });

  console.log("Plugins");
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

  console.log("Custom checks");
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

  console.log("DOM test");
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

  console.log("Engagement (rules of engagement)");
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

  console.log("Proxy setup");
  await open("setup");
  await page.waitForSelector('[data-testid="ca-fingerprint"]');
  const caShown = await page.getByTestId("ca-fingerprint").textContent();
  const pem = await page.evaluate(async () => (await fetch("/api/v1/ca.pem")).text());
  check(caShown === new X509Certificate(pem).fingerprint256, "the CA fingerprint matches the downloaded certificate");
  check(await page.getByTestId("setup-proxy").textContent() === `127.0.0.1:${proxy}`, "the proxy address is shown");

  console.log("Built-in browser");
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

  console.log("Proxy listeners");
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

  console.log("Network: hostname overrides and TLS pass-through");
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

  console.log("Session handling");
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

  console.log("Scans: profiles, schedules, tasks");
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
  await page.getByTestId("scan-start").click();
  await page.locator('[data-testid="scan-tasks"] td', { hasText: "e2e-quick" }).first().waitFor();
  await page.locator('[data-testid="scan-tasks"] tr', { hasText: "e2e-quick" }).filter({ hasText: "done" }).first().waitFor({ timeout: 60000 });
  check(true, "a scan with a saved profile runs to the end");
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

  console.log("Recorded login");
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

  console.log("Model, coverage and audit");
  await open("model");
  await page.locator('[data-testid="operations"] strong', { hasText: "/api/orders/{id}" }).waitFor();
  check(true, "model shows /api/orders/{id}");
  await page.screenshot({ path: join(SHOTS, "7-model.png"), fullPage: true });
  await open("audit");
  await page.waitForSelector('[data-testid="audit-verify"]');
  check(await page.getByTestId("audit-verify").textContent().then((t) => t.includes("intact")), "audit log verified intact");
  await page.screenshot({ path: join(SHOTS, "8-audit.png") });

  // A fresh browser without the cookie is refused.
  const other = await browser.newPage();
  await other.goto(link.replace(/\/auth.*/, "/"));
  await other.waitForSelector("text=Not signed in");
  check(true, "a browser without the token sees 'Not signed in'");

  const unexpected = consoleErrors.filter((e) => !e.includes("q=stauts%3A200") && !e.includes("/api/v1/recon/dns"));
  check(unexpected.length === 0, `no console errors${unexpected.length ? ": " + unexpected.join(" | ") : ""}`);
  if (failedResponses.length) console.log(`  (failed requests during the run: ${failedResponses.join(" | ")})`);
  await browser.close();
} catch (e) {
  console.error(e);
  failures++;
} finally {
  for (const c of children) c.kill();
}
console.log(failures ? `\n${failures} check(s) failed` : `\nAll UI checks passed. Screenshots: ${SHOTS}`);
process.exit(failures ? 1 : 0);
