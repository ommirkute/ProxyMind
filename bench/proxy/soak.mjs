// Browses the soak site (and Juice Shop if given) with Chromium, directly
// or through a proxy, and reports failed requests and page results.
// usage: node soak.mjs <site url> <rounds> [proxy host:port] [juice url]
import { createRequire } from "node:module";
const { chromium } = createRequire(import.meta.url)("playwright");
const [site, rounds, proxy, juice] = process.argv.slice(2);
const browser = await chromium.launch({ proxy: proxy ? { server: `http://${proxy}`, bypass: "<-loopback>" } : undefined, args: ["--ignore-certificate-errors"] });
const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
const failed = []; let requests = 0;
ctx.on("request", () => requests++);
ctx.on("requestfailed", (r) => failed.push(`${r.method()} ${r.url().slice(0, 90)} ${r.failure()?.errorText}`));
const t0 = Date.now(); const titles = {};
async function visit(page) {
  await page.goto(site, { waitUntil: "load", timeout: 60000 });
  await page.waitForFunction(() => document.title.startsWith("done"), null, { timeout: 60000 }).catch(() => {});
  const t = await page.title(); titles[t] = (titles[t] || 0) + 1;
}
for (let r = 0; r < Number(rounds); r++) {
  // Four tabs at once each round: parallel streams and connections.
  const pages = await Promise.all([0, 1, 2, 3].map(() => ctx.newPage()));
  await Promise.all(pages.map(visit));
  await Promise.all(pages.map((p) => p.close()));
}
let juiceInfo = "";
if (juice) {
  const page = await ctx.newPage();
  const ws = []; page.on("websocket", (w) => { ws.push(w.url()); w.on("framereceived", () => (ws.frames = (ws.frames || 0) + 1)); });
  const errors = []; page.on("console", (m) => m.type() === "error" && errors.push(m.text().slice(0, 100)));
  for (const path of ["/#/", "/#/search?q=apple", "/#/login", "/#/contact", "/#/about", "/#/photo-wall"]) {
    await page.goto(juice + path, { waitUntil: "networkidle", timeout: 60000 }).catch((e) => errors.push("goto " + path + ": " + e.message.slice(0, 80)));
  }
  await page.waitForTimeout(2000);
  juiceInfo = `juice: websockets=${ws.length} frames=${ws.frames || 0} console_errors=${errors.length} ${errors.slice(0, 3).join(" | ")}`;
}
console.log(JSON.stringify({ via: proxy || "direct", seconds: (Date.now() - t0) / 1000, requests, failed: failed.length, titles, sample_failures: failed.slice(0, 8), juice: juiceInfo }, null, 1));
await browser.close();
