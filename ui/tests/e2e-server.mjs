// Browser end-to-end test of server mode (ADR-0022 step 4): `proxymind serve --accounts` on plain loopback HTTP.
//
//   npm run build && (cd .. && cargo build) && node tests/e2e-server.mjs      (also run by `npm run test:e2e`)
//
// Covers setup, TOTP enrolment, recovery codes, invites, sign-out, wrong passwords, sign-in with a code and with a
// recovery code, the account page, sessions, a lost session (401) and the re-authentication dialog (403
// fresh_login_required). TOTP codes are computed here (RFC 6238); the server refuses a code for a step it has already
// seen, so `nextCode` never repeats a step for one secret and waits for the clock when it has to.
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { createHmac } from "node:crypto";
import { chromium } from "playwright-core";

const BIN = process.env.PROXYMIND ?? new URL("../../target/debug/proxymind", import.meta.url).pathname;
const SHOTS = process.env.SCREENSHOTS ?? join(tmpdir(), "proxymind-ui-shots");
const dir = mkdtempSync(join(tmpdir(), "pm-ui-e2e-server-"));
const project = join(dir, "server.pmproj");
const home = join(dir, "home");
const children = [];
let failures = 0;

const PW = "correct horse battery staple";
const PW2 = "another long passphrase here";
const PW3 = "a third passphrase for this account";

const freePort = () =>
  new Promise((res) => {
    const s = net.createServer().listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function check(cond, msg) {
  if (cond) console.log(`  ✓ ${msg}`);
  else {
    console.log(`  ✗ ${msg}`);
    failures++;
  }
}
/** Runs one part; a failure is counted and a screenshot of every open page is saved, then the next part runs. */
const pages = [];
async function section(name, body) {
  console.log(name);
  try {
    await body();
  } catch (e) {
    failures++;
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
    console.log(`  ✗ ${name} stopped: ${String(e?.message ?? e).split("\n")[0]} (screenshots failed-${slug}-N.png)`);
    for (const [i, p] of pages.entries()) await p.screenshot({ path: join(SHOTS, `failed-${slug}-${i}.png`), fullPage: true }).catch(() => {});
  }
}

// ---- TOTP (RFC 6238: HMAC-SHA1, 30 s, 6 digits) -------------------------------------------------------------------

function b32decode(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, buf = 0;
  const out = [];
  for (const c of s.replace(/=+$/, "").toUpperCase()) {
    buf = (buf << 5) | A.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 0xff);
      buf &= (1 << bits) - 1;
    }
  }
  return Buffer.from(out);
}
function totpAt(secret, step) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", b32decode(secret)).update(msg).digest();
  const o = h[h.length - 1] & 0xf;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1_000_000).padStart(6, "0");
}
const stepNow = () => Math.floor(Date.now() / 30000);
const lastStep = new Map();
/**
 * A code the server has not seen: the server takes the current step and one on either side, but only a step later
 * than the last one it accepted. So use max(last + 1, now); when that is more than one step ahead, wait for the clock.
 */
async function nextCode(secret) {
  const want = (lastStep.get(secret) ?? -1) + 1;
  const deadline = Date.now() + 35_000;
  while (want > stepNow() + 1 && Date.now() < deadline) await sleep(250);
  const step = Math.max(want, stepNow());
  lastStep.set(secret, step);
  return totpAt(secret, step);
}

// ---- helpers for the screens --------------------------------------------------------------------------------------

const buttonNamed = (p, name) => p.getByRole("button", { name, exact: true });
async function typePassword(p, user, pw) {
  await p.getByLabel("Username", { exact: true }).fill(user);
  await p.getByLabel("Password", { exact: true }).fill(pw);
  await buttonNamed(p, "Sign in").click();
}
async function verifyTotp(p, secret) {
  const code = await nextCode(secret);
  await p.getByLabel("Authentication code").fill(code);
  await buttonNamed(p, "Verify").click();
}
async function verifyRecovery(p, code) {
  await p.getByTestId("auth-toggle-recovery").click();
  await p.getByLabel("Recovery code").fill(code);
  await buttonNamed(p, "Verify").click();
}
/** The enrolment screen: reads the secret, confirms with a code, reads the recovery codes and says they are saved. */
async function enrolAndSave(p) {
  await p.getByTestId("totp-qr").waitFor();
  const secret = (await p.getByTestId("totp-secret").textContent()).trim();
  await p.getByLabel("Authentication code").fill(await nextCode(secret));
  await buttonNamed(p, "Confirm and sign in").click();
  await p.getByTestId("recovery-code-list").waitFor();
  const codes = await p.locator('[data-testid="recovery-code-list"] li').allTextContents();
  await p.getByTestId("recovery-done").click();
  return { secret, codes };
}
const appLoaded = (p) => p.getByTestId("tab-dashboard").waitFor();
const go = async (p, id) => {
  await p.evaluate((h) => (window.location.hash = h), `#/${id}`);
  await p.waitForFunction((h) => window.location.hash === h, `#/${id}`);
};

try {
  mkdirSync(SHOTS, { recursive: true });
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

  // The server: a project with rules of engagement, a server home, plain HTTP on a free loopback port.
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  writeFileSync(join(dir, "roe.yaml"), `version: 1\nscope:\n  include: ["http://127.0.0.1:9/"]\n`);
  execFileSync(BIN, ["-p", project, "--home", home, "roe", "use", join(dir, "roe.yaml")], { encoding: "utf8" });
  let setupUrl = "";
  const server = spawn(
    BIN,
    ["-p", project, "--home", home, "serve", "--accounts", "--server-home", join(dir, "server"), "--listen", `127.0.0.1:${port}`],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  children.push(server);
  let out = "";
  server.stdout.on("data", (d) => {
    out += String(d);
    const m = out.match(/(http:\/\/\S+#setup=\S+)/);
    if (m) setupUrl = m[1];
  });
  server.stderr.on("data", () => {});
  for (let i = 0; i < 300 && !setupUrl; i++) await sleep(100);
  if (!setupUrl) throw new Error("proxymind serve did not print a setup URL");
  check(setupUrl.startsWith(`${base}/#setup=pmset_`), "the server prints a one-time setup URL with the token in the fragment");

  const browser = await chromium.launch({ executablePath: exe });
  const pageErrors = [];
  const newPage = async (ctx) => {
    const p = await ctx.newPage();
    p.on("pageerror", (e) => pageErrors.push(String(e)));
    p.setDefaultTimeout(15_000);
    pages.push(p);
    return p;
  };
  const ctx1 = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await newPage(ctx1);
  // Secrets must never reach the console.
  const consoleText = [];
  page.on("console", (m) => consoleText.push(m.text()));
  let owner = { secret: "", codes: [] };
  let tess = { secret: "", codes: [] };
  let inviteUrl = "";

  await section("Setup: the link, the owner, the authenticator", async () => {
    // Without the link: the page explains where it is.
    const bare = await newPage(await browser.newContext());
    await bare.goto(base);
    await bare.getByTestId("setup-no-token").waitFor();
    check(/console/.test(await bare.getByTestId("setup-no-token").textContent()), "without the link the page says it is printed on the server console");
    await bare.close();
    pages.pop();

    await page.goto(setupUrl);
    await page.getByRole("heading", { name: "Create the owner account" }).waitFor();
    await page.waitForFunction(() => !window.location.hash.includes("setup="));
    check(!page.url().includes("pmset_"), "the setup token is removed from the address bar");
    await page.screenshot({ path: join(SHOTS, "server-1-setup.png") });

    await page.getByLabel("Username", { exact: true }).fill("owner");
    await page.getByLabel("Display name (optional)").fill("Olivia Owner");
    await page.getByLabel("Password", { exact: true }).fill(PW);
    await page.getByLabel("Confirm password").fill("not the same password");
    await buttonNamed(page, "Create account").click();
    await page.getByText("not the same").waitFor();
    check(true, "mismatching passwords are refused in the form");
    await page.getByLabel("Confirm password").fill(PW);
    await buttonNamed(page, "Create account").click();

    await page.getByRole("heading", { name: "Set up your authenticator" }).waitFor();
    check((await page.getByTestId("totp-qr").getAttribute("src")).startsWith("data:image/svg+xml;base64,"), "the enrolment shows a QR code");
    const secret = (await page.getByTestId("totp-secret").textContent()).trim();
    check(/^[A-Z2-7]{16,}$/.test(secret), "and the secret as text");
    await page.screenshot({ path: join(SHOTS, "server-2-enrol.png") });
    // a wrong code is refused and the form stays
    await page.getByLabel("Authentication code").fill("000000");
    await buttonNamed(page, "Confirm and sign in").click();
    await page.getByRole("alert").waitFor();
    check((await page.getByRole("alert").textContent()).includes("invalid code"), "a wrong code is refused with a plain message");
    await page.getByLabel("Authentication code").fill(await nextCode(secret));
    await buttonNamed(page, "Confirm and sign in").click();

    await page.getByTestId("recovery-code-list").waitFor();
    const codes = await page.locator('[data-testid="recovery-code-list"] li').allTextContents();
    check(codes.length === 10 && codes.every((c) => /^[A-Z0-9]{4}(-[A-Z0-9]{4}){3}$/.test(c)), "ten recovery codes are shown once");
    check((await page.getByTestId("recovery-download").getAttribute("href")).startsWith("data:text/plain"), "with a download as a data: URL");
    await page.screenshot({ path: join(SHOTS, "server-3-recovery.png") });
    await page.getByTestId("recovery-done").click();
    owner = { secret, codes };

    await appLoaded(page);
    await go(page, "overview");
    await page.getByRole("heading", { name: "Overview" }).waitFor();
    check(true, "the app loads after setup (Overview renders)");
    await page.screenshot({ path: join(SHOTS, "server-4-app.png") });

    const stored = await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
    check(![PW, secret, ...codes].some((s) => stored.includes(s)), "no password, secret or recovery code is in browser storage");
  });

  await section("Account page and invites", async () => {
    await page.getByTestId("tab-account").click();
    await page.getByTestId("account-page").waitFor();
    check((await page.getByTestId("account-actor").textContent()) === "human:owner", "the account page shows the actor");
    check((await page.getByTestId("account-role").textContent()) === "owner", "and the role in this project");
    check((await page.getByTestId("session-current").count()) === 1, "the current session is marked");
    await page.getByRole("button", { name: "Users & invites" }).click();
    await page.getByTestId("admin-page").waitFor();
    check((await page.getByTestId("user-owner").count()) === 1, "the admin page lists the users");

    // a first invite that is revoked again (it is the only one, so the Revoke button is unambiguous)
    await buttonNamed(page, "Create invite").click();
    await page.getByTestId("invite-url").waitFor();
    const thrown = await page.getByTestId("invite-url").inputValue();
    await page.getByRole("button", { name: "Revoke" }).click();
    await page.getByText("revoked", { exact: true }).waitFor();
    check(true, "an invite can be revoked");

    await page.getByTestId("invite-role").selectOption("tester");
    await buttonNamed(page, "Create invite").click();
    await page.waitForFunction((old) => document.querySelector('[data-testid="invite-url"]')?.value !== old, thrown);
    inviteUrl = await page.getByTestId("invite-url").inputValue();
    check(inviteUrl.startsWith(`${base}/#invite=`), "an invite link is shown once, with the token in the fragment");
    await page.screenshot({ path: join(SHOTS, "server-5-invite.png") });
    await go(page, "account");
    await page.getByTestId("account-sign-out").click();
    await page.getByRole("heading", { name: "Sign in" }).waitFor();
    check(true, "signing out shows the sign-in screen");
  });

  await section("Invite: accept, enrol, sign in as the new user", async () => {
    const ctx2 = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const p2 = await newPage(ctx2);
    await p2.goto(inviteUrl);
    await p2.getByRole("heading", { name: "Join this project" }).waitFor();
    await p2.waitForFunction(() => !window.location.hash.includes("invite="));
    check(!p2.url().includes("pminv"), "the invite token is removed from the address bar");
    await p2.getByLabel("Username", { exact: true }).fill("tess");
    await p2.getByLabel("Display name (optional)").fill("Tess Tester");
    await p2.getByLabel("Password", { exact: true }).fill(PW2);
    await p2.getByLabel("Confirm password").fill(PW2);
    await buttonNamed(p2, "Create account").click();
    tess = await enrolAndSave(p2);
    await appLoaded(p2);
    await p2.getByTestId("tab-account").click();
    await p2.getByTestId("account-page").waitFor();
    check((await p2.getByTestId("account-actor").textContent()) === "human:tess" && (await p2.getByTestId("account-role").textContent()) === "tester", "signed in as the new user, a tester");
    check((await p2.getByRole("button", { name: "Users & invites" }).count()) === 0, "a tester has no admin page");

    // the same invite cannot be used twice
    const ctx3 = await browser.newContext();
    const p3 = await newPage(ctx3);
    await p3.goto(inviteUrl);
    await p3.getByLabel("Username", { exact: true }).fill("tess2");
    await p3.getByLabel("Password", { exact: true }).fill(PW2);
    await p3.getByLabel("Confirm password").fill(PW2);
    await buttonNamed(p3, "Create account").click();
    await p3.getByRole("alert").waitFor();
    check((await p3.getByRole("alert").textContent()).includes("invalid or expired invite"), "a used invite is refused");
    await ctx3.close();
    pages.pop();

    // sign out; a wrong password and an unknown user get the same constant text; then password + TOTP
    await p2.getByTestId("account-sign-out").click();
    await p2.getByRole("heading", { name: "Sign in" }).waitFor();
    const attempt = async (user, pw) => {
      await p2.getByLabel("Username", { exact: true }).fill(user);
      await p2.getByLabel("Password", { exact: true }).fill(pw);
      const [res] = await Promise.all([
        p2.waitForResponse((r) => r.url().endsWith("/api/v1/auth/login")),
        buttonNamed(p2, "Sign in").click(),
      ]);
      return { status: res.status(), body: await res.json() };
    };
    const badPassword = await attempt("tess", "wrong wrong wrong wrong");
    const badUser = await attempt("nobody-here", "wrong wrong wrong wrong");
    await p2.getByRole("alert").waitFor();
    check(
      badPassword.status === 401 && badPassword.body.error === "invalid credentials" && JSON.stringify(badPassword) === JSON.stringify(badUser),
      "a wrong password and an unknown user get the same constant answer",
    );
    check((await p2.getByRole("alert").textContent()).trim() === "invalid credentials", "which the screen shows as a generic error");
    await typePassword(p2, "tess", PW2);
    await p2.getByRole("heading", { name: "Two-step verification" }).waitFor();
    await verifyTotp(p2, tess.secret);
    await appLoaded(p2);
    check(true, "password + authenticator code signs in");
    await p2.getByTestId("tab-account").click();
    await p2.getByTestId("account-sign-out").click();
    await p2.getByRole("heading", { name: "Sign in" }).waitFor();
    await typePassword(p2, "tess", PW2);
    await verifyRecovery(p2, tess.codes[0]);
    await appLoaded(p2);
    check(true, "password + recovery code signs in");
    await ctx2.close();
    pages.pop();
  });

  // The owner again, with recovery codes (no waiting for the clock).
  let rc = 0;
  const ownerSignIn = async (p, pw = PW) => {
    await typePassword(p, "owner", pw);
    await p.getByRole("heading", { name: "Two-step verification" }).waitFor();
    await verifyRecovery(p, owner.codes[rc++]);
    await appLoaded(p);
  };

  await section("A lost session returns to sign-in and back to the same page", async () => {
    await page.getByRole("heading", { name: "Sign in" }).waitFor();
    await ownerSignIn(page);
    check(true, "the owner signs in with a recovery code");
    await go(page, "findings");
    // The server ends the session: the next call is a 401.
    let once = true;
    await page.route("**/api/v1/auth/sessions", async (route) => {
      if (once && route.request().method() === "GET") {
        once = false;
        await route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ error: "not signed in", code: "unauthenticated" }) });
      } else await route.continue();
    });
    await go(page, "account");
    await page.getByTestId("auth-notice").waitFor();
    check(/session ended/i.test(await page.getByTestId("auth-notice").textContent()), "an API 401 shows the sign-in screen with a notice");
    await page.unroute("**/api/v1/auth/sessions");
    await page.screenshot({ path: join(SHOTS, "server-6-expired.png") });
    await typePassword(page, "owner", PW);
    await verifyRecovery(page, owner.codes[rc++]);
    await page.getByTestId("account-page").waitFor();
    check(new URL(page.url()).hash === "#/account", "after signing in the person is back on the page they were on");
  });

  await section("Fresh sign-in: the dialog and the retry", async () => {
    await go(page, "admin");
    await page.getByTestId("admin-page").waitFor();
    let once = true;
    await page.route("**/api/v1/auth/invites", async (route) => {
      if (once && route.request().method() === "POST") {
        once = false;
        await route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ error: "this needs a recent sign-in", code: "fresh_login_required" }) });
      } else await route.continue();
    });
    await buttonNamed(page, "Create invite").click();
    await page.getByTestId("reauth-dialog").waitFor();
    await page.screenshot({ path: join(SHOTS, "server-7-reauth.png") });
    const dialog = page.getByTestId("reauth-dialog");
    // cancelling leaves the action undone, with the server's message
    await dialog.getByTestId("reauth-cancel").click();
    await dialog.waitFor({ state: "detached" });
    check(await page.getByRole("alert").filter({ hasText: "recent sign-in" }).count() === 1, "cancelling shows the server's message and does nothing");
    once = true;
    await buttonNamed(page, "Create invite").click();
    await dialog.waitFor();
    await dialog.getByLabel("Password", { exact: true }).fill(PW);
    await dialog.getByRole("button", { name: "Sign in again", exact: true }).click();
    await dialog.getByRole("heading", { name: "Two-step verification" }).waitFor();
    await verifyRecovery(dialog, owner.codes[rc++]);
    await dialog.waitFor({ state: "detached" });
    await page.getByTestId("invite-url").waitFor();
    check(true, "after signing in again the action is repeated once and succeeds");
    await page.unroute("**/api/v1/auth/invites");
  });

  await section("Sessions, password, recovery codes", async () => {
    await go(page, "account");
    await page.getByTestId("account-page").waitFor();
    // a second browser signs in as the owner
    const ctx4 = await browser.newContext();
    const p4 = await newPage(ctx4);
    await p4.goto(base);
    await ownerSignIn(p4);
    await page.reload();
    await page.getByTestId("session-other").waitFor();
    check((await page.getByTestId("session-other").count()) === 1 && (await page.getByTestId("session-current").count()) === 1, "the account page lists both sessions");
    await page.getByTestId("sessions-revoke-others").click();
    await page.getByTestId("session-other").waitFor({ state: "detached" });
    check(true, "sign out everywhere else ends the other session");
    // the other browser finds out on its next call
    await go(p4, "findings");
    await p4.getByTestId("auth-notice").waitFor();
    check(true, "the other browser is sent to the sign-in screen");
    await ctx4.close();
    pages.pop();

    // change the password
    await page.getByLabel("Current password").fill(PW);
    await page.getByLabel("New password", { exact: true }).fill(PW3);
    await page.getByLabel("Confirm new password").fill(PW3);
    await page.getByTestId("pw-submit").click();
    await page.getByText("Password changed").waitFor();
    check(true, "the password changes");

    // new recovery codes
    page.once("dialog", (d) => void d.accept());
    await page.getByTestId("recovery-regenerate").click();
    await page.getByTestId("recovery-code-list").waitFor();
    const fresh = await page.locator('[data-testid="recovery-code-list"] li').allTextContents();
    check(fresh.length === 10 && !fresh.some((c) => owner.codes.includes(c)), "new recovery codes replace the old ones");
    await page.getByTestId("recovery-done").click();
    owner.codes = fresh;
    rc = 0;
  });

  await section("Sign in again with the new password and a code", async () => {
    await page.getByTestId("account-sign-out").click();
    await page.getByRole("heading", { name: "Sign in" }).waitFor();
    await typePassword(page, "owner", PW);
    await page.getByRole("alert").waitFor();
    check((await page.getByRole("alert").textContent()).trim() === "invalid credentials", "the old password no longer works");
    await typePassword(page, "owner", PW3);
    await page.getByRole("heading", { name: "Two-step verification" }).waitFor();
    await verifyTotp(page, owner.secret);
    await appLoaded(page);
    check(true, "the new password + authenticator code signs in");
  });

  await section("API tokens (pm3_): make one, use it with only a bearer header, revoke it", async () => {
    await go(page, "account");
    await page.getByTestId("account-page").waitFor();
    await page.getByTestId("tokens-intro").waitFor();
    await page.getByTestId("token-kind").selectOption("agent");
    await page.getByTestId("token-name").fill("e2e-agent");
    await page.getByTestId("token-cap").selectOption("passive");
    await page.getByTestId("token-days").fill("7");
    await page.getByTestId("token-create").click();
    await page.getByTestId("token-made").waitFor();
    const secret = await page.getByTestId("token-value").inputValue();
    check(/^pm3_agent_[0-9a-f]{64}$/.test(secret), "the token is shown once, as pm3_agent_ and 64 hex digits");
    await page.screenshot({ path: join(SHOTS, "server-9-tokens.png"), fullPage: true });
    const call = (method, path, body, headers = {}) =>
      fetch(`${base}/api/v1${path}`, { method, headers: { Authorization: `Bearer ${secret}`, ...(body ? { "Content-Type": "application/json" } : {}), ...headers }, body: body && JSON.stringify(body) });
    // Only a bearer header: no cookie, no Origin, no X-ProxyMind. Node's fetch sends none of them.
    const who = await (await call("GET", "/status")).json();
    check(who.you_are === "agent:e2e-agent", `a script with the token is ${who.you_are}`);
    const post = await call("POST", "/findings", { nothing: "useful" });
    check(post.status !== 403 || (await post.json()).code !== "csrf", "a bearer request needs no Origin or X-ProxyMind");
    const replay = await (await call("POST", "/replay", { url: "http://127.0.0.1:9", raw: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" })).json();
    check(replay.status === "denied" && /limited to passive/.test(replay.reasons?.[0] ?? ""), "the tier cap denies a request above it");
    for (const [m, p, b] of [["POST", "/tokens", { kind: "agent", name: "child" }], ["GET", "/tokens"], ["GET", "/auth/me"]]) {
      const r = await call(m, p, b);
      check(r.status === 403, `a token cannot use ${m} ${p} (${r.status})`);
    }
    const mcp = await (await call("POST", "/mcp", { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "roe_get", arguments: {} } })).json();
    check(JSON.parse(mcp.result.content[0].text).you_are === "agent:e2e-agent", "the MCP endpoint runs the tools as the token's agent");
    // The install token of single-user mode is no credential here.
    check((await fetch(`${base}/api/v1/status`, { headers: { Authorization: "Bearer pm2_nothing" } })).status === 401, "the install token is not accepted");
    await page.getByTestId("token-dismiss").click();
    await page.reload();
    await page.getByTestId("token-agent:e2e-agent").waitFor();
    check((await page.getByTestId("token-agent:e2e-agent").textContent()).includes("passive"), "the list shows the token and its cap");
    check(!(await page.content()).includes(secret), "the page never holds the token after it was dismissed");
    const stored = await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
    check(!stored.includes(secret), "the token is not in browser storage");
    check(!consoleText.some((t) => t.includes(secret)), "the token never reached the console");
    // The owner may see everyone's tokens.
    await page.getByTestId("tokens-all").check();
    await page.getByTestId("token-agent:e2e-agent").waitFor();
    page.once("dialog", (d) => void d.accept());
    await page.getByTestId("token-revoke-agent:e2e-agent").click();
    await page.locator('[data-testid="token-agent:e2e-agent"] .chip.bad').waitFor();
    check((await call("GET", "/status")).status === 401, "after revoking, the token gets 401");
  });

  await section("Not a member", async () => {
    // The server never answers this for the project's own members; the screen is checked with a faked /me.
    await page.route("**/api/v1/auth/me", async (route) => {
      const res = await route.fetch();
      const j = await res.json();
      await route.fulfill({ response: res, json: { ...j, role: null } });
    });
    await page.reload();
    await page.getByTestId("not-member").waitFor();
    check((await page.getByTestId("not-member").textContent()).includes("not a member"), "a signed-in account without a membership gets a clear screen");
    await page.unroute("**/api/v1/auth/me");
    await page.getByTestId("sign-out").click();
    await page.getByRole("heading", { name: "Sign in" }).waitFor();
    check(true, "with a way to sign out");
  });

  const leaked = consoleText.filter((t) => [PW, PW2, PW3, owner.secret, tess.secret, ...owner.codes, ...tess.codes].some((s) => s && t.includes(s)));
  check(leaked.length === 0, "no secret appears in the browser console");
  check(pageErrors.length === 0, `no uncaught errors in the page${pageErrors.length ? ": " + pageErrors.join(" | ") : ""}`);
  await browser.close();
} catch (e) {
  console.error(e);
  failures++;
} finally {
  for (const c of children) c.kill();
}
console.log(failures ? `\n${failures} check(s) failed` : `\nAll server-mode UI checks passed. Screenshots: ${SHOTS}`);
process.exit(failures ? 1 : 0);
