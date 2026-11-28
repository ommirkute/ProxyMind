// Browser end-to-end test of server mode (ADR-0022 step 4): `proxymind serve --accounts` on plain loopback HTTP.
//
//   npm run build && (cd .. && cargo build) && node tests/e2e-server.mjs      (also run by `npm run test:e2e`)
//
// Covers setup, TOTP enrolment, recovery codes, invites, sign-out, wrong passwords, sign-in with a code and with a
// recovery code, the account page, sessions, a lost session (401) and the re-authentication dialog (403
// fresh_login_required). The last sections are passkeys (ADR-0022 step 7), with Chromium's virtual authenticator
// (CDP `WebAuthn.addVirtualAuthenticator`: ctap2, internal, resident keys, user verification): add, sign in, rename,
// remove, the "require a passkey" rule, an enrolment link and setup with a passkey. WebAuthn needs a secure context
// and a host name for its RP id, so those sections use http://localhost:PORT. The section before them is OIDC sign-in
// (ADR-0022 step 8) against a small fake provider written in this file (node:http, ES256 with node:crypto): the
// administrator configures it, an invite is redeemed through it, a linked person signs in with it, an unknown identity
// is refused, and an owner links and unlinks an identity. TOTP codes are computed here (RFC 6238); the server refuses a code for a step it has already
// seen, so `nextCode` never repeats a step for one secret and waits for the clock when it has to.
import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, existsSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { createHmac, createHash, generateKeyPairSync, randomBytes, sign as cryptoSign } from "node:crypto";
import http from "node:http";
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
    console.log(`  ✗ ${name} stopped: ${String(e?.message ?? e).split("\n").slice(0, 4).join(" / ")} (screenshots failed-${slug}-N.png)`);
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


// ---- a fake OpenID Connect provider -----------------------------------------------------------------------------
// Discovery, a key set, an authorize endpoint that sends the browser straight back (the person always approves), and a
// token endpoint that checks the client's credentials, the redirect URI, PKCE S256 and that a code is used once.

const b64u = (b) => Buffer.from(b).toString("base64url");
function startFakeProvider({ port, redirectUri, clientId, clientSecret }) {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid: "e2e-1", use: "sig", alg: "ES256" };
  const issuer = `http://127.0.0.1:${port}`;
  const codes = new Map();
  const idp = { issuer, grant: { sub: "sub-nobody", email: "nobody@corp.example", name: "Nobody", groups: [] }, tokens: 0, bad: [] };
  const json = (res, status, body) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  idp.server = http.createServer((req, res) => {
    const url = new URL(req.url, issuer);
    if (url.pathname === "/.well-known/openid-configuration") {
      return json(res, 200, {
        issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        response_types_supported: ["code"],
        code_challenge_methods_supported: ["S256"],
        id_token_signing_alg_values_supported: ["ES256"],
        token_endpoint_auth_methods_supported: ["client_secret_basic"],
        authorization_response_iss_parameter_supported: true,
      });
    }
    if (url.pathname === "/jwks") return json(res, 200, { keys: [jwk] });
    if (url.pathname === "/authorize") {
      const q = url.searchParams;
      if (q.get("redirect_uri") !== redirectUri || q.get("client_id") !== clientId || q.get("code_challenge_method") !== "S256" || q.get("response_type") !== "code") {
        idp.bad.push(`authorize: ${url.search}`);
        res.writeHead(400);
        return res.end("bad request");
      }
      const code = b64u(randomBytes(18));
      codes.set(code, { challenge: q.get("code_challenge"), nonce: q.get("nonce"), grant: { ...idp.grant }, used: false });
      const back = new URL(redirectUri);
      back.searchParams.set("code", code);
      back.searchParams.set("state", q.get("state"));
      back.searchParams.set("iss", issuer);
      res.writeHead(302, { location: back.toString() });
      return res.end();
    }
    if (url.pathname === "/token" && req.method === "POST") {
      let body = "";
      req.on("data", (d) => (body += d));
      req.on("end", () => {
        const f = new URLSearchParams(body);
        const basic = (req.headers.authorization ?? "").replace(/^Basic /, "");
        const [id, secret] = Buffer.from(basic, "base64").toString().split(":").map(decodeURIComponent);
        if (id !== clientId || secret !== clientSecret) return json(res, 401, { error: "invalid_client" });
        const rec = codes.get(f.get("code"));
        if (!rec || rec.used || f.get("redirect_uri") !== redirectUri) return json(res, 400, { error: "invalid_grant" });
        rec.used = true;
        if (b64u(createHash("sha256").update(f.get("code_verifier") ?? "").digest()) !== rec.challenge) {
          idp.bad.push("token: PKCE verifier does not match");
          return json(res, 400, { error: "invalid_grant" });
        }
        const now = Math.floor(Date.now() / 1000);
        const header = { alg: "ES256", typ: "JWT", kid: "e2e-1" };
        const claims = {
          iss: issuer, sub: rec.grant.sub, aud: clientId, iat: now, exp: now + 300, nonce: rec.nonce,
          email: rec.grant.email, email_verified: true, name: rec.grant.name, preferred_username: rec.grant.username, groups: rec.grant.groups,
        };
        const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
        const sig = cryptoSign("sha256", Buffer.from(input), { key: privateKey, dsaEncoding: "ieee-p1363" });
        idp.tokens++;
        json(res, 200, { access_token: "not-used", token_type: "Bearer", id_token: `${input}.${b64u(sig)}` });
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });
  return new Promise((resolve) => idp.server.listen(port, "127.0.0.1", () => resolve(idp)));
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
    await page.getByTestId("user-owner").waitFor();
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

  await section("Roles: a viewer reads redacted traffic, a promotion and a removal take effect without signing in again", async () => {
    const COOKIE = "SECRETCOOKIEVALUE123456";
    // History with a secret in it, imported by the owner.
    const har = {
      log: { version: "1.2", entries: [{
        startedDateTime: new Date().toISOString(), time: 5,
        request: { method: "GET", url: "http://127.0.0.1:9/account", httpVersion: "HTTP/1.1", headers: [{ name: "Host", value: "127.0.0.1:9" }, { name: "Cookie", value: `session=${COOKIE}` }], queryString: [], cookies: [], headersSize: -1, bodySize: 0 },
        response: { status: 200, statusText: "OK", httpVersion: "HTTP/1.1", headers: [{ name: "Content-Type", value: "text/plain" }], cookies: [], content: { size: 2, mimeType: "text/plain", text: "hi" }, redirectURL: "", headersSize: -1, bodySize: 2 },
        cache: {}, timings: { send: 0, wait: 5, receive: 0 },
      }] },
    };
    const imp = await page.evaluate(async (h) => {
      const r = await fetch("/api/v1/import/har", { method: "POST", headers: { "X-ProxyMind": "1", "Content-Type": "application/json" }, body: JSON.stringify({ har: JSON.stringify(h) }) });
      return { status: r.status, body: await r.text() };
    }, har);
    check(imp.status === 200 && /"imported":1/.test(imp.body), `the owner imports history that holds a cookie (${imp.status})`);

    // Invite a viewer.
    await go(page, "admin");
    await page.getByTestId("admin-page").waitFor();
    check((await page.getByTestId("member-owner").count()) === 1, "the Members panel lists the owner");
    await page.getByTestId("invite-role").selectOption("viewer");
    const before = await page.getByTestId("invite-url").count() ? await page.getByTestId("invite-url").inputValue() : "";
    await buttonNamed(page, "Create invite").click();
    await page.waitForFunction((old) => (document.querySelector('[data-testid="invite-url"]')?.value ?? "") !== old, before);
    const viewerInvite = await page.getByTestId("invite-url").inputValue();
    const ctxV = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const pv = await newPage(ctxV);
    await pv.goto(viewerInvite);
    await pv.getByLabel("Username", { exact: true }).fill("vera");
    await pv.getByLabel("Password", { exact: true }).fill(PW2);
    await pv.getByLabel("Confirm password").fill(PW2);
    await buttonNamed(pv, "Create account").click();
    await enrolAndSave(pv);
    await appLoaded(pv);
    await pv.getByTestId("tab-account").click();
    check((await pv.getByTestId("account-role").textContent()) === "viewer", "the invited person is a viewer");

    // What a viewer sees: history with the secret hidden, and no way to send.
    await go(pv, "history");
    await pv.getByText("/account").first().waitFor();
    await pv.getByText("/account").first().click();
    await pv.getByTestId("tab-request").click().catch(() => {});
    await sleep(500);
    const html = await pv.content();
    check(!html.includes(COOKIE), "the viewer's history page does not contain the cookie value");
    const viewerDetail = await pv.evaluate(async () => {
      const list = await (await fetch("/api/v1/exchanges")).json();
      const id = list.exchanges[0].id;
      return await (await fetch(`/api/v1/exchanges/${id}`)).text();
    });
    check(!viewerDetail.includes(COOKIE) && viewerDetail.includes("{{secret:"), "the exchange the API gives a viewer has the secret replaced by a placeholder");
    const ownerDetail = await page.evaluate(async () => {
      const list = await (await fetch("/api/v1/exchanges")).json();
      return await (await fetch(`/api/v1/exchanges/${list.exchanges[0].id}`)).text();
    });
    check(ownerDetail.includes(COOKIE), "while the owner sees the real value");
    check((await pv.getByTestId("tab-replay").count()) === 0 && (await pv.getByTestId("tab-fuzzer").count()) === 0, "a viewer's sidebar has no Replay or Fuzzer");
    const attempt = (p, path, body) =>
      p.evaluate(async ([path, body]) => (await fetch(`/api/v1${path}`, { method: "POST", headers: { "X-ProxyMind": "1", "Content-Type": "application/json" }, body: JSON.stringify(body) })).status, [path, body]);
    const replayBody = { url: "http://127.0.0.1:9", raw: "GET / HTTP/1.1\r\nHost: x\r\n\r\n" };
    check((await attempt(pv, "/replay", replayBody)) === 403, "the server refuses a viewer's replay (403)");
    check((await attempt(pv, "/scan/tasks", { url: "http://127.0.0.1:9/" })) === 403, "and a viewer's scan (403)");
    await pv.screenshot({ path: join(SHOTS, "server-10-viewer.png") });

    // Promote: the owner changes the role; the viewer's open page follows without signing in again.
    await page.reload();
    await page.getByTestId("member-role-vera").waitFor();
    await page.getByTestId("member-role-vera").selectOption("tester");
    await page.getByText("vera is now tester").waitFor();
    check(true, "the owner makes the viewer a tester in the Members panel");
    check((await attempt(pv, "/replay", replayBody)) !== 403, "at once the server lets that session send");
    await pv.getByTestId("tab-replay").waitFor({ timeout: 25_000 });
    check(true, "and the open page shows Replay without a new sign-in");

    // Remove: the session ends.
    page.once("dialog", (d) => void d.accept());
    await page.getByTestId("member-remove-vera").click();
    await page.getByText("vera removed").waitFor();
    const gone = await pv.evaluate(async () => (await fetch("/api/v1/status")).status);
    check(gone === 401, `the removed member's session is refused at once (${gone})`);
    await pv.getByTestId("auth-notice").waitFor({ timeout: 25_000 });
    check(true, "and their open page shows the sign-in");
    // The last owner cannot be removed or demoted.
    const lastOwner = await page.evaluate(async () => {
      const members = await (await fetch("/api/v1/auth/members")).json();
      const me = members.find((m) => m.you);
      const r = await fetch(`/api/v1/auth/members/${me.user_id}`, { method: "PUT", headers: { "X-ProxyMind": "1", "Content-Type": "application/json" }, body: JSON.stringify({ role: "viewer" }) });
      return { status: r.status, code: (await r.json()).code };
    });
    check(lastOwner.status === 409 && lastOwner.code === "last_owner", "the last owner cannot be demoted");
    await ctxV.close();
    pages.splice(pages.indexOf(pv), 1);
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

  // ---- passkeys (ADR-0022 step 7): Chromium's virtual authenticator (CDP WebAuthn domain) plays the device ----------
  // A passkey belongs to a host name, and the server run here has no --public-url, so its RP id is `localhost`: these
  // sections use http://localhost:PORT (a secure context), not the 127.0.0.1 address of the sections above.
  const lbase = `http://localhost:${port}`;
  /** A fresh browser context whose WebAuthn requests are answered by a virtual platform authenticator. */
  const withAuthenticator = async () => {
    const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const p = await newPage(ctx);
    const cdp = await ctx.newCDPSession(p);
    await cdp.send("WebAuthn.enable");
    const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });
    return { ctx, page: p, cdp, authenticatorId, credentials: async () => (await cdp.send("WebAuthn.getCredentials", { authenticatorId })).credentials };
  };
  const meOf = (p) => p.evaluate(async () => (await fetch("/api/v1/auth/me")).json());
  const statusOf = (p, path = "/api/v1/status") => p.evaluate(async (u) => (await fetch(u)).status, path);
  const adminTab = async (p) => {
    await go(p, "account");
    await p.getByTestId("account-page").waitFor();
    await p.getByRole("button", { name: "Users & invites" }).click();
    await p.getByTestId("admin-page").waitFor();
  };
  const owner2 = { pw: PW3 };
  let ownerDevice = null;
  let tessDevice = null;

  await section("OIDC sign-in: configure a provider, redeem an invite through it, sign in, link and unlink", async () => {
    const clientSecret = "e2e-client-secret-7c1f0b2d9a";
    const idpPort = await freePort();
    const callback = `${base}/api/v1/auth/oidc/callback`;
    const idp = await startFakeProvider({ port: idpPort, redirectUri: callback, clientId: "pm-e2e", clientSecret });
    children.push({ kill: () => idp.server.close() });

    // The owner (password and authenticator, at 127.0.0.1) configures the provider.
    const op = await newPage(await browser.newContext({ viewport: { width: 1440, height: 900 } }));
    const opConsole = [];
    op.on("console", (m) => opConsole.push(m.text()));
    await op.goto(base);
    await typePassword(op, "owner", owner2.pw);
    await verifyTotp(op, owner.secret);
    await appLoaded(op);
    await adminTab(op);
    await op.getByTestId("oidc-add").click();
    await op.getByTestId("oidc-name").fill("Corp SSO");
    await op.getByTestId("oidc-issuer").fill(idp.issuer);
    await op.getByTestId("oidc-client-id").fill("pm-e2e");
    await op.getByTestId("oidc-client-secret").fill(clientSecret);
    await op.getByTestId("oidc-group-claim").fill("groups");
    await op.getByTestId("oidc-group-roles").fill("pm-owners = owner");
    await op.getByTestId("oidc-save").click();
    await op.getByRole("alert").waitFor();
    check(/never owner/.test(await op.getByRole("alert").textContent()), "a group cannot be mapped to owner (the form says so)");
    await op.getByTestId("oidc-group-roles").fill("pm-testers = tester");
    await op.getByTestId("oidc-save").click();
    await op.getByTestId("oidc-provider-row").waitFor();
    check((await op.getByTestId("oidc-secret-cell").textContent()) === "********", "the client secret is shown masked");
    check((await op.getByTestId("oidc-redirect-uri").textContent()).trim() === callback, "the page says which redirect URI to register");
    await op.getByTestId("oidc-test").click();
    await op.getByTestId("oidc-test-result").waitFor();
    check(/answers as ProxyMind needs/.test(await op.getByTestId("oidc-test-result").textContent()), "the test fetches discovery and keys and reports them");
    await op.screenshot({ path: join(SHOTS, "server-oidc-1-admin.png") });
    const apiText = await op.evaluate(async () => (await fetch("/api/v1/auth/oidc/providers")).text());
    check(!apiText.includes(clientSecret), "the provider list from the API holds no client secret");

    // An invite redeemed by signing in with the provider.
    await op.getByTestId("invite-role").selectOption("viewer");
    await op.getByTestId("invite-create").click();
    await op.getByTestId("invite-url").waitFor();
    const ivyInvite = await op.getByTestId("invite-url").inputValue();
    idp.grant = { sub: "sub-ivy", email: "ivy@corp.example", name: "Ivy Invited", username: "ivy", groups: [] };
    const ip = await newPage(await browser.newContext({ viewport: { width: 1440, height: 900 } }));
    await ip.goto(ivyInvite);
    await ip.getByRole("heading", { name: "Join this project" }).waitFor();
    await ip.locator('[data-testid^="oidc-invite-"]').click();
    await appLoaded(ip);
    const ivy = await meOf(ip);
    check(ivy.user.username === "ivy" && ivy.role === "viewer" && ivy.session.auth_method === "oidc", "the invite is redeemed through the provider: a viewer, session method oidc");
    check(!ip.url().includes("code=") && !ip.url().includes("state="), "the address bar holds no code or state afterwards");
    await ip.getByTestId("tab-account").click();
    await ip.getByTestId("identity-row").waitFor();
    check((await ip.getByTestId("identity-email").textContent()) === "ivy@corp.example" && (await ip.getByTestId("identity-provider").textContent()) === "Corp SSO", "her Account page lists the linked identity");
    await ip.screenshot({ path: join(SHOTS, "server-oidc-2-identity.png") });
    // It is her only way in: unlinking is refused.
    ip.once("dialog", (d) => void d.accept());
    await ip.getByTestId("identity-unlink").click();
    await ip.getByRole("alert").waitFor();
    check(/last way to sign in/.test(await ip.getByRole("alert").textContent()), "the last way to sign in cannot be unlinked");

    // Signed out, the sign-in page offers the provider and a linked person gets in with it.
    await ip.getByTestId("account-sign-out").click();
    await ip.getByRole("heading", { name: "Sign in" }).waitFor();
    await ip.locator('[data-testid^="oidc-signin-"]').waitFor();
    check((await ip.locator('[data-testid^="oidc-signin-"]').textContent()).includes("Sign in with Corp SSO"), "the sign-in page offers \"Sign in with Corp SSO\"");
    await ip.screenshot({ path: join(SHOTS, "server-oidc-3-signin.png") });
    await ip.locator('[data-testid^="oidc-signin-"]').click();
    await appLoaded(ip);
    check((await meOf(ip)).user.username === "ivy", "a linked person signs in through the provider");

    // An identity nobody linked is refused, with the way forward.
    idp.grant = { sub: "sub-nobody", email: "nobody@corp.example", name: "Nobody", groups: [] };
    const np = await newPage(await browser.newContext());
    await np.goto(base);
    await np.locator('[data-testid^="oidc-signin-"]').click();
    await np.getByTestId("auth-notice").waitFor();
    check(/ask a project owner for an invite/i.test(await np.getByTestId("auth-notice").textContent()), "an unknown identity is refused: ask an owner for an invite");
    check(!np.url().includes("oidc_error"), "and the error code is taken out of the address bar");
    await np.close();
    pages.pop();

    // The owner links an identity from the Account page (a round trip bound to the session), then unlinks it.
    idp.grant = { sub: "sub-owner", email: "olivia@corp.example", name: "Olivia", groups: [] };
    await go(op, "account");
    await op.getByTestId("account-page").waitFor();
    await op.locator('[data-testid^="oidc-link-"]').click();
    await appLoaded(op);
    await go(op, "account");
    await op.getByTestId("identity-row").waitFor();
    check((await op.getByTestId("identity-email").textContent()) === "olivia@corp.example", "the owner's identity is linked from the Account page");
    await op.screenshot({ path: join(SHOTS, "server-oidc-4-linked.png") });
    op.once("dialog", (d) => void d.accept());
    await op.getByTestId("identity-unlink").click();
    await op.getByText("Identity unlinked").waitFor();
    check((await op.getByTestId("identity-row").count()) === 0, "and unlinked again (the owner keeps a password and an authenticator)");
    check(idp.bad.length === 0, `the provider saw only well-formed requests: the exact redirect URI and PKCE S256${idp.bad.length ? " (" + idp.bad.join("; ") + ")" : ""}`);
    check(idp.tokens >= 3, "the provider issued tokens for each round trip");
    const everything = [...opConsole, ...consoleText, await op.content(), await ip.content()].join("\n");
    check(!everything.includes(clientSecret), "the client secret appears neither in the console nor in the pages");
  });

  await section("Passkeys: add one, sign in with it, rename it, remove it", async () => {
    // At 127.0.0.1 a passkey cannot work (the RP id is localhost): the sign-in page offers none, the account page says why.
    const wrong = await newPage(await browser.newContext());
    await wrong.goto(base);
    await wrong.getByRole("heading", { name: "Sign in" }).waitFor();
    check((await wrong.getByTestId("passkey-signin").count()) === 0, "at 127.0.0.1 the sign-in page offers no passkey (they are bound to localhost)");
    await wrong.close();
    pages.pop();

    ownerDevice = await withAuthenticator();
    const pk = ownerDevice.page;
    await pk.goto(lbase);
    await pk.getByRole("heading", { name: "Sign in" }).waitFor();
    await pk.getByTestId("passkey-signin").waitFor();
    check(true, "at localhost the sign-in page offers \"Sign in with a passkey\"");
    await pk.screenshot({ path: join(SHOTS, "server-11-passkey-signin.png") });
    await typePassword(pk, "owner", owner2.pw);
    await verifyTotp(pk, owner.secret);
    await appLoaded(pk);
    await pk.getByTestId("tab-account").click();
    await pk.getByTestId("account-page").waitFor();
    check((await pk.getByTestId("passkey-rp").textContent()).trim() === "localhost", "the account page names the host name passkeys are bound to");

    await pk.getByTestId("passkey-name").fill("Test authenticator");
    await pk.getByTestId("passkey-add").click();
    await pk.getByTestId("passkey-row").waitFor();
    check((await pk.getByTestId("passkey-name-cell").textContent()) === "Test authenticator", "a passkey is added and listed under its name");
    const creds = await ownerDevice.credentials();
    check(creds.length === 1 && creds[0].rpId === "localhost" && creds[0].isResidentCredential, "the authenticator holds a discoverable credential for localhost");
    await pk.screenshot({ path: join(SHOTS, "server-12-passkeys.png") });
    const stored = await pk.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
    check(!stored.includes(creds[0].credentialId), "no credential id is in browser storage");

    // Sign out and in again with the passkey: no username, no password.
    await pk.getByTestId("account-sign-out").click();
    await pk.getByRole("heading", { name: "Sign in" }).waitFor();
    await pk.getByTestId("passkey-signin").click();
    await appLoaded(pk);
    const me = await meOf(pk);
    check(me.user.username === "owner" && me.session.auth_method === "passkey" && me.passkey_count === 1, "the passkey signs in as the owner (session method passkey)");
    check((await ownerDevice.credentials())[0].signCount >= 1, "the authenticator's counter moved");

    // Rename.
    await pk.getByTestId("tab-account").click();
    await pk.getByTestId("passkey-rename").click();
    await pk.getByTestId("passkey-rename-input").fill("Work laptop");
    await pk.getByTestId("passkey-rename-save").click();
    await pk.getByTestId("passkey-name-cell").getByText("Work laptop").waitFor();
    check(true, "a passkey can be renamed");

    // Remove (the owner still has a password and an authenticator, so this is allowed), then it no longer signs in.
    pk.once("dialog", (d) => void d.accept());
    await pk.getByTestId("passkey-remove").click();
    await pk.getByText("No passkeys yet.").waitFor();
    check(true, "removing the passkey empties the list");
    await pk.getByTestId("account-sign-out").click();
    await pk.getByRole("heading", { name: "Sign in" }).waitFor();
    await pk.getByTestId("passkey-signin").click();
    await pk.getByRole("alert").waitFor();
    check((await pk.getByRole("alert").textContent()).includes("invalid credentials"), "the removed passkey is refused, with the plain message");
  });

  await section("Require a passkey: accounts without one are sent to add one", async () => {
    const pk = ownerDevice.page;
    // The password still works while the rule is off; add a passkey again, then turn the rule on.
    await pk.reload();
    await typePassword(pk, "owner", owner2.pw);
    await verifyTotp(pk, owner.secret);
    await appLoaded(pk);
    await pk.getByTestId("tab-account").click();
    await pk.getByTestId("passkey-add").click();
    await pk.getByTestId("passkey-row").waitFor();
    await adminTab(pk);
    check((await pk.getByTestId("passkey-rule-text").textContent()).includes("every account must have a passkey"), "the admin page explains the rule");
    await pk.getByTestId("passkey-required-toggle").click();
    await pk.getByText("Passkeys are now required").waitFor();
    check(true, "the administrator requires a passkey");
    await pk.screenshot({ path: join(SHOTS, "server-13-require-passkey.png") });

    // tess has a password and an authenticator but no passkey: she may only add one.
    tessDevice = await withAuthenticator();
    const tp = tessDevice.page;
    await tp.goto(lbase);
    await typePassword(tp, "tess", PW2);
    await verifyTotp(tp, tess.secret);
    await tp.getByTestId("passkey-gate").waitFor();
    check(true, "an account without a passkey is sent to add one after signing in");
    check((await statusOf(tp)) === 403 && (await statusOf(tp, "/api/v1/auth/sessions")) === 403, "and the server refuses everything else to that session (403)");
    await tp.screenshot({ path: join(SHOTS, "server-14-passkey-gate.png") });
    await tp.getByTestId("passkey-add").click();
    await appLoaded(tp);
    check((await statusOf(tp)) === 200, "once a passkey is added the session works normally");

    // The owner has a passkey: a password sign-in is refused with the reason, the passkey works.
    await go(pk, "account");
    await pk.getByTestId("account-page").waitFor();
    await pk.getByTestId("account-sign-out").click();
    await pk.getByRole("heading", { name: "Sign in" }).waitFor();
    await typePassword(pk, "owner", owner2.pw);
    await pk.getByRole("alert").waitFor();
    check((await pk.getByRole("alert").textContent()).includes("signs in with a passkey"), "with passkeys required, an account that has one cannot sign in by password");
    await pk.getByTestId("passkey-signin").click();
    await appLoaded(pk);
    check(true, "the passkey signs in");
  });

  await section("Enrolment link: recover an account with a new passkey", async () => {
    const pk = ownerDevice.page;
    await adminTab(pk);
    pk.once("dialog", (d) => void d.accept());
    await pk.getByTestId("member-recover-tess").click();
    await pk.getByTestId("enrol-link-url").waitFor();
    const url = await pk.getByTestId("enrol-link-url").inputValue();
    check(url.startsWith(`${lbase}/#enrol=pmenr_`), "the owner gets a one-time link on the address they used");
    check((await statusOf(tessDevice.page)) === 401, "making it ended tess's sessions");
    await pk.screenshot({ path: join(SHOTS, "server-15-recovery-link.png") });

    const rc = await withAuthenticator();
    await rc.page.goto(url);
    await rc.page.getByTestId("enrol-link-who").waitFor();
    check((await rc.page.getByTestId("enrol-link-who").textContent()).includes("tess"), "the link's page says whose account it recovers");
    check(!rc.page.url().includes("pmenr_"), "and takes the token out of the address bar");
    await rc.page.getByTestId("passkey-name").fill("Replacement phone");
    await rc.page.getByTestId("auth-submit").click();
    await appLoaded(rc.page);
    const me = await meOf(rc.page);
    check(me.user.username === "tess" && me.session.auth_method === "passkey" && me.passkey_count === 1, "a new passkey recovers the account and signs in");
    // The old passkey is gone, and the link is spent.
    await tessDevice.page.goto(lbase);
    await tessDevice.page.getByTestId("passkey-signin").click();
    await tessDevice.page.getByRole("alert").waitFor();
    check(true, "tess's old passkey no longer signs in");
    const again = await newPage(await browser.newContext());
    await again.goto(url);
    await again.getByTestId("enrol-link-bad").waitFor();
    check(true, "the link works once");
    await again.close();
    pages.pop();
    await rc.page.getByTestId("tab-account").click();
    await rc.page.getByTestId("passkey-row").waitFor();
    check((await rc.page.getByTestId("passkey-name-cell").textContent()) === "Replacement phone", "tess's list holds only the new passkey");
  });

  await section("Setup with a passkey on a new server", async () => {
    const dir2 = mkdtempSync(join(tmpdir(), "pm-ui-e2e-server2-"));
    const project2 = join(dir2, "server.pmproj");
    const port2 = await freePort();
    writeFileSync(join(dir2, "roe.yaml"), `version: 1\nscope:\n  include: ["http://127.0.0.1:9/"]\n`);
    execFileSync(BIN, ["-p", project2, "--home", join(dir2, "home"), "roe", "use", join(dir2, "roe.yaml")], { encoding: "utf8" });
    const server2 = spawn(
      BIN,
      ["-p", project2, "--home", join(dir2, "home"), "serve", "--accounts", "--server-home", join(dir2, "server"), "--listen", `127.0.0.1:${port2}`],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    children.push(server2);
    let out2 = "";
    let setup2 = "";
    server2.stdout.on("data", (d) => {
      out2 += String(d);
      const m = out2.match(/(http:\/\/\S+#setup=\S+)/);
      if (m) setup2 = m[1];
    });
    server2.stderr.on("data", () => {});
    for (let i = 0; i < 300 && !setup2; i++) await sleep(100);
    if (!setup2) throw new Error("the second server did not print a setup URL");
    const dev = await withAuthenticator();
    await dev.page.goto(setup2.replace("127.0.0.1", "localhost"));
    await dev.page.getByRole("heading", { name: "Create the owner account" }).waitFor();
    check(await dev.page.getByTestId("choice-passkey").isChecked(), "setup offers a passkey first");
    check((await dev.page.getByTestId("auth-password").count()) === 0, "and asks for no password with it");
    await dev.page.screenshot({ path: join(SHOTS, "server-16-setup-passkey.png") });
    await dev.page.getByLabel("Username", { exact: true }).fill("solo");
    await buttonNamed(dev.page, "Create account with a passkey").click();
    await appLoaded(dev.page);
    const me = await meOf(dev.page);
    check(me.user.username === "solo" && me.user.server_admin && me.role === "owner" && me.passkey_count === 1, "the owner is made with a passkey and nothing else (no authenticator app, no recovery codes)");
    await dev.page.getByTestId("tab-account").click();
    await dev.page.getByTestId("account-sign-out").click();
    await dev.page.getByRole("heading", { name: "Sign in" }).waitFor();
    await dev.page.getByTestId("passkey-signin").click();
    await appLoaded(dev.page);
    check(true, "and it signs in with that passkey");
    server2.kill();
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
