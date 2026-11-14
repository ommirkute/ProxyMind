# Benchmarks

ProxyMind's claims about agents and proofs have to be measurable. This directory holds the targets, the ground truth, a runner and the scoring.

> ⚠️ These apps are deliberately vulnerable. Bind them to `127.0.0.1` (as the compose file does) and never expose them to a network.

## Targets and ground truth

| App | Ground truth | Checked against | How to run |
|---|---|---|---|
| VulnShop (built in) | [`vulnshop.yaml`](ground-truth/vulnshop.yaml): 38 bugs + traps | `proxymind demo-target` | nothing to start |
| [VAmPI](https://github.com/erev0s/VAmPI) | [`vampi.yaml`](ground-truth/vampi.yaml): 7 bugs + 1 trap | image digest in the file | `docker compose -f bench/docker-compose.yml up -d vampi` |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | [`juice-shop.yaml`](ground-truth/juice-shop.yaml): 8 API-level bugs | v20.3.0 | `docker compose -f bench/docker-compose.yml up -d juice-shop` |

The images come from Docker Hub. To avoid its pull limits, the **Bench images** workflow (Actions, run by hand) copies them to `ghcr.io/<owner>/bench-mirror`; set `BENCH_REGISTRY=ghcr.io/<owner>/bench-mirror` to use the copy (the nightly benchmark job does this once the mirror exists). To run only the benchmarks in CI, start the **Nightly** workflow with "Run only the benchmarks" ticked. The copies keep their digests, so the pins in `docker-compose.yml` still apply.
| [OWASP crAPI](https://github.com/OWASP/crAPI) | [`crapi.yaml`](ground-truth/crapi.yaml): 10 bugs from crAPI's challenge list | not yet run | crAPI's own compose file (about 4 GB of images) |

Every VAmPI and Juice Shop entry was reproduced by hand against the pinned image. Path segments written `{name}` match any one segment.

## Running a benchmark

```bash
cargo build --release
PROXYMIND=$PWD/target/release/proxymind bench/run.sh vampi      # or juice-shop, vulnshop
```

The runner starts the app, browses it through the proxy as two users (profiles in [`apps/`](apps/)), captures their sessions, crawls, runs the **model-free baseline** (`proxymind bench auto`), runs the passive scan, then scores with `proxymind bench score --app <app>`.

To score an agent, set `BENCH_AGENT` to a command; it runs with `PROXYMIND_PROJECT` pointing at the project, after the baseline steps:

```bash
BENCH_AGENT='claude -p "Use the proxymind MCP server to find and prove vulnerabilities"' bench/run.sh juice-shop
```

The nightly workflow runs the baseline on VulnShop, VAmPI and Juice Shop and posts the scores in the job summary.

The model-free baseline (`proxymind bench auto`) has four steps, all through the policy gate:

1. **Discovery**: hidden files at each origin's root. Sensitive ones (source control, `.env`, dumps, metrics) become suspected *exposure* findings, one per kind. An API description that turns up is imported and its GET examples sent, so the next steps see those endpoints.
2. **Access control**: every candidate the app model suggests (objects with a known owner, admin-looking operations) is replayed as the other identities; leaks are recorded and proven, unprovable ones dropped. Data an anonymous request also gets is public, not a leak.
3. **Active sweep**: the active scanner runs once over each recorded GET operation with parameters (query values and path identifiers, including words like `/users/v1/{username}`); SQL errors, template evaluation, file reads and open redirects become suspected findings.
4. **Prove** (`--no-prove` to skip): each suspected finding is handed to the oracle that fits its class — boolean/time-based for SQLi, timing for command injection, out-of-band for SSRF, the headless browser for reflected XSS, two-file reads for path traversal, a fresh marker for open redirect and CRLF, and the differential oracle for IDOR/BFLA. A finding that proves gets a stored proof and is marked proven.

## Baseline today (no agent)

| App | Found | Proven | False positives |
|---|---|---|---|
| VulnShop | 35/38 | 12/38 | 0 |
| Juice Shop | 9/9 | ≥1/9 | 0 |
| VAmPI | 8/8 | ≥1/8 | 0 |

Measured 2026-11-14 after the second round of Phase 0 proofs: VulnShop **20/38 proven**, found 35/38, no false positives. Newly proven: VS-12 (IDOR in a GraphQL query sent by POST), VS-15 (time-based SQLi in the User-Agent header), VS-19 (Host header), VS-23 (stored XSS, headless browser on the page that shows it) and VS-25 (DOM XSS, the page's own script runs). Still found but not proven: token, cache, OAuth, deserialization, smuggling, CSRF, mass assignment, prototype pollution, file upload, exposure and access-control-bypass classes (no automatic oracle yet). Missed: VS-5 (race), VS-10 (template injection; the scanner doesn't find it, though the oracle exists) and VS-11 (weak reset tokens).

Measured earlier on 2026-11-14 with the roadmap's first Phase 0 proofs (template injection, NoSQL operator injection, XXE, CORS, Host-header injection): VulnShop **15/38 proven** (was 12), found still 35/38, no false positives (`unmatched_findings` and `findings_on_secure_endpoints` empty). Newly proven: VS-16 (blind XXE, out-of-band), VS-20 (CORS, origin trusted with credentials) and VS-21 (NoSQL operator, boolean split). VS-19 (Host header) is proven by the forged-`Host` attempt added after this run. VS-10 (template injection) is not found by the scanner in this run, so there is nothing to prove; the oracle is tested in `crates/pm-service/tests/prove_more.rs`.

Measured 2026-11-12 after the automatic **prove** step was added (`bench auto`, step 4): VulnShop's proven count went from 2/38 to **12/38** with no false positives (`unmatched_findings` and `findings_on_secure_endpoints` both empty). The prove step picks an oracle by class and verifies each suspected finding: VS-1/VS-2 (IDOR/BFLA, differential), VS-3 (boolean SQLi), VS-7/VS-26/VS-38 (error-based SQLi), VS-4 (SSRF, out-of-band), VS-6 (reflected XSS, headless browser), VS-8 (open redirect, marker), VS-9 (path traversal, two-file), VS-14 (command injection, timing) and VS-18 (CRLF, marker). Still suspected (no automatic oracle yet or out of reach): VS-15 (time-based SQLi in the User-Agent header, whose insertion point the recorded baseline lacks), VS-12 (GraphQL IDOR over POST), VS-16 (blind XXE), VS-19 (host-header), VS-21 (NoSQL operator), VS-23/VS-25 (stored/DOM XSS) and the token/cache/OAuth/deserialization classes. VAmPI and Juice Shop were **not** re-measured on this machine (Docker Hub rate-limited image pulls here); their rows show the lower bound from the differential oracle and should be re-measured in CI — the prove step only runs the same rigorous, control-checked oracles there, and every oracle rejects its VulnShop trap in `crates/pm-service/tests/prove_auto.rs` and `crates/pm-service/tests/proof.rs`.

Measured 2026-11-06 for VAmPI (8/8): `bench auto --write-checks` (destructive tier, allowed by the bench rules) tries the description's write operations on a test user's object: a ReDoS probe as the owner (VA-7) and the write as the other user, read back to tell a cross-user change from the caller's own (VA-4). Before that, on 2026-11-05 (6/8): the OpenAPI import now resolves an empty server URL to the document's folder (examples were sent to `/openapi.json/...`), skips GET examples that change state (`/createdb`), and the baseline sends the description's sign-up example with unique account values, so the mass-assignment check (which now also reads back account listings) finds VA-5. Measured 2026-10-26 after the detection pass driven by these benchmarks: logins are scanned (SQL injection in Juice Shop's login, JS-1; account enumeration in VAmPI's, VA-6), password changes are re-sent without the current password (JS-6), sign-ups get a unique email per probe (JS-4), discovery finds debug endpoints that leak credentials under API collections (VA-2) and confidential files in directory listings (JS-8, which needed the HTTP client to keep a body the server cut short), the access-control pass flags responses that show another test user's email (JS-5), and reflected input becomes an XSS finding (VS-6). VAmPI's remaining misses need state-changing tests (VA-4 changes another user's password, VA-5's sign-up doesn't echo the admin flag) or a ReDoS (VA-7).

Measured 2026-10-20 against the pinned images, after scanner step 1 (blind SQL injection by true/false pairs and delays, in parameters and headers; command injection; error confirmation): VulnShop's blind SQLi (VS-3), command injection (VS-14) and User-Agent SQLi (VS-15) are now found. Its other bugs sit on endpoints that nothing links to and its OpenAPI file doesn't list, or need a browser (XSS), concurrency (race) or a second step (GraphQL, reset codes): that's what agents are for. `bench/run.sh` also starts an OAST listener (on the Docker bridge, so containers can reach it) for the out-of-band checks; VulnShop's SSRF (VS-4) is only reachable from an endpoint nothing links to, and its blind XXE (VS-16) is a POST, which the sweep doesn't send. The sweep scans GETs with parameters first, then up to 20 without (headers and cookies), and skips paths whose names change state (`/createdb`, `/logout`…). After step 3b the sweep also renders HTML pages in headless Chromium for DOM XSS (VS-25), and re-sends up to 10 recorded submissions (not logins) for stored XSS (VS-23, values looked for on pages from history) and CSRF (VS-24; a request accepted without cookies isn't counted); the base64-JSON SQLi (VS-26) is found through nested insertion points. Juice Shop and VAmPI are unchanged. Step 4a adds JWT, GraphQL, web cache, mass assignment and prototype pollution checks: VulnShop's VS-27…VS-33 are all found, plus two real token bugs the ground truth lacked until then: VAmPI's JWT secret is `random` (VA-8) and Juice Shop accepts unsigned `alg: none` tokens (JS-9). App-wide bugs like these use `method: "*"` and `path: "*"` in the ground truth. Step 4b adds OAuth and deserialization checks, plus request smuggling, file upload and race checks that need approval; `bench/run.sh` allows them for its throwaway apps (`tiers: human: destructive: allow`). VulnShop's VS-34…VS-37 are found; its race (VS-5) needs a one-time action that hasn't been used yet, which the recorded traffic doesn't have.

2026-11-06: the sweep adds the Host header, CORS and hidden-parameter checks (VS-19, VS-20, VS-22; only a debug-like name such as `debug` that changes the answer is recorded, as an exposure: on Juice Shop the other names were list filters like `sort`). Discovery now looks inside the folders robots.txt hides (VS-17's 403 page; discovery's 401/403 hits are recorded again as `discover_hit` so the model keeps them for the auth bypass check), tries other API versions of known logins and GETs (`/api/v2/login` next to `/api/login` and `/api/v3/…`: VS-21), and sends the description's XML upload examples, which the OpenAPI parser now builds, so the XXE check has a request (VS-16). Write checks also race described one-time actions (redeem, claim, vote) as a second user; VulnShop's gift card needs a code its description doesn't give, so VS-5 stays missed. VulnShop 31/38, no false positives. 2026-11-07: GraphQL queries that take an id are asked, as another test user, for an object the model knows the owner of (VS-12): 32/38. Still missed: endpoints nothing links to or describes (VS-4, VS-8…VS-11) and the gift-card race (VS-5).

2026-11-09: parameters a page reads though nothing sends them are scanned (hidden-parameter discovery now also notices a changed redirect target), and discovery tries common names of pages that take a URL or file: VulnShop's `/go?url=` open redirect (VS-8) is found, 33/38. `/go` was also header-injectable (found on the way); like `/out` it now refuses control characters. The automatic pass also reads the app's JavaScript for endpoints: on Juice Shop 19 of the 50 new routes its scripts mention exist and get scanned, with no new false positives. Still missed: SSRF and path traversal on endpoints that answer 404 without their parameter (VS-4, VS-9), `/greet` (VS-10), the reset codes (VS-11) and the gift-card race (VS-5).

2026-11-12: discovery's guessed-parameter probe now sends its query (it sent the bare path), the same page names are tried inside API folders the model knows (`/api/fetch` next to `/api/orders/{id}`), and the sweep also scans GETs with a query that failed on its value (400, 404, 410, 422, 5xx: a `?file=` that is not there, a `?url=` that does not resolve), after the ones that worked. VS-4 (SSRF) and VS-9 (path traversal) are found: 35/38, no false positives. Still missed: `/greet` (VS-10, nothing links to it), the reset codes (VS-11, not browsed) and the gift-card race (VS-5).

## Proxy traffic matrix

`bench/proxy/run.sh` checks the intercepting proxy against real-world traffic patterns, through `proxymind proxy`, over plain HTTP, HTTPS with HTTP/2 to the proxy (as browsers do) and HTTPS with HTTP/1.1:

- server-sent events and slowly chunked responses arrive as they're sent;
- a 300 MB download and a 70 s long poll complete;
- `Expect: 100-continue` uploads don't stall; a 50 MB upload completes;
- 40 keep-alive requests share one server connection, and a connection the server closed while idle is retried;
- 204, 304, HEAD, 302 and close-delimited responses end correctly, and gzip bodies stay byte-exact.

```bash
PROXYMIND=$PWD/target/debug/proxymind bench/proxy/run.sh            # all 30 cases, about 5 minutes
PROXYMIND=$PWD/target/debug/proxymind bench/proxy/run.sh https-sse-streams   # one case
```

2026-11-04: 30/30 (7 of the first 18 cases passed before responses streamed).

`bench/proxy/soak.sh [rounds] [juice-url]` is the real-browser check: Chromium loads a modern HTTPS site over HTTP/2 (120 images, 20 gzip scripts, server-sent events, a 20 MB fetch, a 1 MB upload, a slow request, a `wss://` echo), four tabs at a time, directly and then through ProxyMind, and prints both results plus the errors in history. `bench/proxy/load.py` is a load test (threads × keep-alive requests through the proxy).

2026-11-04: every page completes through ProxyMind as it does directly, in the same time (77 s for 20 loads with 3,000 requests), with no errors in history; Juice Shop loads with its WebSocket; with response rules on (full buffering) pages complete too. Load: 6,000 requests from 20 clients, 0 errors, ~800 req/s over HTTP and ~400 req/s over HTTPS, memory flat (85.5 → 85.8 MB).
