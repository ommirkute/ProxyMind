# Benchmarks

ProxyMind's claims about agents and proofs have to be measurable. This directory holds the targets, the ground truth, a runner and the scoring.

> ⚠️ These apps are deliberately vulnerable. Bind them to `127.0.0.1` (as the compose file does) and never expose them to a network.

## Targets and ground truth

| App | Ground truth | Checked against | How to run |
|---|---|---|---|
| VulnShop (built in) | [`vulnshop.yaml`](ground-truth/vulnshop.yaml): 38 bugs + traps | `proxymind demo-target` | nothing to start |
| [VAmPI](https://github.com/erev0s/VAmPI) | [`vampi.yaml`](ground-truth/vampi.yaml): 7 bugs + 1 trap | image digest in the file | `docker compose -f bench/docker-compose.yml up -d vampi` |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | [`juice-shop.yaml`](ground-truth/juice-shop.yaml): 8 API-level bugs | v20.3.0 | `docker compose -f bench/docker-compose.yml up -d juice-shop` |
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

The model-free baseline (`proxymind bench auto`) has three steps, all through the policy gate:

1. **Discovery**: hidden files at each origin's root. Sensitive ones (source control, `.env`, dumps, metrics) become suspected *exposure* findings, one per kind. An API description that turns up is imported and its GET examples sent, so the next steps see those endpoints.
2. **Access control**: every candidate the app model suggests (objects with a known owner, admin-looking operations) is replayed as the other identities; leaks are recorded and proven, unprovable ones dropped. Data an anonymous request also gets is public, not a leak.
3. **Active sweep**: the active scanner runs once over each recorded GET operation with parameters (query values and path identifiers, including words like `/users/v1/{username}`); SQL errors, template evaluation, file reads and open redirects become suspected findings.

## Baseline today (no agent)

| App | Found | Proven | False positives |
|---|---|---|---|
| VulnShop | 24/38 | 2/38 | 0 |
| Juice Shop | 4/9 | 1/9 | 0 |
| VAmPI | 3/8 | 1/8 | 0 |

Measured 2026-10-20 against the pinned images, after scanner step 1 (blind SQL injection by true/false pairs and delays, in parameters and headers; command injection; error confirmation): VulnShop's blind SQLi (VS-3), command injection (VS-14) and User-Agent SQLi (VS-15) are now found. Its other bugs sit on endpoints that nothing links to and its OpenAPI file doesn't list, or need a browser (XSS), concurrency (race) or a second step (GraphQL, reset codes): that's what agents are for. `bench/run.sh` also starts an OAST listener (on the Docker bridge, so containers can reach it) for the out-of-band checks; VulnShop's SSRF (VS-4) is only reachable from an endpoint nothing links to, and its blind XXE (VS-16) is a POST, which the sweep doesn't send. The sweep scans GETs with parameters first, then up to 20 without (headers and cookies), and skips paths whose names change state (`/createdb`, `/logout`…). After step 3b the sweep also renders HTML pages in headless Chromium for DOM XSS (VS-25), and re-sends up to 10 recorded submissions (not logins) for stored XSS (VS-23, values looked for on pages from history) and CSRF (VS-24; a request accepted without cookies isn't counted); the base64-JSON SQLi (VS-26) is found through nested insertion points. Juice Shop and VAmPI are unchanged. Step 4a adds JWT, GraphQL, web cache, mass assignment and prototype pollution checks: VulnShop's VS-27…VS-33 are all found, plus two real token bugs the ground truth lacked until then: VAmPI's JWT secret is `random` (VA-8) and Juice Shop accepts unsigned `alg: none` tokens (JS-9). App-wide bugs like these use `method: "*"` and `path: "*"` in the ground truth. Step 4b adds OAuth and deserialization checks, plus request smuggling, file upload and race checks that need approval; `bench/run.sh` allows them for its throwaway apps (`tiers: human: destructive: allow`). VulnShop's VS-34…VS-37 are found; its race (VS-5) needs a one-time action that hasn't been used yet, which the recorded traffic doesn't have.
