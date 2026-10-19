# Benchmarks

ProxyMind's claims about agents and proofs have to be measurable. This directory holds the targets, the ground truth, a runner and the scoring.

> ⚠️ These apps are deliberately vulnerable. Bind them to `127.0.0.1` (as the compose file does) and never expose them to a network.

## Targets and ground truth

| App | Ground truth | Checked against | How to run |
|---|---|---|---|
| VulnShop (built in) | [`vulnshop.yaml`](ground-truth/vulnshop.yaml): 6 bugs + traps | `proxymind demo-target` | nothing to start |
| [VAmPI](https://github.com/erev0s/VAmPI) | [`vampi.yaml`](ground-truth/vampi.yaml): 7 bugs + 1 trap | image digest in the file | `docker compose -f bench/docker-compose.yml up -d vampi` |
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | [`juice-shop.yaml`](ground-truth/juice-shop.yaml): 8 API-level bugs | v20.3.0 | `docker compose -f bench/docker-compose.yml up -d juice-shop` |
| [OWASP crAPI](https://github.com/OWASP/crAPI) | [`crapi.yaml`](ground-truth/crapi.yaml): 10 bugs from crAPI's challenge list | not yet run | crAPI's own compose file (about 4 GB of images) |

Every VAmPI and Juice Shop entry was reproduced by hand against the pinned image. Path segments written `{name}` match any one segment.

## Running a benchmark

```bash
cargo build --release
PROXYMIND=$PWD/target/release/proxymind bench/run.sh vampi      # or juice-shop, vulnshop
```

The runner starts the app, browses it through the proxy as two users (profiles in [`apps/`](apps/)), captures their sessions, crawls, runs the **model-free access-control pass** (`proxymind bench auto`: check every candidate the app model suggests as the other identities, record and prove each leak, and drop what can't be proven), runs the passive scan, then scores with `proxymind bench score --app <app>`.

To score an agent, set `BENCH_AGENT` to a command; it runs with `PROXYMIND_PROJECT` pointing at the project, after the baseline steps:

```bash
BENCH_AGENT='claude -p "Use the proxymind MCP server to find and prove vulnerabilities"' bench/run.sh juice-shop
```

The nightly workflow runs the baseline on VulnShop, VAmPI and Juice Shop and posts the scores in the job summary.

## Baseline today (no agent)

| App | Found | Proven | False positives |
|---|---|---|---|
| VulnShop | 2/6 | 2/6 | 0 |
| Juice Shop | 1/8 | 1/8 | 0 |
| VAmPI | 0/7 | 0/7 | 0 |

The baseline only tests access control on objects the model recognises by numeric or UUID ids; VAmPI identifies objects by name (book titles, usernames), which the model doesn't template yet. Everything else is for agents.
