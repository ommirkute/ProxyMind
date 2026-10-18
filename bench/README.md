# Benchmarks

ProxyMind's claims about agents and proofs have to be measurable. This directory will hold the targets, the ground truth and the scoring.

> ⚠️ These apps are deliberately vulnerable. Bind them to `127.0.0.1` (as the compose file does) and never expose them to a network.

## Targets

| App | Focus | How to run |
|---|---|---|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | broad web vulnerabilities | `docker compose -f bench/docker-compose.yml up -d juice-shop` |
| [VAmPI](https://github.com/erev0s/VAmPI) | API vulnerabilities, BOLA | `docker compose -f bench/docker-compose.yml up -d vampi` |
| [OWASP crAPI](https://github.com/OWASP/crAPI) | API access control (main demo target) | uses its own multi-container compose file; follow its README |

## Planned (milestone M6)

- `ground-truth/<app>.yaml`: known vulnerabilities with endpoint, class and how to prove them.
- `score/`: compares findings in a project file against ground truth and reports detections, missed issues, false proofs, requests sent and model cost.
- Nightly CI job publishing results to the README.
