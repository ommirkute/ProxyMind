# Contributing to ProxyMind

Thanks for helping. ProxyMind is early, so the most useful contributions right now are bug reports from real traffic, parser test cases, and work on the current milestone in [`docs/plan.md`](docs/plan.md).

## Before you start

- **Small fixes** (bugs, docs, tests): open a pull request directly.
- **New features or design changes:** open an issue first. Larger changes need a short RFC in `docs/rfc/` so the design can be discussed before code is written.
- **Decisions that are hard to reverse** (dependencies, formats, protocols) are recorded as ADRs in `docs/adr/`.

## Development

```bash
cargo build
cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

CI runs the same checks. Please run them before pushing.

## Rules that keep the project healthy

1. **Never normalize traffic by accident.** The proxy must forward bytes exactly as received unless the user (or a rule) asked for a change. Add a test when you touch `pm-http` or `pm-proxy`.
2. **Everything goes through the service layer.** The UI, REST API, MCP server and CLI must not reach into lower crates for actions. This is what keeps scope enforcement impossible to bypass.
3. **Lower crates don't import higher ones.** See the dependency rule in `docs/plan.md`.
4. **No `unsafe`.** The workspace forbids it.
5. **Target content is untrusted.** Anything that came from a tested app must be treated as hostile, including when it is shown to a model.

## Commit messages

Use the imperative mood and explain why, not just what: `Keep header case when rewriting absolute-form targets`.

## Code of conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
