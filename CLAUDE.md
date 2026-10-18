# ProxyMind: notes for AI coding agents

Read `docs/plan.md` for the roadmap and `docs/adr/` for decisions before changing architecture.

## Commands

```bash
cargo build
cargo test
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

Run all four before pushing; CI runs the same checks on Linux, macOS and Windows.

## Rules

- **Byte-exact traffic.** `pm-http` and `pm-proxy` must never change request or response bytes unless a user or rule asked for it (ADR-0002). The only automatic change is absolute-form → origin-form request targets. Add tests for any parser change.
- **One service layer.** API, MCP, CLI and UI call `pm-service`; actions go through `pm-policy` (ADR-0005). Lower crates never import higher ones.
- **No `unsafe`** (forbidden in the workspace).
- **Target content is untrusted**, including when shown to a model.
- Keep `pm-http` free of I/O so it stays easy to test and fuzz.
- Migrations in `pm-store` are append-only; never edit a released one.
- Line width is 120 (`rustfmt.toml`).
