## What and why

<!-- What this changes, and the problem it solves. Link an issue if there is one. -->

## How it was tested

<!-- Commands you ran and what you checked. -->

- [ ] `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings` and `cargo test` pass
- [ ] UI changes: `cd ui && npm run build && npm run test:e2e`
- [ ] Parser or proxy changes keep traffic byte-exact, with a test ([ADR-0002](https://github.com/ommirkute/ProxyMind/blob/main/docs/adr/0002-raw-http.md))
- [ ] Docs updated where behaviour changed
