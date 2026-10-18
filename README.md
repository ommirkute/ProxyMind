# ProxyMind

**The proxy that thinks.** An open-source, AI-native intercepting proxy for web application pentesting.

Other proxies give AI access to their tools. ProxyMind gives AI an understanding of the app, a memory of the engagement and a requirement to prove every finding, all within rules of engagement the client can audit.

> **Status: early development (pre-alpha).** Working today: the HTTP/1.1 intercepting proxy with TLS interception, project history, and the policy gate (scope, rules of engagement, approvals, tamper-evident audit log). Everything else below is planned. See [`docs/plan.md`](docs/plan.md).

## Why ProxyMind

| | What it means |
|---|---|
| 🧠 **Live app model** | Builds a map of the app from traffic: objects, IDs, who owns them, and operations. Agents ask questions like "which endpoints accept another user's order ID?" instead of reading raw logs. |
| 👥 **Multi-identity by default** | Keeps several user sessions alive, replays any request as any user, and fills in an authorization matrix while you browse. |
| ✅ **No proof, no finding** | Findings count only when ProxyMind proves them itself (differential authz, OAST callbacks, statistical timing). Every proof can be re-run with one click. |
| 📒 **Hypothesis ledger & coverage** | Shared memory of what was tested, by whom, and what's still untested, for humans and agents alike. |
| 🛡️ **Rules of engagement as code** | Scope, rate limits, time windows and approvals are enforced by the core, outside the model, with a tamper-evident audit log. |
| 🔌 **Any model, any agent, offline** | MCP server and REST API for Claude Code, Cursor or your own agents. Works with cloud models or fully local ones. |

## Quick start (current spike)

Requires Rust 1.88+.

```bash
cargo build --release
./target/release/proxymind proxy --listen 127.0.0.1:8080
```

On first run ProxyMind creates a CA at `~/.proxymind/proxymind-ca.pem`. Install it in your browser (or pass it to curl with `--cacert`), then set the browser's proxy to `127.0.0.1:8080`.

```bash
# Try it with curl
curl --cacert ~/.proxymind/proxymind-ca.pem -x http://127.0.0.1:8080 https://example.com/

# See what was recorded
./target/release/proxymind history
./target/release/proxymind show 1
./target/release/proxymind history --json     # machine-readable, for scripts and agents
```

Traffic is stored in `proxymind.pmproj` (a SQLite file) in the current directory. Use `--project <file>` to choose another.

### Rules of engagement

Describe what's in scope and what each kind of actor may do in a YAML file (see [`examples/roe.yaml`](examples/roe.yaml)), then check it and try requests against it. Nothing is sent when testing.

```bash
./target/release/proxymind roe check examples/roe.yaml
./target/release/proxymind roe test examples/roe.yaml https://app.example.com/profile --actor agent:claude --method POST
# During the engagement dates in the file (2–13 Nov 2026), on weekdays 09:00–18:00 London time:
# NEEDS APPROVAL: POST https://app.example.com/profile as agent:claude (ActiveIntrusive)
# Outside them it prints DENY with the reason.

./target/release/proxymind audit verify     # check the audit log was not tampered with
./target/release/proxymind audit list
```

Scope rules resist the usual bypass tricks (encoded paths, `../`, `;params`, look-alike hosts, odd IP formats, IPv4-mapped IPv6). The full list is in [`crates/pm-policy/tests/scope_bypass.rs`](crates/pm-policy/tests/scope_bypass.rs).

## Repository layout

```
crates/
  pm-http      raw HTTP/1.x parsing that keeps exact bytes      ✅ working
  pm-tls       CA and per-host certificates, upstream TLS       ✅ working
  pm-store     SQLite project file and compressed blob store    ✅ working
  pm-proxy     intercepting proxy                               ✅ working (HTTP/1.1)
  pm-cli       the `proxymind` binary                           ✅ working
  pm-policy    scope, ROE, approvals, rate limits, audit chain  ✅ working
  pm-replay    Repeater-style send engine                       ⏳ planned (M2)
  pm-identity  multi-identity sessions                          ⏳ planned (M3)
  pm-diff      semantic diff                                    ⏳ planned (M3)
  pm-model     live app model                                   ⏳ planned (M4)
  pm-ledger    hypotheses and coverage                          ⏳ planned (M4)
  pm-proof     proof oracles and findings                       ⏳ planned (M5)
  pm-oast      out-of-band testing client/server                ⏳ planned (M5)
  pm-ai        LLM views, redaction, providers                  ⏳ planned (M6)
  pm-service   the one service layer every client uses          🟡 started (policy + audit)
  pm-api       REST API and event stream                        ⏳ planned (M2)
  pm-mcp       MCP server                                       ⏳ planned (M2)
docs/          plan, decision records (ADRs), RFCs
examples/      example rules-of-engagement file
schemas/       JSON schemas
bench/         vulnerable target apps for benchmarking
```

## Responsible use

ProxyMind is for testing systems you are authorized to test. The rules-of-engagement features exist to help you stay within that authorization and prove it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

The core is licensed under [AGPL-3.0](LICENSE). SDKs will be Apache-2.0. See [ADR-007](docs/adr/0007-license.md).
