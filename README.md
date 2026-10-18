# ProxyMind

**The proxy that thinks.** An open-source, AI-native intercepting proxy for web application pentesting.

Other proxies give AI access to their tools. ProxyMind gives AI an understanding of the app, a memory of the engagement and a requirement to prove every finding, all within rules of engagement the client can audit.

> **Status: pre-alpha.** The engine and agent interface work end to end (see the demo); there is no desktop UI yet and the proxy speaks HTTP/1.1 only. See [What's done and what's next](docs/plan.md#status).

## Why ProxyMind

| | What it means |
|---|---|
| 🧠 **Live app model** | Builds a map of the app from traffic: objects, IDs, who owns them, and operations. Agents ask questions like "which endpoints accept another user's order ID?" instead of reading raw logs. |
| 👥 **Multi-identity by default** | Keeps several user sessions alive (automatic re-login), replays any request as any user, and compares the responses while ignoring timestamps and tokens. |
| ✅ **No proof, no finding** | Findings count only when ProxyMind proves them itself (differential authz, OAST callbacks, statistical timing). Every proof can be re-run with one command. |
| 📒 **Hypothesis ledger & coverage** | Shared memory of what was tested, by whom, and what's still untested, for humans and agents alike. |
| 🛡️ **Rules of engagement as code** | Scope, rate limits, time windows and approvals are enforced by the core, outside the model, with a tamper-evident audit log. |
| 🔌 **Any model, any agent, offline** | MCP server for Claude Code, Cursor or your own agents, including ones running local models (REST API planned). ProxyMind never sends your data to a model itself, and agents see secrets only as placeholders. |

## Try it in two minutes

```bash
cargo build --release
PROXYMIND=./target/release/proxymind bench/demo.sh
```

The script starts **VulnShop** (a small, deliberately vulnerable API built into ProxyMind), browses it through the proxy as three users, captures their sessions, replays requests as other users, and has ProxyMind **prove** the access-control bugs it finds, while correctly refusing to "prove" the protected endpoint. It ends with a benchmark score, an audit-log check and a Markdown report.

Then connect an AI agent ([docs/agents.md](docs/agents.md)) and ask it to find the remaining two bugs.

## Quick start

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

### Use it with AI agents (MCP)

```bash
./target/release/proxymind roe use examples/roe.yaml
claude mcp add proxymind -- "$PWD/target/release/proxymind" -p "$PWD/proxymind.pmproj" mcp --actor agent:claude
./target/release/proxymind approvals watch    # approve or deny what the agent asks to do
```

Agents can search history, read exchanges in token-budgeted views with secrets hidden, and send requests through the policy gate. See [docs/agents.md](docs/agents.md).

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
  pm-demo      VulnShop, a deliberately vulnerable demo API     ✅ working
  pm-policy    scope, ROE, approvals, rate limits, audit chain  ✅ working
  pm-replay    send engine (incl. single-packet parallel sends) ✅ working
  pm-identity  multi-identity sessions, auto re-login           ✅ working
  pm-diff      semantic diff with learned noise masks           ✅ working
  pm-model     live app model: operations, objects, ownership   ✅ working
  pm-ledger    hypotheses and coverage                          ✅ working
  pm-proof     proof oracles (authz, timing, OAST)              ✅ working
  pm-oast      out-of-band callback listener (HTTP)             ✅ working (DNS planned)
  pm-ai        LLM views, redaction, untrusted tagging          ✅ working (providers planned)
  pm-service   the one service layer every client uses          ✅ working
  pm-api       REST API and event stream                        ⏳ planned (M2)
  pm-mcp       MCP server                                       ✅ working
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
