# ADR-0019: One source of truth for API contracts

**Status:** Proposed. Roadmap work package 1.3 (`docs/roadmap.md`, Phase 1 and "Architecture gaps": "Hand-written contracts").

## Context
The same request shape is written down up to five times, and nothing checks that the copies agree.

- **Rust.** `pm-service` request types derive `Deserialize` (about 72 derive lines in `crates/pm-service/src`, 25 structs named `*Request`). They carry the real rules in serde attributes, for example `#[serde(default, deny_unknown_fields)]` on `ProofRequest` (`crates/pm-service/src/proof.rs`), and field docs as `///` comments.
- **REST.** `crates/pm-api/src/routes.rs` has about 79 `Json<...>` extractors. Roughly 27 use service types directly (`Json<ReplayRequest>` in `replay`, `Json<ProofRequest>` in `proof_run`, `pm_service::AuthzMatrixRequest`, `ScanTaskRequest`, `EngageFilter`). The rest use body and query structs private to the file (48 derive lines: `CaptureBody`, `SmtpBody`, `UpdateSet`, `HostQuery`, ...), which no other crate can see. Every handler returns `Result<Json<Value>, ApiError>` (`type ApiResult`), so responses have no declared type at all.
- **MCP.** `crates/pm-mcp/src/tools.rs` holds 79 `tool(name, description, json!({...}), &[required])` calls (`tool()` always sets `additionalProperties: false`). The dispatcher in the same file then deserializes with `args::<T>(a)` into the service type, for example `"proof_run" => pm_service::ProofRequest`. The guard test `every_handled_tool_is_listed_and_every_listed_tool_is_handled` in `crates/pm-mcp/src/lib.rs` keeps tool names and handlers in step, but it checks names only, not that a schema matches its struct.
- **SDKs.** `sdk/python/proxymind/__init__.py` (403 lines) and `sdk/typescript/src/index.ts` (506 lines) are hand-written. Many methods take `**inputs` or return untyped `dict`/`Json` (`proof(oracle, **inputs)` in both).
- **UI.** `ui/src/api.ts` (about 380 lines) has about 28 hand-copied interfaces and unions such as `ProofResult`, which mirrors `pm_service::ProofResult` (`#[serde(tag = "status", rename_all = "snake_case")]`). The pages call `api.post<ProofResult>("/proofs", {...})` with inline objects.

**Concrete drift.** `ProofRequest::view_raw` (stored XSS) exists in the struct, in its `///` doc and in the `proof_run` JSON schema, each written separately. The bounds of `samples` (5 to 30) are prose in the Rust comment and `"minimum":5,"maximum":30` in the MCP schema, and nothing enforces them in either place. Neither SDK knows the field exists, and a new oracle such as `marker` (with `marker_kind`) means editing the Rust enum-by-string, the MCP `enum` array, the tool description, docs and the SDK docstrings by hand. `deny_unknown_fields` already rejects unknown fields at runtime, so a stale schema fails late and with a poor message.

There is no `xtask`, codegen crate, `schemars` or `utoipa` in the workspace today (`Cargo.toml` members are `crates/*`; `schemas/` holds only `roe.schema.json`). `deny.toml` allows MIT, Apache-2.0, BSD, ISC, Zlib, MPL-2.0, Unicode-3.0 and AGPL-3.0-only, which covers `schemars` (MIT) and its small dependency set.

## Decision
- **Rust types are the contract.** Request and response types in `pm-service` derive `schemars::JsonSchema` next to `Deserialize`/`Serialize`. `schemars` reads the existing serde attributes (`default`, `deny_unknown_fields`, `rename_all`, `tag`, `skip_serializing_if`), so the schema follows the wire format. Doc comments become `description`. Bounds that matter use `#[schemars(range(min = 5, max = 30))]` and are also checked by the service.
- **Private route structs move.** Body and query structs that live only in `routes.rs` move into `pm-service` (or a `contracts` module in it) so MCP, SDKs and the UI can name them. Handlers return typed responses (`Json<ProofResult>`) instead of `Value`; the serialized bytes stay the same.
- **Generated artifacts, committed:**
  1. `docs/api/openapi.json`: OpenAPI 3.1 for `/api/v1`, one operation per route from a table of (method, path, request type, response type) kept in `pm-api`.
  2. `crates/pm-mcp/schemas/tools.json`: MCP `inputSchema` per tool, built from the request type named in the tool table. Tool descriptions stay hand-written for models, in one `tools.toml` (or doc comments on the types) read by the generator; they are not generated from field names.
  3. `ui/src/api.gen.ts`: TypeScript types only (no runtime code, no new UI dependency). `ui/src/api.ts` keeps the `call()` client and re-exports types.
  4. `sdk/typescript/src/types.gen.ts` and `sdk/python/proxymind/models.py` (`TypedDict`/dataclasses, stdlib only), used by the SDK methods in place of `**inputs` and `dict`.
- **Where it lives.** A new top-level crate `xtask/` (outside `crates/*`, listed in the workspace `exclude` or as a member with `publish = false`) depending on `pm-api`, `pm-mcp` and `pm-service`. It sits above everything, so "lower crates never import higher ones" holds. Run it as `cargo xtask contracts`. TypeScript generation uses a dev-time Node script (`json-schema-to-typescript` in `ui/` devDependencies only) or a small Rust emitter; the choice is left to the implementation, with the rule that nothing generated adds a runtime dependency.
- **Drift check.** A `pm-api` test (or `cargo xtask contracts --check`) regenerates in memory and compares to the committed files; CI fails with "run `cargo xtask contracts`". The existing MCP name-parity test stays and gains a check that every tool maps to a type.
- **Wire compatibility is a hard rule.** No serde attribute changes to make the schema nicer. Golden tests serialize sample values of each migrated type before and after and compare bytes.

## Migration
1. Add `schemars` to `pm-service`; derive it on the ten most used request types (`ReplayRequest`, `ProofRequest`, `AuthzCheckRequest`, `ScanTaskRequest`, `HistoryFilter`, `NewFinding`, `FindingUpdate`, `EngageFilter`, `WsReplayRequest`, `ModelFilter`) and `ProofResult`/`ReplayResult`.
2. Create `xtask`, emit `openapi.json` for those routes, and turn on the drift check in CI (Linux PR job only, as today).
3. Compare generated MCP schemas with the hand-written ones for the same tools; fix differences in the Rust types (missing bounds, descriptions), not by hand-editing output.
4. Move MCP tools one at a time to generated schemas; the guard test must pass at each step. Keep prose descriptions as they are.
5. Move private `routes.rs` structs into `pm-service`; type the responses; extend OpenAPI to all routes.
6. Generate UI and SDK types; replace the matching hand-written interfaces in `ui/src/api.ts` and the SDK method signatures.
7. Delete the hand-written `json!` property maps and `VIEW_SCHEMA` last, when all 79 tools are generated. This closes 1.3 ("the hand-written MCP schemas are gone").

## Alternatives
- **OpenAPI first, generate Rust.** One neutral document, strong tooling. But MCP and the byte-exact serde behaviour (`deny_unknown_fields`, defaults) would depend on a generator's output, the service types would become generated code, and MCP tools are not REST routes. Rejected.
- **`utoipa` annotations on handlers.** Mature, gives OpenAPI directly. It puts a large attribute on each of about 150 routes, still needs a second path for MCP and SDK types, and handlers returning `Value` need rewriting anyway. Could be adopted later for the route table only.
- **Keep it by hand plus a drift test.** Cheapest; a test could compare MCP schema keys with struct fields. It still leaves four copies to write, and the SDKs and UI stay untyped. Rejected as the end state; a cheap form of it is a fine stopgap before step 1.

## Consequences
- A new field is written once, in Rust with a doc comment; schemas, SDK types and UI types follow from `cargo xtask contracts`. Stale contracts fail CI instead of failing for an agent at runtime.
- SDK users and the UI get real types for requests and responses.

Risks:
- **Schema differences.** `schemars` handles internally tagged enums such as `ProofResult` well, but `untagged`, `flatten` and custom `Serialize` impls (about 9 `untagged`/`flatten` uses in `pm-service`) can produce `anyOf` shapes that some consumers handle badly. Those types get hand-tuned `#[schemars(...)]` attributes or manual impls, each with a golden test.
- **MCP quality.** Models do better with short schemas. Generated `$ref`, `definitions` and `anyOf: [T, null]` for `Option` are inlined and simplified by the generator; descriptions are reviewed per tool, and the tool descriptions are not generated.
- **Compile time.** The derive adds a little to `pm-service`, already the largest crate (about 21,500 lines). The generator lives in `xtask` so normal builds do not run it; this fits the 1.5 service split.
- **Dependencies.** `schemars` and any TS generator need a pass through the "licenses and advisories" job (`deny.toml`) before merging. If `schemars` is rejected, the fallback is a small in-repo schema walker over the same types.
- **Churn.** Moving the private `routes.rs` structs touches many handlers; each move is its own small change with a wire-format test.
