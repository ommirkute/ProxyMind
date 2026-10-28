# ADR-0002: Own raw HTTP/1.x parser

**Status:** Accepted

## Context
General HTTP libraries (hyper, h11) normalize messages: they fix header casing, reject odd whitespace, reframe bodies and refuse ambiguous requests. For pentesting, those "broken" messages are the point: request smuggling, desync, parser differentials and header injection all depend on sending exactly the bytes the tester wrote.

## Decision
`pm-http` is a small sans-I/O parser that finds message boundaries and reads headers but never rewrites bytes. The proxy forwards the original bytes. The only automatic change is rewriting an absolute-form target (`GET http://host/x`) to origin-form (`GET /x`), which servers require; it touches only the request target.

HTTP/2 will use the `h2` crate, because HPACK and framing make byte-exact pass-through meaningless there.

## Consequences
- Byte-exact pass-through, verified by an end-to-end test.
- We own the edge cases (chunk extensions, bare LF, obsolete line folding). Mitigation: fuzzing (`cargo-fuzz`) and golden-file tests in CI.
- Framing is decided conservatively (any `chunked` in Transfer-Encoding wins) so the proxy never hangs. Smuggling tests that need different framing will use the raw Replay, not the proxy path.
