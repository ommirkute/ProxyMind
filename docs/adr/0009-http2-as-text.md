# ADR-0009: HTTP/2 as text, sent with the h2 crate

**Status:** Accepted

## Context
ADR-0002 keeps HTTP/1.x byte-exact. HTTP/2 has no such bytes to keep: HPACK and framing are re-encoded on every hop. Testers and models still need to read, edit and resend HTTP/2 requests, and the same tools (rules, intercept, Repeater, identities, authz checks, redaction) should work on them without a second code path.

## Decision
- HTTP/2 messages are shown, edited and stored as HTTP/1-style text with `HTTP/2` as the version and `host:` standing for `:authority` (`pm_http::h2text`). Split `cookie` headers are joined (RFC 9113 §8.2.3).
- A request whose request line says `HTTP/2` is sent over HTTP/2 (`h2` crate): ALPN `h2` over TLS, prior knowledge (h2c) over plain HTTP. If the server only speaks HTTP/1.1, the request is downgraded and history records the HTTP/1.1 bytes actually sent (`Response::sent`).
- The proxy offers `h2` to browsers on intercepted TLS connections (`--no-http2` turns it off). Each stream becomes HTTP/2 text and goes through the same rules, intercept queue, sender and recorder as HTTP/1.1.

## Consequences
- One representation for every tool; changing the version in the request line switches protocol.
- HTTP/2-level attacks that need control over frames (CONTINUATION floods, h2-only smuggling, single-packet sends of many streams) need frame-level tooling later; the text form can't express them.
- Not supported yet: WebSockets over HTTP/2 (RFC 8441), server push, and HTTP/2 in race/parallel sends (they downgrade to HTTP/1.1).
