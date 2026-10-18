# ADR-0003: TLS with rustls (ring)

**Status:** Accepted

## Context
TLS is needed both to intercept clients (acting as the server with per-host certificates) and to talk to targets. The default rustls crypto provider (aws-lc-rs) needs a C/C++ toolchain and cmake to build, which makes contributor setup harder.

## Decision
- Use rustls with the `ring` provider for both sides, and `rcgen` to generate the CA and leaf certificates.
- One CA per install, stored in `~/.proxymind` with the key at mode 0600.
- One shared key pair for all leaf certificates (fast; no security loss for a local interception CA). Leaf certificates are valid for 365 days (browsers reject more than 398).
- Upstream certificates are **not verified by default**, since pentest targets often use self-signed certificates. `--verify-upstream` turns verification on. Handshake signatures are always checked.

## Consequences
- Pure-Rust build, easy cross-compilation.
- rustls does not support TLS 1.0/1.1 or some legacy cipher suites. A later ADR will add an optional OpenSSL upstream connector for legacy targets.
- rustls has a recognisable client fingerprint. Fingerprint control (JA3/JA4) is a later feature.
