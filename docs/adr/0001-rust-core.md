# ADR-0001: Rust for the core

**Status:** Accepted

## Context
The core parses hostile traffic from targets all day, handles thousands of concurrent connections during fuzzing, and should ship as a single binary for desktop, CI and Docker. Burp and ZAP run on the JVM; mitmproxy is Python.

## Decision
Write the core in Rust (2024 edition) on tokio. `unsafe` is forbidden workspace-wide.

## Consequences
- Memory safety when parsing malicious input; predictable performance; small single binary.
- Smaller contributor pool than Python or Java. Mitigation: Python SDK and template-based scanner checks give non-Rust contributors a way in.
