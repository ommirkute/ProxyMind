# ADR-0015: Active-check plugins propose requests; ProxyMind sends them. Plugin processes run sandboxed

**Status:** Accepted. Extends ADR-0014 (which left both as future work).

## Context
Plugin authors want checks that send requests (try a payload, compare the answer), not only checks over recorded traffic. Letting a plugin open its own connections would be a second path to targets that skips the policy gate (ADR-0005). Plugin processes also ran with the user's full environment: API keys, tokens and network access.

## Decision
- **Active checks are proposals.** A manifest's `active:` section names a command. For one recorded exchange ProxyMind runs it twice: `probe` (the plugin prints requests, origin-form only, to the exchange's own host; parsed, at most `max_requests`, 64 KB each) and `judge` (the plugin gets each request's recorded exchange, status and response, and prints issues in the passive format). Between the two, ProxyMind sends the requests itself.
- **One gate decision per check, binding the exact requests.** The batch is gated as `plugin_check`, at least `active_intrusive` (the payload classifier can raise it). An approval stores the requests; running with the approval id sends those requests, not a fresh set, so what the person approved is what goes out. Each request still passes the per-request scope check, rate limits and identity handling of the normal send path, and lands in history as source `plugin`.
- **Plugin issues are leads**, labelled `<plugin>/<check>`, never findings by themselves.
- **Sandbox for every plugin process** (passive and active): a cleared environment (`PATH`, locale, `HOME` = the plugin's directory, `PROXYMIND_PLUGIN=1`); on Linux, new user and network namespaces (`unshare --user --net`: only loopback) and `prlimit` (CPU time, writable memory, file size, open files); everywhere the timeout and output caps. `pm_plugin::sandbox::status()` reports what applies on the machine, and the UI and CLI show it.
- Plugins stay **per user**. The service reads the user's registry when plugins are used, so installing or turning a plugin off applies at once. Only people can turn plugins on or off.

## Consequences
- An active plugin can't reach the network or another host even if it tries, on Linux with user namespaces. Elsewhere (macOS, Windows, containers without user namespaces) a plugin can still open connections of its own: the status says so, and installing only trusted plugins remains the rule there.
- Plugins see raw traffic, as passive plugins always have (token checks need real values). The network sandbox is what keeps that data local.
- A plugin that wants requests sent must be fine with them going through the gate: an agent running it usually waits for approval.
- Not done yet: UI panels contributed by plugins, a WASM runtime for portable sandboxing, signed manifests.
