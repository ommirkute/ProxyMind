# Changelog

All notable changes to ProxyMind. Versions follow [semantic versioning](https://semver.org/); before 1.0, a minor
version may change project files, APIs and the CLI.

## Unreleased

### Proof

- **Automatic proving.** A new step turns the scanner's *suspected* findings into *proven* ones: it picks the oracle
  that fits each finding's class, rebuilds the request from its evidence and runs it through the policy gate. SQL
  injection is proven by a boolean true/false split (or the timing oracle), command injection by timing, SSRF by an
  out-of-band callback, reflected XSS in the headless browser, path traversal by reading known files while a bogus
  name reads nothing, and open redirect and CRLF by a fresh random marker reaching the redirect target or a response
  header. IDOR and BFLA reuse the differential oracle. It runs at the end of `proxymind bench auto` (skip with
  `--no-prove`), as `proxymind findings prove [id]`, over the API (`POST /api/v1/findings/{id}/prove`,
  `POST /api/v1/findings/prove`), as the MCP tool `finding_prove`, and from an **Auto-prove** button on the Findings
  page. Also exposed as new `proof_run` oracles `boolean_injection`, `path_traversal` and `marker`. SDKs gain
  `finding_prove` / `findings_prove_all` (Python) and `findingProve` / `findingsProveAll` (TypeScript).

## 0.2.0 (2026-11-12)

### AI testing

- **AI scan**: an autonomous agent goes from recon to chained findings under the rules of engagement, with an
  attack graph, live steering (pause, redirect, add notes), an independent verifier for each finding and
  business-logic tests.
- **Cost meter** with a budget, a **prompt-injection guard** for target content shown to the model, **explain and
  fix** for findings, presets for local models, **memory** across engagements, learning from your verdicts, traffic
  **triage** and **parallel workers**.
- Model **API keys can be set in the UI** (stored in the project vault) for both the AI scan and the assistant.
- **Skills (playbooks)** for agents over MCP.

### Proof and reporting

- **Signed evidence packs** (`proxymind evidence`) with a coverage proof, checked offline by `proxymind verify`.
- **Proven findings as CI regression tests**: `proxymind regress export|run`.
- **Authorization matrix**: every readable operation as every identity and anonymously, as one grid; IDOR, missing
  function-level checks and missing authentication flagged and proven with the differential oracle.
- **What changed since the last test**: model snapshots and a diff that names new, changed and removed endpoints
  and the earlier findings to retest (`proxymind changes`).

### Recon and scanning

- Passive recon: **DNS records** and **Wayback** history.
- **JavaScript endpoint mining**; parameters a page reads but nothing sends are found and scanned.
- Discovery tries common names of pages that take a URL or a file, also inside API folders, and sends them once
  with a likely parameter; the sweep now scans parameterised pages that fail on their value (a `?file=` that is not
  found, a `?url=` that does not resolve). VulnShop: 33/38 → 35/38 (SSRF and path traversal), no new false
  positives.
- Out-of-band callbacks that arrive late are still counted.
- Opt-in update check.

### Fixes

- Discovery's guessed-parameter probe sent the path without its query.
- Absolute-form targets with an empty path are split correctly.
- The out-of-band deadline uses one clock, so a callback at the deadline counts.

## 0.1.0 (2026-11-07)

First public release: intercepting proxy, history, replay, fuzzer, scanner, crawler, discovery, identities and
authorization checks, the proof engine, MCP server, web UI, desktop app, Python and TypeScript SDKs.
