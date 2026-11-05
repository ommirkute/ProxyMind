# ADR-0016: Signed plugins, install-time integrity, and data-only plugin panels

**Status:** Accepted. Extends ADR-0014 and ADR-0015.

## Context
ADR-0015 left three things open: UI panels contributed by plugins, a portable (WASM) sandbox, and signed manifests. Plugins run code on the user's machine, so knowing who wrote a plugin, and that it hasn't changed since it was installed, matters as much as the sandbox.

## Decision
- **Signatures.** A plugin folder may carry `proxymind-plugin.sig` (JSON: signer label, Ed25519 public key, signature), signing a digest of every file in the folder (`sha256  path` lines, sorted; `.git`, `__pycache__` and `*.pyc` left out; symbolic links refused). `proxymind plugin keygen | sign | trust | untrust | trusted` manage keys; trusted keys live per user in `<home>/trusted-keys.json`.
- **Install.** A signature that doesn't match the files is refused. Unsigned plugins still install (the list and UI say "unsigned") unless `plugin add --require-signed`, which accepts only keys on the trusted list.
- **Integrity.** Install records each file's SHA-256 in the registry. Before every run, recorded files must be unchanged; otherwise the plugin doesn't run until it is installed again. New files (caches) are not checked, so a plugin can still write state.
- **Panels are data.** A manifest's `panels:` names commands that get recorded exchanges (the passive plugin format) and print one JSON object (title, text, columns, rows). ProxyMind clips and validates it and the UI renders text and table cells as plain text, never as HTML or script from the plugin. Panels run in the same sandbox; for agents the output is redacted and marked untrusted.
- **No WASM runtime yet.** A WebAssembly runtime (wasmtime) would give the same sandbox on every OS, but it adds a large dependency to the core binary. The OS sandbox (Linux namespaces) plus signatures and integrity checks cover the main risks; WASM stays a separate decision when plugin authors need cross-platform isolation.

## Consequences
- Users can see who signed a plugin and require trusted signers; a tampered plugin stops running instead of running changed code.
- Plugin authors who want panels write ordinary programs; they can't change the UI's look or run code in it.
- On macOS and Windows plugins still aren't network-isolated (ADR-0015); signatures make "install only code you trust" checkable.
