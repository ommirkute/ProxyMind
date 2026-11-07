# Releasing ProxyMind

## Cutting a release

1. Make sure `main` is green: run CI by hand (Actions → CI → Run workflow) so macOS and Windows are covered, and run Nightly.
2. Set the version in `Cargo.toml` (`[workspace.package] version`) and commit.
3. Tag and push: `git tag v0.1.0 && git push origin v0.1.0`.

`.github/workflows/release.yml` then:

- builds `proxymind` with the web UI embedded for Linux (x86_64 and ARM64), macOS (Apple silicon and Intel) and Windows (x86_64), packaged with the README, licence and examples;
- writes `SHA256SUMS` and an SPDX SBOM of the Rust and npm dependencies;
- signs build provenance for every file and the SBOM with GitHub artifact attestations (Sigstore, keyless);
- publishes a GitHub release (marked pre-release for `v0.x`);
- builds desktop installers with `cargo tauri build` (Linux .deb/.rpm/.AppImage, macOS .dmg, Windows .msi and setup .exe; unsigned until code-signing certificates are set up, but covered by the provenance attestations);
- builds and pushes `ghcr.io/<owner>/proxymind:<version>` with its own SBOM and provenance.

## Verifying a download

```bash
sha256sum -c SHA256SUMS --ignore-missing
gh attestation verify proxymind-v0.1.0-x86_64-unknown-linux-gnu.tar.gz --repo ommirkute/ProxyMind
gh attestation verify oci://ghcr.io/ommirkute/proxymind:0.1.0 --repo ommirkute/ProxyMind
```

## Container image

```bash
docker build -t proxymind .
docker run --rm -v proxymind:/data -v "$PWD/roe.yaml:/roe.yaml:ro" proxymind roe use /roe.yaml
docker run -d --name proxymind -v proxymind:/data -p 127.0.0.1:7777:7777 -p 127.0.0.1:8080:8080 proxymind
docker logs proxymind   # prints the login link
```

The image includes Chromium for XSS proofs (about 1.1 GB in all; build with `--build-arg WITH_CHROMIUM=false` to leave it out). The UI listens on all interfaces *inside* the container (`--bind-any`); publish it on `127.0.0.1` only. Requests must still be addressed to localhost and carry the token. Behind a TLS-intercepting proxy, pass its CA to the build: `--secret id=extra_ca,src=ca.pem`.

## Nightly checks

`.github/workflows/nightly.yml` (run by hand from the Actions tab for now, to save Actions minutes) fuzzes the parsers that read hostile input (HTTP/1.x and HTTP/2 text, WebSocket frames, DNS queries, the payload classifier, the crawler's HTML reader, Fuzzer templates, the passive checks and OpenAPI specs) for five minutes each, and builds and smoke-tests the container image. Crashes are uploaded as artifacts; add each one as a regression test next to the code it broke.

Run a fuzz target locally:

```bash
cargo install cargo-fuzz
cd fuzz && cargo +nightly fuzz run crawl_extract -- -max_total_time=60
```
