# ADR-0013: Projects are encrypted at rest by sealing, before transparent encryption

**Status:** Accepted

## Context
A project file holds a client's traffic, session cookies, credentials and findings. It is copied to laptops, backups and the client. The plan called for project encryption in v0.2. Transparent page-level encryption (SQLCipher) needs a different SQLite build linked against OpenSSL or a crypto library, on three platforms.

## Decision
- First step: `proxymind project lock` seals a consistent snapshot of the project (`VACUUM INTO`) into a `.pmlock` file; `project unlock` restores it. `pm-vault` does the cryptography.
- Key: Argon2id over the passphrase (64 MiB, 3 passes by default; the parameters are stored in the authenticated header, with upper bounds so a hostile file can't hang the opener). Passphrases shorter than 12 characters are refused.
- Data: ChaCha20-Poly1305 (ring) in 1 MiB chunks, nonce = random 7-byte prefix, chunk counter, last-chunk flag; the header is associated data for every chunk. Reordering, truncation, splicing and parameter changes all fail to open.
- Output is written to a temporary file and renamed only on success, so a wrong passphrase never leaves a half-written project. Opening a locked file as a project gives a clear error.

## Consequences
- Projects can be stored and handed over safely today, with no new native dependency.
- While a project is unlocked it is plaintext on disk; `--remove` is a normal delete, not a secure wipe. Full-disk encryption is still advised.
- Transparent encryption of the live project (SQLCipher or an encrypted VFS) remains the v0.2 goal; sealing stays useful for hand-over either way.
