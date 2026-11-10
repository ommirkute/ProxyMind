---
name: jwt_audit
title: JWT and session token audit
description: Check how the app's tokens are signed, validated and expire: weak secrets, alg none, key confusion, missing expiry, tokens that survive logout.
args: focus
---
Goal: find weaknesses in JSON Web Tokens and session tokens. {{focus}}

1. `history_grep` for `eyJ` (base64 JWT header) in request headers and cookies; note which endpoints accept tokens and which identity each belongs to (`identity_list`).
2. `decode` one token: record `alg`, `kid`, `jku`/`x5u`, `exp`, `iat` and the claims (role, user id). Missing `exp`, or one far in the future, is a finding to note.
3. Run `scan_active` with checks `["jwt"]` on one recorded authenticated request: it tests alg none, weak HMAC secrets and signature stripping. For each issue, `finding_create` and keep the exchange as evidence.
4. Claims: with `replay_send`, change a role or user-id claim only after confirming the signature isn't checked (step 3). Compare with `compare_exchanges`.
5. Lifetime: replay an old token after the user logs out (ask the person to log out, or use `identity_check`). A token that still works after logout is a finding.
6. Session cookies: `token_analyzer_run` on 20+ fresh session values to check randomness.

Never brute-force secrets beyond what `scan_active` does, and keep tokens out of your written notes (they show as placeholders).
