---
name: auth_review
title: Authentication review
description: Login, password change, logout and session handling: user enumeration, missing current-password checks, session fixation and expiry, auth bypass.
args: focus
---
Goal: check that authentication can't be bypassed or abused. {{focus}}

1. Find the login, logout, sign-up, password-change and password-reset operations in `model_get` (or `history_search` for login, signin, password, reset).
2. Run `scan_active` on the recorded login with checks `["sql_error", "sql_boolean", "nosql_operator", "user_enumeration"]`. It re-sends the login only; it changes nothing.
3. Password change: `scan_active` with `["password_change"]` checks whether the current password is required. Use a test account only.
4. Session: with `identity_check`, compare the session cookie before and after login (fixation), and check that the old session stops working after logout. `identity_learn_logged_out` teaches ProxyMind what "logged out" looks like.
5. Pages that answer 401/403: `scan_active` with `["auth_bypass"]` tries path and header tricks against a control.
6. Reset tokens: `token_analyzer_run` on several reset codes (ask the person to trigger them) to spot predictable values.
7. Rate limiting: describe a small burst test to the person before running it; never brute-force real accounts.
